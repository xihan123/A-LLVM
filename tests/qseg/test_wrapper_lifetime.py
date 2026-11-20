"""Host checks for the evidence boundaries; no compiler or device is invoked."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import wrapper_lifetime as wrapper

sys.path.insert(0, str(wrapper.ROOT / 'tests/cse-hardened'))
import test_seal_cse


TOKEN = wrapper.sha(b'wrapper-test-token')[:32]


def fixture_resources():
    contract, receipt, raw_resources = {}, {'segments': []}, {}
    for index, name in enumerate(wrapper.METHODS):
        size = 128 if name in (*wrapper.TARGETS, 'marker') else 80000
        raw = bytes([index + 1]) * size
        identity = format(index + 1, '032x')
        contract[name] = {'method': wrapper.METHODS[name], 'symbol': wrapper.SYMBOLS[name],
                          'id': identity, 'bytes': size, 'sha256': wrapper.sha(raw)}
        raw_resources[bytes.fromhex(identity), 1] = raw
        for number, offset in enumerate(range(0, size, 65536)):
            chunk = raw[offset:offset + 65536]
            receipt['segments'].append({'id': identity, 'kind': 1, 'name': wrapper.SYMBOLS[name],
                'lifetime': 'lease-v1', 'chunk': number, 'bytes': len(chunk), 'sha256': wrapper.sha(chunk),
                'resourceSha256': wrapper.sha(raw), 'codec': 1})
    return contract, receipt, raw_resources


def plan_fixture():
    resources = wrapper.select_resources(*fixture_resources())
    for index, item in enumerate(resources):
        item['address'] = 0x1000 + index * 32
    return {'schemaVersion': 1, 'resources': resources, 'onloadRva': 0x2000,
            'apkSha256': 'a1' * 32, 'libraryEntry': 'lib/arm64-v8a/libdex2c_semantics.so',
            'librarySha256': 'b2' * 32, 'containerSha256': 'c3' * 32,
            'pageSize': wrapper.PAGE, 'idleBudgetBytes': wrapper.BUDGET,
            'executableSpans': [{'address': 0x1000, 'bytes': 0x3000, 'sha256': '12' * 32}]}


def event_rows(case, plan, token=TOKEN):
    rows = [{'token': token, 'case': case, 'seq': 0, 'event': 0, 'depth': 0,
             'active': 0, 'idle': 4096, 'pinned': 0, 'peak': wrapper.BUDGET, 'evictions': 0, 'targetLoans': 0}]
    for sequence, (event, depth) in enumerate(wrapper.EVENTS[case], 1):
        row = {'token': token, 'case': case, 'seq': sequence, 'event': event, 'depth': depth,
               'active': wrapper.expected_active(case, event, plan), 'idle': 4096, 'pinned': 0,
               'peak': wrapper.BUDGET, 'evictions': sequence, 'targetLoans': 0,
               'steps': wrapper.PRESSURE_COUNT, 'readonly': True, 'digests': True}
        if event == 9 or (case == 'nested' and event == 4):
            index = (1 if event == 4 else 0) if case == 'nested' else 2
            row.update(reclaimed=plan['resources'][index]['id'], absent=True,
                       oldBegin=hex((index + 1) * 0x10000), oldBytes=plan['resources'][index]['mappedBytes'],
                       releasedReadonly=True, steps=3)
        rows.append(row)
    expected = 71 if case == 'nested' else 342
    rows.append({'token': token, 'case': case, 'seq': len(rows), 'event': 10, 'depth': 0,
                 'active': 0, 'idle': 4096, 'pinned': 0, 'peak': wrapper.BUDGET,
                 'evictions': len(rows), 'targetLoans': 0, 'first': expected, 'again': expected, 'semanticReentry': True})
    return rows


def output(rows):
    return b''.join(b'QSEG_WRAPPER:' + json.dumps(row).encode() + b'\n' for row in rows)


class ResourceContractTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.receipt, self.resources = fixture_resources()

    def select(self):
        return wrapper.select_resources(self.contract, self.receipt, self.resources)

    def test_explicit_targets_and_all_pressure(self):
        selected = self.select()
        self.assertEqual([item['name'] for item in selected[:3]], list(wrapper.TARGETS))
        self.assertEqual([item['name'] for item in selected[3:]], [f'work{i}' for i in range(14)])
        self.assertGreater(sum(item['mappedBytes'] for item in selected[3:]), wrapper.BUDGET)
        self.assertLess(selected[0]['bytes'], selected[3]['bytes'])

    def test_pinned_chunk_is_not_lease_evidence(self):
        self.receipt['segments'][0]['lifetime'] = 'pinned-unproven-unwind'
        with self.assertRaises(ValueError):
            self.select()

    def test_missing_and_duplicate_chunks_rejected(self):
        self.receipt['segments'].append(copy.deepcopy(self.receipt['segments'][0]))
        with self.assertRaises(ValueError):
            self.select()
        self.receipt['segments'].pop()
        self.receipt['segments'].pop(0)
        with self.assertRaises(ValueError):
            self.select()

    def test_authenticated_bytes_must_match_build(self):
        key = bytes.fromhex(self.contract['outer']['id']), 1
        self.resources[key] = b'x' * 128
        with self.assertRaises(ValueError):
            self.select()

    def test_wrong_name_size_kind_and_digest_rejected(self):
        for field, value in (('name', 'wrong'), ('bytes', 123), ('kind', 2), ('sha256', '00' * 32)):
            with self.subTest(field=field):
                row = self.receipt['segments'][0]
                old = row[field]
                row[field] = value
                with self.assertRaises(ValueError):
                    self.select()
                row[field] = old

    def test_pressure_and_compression_are_actual_product_gates(self):
        for row in self.receipt['segments']:
            row['codec'] = 0
        with self.assertRaises(ValueError):
            self.select()

    def test_target_identities_do_not_come_from_largest_resource(self):
        selected = self.select()
        self.assertEqual(selected[0]['id'], self.contract['outer']['id'])
        self.assertEqual(selected[1]['id'], self.contract['inner']['id'])
        self.assertEqual(selected[2]['id'], self.contract['recursive']['id'])


class EventEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()

    def check(self, case, rows=None, stderr=b''):
        rows = event_rows(case, self.plan) if rows is None else rows
        return wrapper.validate_run(output(rows), stderr, TOKEN, case, self.plan)

    def test_both_normal_return_cases(self):
        for case in wrapper.EVENTS:
            self.assertEqual(self.check(case)[-1]['event'], 10)

    def test_four_recursive_frames_and_return_continuations(self):
        rows = self.check('recursive')
        self.assertEqual([row['depth'] for row in rows if row['event'] == 6], [3, 2, 1, 0])
        self.assertEqual([row['depth'] for row in rows if row['event'] == 7], [1, 2, 3])
        self.assertEqual(len({row['active'] for row in rows if row['event'] in (6, 7, 8)}), 1)

    def test_recursion_is_not_billed_as_reference_count(self):
        rows = event_rows('recursive', self.plan)
        rows[1]['active'] *= 4
        with self.assertRaises(ValueError):
            self.check('recursive', rows)

    def test_all_eleven_recursive_inside_events_require_full_pressure(self):
        for index in range(1, 12):
            with self.subTest(index=index):
                rows = event_rows('recursive', self.plan)
                rows[index]['steps'] = 13
                with self.assertRaises(ValueError):
                    self.check('recursive', rows)

    def test_wrong_token_missing_duplicate_and_reordered_events_rejected(self):
        rows = event_rows('nested', self.plan)
        mutations = []
        wrong = copy.deepcopy(rows); wrong[2]['token'] = 'f' * 32; mutations.append(wrong)
        missing = copy.deepcopy(rows); missing.pop(2); mutations.append(missing)
        duplicate = copy.deepcopy(rows); duplicate.insert(2, copy.deepcopy(duplicate[2])); mutations.append(duplicate)
        order = copy.deepcopy(rows); order[2], order[3] = order[3], order[2]; mutations.append(order)
        for changed in mutations:
            with self.assertRaises(ValueError):
                self.check('nested', changed)

    def test_inner_and_outer_each_need_exact_absence(self):
        for index in (4, 6):
            rows = event_rows('nested', self.plan)
            rows[index]['absent'] = False
            with self.assertRaises(ValueError):
                self.check('nested', rows)

    def test_eviction_counter_alone_cannot_replace_absence(self):
        rows = event_rows('nested', self.plan)
        rows[4].pop('oldBegin')
        with self.assertRaises((ValueError, KeyError)):
            self.check('nested', rows)

    def test_target_loan_readonly_digest_and_pinned_failures_rejected(self):
        for field, value in (('targetLoans', 1), ('readonly', False), ('digests', False), ('pinned', 4096)):
            rows = event_rows('recursive', self.plan)
            rows[4][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check('recursive', rows)

    def test_jni_stderr_and_stdout_are_both_checked(self):
        with self.assertRaises(ValueError):
            self.check('nested', stderr=b'JNI DETECTED ERROR IN APPLICATION\n')
        with self.assertRaises(ValueError):
            wrapper.validate_run(output(event_rows('nested', self.plan)) + b'WARNING JNI\n', b'', TOKEN, 'nested', self.plan)

    def test_reentry_requires_fixed_semantics(self):
        rows = event_rows('recursive', self.plan)
        rows[-1]['again'] = 0
        with self.assertRaises(ValueError):
            self.check('recursive', rows)

    def test_extra_stdout_and_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):
            wrapper.validate_run(b'extra\n' + output(event_rows('nested', self.plan)), b'', TOKEN, 'nested', self.plan)
        raw = output(event_rows('nested', self.plan)).replace(b'"active": 0', b'"active": 0,"active": 0', 1)
        with self.assertRaises(ValueError):
            wrapper.validate_run(raw, b'', TOKEN, 'nested', self.plan)


class BuildBoundaryTests(unittest.TestCase):
    def test_actual_v1_nounwind_absence_is_recorded_and_unknown_attributes_fail(self):
        header = 'define hidden i32 @wrapper(ptr %0) #0 !ndkp.qseg.lifetime !1 {'
        attributes = 'attributes #0 = { alwaysinline uwtable "aproc-vmp-artifact" "frame-pointer"="non-leaf" }\n'
        self.assertFalse(wrapper.nounwind(attributes, header))
        self.assertTrue(wrapper.nounwind(attributes.replace('alwaysinline', 'alwaysinline nounwind'), header))
        for invalid in ('', attributes + attributes):
            with self.assertRaises(ValueError): wrapper.nounwind(invalid, header)

    def test_registration_only_has_one_reviewable_change(self):
        original = 'extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) {\n' + wrapper.REGISTRATION_END + '\n}\n'
        changed = wrapper.inject_registration(original)
        self.assertTrue(changed.startswith('#include "wrapper_lifetime.cpp"'))
        self.assertEqual(changed.count('wrapper_lifetime_register(env)'), 1)
        for invalid in (original + original, original.replace(wrapper.REGISTRATION_END, 'return 0;'), changed):
            with self.assertRaises(ValueError):
                wrapper.inject_registration(invalid)

    def test_fixture_methods_are_explicit_and_baseline_hooks_disabled(self):
        source, probe = wrapper.fixture_sources()
        self.assertEqual(source.count('@dex2c'), 18)
        self.assertIn('Probe.hit(7,depth); v=v+child+depth*3;', source)
        self.assertIn('if(enabled) observe(event,depth);', probe)
        self.assertNotIn('System.load', probe)
        self.assertNotIn('noexcept', source)
        for name, method in wrapper.METHODS.items():
            self.assertEqual(wrapper.SYMBOLS[name], 'd2c_' + wrapper.sha(method.encode())[:24])

    def test_binary_plan_is_post_signing_data_not_a_generated_include(self):
        plan = plan_fixture()
        binary = wrapper.encode_plan(plan)
        self.assertEqual(struct.unpack_from('<8sIIIIQ', binary), (b'QWRAP01\0', 4096, 1048576, 17, 1, 8192))
        self.assertIn(bytes.fromhex(plan['resources'][0]['prefix']), binary)
        self.assertNotIn('cache_plan.h', wrapper.RUNNER)

    def test_binary_plan_rejects_count_and_size_bounds(self):
        plan = plan_fixture(); plan['resources'].pop()
        with self.assertRaises(ValueError):
            wrapper.encode_plan(plan)
        plan = plan_fixture(); plan['resources'][0]['bytes'] = 1 << 25
        with self.assertRaises(ValueError):
            wrapper.encode_plan(plan)

    def test_fresh_output_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'failure.json').write_text('{}')
            with self.assertRaises(ValueError):
                wrapper.fresh(path)

    def test_verify_is_offline_and_requires_results(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(wrapper.subprocess, 'run', side_effect=AssertionError('must be offline')):
            with self.assertRaises(FileNotFoundError):
                wrapper.verify_results(Path(temporary))


FINAL_BODY = r'''
  %4 = load ptr, ptr @gv_data_seg_wrapper, align 8
  %5 = alloca [315 x i8], align 16
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(315) %5, i8 0, i64 315, i1 false)
  store ptr %5, ptr @gv_data_seg_wrapper, align 8
  %6 = getelementptr inbounds nuw i8, ptr %5, i64 4
  store ptr %0, ptr %6, align 8
  %9 = ptrtoint ptr %5 to i64
  store i64 %9, ptr @vmp_shared_data_seg_addr, align 8
  %10 = call ptr @ndkp_qseg_acquire_v1(ptr nonnull @target_ref)
  %11 = ptrtoint ptr %10 to i64
  store i64 %11, ptr @vmp_shared_code_seg_addr, align 8
  %12 = ptrtoint ptr @gv_code_seg_wrapper to i64
  store i64 %12, ptr @vmp_shared_dispatch_code_seg_addr, align 8
  %13 = load volatile i64, ptr @ndkp_selfcheck_runtime_acc, align 8
  %14 = call ptr @ndkp_qseg_acquire_v1(ptr nonnull @target_ref)
  %15 = call fastcc i64 @ndkp_selfcheck_one(ptr %14, i64 2123, i64 3972896462161274850)
  call void @ndkp_qseg_release_v1(ptr nonnull @target_ref)
  %16 = load volatile i64, ptr @ndkp_cert_k64, align 8
  %17 = xor i64 %13, %15
  %18 = xor i64 %17, %16
  %19 = load volatile i64, ptr @5, align 1
  %20 = add i64 %19, -4696797429435659879
  %21 = xor i64 %18, %20
  store i64 %21, ptr @vmp_shared_vm_function_key, align 8, !ndkp.vmpkey.entry !0
  store i32 0, ptr @vmp_shared_ip, align 4
  store i64 0, ptr @vmp_shared_vm_block_chain_state, align 8
  store i64 0, ptr @vmp_shared_expected_bb_token, align 8
  store i8 0, ptr @vmp_shared_exception_thrown, align 4
  call fastcc void @interpreter()
  call void @ndkp_qseg_release_v1(ptr nonnull @target_ref)
  %22 = load i8, ptr @vmp_shared_exception_thrown, align 4
  %23 = load volatile i8, ptr @4, align 1
  %24 = add i8 %23, 53
  %.not = icmp eq i8 %22, %24
  %25 = select i1 %.not, i32 0, i32 1
  %26 = getelementptr [2 x i32], ptr @wrapper.post.targets, i32 0, i32 %25
  %27 = load volatile i32, ptr %26, align 4
  %28 = sub i32 %27, -1645784768
  %29 = sext i32 %28 to i64
  %30 = getelementptr i8, ptr dso_local_equivalent @wrapper, i64 %29
  indirectbr ptr %30, [label %ndkp.bb, label %ndkp.bb2]

ndkp.bb:
  %31 = load i32, ptr %5, align 16
  store ptr %4, ptr @gv_data_seg_wrapper, align 8
  ret i32 %31

ndkp.bb2:
  store ptr %4, ptr @gv_data_seg_wrapper, align 8
  call fastcc void @vmp_resume_unwind_shared()
  unreachable
'''


class FinalWrapperPathTests(unittest.TestCase):
    def check(self, body=FINAL_BODY):
        return wrapper.final_wrapper_paths(body, 'target_ref', 'interpreter')

    def test_actual_final_indirectbr_shape_closes_both_lease_paths(self):
        paths = self.check()
        self.assertEqual(paths['mainPointer'], '%10')
        self.assertEqual(paths['selfCheckPointers'], ['%14'])
        self.assertEqual(paths['branchKind'], 'indirectbr')
        self.assertEqual({row['exit'] for row in paths['paths']}, {'return', 'resume'})
        self.assertTrue(all(row['exitLeaseDepth'] == 0 for row in paths['paths']))

    def test_missing_main_or_temporary_release_and_foreign_descriptor_fail(self):
        release = '  call void @ndkp_qseg_release_v1(ptr nonnull @target_ref)\n'
        main = '  call fastcc void @interpreter()\n' + release
        mutations = (FINAL_BODY.replace(main, '  call fastcc void @interpreter()\n'),
                     FINAL_BODY.replace(release, '', 1),
                     FINAL_BODY.replace(main, main.replace('@target_ref', '@foreign_ref')),
                     FINAL_BODY.replace('@ndkp_qseg_acquire_v1(ptr nonnull @target_ref)',
                                        '@ndkp_qseg_acquire_v1(ptr nonnull @foreign_ref)', 1))
        for body in mutations:
            with self.assertRaises(ValueError): self.check(body)

    def test_release_moved_to_one_successor_or_before_interpreter_fails(self):
        release = '  call void @ndkp_qseg_release_v1(ptr nonnull @target_ref)\n'
        main = '  call fastcc void @interpreter()\n' + release
        before = FINAL_BODY.replace(main, release + '  call fastcc void @interpreter()\n')
        one_path = FINAL_BODY.replace(main, '  call fastcc void @interpreter()\n').replace('ndkp.bb:\n', 'ndkp.bb:\n' + release)
        for body in (before, one_path):
            with self.assertRaises(ValueError): self.check(body)

    def test_selfcheck_escape_unknown_call_or_successor_is_rejected(self):
        mutations = (FINAL_BODY.replace('ptr %14, i64 2123', 'ptr %10, i64 2123'),
                     FINAL_BODY.replace('%17 = xor', 'store ptr %10, ptr @escaped, align 8\n  %17 = xor'),
                     FINAL_BODY.replace('@interpreter()', '@foreign_interpreter()'),
                     FINAL_BODY.replace('[label %ndkp.bb, label %ndkp.bb2]', '[label %ndkp.bb, label %unknown]'),
                     FINAL_BODY.replace('[label %ndkp.bb, label %ndkp.bb2]', '[label %ndkp.bb, label %ndkp.bb]'))
        for body in mutations:
            with self.assertRaises(ValueError): self.check(body)


def device_report_fixture(root):
    fixture, sdk, java = root / 'fixture', root / 'sdk', root / 'jdk/bin/java.exe'
    fixture.mkdir(); java.parent.mkdir(parents=True); java.write_bytes(b'host-test-java-identity')
    serial, port, remote = 'host-test-serial', 5041, '/data/local/tmp/dex2c-' + TOKEN
    adb = [str(sdk / 'platform-tools/adb.exe'), '-P', str(port), '-s', serial]
    report = {'schemaVersion': 2, 'status': 'passed', 'fixtures': str(fixture), 'serial': serial,
              'deviceCommand': adb, 'remote': remote, 'sdk': '36', 'pageSize': '4096',
              'invocation': [str(Path(wrapper.sys.executable)), str(wrapper.ROOT / 'tests/dex2c/device.py'),
                  '--fixtures', str(fixture), '--sdk', str(sdk), '--java', str(java), '--serial', serial,
                  '--server-port', str(port)],
              'results': [{'main': 'sample.Run', 'mode': mode, 'output': wrapper.EXPECTED.decode().strip()}
                          for mode in ('baseline', 'protected')],
              'negativeCases': [{'mode': mode, 'expectedCodes': [127]} for mode in wrapper.NEGATIVES]}
    for index, mode in enumerate(wrapper.NEGATIVES):
        path = fixture / (mode + '.apk'); path.write_bytes(('host-test-' + mode).encode())
        target, token = remote + '/' + path.name, 'DEX2C_' + format(index, '032x')
        command, child = wrapper.device_helper.negative_command(adb, target, token)
        report['results'].append({'mode': mode, 'rejected': True, 'status': 'expected-exit-signature',
            'expectedCodes': [127], 'exitCode': 127, 'protocolToken': token, 'remoteApk': target,
            'command': command, 'childArgv': child, 'environment': {'CLASSPATH': target},
            'artifact': wrapper.identity(path),
            'push': {'command': [*adb, 'push', str(path), target], 'status': 'completed', 'returnCode': 0,
                     **wrapper.device_helper.streams(b'', b'')},
            'execution': {'command': command, 'status': 'completed', 'returnCode': 0,
                          **wrapper.device_helper.streams(b'', (token + ':BEGIN\n' + token + ':EXIT:127\n').encode())}})
    report['pushed'] = [remote + '/' + name for name in ('baseline.zip', 'protected.apk', 'protected.zip',
                        'libdex2c_semantics.so', *(mode + '.apk' for mode in wrapper.NEGATIVES))]
    report['cleanup'] = [{'command': argv, 'status': 'completed', 'returnCode': 0} for argv in
        ([*adb, 'shell', 'rm', '-f', *report['pushed']], [*adb, 'shell', 'rmdir', remote])]
    return fixture, sdk, java, serial, port, report


class DeviceReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.fixture, self.sdk, self.java, self.serial, self.port, self.report = device_report_fixture(Path(self.temporary.name))

    def check(self):
        path = self.fixture / 'device-results.json'
        path.write_text(json.dumps(self.report), 'utf-8')
        return wrapper.verify_device_report(path, self.fixture, self.sdk, self.java, self.serial, self.port)

    def test_full_fixed_negative_denominator_passes_without_executing(self):
        with patch.object(wrapper.subprocess, 'run', side_effect=AssertionError('offline')):
            self.assertEqual(self.check()['status'], 'passed')

    def test_invocation_jdk_port_fixture_and_reference_options_rejected(self):
        original = copy.deepcopy(self.report)
        for option, value in (('--java', str(self.java.with_name('other.exe'))), ('--server-port', '5037'),
                              ('--fixtures', str(self.sdk)), ('--native-reference', 'reference.so')):
            with self.subTest(option=option):
                self.report = copy.deepcopy(original)
                args = self.report['invocation']
                if option in args: args[args.index(option) + 1] = value
                else: args.extend([option, value])
                with self.assertRaises(ValueError): self.check()

    def test_negative_exit_raw_push_and_cleanup_mutations_rejected(self):
        mutations = (
            lambda r: r['results'][2].update(exitCode=137),
            lambda r: r['results'][2].update(expectedCodes=[127, 137]),
            lambda r: r['results'][2]['execution'].update(stderrBase64=''),
            lambda r: r['results'][2]['push'].update(returnCode=1),
            lambda r: r['results'][2]['push']['command'].append('foreign'),
            lambda r: r['results'][3].update(protocolToken=r['results'][2]['protocolToken']),
            lambda r: r['results'].pop(),
            lambda r: r['cleanup'][0]['command'].append('foreign'),
            lambda r: r['cleanup'][1].update(returnCode=1),
        )
        original = copy.deepcopy(self.report)
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.report = copy.deepcopy(original); mutate(self.report)
                with self.assertRaises(ValueError): self.check()

    def test_changed_negative_artifact_is_rejected(self):
        (self.fixture / 'wrong-signer.apk').write_bytes(b'replaced')
        with self.assertRaises(ValueError): self.check()


class OfflineReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        fixture, sdk, java, serial, port, device_report = device_report_fixture(root)
        wrapper.write_json(fixture / 'device-results.json', device_report)
        build = {'inputsBefore': wrapper.identities([java]), 'artifacts': wrapper.identities([fixture / 'wrong-signer.apk'])}
        wrapper.write_json(fixture / 'build.json', build)
        self.path = root / 'observation'; self.path.mkdir()
        plan = plan_fixture(); self.expected_plan = copy.deepcopy(plan)
        wrapper.write_json(self.path / 'plan.json', plan)
        (self.path / 'plan.bin').write_bytes(wrapper.encode_plan(plan))
        fixed = wrapper.identities([fixture / 'build.json', fixture / 'device-results.json', java])
        self.report = {'schemaVersion': 1, 'checkerRevision': 1, 'status': 'passed', 'callRoute': 'ART/JNI',
            'productionWrapperExecution': True, 'nativeDirectHandlerExecution': False, 'directWipeObservation': False,
            'inputsBefore': fixed, 'inputsAfter': fixed, 'fixture': str(fixture), 'sdk': str(sdk), 'java': str(java),
            'ndk': str(root / 'ndk'), 'serial': serial, 'serverPort': port,
            'remote': '/data/local/tmp/qseg-wrapper-' + TOKEN,
            'device': {'model': 'host-test-model', 'sdk': '36', 'pageSize': '4096', 'arch': 'aarch64'},
            'plan': wrapper.identity(self.path / 'plan.json'), 'binaryPlan': wrapper.identity(self.path / 'plan.bin'),
            'runs': [{'case': case, 'token': wrapper.sha(case.encode())[:32]} for case in wrapper.EVENTS]}
        commands = wrapper.Commands(self.path, wrapper.ROOT)
        for label, argv in wrapper.expected_commands(self.report, self.path).items():
            if label.startswith('device-'):
                stdout = (self.report['device'][label[7:]] + '\n').encode()
            elif label.startswith('normal-'):
                stdout = wrapper.EXPECTED
            elif label in wrapper.EVENTS:
                run = next(r for r in self.report['runs'] if r['case'] == label)
                run['events'] = event_rows(label, plan, run['token']); stdout = output(run['events'])
            else: stdout = b''
            completed = wrapper.subprocess.CompletedProcess(argv, 0, stdout, b'')
            with patch.object(wrapper.subprocess, 'run', return_value=completed): commands.checked(label, argv)
            if label in wrapper.EVENTS: run['command'] = commands.records[-1]
        self.report['commands'] = commands.records
        self.report['normal'] = [{'mode': mode, 'command': next(ref for ref in commands.records if 'normal-' + mode in ref)}
                                 for mode in ('baseline', 'protected')]
        self.report['cleanup'] = commands.records[-2:]
        self.report['artifacts'] = wrapper.identities(wrapper.tree_files(self.path))

    def check(self):
        with patch.object(wrapper.subprocess, 'run', side_effect=AssertionError('offline')), \
             patch.object(wrapper, 'rebuild_plan', return_value=copy.deepcopy(self.expected_plan)):
            return wrapper.verify_report(self.path, self.report)

    def change_record(self, index, field, value):
        path = self.path / self.report['commands'][index]
        row = wrapper.read_json(path); row[field] = value
        path.write_text(json.dumps(row), 'utf-8')
        # Exercise the semantic gate even when the untrusted manifest is refreshed.
        self.report['artifacts'][str(path)] = wrapper.identity(path)

    def test_complete_report_replays_without_subprocess(self):
        self.assertEqual(self.check()['status'], 'passed')

    def test_unencoded_apk_method_and_symbol_fields_are_rebound(self):
        path = self.path / 'plan.json'
        mutations = (lambda p: p.update(apkSha256='ff' * 32),
                     lambda p: p.update(libraryEntry='lib/arm64-v8a/foreign.so'),
                     lambda p: p['resources'][0].update(method='foreign/Run.outer(I)I'),
                     lambda p: p['resources'][0].update(symbol='foreign_symbol'))
        binary = (self.path / 'plan.bin').read_bytes()
        for mutate in mutations:
            changed = copy.deepcopy(self.expected_plan); mutate(changed)
            path.write_text(json.dumps(changed), 'utf-8')
            self.report['plan'] = self.report['artifacts'][str(path)] = wrapper.identity(path)
            self.assertEqual(wrapper.encode_plan(changed), binary)
            with self.assertRaisesRegex(ValueError, 'plan differs from final APK'):
                self.check()

    def test_exact_argv_cwd_timeout_and_command_failure_rejected(self):
        for field, value in (('argv', ['foreign']), ('cwd', str(self.path)), ('timeoutSeconds', 600), ('returncode', 1)):
            with self.subTest(field=field):
                path = self.path / self.report['commands'][0]; saved = path.read_bytes()
                self.change_record(0, field, value)
                with self.assertRaises(ValueError): self.check()
                path.write_bytes(saved); self.report['artifacts'][str(path)] = wrapper.identity(path)

    def test_duplicate_order_and_cleanup_reference_rejected(self):
        original = copy.deepcopy(self.report)
        for mutate in (lambda r: r['commands'].append(r['commands'][0]),
                       lambda r: r['commands'].reverse(), lambda r: r['cleanup'].pop()):
            self.report = copy.deepcopy(original); mutate(self.report)
            with self.assertRaises(ValueError): self.check()

    def test_raw_stream_device_token_and_failure_file_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['device']['pageSize'] = '16384'
        with self.assertRaises(ValueError): self.check()
        self.report = copy.deepcopy(original); self.report['runs'][1]['token'] = self.report['runs'][0]['token']
        with self.assertRaises(ValueError): self.check()
        self.report = copy.deepcopy(original)
        (self.path / 'failure.json').write_text('{}')
        with self.assertRaises(ValueError): self.check()
        (self.path / 'failure.json').unlink()
        row = wrapper.read_json(self.path / self.report['normal'][0]['command'])
        Path(row['stderr']['path']).write_bytes(b'JNI DETECTED ERROR IN APPLICATION\n')
        with self.assertRaises(ValueError): self.check()


class PlanRebuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name); native = self.fixture / 'native'; native.mkdir()
        self.contract, receipt, self.resources = fixture_resources()
        library = bytearray(test_seal_cse.elf(bytes(512)))
        for index, name in enumerate((*wrapper.TARGETS, *(f'work{i}' for i in range(wrapper.PRESSURE_COUNT)))):
            item = self.contract[name]; address = 0x1100 + index * 32
            library[address:address + 24] = bytes.fromhex(item['id']) + struct.pack('<II', item['bytes'], 1)
        self.asset = 'assets/dex2c_semantics.qseg'
        library[0x2100:0x2100 + len(self.asset) + 1] = self.asset.encode() + b'\0'
        self.library = bytes(library); (native / 'linked.so').write_bytes(self.library)
        (native / 'signing-cert.der').write_bytes(b'host-test-certificate')
        wrapper.write_json(native / 'segments.json', receipt)
        wrapper.write_json(native / 'protection.json', {'qsegLifetimeAbi': 1,
            'idlePlaintextBudgetBytes': wrapper.BUDGET, 'apkSignatureVerification': True,
            'librarySha256': wrapper.sha(self.library), 'containerSha256': wrapper.sha(b'host-test-container')})
        self.entry = 'lib/arm64-v8a/libdex2c_semantics.so'
        with wrapper.zipfile.ZipFile(self.fixture / 'protected.apk', 'w') as archive:
            archive.writestr(self.entry, self.library); archive.writestr(self.asset, b'host-test-container')
        self.audited = {'libraries': [{'name': self.entry, 'sha256': wrapper.sha(self.library)}],
                        'apkSha256': wrapper.sha((self.fixture / 'protected.apk').read_bytes())}
        self.nm = b''.join(f'{0x1400 + i * 4:016x} T {name}\n'.encode() for i, name in enumerate(
            ('ndkp_qseg_acquire_v1', 'ndkp_qseg_release_v1', 'ndkp_qseg_stats_v1', 'JNI_OnLoad')))

    def check(self):
        with patch.object(wrapper.subprocess, 'run', side_effect=AssertionError('offline')), \
             patch.object(wrapper, 'bind_wrappers', return_value=copy.deepcopy(self.contract)) as binding, \
             patch.object(wrapper.cache, 'audit', return_value=self.audited) as authentication, \
             patch.object(wrapper.cache.qseg, 'locate_image', return_value=(None, 0x2000)), \
             patch.object(wrapper.cache.qseg, 'unpack', return_value=self.resources) as unpack:
            plan = wrapper.rebuild_plan(self.fixture, self.nm)
            binding.assert_called_once_with(self.fixture)
            native = self.fixture / 'native'
            authentication.assert_called_once_with(self.fixture / 'protected.apk', native / 'protection.json',
                                                     native / 'segments.json', native / 'signing-cert.der')
            unpack.assert_called_once_with(self.library, b'host-test-container', b'host-test-certificate')
            return plan

    def test_final_bytes_exact_methods_descriptors_and_rx_are_shared_offline(self):
        plan = self.check()
        self.assertEqual(plan['apkSha256'], self.audited['apkSha256'])
        self.assertEqual(plan['librarySha256'], wrapper.sha(self.library))
        self.assertEqual(plan['onloadRva'], 0x140c)
        self.assertEqual(plan['executableSpans'][0]['sha256'], wrapper.sha(self.library[0x1000:0x2000]))
        for index, row in enumerate(plan['resources']):
            self.assertEqual(row['method'], wrapper.METHODS[row['name']])
            self.assertEqual(row['symbol'], wrapper.SYMBOLS[row['name']])
            self.assertEqual(row['address'], 0x1100 + index * 32)

    def test_recorded_nm_required_symbols_missing_or_duplicate_are_rejected(self):
        original = self.nm
        for changed in (original + original.splitlines(keepends=True)[0], original.split(b'\n', 1)[1]):
            self.nm = changed
            with self.assertRaises(ValueError): self.check()

    def test_linked_rx_drift_is_rejected(self):
        path = self.fixture / 'native/linked.so'; raw = bytearray(path.read_bytes()); raw[0x1500] ^= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'executable load bytes differ'): self.check()

    def test_authentication_failure_is_not_replaced_by_plan_metadata(self):
        with patch.object(wrapper, 'bind_wrappers', return_value=self.contract), \
             patch.object(wrapper.cache, 'audit', side_effect=ValueError('authenticated recovery failed')), \
             patch.object(wrapper.subprocess, 'run', side_effect=AssertionError('offline')):
            with self.assertRaisesRegex(ValueError, 'authenticated recovery failed'):
                wrapper.rebuild_plan(self.fixture, self.nm)


if __name__ == '__main__':
    unittest.main()
