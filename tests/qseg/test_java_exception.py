"""Host checks for the evidence boundaries; no compiler or device is invoked."""
import copy
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import java_exception as exception
from test_compiler_lifetime import fixture as compiler_fixture
from test_wrapper_lifetime import FINAL_BODY

sys.path.insert(0, str(exception.ROOT / 'tests/cse-hardened'))
import test_seal_cse


TOKEN = exception.sha(b'java-exception-test-token')[:32]


def fixture_resources():
    contract, receipt, raw_resources = {}, {'segments': []}, {}
    for index, name in enumerate(exception.METHODS):
        size = 128 if name in (*exception.TARGETS, 'marker') else 80000
        raw = bytes([index + 1]) * size
        identity = format(index + 1, '032x')
        contract[name] = {'method': exception.METHODS[name], 'symbol': exception.SYMBOLS[name],
                          'id': identity, 'bytes': size, 'sha256': exception.sha(raw)}
        raw_resources[bytes.fromhex(identity), 1] = raw
        for number, offset in enumerate(range(0, size, 65536)):
            chunk = raw[offset:offset + 65536]
            receipt['segments'].append({'id': identity, 'kind': 1, 'name': exception.SYMBOLS[name],
                'lifetime': 'lease-v1', 'chunk': number, 'bytes': len(chunk), 'sha256': exception.sha(chunk),
                'resourceSha256': exception.sha(raw), 'codec': 1})
    return contract, receipt, raw_resources


def plan_fixture():
    contract, receipt, raw = fixture_resources()
    methods = exception.authenticated_methods(contract, receipt, raw)
    resources = exception.observed_resources(methods, receipt)
    for index, item in enumerate(resources):
        item['address'] = 0x1000 + index * 32
    return {'schemaVersion': 1, 'resources': resources, 'methodBindings': methods, 'onloadRva': 0x2000,
            'apkSha256': 'a1' * 32, 'libraryEntry': 'lib/arm64-v8a/libdex2c_semantics.so',
            'librarySha256': 'b2' * 32, 'containerSha256': 'c3' * 32,
            'pageSize': exception.PAGE, 'idleBudgetBytes': exception.BUDGET,
            'executableSpans': [{'address': 0x1000, 'bytes': 0x3000, 'sha256': '12' * 32}]}


def event_rows(case, plan, token=TOKEN):
    base = {'token': token, 'case': case, 'active': 0, 'idle': 4096, 'pinned': 0,
            'peak': exception.BUDGET, 'evictions': 0, 'targetLoans': 0,
            'pendingClear': True, 'sentinelIdentity': True, 'caughtIdentity': False}
    rows = [{**base, 'seq': 0, 'event': 0, 'depth': 0}]
    for sequence, (event, depth) in enumerate(exception.EVENTS[case], 1):
        row = {**base, 'seq': sequence, 'event': event, 'depth': depth,
               'active': exception.expected_active(case, event, plan), 'evictions': sequence,
               'caughtIdentity': event == 3 or (event == 4 and case == 'rethrow'),
               'steps': exception.PRESSURE_COUNT, 'readonly': True, 'digests': True}
        if event in (1, 2):
            index = 0 if event == 2 else 1 if case == 'caught' else 2
            row.update(discovered=plan['resources'][index]['id'],
                       discoveredBegin=hex((index + 1) * 0x10000),
                       discoveredBytes=plan['resources'][index]['mappedBytes'])
        if event in (3, 4):
            index = 0 if event == 3 else 1 if case == 'caught' else 2
            row.update(reclaimed=plan['resources'][index]['id'], absent=True,
                       oldBegin=hex((index + 1) * 0x10000), oldBytes=plan['resources'][index]['mappedBytes'],
                       releasedReadonly=True, steps=3)
        rows.append(row)
    expected = 73 if case == 'caught' else 91
    rows.append({**base, 'seq': 5, 'event': 10, 'depth': 0, 'evictions': 5,
                 'first': expected, 'again': expected, 'semanticReentry': True})
    return rows


def output(rows):
    return b''.join(b'QSEG_JAVA_EXCEPTION:' + json.dumps(row).encode() + b'\n' for row in rows)


def control_streams(case, token, plan):
    stdout = output(event_rows('rethrow', plan, token)[:1])
    stderr = (token + ':BEGIN\nQSEG_JAVA_EXCEPTION_CONTROL:' + token + ':' + case + ':ATTEMPT\n' +
              'QSEG_JAVA_EXCEPTION_FAIL:' + token + ':' + exception.CONTROLS[case] + '\n\n' + token + ':EXIT:125\n').encode()
    return stdout, stderr


class ResourceContractTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.receipt, self.resources = fixture_resources()

    def select(self):
        return exception.select_resources(self.contract, self.receipt, self.resources)

    def test_explicit_targets_and_all_pressure(self):
        selected = self.select()
        self.assertEqual([item['name'] for item in selected[:3]], list(exception.TARGETS))
        self.assertEqual([item['name'] for item in selected[3:]], [f'work{i}' for i in range(14)])
        self.assertGreater(sum(item['mappedBytes'] for item in selected[3:]), exception.BUDGET)
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
        key = bytes.fromhex(self.contract['exceptionLeaf']['id']), 1
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
        self.assertEqual(selected[0]['id'], self.contract['exceptionLeaf']['id'])
        self.assertEqual(selected[1]['id'], self.contract['caughtOuter']['id'])
        self.assertEqual(selected[2]['id'], self.contract['rethrowOuter']['id'])

    def test_marker_is_authenticated_even_though_not_observed(self):
        marker = self.contract['marker']['id']
        self.assertNotIn('marker', [r['name'] for r in self.select()])
        original = copy.deepcopy(self.receipt)
        for field, value in (('lifetime', 'pinned-unproven-unwind'), ('name', 'foreign'), ('sha256', '00' * 32)):
            self.receipt = copy.deepcopy(original)
            next(r for r in self.receipt['segments'] if r['id'] == marker)[field] = value
            with self.assertRaises(ValueError): self.select()
        self.receipt = copy.deepcopy(original)
        self.resources[bytes.fromhex(marker), 1] = b'x' * self.contract['marker']['bytes']
        with self.assertRaises(ValueError): self.select()

    def test_extra_vm_and_duplicate_identity_fail_all18_denominator(self):
        extra = copy.deepcopy(self.receipt['segments'][0]); extra['id'] = 'ff' * 16
        self.receipt['segments'].append(extra)
        with self.assertRaises(ValueError): self.select()
        self.receipt['segments'].pop()
        self.contract['marker']['id'] = self.contract['exceptionLeaf']['id']
        with self.assertRaises(ValueError): self.select()

    def resize(self, name, size):
        item = self.contract[name]; raw = b'changed-product-' * (size // 16 + 1); raw = raw[:size]
        item.update(bytes=size, sha256=exception.sha(raw))
        self.resources[bytes.fromhex(item['id']), 1] = raw
        self.receipt['segments'] = [r for r in self.receipt['segments'] if r['id'] != item['id']]
        for number, offset in enumerate(range(0, size, 65536)):
            chunk = raw[offset:offset + 65536]
            self.receipt['segments'].append({'id': item['id'], 'kind': 1, 'name': item['symbol'], 'lifetime': 'lease-v1',
                                            'chunk': number, 'bytes': len(chunk), 'sha256': exception.sha(chunk),
                                            'resourceSha256': exception.sha(raw), 'codec': 1})

    def test_product_pair_budgets_and_independent_pressure_bounds(self):
        self.resize('caughtOuter', 700000); self.resize('rethrowOuter', 700000)
        # The mutually exclusive outers need not fit at the same time.
        self.assertEqual(len(self.select()), 17)
        self.resize('exceptionLeaf', exception.BUDGET)
        with self.assertRaisesRegex(ValueError, 'target set'): self.select()
        self.resize('exceptionLeaf', 128); self.resize('work0', exception.BUDGET + 1)
        with self.assertRaisesRegex(ValueError, 'pressure resource'): self.select()
        for index in range(14): self.resize('work' + str(index), 128)
        with self.assertRaisesRegex(ValueError, 'pressure VMs'): self.select()


class EventEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()

    def check(self, case='caught', rows=None, stderr=b''):
        rows = event_rows(case, self.plan) if rows is None else rows
        return exception.validate_run(output(rows), stderr, TOKEN, case, self.plan)

    def test_both_exact_six_event_cases(self):
        for case in exception.EVENTS:
            rows = self.check(case)
            self.assertEqual(len(rows), 6)
            self.assertEqual([(r['event'], r['depth']) for r in rows], [(0, 0), (1, 0), (2, 1), (3, 0), (4, 0), (10, 0)])
            self.assertEqual([r['steps'] for r in rows[1:3]], [14, 14])

    def test_missing_duplicate_reordered_wrong_token_and_depth_rejected(self):
        mutations = (lambda r: r.pop(2), lambda r: r.insert(2, copy.deepcopy(r[2])),
                     lambda r: r.reverse(), lambda r: r[2].update(token='f' * 32),
                     lambda r: r[2].update(depth=0), lambda r: r[4].update(seq=3))
        for mutate in mutations:
            rows = event_rows('caught', self.plan); mutate(rows)
            with self.assertRaises(ValueError): self.check(rows=rows)

    def test_every_event_checks_pending_identity_active_pinned_and_target_loans(self):
        for case in exception.EVENTS:
            for index in range(6):
                for field, value in (('pendingClear', False), ('sentinelIdentity', False),
                                     ('caughtIdentity', not event_rows(case, self.plan)[index]['caughtIdentity']),
                                     ('active', 12345), ('pinned', 4096), ('targetLoans', 1), ('idle', exception.BUDGET + 1)):
                    with self.subTest(case=case, event=index, field=field):
                        rows = event_rows(case, self.plan); rows[index][field] = value
                        with self.assertRaises(ValueError): self.check(case, rows)

    def test_numeric_booleans_missing_identity_or_unknown_fields_rejected(self):
        for field, value in (('active', False), ('sentinelIdentity', 1), ('targetLoans', False), ('foreign', True)):
            rows = event_rows('caught', self.plan); rows[2][field] = value
            with self.assertRaises(ValueError): self.check(rows=rows)
        rows = event_rows('caught', self.plan); rows[3].pop('caughtIdentity')
        with self.assertRaises(ValueError): self.check(rows=rows)

    def test_all_pressure_and_first_absence_reclamation_are_distinct(self):
        for index in range(1, 5):
            for field, value in (('steps', 0), ('steps', 15), ('evictions', 0), ('readonly', False), ('digests', False)):
                rows = event_rows('caught', self.plan); rows[index][field] = value
                with self.assertRaises(ValueError): self.check(rows=rows)
        for index in (1, 2):
            rows = event_rows('caught', self.plan); rows[index]['steps'] = 13
            with self.assertRaises(ValueError): self.check(rows=rows)
        for index in (3, 4):
            for field, value in (('reclaimed', 'f' * 32), ('absent', False), ('releasedReadonly', False),
                                 ('oldBegin', '0x10001'), ('oldBytes', 8192)):
                rows = event_rows('caught', self.plan); rows[index][field] = value
                with self.assertRaises(ValueError): self.check(rows=rows)

    def test_leaf_outer_old_intervals_must_be_distinct_and_nonoverlapping(self):
        rows = event_rows('caught', self.plan); rows[4]['oldBegin'] = rows[3]['oldBegin']
        rows[1]['discoveredBegin'] = rows[4]['oldBegin']
        with self.assertRaises(ValueError): self.check(rows=rows)
        self.plan['resources'][0]['mappedBytes'] = 8192
        rows = event_rows('caught', self.plan); rows[4]['oldBegin'] = hex(int(rows[3]['oldBegin'], 16) + 4096)
        rows[1]['discoveredBegin'] = rows[4]['oldBegin']
        with self.assertRaises(ValueError): self.check(rows=rows)

    def test_released_intervals_must_match_first_discovery_in_both_cases(self):
        for case in exception.EVENTS:
            for index in (3, 4):
                rows = event_rows(case, self.plan)
                rows[index]['oldBegin'] = hex(int(rows[index]['oldBegin'], 16) + 0x100000)
                with self.subTest(case=case, event=index), self.assertRaisesRegex(ValueError, 'first discovered'):
                    self.check(case, rows)
            for index in (1, 2):
                rows = event_rows(case, self.plan)
                rows[index]['discoveredBegin'] = hex(int(rows[index]['discoveredBegin'], 16) + 0x100000)
                with self.subTest(case=case, discovered=index), self.assertRaisesRegex(ValueError, 'first discovered'):
                    self.check(case, rows)

    def test_first_discovery_identity_dimensions_fields_and_bounds_are_exact(self):
        for case in exception.EVENTS:
            for index in (1, 2):
                for field, value in (('discovered', 'f' * 32), ('discoveredBegin', '0x10001'),
                                     ('discoveredBegin', 65536), ('discoveredBegin', '0x10000000000000000'),
                                     ('discoveredBytes', True), ('discoveredBytes', 8192)):
                    rows = event_rows(case, self.plan); rows[index][field] = value
                    with self.subTest(case=case, event=index, field=field, value=value), self.assertRaises(ValueError):
                        self.check(case, rows)
                for field in ('discovered', 'discoveredBegin', 'discoveredBytes'):
                    rows = event_rows(case, self.plan); rows[index].pop(field)
                    with self.subTest(case=case, event=index, missing=field), self.assertRaises(ValueError):
                        self.check(case, rows)

    def test_default_native_return_is_never_semantic_success(self):
        for case in exception.EVENTS:
            for field in ('first', 'again'):
                rows = event_rows(case, self.plan); rows[-1][field] = 0
                with self.assertRaises(ValueError): self.check(case, rows)

    def test_both_raw_streams_extra_lines_duplicate_json_and_truncation_rejected(self):
        with self.assertRaises(ValueError): self.check(stderr=b'JNI DETECTED ERROR IN APPLICATION\n')
        raw = output(event_rows('caught', self.plan))
        for changed in (b'WARNING JNI\n' + raw, raw.replace(b'"active": 0', b'"active":0,"active":0', 1), raw[:-1]):
            with self.assertRaises(ValueError): exception.validate_run(changed, b'', TOKEN, 'caught', self.plan)


class ControlEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()

    def test_both_token_bound_controls_need_configure_attempt_diagnostic_and125(self):
        for case in exception.CONTROLS:
            streams = control_streams(case, TOKEN, self.plan)
            self.assertEqual(exception.validate_control(*streams, TOKEN, case)['exitCode'], 125)

    def test_exitcode_alone_launch_transport_signal_and_wrong_diagnostic_rejected(self):
        out, err = control_streams('reject-substitute', TOKEN, self.plan)
        for changed in (err.replace(b':ATTEMPT', b':OMITTED'), err.replace(b':EXIT:125', b':EXIT:137'),
                        err.replace(b':BEGIN', b':LAUNCH_FAILED'), err.replace(b'identity differs', b'message differs'),
                        err + b'WARNING JNI\n', err.replace(TOKEN.encode(), b'f' * 32, 1), err.splitlines(keepends=True)[-1]):
            with self.assertRaises(ValueError): exception.validate_control(out, changed, TOKEN, 'reject-substitute')
        with self.assertRaises(ValueError): exception.validate_control(out + out, err, TOKEN, 'reject-substitute')
        with self.assertRaises(ValueError): exception.validate_control(out, err, TOKEN, 'reject-pending')

    def test_control_command_is_same_signed_apk_new_app_process_and_exact_child(self):
        command, child = exception.control_command(['adb', '-P', '5038', '-s', 'device'], '/data/local/tmp/qseg-java-exception-' + TOKEN,
                                                   'reject-pending', TOKEN)
        self.assertEqual(command[:6], ['adb', '-P', '5038', '-s', 'device', 'shell'])
        self.assertIn('-Xcheck:jni', child)
        self.assertEqual(child[-3:], ['reject-pending', TOKEN, '/data/local/tmp/qseg-java-exception-' + TOKEN + '/plan.bin'])
        self.assertIn('trap ', command[-1]); self.assertIn(' exec ', command[-1]); self.assertIn(':EXIT', command[-1])


class BuildBoundaryTests(unittest.TestCase):
    def test_actual_v1_nounwind_absence_is_recorded_and_unknown_attributes_fail(self):
        header = 'define hidden i32 @wrapper(ptr %0) #0 !ndkp.qseg.lifetime !1 {'
        attributes = 'attributes #0 = { alwaysinline uwtable "aproc-vmp-artifact" "frame-pointer"="non-leaf" }\n'
        self.assertFalse(exception.nounwind(attributes, header))
        self.assertTrue(exception.nounwind(attributes.replace('alwaysinline', 'alwaysinline nounwind'), header))
        for invalid in ('', attributes + attributes):
            with self.assertRaises(ValueError): exception.nounwind(invalid, header)

    def test_registration_only_has_one_reviewable_change(self):
        original = 'extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) {\n' + exception.REGISTRATION_END + '\n}\n'
        changed = exception.inject_registration(original)
        self.assertTrue(changed.startswith('#include "java_exception.cpp"'))
        self.assertEqual(changed.count('java_exception_register(env)'), 1)
        for invalid in (original + original, original.replace(exception.REGISTRATION_END, 'return 0;'), changed):
            with self.assertRaises(ValueError):
                exception.inject_registration(invalid)

    def test_fixture_methods_are_explicit_and_baseline_hooks_disabled(self):
        source, probe = exception.fixture_sources()
        self.assertEqual(source.count('@dex2c'), 18)
        self.assertIn('Probe.hit(2,supplied,null); throw supplied;', source)
        self.assertIn('throw new AssertionError("outer returned normally")', source)
        self.assertEqual(source.count('if(caught!=supplied) return -12;'), 2)
        self.assertIn('if(enabled) observe(event,supplied,caught);', probe)
        self.assertNotIn('System.load', probe)
        self.assertNotIn('noexcept', source)
        for name, method in exception.METHODS.items():
            self.assertEqual(exception.SYMBOLS[name], 'd2c_' + exception.sha(method.encode())[:24])

    def test_binary_plan_is_post_signing_data_not_a_generated_include(self):
        plan = plan_fixture()
        binary = exception.encode_plan(plan)
        self.assertEqual(struct.unpack_from('<8sIIIIQ', binary), (b'QJEX01\0\0', 4096, 1048576, 17, 1, 8192))
        self.assertIn(bytes.fromhex(plan['resources'][0]['prefix']), binary)
        self.assertNotIn('cache_plan.h', exception.RUNNER)

    def test_binary_plan_rejects_count_and_size_bounds(self):
        plan = plan_fixture(); plan['resources'].pop()
        with self.assertRaises(ValueError):
            exception.encode_plan(plan)
        plan = plan_fixture(); plan['resources'][0]['bytes'] = 1 << 25
        with self.assertRaises(ValueError):
            exception.encode_plan(plan)

    def test_fresh_output_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'failure.json').write_text('{}')
            with self.assertRaises(ValueError):
                exception.fresh(path)

    def test_verify_is_offline_and_requires_results(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(exception.subprocess, 'run', side_effect=AssertionError('must be offline')):
            with self.assertRaises(FileNotFoundError):
                exception.verify_results(Path(temporary))

    def test_observer_cannot_borrow_targets_and_pending_is_first_jni_operation(self):
        source = Path(exception.__file__).with_suffix('.cpp').read_text('utf-8')
        _, configure = exception.cpp_function(source, 'void configure(JNIEnv* env, jclass, jbyteArray input, jstring run_token, jint run_mode, jobject supplied) {')
        _, observe = exception.cpp_function(source, 'void observe(JNIEnv* env, jclass, jint event, jobject supplied, jobject caught) {')
        self.assertNotIn('ndkp_qseg_acquire', configure)
        self.assertNotIn('ndkp_qseg_get', configure)
        self.assertNotIn('ndkp_qseg_get', observe)
        self.assertEqual(re.findall(r'env->(\w+)\(', observe)[0], 'ExceptionCheck')
        self.assertEqual(observe.count('ndkp_qseg_acquire_v1(ref(resources[i]))'), 1)
        self.assertIn('for (size_t i = 3; i < Count; ++i)', observe)
        self.assertIn('if (after_acquire) resources[reclaim].live = 0;', observe)
        self.assertLess(observe.index('if (absent) break;'), observe.index('print_start(event'))

    def test_actual_released_interval_gate_rejects_partial_overlap_and_permission_drift(self):
        source = Path(exception.__file__).with_suffix('.cpp').read_text('utf-8')
        _, interval = exception.cpp_function(source, 'bool interval(uintptr_t begin, size_t size, bool absent) {')
        match = re.search(r'require\((.+), "released target partial overlap or permission drift"\);', interval)
        self.assertIsNotNone(match)
        expression = match[1].replace('!', ' not ').replace('||', ' or ').replace('&&', ' and ')
        # Evaluate the actual native rejection expression against independently described map coverage.
        cases = (([], True), ([(0x1000, 0x3000, 'r--p')], True),
                 ([(0x1000, 0x2000, 'r--p'), (0x2000, 0x3000, 'r--p')], True),
                 ([(0x1000, 0x2000, 'r--p')], False), ([(0x2000, 0x3000, 'r--p')], False),
                 ([(0x1000, 0x3000, 'rw-p')], False),
                 ([(0x1000, 0x2000, 'r--p'), (0x2000, 0x3000, 'rw-p')], False))
        for mappings, accepted in cases:
            pieces = [(max(left, 0x1000), min(right, 0x3000), perm) for left, right, perm in mappings
                      if left < 0x3000 and right > 0x1000]
            coverage = sorted(pieces)
            complete = bool(coverage) and coverage[0][0] == 0x1000 and coverage[-1][1] == 0x3000 and all(
                a[1] == b[0] for a, b in zip(coverage, coverage[1:]))
            state = {'overlap': bool(pieces), 'readonly': complete and all(p[2] == 'r--p' for p in pieces),
                     'covered': max((p[1] for p in pieces), default=0x1000), 'end': 0x3000}
            self.assertEqual(bool(eval(expression, {'__builtins__': {}}, state)), accepted)


def emitted_method(name):
    entry = ['d2c_frame* f = d2c_open(env, owner, 16);', 'if (!f) return 0;',
             'd2c_ref(f, 0, env->NewLocalRef(a0));', 'if (env->ExceptionCheck()) goto failed;']
    statements, exceptional = [], {}

    def line(label, text, checked=False, catches=False):
        statements.extend(['L' + str(label) + ':;', text])
        if checked:
            statements.append('if (env->ExceptionCheck()) goto E' + str(label) + ';')
            exceptional[label] = catches

    hit = 'd2c_invoke(f,2,"sample/Probe","hit","(ILjava/lang/Throwable;Ljava/lang/Throwable;)V",0,3);'
    result = '{ jint result=(jint)f->slots[2].v.i; d2c_close(f,nullptr); return result; }'
    if name == 'exceptionLeaf':
        line(0, 'd2c_i(f, 2, 2);')
        line(1, 'd2c_copy(f, 3, 0);', True)
        line(2, 'd2c_ref(f,4,nullptr);')
        line(3, hit, True)
        line(4, 'd2c_copy(f, 2, 0);', True)
        line(5, 'd2c_throw(f,f->slots[2].v.l);', True)
    else:
        line(0, 'd2c_i(f, 2, 1);')
        line(1, 'd2c_copy(f, 3, 0);', True)
        line(2, 'd2c_ref(f,4,nullptr);')
        line(3, hit, True)
        line(4, 'd2c_copy(f, 2, 0);', True, True)
        line(5, 'd2c_invoke(f,2,"sample/Run","exceptionLeaf","(Ljava/lang/IllegalStateException;)I",0,1);', True, True)
        line(6, result)
        line(7, 'd2c_copy(f, 1, 2);', True)
        line(8, 'd2c_i(f, 2, -11);')
        line(9, result)
        line(10, 'd2c_copy(f, 1, 2);', True)
        line(11, 'd2c_copy(f, 2, 1);', True)
        line(12, 'd2c_copy(f, 3, 0);', True)
        line(13, 'if (env->IsSameObject(f->slots[2].v.l,f->slots[3].v.l)) goto L16;')
        line(14, 'd2c_i(f, 2, -12);')
        line(15, result)
        line(16, 'd2c_i(f, 2, 3);')
        line(17, 'd2c_copy(f, 3, 0);', True)
        line(18, 'd2c_copy(f, 4, 1);', True)
        line(19, hit, True)
        line(20, 'd2c_i(f, 2, 73);' if name == 'caughtOuter' else 'd2c_copy(f, 2, 1);', name == 'rethrowOuter')
        line(21, result if name == 'caughtOuter' else 'd2c_throw(f,f->slots[2].v.l);', name == 'rethrowOuter')
    statements.append('goto failed;')
    for label, catches in exceptional.items():
        statements.append('E' + str(label) + ':;')
        if catches:
            statements.extend(['if (d2c_catch(f, "java/lang/IllegalArgumentException", 2)) goto L7;',
                               'if (d2c_catch(f, "java/lang/IllegalStateException", 2)) goto L10;'])
        statements.append('goto failed;')
    statements.append('failed: d2c_close(f, nullptr); return 0;')
    return ('extern "C" D2C_PROTECTED jint ' + exception.SYMBOLS[name] +
            '(JNIEnv* env, jclass owner, jobject a0) {\n' + '\n'.join(entry + statements) + '\n}\n')


class GeneratedExceptionBindingTests(unittest.TestCase):
    def test_generated_paths_bind_catch_order_identity_and_same_object_rethrow(self):
        for name in exception.TARGETS:
            binding = exception.bind_exception_cpp(emitted_method(name), name)
            self.assertIn('sentinel', binding['paths'])
            self.assertEqual(binding['sha256'], exception.sha(binding['source'].encode()))
            if name != 'exceptionLeaf':
                self.assertEqual(binding['paths']['normal']['value'], 0)
                self.assertEqual(binding['paths']['wrong-type']['value'], -11)
                self.assertEqual(binding['paths']['substitute']['value'], -12)

    def test_literal_whitespace_is_preserved_and_wrong_bindings_fail(self):
        source = emitted_method('rethrowOuter')
        literals = ('"sample/Run"', '"sample/Probe"', '"exceptionLeaf"', '"hit"',
                    '"(Ljava/lang/IllegalStateException;)I"',
                    '"(ILjava/lang/Throwable;Ljava/lang/Throwable;)V"',
                    '"java/lang/IllegalArgumentException"', '"java/lang/IllegalStateException"')
        for literal in literals:
            for whitespace in (' ', '\t'):
                changed = source.replace(literal, literal[:2] + whitespace + literal[2:])
                with self.subTest(literal=literal, whitespace=repr(whitespace)), self.assertRaises(ValueError):
                    exception.bind_exception_cpp(changed, 'rethrowOuter')
        # The exact owner mutation from independent review must retain its embedded space.
        with self.assertRaises(ValueError):
            exception.bind_exception_cpp(source.replace('"sample/Run"', '"sample/ Run"'), 'rethrowOuter')
        layout = source.replace('d2c_invoke(f,2,', 'd2c_invoke(\t f, 2, ')
        self.assertEqual(exception.bind_exception_cpp(layout, 'rethrowOuter')['paths'],
                         exception.bind_exception_cpp(source, 'rethrowOuter')['paths'])

    def test_cpp_compaction_preserves_escaped_literal_bytes(self):
        raw = r''' call ( "sample/ Run\t\" x", 'a b' ); '''
        self.assertEqual(exception.cpp_compact(raw), r'''call("sample/ Run\t\" x",'a b');''')
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            exception.cpp_compact('call("unterminated);')

    def test_frame_capacity_matches_production_and_covers_every_used_slot(self):
        runtime = exception.ROOT / 'dex2c/core/src/main/resources/native/dex2c_runtime.cpp'
        _, body = exception.cpp_function(runtime.read_text('utf-8'),
            'd2c_frame* d2c_open(JNIEnv* env, jclass owner, int count) {')
        self.assertIn('count > ' + str(exception.CPP_FRAME_SLOT_LIMIT), body)
        for name in exception.TARGETS:
            source = emitted_method(name)
            for count in (0, 1, 4, exception.CPP_FRAME_SLOT_LIMIT + 1):
                with self.subTest(name=name, count=count), self.assertRaisesRegex(ValueError, 'frame'):
                    exception.bind_exception_cpp(source.replace('owner, 16)', f'owner, {count})'), name)
            for count in (5, exception.CPP_FRAME_SLOT_LIMIT):
                with self.subTest(name=name, count=count):
                    exception.bind_exception_cpp(source.replace('owner, 16)', f'owner, {count})'), name)

    def test_all_slot_operands_and_invocation_spans_are_checked_even_if_unreachable(self):
        source = emitted_method('rethrowOuter')
        replacements = (('d2c_i(f, 2, 1)', 'd2c_i(f, 16, 1)'),
                        ('d2c_ref(f,4,nullptr)', 'd2c_ref(f,16,nullptr)'),
                        ('d2c_copy(f, 3, 0)', 'd2c_copy(f, 16, 0)'),
                        ('d2c_copy(f, 3, 0)', 'd2c_copy(f, 3, 16)'),
                        ('d2c_throw(f,f->slots[2].v.l)', 'd2c_throw(f,f->slots[16].v.l)'),
                        ('"java/lang/IllegalArgumentException", 2)', '"java/lang/IllegalArgumentException", 16)'),
                        ('IsSameObject(f->slots[2]', 'IsSameObject(f->slots[16]'),
                        ('f->slots[3].v.l))', 'f->slots[16].v.l))'),
                        ('result=(jint)f->slots[2]', 'result=(jint)f->slots[16]'),
                        ('d2c_invoke(f,2,"sample/Probe"', 'd2c_invoke(f,14,"sample/Probe"'),
                        ('d2c_invoke(f,2,"sample/Run"', 'd2c_invoke(f,16,"sample/Run"'))
        for old, new in replacements:
            self.assertIn(old, source)
            with self.subTest(operand=old), self.assertRaisesRegex(ValueError, 'slots? outside frame'):
                exception.bind_exception_cpp(source.replace(old, new), 'rethrowOuter')
        changed = source.replace('failed: d2c_close', 'L999:;\nd2c_i(f,16,0);\nfailed: d2c_close')
        with self.assertRaisesRegex(ValueError, 'slot outside frame'):
            exception.bind_exception_cpp(changed, 'rethrowOuter')

    def test_octal_constants_and_all_noncanonical_numeric_operands_fail(self):
        source = emitted_method('rethrowOuter')
        replacements = (('owner, 16)', 'owner, 016)'),
                        ('d2c_i(f, 2, -11)', 'd2c_i(f, 2, -011)'),
                        ('d2c_i(f, 2, -12)', 'd2c_i(f, 2, -012)'),
                        ('d2c_i(f, 2, 1)', 'd2c_i(f, 2, 01)'),
                        ('d2c_i(f, 2, 1)', 'd2c_i(f, 2, -0)'),
                        ('d2c_copy(f, 3, 0)', 'd2c_copy(f, 03, 0)'),
                        ('d2c_copy(f, 3, 0)', 'd2c_copy(f, 3, 00)'),
                        ('d2c_ref(f,4,nullptr)', 'd2c_ref(f,04,nullptr)'),
                        ('d2c_throw(f,f->slots[2]', 'd2c_throw(f,f->slots[02]'),
                        ('"java/lang/IllegalArgumentException", 2)', '"java/lang/IllegalArgumentException", 02)'),
                        ('IsSameObject(f->slots[2]', 'IsSameObject(f->slots[02]'),
                        ('f->slots[3].v.l))', 'f->slots[03].v.l))'),
                        ('result=(jint)f->slots[2]', 'result=(jint)f->slots[02]'),
                        ('d2c_invoke(f,2,', 'd2c_invoke(f,02,'),
                        ('V",0,3)', 'V",00,3)'), ('V",0,3)', 'V",0,03)'))
        for old, new in replacements:
            self.assertIn(old, source)
            with self.subTest(operand=old), self.assertRaises(ValueError):
                exception.bind_exception_cpp(source.replace(old, new), 'rethrowOuter')
        caught = emitted_method('caughtOuter')
        for literal in ('073', '+73', '0x49'):
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                exception.bind_exception_cpp(caught.replace('d2c_i(f, 2, 73)', f'd2c_i(f, 2, {literal})'), 'caughtOuter')
        _, body = exception.cpp_function(caught, 'extern "C" D2C_PROTECTED jint ' +
            exception.SYMBOLS['caughtOuter'] + '(JNIEnv* env, jclass owner, jobject a0) {')
        program, _ = exception.cpp_program(body.replace('d2c_i(f, 2, 73)', 'd2c_i(f, 2, 0)'))
        self.assertIn(('int', ('2', '0'), 'L20'), program)

    def test_missing_check_changed_handler_identity_rethrow_and_default_success_fail(self):
        source = emitted_method('rethrowOuter')
        catches = ('if (d2c_catch(f, "java/lang/IllegalArgumentException", 2)) goto L7;\n'
                   'if (d2c_catch(f, "java/lang/IllegalStateException", 2)) goto L10;')
        mutations = (source.replace('if (env->ExceptionCheck()) goto E5;', ''),
                     source.replace(catches, '\n'.join(reversed(catches.splitlines()))),
                     source.replace('java/lang/IllegalArgumentException', 'java/lang/RuntimeException'),
                     source.replace('"exceptionLeaf"', '"foreign"'),
                     source.replace('if (env->IsSameObject(', 'if (!env->IsSameObject('),
                     source.replace('f->slots[2].v.l,f->slots[3].v.l', 'f->slots[2].v.l,f->slots[2].v.l'),
                     source.replace('d2c_throw(f,f->slots[2].v.l)', 'd2c_throw(f,f->slots[0].v.l)'),
                     source.replace('d2c_i(f, 2, -12)', 'd2c_i(f, 2, 91)'),
                     source.replace('d2c_i(f, 2, 3)', 'd2c_i(f, 2, 4)'),
                     source.replace('goto failed;\nfailed:', 'goto L0;\nfailed:'))
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                exception.bind_exception_cpp(changed, 'rethrowOuter')
        source = emitted_method('caughtOuter').replace('d2c_i(f, 2, 73)', 'd2c_i(f, 2, 0)')
        with self.assertRaises(ValueError): exception.bind_exception_cpp(source, 'caughtOuter')

    def test_leaf_unique_throw_and_failed_cleanup_are_required(self):
        source = emitted_method('exceptionLeaf')
        for changed in (source.replace('d2c_i(f, 2, 2)', 'd2c_i(f, 2, 1)'),
                        source.replace('d2c_throw(f,f->slots[2].v.l);', 'd2c_throw(f,f->slots[2].v.l);\nd2c_throw(f,f->slots[2].v.l);'),
                        source.replace('if (env->ExceptionCheck()) goto E5;', ''),
                        source.replace('d2c_close(f, nullptr); return 0;', 'return 0;'),
                        source.replace('E5:;\ngoto failed;', 'E5:;\ngoto L0;')):
            with self.assertRaises(ValueError): exception.bind_exception_cpp(changed, 'exceptionLeaf')

    def test_unknown_generated_statement_and_duplicate_function_fail_closed(self):
        source = emitted_method('caughtOuter')
        for changed in (source.replace('L0:;', 'L0:;\nunknown_native_call();'), source + source):
            with self.assertRaises(ValueError): exception.bind_exception_cpp(changed, 'caughtOuter')

    def test_runtime_and_actual_classpath_are_rebound_without_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); generated = root / 'generated'; generated.mkdir()
            source, probe = exception.fixture_sources()
            (root / 'Run.java').write_text(source, 'utf-8'); (root / 'Probe.java').write_text(probe, 'utf-8')
            classes = root / 'classes/sample'; classes.mkdir(parents=True)
            for name in ('Run.class', 'Probe.class'): (classes / name).write_bytes(b'host-test-class-' + name.encode())
            emitted = ''.join(emitted_method(name) for name in exception.TARGETS)
            (generated / 'protected.cpp').write_text(emitted, 'utf-8')
            production = exception.ROOT / 'dex2c/core/src/main/resources/native/dex2c_runtime.cpp'
            (generated / 'dex2c_runtime.cpp').write_bytes(production.read_bytes())
            resource = root / 'classpath/native/dex2c_runtime.cpp'; resource.parent.mkdir(parents=True)
            resource.write_bytes(production.read_bytes()); resource_id = exception.identity(resource)
            tsv = str(resource) + '\t' + str(resource_id['bytes']) + '\t' + resource_id['sha256'] + '\n'
            for name in ('before', 'after'): (root / ('classpath-' + name + '.tsv')).write_text(tsv, 'utf-8')
            with patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')):
                self.assertEqual(set(exception.bind_generated_cpp(root)), set(exception.TARGETS))
                path = generated / 'dex2c_runtime.cpp'; raw = path.read_text()
                path.write_text(raw.replace('env->ExceptionClear();', '/* missing clear */'))
                with self.assertRaisesRegex(ValueError, 'exception runtime differs'): exception.bind_generated_cpp(root)
                path.write_text(raw)
                resource.write_bytes(b'foreign resource')
                with self.assertRaisesRegex(ValueError, 'classpath file'): exception.bind_generated_cpp(root)


class WholeMethodBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        generated, native = self.fixture / 'generated', self.fixture / 'native'
        generated.mkdir(); (native / 'staging/protected').mkdir(parents=True)
        self.contract, _, resources = fixture_resources()
        raw_ir, _ = compiler_fixture()
        _, raw_body = exception.compiler_contract.function(raw_ir, 'safe')
        raw_rows, final_rows, manifest = [], [], []
        for index, name in enumerate(exception.METHODS):
            item = self.contract[name]; symbol = item['symbol']; ref = 'ref_' + name; interpreter = 'interpreter_' + name
            staged = resources[bytes.fromhex(item['id']), 1]
            for file in (item['id'], symbol): (native / 'staging/protected' / (file + '.bin')).write_bytes(staged)
            manifest.append({'kind': 1, 'name': symbol, 'id': item['id'], 'bytes': item['bytes'], 'lifetime': 'lease-v1'})
            descriptor = bytes.fromhex(item['id']) + struct.pack('<II', item['bytes'], 1)
            escaped = ''.join('\\%02X' % byte for byte in descriptor)
            common = (f'@gv_code_seg_{symbol} = internal constant i8 0, !ndkp.qseg !{10 + index}\n'
                      f'@{ref} = private constant [24 x i8] c"{escaped}", section ".text.ndkp.qseg.refs", !ndkp.qseg.lifetime !1\n')
            header = f'define i32 @{symbol}(ptr %0) #0 !ndkp.qseg.lifetime !1 !ndkp.vmp.protected !{100 + index} {{\n'
            metadata = f'!{10 + index} = !{{ptr @{ref}}}\n!{100 + index} = !{{ptr @gv_code_seg_{symbol}, ptr @{interpreter}}}\n'
            body = raw_body.replace('@ref_safe', '@' + ref).replace('@vm_interpreter_safe_k0000000000000000', '@' + interpreter)
            raw_rows.append(common + header + body + '}\n' + metadata)
            body = FINAL_BODY.replace('@target_ref', '@' + ref).replace('@interpreter()', '@' + interpreter + '()')
            final_rows.append(common + header + body + '}\n' + metadata)
        (native / 'protected.raw.ll').write_text(''.join(raw_rows) + '!1 = !{!"lease-v1"}\nattributes #0 = { noinline nounwind }\n')
        (native / 'protected.ll').write_text(''.join(final_rows) + '!1 = !{!"lease-v1"}\nattributes #0 = { noinline }\n')
        self.selection = generated / 'selection.json'; self.protection = native / 'protection.json'
        self.manifest = native / 'staging/protected/manifest.json'
        exception.write_json(self.selection, {'methods': [{'method': exception.METHODS[name], 'symbol': exception.SYMBOLS[name],
                                                           'protection': 'vmp'} for name in exception.METHODS]})
        exception.write_json(self.protection, {'symbols': list(exception.SYMBOLS.values()),
                                              'vmLifetimePolicies': dict.fromkeys(exception.SYMBOLS.values(), 'lease-v1')})
        exception.write_json(self.manifest, manifest)

    def check(self):
        with patch.object(exception, 'bind_generated_cpp', return_value={name: exception.bind_exception_cpp(emitted_method(name), name)
                                                                        for name in exception.TARGETS}), \
             patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')):
            return exception.bind_wrappers(self.fixture)

    def test_all18_include_marker_selection_staging_raw_and_final_lease_gates(self):
        rows = self.check()
        self.assertEqual(set(rows), set(exception.METHODS))
        self.assertEqual(len(rows), 18)
        for row in rows.values():
            self.assertEqual([binding['nounwind'] for binding in row['irBindings']], [True, False])
            self.assertTrue(all(binding['paths']['paths'][0]['exitLeaseDepth'] == 0 for binding in row['irBindings']))

    def test_missing_extra_duplicate_selection_and_pinned_marker_rejected(self):
        original = self.selection.read_bytes()
        for mutate in (lambda r: r['methods'].pop(), lambda r: r['methods'].append(copy.deepcopy(r['methods'][0])),
                       lambda r: r['methods'][-1].update(symbol='foreign')):
            rows = json.loads(original); mutate(rows); self.selection.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): self.check()
        self.selection.write_bytes(original)
        rows = exception.read_json(self.protection); rows['vmLifetimePolicies'][exception.SYMBOLS['marker']] = 'pinned-unproven-unwind'
        self.protection.write_text(json.dumps(rows))
        with self.assertRaises(ValueError): self.check()

    def test_marker_raw_missing_early_wrong_descriptor_release_and_unknown_cfg_fail(self):
        path = self.fixture / 'native/protected.raw.ll'; text = path.read_text()
        header, body = exception.compiler_contract.function(text, exception.SYMBOLS['marker'])
        release = '  call void @ndkp_qseg_release_v1(ptr @ref_marker)\n'
        interpreter = '  call void @interpreter_marker()\n'
        for changed in (body.replace(interpreter + release, interpreter),
                        body.replace(interpreter + release, release + interpreter),
                        body.replace('ptr @ref_marker)', 'ptr @ref_foreign)', 1),
                        body.replace('br i1 %thrown', 'indirectbr i1 %thrown')):
            path.write_text(text.replace(header + '\n' + body, header + '\n' + changed))
            with self.assertRaises(ValueError): self.check()
        path.write_text(text)

    def test_marker_staging_policy_and_descriptor_identity_fail(self):
        original = self.manifest.read_bytes()
        for field, value in (('lifetime', 'pinned-unproven-unwind'), ('id', 'ff' * 16), ('bytes', 999)):
            rows = json.loads(original); rows[-1][field] = value; self.manifest.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): self.check()



class FinalWrapperPathTests(unittest.TestCase):
    def check(self, body=FINAL_BODY):
        return exception.final_wrapper_paths(body, 'target_ref', 'interpreter')

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
              'invocation': [str(Path(exception.sys.executable)), str(exception.ROOT / 'tests/dex2c/device.py'),
                  '--fixtures', str(fixture), '--sdk', str(sdk), '--java', str(java), '--serial', serial,
                  '--server-port', str(port)],
              'results': [{'main': 'sample.Run', 'mode': mode, 'output': exception.EXPECTED.decode().strip()}
                          for mode in ('baseline', 'protected')],
              'negativeCases': [{'mode': mode, 'expectedCodes': [127]} for mode in exception.NEGATIVES]}
    for index, mode in enumerate(exception.NEGATIVES):
        path = fixture / (mode + '.apk'); path.write_bytes(('host-test-' + mode).encode())
        target, token = remote + '/' + path.name, 'DEX2C_' + format(index, '032x')
        command, child = exception.device_helper.negative_command(adb, target, token)
        report['results'].append({'mode': mode, 'rejected': True, 'status': 'expected-exit-signature',
            'expectedCodes': [127], 'exitCode': 127, 'protocolToken': token, 'remoteApk': target,
            'command': command, 'childArgv': child, 'environment': {'CLASSPATH': target},
            'artifact': exception.identity(path),
            'push': {'command': [*adb, 'push', str(path), target], 'status': 'completed', 'returnCode': 0,
                     **exception.device_helper.streams(b'', b'')},
            'execution': {'command': command, 'status': 'completed', 'returnCode': 0,
                          **exception.device_helper.streams(b'', (token + ':BEGIN\n' + token + ':EXIT:127\n').encode())}})
    report['pushed'] = [remote + '/' + name for name in ('baseline.zip', 'protected.apk', 'protected.zip',
                        'libdex2c_semantics.so', *(mode + '.apk' for mode in exception.NEGATIVES))]
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
        return exception.verify_device_report(path, self.fixture, self.sdk, self.java, self.serial, self.port)

    def test_full_fixed_negative_denominator_passes_without_executing(self):
        with patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')):
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

    def test_auth_negative_checkjni_is_not_accepted_as_extra_shell_output(self):
        row = self.report['results'][2]['execution']
        row.update(exception.device_helper.streams(b'', (row['stderr'] + 'WARNING: JNI pending exception\n').encode()))
        with self.assertRaisesRegex(ValueError, 'CheckJNI'): self.check()

    def test_changed_negative_artifact_is_rejected(self):
        (self.fixture / 'wrong-signer.apk').write_bytes(b'replaced')
        with self.assertRaises(ValueError): self.check()


class OfflineReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        fixture, sdk, java, serial, port, device_report = device_report_fixture(root)
        exception.write_json(fixture / 'device-results.json', device_report)
        build = {'classpathInputs': {}, 'inputsBefore': exception.identities([java]), 'artifacts': exception.identities([fixture / 'wrong-signer.apk'])}
        exception.write_json(fixture / 'build.json', build)
        self.path = root / 'observation'; self.path.mkdir()
        plan = plan_fixture(); self.expected_plan = copy.deepcopy(plan)
        exception.write_json(self.path / 'plan.json', plan)
        (self.path / 'plan.bin').write_bytes(exception.encode_plan(plan))
        fixed = exception.identities([fixture / 'build.json', fixture / 'device-results.json', java])
        self.report = {'schemaVersion': 1, 'checkerRevision': 1, 'status': 'passed', 'callRoute': 'ART/JNI', 'scope': 'signed APK Java catch/rethrow ART/JNI wrapper lease',
            'productionWrapperExecution': True, 'nativeDirectHandlerExecution': False, 'directWipeObservation': False,
            'inputsBefore': fixed, 'inputsAfter': fixed, 'fixture': str(fixture), 'sdk': str(sdk), 'java': str(java),
            'ndk': str(root / 'ndk'), 'serial': serial, 'serverPort': port,
            'remote': '/data/local/tmp/qseg-java-exception-' + TOKEN,
            'device': {'model': 'host-test-model', 'sdk': '36', 'pageSize': '4096', 'arch': 'aarch64'},
            'plan': exception.identity(self.path / 'plan.json'), 'binaryPlan': exception.identity(self.path / 'plan.bin'),
            'runs': [{'case': case, 'token': exception.sha(case.encode())[:32]} for case in exception.EVENTS],
            'controlNegatives': [{'case': case, 'token': exception.sha(case.encode())[:32]} for case in exception.CONTROLS]}
        commands = exception.Commands(self.path, exception.ROOT)
        for label, argv in exception.expected_commands(self.report, self.path).items():
            if label.startswith('device-'):
                stdout = (self.report['device'][label[7:]] + '\n').encode()
            elif label.startswith('normal-'):
                stdout = exception.EXPECTED
            elif label in exception.EVENTS:
                run = next(r for r in self.report['runs'] if r['case'] == label)
                run['events'] = event_rows(label, plan, run['token']); stdout = output(run['events'])
            elif label in exception.CONTROLS:
                control = next(r for r in self.report['controlNegatives'] if r['case'] == label)
                stdout, stderr = control_streams(label, control['token'], plan)
                control.update(exception.validate_control(stdout, stderr, control['token'], label))
                _, child = exception.control_command([], self.report['remote'], label, control['token'])
                control.update(childArgv=child, environment={'CLASSPATH': self.report['remote'] + '/protected.apk'})
            else: stdout = b''
            if label not in exception.CONTROLS: stderr = b''
            completed = exception.subprocess.CompletedProcess(argv, 0, stdout, stderr)
            with patch.object(exception.subprocess, 'run', return_value=completed): commands.checked(label, argv)
            if label in exception.EVENTS: run['command'] = commands.records[-1]
            if label in exception.CONTROLS: control['command'] = commands.records[-1]
        self.report['commands'] = commands.records
        self.report['normal'] = [{'mode': mode, 'command': next(ref for ref in commands.records if 'normal-' + mode in ref)}
                                 for mode in ('baseline', 'protected')]
        self.report['cleanup'] = commands.records[-2:]
        self.report['artifacts'] = exception.identities(exception.tree_files(self.path))

    def check(self):
        with patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')), \
             patch.object(exception, 'rebuild_plan', return_value=copy.deepcopy(self.expected_plan)):
            return exception.verify_report(self.path, self.report)

    def change_record(self, index, field, value):
        path = self.path / self.report['commands'][index]
        row = exception.read_json(path); row[field] = value
        path.write_text(json.dumps(row), 'utf-8')
        # Exercise the semantic gate even when the untrusted manifest is refreshed.
        self.report['artifacts'][str(path)] = exception.identity(path)

    def test_complete_report_replays_without_subprocess(self):
        self.assertEqual(self.check()['status'], 'passed')
        exception.write_json(self.path / 'results.json', self.report)
        with patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')), \
             patch.object(exception, 'rebuild_plan', return_value=copy.deepcopy(self.expected_plan)):
            self.assertEqual(exception.verify_results(self.path)['status'], 'passed')

    def test_unencoded_apk_method_and_symbol_fields_are_rebound(self):
        path = self.path / 'plan.json'
        mutations = (lambda p: p.update(apkSha256='ff' * 32),
                     lambda p: p.update(libraryEntry='lib/arm64-v8a/foreign.so'),
                     lambda p: p['resources'][0].update(method='foreign/Run.outer(I)I'),
                     lambda p: p['resources'][0].update(symbol='foreign_symbol'),
                     lambda p: p['methodBindings']['marker'].update(sha256='ff' * 32),
                     lambda p: p['methodBindings']['exceptionLeaf'].update(cppBinding={'source': 'wrong catch/throw'}))
        binary = (self.path / 'plan.bin').read_bytes()
        for mutate in mutations:
            changed = copy.deepcopy(self.expected_plan); mutate(changed)
            path.write_text(json.dumps(changed), 'utf-8')
            self.report['plan'] = self.report['artifacts'][str(path)] = exception.identity(path)
            self.assertEqual(exception.encode_plan(changed), binary)
            with self.assertRaisesRegex(ValueError, 'plan differs from final APK'):
                self.check()

    def test_exact_argv_cwd_timeout_and_command_failure_rejected(self):
        for field, value in (('argv', ['foreign']), ('cwd', str(self.path)), ('timeoutSeconds', 600), ('returncode', 1)):
            with self.subTest(field=field):
                path = self.path / self.report['commands'][0]; saved = path.read_bytes()
                self.change_record(0, field, value)
                with self.assertRaises(ValueError): self.check()
                path.write_bytes(saved); self.report['artifacts'][str(path)] = exception.identity(path)

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
        row = exception.read_json(self.path / self.report['normal'][0]['command'])
        Path(row['stderr']['path']).write_bytes(b'JNI DETECTED ERROR IN APPLICATION\n')
        with self.assertRaises(ValueError): self.check()

    def test_controls_cannot_be_omitted_reused_or_renamed_and_exitcode_alone_fails(self):
        original = copy.deepcopy(self.report)
        for mutate in (lambda r: r['controlNegatives'].pop(),
                       lambda r: r['controlNegatives'][0].update(token=r['runs'][0]['token']),
                       lambda r: r['controlNegatives'][1].update(case='reject-substitute'),
                       lambda r: r['controlNegatives'][0].update(exitCode=127),
                       lambda r: r['controlNegatives'][0].update(childArgv=['foreign'])):
            self.report = copy.deepcopy(original); mutate(self.report)
            with self.assertRaises(ValueError): self.check()

    def test_changed_control_raw_stream_is_replayed_even_if_manifest_is_refreshed(self):
        control = self.report['controlNegatives'][0]
        reference = control['command']; record = exception.read_json(self.path / reference)
        path = Path(record['stderr']['path'])
        path.write_bytes(path.read_bytes().replace(b'sentinel identity differs', b'wrong diagnostic'))
        record['stderr'] = exception.identity(path)
        (self.path / reference).write_text(json.dumps(record), 'utf-8')
        self.report['artifacts'][str(path)] = exception.identity(path)
        self.report['artifacts'][str(self.path / reference)] = exception.identity(self.path / reference)
        with self.assertRaisesRegex(ValueError, 'protocol differs'): self.check()


class PlanRebuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name); native = self.fixture / 'native'; native.mkdir()
        self.contract, receipt, self.resources = fixture_resources()
        library = bytearray(test_seal_cse.elf(bytes(512)))
        for index, name in enumerate((*exception.TARGETS, *(f'work{i}' for i in range(exception.PRESSURE_COUNT)))):
            item = self.contract[name]; address = 0x1100 + index * 32
            library[address:address + 24] = bytes.fromhex(item['id']) + struct.pack('<II', item['bytes'], 1)
        self.asset = 'assets/dex2c_semantics.qseg'
        library[0x2100:0x2100 + len(self.asset) + 1] = self.asset.encode() + b'\0'
        self.library = bytes(library); (native / 'linked.so').write_bytes(self.library)
        (native / 'signing-cert.der').write_bytes(b'host-test-certificate')
        exception.write_json(native / 'segments.json', receipt)
        exception.write_json(native / 'protection.json', {'qsegLifetimeAbi': 1,
            'idlePlaintextBudgetBytes': exception.BUDGET, 'apkSignatureVerification': True,
            'librarySha256': exception.sha(self.library), 'containerSha256': exception.sha(b'host-test-container')})
        self.entry = 'lib/arm64-v8a/libdex2c_semantics.so'
        with exception.zipfile.ZipFile(self.fixture / 'protected.apk', 'w') as archive:
            archive.writestr(self.entry, self.library); archive.writestr(self.asset, b'host-test-container')
        self.audited = {'libraries': [{'name': self.entry, 'sha256': exception.sha(self.library)}],
                        'apkSha256': exception.sha((self.fixture / 'protected.apk').read_bytes())}
        self.nm = b''.join(f'{0x1400 + i * 4:016x} T {name}\n'.encode() for i, name in enumerate(
            ('ndkp_qseg_acquire_v1', 'ndkp_qseg_release_v1', 'ndkp_qseg_stats_v1', 'JNI_OnLoad')))

    def check(self):
        with patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')), \
             patch.object(exception, 'bind_wrappers', return_value=copy.deepcopy(self.contract)) as binding, \
             patch.object(exception.cache, 'audit', return_value=self.audited) as authentication, \
             patch.object(exception.cache.qseg, 'locate_image', return_value=(None, 0x2000)), \
             patch.object(exception.cache.qseg, 'unpack', return_value=self.resources) as unpack:
            plan = exception.rebuild_plan(self.fixture, self.nm)
            binding.assert_called_once_with(self.fixture)
            native = self.fixture / 'native'
            authentication.assert_called_once_with(self.fixture / 'protected.apk', native / 'protection.json',
                                                     native / 'segments.json', native / 'signing-cert.der')
            unpack.assert_called_once_with(self.library, b'host-test-container', b'host-test-certificate')
            return plan

    def test_final_bytes_exact_methods_descriptors_and_rx_are_shared_offline(self):
        plan = self.check()
        self.assertEqual(plan['apkSha256'], self.audited['apkSha256'])
        self.assertEqual(plan['librarySha256'], exception.sha(self.library))
        self.assertEqual(plan['onloadRva'], 0x140c)
        self.assertEqual(plan['executableSpans'][0]['sha256'], exception.sha(self.library[0x1000:0x2000]))
        for index, row in enumerate(plan['resources']):
            self.assertEqual(row['method'], exception.METHODS[row['name']])
            self.assertEqual(row['symbol'], exception.SYMBOLS[row['name']])
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
        with patch.object(exception, 'bind_wrappers', return_value=self.contract), \
             patch.object(exception.cache, 'audit', side_effect=ValueError('authenticated recovery failed')), \
             patch.object(exception.subprocess, 'run', side_effect=AssertionError('offline')):
            with self.assertRaisesRegex(ValueError, 'authenticated recovery failed'):
                exception.rebuild_plan(self.fixture, self.nm)


if __name__ == '__main__':
    unittest.main()
