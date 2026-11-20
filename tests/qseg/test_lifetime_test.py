"""Host-only runner regressions: all compiler/ADB subprocesses are mocked."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import lifetime_test as lifetime


TOKEN = 'a' * 32
STDOUT = b'page=4096 active=0 idle=700416 pinned=700416 peak=4194304 evictions=9 wiped=9\n'
EVENTS = '''control:BEGIN
control:WARMUP_OK
control:COLD_TARGET bytes=2097152
control:TARGET_ATTEMPT
control:MMAP_REAL attempts=1 hits=0 bytes=2097152
control:TARGET_OK attempts=1 hits=0
control:WAIT status=0 exited=1 code=0 signal=0
enomem:BEGIN
enomem:WARMUP_OK
enomem:COLD_TARGET bytes=2097152
enomem:ARMED
enomem:TARGET_ATTEMPT
enomem:MMAP_ENOMEM attempts=1 hits=1 bytes=2097152 errno=12
enomem:WAIT status=32512 exited=1 code=127 signal=0
suite:COMPLETE'''.splitlines()


def copy_records(token=TOKEN, page=4096):
    """Synthetic observations only; compiler/ADB and the C++ fixture are never executed here."""
    records = []
    mapped = (700000 + page - 1) // page * page
    for case, reject, base in (('positive', False, 0x10000000), ('reject-padding', True, 0x11000000)):
        buffer, pressure_base = base + 0x60000000, base + 0x10000000
        target = {'id': '05000000000000000000000000000000', 'kind': 2, 'size': 700000,
                  'data': 0, 'mapped': 0, 'references': 0, 'pinned': False, 'lastUsed': 0}
        pressure = {'id': '01000000000000000000000000000000', 'kind': 1, 'size': 700000,
                    'data': 0, 'mapped': 0, 'references': 0, 'pinned': False, 'lastUsed': 0}
        cache = {'activeBytes': 0, 'idleBytes': 0, 'pinnedBytes': 0, 'peakResidentBytes': 0, 'evictions': 0}
        common = {'runToken': token, 'case': case, 'target': target, 'pressure': pressure,
                  'pageSize': page, 'mappedBytes': mapped, 'sourceBase': 0, 'bufferBase': buffer,
                  'cache': cache, 'clock': 0, 'otherResourcesCold': True,
                  'targetMatches': 0, 'injectHits': 0, 'realMunmapCalls': 0, 'armed': False}
        seq = 0

        def emit(event, **extra):
            nonlocal seq
            records.append(copy.deepcopy({**common, 'seq': seq, 'event': event, **extra}))
            seq += 1

        source = {'sourceCheckedBytes': 700000, 'sourceValue': 69,
                  'paddingCheckedBytes': mapped - 700000, 'paddingValue': 0}
        payload = {'payloadCheckedBytes': 64, 'payloadValue': 69, 'leadingCheckedBytes': 16,
                   'trailingCheckedBytes': 16, 'canaryValue': 165}
        interval = {'unmapBase': base, 'unmapBytes': mapped}
        emit('BEGIN')
        common.update(sourceBase=base, clock=1)
        target.update(data=base, mapped=mapped, references=1, lastUsed=1)
        cache.update(activeBytes=mapped, peakResidentBytes=mapped)
        emit('SOURCE_HELD', **source)
        emit('COPY_BEFORE', offset=65520, length=64, encoding=2, bufferBytes=96, payloadOffset=16,
             leadingCanaryBytes=16, trailingCanaryBytes=16, initialCheckedBytes=96, initialValue=165, disjoint=True)
        emit('COPY_AFTER', **payload)
        target.update(references=0, lastUsed=2)
        common.update(clock=2)
        cache.update(activeBytes=0, idleBytes=mapped)
        emit('SOURCE_RELEASED', **source)
        common.update(clock=3)
        pressure.update(data=pressure_base, mapped=mapped, references=1, lastUsed=3)
        cache.update(activeBytes=mapped, peakResidentBytes=2 * mapped)
        emit('PRESSURE_ACQUIRED', pressureCheckedBytes=700000, pressureValue=65)
        common.update(armed=True)
        emit('PRESSURE_RELEASE_ATTEMPT')
        common.update(clock=4, targetMatches=1)
        pressure.update(references=0, lastUsed=4)
        cache.update(activeBytes=0, idleBytes=2 * mapped)
        emit('TARGET_ENTER', **interval)
        if reject:
            common.update(injectHits=1)
            emit('INJECTED', **interval, offset=mapped - 1, oldValue=0, newValue=123)
        emit('ZERO_SCAN', **interval, checkedBytes=mapped, nonzeroBytes=1 if reject else 0,
             firstBadOffset=mapped - 1 if reject else -1, firstBadValue=123 if reject else 0)
        if reject:
            emit('REJECT_SOURCE_NONZERO', **interval, exitCode=123)
        else:
            common.update(realMunmapCalls=1)
            emit('REAL_MUNMAP', **interval, result=0)
            common.update(armed=False)
            target.update(data=0, mapped=0)
            cache.update(idleBytes=mapped, evictions=1)
            emit('EVICTED')
            emit('COPY_RETAINED', **payload)
            emit('COPY_WIPED', **{**payload, 'payloadValue': 0}, wipeOffset=16, wipedBytes=64)
            emit('COMPLETE', apkOnlyRecoveryPrevented=False)
        records.append({'runToken': token, 'case': case, 'seq': seq, 'event': 'WAIT',
                        'status': 31488 if reject else 0, 'exited': True, 'code': 123 if reject else 0, 'signal': 0})
    return records


def copy_stderr(records):
    return b''.join(b'QSEG_COPY_WIPE:' + json.dumps(record, separators=(',', ':')).encode('ascii') + b'\n'
                    for record in records)


def stderr_for(token=TOKEN, events=EVENTS, copy_events=None):
    return copy_stderr(copy_records(token) if copy_events is None else copy_events) + b''.join(
        ('QSEG_MMAP:' + token + ':' + event + '\n').encode('ascii') for event in events)


class EventTests(unittest.TestCase):
    def test_complete_protocol_allows_raw_diagnostics(self):
        stats = lifetime.validate_run(STDOUT, b'\xff diagnostic\n' + stderr_for(), TOKEN, 4096)
        self.assertEqual(stats['evictions'], 9)

    def test_each_event_is_required_including_warm_cold_and_hit(self):
        for index in range(len(EVENTS)):
            with self.subTest(missing=EVENTS[index]), self.assertRaises(ValueError):
                lifetime.validate_run(STDOUT, stderr_for(events=EVENTS[:index] + EVENTS[index + 1:]), TOKEN, 4096)

    def test_order_duplicate_foreign_token_and_returned_are_rejected(self):
        reordered = EVENTS.copy()
        reordered[10], reordered[11] = reordered[11], reordered[10]
        for data in (stderr_for(events=reordered), stderr_for() + stderr_for(events=EVENTS[:1]),
                     stderr_for('b' * 32), stderr_for() + stderr_for(events=['enomem:RETURNED'])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                lifetime.validate_run(STDOUT, data, TOKEN, 4096)

    def test_attempt_hit_errno_wait_status_exit_and_signal_are_exact(self):
        mutations = (
            (b'attempts=1 hits=1', b'attempts=2 hits=1'),
            (b'attempts=1 hits=1', b'attempts=1 hits=0'),
            (b'errno=12', b'errno=11'),
            (b'status=32512', b'status=0'),
            (b'code=127', b'code=126'),
            (b'status=32512 exited=1 code=127 signal=0', b'status=9 exited=0 code=-1 signal=9'),
        )
        for old, new in mutations:
            with self.subTest(new=new), self.assertRaises(ValueError):
                lifetime.validate_run(STDOUT, stderr_for().replace(old, new), TOKEN, 4096)

    def test_old_suite_statistics_and_complete_remain_required(self):
        for stdout in (b'', STDOUT + STDOUT, STDOUT.replace(b'active=0', b'active=1'),
                       STDOUT.replace(b'wiped=9', b'wiped=8'), STDOUT.replace(b'page=4096', b'page=16384')):
            with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                lifetime.validate_run(stdout, stderr_for(), TOKEN, 4096)


class CopyWipeTests(unittest.TestCase):
    def validate(self, records):
        return lifetime.validate_run(STDOUT, stderr_for(copy_events=records), TOKEN, 4096)

    def event(self, records, name, case='positive'):
        return next(record for record in records if record['case'] == case and record['event'] == name)

    def changed(self, name, field, value, case='positive'):
        records = copy_records()
        target = self.event(records, name, case)
        parts = field.split('.')
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        return records

    def test_both_complete_bound_cases_are_required(self):
        proof = lifetime.validate_copy_wipe(stderr_for(), TOKEN, 4096)
        self.assertEqual(proof['mappedBytes'], 700416)
        self.assertIs(proof['apkOnlyRecoveryPrevented'], False)
        positive, negative = proof['cases']
        self.assertEqual((positive['eventCount'], negative['eventCount']), (15, 12))
        self.assertEqual((positive['realMunmapCalls'], negative['realMunmapCalls']), (1, 0))
        self.assertEqual((negative['firstBadOffset'], negative['wait']['status']), (700415, 31488))
        self.assertNotEqual(positive['sourceBase'], negative['sourceBase'])
        with self.assertRaises(ValueError):
            self.validate([])

    def test_every_new_event_and_each_occurrence_is_required_once(self):
        records = copy_records()
        for index, record in enumerate(records):
            for changed in (records[:index] + records[index + 1:], records[:index] + [record] + records[index:]):
                with self.subTest(case=record['case'], event=record['event'], count=len(changed)), self.assertRaises(ValueError):
                    self.validate(changed)

    def test_order_case_token_and_sequence_are_bound(self):
        mutations = (('COPY_AFTER', 'seq', 2), ('COPY_AFTER', 'case', 'reject-padding'),
                     ('SOURCE_HELD', 'runToken', 'b' * 32), ('TARGET_ENTER', 'event', 'COUNTER_ONLY'),
                     ('COMPLETE', 'seq', 0), ('WAIT', 'seq', 15))
        for name, field, value in mutations:
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))
        records = copy_records()
        records[2], records[3] = records[3], records[2]
        with self.assertRaises(ValueError):
            self.validate(records)
        records = copy_records()
        records.insert(1, records.pop(13))  # Early success cannot stand in for the source/copy evidence.
        with self.assertRaises(ValueError):
            self.validate(records)

    def test_suite_complete_must_follow_all_new_cases(self):
        old = stderr_for(copy_events=[])
        with self.assertRaisesRegex(ValueError, 'early/interleaved'):
            lifetime.validate_run(STDOUT, old + copy_stderr(copy_records()), TOKEN, 4096)

    def test_exact_target_pressure_and_cold_state(self):
        mutations = (
            ('BEGIN', 'target.id', '04000000000000000000000000000000'), ('BEGIN', 'target.kind', 1),
            ('BEGIN', 'target.size', 699999), ('BEGIN', 'target.data', 0x10000000),
            ('BEGIN', 'cache.evictions', 1), ('BEGIN', 'clock', 1), ('BEGIN', 'otherResourcesCold', False),
            ('SOURCE_HELD', 'target.mapped', 700000), ('SOURCE_HELD', 'target.pinned', True),
            ('PRESSURE_ACQUIRED', 'pressure.id', '02000000000000000000000000000000'),
            ('PRESSURE_ACQUIRED', 'pressure.kind', 2), ('PRESSURE_ACQUIRED', 'pressure.size', 700001),
            ('PRESSURE_ACQUIRED', 'pressure.references', 0), ('PRESSURE_ACQUIRED', 'pressureCheckedBytes', 1),
            ('PRESSURE_ACQUIRED', 'pressureValue', 66), ('EVICTED', 'target.data', 0x10000000),
            ('EVICTED', 'target.mapped', 700416), ('EVICTED', 'pressure.data', 0),
        )
        for name, field, value in mutations:
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))

    def test_copy_must_return_internal_reference_not_just_active_bytes(self):
        for name in ('COPY_BEFORE', 'COPY_AFTER'):
            for field, value in (('target.references', 0), ('target.references', 2), ('target.data', 0),
                                 ('target.mapped', 0), ('target.pinned', True), ('target.lastUsed', 2)):
                with self.subTest(name=name, field=field, value=value), self.assertRaises(ValueError):
                    self.validate(self.changed(name, field, value))

    def test_copy_layout_source_content_and_payload_proofs_are_exact(self):
        mutations = (
            ('SOURCE_HELD', 'sourceCheckedBytes', 699999), ('SOURCE_HELD', 'sourceValue', 68),
            ('SOURCE_HELD', 'paddingCheckedBytes', 415), ('SOURCE_RELEASED', 'paddingValue', 1),
            ('SOURCE_RELEASED', 'sourceCheckedBytes', 0), ('COPY_BEFORE', 'offset', 65536),
            ('COPY_BEFORE', 'length', 32), ('COPY_BEFORE', 'encoding', 1), ('COPY_BEFORE', 'bufferBytes', 64),
            ('COPY_BEFORE', 'payloadOffset', 0), ('COPY_BEFORE', 'leadingCanaryBytes', 0),
            ('COPY_BEFORE', 'trailingCanaryBytes', 15), ('COPY_BEFORE', 'initialCheckedBytes', 64),
            ('COPY_BEFORE', 'initialValue', 0), ('COPY_BEFORE', 'disjoint', False),
            ('COPY_AFTER', 'payloadCheckedBytes', 63), ('COPY_AFTER', 'payloadValue', 0),
            ('COPY_RETAINED', 'payloadValue', 0), ('COPY_RETAINED', 'leadingCheckedBytes', 0),
            ('COPY_RETAINED', 'trailingCheckedBytes', 0), ('COPY_RETAINED', 'canaryValue', 0),
            ('COPY_WIPED', 'payloadValue', 69), ('COPY_WIPED', 'wipeOffset', 0),
            ('COPY_WIPED', 'wipedBytes', 96), ('COPY_WIPED', 'canaryValue', 0),
        )
        for name, field, value in mutations:
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))

    def test_addresses_bind_full_original_intervals_and_caller_allocation(self):
        for name, field, value in (
            ('SOURCE_HELD', 'sourceBase', 0), ('SOURCE_HELD', 'sourceBase', -4096),
            ('SOURCE_HELD', 'sourceBase', 0x10000001), ('SOURCE_HELD', 'sourceBase', 1 << 64),
            ('SOURCE_HELD', 'sourceBase', True), ('BEGIN', 'bufferBase', 0x10000000 + 700400),
            ('BEGIN', 'bufferBase', (1 << 64) - 64), ('COPY_AFTER', 'bufferBase', 0x70000100),
            ('TARGET_ENTER', 'unmapBase', 0x10001000), ('TARGET_ENTER', 'unmapBytes', 700000),
            ('ZERO_SCAN', 'sourceBase', 0x20000000), ('REAL_MUNMAP', 'unmapBase', 0x20000000),
            ('PRESSURE_ACQUIRED', 'pressure.data', 0x10000000),
        ):
            with self.subTest(name=name, field=field, value=value), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))

    def test_cache_lru_and_exact_target_counts_follow_real_trim_order(self):
        for name, field, value in (
            ('SOURCE_RELEASED', 'cache.activeBytes', 700416), ('SOURCE_RELEASED', 'target.references', 1),
            ('SOURCE_RELEASED', 'target.lastUsed', 1), ('PRESSURE_ACQUIRED', 'clock', 4),
            ('PRESSURE_ACQUIRED', 'cache.peakResidentBytes', 700416),
            ('PRESSURE_RELEASE_ATTEMPT', 'armed', False), ('TARGET_ENTER', 'cache.idleBytes', 700416),
            ('TARGET_ENTER', 'cache.evictions', 1), ('TARGET_ENTER', 'target.data', 0),
            ('TARGET_ENTER', 'targetMatches', 0), ('TARGET_ENTER', 'targetMatches', 2),
            ('TARGET_ENTER', 'realMunmapCalls', 1), ('TARGET_ENTER', 'pressure.lastUsed', 3),
            ('REAL_MUNMAP', 'realMunmapCalls', 0), ('REAL_MUNMAP', 'realMunmapCalls', 2),
            ('REAL_MUNMAP', 'result', -1), ('EVICTED', 'cache.evictions', 0),
            ('EVICTED', 'cache.idleBytes', 1400832), ('COMPLETE', 'injectHits', 1),
            ('COMPLETE', 'apkOnlyRecoveryPrevented', True),
        ):
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))

    def test_full_volatile_readback_cannot_be_replaced_by_counters(self):
        for field, value in (('checkedBytes', 700000), ('checkedBytes', 0), ('nonzeroBytes', 1),
                             ('firstBadOffset', 0), ('firstBadValue', 123)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(self.changed('ZERO_SCAN', field, value))
        records = copy_records()
        del self.event(records, 'ZERO_SCAN')['checkedBytes']
        with self.assertRaises(ValueError):
            self.validate(records)
        with self.assertRaises(ValueError):
            self.validate([self.event(copy_records(), 'COMPLETE')])

    def test_negative_requires_exact_last_padding_injection_and_same_scan_gate(self):
        for name, field, value in (
            ('INJECTED', 'offset', 699999), ('INJECTED', 'oldValue', 1), ('INJECTED', 'newValue', 124),
            ('INJECTED', 'injectHits', 0), ('INJECTED', 'injectHits', 2), ('INJECTED', 'unmapBase', 0x10000000),
            ('ZERO_SCAN', 'checkedBytes', 700415), ('ZERO_SCAN', 'nonzeroBytes', 0),
            ('ZERO_SCAN', 'nonzeroBytes', 2), ('ZERO_SCAN', 'firstBadOffset', 699999),
            ('ZERO_SCAN', 'firstBadValue', 0), ('REJECT_SOURCE_NONZERO', 'realMunmapCalls', 1),
            ('REJECT_SOURCE_NONZERO', 'exitCode', 127), ('REJECT_SOURCE_NONZERO', 'event', 'COMPLETE'),
        ):
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value, 'reject-padding'))
        for name in ('REAL_MUNMAP', 'EVICTED', 'COPY_RETAINED', 'COPY_WIPED', 'COMPLETE'):
            records = copy_records()
            forbidden = copy.deepcopy(self.event(records, name))
            forbidden['case'] = 'reject-padding'
            records.insert(-1, forbidden)
            with self.subTest(forbidden=name), self.assertRaises(ValueError):
                self.validate(records)

    def test_wait_rejects_assertions_signals_other_exits_and_fake_success(self):
        for case, expected_code in (('positive', 0), ('reject-padding', 123)):
            for field, value in (('status', 6), ('exited', False), ('exited', 1), ('code', 127),
                                 ('code', -1), ('signal', 6), ('status', expected_code), ('code', True)):
                if field == 'status' and value == 0:
                    continue
                with self.subTest(case=case, field=field, value=value), self.assertRaises(ValueError):
                    self.validate(self.changed('WAIT', field, value, case))

    def test_json_field_sets_and_types_are_strict_at_every_level(self):
        for name, field, value in (
            ('BEGIN', 'seq', False), ('BEGIN', 'seq', 0.0), ('BEGIN', 'pageSize', '4096'),
            ('COPY_AFTER', 'target.references', True), ('COPY_AFTER', 'payloadCheckedBytes', 64.0),
            ('SOURCE_HELD', 'target.size', '700000'), ('ZERO_SCAN', 'nonzeroBytes', False),
            ('TARGET_ENTER', 'targetMatches', True), ('COMPLETE', 'apkOnlyRecoveryPrevented', 0),
        ):
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                self.validate(self.changed(name, field, value))
        for root in ([], None, 1, True, 'BEGIN'):
            records = copy_records(); records[0] = root
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.validate(records)
        for field in ('unexpected', 'cache'):
            records = copy_records(); records[0][field] = {'unexpected': 0}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(records)

    def test_duplicate_json_keys_malformed_json_and_constants_are_rejected(self):
        raw = stderr_for()
        for changed in (
            raw.replace(b'"seq":0', b'"seq":0,"seq":0', 1),
            raw.replace(b'"references":0', b'"references":0,"references":0', 1),
            raw.replace(b'"seq":0', b'"seq":NaN', 1),
            raw.replace(b'"seq":0', b'"seq":Infinity', 1),
            raw.replace(b'QSEG_COPY_WIPE:{', b'QSEG_COPY_WIPE:{invalid', 1),
        ):
            with self.subTest(changed=changed[:100]), self.assertRaises(ValueError):
                lifetime.validate_run(STDOUT, changed, TOKEN, 4096)

    def test_mapping_math_uses_observed_page_size_without_claiming_a_device_run(self):
        proof = lifetime.validate_copy_wipe(copy_stderr(copy_records(page=16384)), TOKEN, 16384)
        self.assertEqual(proof['mappedBytes'], 704512)
        for page in (False, 0, 3, 1, 131072):
            with self.subTest(page=page), self.assertRaises(ValueError):
                lifetime.validate_copy_wipe(stderr_for(), TOKEN, page)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for name in lifetime.SOURCE_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('fixture ' + name).encode())
        self.args = argparse.Namespace(ndk=self.root / 'ndk', adb=self.root / 'adb',
                                       output=self.root / 'evidence', serial='fixture:5555', server_port=5037)
        self.clang = lifetime.compiler_path(self.args.ndk)
        self.clang.parent.mkdir(parents=True)
        self.clang.write_bytes(b'mocked compiler; never executed')
        (self.args.ndk / 'source.properties').write_bytes(b'Pkg.Revision = fixture')
        self.args.adb.write_bytes(b'mocked adb; never executed')
        self.actions, self.calls, self.optimization = {}, [], None
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(lifetime, '__file__', str(self.root / 'tests/qseg/lifetime_test.py')).start()
        self.process = mock.patch.object(lifetime.subprocess, 'run', side_effect=self.fake_process).start()

    def fake_process(self, argv, **kwargs):
        self.assertEqual(kwargs, {'cwd': self.root, 'capture_output': True, 'timeout': 180, 'check': False})
        stdout, stderr = b'', b''
        if argv[0] == str(self.clang):
            self.optimization = 'O0' if '-O0' in argv else 'O2'
            label = self.optimization + '-compile'
            Path(argv[argv.index('-o') + 1]).write_bytes(('binary ' + self.optimization).encode())
            self.assertIn('-UNDEBUG', argv)
            self.assertNotIn('-DNDEBUG', argv)
        else:
            self.assertEqual(argv[:5], [str(self.args.adb), '-P', str(self.args.server_port), '-s', self.args.serial])
            body = argv[6:]
            identity = next((name for name, command in lifetime.DEVICE_COMMANDS.items() if body == command), None)
            if identity:
                label = 'device-' + identity
                stdout = {'model': b'GM1901\n', 'sdk': b'37\n', 'pageSize': b'4096\n', 'arch': b'aarch64\n'}[identity]
            elif argv[5] == 'push':
                label = self.optimization + '-push'
            elif body[0] == 'mkdir':
                label = 'remote-mkdir'
            elif body[0] == 'chmod':
                label = self.optimization + '-chmod'
            elif body[0] == 'rm':
                label = 'cleanup-files'
                self.assertFalse((self.args.output / 'results.json').exists())
            elif body[0] == 'rmdir':
                label = 'cleanup-directory'
                self.assertFalse((self.args.output / 'results.json').exists())
            else:
                self.assertTrue(body[0].endswith('/test'))
                label = self.optimization + '-run'
                stdout, stderr = STDOUT, stderr_for(argv[-1])
        self.calls.append((label, argv))
        result = subprocess.CompletedProcess(argv, 0, stdout, stderr)
        action = self.actions.get(label)
        if isinstance(action, Exception):
            raise action
        return action(argv, result) if action else result

    def failed(self):
        with self.assertRaises(ValueError):
            lifetime.execute(self.args)
        self.assertFalse((self.args.output / 'results.json').exists())
        report = lifetime.read_json(self.args.output / 'failure.json')
        self.assertEqual(report['status'], 'failed')
        return report

    def command(self, report, label):
        records = [lifetime.read_json(self.args.output / path) for path in report['commands']]
        return next(record for record in records if record['label'] == label)

    def test_both_optimizations_identity_logs_cleanup_and_revalidation(self):
        report = lifetime.execute(self.args)
        self.assertEqual(lifetime.verify_results(self.args.output), report)
        self.assertEqual(report['device'], {'model': 'GM1901', 'sdk': 37, 'pageSize': 4096, 'arch': 'aarch64'})
        self.assertEqual([run['optimization'] for run in report['runs']], ['O0', 'O2'])
        self.assertEqual(len(report['commands']), 15)
        self.assertEqual([label for label, _ in self.calls[-2:]], ['cleanup-files', 'cleanup-directory'])
        remote = report['remoteDirectory']
        self.assertEqual(self.calls[-2][1][-4:], ['rm', '-f', remote + '/test', remote + '/chunks.bin'])
        self.assertEqual(self.calls[-1][1][-2:], ['rmdir', remote])
        self.assertFalse((self.args.output / 'failure.json').exists())
        self.assertEqual(report['checkerRevision'], 2)
        self.assertIs(report['apkOnlyRecoveryPrevented'], False)
        for run in report['runs']:
            self.assertEqual([case['case'] for case in run['copyWipe']['cases']], ['positive', 'reject-padding'])
            self.assertIs(run['copyWipe']['apkOnlyRecoveryPrevented'], False)

    def test_offline_revalidation_never_launches_a_subprocess(self):
        report = lifetime.execute(self.args)
        self.process.reset_mock()
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('offline replay launched a process')):
            self.assertEqual(lifetime.verify_results(self.args.output), report)
        self.process.assert_not_called()

    def test_missing_or_invalid_copy_proof_prevents_success_and_preserves_raw_bytes(self):
        def changed(argv, result):
            records = copy_records(argv[-1])
            next(record for record in records if record['event'] == 'ZERO_SCAN')['checkedBytes'] = 700000
            return subprocess.CompletedProcess(argv, 0, result.stdout, stderr_for(argv[-1], copy_events=records) + b'\xffraw\n')
        self.actions['O0-run'] = changed
        report = self.failed()
        self.assertIn('copy wipe event', report['error']['message'])
        self.assertTrue(Path(self.command(report, 'O0-run')['stderr']['path']).read_bytes().endswith(b'\xffraw\n'))
        self.assertEqual([label for label, _ in self.calls[-2:]], ['cleanup-files', 'cleanup-directory'])

    def test_o0_success_o2_failure_does_not_publish_success(self):
        self.actions['O2-run'] = lambda argv, result: subprocess.CompletedProcess(argv, 127, b'\xffout', b'\xfeerror')
        report = self.failed()
        self.assertIn('O2-run', report['error']['message'])
        self.assertIn('stats', report['runs'][0])
        self.assertNotIn('stats', report['runs'][1])
        command = self.command(report, 'O2-run')
        self.assertEqual(command['returncode'], 127)
        self.assertEqual(Path(command['stdout']['path']).read_bytes(), b'\xffout')
        self.assertEqual(Path(command['stderr']['path']).read_bytes(), b'\xfeerror')

    def test_top_level_127_with_valid_internal_events_is_still_failure(self):
        self.actions['O0-run'] = lambda argv, result: subprocess.CompletedProcess(argv, 127, result.stdout, result.stderr)
        self.assertIn('exit=127', self.failed()['error']['message'])

    def test_parent_signal_is_failure(self):
        self.actions['O0-run'] = lambda argv, result: subprocess.CompletedProcess(argv, -9, result.stdout, result.stderr)
        self.assertIn('exit=-9', self.failed()['error']['message'])

    def test_timeout_preserves_partial_raw_logs(self):
        self.actions['O0-run'] = subprocess.TimeoutExpired(['fixture'], 180, output=b'\xffpartial', stderr=b'\xfeerr')
        report = self.failed()
        command = self.command(report, 'O0-run')
        self.assertEqual(command['status'], 'timeout')
        self.assertIsNone(command['returncode'])
        self.assertEqual(Path(command['stdout']['path']).read_bytes(), b'\xffpartial')
        self.assertEqual(Path(command['stderr']['path']).read_bytes(), b'\xfeerr')

    def test_launch_error_is_logged_before_validation(self):
        self.actions['O0-compile'] = FileNotFoundError('mock launch failure')
        report = self.failed()
        command = self.command(report, 'O0-compile')
        self.assertEqual(command['status'], 'launch-error')
        self.assertIn('mock launch failure', command['error'])
        self.assertTrue(Path(command['stdout']['path']).exists())

    def test_event_failure_preserves_bytes_and_attempts_cleanup(self):
        self.actions['O0-run'] = lambda argv, result: subprocess.CompletedProcess(argv, 0, result.stdout,
            result.stderr.replace(b'enomem:WARMUP_OK\n', b'enomem:RETURNED\n') + b'\xffraw\n')
        report = self.failed()
        self.assertIn('mmap events', report['error']['message'])
        self.assertTrue(Path(self.command(report, 'O0-run')['stderr']['path']).read_bytes().endswith(b'\xffraw\n'))
        self.assertEqual([label for label, _ in self.calls[-2:]], ['cleanup-files', 'cleanup-directory'])

    def test_cleanup_failure_after_success_prevents_publication(self):
        self.actions['cleanup-files'] = lambda argv, result: subprocess.CompletedProcess(argv, 1, b'', b'permission denied')
        report = self.failed()
        self.assertIsNone(report['error'])
        self.assertIn('cleanup-files', report['cleanupErrors'][0]['message'])
        self.assertEqual(self.calls[-1][0], 'cleanup-directory')

    def test_primary_and_cleanup_failures_are_both_retained(self):
        self.actions['O0-run'] = subprocess.TimeoutExpired(['fixture'], 180)
        self.actions['cleanup-directory'] = OSError('cleanup launch error')
        report = self.failed()
        self.assertIn('timeout', report['error']['message'])
        self.assertIn('cleanup-directory', report['cleanupErrors'][0]['message'])
        self.assertEqual(self.command(report, 'cleanup-directory')['status'], 'launch-error')

    def test_stale_success_is_never_overwritten(self):
        self.args.output.mkdir()
        stale = self.args.output / 'results.json'
        stale.write_bytes(b'old evidence')
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            lifetime.execute(self.args)
        self.assertEqual(stale.read_bytes(), b'old evidence')
        self.process.assert_not_called()
        self.assertEqual(list(self.args.output.iterdir()), [stale])

    def test_invalid_serial_is_reported_without_subprocess(self):
        self.args.serial = ''
        self.failed()
        self.process.assert_not_called()

    def test_invalid_port_is_reported_without_subprocess(self):
        self.args.server_port = 65536
        self.failed()
        self.process.assert_not_called()

    def test_invalid_device_identity_is_not_accepted(self):
        self.actions['device-arch'] = lambda argv, result: subprocess.CompletedProcess(argv, 0, b'x86_64\n', b'')
        report = self.failed()
        self.assertIn('device identity', report['error']['message'])
        self.assertNotIn('remote-mkdir', [label for label, _ in self.calls])

    def test_source_change_during_run_prevents_success(self):
        def change_source(argv, result):
            (self.root / 'runtime/ndkp_qseg_runtime.cpp').write_bytes(b'changed')
            return result
        self.actions['O2-run'] = change_source
        report = self.failed()
        self.assertIn('inputs changed', report['cleanupErrors'][0]['message'])

    def test_binary_change_during_run_prevents_success(self):
        def change_binary(argv, result):
            (self.args.output / 'lifetime-O0').write_bytes(b'changed')
            return result
        self.actions['O2-run'] = change_binary
        report = self.failed()
        self.assertIn('binary changed', report['cleanupErrors'][0]['message'])

    def test_revalidator_detects_changed_log(self):
        report = lifetime.execute(self.args)
        Path(self.command(report, 'O0-run')['stderr']['path']).write_bytes(b'replaced')
        with self.assertRaisesRegex(ValueError, 'command bytes changed'):
            lifetime.verify_results(self.args.output)

    def test_revalidator_rechecks_semantics_even_if_raw_identity_is_updated(self):
        report = lifetime.execute(self.args)
        reference = next(path for path in report['commands']
                         if lifetime.read_json(self.args.output / path)['label'] == 'O0-run')
        record_path = self.args.output / reference
        record = lifetime.read_json(record_path)
        stderr_path = Path(record['stderr']['path'])
        stderr_path.write_bytes(stderr_path.read_bytes().replace(b'"checkedBytes":700416', b'"checkedBytes":700000', 1))
        record['stderr'] = lifetime.identity(stderr_path)
        record_path.write_text(json.dumps(record), 'utf-8')
        with self.assertRaisesRegex(ValueError, 'copy wipe event'):
            lifetime.verify_results(self.args.output)

    def test_revalidator_rejects_report_proof_tamper_missing_fields_and_type_confusion(self):
        original = lifetime.execute(self.args)
        report_path = self.args.output / 'results.json'
        mutations = (
            ('checkerRevision', 1), ('apkOnlyRecoveryPrevented', True),
            ('runs.0.stats.active', False), ('runs.0.copyWipe.mappedBytes', 700000),
            ('runs.0.copyWipe.apkOnlyRecoveryPrevented', 0), ('runs.1.copyWipe.cases.1.injectHits', 0),
            ('runs.0.copyWipe.cases.0.realMunmapCalls', True), ('runs.0.copyWipe.cases.0.bufferBase', 1),
            ('runs.0.copyWipe.cases.1.wait.signal', 6), ('runs.1.token', original['runs'][0]['token']),
        )
        for field, value in mutations:
            report = copy.deepcopy(original)
            target = report
            parts = field.split('.')
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            target[parts[-1]] = value
            report_path.write_text(json.dumps(report), 'utf-8')
            with self.subTest(field=field), self.assertRaises(ValueError):
                lifetime.verify_results(self.args.output)
        report = copy.deepcopy(original)
        del report['runs'][0]['copyWipe']
        report_path.write_text(json.dumps(report), 'utf-8')
        with self.assertRaisesRegex(ValueError, 'copy wipe proof mismatch'):
            lifetime.verify_results(self.args.output)

    def test_revalidator_rejects_duplicate_report_keys(self):
        lifetime.execute(self.args)
        report_path = self.args.output / 'results.json'
        report_path.write_text(report_path.read_text('utf-8').replace('"checkerRevision": 2',
            '"checkerRevision": 2, "checkerRevision": 2', 1), 'utf-8')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            lifetime.verify_results(self.args.output)

    def test_revalidator_checks_cleanup_status_and_arguments(self):
        report = lifetime.execute(self.args)
        path = self.args.output / report['commands'][-1]
        record = lifetime.read_json(path)
        record['argv'][-1] += '-other'
        path.write_text(json.dumps(record), 'utf-8')
        with self.assertRaisesRegex(ValueError, 'command arguments changed'):
            lifetime.verify_results(self.args.output)
        record['argv'][-1] = report['remoteDirectory']
        record['returncode'] = 1
        path.write_text(json.dumps(record), 'utf-8')
        with self.assertRaisesRegex(ValueError, 'failed/duplicate command'):
            lifetime.verify_results(self.args.output)

    def test_non_utf8_compile_diagnostics_are_preserved_on_success(self):
        self.actions['O0-compile'] = lambda argv, result: subprocess.CompletedProcess(argv, 0, b'\xffout', b'\xfeerr')
        report = lifetime.execute(self.args)
        self.assertEqual(Path(self.command(report, 'O0-compile')['stderr']['path']).read_bytes(), b'\xfeerr')


if __name__ == '__main__':
    unittest.main()
