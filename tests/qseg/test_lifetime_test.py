"""Host-only runner regressions: all compiler/ADB subprocesses are mocked."""
import argparse
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


def stderr_for(token=TOKEN, events=EVENTS):
    return b''.join(('QSEG_MMAP:' + token + ':' + event + '\n').encode('ascii') for event in events)


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
