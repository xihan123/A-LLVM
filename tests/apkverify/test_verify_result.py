"""Offline contract tests for the APK verifier result protocol."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import test_verify as verify


def result_for(case, device=False, **changes):
    method, valid = verify.EXPECTED_CASES[case]
    api = verify.EXPECTED_API.get(case, 37)
    expected_code = 0 if valid else 1
    oracle_requested = case in verify.EXPECTED_ORACLE
    record = {
        'case': case, 'method': method, 'status': 'passed', 'valid': valid,
        'apkSha256': 'a' * 64, 'certSha256': 'b' * 64, 'api': api,
        'hostExitCode': expected_code,
        'oracle': {
            'status': 'passed' if oracle_requested else 'not-requested',
            'minSdkVersion': verify.EXPECTED_ORACLE_MIN_SDK[case] if oracle_requested else None,
            'output': '' if oracle_requested else None,
        },
    }
    if device:
        record.update({'deviceExitCode': expected_code, 'device': 'probe: accepted' if valid else 'probe: rejected'})
    record.update(changes)
    return record


def passing_result(**changes):
    values = {
        'testsRun': 6, 'failures': [], 'errors': [], 'skipped': [],
        'expectedFailures': [], 'unexpectedSuccesses': [],
    }
    values.update(changes)
    return SimpleNamespace(**values)


def stable_inputs():
    return {'selectedPlatform': 'android-36', 'files': {
        'runner': {'path': 'runner.py', 'size': 1, 'sha256': 'a' * 64},
        'probe': {'path': 'probe.exe', 'size': 1, 'sha256': 'b' * 64},
    }}


def stable_device_inputs():
    inputs = stable_inputs()
    inputs['files'].update({
        'deviceProbe': {'path': 'device-probe', 'size': 1, 'sha256': 'c' * 64},
        'adb': {'path': 'adb.exe', 'size': 1, 'sha256': 'd' * 64},
    })
    return inputs


class ResultContractTest(unittest.TestCase):
    def all_records(self):
        return [result_for(case) for case in verify.EXPECTED_CASES]

    def method_ids(self):
        return ['suite.' + method for method in sorted(verify.EXPECTED_METHODS)]

    def test_complete_run_is_accepted(self):
        issues = verify.result_issues(
            passing_result(), self.method_ids(), self.all_records(), stable_inputs(), stable_inputs())
        self.assertEqual([], issues)

    def test_each_unittest_nonpassing_state_is_rejected_independently(self):
        records = self.all_records()
        markers = {
            'failures': [('test', 'failure')],
            'errors': [('test', 'error')],
            'skipped': [('test', 'skip')],
            'expectedFailures': [('test', 'xfail')],
            'unexpectedSuccesses': ['test'],
        }
        for field, marker in markers.items():
            with self.subTest(field=field):
                result = passing_result(**{field: marker})
                issues = verify.result_issues(result, self.method_ids(), records,
                                              stable_inputs(), stable_inputs())
                self.assertTrue(any(f'unittest {field}: 1' in issue for issue in issues))

    def test_incomplete_case_list_is_rejected_independently(self):
        records = self.all_records()[:-1]
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('case set mismatch' in issue for issue in issues))

    def test_setup_and_teardown_errors_cannot_pass(self):
        records = self.all_records()
        setup = passing_result(testsRun=1, errors=[('setUpClass', 'setup error')])
        issues = verify.result_issues(setup, ['suite.setUpClass'], [], stable_inputs(), stable_inputs())
        self.assertTrue(any('unittest errors: 1' in issue for issue in issues))
        teardown = passing_result(errors=[('tearDownClass', 'teardown error')])
        issues = verify.result_issues(teardown, self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('unittest errors: 1' in issue for issue in issues))

    def test_empty_and_wrong_method_sets_are_rejected(self):
        issues = verify.result_issues(passing_result(), [], [], stable_inputs(), stable_inputs())
        self.assertTrue(any('six test methods exactly once' in issue for issue in issues))
        self.assertTrue(any('case set mismatch' in issue for issue in issues))
        wrong = self.method_ids()[:-1] + ['suite.test_unexpected_method']
        issues = verify.result_issues(passing_result(), wrong, self.all_records(),
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('six test methods exactly once' in issue for issue in issues))

    def test_duplicate_and_replaced_cases_are_rejected(self):
        records = self.all_records()
        records.append(result_for('algorithm-101'))
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('case set mismatch' in issue for issue in issues))

        replaced = self.all_records()[:-1]
        replaced.append({'case': 'unrecognized-case', 'status': 'passed'})
        issues = verify.result_issues(passing_result(), self.method_ids(), replaced,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('case set mismatch' in issue for issue in issues))

        extra = self.all_records() + [{'case': 'unrecognized-case', 'status': 'passed'}]
        issues = verify.result_issues(passing_result(), self.method_ids(), extra,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('case set mismatch' in issue for issue in issues))

    def test_wrong_expected_result_is_rejected(self):
        records = self.all_records()
        records[0]['valid'] = False
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('algorithm-101: expected valid=True' in issue for issue in issues))

    def test_api_return_codes_and_oracle_fields_are_bound(self):
        records = self.all_records()
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertEqual([], issues)

        records = self.all_records()
        records_by_case = {record['case']: record for record in records}
        records_by_case['v3-api26']['api'] = 37
        records_by_case['v3-api26']['hostExitCode'] = 0
        records_by_case['algorithm-103']['oracle']['minSdkVersion'] = 37
        records_by_case['algorithm-103']['oracle']['output'] = None
        records_by_case['algorithm-101']['oracle']['status'] = 'passed'
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('v3-api26: expected api=26' in issue for issue in issues))
        self.assertTrue(any('v3-api26: expected hostExitCode=1' in issue for issue in issues))
        self.assertTrue(any('algorithm-103: expected oracle minSdkVersion=26' in issue for issue in issues))
        self.assertTrue(any('algorithm-103: invalid oracle output' in issue for issue in issues))
        self.assertTrue(any('algorithm-101: expected oracle status not-requested' in issue for issue in issues))

    def test_device_return_codes_and_output_are_required_for_device_scope(self):
        records = [result_for(case, device=True) for case in verify.EXPECTED_CASES]
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_device_inputs(), stable_device_inputs())
        self.assertEqual([], issues)

        records[0].pop('deviceExitCode')
        records[1]['deviceExitCode'] = '0'
        records[2]['device'] = None
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_device_inputs(), stable_device_inputs())
        self.assertTrue(any('algorithm-101: missing deviceExitCode' in issue for issue in issues))
        self.assertTrue(any('algorithm-102: invalid deviceExitCode' in issue for issue in issues))
        self.assertTrue(any('algorithm-103: invalid device output' in issue for issue in issues))

    def test_missing_audit_fields_are_rejected(self):
        records = self.all_records()
        records[0].pop('certSha256')
        records[1]['apkSha256'] = 'not-a-digest'
        records[2]['api'] = True
        records[3]['hostExitCode'] = '0'
        records[4]['status'] = 'pending'
        issues = verify.result_issues(passing_result(), self.method_ids(), records,
                                      stable_inputs(), stable_inputs())
        self.assertTrue(any('algorithm-101: missing certSha256' in issue for issue in issues))
        self.assertTrue(any('algorithm-102: invalid apkSha256' in issue for issue in issues))
        self.assertTrue(any('algorithm-103: invalid api' in issue for issue in issues))
        self.assertTrue(any('algorithm-104: invalid hostExitCode' in issue for issue in issues))
        self.assertTrue(any('algorithm-201: result status' in issue for issue in issues))

    def test_input_change_and_unreadable_identity_are_rejected(self):
        before = stable_inputs()
        after = stable_inputs()
        after['files']['probe']['sha256'] = 'c' * 64
        issues = verify.result_issues(passing_result(), self.method_ids(), self.all_records(), before, after)
        self.assertTrue(any('inputs changed' in issue for issue in issues))
        after['files']['probe'] = {'path': 'probe.exe', 'error': 'gone'}
        issues = verify.result_issues(passing_result(), self.method_ids(), self.all_records(), before, after)
        self.assertTrue(any('input identity is incomplete' in issue for issue in issues))

    def test_atomic_json_replaces_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.json'
            data = verify.atomic_json(target, {'status': 'running'})
            self.assertEqual(data, target.read_bytes())
            self.assertEqual({'status': 'running'}, json.loads(target.read_text()))
            with patch.object(verify.os, 'replace', side_effect=OSError('replace failed')):
                with self.assertRaises(OSError):
                    verify.atomic_json(target, {'status': 'failed'})
            self.assertEqual({'status': 'running'}, json.loads(target.read_text()))
            self.assertEqual([], list(Path(directory).glob('*.tmp')))

    def test_running_publication_removes_old_success_when_it_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'run-summary.json'
            target.write_text('{"status":"passed"}\n')
            with patch.object(verify, 'atomic_json', side_effect=OSError('cannot publish')):
                with self.assertRaises(OSError):
                    verify.publish_running(target, {'status': 'running'})
            self.assertFalse(target.exists())

    def test_cli_final_result_and_summary_publication_failures_do_not_leave_passed(self):
        real_atomic_json = verify.atomic_json
        for failed_name in ('results.json', 'run-summary.json'):
            with self.subTest(file=failed_name), tempfile.TemporaryDirectory() as directory:
                work = Path(directory) / 'work'
                work.mkdir()
                summary_path = work / 'run-summary.json'
                results_path = work / 'results.json'
                summary_path.write_text('{"runId":"old","status":"passed"}\n')
                writes = {}

                def fail_final_write(path, value):
                    path = Path(path)
                    writes[path.name] = writes.get(path.name, 0) + 1
                    final_attempt = 2
                    if path.name == failed_name and writes[path.name] == final_attempt:
                        raise OSError(f'simulated final {failed_name} failure')
                    return real_atomic_json(path, value)

                with patch.object(verify, 'atomic_json', side_effect=fail_final_write):
                    code = verify.main([
                        '--probe', str(Path(directory) / 'missing-probe'),
                        '--sdk', str(Path(directory) / 'missing-sdk'),
                        '--java', str(Path(directory) / 'missing-jdk'),
                        '--work', str(work),
                    ])

                self.assertNotEqual(0, code)
                if failed_name == 'results.json':
                    self.assertEqual('failed', json.loads(summary_path.read_text())['status'])
                    self.assertIn('cannot write results.json', summary_path.read_text())
                    self.assertEqual([], json.loads(results_path.read_text()))
                else:
                    self.assertFalse(summary_path.exists())
                    self.assertEqual([], json.loads(results_path.read_text()))

    def test_cli_invalid_probe_invalidates_previous_success_and_results(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / 'work'
            work.mkdir()
            summary_path = work / 'run-summary.json'
            results_path = work / 'results.json'
            summary_path.write_text('{"runId":"old","status":"passed"}\n')
            results_path.write_text('[{"case":"stale"}]\n')
            stderr = StringIO()
            with redirect_stderr(stderr):
                code = verify.main([
                    '--probe', str(Path(directory) / 'missing-probe'),
                    '--sdk', str(Path(directory) / 'missing-sdk'),
                    '--java', str(Path(directory) / 'missing-jdk'),
                    '--work', str(work),
                ])
            summary = json.loads(summary_path.read_text())
            self.assertNotEqual(0, code)
            self.assertNotEqual('old', summary['runId'])
            self.assertEqual('failed', summary['status'])
            self.assertEqual([], json.loads(results_path.read_text()))
            self.assertIn('missing-probe', json.dumps(summary['inputsBefore']))

    def test_cli_shares_setup_and_probe_records_with_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / 'sdk'
            java = root / 'jdk'
            work = root / 'work'
            probe = root / 'apkverify_probe.exe'
            platform_dir = sdk / 'platforms' / 'android-36'
            build_tools = sdk / 'build-tools' / '37.0.0'
            for path in (
                platform_dir / 'android.jar', java / 'bin' / 'java.exe',
                java / 'bin' / 'javac.exe', java / 'bin' / 'keytool.exe',
                build_tools / 'aapt2.exe', build_tools / 'lib' / 'apksigner.jar', probe,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'stub')

            def stub_run(command):
                command = [str(item) for item in command]
                if len(command) > 1 and command[1] == 'link':
                    manifest_apk = Path(command[command.index('-o') + 1])
                    with zipfile.ZipFile(manifest_apk, 'w') as archive:
                        archive.writestr('AndroidManifest.xml', b'manifest fixture')
                return ''

            class StubRunner:
                def __init__(self, *args, **kwargs):
                    pass

                def run(self, suite):
                    verify.VerifyTest.setUpClass()
                    probe_test = verify.VerifyTest('test_all_signature_algorithms')
                    probe_test.probe('algorithm-101', b'apk fixture', 'a' * 64, True)
                    verify.VerifyTest.results.extend(
                        record for record in ResultContractTest().all_records()
                        if record['case'] != 'algorithm-101'
                    )
                    verify.VerifyTest.tearDownClass()
                    result = passing_result(method_ids=self_test.method_ids())
                    return result

            self_test = self
            stderr = StringIO()
            with patch.object(verify, 'run', side_effect=stub_run), \
                    patch.object(verify.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='accepted', stderr='')) as probe_run, \
                    patch.object(verify.unittest, 'TextTestRunner', StubRunner), \
                    redirect_stderr(stderr):
                code = verify.main([
                    '--probe', str(probe), '--sdk', str(sdk), '--java', str(java),
                    '--work', str(work),
                ])

            summary = json.loads((work / 'run-summary.json').read_text())
            records = json.loads((work / 'results.json').read_text())
            self.assertEqual(1, probe_run.call_count)
            self.assertEqual(0, code, stderr.getvalue())
            self.assertEqual('passed', summary['status'])
            self.assertEqual(33, len(records))
            self.assertEqual('accepted', next(record['host'] for record in records
                                              if record['case'] == 'algorithm-101'))

    def test_summary_starts_running_and_binds_expected_inputs(self):
        args = SimpleNamespace(probe=Path('probe'), sdk=Path('sdk'), java=Path('jdk'),
                               build_tools='37.0.0', serial=None, device_probe=None,
                               work=Path('results'))
        summary = verify.run_summary(args, 'abc123', 'timestamp')
        self.assertEqual('running', summary['status'])
        self.assertEqual(33, summary['expectedCaseCount'])
        self.assertEqual('results.json', summary['resultsFile'])
        self.assertEqual(sorted(verify.EXPECTED_METHODS), summary['expectedTestMethods'])


if __name__ == '__main__':
    unittest.main()
