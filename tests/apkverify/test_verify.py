"""Real signatures, independently computed APK digests, and malformed signed records.

Requires a built apkverify_probe, JDK 21 and SDK apksigner.jar. --serial additionally
tests the same files with an Android probe, without installing any APK.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
import uuid
import struct
import subprocess
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
V2, V3 = 0x7109871A, 0xF05368C0
EXPECTED_CASES = {
    'algorithm-101': ('test_all_signature_algorithms', True),
    'algorithm-102': ('test_all_signature_algorithms', True),
    'algorithm-103': ('test_all_signature_algorithms', True),
    'algorithm-104': ('test_all_signature_algorithms', True),
    'algorithm-201': ('test_all_signature_algorithms', True),
    'algorithm-202': ('test_all_signature_algorithms', True),
    'sdk-v2-v3': ('test_sdk_apksigner_output', True),
    'multiple-signers': ('test_authenticated_invalid_records', False),
    'algorithm-mismatch': ('test_authenticated_invalid_records', False),
    'unsupported-algorithm': ('test_authenticated_invalid_records', False),
    'public-key-mismatch': ('test_authenticated_invalid_records', False),
    'stripped-v3': ('test_authenticated_invalid_records', False),
    'rotation': ('test_authenticated_invalid_records', False),
    'v31-rotation': ('test_authenticated_invalid_records', False),
    'sdk-mismatch': ('test_authenticated_invalid_records', False),
    'sdk-range': ('test_authenticated_invalid_records', False),
    'malformed-attrs': ('test_authenticated_invalid_records', False),
    'v3-only': ('test_v3_and_api26', True),
    'v3-api26': ('test_v3_and_api26', False),
    'v2-api26': ('test_v3_and_api26', True),
    'wrong-certificate': ('test_mutations', False),
    'unsigned': ('test_mutations', False),
    'tampered-dex': ('test_mutations', False),
    'tampered-so': ('test_mutations', False),
    'tampered-resource': ('test_mutations', False),
    'tampered-signature': ('test_mutations', False),
    'tampered-length': ('test_mutations', False),
    'tampered-central-directory': ('test_mutations', False),
    'truncated': ('test_mutations', False),
    'empty': ('test_mutations', False),
    'copied-signing-block': ('test_copied_block_and_excluded_schemes', False),
    'v31-block': ('test_copied_block_and_excluded_schemes', False),
    'v1-only': ('test_copied_block_and_excluded_schemes', False),
}
EXPECTED_METHODS = {
    'test_all_signature_algorithms', 'test_sdk_apksigner_output',
    'test_authenticated_invalid_records', 'test_v3_and_api26',
    'test_mutations', 'test_copied_block_and_excluded_schemes',
}
EXPECTED_API = {'v3-api26': 26, 'v2-api26': 26}
EXPECTED_ORACLE = {
    'algorithm-103', 'algorithm-104', 'algorithm-201', 'algorithm-202',
    'sdk-v2-v3', 'v3-only',
}
EXPECTED_ORACLE_MIN_SDK = {case: 37 if case == 'v3-only' else 26 for case in EXPECTED_ORACLE}
ARGS = None
RESULTS = []


def atomic_json(path, value):
    path = Path(path)
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')
    fd, temp_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return data


def publish_running(path, summary):
    try:
        atomic_json(path, summary)
    except BaseException:
        try:
            Path(path).unlink()
        except OSError:
            pass
        raise


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def selected_platform(sdk):
    platforms = list((Path(sdk) / 'platforms').glob('android-*'))
    if not platforms:
        raise FileNotFoundError(f'no Android platform under {Path(sdk) / "platforms"}')
    return max(platforms, key=lambda p: int(p.name.split('-')[1]) if p.name.split('-')[1].isdigit() else 0)


def selected_adb(sdk):
    windows_adb = Path(sdk) / 'platform-tools/adb.exe'
    return windows_adb if windows_adb.exists() else Path(sdk) / 'platform-tools/adb'


def file_identity(path):
    path = Path(path).resolve()
    try:
        stat = path.stat()
        return {'path': str(path), 'size': stat.st_size, 'sha256': sha256_file(path)}
    except OSError as exc:
        return {'path': str(path), 'error': f'{type(exc).__name__}: {exc}'}


def input_identity(args):
    java = Path(args.java) / 'bin' / ('java.exe' if (Path(args.java) / 'bin/java.exe').exists() else 'java')
    tools = java.parent
    ext = java.suffix
    build_tools = Path(args.sdk) / 'build-tools' / args.build_tools
    try:
        platform_dir = selected_platform(args.sdk)
        selected = str(platform_dir.resolve())
    except OSError as exc:
        platform_dir = None
        selected = f'ERROR: {type(exc).__name__}: {exc}'
    paths = {
        'runner': Path(__file__), 'signFixture': ROOT / 'tests/apkverify/SignFixture.java',
        'probe': args.probe, 'java': java, 'javac': tools / ('javac' + ext),
        'keytool': tools / ('keytool' + ext),
        'aapt2': build_tools / ('aapt2.exe' if ext else 'aapt2'),
        'apksigner': build_tools / 'lib/apksigner.jar',
    }
    if platform_dir is not None:
        paths['androidJar'] = platform_dir / 'android.jar'
    if args.device_probe:
        paths['deviceProbe'] = args.device_probe
    if args.serial:
        paths['adb'] = selected_adb(args.sdk)
    return {'selectedPlatform': selected, 'files': {name: file_identity(path) for name, path in paths.items()}}


def result_issues(test_result, method_ids, records, before, after):
    issues = []
    methods = [item.rsplit('.', 1)[-1] for item in method_ids]
    methods_found = set(methods)
    if len(method_ids) != len(EXPECTED_METHODS) or methods_found != EXPECTED_METHODS:
        issues.append('expected each of the six test methods exactly once')
    if test_result.testsRun != len(EXPECTED_METHODS):
        issues.append(f'expected {len(EXPECTED_METHODS)} unittest tests, got {test_result.testsRun}')
    for field in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
        if getattr(test_result, field, ()):
            issues.append(f'unittest {field}: {len(getattr(test_result, field))}')
    object_records = [record for record in records if isinstance(record, dict)]
    counts = Counter(record.get('case') for record in object_records)
    if len(object_records) != len(records):
        issues.extend(f'non-object result record: {record!r}'
                      for record in records if not isinstance(record, dict))
    if set(counts) != set(EXPECTED_CASES) or any(count != 1 for count in counts.values()):
        missing = sorted(set(EXPECTED_CASES) - set(counts))
        extra = sorted(set(counts) - set(EXPECTED_CASES))
        duplicates = sorted(case for case, count in counts.items() if count != 1)
        issues.append(f'case set mismatch: missing={missing}, extra={extra}, duplicate={duplicates}')
    device_required = 'deviceProbe' in before.get('files', {}) or 'adb' in before.get('files', {})
    for record in object_records:
        case = record.get('case')
        expected = EXPECTED_CASES.get(case)
        if expected is not None:
            method, valid = expected
            expected_api = EXPECTED_API.get(case, 37)
            expected_code = 0 if valid else 1
            if record.get('method') != method:
                issues.append(f'{case}: recorded under {record.get("method")!r}, expected {method!r}')
            if record.get('valid') is not valid:
                issues.append(f'{case}: expected valid={valid}')
            if record.get('api') != expected_api:
                issues.append(f'{case}: expected api={expected_api}')
            if record.get('hostExitCode') != expected_code:
                issues.append(f'{case}: expected hostExitCode={expected_code}')
            for field in ('apkSha256', 'certSha256', 'api', 'hostExitCode'):
                if field not in record:
                    issues.append(f'{case}: missing {field}')
            for field in ('apkSha256', 'certSha256'):
                value = record.get(field)
                if (not isinstance(value, str) or len(value) != 64 or
                        any(char not in '0123456789abcdefABCDEF' for char in value)):
                    issues.append(f'{case}: invalid {field}')
            if not isinstance(record.get('api'), int) or isinstance(record.get('api'), bool):
                issues.append(f'{case}: invalid api')
            if not isinstance(record.get('hostExitCode'), int) or isinstance(record.get('hostExitCode'), bool):
                issues.append(f'{case}: invalid hostExitCode')
            oracle = record.get('oracle')
            oracle_status = 'passed' if case in EXPECTED_ORACLE else 'not-requested'
            if not isinstance(oracle, dict) or oracle.get('status') != oracle_status:
                issues.append(f'{case}: expected oracle status {oracle_status}')
            elif oracle_status == 'passed':
                if oracle.get('minSdkVersion') != EXPECTED_ORACLE_MIN_SDK[case]:
                    issues.append(f'{case}: expected oracle minSdkVersion={EXPECTED_ORACLE_MIN_SDK[case]}')
                if not isinstance(oracle.get('output'), str):
                    issues.append(f'{case}: invalid oracle output')
            elif oracle.get('minSdkVersion') is not None:
                issues.append(f'{case}: unexpected oracle minSdkVersion')
            if device_required:
                for field in ('deviceExitCode', 'device'):
                    if field not in record:
                        issues.append(f'{case}: missing {field}')
                if record.get('deviceExitCode') != expected_code:
                    issues.append(f'{case}: expected deviceExitCode={expected_code}')
                if not isinstance(record.get('deviceExitCode'), int) or isinstance(record.get('deviceExitCode'), bool):
                    issues.append(f'{case}: invalid deviceExitCode')
                if not isinstance(record.get('device'), str):
                    issues.append(f'{case}: invalid device output')
        if record.get('status') != 'passed':
            issues.append(f'{case}: result status is {record.get("status")!r}')
    if before != after:
        issues.append('validation inputs changed during the run')
    for label, identity in (('before', before), ('after', after)):
        if str(identity.get('selectedPlatform', '')).startswith('ERROR:'):
            issues.append(f'{label} Android platform selection failed')
        if any('error' in item for item in identity.get('files', {}).values()):
            issues.append(f'{label} input identity is incomplete')
    return issues


class ContractTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.method_ids = []

    def startTest(self, test):
        self.method_ids.append(test.id())
        super().startTest(test)


def result_counts(test_result):
    return {
        'testsRun': test_result.testsRun,
        'failures': len(test_result.failures), 'errors': len(test_result.errors),
        'skipped': len(test_result.skipped), 'expectedFailures': len(test_result.expectedFailures),
        'unexpectedSuccesses': len(test_result.unexpectedSuccesses),
    }


def run_summary(args, run_id, started_at):
    return {
        'schemaVersion': 1, 'runId': run_id, 'status': 'running', 'startedAt': started_at,
        'scope': 'host-and-device' if args.serial else 'host-only',
        'resultsFile': 'results.json', 'resultsSizeBytes': None, 'resultsSha256': None,
        'expectedTestMethods': sorted(EXPECTED_METHODS), 'actualTestMethods': [],
        'expectedCaseCount': len(EXPECTED_CASES), 'actualCaseCount': 0,
        'unittest': None, 'inputsBefore': None, 'inputsAfter': None,
        'parameters': {
            'probe': str(args.probe.resolve()), 'sdk': str(args.sdk.resolve()),
            'javaHome': str(args.java.resolve()), 'buildTools': args.build_tools,
            'serial': args.serial, 'deviceProbe': str(args.device_probe.resolve()) if args.device_probe else None,
            'work': str(args.work.resolve()),
        },
        'host': {'platform': platform.platform(), 'python': sys.version.split()[0],
                 'pythonExecutable': str(Path(sys.executable).resolve())},
    }


def main(argv=None):
    global ARGS, RESULTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--build-tools', default='37.0.0')
    parser.add_argument('--work', type=Path, default=ROOT / 'build/apkverify-tests')
    parser.add_argument('--serial')
    parser.add_argument('--device-probe', type=Path)
    args = parser.parse_args(argv)
    if bool(args.serial) != bool(args.device_probe):
        parser.error('--serial and --device-probe must be supplied together')

    ARGS, RESULTS = args, []
    out = args.work.resolve()
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f'cannot prepare result directory {out}: {exc}', file=sys.stderr)
        return 2

    run_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc).isoformat()
    summary_path, results_path = out / 'run-summary.json', out / 'results.json'
    summary = run_summary(args, run_id, started_at)
    try:
        publish_running(summary_path, summary)
    except BaseException as exc:
        print(f'cannot invalidate prior run summary: {exc}', file=sys.stderr)
        return 2

    result = ContractTestResult(stream=sys.stderr, descriptions=True, verbosity=2)
    method_ids = []
    before = after = {'selectedPlatform': None, 'files': {}}
    runner_errors = []
    try:
        atomic_json(results_path, [])
        before = input_identity(args)
        summary['inputsBefore'] = before
        unreadable = [name for name, item in before['files'].items() if 'error' in item]
        if unreadable:
            runner_errors.append('unreadable inputs: ' + ', '.join(unreadable))
        else:
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(VerifyTest)
            runner = unittest.TextTestRunner(stream=sys.stderr, descriptions=True, verbosity=2,
                                             resultclass=ContractTestResult)
            result = runner.run(suite)
    except BaseException as exc:
        runner_errors.append(f'{type(exc).__name__}: {exc}')
    finally:
        try:
            after = input_identity(args)
        except BaseException as exc:
            runner_errors.append(f'cannot capture final input identity: {type(exc).__name__}: {exc}')

    method_ids = getattr(result, 'method_ids', [])
    issues = result_issues(result, method_ids, RESULTS, before, after)
    issues.extend(runner_errors)
    summary.update({
        'actualTestMethods': [item.rsplit('.', 1)[-1] for item in method_ids],
        'actualCaseCount': len(RESULTS), 'unittest': result_counts(result),
        'inputsBefore': before, 'inputsAfter': after,
    })
    try:
        result_bytes = atomic_json(results_path, RESULTS)
        summary['resultsSizeBytes'] = len(result_bytes)
        summary['resultsSha256'] = hashlib.sha256(result_bytes).hexdigest()
    except BaseException as exc:
        issues.append(f'cannot write results.json: {type(exc).__name__}: {exc}')

    summary['issues'] = issues
    summary['finishedAt'] = datetime.now(timezone.utc).isoformat()
    summary['status'] = 'passed' if not issues else 'failed'
    try:
        atomic_json(summary_path, summary)
    except BaseException as exc:
        try:
            summary_path.unlink()
        except OSError:
            pass
        print(f'cannot write final run summary: {exc}', file=sys.stderr)
        return 2
    print(f"APK verifier result: {summary['status']} ({len(issues)} issue(s)); summary: {summary_path}",
          file=sys.stderr)
    return 0 if summary['status'] == 'passed' else 1


def lp(data):
    return struct.pack('<I', len(data)) + data


def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed: {result.stdout}\n{result.stderr}')
    return result.stdout


class VerifyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        RESULTS.clear()
        cls.results = RESULTS
        cls.out = ARGS.work.resolve()
        cls.out.mkdir(parents=True, exist_ok=True)
        cls.java = ARGS.java / 'bin/java.exe' if (ARGS.java / 'bin/java.exe').exists() else ARGS.java / 'bin/java'
        cls.keytool = cls.java.with_name('keytool' + cls.java.suffix)
        run([cls.java.with_name('javac' + cls.java.suffix), '-d', cls.out, ROOT / 'tests/apkverify/SignFixture.java'])
        cls.keys = {}
        for kind, key_options in [('rsa', ['-keyalg', 'RSA', '-keysize', '2048']), ('ec', ['-keyalg', 'EC', '-groupname', 'secp256r1'])]:
            key = cls.out / f'{kind}.p12'
            if not key.exists():
                run([cls.keytool, '-genkeypair', '-keystore', key, '-storetype', 'PKCS12', '-storepass', 'android',
                     '-keypass', 'android', '-alias', 'test', '-dname', 'CN=apkverify disposable test', '-validity', '3650', *key_options])
            cls.keys[kind] = key
        unsigned = cls.out / 'unsigned.apk'
        manifest = cls.out / 'AndroidManifest.xml'
        manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.ndkp.verify"><application android:hasCode="false"/></manifest>')
        platform = selected_platform(ARGS.sdk)
        aapt = ARGS.sdk / 'build-tools' / ARGS.build_tools / ('aapt2.exe' if cls.java.suffix else 'aapt2')
        manifest_apk = cls.out / 'manifest.apk'
        run([aapt, 'link', '-o', manifest_apk, '--manifest', manifest, '-I', platform / 'android.jar', '--min-sdk-version', '26', '--target-sdk-version', '28'])
        with zipfile.ZipFile(unsigned, 'w') as z:
            with zipfile.ZipFile(manifest_apk) as source:
                z.writestr('AndroidManifest.xml', source.read('AndroidManifest.xml'))
            z.writestr('classes.dex', b'dex fixture' + b'X' * (2 * 1024 * 1024 + 71))
            z.writestr('lib/arm64-v8a/libtest.so', b'ELF fixture')
            z.writestr('assets/resource', b'protected resource')
            z.comment = b'comment with fake PK\x05\x06 marker'
        cls.unsigned = unsigned.read_bytes()
        cls.eocd = len(cls.unsigned) - 22 - len(b'comment with fake PK\x05\x06 marker')
        cls.cd = struct.unpack_from('<I', cls.unsigned, cls.eocd + 16)[0]
        cls.signer = ARGS.sdk / 'build-tools' / ARGS.build_tools / 'lib/apksigner.jar'
        if ARGS.serial:
            cls.adb = ARGS.sdk / 'platform-tools' / ('adb.exe' if (ARGS.sdk / 'platform-tools/adb.exe').exists() else 'adb')
            cls.remote = '/data/local/tmp/ndkp-apkverify-test'
            run([cls.adb, '-s', ARGS.serial, 'shell', 'mkdir', '-p', cls.remote])
            run([cls.adb, '-s', ARGS.serial, 'push', ARGS.device_probe, cls.remote + '/probe'])
            run([cls.adb, '-s', ARGS.serial, 'shell', 'chmod', '700', cls.remote + '/probe'])

    @classmethod
    def tearDownClass(cls):
        if ARGS.serial:
            # This fixed, test-owned directory contains only fixtures created above.
            run([cls.adb, '-s', ARGS.serial, 'shell', 'rm', '-r', cls.remote])

    def signed(self, algorithm=0x0103, scheme=V2, attrs=b'', extra_signer=False,
               digest_id=None, public_mismatch=False, sdk=(28, 0x7FFFFFFF), signed_sdk=None):
        sha = 'sha512' if algorithm in (0x0102, 0x0104, 0x0202) else 'sha256'
        chunks = []
        for section in (self.unsigned[:self.cd], self.unsigned[self.cd:self.eocd], self.unsigned[self.eocd:]):
            for i in range(0, len(section), 1024 * 1024):
                chunk = section[i:i + 1024 * 1024]
                chunks.append(hashlib.new(sha, b'\xa5' + struct.pack('<I', len(chunk)) + chunk).digest())
        digest = hashlib.new(sha, b'\x5a' + struct.pack('<I', len(chunks)) + b''.join(chunks)).digest()
        key = self.keys['ec' if algorithm in (0x0201, 0x0202) else 'rsa']
        data_file, sig_file = self.out / 'signed-data', self.out / 'signature'
        # Export the certificate independently of the signature helper.
        cert_file = self.out / 'cert.der'
        run([self.keytool, '-exportcert', '-keystore', key, '-storepass', 'android', '-alias', 'test', '-file', cert_file])
        cert = cert_file.read_bytes()
        signed = lp(lp(struct.pack('<I', algorithm if digest_id is None else digest_id) + lp(digest))) + lp(lp(cert))
        if scheme == V3:
            signed += struct.pack('<II', *(signed_sdk or sdk))
        signed += lp(attrs)
        data_file.write_bytes(signed)
        name = 'RSASSA-PSS' if algorithm in (0x0101, 0x0102) else ('SHA512' if sha == 'sha512' else 'SHA256') + ('withECDSA' if key == self.keys['ec'] else 'withRSA')
        run([self.java, '-cp', self.out, 'SignFixture', key, data_file, sig_file, name, 'SHA-512' if sha == 'sha512' else 'SHA-256'])
        public = Path(str(sig_file) + '.pub').read_bytes()
        if public_mismatch:
            public = public[:-1] + bytes([public[-1] ^ 1])
        signatures = lp(struct.pack('<I', algorithm) + lp(sig_file.read_bytes()))
        signer = lp(signed) + (struct.pack('<II', *sdk) if scheme == V3 else b'') + lp(signatures) + lp(public)
        value = lp(lp(signer) * (2 if extra_signer else 1))
        pair = struct.pack('<QI', len(value) + 4, scheme) + value
        length = struct.pack('<Q', len(pair) + 24)
        block = length + pair + length + b'APK Sig Block 42'
        apk = bytearray(self.unsigned[:self.cd] + block + self.unsigned[self.cd:])
        struct.pack_into('<I', apk, self.eocd + len(block) + 16, self.cd + len(block))
        return apk, hashlib.sha256(cert).hexdigest()

    def probe(self, name, data, cert, valid, api=37, oracle=False):
        apk = self.out / f'{name}.apk'; apk.write_bytes(data)
        result = subprocess.run([str(ARGS.probe.resolve()), str(apk), cert, str(api)], capture_output=True, text=True)
        device = None
        device_code = None
        if ARGS.serial:
            run([self.adb, '-s', ARGS.serial, 'push', apk, self.remote + '/input.apk'])
            remote = subprocess.run([str(self.adb), '-s', ARGS.serial, 'shell', self.remote + '/probe', self.remote + '/input.apk', cert, str(api)], capture_output=True, text=True)
            device_code = remote.returncode
            device = remote.stdout.strip()
        oracle_min_sdk = max(28, api) if name.startswith('v3') else 26
        record = {'case': name, 'method': self._testMethodName, 'status': 'failed',
                  'apkSha256': hashlib.sha256(data).hexdigest(), 'valid': valid, 'api': api,
                  'certSha256': cert, 'hostExitCode': result.returncode,
                  'host': result.stdout.strip(), 'deviceExitCode': device_code, 'device': device,
                  'oracle': {'status': 'pending' if oracle else 'not-requested',
                             'minSdkVersion': oracle_min_sdk if oracle else None}}
        self.results.append(record)
        self.assertEqual(result.returncode, 0 if valid else 1, name + ': ' + result.stdout + result.stderr)
        if ARGS.serial:
            self.assertEqual(device_code, result.returncode, name + ': ' + device)
        if oracle:
            oracle_output = run([self.java, '-jar', self.signer, 'verify', '--min-sdk-version', oracle_min_sdk, apk])
            record['oracle'] = {'status': 'passed', 'minSdkVersion': oracle_min_sdk,
                                'output': oracle_output.strip()}
        record['status'] = 'passed'

    def test_all_signature_algorithms(self):
        for alg in (0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202):
            with self.subTest(algorithm=alg):
                data, cert = self.signed(alg)
                # SDK apksig requests obsolete JCA PSS aliases absent from stock JDK 21.
                self.probe(f'algorithm-{alg:x}', data, cert, True, oracle=alg not in (0x0101, 0x0102))

    def test_sdk_apksigner_output(self):
        output = self.out / 'sdk-signed.apk'
        run([self.java, '-jar', self.signer, 'sign', '--ks', self.keys['rsa'], '--ks-pass', 'pass:android',
             '--min-sdk-version', '26', '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
             '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false', '--out', output, self.out / 'unsigned.apk'])
        _, cert = self.signed()
        self.probe('sdk-v2-v3', output.read_bytes(), cert, True, oracle=True)

    def test_authenticated_invalid_records(self):
        options = {
            'multiple-signers': {'extra_signer': True},
            'algorithm-mismatch': {'digest_id': 0x0104},
            'unsupported-algorithm': {'algorithm': 0x0301},
            'public-key-mismatch': {'public_mismatch': True},
            'stripped-v3': {'attrs': lp(struct.pack('<II', 0xBEEFF00D, 3))},
            'rotation': {'scheme': V3, 'attrs': lp(struct.pack('<I', 0x3BA06F8C))},
            'v31-rotation': {'scheme': V3, 'attrs': lp(struct.pack('<II', 0x559F8B02, 33))},
            'sdk-mismatch': {'scheme': V3, 'signed_sdk': (29, 0x7FFFFFFF)},
            'sdk-range': {'scheme': V3, 'sdk': (28, 30)},
            'malformed-attrs': {'attrs': struct.pack('<I', 100)},
        }
        for name, settings in options.items():
            with self.subTest(case=name):
                data, cert = self.signed(**settings); self.probe(name, data, cert, False)

    def test_v3_and_api26(self):
        data, cert = self.signed(scheme=V3)
        self.probe('v3-only', data, cert, True, oracle=True)
        self.probe('v3-api26', data, cert, False, api=26)
        data, cert = self.signed()
        self.probe('v2-api26', data, cert, True, api=26)

    def test_mutations(self):
        original, cert = self.signed()
        self.probe('wrong-certificate', original, '00' * 32, False)
        self.probe('unsigned', self.unsigned, cert, False)
        for name, at in [('dex', 100), ('so', original.index(b'ELF fixture')),
                         ('resource', original.index(b'protected resource')), ('signature', self.cd + 40),
                         ('length', self.cd), ('central-directory', self.cd + len(original) - len(self.unsigned) + 16)]:
            data = bytearray(original); data[at] ^= 1
            self.probe('tampered-' + name, data, cert, False)
        self.probe('truncated', original[:-1], cert, False)
        self.probe('empty', b'', cert, False)

    def test_copied_block_and_excluded_schemes(self):
        original, cert = self.signed()
        source = self.unsigned
        try:
            self.unsigned = source.replace(b'protected resource', b'changed!! resource')
            changed, _ = self.signed()
        finally:
            self.unsigned = source
        block_size = len(original) - len(source)
        copied = changed[:self.cd] + original[self.cd:self.cd + block_size] + changed[self.cd + block_size:]
        self.probe('copied-signing-block', copied, cert, False)
        v31 = bytearray(original)
        struct.pack_into('<I', v31, self.cd + 16, 0x1B93AD61)
        self.probe('v31-block', v31, cert, False)
        signed = self.out / 'v1-only.apk'
        run([self.java, '-jar', self.signer, 'sign', '--ks', self.keys['rsa'], '--ks-pass', 'pass:android',
             '--min-sdk-version', '26', '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'false',
             '--v3-signing-enabled', 'false', '--out', signed, self.out / 'unsigned.apk'])
        self.probe('v1-only', signed.read_bytes(), cert, False)


if __name__ == '__main__':
    raise SystemExit(main())
