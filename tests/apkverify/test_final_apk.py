"""Exercise the final verifier against real signed dex2c device fixtures (no device needed)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_dex2c_apk import verify


class FinalApkTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dex2c-final-')
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        self.report = self.out / 'report.json'
        self.generated = self.out / 'generated'
        self.native = self.out / 'native'
        self.generated.mkdir(); self.native.mkdir()
        for directory, name in ((self.generated, 'selection.json'), (self.native, 'protection.json')):
            (directory / name).write_bytes((ARGS.fixtures / directory.name / name).read_bytes())
        string_selection = ARGS.fixtures / 'generated/string-selection.json'
        if string_selection.exists():
            (self.generated / string_selection.name).write_bytes(string_selection.read_bytes())
        classes = ARGS.fixtures / 'generated/classes.jar'
        if classes.exists():
            (self.generated / classes.name).write_bytes(classes.read_bytes())
        if (ARGS.fixtures / 'native/segments.json').exists():
            (self.native / 'segments.json').write_bytes((ARGS.fixtures / 'native/segments.json').read_bytes())
        receipt = json.loads((self.native / 'protection.json').read_bytes())
        for unit in (receipt.get('integrityRecheck') or {}).get('irSha256', {}):
            name = unit + '.ll'
            (self.native / name).write_bytes((ARGS.fixtures / 'native' / name).read_bytes())

    def check(self, *apks):
        verify(list(apks) or [ARGS.fixtures / 'protected.apk'], self.native, self.generated,
               ARGS.java, ARGS.apksigner, 26, self.report)

    def repack(self, transform, additions=()):
        unsigned, signed = self.out / 'unsigned.apk', self.out / 'signed.apk'
        with zipfile.ZipFile(ARGS.fixtures / 'protected.apk') as source, zipfile.ZipFile(unsigned, 'w') as output:
            for item in source.infolist():
                data = transform(item.filename, source.read(item))
                if data is not None:
                    output.writestr(item.filename, data)
            for name, data in additions:
                output.writestr(name, data)
        subprocess.run([str(ARGS.java), '-jar', str(ARGS.apksigner), 'sign', '--ks', str(ARGS.fixtures / 'test.jks'),
                        '--ks-key-alias', 'test', '--ks-pass', 'pass:android', '--min-sdk-version', '26',
                        '--out', str(signed), str(unsigned)], check=True, capture_output=True)
        return signed

    def test_valid_and_no_mutation(self):
        original = (ARGS.fixtures / 'protected.apk').read_bytes()
        self.check()
        expected = json.loads((self.native / 'protection.json').read_text())['apkSignatureVerification']
        result = json.loads(self.report.read_text())
        self.assertEqual(expected, result['apkSignatureVerification'])
        self.assertEqual(result['scope'], 'signed-apk-static')
        self.assertEqual(result['apks'][0]['sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(result['evidence']['selectionSha256'], hashlib.sha256((self.generated / 'selection.json').read_bytes()).hexdigest())
        self.assertEqual(result['evidence']['apksignerSha256'], hashlib.sha256(ARGS.apksigner.read_bytes()).hexdigest())
        self.assertEqual(result['capabilities']['criticalMethodCoverage']['validationStatus'], 'unverified')
        self.assertEqual(result['capabilities']['buildProvenance']['validationStatus'], 'unverified')
        for name in ('vmp', 'nativeCse', 'segmentedData', 'apkSignatureVerification'):
            self.assertNotEqual(result['capabilities'][name]['validationStatus'], 'passed')
        self.assertEqual(original, (ARGS.fixtures / 'protected.apk').read_bytes())

    def test_frozen_critical_requirement_reaches_the_final_wrapper(self):
        selection = json.loads((self.generated / 'selection.json').read_bytes())
        if not selection['methods']:
            self.skipTest('requires protected methods')
        method = selection['methods'][0]
        requirement = {'schemaVersion': 1, 'methods': [{'method': method['method'], 'protection': method['protection']}]}
        path = self.out / 'critical.json'; path.write_text(json.dumps(requirement))
        verify([ARGS.fixtures / 'protected.apk'], self.native, self.generated, ARGS.java, ARGS.apksigner, 26, self.report, path)
        result = json.loads(self.report.read_bytes())
        self.assertEqual(result['requirementsSha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(result['criticalMethods'][0]['symbol'], method['symbol'])
        self.assertEqual(result['criticalMethods'][0]['bridge'], method['bridge'])
        self.assertEqual(result['capabilities']['criticalMethodCoverage']['validationStatus'], 'passed')
        requirement['methods'][0]['protection'] = 'native-cse' if method['protection'] == 'vmp' else 'vmp'
        path.write_text(json.dumps(requirement))
        with self.assertRaisesRegex(ValueError, 'critical method protection differs'):
            verify([ARGS.fixtures / 'protected.apk'], self.native, self.generated, ARGS.java, ARGS.apksigner, 26, self.report, path)
        self.assertFalse(self.report.exists())

    def test_frozen_integrity_recheck_requires_methods_and_registration(self):
        receipt = json.loads((self.native / 'protection.json').read_bytes())
        if not receipt.get('integrityRecheck'):
            self.skipTest('requires generated integrity-recheck fixture')
        requirement = {'schemaVersion': 1, 'registrationIntegrityRecheck': True, 'methods': [
            {'method': 'sample/Run.initialize(Ljava/lang/String;)Ljava/lang/String;', 'protection': 'vmp', 'integrityRecheck': True},
            {'method': 'sample/Run.commit(Ljava/lang/String;)Ljava/lang/String;', 'protection': 'native-cse', 'integrityRecheck': True}]}
        path = self.out / 'recheck-critical.json'
        path.write_text(json.dumps(requirement))
        def check():
            verify([ARGS.fixtures / 'protected.apk'], self.native, self.generated,
                   ARGS.java, ARGS.apksigner, 26, self.report, path)
        check()
        result = json.loads(self.report.read_bytes())
        self.assertEqual(result['integrityRecheckWiring']['validationStatus'], 'passed')
        self.assertEqual(result['integrityRecheckWiring']['scope'], 'compiler-ir-and-signed-apk-static')
        self.assertEqual(len(result['integrityRecheckWiring']['entries']), 3)
        self.assertEqual(len(result['criticalMethods']), 2)
        self.assertTrue(all(row['integrityRecheck'] is True for row in result['criticalMethods']))
        self.assertEqual(result['capabilities']['integrityRecheck']['validationStatus'], 'unverified')
        requirement['methods'][0]['integrityRecheck'] = False
        path.write_text(json.dumps(requirement))
        with self.assertRaisesRegex(ValueError, 'critical method integrity recheck differs'):
            check()
        self.assertFalse(self.report.exists())
        requirement['methods'][0]['integrityRecheck'] = True
        requirement['registrationIntegrityRecheck'] = False
        path.write_text(json.dumps(requirement))
        with self.assertRaisesRegex(ValueError, 'critical registration integrity recheck differs'):
            check()

    def test_integrity_recheck_missing_or_wrong_ir_receipt_is_rejected(self):
        path = self.native / 'protection.json'
        receipt = json.loads(path.read_bytes())
        if not receipt.get('integrityRecheck'):
            self.skipTest('requires generated integrity-recheck fixture')
        for unit in receipt['integrityRecheck']['irSha256']:
            ir = self.native / (unit + '.ll')
            original = ir.read_bytes()
            ir.unlink()
            with self.subTest(unit=unit), self.assertRaisesRegex(ValueError, 'missing integrity recheck IR'):
                self.check()
            self.assertFalse(self.report.exists())
            ir.write_bytes(original)
        for unit, digest in list(receipt['integrityRecheck']['irSha256'].items()):
            receipt['integrityRecheck']['irSha256'][unit] = '0' * 64
            path.write_text(json.dumps(receipt))
            with self.subTest(unit=unit), self.assertRaisesRegex(ValueError, 'integrity recheck IR changed'):
                self.check()
            receipt['integrityRecheck']['irSha256'][unit] = digest
        receipt['integrityRecheck']['entries'][0]['guard'] = 'wrong_guard'
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'integrity recheck guard receipt differs'):
            self.check()

    def test_legacy_toolchain_identity_is_explicitly_missing(self):
        path = self.native / 'protection.json'
        receipt = json.loads(path.read_bytes())
        receipt.pop('compilerIdentity', None); receipt.pop('configuration', None)
        path.write_text(json.dumps(receipt))
        self.check()
        result = json.loads(self.report.read_bytes())
        self.assertIn('compilerIdentity', result['evidence']['missing'])
        self.assertIn('configuration', result['evidence']['missing'])
        self.assertEqual(result['capabilities']['buildProvenance']['validationStatus'], 'unverified')

    def test_compiler_identity_and_build_configuration_are_validated(self):
        path = self.native / 'protection.json'
        receipt = json.loads(path.read_bytes())
        receipt['compilerIdentity'] = {field: '0' * 64 for field in
            ('compilerSha256', 'ndkPropertiesSha256', 'linkerSha256', 'stripSha256', 'runtimeFingerprint')}
        receipt['compilerIdentity']['version'] = 'clang version 21 fixture'
        selection = json.loads((self.generated / 'selection.json').read_bytes())
        receipt['configuration'] = {'minSdk': 26, 'library': selection['library'],
            'segmentedData': receipt['segmentedData'], 'apkSignatureVerification': receipt.get('apkSignatureVerification', False)}
        path.write_text(json.dumps(receipt)); self.check()
        receipt['configuration']['minSdk'] = 28
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'build configuration differs'):
            self.check()
        receipt['configuration']['minSdk'] = 26
        receipt['compilerIdentity']['compilerSha256'] = 'not a digest'
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'invalid compiler identity'):
            self.check()

    def test_transformed_classes_are_bound_for_method_only_builds_too(self):
        path = self.generated / 'classes.jar'
        receipt = json.loads((self.native / 'protection.json').read_bytes())
        if not receipt.get('classesSha256'):
            self.skipTest('legacy fixture has no transformed class digest')
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'transformed classes changed'):
            self.check()

    def test_wrong_signer_removes_stale_success(self):
        self.check()
        with self.assertRaisesRegex(ValueError, 'certificate differs'):
            self.check(ARGS.fixtures / 'wrong-signer.apk')
        self.assertFalse(self.report.exists())

    def test_selected_methods_changed(self):
        path = self.generated / 'selection.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'selection receipt changed'):
            self.check()

    def test_manifest_changed(self):
        path = self.native / 'protection.json'
        data = json.loads(path.read_text()); data['symbols'] = ['incorrect']
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'VMP manifest differs'):
            self.check()

    def test_signed_so_substitution(self):
        apk = self.repack(lambda name, data: data + b'changed' if name.endswith('.so') else data)
        with self.assertRaisesRegex(ValueError, 'packaged SO differs'):
            self.check(apk)

    def test_signed_missing_dex(self):
        apk = self.repack(lambda name, data: None if name.endswith('.dex') else data)
        with self.assertRaises(AssertionError):
            self.check(apk)

    def test_signed_container_substitution(self):
        if not json.loads((self.native / 'protection.json').read_text())['segmentedData']:
            self.skipTest('requires QSEG fixture')
        apk = self.repack(lambda name, data: data + b'changed' if name.endswith('.qseg') else data)
        with self.assertRaisesRegex(ValueError, 'packaged QSEG differs'):
            self.check(apk)

    def test_segment_receipt_changed(self):
        path = self.native / 'segments.json'
        if not path.exists():
            self.skipTest('requires QSEG fixture')
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'segment receipt changed'):
            self.check()

    def test_signed_extra_container_or_abi_is_rejected(self):
        binary = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\0'
        for entry, message in (('assets/stale.qseg', 'unexpected QSEG'), ('lib/x86_64/extra.so', 'unsupported SO ABI')):
            apk = self.repack(lambda name, data: data, [(entry, binary)])
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, message):
                self.check(apk)

    def test_signed_build_diagnostic_is_rejected(self):
        apk = self.repack(lambda name, data: data, [('assets/debug/selection.json', b'{"methods":[]}')])
        with self.assertRaisesRegex(ValueError, 'packaged build diagnostic'):
            self.check(apk)

    def test_signed_wrong_machine_in_arm64_path_is_rejected(self):
        def change(name, data):
            if name.endswith('.so'):
                return data[:18] + b'\x3e\0' + data[20:]
            return data
        apk = self.repack(change)
        with self.assertRaisesRegex(ValueError, 'unsupported SO ABI'):
            self.check(apk)

    def test_duplicate_method_with_updated_digest_is_rejected(self):
        selection = self.generated / 'selection.json'
        data = json.loads(selection.read_text())
        receipt = self.native / 'protection.json'
        receipt_data = json.loads(receipt.read_text())
        if not data['methods']:
            method = {'method': 'Example.run()V', 'symbol': 'd2c_' + '0' * 24, 'protection': 'vmp'}
            data['methods'] = [method]
            data['strings'] = {}
            (self.generated / 'string-selection.json').unlink(missing_ok=True)
        data['methods'].append(data['methods'][0])
        selection.write_text(json.dumps(data))
        receipt_data['selectionSha256'] = hashlib.sha256(selection.read_bytes()).hexdigest()
        receipt_data['protectedMethods'] = len(data['methods'])
        receipt_data['protectedStrings'] = 0
        receipt.write_text(json.dumps(receipt_data))
        with self.assertRaisesRegex(ValueError, 'duplicate selected'):
            self.check()

    def test_self_consistent_stale_segment_receipt_is_rejected(self):
        path = self.native / 'segments.json'
        if not path.exists():
            self.skipTest('requires QSEG fixture')
        data = json.loads(path.read_text()); data['containerSha256'] = '0' * 64
        path.write_text(json.dumps(data))
        receipt = self.native / 'protection.json'
        data = json.loads(receipt.read_text()); data['segmentsReceiptSha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'segment receipt identity differs'):
            self.check()

    def test_duplicate_split_classes(self):
        with self.assertRaises(AssertionError):
            self.check(ARGS.fixtures / 'protected.apk', ARGS.fixtures / 'protected.apk')

    def test_self_consistent_lifetime_mismatch_is_rejected(self):
        receipt = self.native / 'protection.json'
        data = json.loads(receipt.read_text())
        if data.get('qsegLifetimeAbi') != 1:
            self.skipTest('requires lifetime v1 fixture')
        path = self.native / 'segments.json'
        segments = json.loads(path.read_text())
        row = next(row for row in segments['segments'] if row['kind'] == 1)
        row['lifetime'] = 'pinned-legacy' if row['lifetime'] == 'lease-v1' else 'lease-v1'
        path.write_text(json.dumps(segments))
        data['segmentsReceiptSha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'lifetime policy'):
            self.check()

    def test_independent_agp_outputs(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_dex2c_apk.py'),
            '--native', str(self.native), '--generated', str(self.generated), '--java', str(ARGS.java),
            '--apksigner', str(ARGS.apksigner), '--min-sdk', '26', '--report', str(self.report),
            '--apk', str(ARGS.fixtures / 'protected.apk'), '--apk', str(ARGS.fixtures / 'protected.apk'),
            '--independent-apks'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(2, len(json.loads(self.report.read_text())['outputs']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--apksigner', type=Path, required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest])
