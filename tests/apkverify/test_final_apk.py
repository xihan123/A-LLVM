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
        if (ARGS.fixtures / 'native/segments.json').exists():
            (self.native / 'segments.json').write_bytes((ARGS.fixtures / 'native/segments.json').read_bytes())

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
        self.assertTrue(json.loads(self.report.read_text())['apkSignatureVerification'])
        self.assertEqual(original, (ARGS.fixtures / 'protected.apk').read_bytes())

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
        data['methods'].append(data['methods'][0])
        selection.write_text(json.dumps(data))
        receipt = self.native / 'protection.json'
        data = json.loads(receipt.read_text())
        data['selectionSha256'] = hashlib.sha256(selection.read_bytes()).hexdigest()
        data['protectedMethods'] += 1
        receipt.write_text(json.dumps(data))
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
