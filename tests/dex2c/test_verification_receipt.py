"""A frozen critical denominator and real per-method receipts are both required."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from verify_dex2c_apk import capabilities, check_diagnostics, check_method_receipt, check_requirements, check_segment_coverage


class VerificationReceiptTest(unittest.TestCase):
    def setUp(self):
        self.method = {'method': 'Example.critical()V', 'symbol': 'vm_symbol', 'bridge': 'Bridge.call()V', 'protection': 'vmp'}
        self.selection = {'methods': [self.method], 'inherited': {'Subclass#critical()V': self.method['method']}}
        self.receipt = {'vmpMethods': 1, 'nativeMethods': 0, 'symbols': ['vm_symbol'], 'nativeSymbols': [],
                        'methodBytecodeBytes': {'vm_symbol': 9}, 'nativeIndirectBranches': {'vm_symbol': 0},
                        'cseHardened': True, 'certificateBound': True, 'vmpStrict': True, 'vmpPost': True,
                        'selfCheckEntry': True, 'segmentedData': False, 'bytecodeVerifiedInLibrary': True,
                        'bytecodeVerifiedInContainer': False}

    def test_vm_requires_its_own_receipts_even_when_counts_and_crypto_vm_exist(self):
        check_method_receipt(self.receipt, self.selection)
        for field, value in (('vmpMethods', 2), ('vmpMethods', True), ('vmpStrict', False), ('vmpPost', False),
                             ('selfCheckEntry', False), ('methodBytecodeBytes', {'crypto_vm': 9}),
                             ('methodBytecodeBytes', {'vm_symbol': 0}), ('nativeIndirectBranches', {'crypto_vm': 1}),
                             ('bytecodeVerifiedInLibrary', False), ('bytecodeVerifiedInLibrary', None),
                             ('bytecodeVerifiedInLibrary', 'false'), ('bytecodeVerifiedInLibrary', 1),
                             ('symbols', ['vm_symbol', 'vm_symbol'])):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                check_method_receipt({**self.receipt, field: value}, self.selection)
        missing = dict(self.receipt); del missing['bytecodeVerifiedInLibrary']
        with self.assertRaises(ValueError):
            check_method_receipt(missing, self.selection)
        for value in (None, True, 'false'):
            with self.subTest(segmented_library=value), self.assertRaises(ValueError):
                check_method_receipt({**self.receipt, 'segmentedData': True,
                                      'bytecodeVerifiedInContainer': True, 'bytecodeVerifiedInLibrary': value}, self.selection)

    def test_native_only_does_not_gain_business_vm_coverage_from_crypto(self):
        self.method['protection'] = 'native-cse'
        self.receipt.update(vmpMethods=0, nativeMethods=1, symbols=[], nativeSymbols=['vm_symbol'],
                            methodBytecodeBytes={}, cseVmpMethods=2)
        check_method_receipt(self.receipt, self.selection)
        result = capabilities(self.receipt, None)
        self.assertFalse(result['vmp']['enabledInArtifact'])
        self.assertEqual(result['vmp']['validationStatus'], 'not-applicable')
        self.assertEqual(result['nativeCse']['validationStatus'], 'unverified')

    def test_explicit_critical_method_and_inherited_target_must_match(self):
        row = {'method': self.method['method'], 'protection': 'vmp', 'entry': 'Subclass#critical()V'}
        requirements = {'schemaVersion': 1, 'methods': [row]}
        self.assertEqual(check_requirements(self.selection, requirements)[0]['bridge'], self.method['bridge'])
        for changed in ({**row, 'method': 'Missing.run()V'}, {**row, 'protection': 'native-cse'},
                        {**row, 'entry': 'Other#critical()V'}):
            with self.subTest(row=changed), self.assertRaises(ValueError):
                check_requirements(self.selection, {'schemaVersion': 1, 'methods': [changed]})
        self.method['protection'] = 'native-cse'
        with self.assertRaisesRegex(ValueError, 'critical method protection differs'):
            check_requirements(self.selection, requirements)

    def test_empty_duplicate_and_malformed_requirements_cannot_claim_coverage(self):
        row = {'method': self.method['method'], 'protection': 'vmp'}
        for requirements in ({}, {'schemaVersion': 1, 'methods': []},
                             {'schemaVersion': 1, 'methods': [row, row]},
                             {'schemaVersion': 1, 'methods': [{**row, 'entry': []}]},
                             {'schemaVersion': 1, 'methods': [{'method': True, 'protection': 'vmp'}]}):
            with self.subTest(requirements=requirements), self.assertRaises(ValueError):
                check_requirements(self.selection, requirements)

    def test_runtime_and_absent_critical_evidence_are_never_passed(self):
        self.receipt.update(segmentedData=True, apkSignatureVerification=True)
        result = capabilities(self.receipt, None)
        for name in ('vmp', 'segmentedData', 'apkSignatureVerification', 'criticalMethodCoverage', 'buildProvenance'):
            self.assertEqual(result[name]['validationStatus'], 'unverified')
        self.assertEqual(capabilities(self.receipt, [self.method])['criticalMethodCoverage']['validationStatus'], 'passed')

    def test_segment_sizes_must_cover_exact_vm_symbols(self):
        row = {'kind': 1, 'name': 'vm_symbol', 'bytes': 9, 'resourceSha256': 'a' * 64, 'sha256': 'b' * 64}
        check_segment_coverage(self.receipt, {'segments': [row]})
        for changed in ([{**row, 'name': 'other'}], [{**row, 'bytes': 8}], [row, row], [{**row, 'sha256': 'invalid'}]):
            with self.subTest(segments=changed), self.assertRaises(ValueError):
                check_segment_coverage(self.receipt, {'segments': changed})

    def test_known_build_diagnostics_are_rejected_without_banning_normal_assets(self):
        check_diagnostics(['assets/config.json', 'assets/other.cpp', 'classes.dex'])
        for name in ('assets/selection.json', 'res/raw/PROTECTED.CPP', 'assets/debug/protected.ll', 'assets/native-symbols.txt'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'packaged build diagnostic'):
                check_diagnostics([name])


if __name__ == '__main__':
    unittest.main()
