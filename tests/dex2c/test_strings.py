"""Reject incomplete string-only receipts and walk DEX instructions without reading operands as calls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from dex2c_artifacts import Dex
from verify_dex2c_apk import verify


class DexCallsTest(unittest.TestCase):
    def calls(self, units):
        dex = Dex.__new__(Dex)
        dex.methods = ['native.decoder(I)Ljava/lang/String;']
        dex.data = bytes(16) + struct.pack('<I', len(units)) + struct.pack('<' + 'H' * len(units), *units)
        return dex.calls(4)

    def test_const_operands_and_payloads_are_not_invocations(self):
        call = [0x71, 0, 0]
        for prefix in ([0x14, 0x71, 0], [0x100, 1, 0, 0, 0x71, 0],
                       [0x200, 1, 0, 0, 0x71, 0], [0x300, 2, 1, 0, 0x71]):
            self.assertEqual(self.calls([*prefix, *call, 0x0e]), ['native.decoder(I)Ljava/lang/String;'])

    def test_truncation_and_unknown_opcodes_are_rejected(self):
        for units in ([0x71, 0], [0x3f], [0x100, 200, 0, 0]):
            with self.assertRaises(AssertionError):
                self.calls(units)


class StringReceiptTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.generated = self.root / 'generated'; self.generated.mkdir()
        self.native = self.root / 'native'; self.native.mkdir()
        self.strings = {'uniqueStrings': 1, 'occurrences': 1, 'symbol': 'native',
                        'sites': [{'index': 0}]}
        self.selection = {'methods': [], 'strings': self.strings, 'library': 'test'}
        self.write('string-selection.json', self.strings)
        self.write('selection.json', self.selection)
        (self.generated / 'classes.jar').write_bytes(b'transformed class fixture')
        self.receipt = {'protectedMethods': 0, 'protectedStrings': 1, 'symbols': [], 'nativeSymbols': [],
                        'stringSymbols': ['native'], 'selectionSha256': self.digest('selection.json'),
                        'stringSelectionSha256': self.digest('string-selection.json'),
                        'classesSha256': self.digest('classes.jar'), 'cseHardened': True,
                        'certificateBound': True, 'selfCheckEntry': True, 'vmpPost': True, 'cseVmpMethods': 2,
                        'segmentedData': False}

    def write(self, name, value):
        (self.generated / name).write_text(json.dumps(value))

    def digest(self, name):
        return hashlib.sha256((self.generated / name).read_bytes()).hexdigest()

    def check(self):
        (self.native / 'protection.json').write_text(json.dumps(self.receipt))
        verify([], self.native, self.generated, None, None, 26, self.root / 'report.json')

    def test_string_only_output_does_not_take_zero_method_shortcut(self):
        with self.assertRaisesRegex(ValueError, 'missing SO'):
            self.check()

    def test_missing_protection_and_changed_classes_are_rejected(self):
        self.receipt['selfCheckEntry'] = False
        with self.assertRaisesRegex(ValueError, 'protection chain incomplete'):
            self.check()
        self.receipt['selfCheckEntry'] = True
        (self.generated / 'classes.jar').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'transformed classes changed'):
            self.check()

    def test_index_coverage_and_separate_manifests_must_agree(self):
        self.strings['sites'][0]['index'] = 1
        self.write('selection.json', self.selection)
        self.write('string-selection.json', self.strings)
        self.receipt['selectionSha256'] = self.digest('selection.json')
        self.receipt['stringSelectionSha256'] = self.digest('string-selection.json')
        with self.assertRaisesRegex(ValueError, 'index coverage differs'):
            self.check()
        self.write('string-selection.json', {})
        self.receipt['stringSelectionSha256'] = self.digest('string-selection.json')
        with self.assertRaisesRegex(ValueError, 'string manifests differ'):
            self.check()


if __name__ == '__main__':
    unittest.main()
