import struct
import sys
import unittest
import tempfile
from unittest.mock import patch
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from dex2c_artifacts import Dex, verify_wrappers


R8_WRAPPER = (
    0x031d,                         # monitor-enter v3
    0x001c, 0x0eb6,                 # const-class v0
    0x011a, 0x6a58, 0x021a, 0x0f25, # const-string v1/v2
    0x3071, 0, 0x0210,              # invoke-static register
    0x2071, 1, 0x0043,              # invoke-static bridge
    0x031e, 0x000e,                 # monitor-exit v3; return-void
    0x031e, 0x0427,                 # monitor-exit v3; throw v4
    0x040d, 0xfd28,                 # move-exception v4; goto -3
)


class DexWrapperTest(unittest.TestCase):
    def forwarding_calls(self, instructions):
        dex = Dex.__new__(Dex)
        dex.data = struct.pack(f'<16xI{len(instructions)}H', len(instructions), *instructions)
        dex.methods = ['register', 'bridge']
        return dex.forwarding_calls(4, synchronized=True)

    def test_accepts_r8_synchronized_rethrow(self):
        self.assertEqual(self.forwarding_calls(R8_WRAPPER), ['register', 'bridge'])

    def test_rejects_other_gotos(self):
        for instructions in (
            (R8_WRAPPER[0], 0x0d28, *R8_WRAPPER[1:]),  # Skip both calls.
            (*R8_WRAPPER[:-1], 0xfe28),                # Jump past monitor-exit.
            (*R8_WRAPPER[:-3], 0x0327, *R8_WRAPPER[-2:]),  # Throw the wrong register.
        ):
            with self.subTest(instructions=instructions), self.assertRaisesRegex(AssertionError, 'opcode 0x28'):
                self.forwarding_calls(instructions)

    def test_unreachable_calls_cannot_prove_native_forwarding(self):
        for instructions in ((0x000e, 0x3071, 0, 0, 0x2071, 1, 0),
                             (0x0427, 0x3071, 0, 0, 0x2071, 1, 0, 0x000e),
                             (0x3071, 0, 0, 0x2071, 1, 0)):
            with self.subTest(instructions=instructions), self.assertRaises(AssertionError):
                self.forwarding_calls(instructions)

    def test_duplicate_native_bridge_across_dex_files_is_rejected(self):
        selection = {'registrationCall': 'register', 'methods': [{'method': 'original', 'bridge': 'bridge'}]}
        class FakeDex:
            def __init__(self, data):
                self.bodies = {'bridge': (0x100, 0)}
                if data == b'first':
                    self.bodies['original'] = (0, 4)
            def forwarding_calls(self, code, synchronized):
                return ['register', 'bridge']
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'duplicate.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', b'first')
                archive.writestr('classes2.dex', b'second')
            with patch('dex2c_artifacts.Dex', FakeDex), self.assertRaisesRegex(AssertionError, 'duplicate native bridge'):
                verify_wrappers(apk, selection)

    def verify_inherited(self, classes, bodies=None, second_classes=None):
        method = 'Base.critical()V'
        selection = {'registrationCall': 'register', 'methods': [{'method': method, 'bridge': 'bridge'}]}
        requirement = {'method': method, 'entry': 'Child#critical()V'}
        class FakeDex:
            def __init__(self, data):
                self.superclasses = classes if data == b'first' else second_classes
                self.bodies = {method: (0, 4), 'bridge': (0x100, 0), **(bodies or {})} if data == b'first' else {}
            def forwarding_calls(self, code, synchronized):
                return ['register', 'bridge']
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'inherited.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', b'first')
                if second_classes is not None:
                    archive.writestr('classes2.dex', b'second')
            with patch('dex2c_artifacts.Dex', FakeDex):
                verify_wrappers(apk, selection, [requirement])

    def test_inherited_entry_resolves_in_final_dex_including_multidex(self):
        self.verify_inherited({'Child': 'Middle', 'Middle': 'Base', 'Base': None})
        self.verify_inherited({'Base': None}, second_classes={'Child': 'Base'})

    def test_inherited_entry_rejects_override_missing_class_and_changed_superclass(self):
        for classes, bodies in (({'Child': 'Base', 'Base': None}, {'Child.critical()V': (0, 8)}),
                                ({'Base': None}, {}),
                                ({'Child': 'Other', 'Other': None, 'Base': None}, {}),
                                ({'Child': 'Missing', 'Base': None}, {}),
                                ({'Child': 'Child', 'Base': None}, {}),
                                ({'Child': 'Base', 'Base': None}, {'Child.critical()V': (0x400, 0)})):
            with self.subTest(classes=classes, bodies=bodies), self.assertRaises(AssertionError):
                self.verify_inherited(classes, bodies)
        with self.assertRaisesRegex(AssertionError, 'duplicate final DEX entry class'):
            self.verify_inherited({'Child': 'Base', 'Base': None}, second_classes={'Child': 'Base'})
