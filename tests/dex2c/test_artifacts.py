import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from dex2c_artifacts import Dex


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
