"""Distinguish required ABI symbols from exposed protected method literals."""
import struct
import unittest

from hardening import literal_leaks


class StringAuditTest(unittest.TestCase):
    def test_abi_collision_does_not_hide_a_separate_plaintext_copy(self):
        data=bytearray(256)
        struct.pack_into('<Q',data,40,64)
        struct.pack_into('<HH',data,58,64,1)
        struct.pack_into('<I',data,68,3)
        struct.pack_into('<QQ',data,88,128,6)
        data[128:134]=b'close\0'
        self.assertEqual(literal_leaks(data,{b'close\0'})[0],[])
        data[200:206]=b'close\0'
        self.assertEqual(literal_leaks(data,{b'close\0'})[0],[b'close\0'])

    def test_diagnostic_suffix_does_not_hide_a_standalone_member_name(self):
        data=bytearray(256)
        diagnostic=b'DW_OP_deref_size with bad size\0'
        data[128:128+len(diagnostic)]=diagnostic
        self.assertEqual(literal_leaks(data,{b'size\0'})[0],[])
        data[200:205]=b'size\0'
        self.assertEqual(literal_leaks(data,{b'size\0'})[0],[b'size\0'])


if __name__=='__main__': unittest.main()
