"""Safe warm-test mutation anchors must be outside every allocated ELF section."""
import struct
import unittest

from recheck_device import select_anchor


def fixture(sections, flags=5):
    data = bytearray(0x800)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 3, 183, 1)
    struct.pack_into('<QQ', data, 32, 64, 0x300)
    struct.pack_into('<HHHHH', data, 52, 64, 56, 1, 64, len(sections) + 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, flags, 0x100, 0x1000, 0x1000, 0x100, 0x100, 0x100)
    for index, (start, size) in enumerate(sections, 1):
        struct.pack_into('<IIQQQQIIQQ', data, 0x300 + 64 * index,
                         0, 1, 6, start, 0x100 + start - 0x1000, size, 0, 0, 4, 0)
    return data


class RecheckDeviceTest(unittest.TestCase):
    def test_only_interior_allocated_section_gap_is_selected(self):
        data = fixture(((0x1000, 0x20), (0x1040, 0x20)))
        anchor = select_anchor(data)
        self.assertEqual(anchor['relativeAddress'], 0x1020)
        self.assertEqual(anchor['fileOffset'], 0x120)
        self.assertEqual(anchor['originalHex'], '00000000')

    def test_overlapping_sections_cannot_make_a_false_gap(self):
        data = fixture(((0x1000, 0x80), (0x1020, 0x10), (0x1060, 0x10)))
        with self.assertRaisesRegex(ValueError, 'no proven unused RX padding'):
            select_anchor(data)

    def test_instruction_bytes_and_unmeasured_or_writable_segments_are_rejected(self):
        data = fixture(((0x1000, 0x20), (0x1040, 0x20)))
        data[0x120:0x124] = bytes.fromhex('c0035fd6')
        with self.assertRaisesRegex(ValueError, 'no proven unused RX padding'):
            select_anchor(data)
        for flags in (4, 7):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                select_anchor(fixture(((0x1000, 0x20), (0x1040, 0x20)), flags))


if __name__ == '__main__':
    unittest.main()
