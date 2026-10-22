"""本地头/中央目录差异必须在发布时按运行时相同规则拒绝。"""
import io
from pathlib import Path
import struct
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from seal_qseg import zip_entry_range


class ZipBindingTest(unittest.TestCase):
    def fixture(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('assets/test.qseg', b'authenticated resource')
        return bytearray(out.getvalue())

    def check(self, data):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return zip_entry_range(data, archive.infolist()[0], archive.start_dir)

    def test_valid_and_local_header_mutations(self):
        data = self.fixture()
        begin, end = self.check(data)
        self.assertEqual(b'authenticated resource', data[begin:end])
        for offset in (0, 6, 8, 14, 18, 22, 26, 28, 30):
            changed = bytearray(data); changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.check(changed)

    def test_encrypted_or_wrong_local_offset_rejected(self):
        for field in ('encrypted', 'offset'):
            data = self.fixture(); central = data.index(b'PK\x01\x02')
            if field == 'encrypted':
                struct.pack_into('<H', data, 6, 1)
                struct.pack_into('<H', data, central + 8, 1)
            else:
                struct.pack_into('<I', data, central + 42, len(data) - 1)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(data)


if __name__ == '__main__':
    unittest.main()
