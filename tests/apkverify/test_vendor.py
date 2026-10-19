"""Check the pinned offline dependency and compiled source allowlist without network access."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2] / 'runtime'


class VendorTest(unittest.TestCase):
    def test_pinned_sources(self):
        vendor = ROOT / 'third_party/mbedtls'
        manifest = json.loads((vendor / 'MANIFEST.json').read_text())
        self.assertEqual('3.6.7', manifest['version'])
        self.assertEqual('068ff080b369adfac81509f9b57b2afabaf82dc5', manifest['commit'])
        self.assertEqual('ca6bd316bbec49ef20088f39b8755fcaec0b7e45781506de55b17cd191ae6937', manifest['archiveSha256'])
        for name, expected in manifest['files'].items():
            with self.subTest(file=name):
                self.assertEqual(expected, hashlib.sha256((vendor / name).read_bytes()).hexdigest())
        sources = (ROOT / 'apkverify_sources.txt').read_text().splitlines()
        self.assertEqual(22, len(set(sources)))
        self.assertEqual({p.stem for p in (vendor / 'library').glob('*.c')}, set(sources))
        self.assertTrue((vendor / 'LICENSE').is_file())


if __name__ == '__main__':
    unittest.main()
