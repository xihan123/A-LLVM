"""QSEG format, authenticated malformed-input and exact recovery regressions."""
import hashlib
import secrets
import struct
import sys
import unittest
import zlib
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests/cse-hardened"))
import seal_qseg as qseg
import test_seal_cse


class SegmentedTests(unittest.TestCase):
    def fixture(self, resources=None):
        self.cert = b"public-test-certificate"
        self.resources = resources or [(bytes(range(16)), 1, secrets.token_bytes(150000), "vm"),
                                       (bytes(range(16, 32)), 2, ("中文字符串\0" * 1024).encode("utf-16le"), "cse")]
        header = qseg.prepare(self.resources, "assets/fixture.qseg", self.cert)
        image = bytearray(test_seal_cse.elf(header))
        struct.pack_into("<I", image, 64 + 2 * 56 + 4, 4)
        return qseg.pack(image, self.resources)

    def test_exact_cross_chunk_and_utf16(self):
        library, container, receipt = self.fixture()
        self.assertEqual(qseg.unpack(library, container, self.cert), {(i, k): b for i, k, b, _ in self.resources})
        self.assertEqual([x["chunk"] for x in receipt if x["kind"] == 1], [0, 1, 2])
        self.assertTrue(any(x["codec"] == 1 for x in receipt if x["kind"] == 2))
        self.assertTrue(all(x["codec"] == 0 for x in receipt if x["kind"] == 1))

    def test_compression_threshold(self):
        resources = [(bytes(16), 2, b"A" * 17, "tiny"), (bytes([1]) * 16, 2, b"A" * 1000, "pool")]
        _, _, receipt = self.fixture(resources)
        self.assertEqual([x["codec"] for x in receipt], [0, 1])

    def test_wrong_certificate(self):
        lib, blob, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, "authentication"):
            qseg.unpack(lib, blob, b"wrong")

    def test_all_tag_bytes_and_payload_tamper(self):
        lib, blob, _ = self.fixture()
        directory_bytes = qseg.u32(blob, 12)
        for offset in [16, len(blob) - 1, *range(16 + directory_bytes, 32 + directory_bytes)]:
            with self.subTest(offset=offset):
                changed = bytearray(blob); changed[offset] ^= 1
                # Pin a new file digest so this exercises AEAD, not just the outer digest.
                image = bytearray(lib); _, pos = qseg.locate_image(image)
                image[pos + 384:pos + 416] = hashlib.sha256(changed).digest()
                with self.assertRaisesRegex(ValueError, "authentication"):
                    qseg.unpack(image, changed, self.cert)

    def test_index_bounds_with_valid_authentication(self):
        lib, blob, _ = self.fixture()
        _, pos = qseg.locate_image(lib); header = lib[pos:pos + 512]
        root = qseg.derive(header, header[152:184], qseg.expected_inputs(2, certificate=self.cert))
        size = qseg.u32(blob, 12)
        key = qseg.index_key(root, header)
        original = qseg.decrypt(key, bytes(12), blob[:16] + header[24:40], blob[16:16 + size], blob[16 + size:32 + size])
        for offset, value in ((16, 3), (20, 1), (24, 0xffffffff), (28, 0), (32, 0xffffffff), (36, 1), (40, 2), (44, 9)):
            with self.subTest(offset=offset):
                directory = bytearray(original); struct.pack_into("<I", directory, offset, value)
                ciphertext, tag = qseg.encrypt(key, bytes(12), blob[:16] + header[24:40], directory)
                changed = blob[:16] + ciphertext + tag + blob[32 + size:]
                image = bytearray(lib); image[pos + 384:pos + 416] = hashlib.sha256(changed).digest()
                with self.assertRaises(ValueError):
                    qseg.unpack(image, changed, self.cert)

    def test_code_and_container_identity(self):
        lib, blob, _ = self.fixture()
        changed = bytearray(lib); changed[0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, "code binding"):
            qseg.unpack(changed, blob, self.cert)
        another, other_blob, _ = self.fixture()
        with self.assertRaises(ValueError):
            qseg.unpack(lib, other_blob, self.cert)
        with self.assertRaises(ValueError):
            qseg.unpack(another, blob, self.cert)

    def test_build_material_and_domains_are_distinct(self):
        builds = [self.fixture([(bytes(16), 2, b'A' * 1000, 'pool')]) for _ in range(3)]
        headers = [lib[qseg.locate_image(lib)[1]:qseg.locate_image(lib)[1] + 512] for lib, _, _ in builds]
        for begin, end in ((24, 40), (40, 72), (72, 104), (184, 216)):
            self.assertEqual(3, len({h[begin:end] for h in headers}))
        self.assertEqual(3, len({blob for _, blob, _ in builds}))
        h = headers[0]
        root = qseg.derive(h, h[152:184], qseg.expected_inputs(2, certificate=self.cert))
        keys = [qseg.index_key(root, h), qseg.segment_key(root, h, bytes(16), 1, 0),
                qseg.segment_key(root, h, bytes(16), 1, 1), qseg.segment_key(root, h, bytes(16), 2, 0),
                qseg.segment_key(root, h, bytes([1]) * 16, 1, 0)]
        self.assertEqual(len(keys), len(set(keys)))

    def test_invalid_resources_and_wrong_elf_abi(self):
        for resources in ([(bytes(16), 2, b'', 'empty')], [(bytes(15), 2, b'x', 'short')],
                          [(bytes(16), 3, b'x', 'kind')],
                          [(bytes(16), 1, b'x', 'a'), (bytes(16), 2, b'y', 'b')]):
            with self.subTest(resources=resources), self.assertRaises(ValueError):
                self.fixture(resources)
        lib, blob, _ = self.fixture()
        for offset, value in ((4, 1), (5, 2), (18, 62)):
            changed = bytearray(lib); changed[offset] = value
            with self.assertRaisesRegex(ValueError, 'AArch64'):
                qseg.unpack(changed, blob, self.cert)

    def compressed_variant(self, stored):
        lib, blob, _ = self.fixture([(bytes(16), 2, b'A' * 1000, 'pool')])
        lib = bytearray(lib)
        _, pos = qseg.locate_image(lib); h = lib[pos:pos + 512]
        root = qseg.derive(h, h[152:184], qseg.expected_inputs(2, certificate=self.cert))
        size = qseg.u32(blob, 12)
        directory = bytearray(qseg.decrypt(qseg.index_key(root, h), bytes(12), blob[:16] + h[24:40],
            blob[16:16 + size], blob[16 + size:32 + size]))
        struct.pack_into('<I', directory, 28, len(stored))
        cipher, tag = qseg.encrypt(qseg.segment_key(root, h, bytes(16), 2, 0), bytes(12), h[24:40] + directory[:48], stored)
        directory[48:64] = tag
        index, tag = qseg.encrypt(qseg.index_key(root, h), bytes(12), blob[:16] + h[24:40], directory)
        changed = blob[:16] + index + tag + cipher
        struct.pack_into('<I', lib, pos + 8, len(changed))
        lib[pos + 384:pos + 416] = hashlib.sha256(changed).digest()
        return lib, changed

    def test_authenticated_malformed_compression(self):
        def deflate(raw):
            encoder = zlib.compressobj(wbits=-15)
            return encoder.compress(raw) + encoder.flush()
        for stored in (b'\xff' * 11, deflate(b'A' * 1000)[:-1],
                       deflate(b'A' * 1000) + b'x', deflate(b'A' * 1001)):
            with self.subTest(stored=stored):
                lib, blob = self.compressed_variant(stored)
                with self.assertRaises((ValueError, zlib.error)):
                    qseg.unpack(lib, blob, self.cert)

    def test_unauthenticated_payload_never_reaches_decompressor(self):
        lib, blob, _ = self.fixture([(bytes(16), 2, b'A' * 1000, 'pool')])
        changed = bytearray(blob); changed[-1] ^= 1
        image = bytearray(lib); _, pos = qseg.locate_image(image)
        image[pos + 384:pos + 416] = hashlib.sha256(changed).digest()
        with patch.object(qseg.zlib, 'decompressobj', side_effect=AssertionError('unauthenticated decompression')):
            with self.assertRaisesRegex(ValueError, 'authentication'):
                qseg.unpack(image, changed, self.cert)

    def test_truncation_trailing_and_reseal(self):
        lib, blob, _ = self.fixture()
        for changed in (blob[:16], blob[:-1], blob + b"x"):
            with self.assertRaises(ValueError): qseg.unpack(lib, changed, self.cert)
        with self.assertRaisesRegex(ValueError, "already sealed"):
            qseg.pack(lib, self.resources)

    def test_invalid_asset_names(self):
        for name in ("../x", "assets/../x", "assets/" + "a" * 128, "lib/a.so"):
            with self.assertRaises(ValueError): qseg.prepare([], name, b"cert")

    def test_image_locator_ignores_nearby_magic_and_rejects_executable_slot(self):
        header = qseg.prepare([], "assets/locator.qseg", b"cert")
        image = bytearray(test_seal_cse.elf(header))
        struct.pack_into("<I", image, 64 + 2 * 56 + 4, 4)
        image.extend(bytes(32))
        # A runtime magic literal may precede the actual image by less than 512 bytes.
        image[0x2000:0x2000+512] = bytes(512)
        image[0x2000:0x2008] = qseg.IMAGE_MAGIC
        image[0x2020:0x2220] = header
        struct.pack_into("<QQ", image, 64 + 2 * 56 + 32, 544, 544)
        self.assertEqual(qseg.locate_image(image)[1], 0x2020)
        struct.pack_into("<I", image, 64 + 2 * 56 + 4, 5)
        with self.assertRaises(ValueError): qseg.locate_image(image)


if __name__ == "__main__":
    unittest.main()
