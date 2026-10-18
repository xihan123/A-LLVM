"""CSE v1 crypto, malformed-input and atomic-output regressions (no NDK needed)."""
import base64
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import seal_cse as cse


def payload(flags=0, package=None, certificate=None, module=bytes(range(16))):
    h = bytearray(cse.HEADER)
    h[:8] = cse.MAGIC
    h[24:40] = module
    h[40:72] = bytes(range(32))
    h[184:216] = bytes(range(32, 64))
    struct.pack_into("<II", h, 16, flags, 2)
    h[104:152] = cse.expected_inputs(flags, package, certificate)
    plain = struct.pack("<IIII", 7, 1, 0, 0) + b"secret\0" + bytes(9)
    decoy = struct.pack("<IIII", 6, 2, 1, 0) + b"a\0b\0\0\0" + bytes(10)
    struct.pack_into("<I", h, 8, cse.HEADER + 128)
    key = cse.derive(h, bytes(32), h[104:152])
    for i, text in enumerate((plain, decoy)):
        nonce = struct.pack("<QI", 0, i)
        ciphertext, tag = cse.encrypt(key, nonce, cse.record_aad(h, i, 32), text)
        h += struct.pack("<I", 32) + nonce + tag + ciphertext
    return h


def elf(blob=None):
    blob = payload() if blob is None else blob
    data = bytearray(0x2000 + len(blob))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHH", data, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 3)
    for i, (flags, offset, size) in enumerate(((4, 0, 0x1000), (5, 0x1000, 0x1000), (6, 0x2000, len(blob)))):
        struct.pack_into("<IIQQQQQQ", data, 64 + i * 56, 1, flags, offset, offset, 0, size, size, 0x1000)
    data[0x1000:0x2000] = bytes(range(256)) * 16
    data[0x2000:] = blob
    return bytes(data)


class CryptoTests(unittest.TestCase):
    def test_rfc8439_aead(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        ciphertext, tag = cse.encrypt(key, nonce, aad, plain)
        self.assertEqual(ciphertext.hex(), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(cse.decrypt(key, nonce, aad, ciphertext, tag), plain)
        with self.assertRaises(ValueError):
            cse.decrypt(key, nonce, aad + b"x", ciphertext, tag)

    def test_rfc5869(self):
        self.assertEqual(cse.hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA))).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")

    def test_sizes(self):
        for size in (0, 1, 15, 16, 17, 63, 64, 65, 255, 1024):
            key, nonce = bytes(range(32)), bytes(range(12))
            plain = bytes(i % 251 for i in range(size))
            cipher, tag = cse.encrypt(key, nonce, b"associated", plain)
            self.assertEqual(cse.decrypt(key, nonce, b"associated", cipher, tag), plain)

    def test_overlay_crypto_copies(self):
        for major in (20, 21):
            for name in ("cse_crypto.h", "sha256.h", "cse_region.h"):
                self.assertEqual((ROOT / "runtime" / name).read_text(encoding="utf-8"),
                                 (ROOT / f"obfuscation/llvm-{major}/include" / name).read_text(encoding="utf-8"))


class SealTests(unittest.TestCase):
    def test_public_certificate_offline_recovery_baseline(self):
        # The certificate is public input, never an encryption secret.
        cert = b"public signing certificate fixture"
        sealed = cse.process(elf(payload(2, certificate=cert)))
        image = cse.Elf(sealed)
        start, size = image.payloads()[0]
        blob = sealed[start:start + size]
        key = cse.derive(blob, image.code_hash(), cse.expected_inputs(2, None, cert))
        recovered = []
        for ordinal, offset, capacity in cse.records(blob):
            plain = cse.decrypt(key, blob[offset + 4:offset + 16],
                                cse.record_aad(blob, ordinal, capacity),
                                blob[offset + 32:offset + 32 + capacity], blob[offset + 16:offset + 32])
            recovered.append(plain[16:16 + struct.unpack_from("<I", plain)[0]])
        self.assertEqual(recovered, [b"secret\0", b"a\0b\0\0\0"])

    def test_roundtrip_and_only_data_changes(self):
        original = elf()
        sealed = cse.process(original)
        self.assertEqual(original[:0x2000], sealed[:0x2000])
        self.assertEqual(len(original), len(sealed))
        self.assertEqual(sealed[0x2000 + 104:0x2000 + 152], bytes(48))
        self.assertEqual(cse.process(sealed, verify=True), sealed)
        self.assertNotEqual(cse.process(original), sealed)
        with self.assertRaises(ValueError):
            cse.process(sealed)
        with self.assertRaises(ValueError):
            cse.process(original, verify=True)

    def test_binding_inputs(self):
        cert = b"fixture certificate"
        original = elf(payload(3, "com.example:worker", cert))
        sealed = cse.process(original)
        self.assertEqual(cse.process(sealed, True, "com.example", cert), sealed)
        pem = b"\n-----BEGIN CERTIFICATE-----\r\n" + base64.b64encode(cert) + b"\r\n-----END CERTIFICATE-----\n\n"
        self.assertEqual(cse.process(sealed, True, "com.example", pem), sealed)
        for package, certificate in ((None, cert), ("wrong", cert), ("com.example", None), ("com.example", b"wrong")):
            with self.assertRaises(ValueError):
                cse.process(sealed, True, package, certificate)

    def test_tampering(self):
        sealed = cse.process(elf())
        # Code, nonce, tag, ciphertext, flags, count, seed, erased material, reserved.
        for offset in (0x1100, 0x2000 + 72, 0x2100 + 16, 0x2100 + 32, 0x2000 + 16,
                       0x2000 + 20, 0x2000 + 40, 0x2000 + 104, 0x2000 + 216):
            modified = bytearray(sealed)
            modified[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                cse.process(bytes(modified), True)

    def test_cross_build_replay(self):
        one = cse.process(elf())
        two = bytearray(cse.process(elf(payload(module=b"another module!!"))))
        two[0x2100:] = one[0x2100:]
        with self.assertRaises(ValueError):
            cse.process(bytes(two), True)

    def test_strip_stable_header_in_executable_segment(self):
        original = bytearray(elf())
        struct.pack_into("<I", original, 68, 5)  # ELF headers mapped RX, as with NDK lld.
        sealed = bytearray(cse.process(bytes(original)))
        for p in (*range(40, 48), *range(58, 64)):
            sealed[p] ^= 0xA5
        cse.process(bytes(sealed), True)
        sealed[64] ^= 1  # Program headers remain bound.
        with self.assertRaises(ValueError):
            cse.process(bytes(sealed), True)

    def test_multimodule_nonce_and_duplicate_identity(self):
        one = payload()
        two = payload(module=b"another module!!")
        sealed = cse.process(elf(one + two))
        modules = cse.Elf(sealed).payloads()
        self.assertEqual(len(modules), 2)
        self.assertEqual(sealed[modules[0][0] + 72:modules[0][0] + 104],
                         sealed[modules[1][0] + 72:modules[1][0] + 104])
        cse.process(sealed, True)
        with self.assertRaises(ValueError):
            cse.process(elf(one + one))

    def test_bounds_and_metadata(self):
        for position, value in ((0x2000 + 8, 0xFFFFFFFF), (0x2000 + 20, 0),
                                (0x2100, 0), (0x2100, 33), (0x2100, 1 << 31), (0x2100 + 12, 5)):
            bad = bytearray(elf())
            struct.pack_into("<I", bad, position, value)
            with self.subTest(position=position, value=value), self.assertRaises(ValueError):
                cse.process(bytes(bad))
        for length in (0, 16, 63, 0x1FFF, len(elf()) - 1):
            with self.assertRaises(ValueError):
                cse.process(elf()[:length])
        for plain in (struct.pack("<IIII", 99, 1, 0, 0) + bytes(16),
                      struct.pack("<IIII", 1, 2, 0, 0) + bytes(16),
                      struct.pack("<IIII", 1, 1, 0, 1) + b"x" + bytes(15)):
            with self.assertRaises(ValueError):
                cse.validate_plain(plain, 0)

    def test_empty_and_nonterminated_constants(self):
        # The existing CSE pool includes byte/word arrays, not just C strings.
        for width, content in ((1, b""), (1, b"binary"), (2, b"\xff\xfe")):
            plain = struct.pack("<IIII", len(content), width, 0, 0) + content
            cse.validate_plain(plain, 0)

    def test_atomic_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "input.so", Path(tmp) / "output.so"
            src.write_bytes(elf()[:-1])
            dst.write_bytes(b"existing output")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/seal_cse.py"),
                                     "--input", str(src), "--output", str(dst)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(dst.read_bytes(), b"existing output")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["input.so", "output.so"])


if __name__ == "__main__":
    unittest.main()
