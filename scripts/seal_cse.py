#!/usr/bin/env python3
"""Seal arm64 CSE v1 ELF payloads. Standard library only; never edits the input."""
import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import struct
import tempfile

MAGIC = b"NDKPCSE\x01"
HEADER = 256
MAX_CAPACITY = 1 << 24


def u32(b, p=0):
    return struct.unpack_from("<I", b, p)[0]


def chacha_block(key, nonce, counter):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    x = state[:]

    def qr(a, b, c, d):
        for left, right, shift in ((a, d, 16), (c, b, 12), (a, d, 8), (c, b, 7)):
            x[left] = (x[left] + x[b if left == a else d]) & 0xFFFFFFFF
            v = x[right] ^ x[left]
            x[right] = ((v << shift) | (v >> (32 - shift))) & 0xFFFFFFFF

    for _ in range(10):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            qr(*indices)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, state)])


def crypt(key, nonce, data):
    result = bytearray(data)
    for offset in range(0, len(result), 64):
        ks = chacha_block(key, nonce, offset // 64 + 1)
        for i in range(min(64, len(result) - offset)):
            result[offset + i] ^= ks[i]
    return bytes(result)


def tag(key, nonce, aad, ciphertext):
    one_time = chacha_block(key, nonce, 0)
    r = int.from_bytes(one_time[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time[16:32], "little")
    data = aad + bytes(-len(aad) % 16) + ciphertext + bytes(-len(ciphertext) % 16)
    data += struct.pack("<QQ", len(aad), len(ciphertext))
    accumulator = 0
    for pos in range(0, len(data), 16):
        accumulator = ((accumulator + int.from_bytes(data[pos:pos + 16] + b"\x01", "little")) * r) % ((1 << 130) - 5)
    return ((accumulator + s) % (1 << 128)).to_bytes(16, "little")


def encrypt(key, nonce, aad, plaintext):
    ciphertext = crypt(key, nonce, plaintext)
    return ciphertext, tag(key, nonce, aad, ciphertext)


def decrypt(key, nonce, aad, ciphertext, expected):
    if not hmac.compare_digest(tag(key, nonce, aad, ciphertext), expected):
        raise ValueError("CSE authentication failed")
    return crypt(key, nonce, ciphertext)


def hkdf(ikm, salt, info):
    prk = hmac.digest(salt, ikm, "sha256")
    return hmac.digest(prk, info + b"\x01", "sha256")


def derive(header, code, inputs):
    seed = bytes(a ^ b for a, b in zip(header[40:72], header[184:216]))
    info = b"NDKP-CSE-v1" + bytes(5) + header[24:40] + code
    return hkdf(seed + inputs, header[72:104], info)


def record_aad(header, ordinal, capacity):
    return header[24:40] + struct.pack("<IIIIII", 1, u32(header, 16), ordinal, capacity, u32(header, 8), u32(header, 20))


class Elf:
    def __init__(self, data):
        self.data = data
        if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("expected little-endian ELF64")
        if struct.unpack_from("<HHI", data, 16) != (3, 183, 1):
            raise ValueError("expected arm64 ET_DYN ELF")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        ehsize, entsize, count = struct.unpack_from("<HHH", data, 52)
        if ehsize != 64 or entsize != 56 or not 0 < count < 1024 or phoff + count * 56 > len(data):
            raise ValueError("invalid program headers")
        self.loads = []
        self.executable = []
        for index in range(count):
            kind, flags, offset, va, _, size, memsize, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56)
            if kind in (1, 2) and (offset + size > len(data) or size > memsize or va + memsize >= 1 << 64):
                raise ValueError("invalid segment bounds")
            if kind == 1:
                if align > 1 and (align & (align - 1) or (va - offset) % align):
                    raise ValueError("invalid segment alignment")
                self.loads.append((flags, offset, va, size, memsize))
                if flags & 1:
                    if flags != 5 or size != memsize:
                        raise ValueError("executable segments must be readable, immutable and file-backed")
                    self.executable.append((va, size, offset))
            if kind == 2:
                if size % 16:
                    raise ValueError("invalid dynamic table")
                for p in range(offset, offset + size, 16):
                    dynamic_tag, value = struct.unpack_from("<QQ", data, p)
                    if dynamic_tag == 0:
                        break
                    if dynamic_tag == 22 or (dynamic_tag == 30 and value & 4):
                        raise ValueError("text relocations are unsupported")
        if not self.executable:
            raise ValueError("no executable segments")
        ordered = sorted(self.loads, key=lambda item: item[2])
        if any(a[2] + a[4] > b[2] for a, b in zip(ordered, ordered[1:])):
            raise ValueError("overlapping load segments")
        by_file = sorted((p for p in self.loads if p[3]), key=lambda item: item[1])
        if any(a[1] + a[3] > b[1] for a, b in zip(by_file, by_file[1:])):
            raise ValueError("aliased file-backed load segments")

    def code_hash(self):
        # A bounded-memory digest of ordered segment descriptors and segment digests.
        material = bytearray(b"NDKP-CODE-v1")
        for va, size, offset in self.executable:
            material += struct.pack("<QQ", va, size)
            segment = bytearray(self.data[offset:offset + size])
            # NDK lld may map the ELF header RX. strip changes only section-table
            # bookkeeping here; runtime does not consume section headers.
            for start, end in ((40, 48), (58, 64)):
                for absolute in range(max(start, offset), min(end, offset + size)):
                    segment[absolute - offset] = 0
            material += hashlib.sha256(segment).digest()
        return hashlib.sha256(material).digest()

    def payloads(self):
        found = []
        for flags, offset, _, size, _ in self.loads:
            if flags & 1:
                continue
            pos, end = offset, offset + size
            while True:
                pos = self.data.find(MAGIC, pos, end)
                if pos < 0:
                    break
                if pos + HEADER > end:
                    raise ValueError("truncated CSE header")
                total = u32(self.data, pos + 8)
                if total < HEADER or total > 1 << 28 or pos + total > end:
                    raise ValueError("invalid CSE payload size")
                header = self.data[pos:pos + HEADER]
                if u32(header, 16) & ~3 or any(header[216:]):
                    raise ValueError("unsupported CSE header")
                if not 1 < u32(header, 20) <= (total - HEADER) // 64:
                    raise ValueError("invalid CSE record count")
                found.append((pos, total))
                pos += total
        if not found:
            raise ValueError("no CSE v1 payloads")
        ids = [self.data[p + 24:p + 40] for p, _ in found]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate module identifiers")
        return found


def records(blob):
    pos = HEADER
    for ordinal in range(u32(blob, 20)):
        if pos + 32 > len(blob):
            raise ValueError("truncated record")
        capacity = u32(blob, pos)
        if capacity < 32 or capacity > MAX_CAPACITY or capacity & (capacity - 1) or pos + 32 + capacity > len(blob):
            raise ValueError("invalid record capacity")
        if blob[pos + 4:pos + 16] != struct.pack("<QI", 0, ordinal):
            raise ValueError("invalid record nonce")
        yield ordinal, pos, capacity
        pos += 32 + capacity
    if pos != len(blob):
        raise ValueError("trailing CSE data")


def validate_plain(plain, ordinal):
    length, encoding, identity, reserved = struct.unpack_from("<IIII", plain)
    if identity != ordinal or reserved or encoding not in (1, 2) or length > len(plain) - 16:
        raise ValueError("invalid encrypted metadata")
    if length % encoding:
        raise ValueError("invalid element width")


def expected_inputs(flags, package=None, certificate=None):
    result = bytearray(48)
    if flags & 1:
        if not package or not package.split(":", 1)[0]:
            raise ValueError("--package is required to verify package-bound strings")
        result[:32] = hashlib.sha256(package.split(":", 1)[0].encode()).digest()
    if flags & 2:
        if certificate is None:
            raise ValueError("--cert-file is required to verify certificate-bound strings")
        begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
        if begin in certificate:
            body = certificate.split(begin, 1)[1]
            if end not in body:
                raise ValueError("invalid PEM certificate")
            certificate = base64.b64decode(b"".join(body.split(end, 1)[0].split()), validate=True)
        digest = hashlib.sha256(certificate).digest()
        result[32:] = bytes(a ^ b for a, b in zip(digest[:16], digest[16:]))
    return bytes(result)


def process(data, verify=False, package=None, certificate=None):
    elf = Elf(data)
    code = elf.code_hash()
    output = bytearray(data)
    build_nonce = secrets.token_bytes(32) if not verify else None
    for pos, total in elf.payloads():
        blob = bytearray(data[pos:pos + total])
        state = u32(blob, 12)
        if state != (1 if verify else 0):
            raise ValueError("expected sealed payload" if verify else "payload already sealed or invalid")
        if verify:
            if any(blob[104:152]) or blob[152:184] != code or not any(blob[72:104]):
                raise ValueError("code binding or staging-material check failed")
            inputs = expected_inputs(u32(blob, 16), package, certificate)
            key = derive(blob, code, inputs)
        else:
            if any(blob[72:104]) or any(blob[152:184]):
                raise ValueError("invalid staging header")
            inputs = bytes(blob[104:152])
            flags = u32(blob, 16)
            if (not flags & 1 and any(inputs[:32])) or (not flags & 2 and any(inputs[32:])):
                raise ValueError("staging inputs disagree with binding flags")
            key = derive(blob, bytes(32), inputs)
        staged = bytes(blob[:HEADER])
        decoded = []
        for ordinal, p, capacity in records(blob):
            plain = decrypt(key, blob[p + 4:p + 16], record_aad(staged, ordinal, capacity),
                            blob[p + 32:p + 32 + capacity], blob[p + 16:p + 32])
            validate_plain(plain, ordinal)
            decoded.append((ordinal, p, capacity, plain))
        if not verify:
            blob[72:104] = build_nonce
            blob[152:184] = code
            new_key = derive(blob, code, inputs)
            for ordinal, p, capacity, plain in decoded:
                ciphertext, mac = encrypt(new_key, blob[p + 4:p + 16], record_aad(blob, ordinal, capacity), plain)
                blob[p + 16:p + 32] = mac
                blob[p + 32:p + 32 + capacity] = ciphertext
            blob[104:152] = bytes(48)
            struct.pack_into("<I", blob, 12, 1)
            output[pos:pos + total] = blob
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--package")
    parser.add_argument("--cert-file", type=Path)
    args = parser.parse_args()
    try:
        if args.verify and args.output or not args.verify and args.output is None:
            raise ValueError("use --output for sealing; --verify is read-only")
        if args.output and args.input.resolve() == args.output.resolve():
            raise ValueError("input and output must differ")
        result = process(args.input.read_bytes(), args.verify, args.package,
                         args.cert_file.read_bytes() if args.cert_file else None)
        if not args.verify:
            # All validation precedes creation; replace is atomic even if output exists.
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as stream:
                    temporary = stream.name
                    stream.write(result)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, args.input.stat().st_mode & 0o777)
                os.replace(temporary, args.output)
            finally:
                if temporary and os.path.exists(temporary):
                    os.unlink(temporary)
        print("CSE verified" if args.verify else "CSE sealed")
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"seal_cse: {error}\n")


if __name__ == "__main__":
    main()
