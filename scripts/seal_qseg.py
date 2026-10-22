#!/usr/bin/env python3
"""Build and verify QSEG v1 containers. Uses only Python's standard library."""
import argparse
import hashlib
import json
import secrets
import struct
import zlib
import zipfile
from pathlib import Path

from seal_cse import Elf, derive, encrypt, decrypt, expected_inputs, hkdf, u32

IMAGE_MAGIC = b"NDKPQSG1"
FILE_MAGIC = b"QSEGDAT1"
MAX_SIZE = 1 << 28
ENTRY = struct.Struct("<16s8I16s")


def zip_entry_range(data, entry, central_offset):
    """按运行时规则核对 STORED 条目的本地头和中央目录，返回真实载荷范围。"""
    local = entry.header_offset
    if not 0 <= local <= central_offset - 30 or central_offset > len(data):
        raise ValueError("ZIP local header bounds")
    magic, _, flags, method, _, _, crc, compressed, size, names, extra = struct.unpack_from("<I5H3I2H", data, local)
    encoded = entry.filename.encode('utf-8' if flags & 0x800 else 'cp437')
    start = local + 30 + names + extra
    if (magic != 0x04034b50 or flags != entry.flag_bits or flags & ~0x808 or
            method != zipfile.ZIP_STORED or entry.compress_type != method or
            entry.compress_size != entry.file_size or names != len(encoded) or
            data[local + 30:local + 30 + names] != encoded or
            start > central_offset or entry.file_size > central_offset - start):
        raise ValueError("ZIP local/central header mismatch")
    if not flags & 8 and (crc, compressed, size) != (entry.CRC, entry.compress_size, entry.file_size):
        raise ValueError("ZIP local/central sizes or CRC mismatch")
    return start, start + entry.file_size


def segment_key(root, header, identity, kind, chunk):
    return hkdf(root, header[72:104], b"NDKP-QSEG-v1" + identity + struct.pack("<II", kind, chunk))


def index_key(root, header):
    return hkdf(root, header[72:104], b"NDKP-QSEG-index-v1" + header[24:40])


def read_stages(directories):
    resources, ids = [], set()
    for directory in directories:
        for item in json.loads((directory / "manifest.json").read_text(encoding="utf-8")):
            identity = bytes.fromhex(item["id"])
            data = (directory / (item["id"] + ".bin")).read_bytes()
            if len(identity) != 16 or identity in ids or item["kind"] not in (1, 2):
                raise ValueError("invalid/duplicate staged identity")
            if len(data) != item["bytes"] or not 0 < len(data) <= 1 << 24:
                raise ValueError("invalid staged size")
            ids.add(identity)
            resources.append((identity, item["kind"], data, item["name"]))
    if not resources:
        raise ValueError("empty segmented image")
    return resources


def prepare(resources, asset, certificate):
    if not asset.startswith("assets/") or ".." in asset or len(asset.encode()) >= 128:
        raise ValueError("invalid asset path")
    header = bytearray(512)
    header[:8] = IMAGE_MAGIC
    struct.pack_into("<I", header, 16, 2)
    struct.pack_into("<I", header, 220, 183)  # ELF EM_AARCH64, format v1's only ABI.
    header[24:72] = secrets.token_bytes(48)
    header[184:216] = secrets.token_bytes(32)
    header[104:152] = expected_inputs(2, certificate=certificate)
    header[256:256 + len(asset.encode())] = asset.encode()
    return bytes(header)


def locate_image(data):
    if len(data) < 20 or data[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError("QSEG requires ELF64 little-endian AArch64")
    elf = Elf(data)
    found = []
    for flags, offset, _, size, _ in elf.loads:
        if flags & 1:
            continue
        pos = data.find(IMAGE_MAGIC, offset, offset + size)
        while pos >= 0:
            if pos + 512 <= offset + size and data[pos + 256:pos + 263] == b"assets/":
                if flags != 4:
                    raise ValueError("QSEG descriptor must be read-only")
                found.append(pos)
            pos = data.find(IMAGE_MAGIC, pos + 1, offset + size)
    if len(found) != 1:
        raise ValueError("expected exactly one QSEG image")
    return elf, found[0]


def pack(data, resources):
    identities = set()
    if not resources:
        raise ValueError("empty segmented image")
    for identity, kind, raw, _ in resources:
        if len(identity) != 16 or identity in identities or kind not in (1, 2) or not 0 < len(raw) <= 1 << 24:
            raise ValueError("invalid/duplicate staged identity or size")
        identities.add(identity)
    elf, pos = locate_image(data)
    header = bytearray(data[pos:pos + 512])
    if u32(header, 12) or any(header[72:104]) or any(header[152:184]) or any(header[384:]):
        raise ValueError("QSEG image already sealed or invalid")
    header[72:104] = secrets.token_bytes(32)
    header[152:184] = elf.code_hash()
    staged_inputs = bytes(header[104:152])
    header[104:152] = bytes(48)
    chunks = []
    for identity, kind, raw, _ in resources:
        limit = 65536 if kind == 1 else len(raw)
        for chunk, start in enumerate(range(0, len(raw), limit)):
            plain = raw[start:start + limit]
            codec = zlib.compressobj(6, zlib.DEFLATED, -15)
            compressed = codec.compress(plain) + codec.flush()
            use = len(plain) - len(compressed) >= 16 and len(compressed) * 100 <= len(plain) * 95
            chunks.append((identity, kind, chunk, plain, compressed if use else plain, int(use), len(raw)))
    directory_size = len(chunks) * ENTRY.size
    cursor = 16 + directory_size + 16
    total = cursor + sum(len(c[4]) for c in chunks)
    if total > MAX_SIZE or len(chunks) > 16384:
        raise ValueError("container exceeds size/chunk limits")
    struct.pack_into("<III", header, 8, total, 1, 2)
    struct.pack_into("<I", header, 20, len(chunks))
    struct.pack_into("<I", header, 216, directory_size)
    root = derive(header, header[152:184], staged_inputs)
    sources = {(identity, kind): (name, hashlib.sha256(raw).hexdigest()) for identity, kind, raw, name in resources}
    directory, body, receipt = bytearray(), bytearray(), []
    for ordinal, (identity, kind, chunk, plain, stored, codec, rawsize) in enumerate(chunks):
        meta = ENTRY.pack(identity, kind, chunk, cursor, len(stored), len(plain), rawsize, codec, ordinal, bytes(16))
        key = segment_key(root, header, identity, kind, chunk)
        cipher, mac = encrypt(key, bytes(12), header[24:40] + meta[:48], stored)
        directory += meta[:48] + mac
        body += cipher
        name, resource_hash = sources[identity, kind]
        receipt.append({"id": identity.hex(), "kind": kind, "chunk": chunk, "bytes": len(plain),
                        "name": name, "resourceSha256": resource_hash,
                        "storedBytes": len(stored), "codec": codec, "sha256": hashlib.sha256(plain).hexdigest()})
        cursor += len(stored)
    prefix = FILE_MAGIC + struct.pack("<II", 1, directory_size)
    cipher, mac = encrypt(index_key(root, header), bytes(12), prefix + header[24:40], directory)
    container = prefix + cipher + mac + body
    header[384:416] = hashlib.sha256(container).digest()
    output = bytearray(data)
    output[pos:pos + 512] = header
    return bytes(output), container, receipt


def unpack(data, container, certificate):
    elf, pos = locate_image(data)
    h = data[pos:pos + 512]
    if (u32(h, 12) != 1 or u32(h, 16) != 2 or u32(h, 220) != 183 or any(h[104:152]) or
            any(h[224:256]) or any(h[416:512]) or h[152:184] != elf.code_hash()):
        raise ValueError("QSEG image/code binding failed")
    if len(container) != u32(h, 8) or not 32 <= len(container) <= MAX_SIZE or hashlib.sha256(container).digest() != h[384:416]:
        raise ValueError("QSEG container digest failed")
    if container[:8] != FILE_MAGIC or u32(container, 8) != 1:
        raise ValueError("QSEG format failed")
    count, size = u32(h, 20), u32(container, 12)
    if not 0 < count <= 16384 or size != count * ENTRY.size or size != u32(h, 216) or size + 32 > len(container):
        raise ValueError("QSEG directory bounds failed")
    root = derive(h, h[152:184], expected_inputs(2, certificate=certificate))
    directory = decrypt(index_key(root, h), bytes(12), container[:16] + h[24:40],
                        container[16:16 + size], container[16 + size:32 + size])
    result, expected, identities, cursor = {}, {}, {}, 32 + size
    for ordinal in range(count):
        entry = directory[ordinal * ENTRY.size:(ordinal + 1) * ENTRY.size]
        identity, kind, chunk, offset, stored, length, total, codec, order, mac = ENTRY.unpack(entry)
        key = (identity, kind)
        if kind not in (1, 2) or codec not in (0, 1) or order != ordinal or chunk != expected.get(key, 0):
            raise ValueError("invalid QSEG segment metadata")
        if (identity in identities and identities[identity] != kind) or (kind == 2 and chunk):
            raise ValueError("duplicate QSEG identity/string block")
        identities[identity] = kind
        if offset != cursor or not 0 < stored <= length <= 1 << 24 or not 0 < total <= 1 << 24 or offset + stored > len(container):
            raise ValueError("invalid QSEG segment bounds")
        if kind == 1 and (length > 65536 or (chunk and len(result[key]) != chunk * 65536)):
            raise ValueError("invalid VM chunks")
        raw = decrypt(segment_key(root, h, identity, kind, chunk), bytes(12), h[24:40] + entry[:48],
                      container[offset:offset + stored], mac)
        if codec:
            decoder = zlib.decompressobj(-15)
            raw = decoder.decompress(raw, length + 1)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("invalid/bomb compressed segment")
        if len(raw) != length:
            raise ValueError("QSEG restored length failed")
        if key in result and expected[key + ("total",)] != total:
            raise ValueError("inconsistent QSEG total")
        result.setdefault(key, bytearray()).extend(raw)
        expected[key] = chunk + 1
        expected[key + ("total",)] = total
        cursor += stored
    if cursor != len(container) or any(len(raw) != expected[key + ("total",)] for key, raw in result.items()):
        raise ValueError("QSEG incomplete/trailing data")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, action="append", default=[])
    parser.add_argument("--asset")
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--container", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        cert = args.cert_file.read_bytes()
        resources = read_stages(args.staging) if args.staging else []
        if args.source:
            h = prepare(resources, args.asset, cert)
            args.source.write_text('extern "C" { __attribute__((visibility("hidden"),section(".rodata.ndkp.qseg"),used)) '
                                   'extern const unsigned char ndkp_qseg_image[512]={' + ','.join(map(str, h)) + '}; }\n', encoding="utf-8")
        elif args.verify:
            restored = unpack(args.input.read_bytes(), args.container.read_bytes(), cert)
            if resources and restored != {(i, k): b for i, k, b, _ in resources}:
                raise ValueError("staged/final payload mismatch")
        else:
            output, container, receipt = pack(args.input.read_bytes(), resources)
            # Verify before publishing either candidate output.
            unpack(output, container, cert)
            args.container.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(output)
            args.container.write_bytes(container)
            if args.receipt:
                args.receipt.write_text(json.dumps({"schemaVersion": 1, "containerSha256": hashlib.sha256(container).hexdigest(),
                    "containerBytes": len(container), "segments": receipt}, indent=2) + '\n', encoding="utf-8")
        print("QSEG verified" if args.verify else "QSEG prepared")
    except (OSError, ValueError, struct.error, zlib.error) as error:
        parser.exit(1, f"seal_qseg: {error}\n")


if __name__ == "__main__":
    main()
