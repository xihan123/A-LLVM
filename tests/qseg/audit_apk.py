"""Audit final APK bytes, ZIP/ELF alignment and authenticated QSEG resource receipts."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import seal_qseg as qseg


def audit(apk, protection, segments, certificate):
    receipt = json.loads(protection.read_text(encoding="utf-8"))
    segment_receipt = json.loads(segments.read_text(encoding="utf-8"))
    if hashlib.sha256(segments.read_bytes()).hexdigest() != receipt["segmentsReceiptSha256"]:
        raise ValueError("Segment receipt changed")
    data = apk.read_bytes()
    libraries = []
    with zipfile.ZipFile(apk) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError("Duplicate ZIP names")
        for entry in archive.infolist():
            if not entry.filename.endswith(".so"):
                continue
            start, _ = qseg.zip_entry_range(data, entry, archive.start_dir)
            if entry.compress_type != zipfile.ZIP_STORED or start % 16384:
                raise ValueError("SO ZIP alignment failed: " + entry.filename)
            library = archive.read(entry)
            if not entry.filename.startswith('lib/arm64-v8a/') or library[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', library, 18)[0] != 183:
                raise ValueError("Unsupported SO ABI: " + entry.filename)
            elf = qseg.Elf(library)
            phoff = struct.unpack_from("<Q", library, 32)[0]
            entsize, count = struct.unpack_from("<HH", library, 54)
            for i in range(count):
                kind, _, offset, address, _, _, _, alignment = struct.unpack_from("<IIQQQQQQ", library, phoff+i*entsize)
                if kind == 1 and (alignment < 16384 or (address-offset) % 16384):
                    raise ValueError("SO ELF alignment failed: " + entry.filename)
            libraries.append({"name": entry.filename, "bytes": len(library), "sha256": hashlib.sha256(library).hexdigest()})
        selected = [item for item in libraries if item["sha256"] == receipt["librarySha256"]]
        if len(selected) != 1:
            raise ValueError("Final SO does not match protection receipt")
        library = archive.read(selected[0]["name"])
        _, pos = qseg.locate_image(library)
        asset = library[pos+256:pos+384].split(b"\0", 1)[0].decode("utf-8")
        names = [entry for entry in archive.infolist() if entry.filename.endswith(".qseg")]
        if len(names) != 1 or names[0].filename != asset or names[0].compress_type != zipfile.ZIP_STORED:
            raise ValueError("Missing, extra or compressed container")
        blob = archive.read(names[0])
        qseg.zip_entry_range(data, names[0], archive.start_dir)
        if hashlib.sha256(blob).hexdigest() != receipt["containerSha256"] or len(blob) != receipt["containerBytes"]:
            raise ValueError("Container changed after sealing")
        resources = qseg.unpack(library, blob, certificate.read_bytes())
        expected = {(identity.hex(), kind, chunk)
                    for (identity, kind), raw in resources.items()
                    for chunk in range((len(raw)+65535)//65536 if kind == 1 else 1)}
        seen = set()
        for item in segment_receipt["segments"]:
            key = (item["id"], item["kind"], item["chunk"])
            if key not in expected or key in seen:
                raise ValueError("Extra or duplicate segment receipt")
            seen.add(key)
            raw = resources[(bytes.fromhex(item["id"]), item["kind"])]
            part = raw[item["chunk"]*65536:(item["chunk"]+1)*65536] if item["kind"] == 1 else raw
            if (hashlib.sha256(raw).hexdigest() != item["resourceSha256"] or
                    hashlib.sha256(part).hexdigest() != item["sha256"] or len(part) != item["bytes"]):
                raise ValueError("Original resource/chunk digest mismatch")
        if seen != expected:
            raise ValueError("Incomplete segment receipt")
    return {"apk": str(apk), "apkBytes": len(data), "apkSha256": hashlib.sha256(data).hexdigest(),
            "resources": len(resources), "chunks": len(segment_receipt["segments"]), "libraries": libraries,
            "alignment16384": True, "authenticatedRecovery": True, "apkOnlyRecoveryPrevented": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--protection", type=Path, required=True)
    parser.add_argument("--segments", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.apk, args.protection, args.segments, args.certificate)
    text = json.dumps(result, indent=2)+"\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
