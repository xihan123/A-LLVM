"""Native ownership/parser regression, on Linux or an arm64 Android device.

Linux: python tests/cert-bind/test_apkcert.py
Android: python tests/cert-bind/test_apkcert.py --ndk NDK --serial SERIAL
Synthetic signing blocks exercise certificate extraction, not APK signature verification.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import uuid
import warnings
import zipfile


def lp(data):
    return struct.pack("<I", len(data)) + data


def apk(entries, certs=(), compression=zipfile.ZIP_STORED, extra=b"", comment=b"", local_padding=b""):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", compression) as z:
            for name in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = compression
                info.extra = extra
                z.writestr(info, b"fixture library contents")
            z.comment = comment
    data = buffer.getvalue()
    eocd = len(data) - 22 - len(comment)
    cd = struct.unpack_from("<I", data, eocd + 16)[0]
    if local_padding:
        # zipalign appends raw zero padding to local extras, leaving central extras unchanged.
        assert len(entries) == 1
        data = bytearray(data)
        name_len, extra_len = struct.unpack_from("<HH", data, 26)
        at = 30 + name_len + extra_len
        struct.pack_into("<H", data, 28, extra_len + len(local_padding))
        data[at:at] = local_padding
        cd += len(local_padding)
        eocd += len(local_padding)
        struct.pack_into("<I", data, eocd + 16, cd)
    pairs = b""
    for block_id, cert in certs:
        signed = lp(b"") + lp(lp(cert))
        value = lp(lp(lp(signed) + lp(b"") + lp(b"")))
        pairs += struct.pack("<QI", len(value) + 4, block_id) + value
    if not pairs:
        return data
    size = struct.pack("<Q", len(pairs) + 24)
    block = size + pairs + size + b"APK Sig Block 42"
    result = bytearray(data[:cd] + block + data[cd:])
    struct.pack_into("<I", result, eocd + len(block) + 16, cd + len(block))
    return bytes(result)


def fixtures(root, abi):
    entry = f"lib/{abi}/libowner.so"
    cert_a, cert_b = b"first fixture signer DER", b"second fixture signer DER"
    v2, v3 = 0x7109871A, 0xF05368C0
    good = apk([entry], [(v2, cert_a)])
    files = {
        "owner.apk": good,
        "host.apk": apk([entry], [(v2, cert_b)]),
        "v3.apk": apk([entry], [(v3, cert_b)]),
        "prefer-v2.apk": apk([entry], [(v3, cert_b), (v2, cert_a)]),
        "deflated.apk": apk([entry], [(v2, cert_a)], zipfile.ZIP_DEFLATED),
        "comment.apk": apk([entry], [(v2, cert_a)], comment=b"PK\x05\x06" + b"x" * 40),
        "extra.apk": apk([entry], [(v2, cert_a)], extra=struct.pack("<HHI", 0xCAFE, 4, 7)),
        "zip64-extra.apk": apk([entry], [(v2, cert_a)], extra=struct.pack("<HHQ", 1, 8, 7)),
        "bad-extra.apk": apk([entry], [(v2, cert_a)], extra=b"\x00"),
        "padding-1.apk": apk([entry], [(v2, cert_a)], local_padding=b"\x00"),
        "padding-2.apk": apk([entry], [(v2, cert_a)], local_padding=b"\x00" * 2),
        "padding-3.apk": apk([entry], [(v2, cert_a)], local_padding=b"\x00" * 3),
        "padding-5.apk": apk([entry], [(v2, cert_a)], local_padding=b"\x00" * 5),
        "bad-local-extra.apk": apk([entry], [(v2, cert_a)], local_padding=b"\x01"),
        "duplicate.apk": apk([entry, entry], [(v2, cert_a)]),
        "wrong-abi.apk": apk(["lib/other/libowner.so"], [(v2, cert_b)]),
        "missing.apk": apk(["classes.dex"], [(v2, cert_b)]),
        "unsigned.apk": apk([entry]),
        "truncated.apk": good[:-1],
        "empty.apk": b"",
    }
    for name, offset, fmt, value in (
        ("zip64.apk", -6, "I", 0xFFFFFFFF),
        ("multidisk.apk", -18, "H", 1),
        ("bad-local.apk", 0, "I", 0),
        ("bad-name.apk", 30, "B", ord("X")),
        ("bad-local-size.apk", 18, "I", 1),
    ):
        data = bytearray(good)
        struct.pack_into("<" + fmt, data, offset % len(data), value)
        files[name] = data
    cd = struct.unpack_from("<I", good, len(good) - 6)[0]
    for name, offset, fmt, value in (
        ("bad-count.apk", len(good) - 12, "H", 2),
        ("bad-record.apk", cd + 30, "H", 0xFFFF),
        ("bad-offset.apk", cd + 42, "I", cd),
        ("bad-method.apk", cd + 10, "H", 99),
        ("bad-size.apk", cd + 20, "I", cd),
    ):
        data = bytearray(good)
        struct.pack_into("<" + fmt, data, offset, value)
        files[name] = data
    for name, data in files.items():
        (root / name).write_bytes(data)
    (root / "a.sha").write_bytes(hashlib.sha256(cert_a).digest())
    (root / "b.sha").write_bytes(hashlib.sha256(cert_b).digest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--serial")
    args = parser.parse_args()
    if bool(args.ndk) != bool(args.serial):
        parser.error("--ndk and --serial must be used together")
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="ndkp-apkcert-") as tmp:
        out = Path(tmp)
        if args.ndk:
            host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
            ext = ".exe" if os.name == "nt" else ""
            compiler = [str(args.ndk.resolve() / "toolchains/llvm/prebuilt" / host /
                            f"bin/clang++{ext}"), "--target=aarch64-linux-android21",
                        "-static-libstdc++"]
            abi = "arm64-v8a"
        else:
            compiler = shlex.split(os.environ.get("CXX", "c++"))
            import platform
            abi = {"x86_64": "x86_64", "aarch64": "arm64-v8a",
                   "i686": "x86", "armv7l": "armeabi-v7a"}[platform.machine()]
        fixtures(out, abi)
        executable = out / "apkcert_test"
        subprocess.run([*compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fno-lto", "-I", str(root / "runtime"),
                        str(root / "tests/cert-bind/apkcert_test.cpp"),
                        str(root / "runtime/ndkp_apkcert.cpp"),
                        "-Wl,--wrap=open", "-Wl,--wrap=fopen", "-o", str(executable)],
                       check=True)
        if not args.serial:
            subprocess.run([str(executable), str(out)], check=True)
            return
        remote = "/data/local/tmp/ndkp-apkcert-" + uuid.uuid4().hex
        adb = ["adb", "-s", args.serial]
        try:
            subprocess.run([*adb, "push", str(out), remote], check=True, capture_output=True)
            subprocess.run([*adb, "shell", "chmod", "700", remote + "/apkcert_test"], check=True)
            subprocess.run([*adb, "shell", remote + "/apkcert_test", remote], check=True)
        finally:
            subprocess.run([*adb, "shell", "rm", "-rf", remote], check=True)


if __name__ == "__main__":
    main()
