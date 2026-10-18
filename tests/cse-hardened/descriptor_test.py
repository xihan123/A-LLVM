"""Reject coordinated CSE descriptor edits in sealed ELF files on Android arm64."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import re
import struct
import tempfile
import uuid

from device_test import ROOT, cse, run


def descriptor_locations(data):
    image = cse.Elf(data)
    payload, total = image.payloads()[0]
    blob = data[payload:payload + total]
    key = cse.derive(blob, image.code_hash(), bytes(48))
    regions = bytearray()
    small = large = None
    for ordinal, offset, capacity in cse.records(blob):
        plain = cse.decrypt(key, blob[offset + 4:offset + 16],
                            cse.record_aad(blob, ordinal, capacity),
                            blob[offset + 32:offset + 32 + capacity], blob[offset + 16:offset + 32])
        length, encoding = struct.unpack_from("<II", plain)
        regions += struct.pack("<III", offset, capacity - 16, encoding)
        if plain[16:16 + length] == b"ok\0":
            small = ordinal
        if plain[16:16 + length] == b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\0":
            large = ordinal
    assert small is not None and large is not None
    table = data.find(regions)
    assert table >= 0 and data.find(regions, table + 1) == -1
    assert any(offset <= table and table + len(regions) <= offset + size
               for _, size, offset in image.executable), "region table must be authenticated code bytes"

    def virtual(offset):
        return next(va + offset - start for _, start, va, size, _ in image.loads
                    if start <= offset < start + size)

    def position(address):
        return next(start + address - va for _, start, va, size, _ in image.loads
                    if va <= address < va + size)

    # Tests request ordinary RELA relocations; production may use RELR as well.
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count = struct.unpack_from("<HH", data, 58)
    relocations = {}
    for i in range(count):
        entry = shoff + i * entsize
        if struct.unpack_from("<I", data, entry + 4)[0] != 4:  # SHT_RELA
            continue
        offset, size = struct.unpack_from("<QQ", data, entry + 24)
        for p in range(offset, offset + size, 24):
            address, info, addend = struct.unpack_from("<QQq", data, p)
            if info == 1027:  # R_AARCH64_RELATIVE
                relocations[address] = (p + 16, addend)
    modules = [address for address, (_, addend) in relocations.items()
               if addend == virtual(payload) and address + 16 in relocations
               and relocations[address + 16][1] == virtual(table)]
    assert len(modules) == 1
    module = modules[0]
    assert struct.unpack_from("<II", data, position(module) + 24) == (total, len(regions) // 12)
    return image, table, small, large, position(module), [relocations[module + i * 8] for i in range(3)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    ext = ".exe" if os.name == "nt" else ""
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / f"bin/clang{ext}"
    resource = max((base / "lib/clang").iterdir(), key=lambda p: int(p.name))
    common = ["--target=aarch64-linux-android29", f"--sysroot={base / 'sysroot'}",
              "-resource-dir", resource, f"-B{base / 'bin'}", "-std=c++17", "-fPIC"]
    source = ROOT / "tests/cse-hardened"
    remote = "/data/local/tmp/ndkp-descriptors-" + uuid.uuid4().hex
    adb = ["adb", "-s", args.serial]
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
    with (nullcontext(args.work_dir) if args.work_dir else tempfile.TemporaryDirectory()) as folder:
        out = Path(folder)
        run(*adb, "shell", "mkdir", remote)
        try:
            run(clang, *common, source / "descriptor_loader.cpp", "-ldl", "-o", out / "loader")
            run(*adb, "push", out / "loader", remote + "/loader")
            run(*adb, "shell", "chmod", "700", remote + "/loader")
            run(clang, *common, "-O2", "-fno-lto", "-fno-exceptions", "-c",
                ROOT / "runtime/ndkp_cse_runtime.cpp", "-o", out / "runtime.o")

            def execute(data, expected):
                (out / "test.so").write_bytes(data)
                run(*adb, "push", out / "test.so", remote + "/test.so")
                result = run(*adb, "shell", "timeout", "15", remote + "/loader", remote + "/test.so", check=False)
                assert result.returncode == expected and not result.stdout and not result.stderr, (
                    expected, result.returncode, result.stdout, result.stderr)

            for optimization, mode in (("O0", ""), ("O2", ""), ("Oz", ""), ("O2", "full"), ("O2", "thin"), ("O2", "mixed")):
                flags = ["-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened"]
                if mode == "mixed":
                    for name in ("cie", "indgv", "icall", "fla", "indbr"):
                        flags += ["-mllvm", "-irobf-" + name]
                elif mode:
                    flags += ["-flto=" + mode]
                run(clang, *common, "-" + optimization, *flags, "-S", "-emit-llvm",
                    source / "descriptor_fixture.cpp", "-o", out / "fixture.ll")
                ir = (out / "fixture.ll").read_text(encoding="utf-8")
                guard = re.search(r"define private void @ndkp_cse_module_decode.*?^}", ir, re.M | re.S)
                assert guard and guard[0].count("load volatile") == 5
                assert "@ndkp_cse_decode_region_v1" in guard[0] and "IndirectCallee" not in guard[0]
                run(clang, *common, "-" + optimization, *flags, "-c",
                    source / "descriptor_fixture.cpp", "-o", out / "fixture.o")
                link = [clang, *common, "--driver-mode=g++", "-shared", "-static-libstdc++",
                        "-Wl,--pack-dyn-relocs=none,--no-undefined", out / "fixture.o",
                        out / "runtime.o", "-ldl", "-o", out / "linked.so"]
                run(*link)
                sealed = cse.process((out / "linked.so").read_bytes())
                execute(sealed, 0)
                image, table, small, large, module, pointers = descriptor_locations(sealed)
                for case in ("rebase", "record-swap", "unused-region", "blob", "cache", "total", "count"):
                    data = bytearray(sealed)
                    if case in ("rebase", "record-swap"):
                        position, address = pointers[2]
                        struct.pack_into("<q", data, position, address + 12 * (small - large))
                    if case == "record-swap":
                        data[table + small * 12:table + (small + 1) * 12] = data[table + large * 12:table + (large + 1) * 12]
                    if case == "unused-region":
                        data[table + 2 * 12 + 4] ^= 1
                    if case in ("blob", "cache"):
                        position, address = pointers[0 if case == "blob" else 1]
                        struct.pack_into("<q", data, position, address + 4)
                    if case in ("total", "count"):
                        data[module + (24 if case == "total" else 28)] ^= 1
                    data = bytes(data)
                    if case not in ("record-swap", "unused-region"):
                        assert cse.Elf(data).code_hash() == image.code_hash()
                        cse.process(data, True)  # The module guard must reject edits outside the digest.
                    else:
                        assert cse.Elf(data).code_hash() != image.code_hash()
                    execute(data, 127)
                # A custom linker must not silently put region data outside authenticated RX bytes.
                script = out / "regions-in-rodata.ld"
                script.write_text("SECTIONS { .ndkp.regions : { *(.text.ndkp.cse.regions) } } INSERT AFTER .rodata;\n")
                run(*link, "-Wl,-T," + str(script.resolve()))
                execute(cse.process((out / "linked.so").read_bytes()), 127)
                print(f"[ok] {optimization}/{mode or 'no-lto'}: module/region tampering and non-RX layout rejected", flush=True)
        finally:
            run(*adb, "shell", "rm", "-rf", remote, check=False)


if __name__ == "__main__":
    main()
