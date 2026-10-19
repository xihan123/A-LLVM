"""Exercise VMP cast bytecode on ARM64, including negative and one-bit operands."""
import argparse
import os
from pathlib import Path
import tempfile
import uuid

from memory_ops import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--serial")
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    suffix = ".exe" if os.name == "nt" else ""
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    common = [args.clang.resolve(), "--target=aarch64-linux-android26",
              f"--sysroot={base / 'sysroot'}", f"-resource-dir={base / 'lib/clang/21'}"]
    cases = [
        ("signed32", "i32", "i64", "sext", "int", "long long", "-2147483647", "-2147483647LL"),
        ("signed8", "i8", "i64", "sext", "signed char", "long long", "-128", "-128LL"),
        ("signed16", "i16", "i64", "sext", "short", "long long", "-32768", "-32768LL"),
        ("signed1", "i1", "i32", "sext", "_Bool", "int", "1", "-1"),
        ("unsigned32", "i32", "i64", "zext", "unsigned", "unsigned long long", "0xffffffffU", "4294967295ULL"),
        ("truncate", "i64", "i32", "trunc", "long long", "unsigned", "0x12345678abcdef01LL", "0xabcdef01U"),
        ("truncate1", "i32", "i1", "trunc", "int", "_Bool", "2", "0"),
        ("extendfp", "float", "double", "fpext", "float", "double", "-2.5f", "-2.5"),
        ("truncatefp", "double", "float", "fptrunc", "double", "float", "-2.5", "-2.5f"),
        ("fptosigned", "double", "i32", "fptosi", "double", "int", "-23.75", "-23"),
        ("fptounsigned", "float", "i32", "fptoui", "float", "unsigned", "123.75f", "123U"),
        ("signedtofp", "i32", "double", "sitofp", "int", "double", "-7654321", "-7654321.0"),
        ("unsignedtofp", "i32", "double", "uitofp", "unsigned", "double", "0xffffffffU", "4294967295.0"),
    ]
    with tempfile.TemporaryDirectory(prefix="vmp-casts-") as directory:
        out = Path(directory)
        source = out / "casts.ll"
        source.write_text("\n".join(
            f"define {dest} @{name}({src} %x) {{\n %r = {opcode} {src} %x to {dest}\n ret {dest} %r\n}}"
            for name, src, dest, opcode, *_ in cases))
        driver = out / "driver.c"
        driver.write_text('#include <stdio.h>\n' + "\n".join(
            f"extern {ret} {name}({arg});" for name, _, _, _, arg, ret, _, _ in cases)
            + '\nint main(void) {\n' + "\n".join(
                f'if ({name}({value}) != ({expected})) {{puts("failed: {name}");return 1;}}'
                for name, _, _, _, _, _, value, expected in cases)
            + '\nputs("VMP casts OK");return 0;}\n')
        flags = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict", "-mllvm",
                 "-irobf-vm_functions=" + ";".join(case[0] for case in cases)]
        for mode in ("plain", "vmp"):
            ir = out / (mode + ".ll")
            run(*common, "-O0", *(flags if mode == "vmp" else []), "-S", "-emit-llvm", source, "-o", ir)
            if mode == "vmp":
                assert ir.read_text().count("!ndkp.vmp.protected") == len(cases)
            obj = out / "casts.o"
            run(*common, "-c", ir, "-o", obj)
            binary = out / mode
            run(*common, "--driver-mode=g++", f"--ld-path={base / ('bin/ld.lld' + suffix)}",
                "-static-libstdc++", "-x", "c", driver, "-x", "none", obj, "-o", binary)
            if args.serial:
                remote = "/data/local/tmp/dex2c-casts-" + uuid.uuid4().hex
                adb = ["adb", "-s", args.serial]
                try:
                    run(*adb, "push", binary, remote)
                    run(*adb, "shell", "chmod", "700", remote)
                    assert "VMP casts OK" in run(*adb, "shell", remote)
                finally:
                    run(*adb, "shell", "rm", "-f", remote)
            print(f"[ok] {mode}: {len(cases)} cast operations; "
                  + ("device semantics" if args.serial else "compile only"), flush=True)


if __name__ == "__main__":
    main()
