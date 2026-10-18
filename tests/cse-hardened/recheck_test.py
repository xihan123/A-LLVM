"""Exercise opt-in CSE checkpoints and VMP entry integrity in a disposable arm64 loader."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import re
import tempfile
import uuid

from descriptor_test import descriptor_locations
from device_test import ROOT, cse, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    if not args.compile_only and not args.serial:
        parser.error("--serial is required unless --compile-only is used")
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    ext = ".exe" if os.name == "nt" else ""
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / f"bin/clang{ext}"
    resource = max((base / "lib/clang").iterdir(), key=lambda p: int(p.name))
    common = ["--target=aarch64-linux-android29", f"--sysroot={base / 'sysroot'}",
              "-resource-dir", resource, f"-B{base / 'bin'}", "-std=c++17", "-fPIC",
              "-I", ROOT / "include"]
    source = ROOT / "tests/cse-hardened"
    fixture = source / "descriptor_fixture.cpp"
    remote = "/data/local/tmp/ndkp-recheck-" + uuid.uuid4().hex
    adb = ["adb", "-s", args.serial]
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
    with (nullcontext(args.work_dir) if args.work_dir else tempfile.TemporaryDirectory()) as folder:
        out = Path(folder)
        if not args.compile_only:
            run(*adb, "shell", "mkdir", remote)
        try:
            run(clang, *common, "--driver-mode=g++", "-O2", "-static-libstdc++",
                "-Wall", "-Wextra", "-Werror", source / "recheck_loader.cpp", "-ldl", "-o", out / "loader")
            if not args.compile_only:
                run(*adb, "push", out / "loader", remote + "/loader")
                run(*adb, "shell", "chmod", "700", remote + "/loader")
            run(clang, *common, "-O2", "-fno-lto", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
                "-c", ROOT / "runtime/ndkp_cse_runtime.cpp", "-o", out / "runtime.o")

            def execute(data, phase="clean", address=0, protection=3, action="xor", expected=0):
                if args.compile_only:
                    return "compile-only (not executed)"
                (out / "test.so").write_bytes(data)
                run(*adb, "push", out / "test.so", remote + "/test.so")
                result = run(*adb, "shell", "timeout", "30", remote + "/loader", remote + "/test.so",
                             phase, f"{address:x}", protection, action, check=False)
                assert result.returncode == expected, (phase, hex(address), expected, result.returncode,
                                                       result.stdout, result.stderr)
                if expected == 127:
                    assert not result.stdout and not result.stderr, (result.stdout, result.stderr)
                return result.stdout.strip()

            def build(flags, opt="O2", runtime=True):
                run(clang, *common, "-" + opt, *flags, "-S", "-emit-llvm", fixture, "-o", out / "fixture.ll")
                ir = (out / "fixture.ll").read_text(encoding="utf-8")
                run(clang, *common, "-" + opt, *flags, "-c", fixture, "-o", out / "fixture.o")
                run(clang, *common, "--driver-mode=g++", "-shared", "-static-libstdc++",
                    "-Wl,--pack-dyn-relocs=none,--no-undefined", out / "fixture.o",
                    *([out / "runtime.o"] if runtime else []), "-ldl", "-o", out / "linked.so")
                data = (out / "linked.so").read_bytes()
                return (cse.process(data) if runtime else data), ir

            cse_flags = ["-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened"]
            plain, ir = build([], runtime=False)
            assert "ndkp_cse_module_recheck" not in ir and "ndkp_selfcheck_one" not in ir
            execute(plain)
            cached, ir = build([*cse_flags, "-DNDKP_TEST_NO_RECHECK"])
            assert "ndkp_cse_module_recheck" not in ir
            image, table, _, _, _, _ = descriptor_locations(cached)

            def virtual(image, offset):
                return next(va + offset - start for _, start, va, size, _ in image.loads
                            if start <= offset < start + size)

            # Existing behavior: late RX changes are invisible after all used strings were decoded.
            execute(cached, "warm", virtual(image, table), 5)
            for opt, mode in (("O0", ""), ("O2", ""), ("Oz", ""), ("O2", "full"), ("O2", "thin"), ("O2", "mixed"), ("O2", "vmp"), ("O2", "vmp-mixed")):
                flags = list(cse_flags)
                if mode.startswith("vmp"):
                    flags += ["-femulated-tls", "-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vm_functions=checkpoint",
                              "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry"]
                if "mixed" in mode:
                    for name in ("cie", "indgv", "icall", "fla", "indbr"):
                        flags += ["-mllvm", "-irobf-" + name]
                elif mode in ("full", "thin"):
                    flags += ["-flto=" + mode]
                data, ir = build(flags, opt)
                guard = re.search(r"define private void @ndkp_cse_module_recheck.*?^}", ir, re.M | re.S)
                assert guard and guard[0].count("load volatile") == 5
                assert "@ndkp_cse_recheck_module_v1" in guard[0]
                body = re.search(r"define [^\n]*@checkpoint\(.*?^}", ir, re.M | re.S)
                assert body and "@ndkp_cse_module_recheck()" in body[0]
                gate = re.search(r"define [^\n]*@[^\n(]*unused_gate[^\n(]*\(.*?^}", ir, re.M | re.S)
                assert gate and "@ndkp_cse_module_recheck()" in gate[0]
                caller = re.search(r"define [^\n]*@unchecked_caller\(.*?^}", ir, re.M | re.S)
                assert caller and ("mixed" in mode or "unused_gate" in caller[0])
                assert "call void @llvm.sideeffect" not in ir
                if mode.startswith("vmp"):
                    assert "@ndkp_selfcheck_one" in body[0]
                print(f"[ok] CSE {opt}/{mode or 'no-lto'}: {execute(data)}", flush=True)
                image, table, _, _, module, pointers = descriptor_locations(data)
                cache = pointers[1][1]
                payload, total = image.payloads()[0]
                blob = data[payload:payload + total]
                sentinel = list(cse.records(blob))[-1][1]
                symbols = run(base / f"bin/llvm-nm{ext}", "--defined-only", out / "linked.so").stdout
                native = re.search(r"^([0-9a-fA-F]+) [a-zA-Z] long_value$", symbols, re.M)
                assert native, symbols
                attacks = [("native-code", int(native[1], 16), 5, "xor"),
                           ("regions", virtual(image, table), 5, "xor"),
                           ("permissions", virtual(image, table), 5, "permissions"),
                           ("cache-hash", cache + 4, 3, "xor"),
                           ("cache-inputs", cache + 36, 3, "xor"),
                           ("cache-state", cache, 3, "state"),
                           ("sentinel", virtual(image, payload + sentinel + 32), 3, "xor")]
                for offset in (0, 8, 16, 24, 28):
                    attacks.append((f"module-{offset}", virtual(image, module + offset), 1, "xor"))
                for phase in ("cold", "warm"):
                    for name, address, protection, action in attacks:
                        # A zero-initialized cache hash/input is legitimately replaced on first use.
                        if phase == "cold" and name in ("cache-hash", "cache-inputs"):
                            continue
                        execute(data, phase, address, protection, action, 127)
                    # Calling an unannotated wrapper must not lose its pure checkpoint.
                    execute(data, phase + "-caller", int(native[1], 16), 5, expected=127)
                execute(data, "cached", virtual(image, table), 5)
                stripped = out / "stripped.so"
                stripped.write_bytes(data)
                run(base / f"bin/llvm-strip{ext}", "--strip-all", stripped)
                cse.process(stripped.read_bytes(), True)
                execute(stripped.read_bytes())
                evidence = ("IR, seal and strip only; runtime attacks skipped" if args.compile_only else
                            "cold/warm attacks, cached-access boundary, strip")
                print(f"[ok] CSE {opt}/{mode or 'no-lto'}: {evidence}", flush=True)

            # The existing VMP runtime uses local-exec TLS; DSOs use emulated TLS.
            vm_flags = ["-femulated-tls", "-DNDKP_TEST_NO_RECHECK", "-mllvm", "-irobf-vmp", "-mllvm",
                        "-irobf-vm_functions=checkpoint", "-mllvm", "-irobf-selfcheck"]
            for opt, mixed in (("O0", False), ("O2", False), ("O2", True)):
                for entry in (False, True):
                    flags = vm_flags + (["-mllvm", "-irobf-selfcheck-entry"] if entry else [])
                    if mixed:
                        for name in ("cie", "indgv", "icall", "fla", "indbr"):
                            flags += ["-mllvm", "-irobf-" + name]
                    data, ir = build(flags, opt, runtime=False)
                    body = re.search(r"define [^\n]*@checkpoint\(.*?^}", ir, re.M | re.S)
                    assert body and ("@ndkp_selfcheck_one" in body[0]) == entry
                    print(f"[ok] VMP {opt}/mixed={mixed}/entry={entry}: {execute(data)}", flush=True)
                    if not entry:
                        continue
                    symbols = run(base / f"bin/llvm-nm{ext}", "--defined-only", out / "linked.so").stdout
                    match = re.search(r"^([0-9a-fA-F]+) [a-zA-Z] gv_code_seg_checkpoint$", symbols, re.M)
                    assert match, symbols
                    address = int(match[1], 16)
                    for phase in ("cold", "warm"):
                        execute(data, phase, address, 3, expected=137)
                    image = cse.Elf(data)
                    offset = next(start + address - va for _, start, va, size, _ in image.loads
                                  if va <= address < va + size)
                    altered = bytearray(data)
                    altered[offset] ^= 1
                    execute(bytes(altered), expected=137)  # Constructor, before any VM call.
                    evidence = ("entry-check IR verified; runtime attacks skipped" if args.compile_only else
                                "constructor and cold/warm entry tampering rejected")
                    print(f"[ok] VMP {opt}/mixed={mixed}: {evidence}", flush=True)

            invalid = run(clang, *common, "-mllvm", "-irobf-selfcheck-entry", "-c", fixture,
                          "-o", out / "invalid.o", check=False)
            assert invalid.returncode and "requires -irobf-selfcheck and -irobf-vmp" in invalid.stderr
            empty = out / "empty.cpp"
            empty.write_text('#include "ndkp.h"\nNDKP_CSE_RECHECK int checkpoint() { return 1; }\n')
            run(clang, *common, *cse_flags, "-S", "-emit-llvm", empty, "-o", out / "empty.ll")
            assert "call void @ndkp_cse_module_recheck()" in (out / "empty.ll").read_text()
            print("[ok] prerequisite diagnostics; no flags preserve plain behavior", flush=True)
        finally:
            if not args.compile_only:
                run(*adb, "shell", "rm", "-rf", remote, check=False)


if __name__ == "__main__":
    main()
