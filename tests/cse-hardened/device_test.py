"""Build, seal and exercise CSE on an Android arm64 device (no APK required)."""
import argparse
from contextlib import nullcontext
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import seal_cse as cse


def run(*args, check=True):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            errors="replace", timeout=180)
    if check and result.returncode:
        raise RuntimeError(f"{args}\n{result.stdout}\n{result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--compile-only", action="store_true", help="cross-build and verify ELF artifacts without adb")
    parser.add_argument("--work-dir", type=Path, help="retain local artifacts for inspection")
    args = parser.parse_args()
    if not args.compile_only and not args.serial:
        parser.error("--serial is required unless --compile-only is used")
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    ext = ".exe" if os.name == "nt" else ""
    prebuilt = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else prebuilt / f"bin/clang{ext}"
    resource = max((prebuilt / "lib/clang").iterdir(), key=lambda p: int(p.name))
    common = ["--target=aarch64-linux-android21", f"--sysroot={prebuilt / 'sysroot'}",
              "-resource-dir", resource, f"-B{prebuilt / 'bin'}", "-std=c++17", "-fPIC"]
    adb = ["adb", "-s", args.serial]
    def device(*parts, **kwargs):
        if args.compile_only:
            return subprocess.CompletedProcess([], 0, "", "")
        return run(*adb, *parts, **kwargs)
    remote = "/data/local/tmp/ndkp-cse-" + uuid.uuid4().hex
    source = ROOT / "tests/cse-hardened"
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
    with (nullcontext(args.work_dir) if args.work_dir else tempfile.TemporaryDirectory(prefix="ndkp-cse-")) as tmp:
        out = Path(tmp)
        device("shell", "mkdir", remote)
        try:
            run(clang, *common, "--driver-mode=g++", "-O2", "-static-libstdc++",
                source / "loader.cpp", "-ldl", "-o", out / "loader")
            device("push", out / "loader", remote + "/loader")
            device("shell", "chmod", "700", remote + "/loader")
            run(clang, *common, "-O2", "-fno-lto", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
                "-c", ROOT / "runtime/ndkp_cse_runtime.cpp", "-o", out / "runtime.o")
            run(clang, *common, "--driver-mode=g++", "-O2", "-static-libstdc++", "-I", ROOT / "runtime",
                source / "crypto_test.cpp", "-o", out / "crypto")
            device("push", out / "crypto", remote + "/crypto")
            device("shell", "chmod", "700", remote + "/crypto")
            print(device("shell", remote + "/crypto").stdout.strip(), flush=True)
            run(clang, *common, "--driver-mode=g++", "-O2", "-static-libstdc++", "-I", ROOT / "runtime",
                source / "io_test.cpp", "-o", out / "io-test")
            device("push", out / "io-test", remote + "/io-test")
            device("shell", "chmod", "700", remote + "/io-test")
            print(device("shell", remote + "/io-test").stdout.strip(), flush=True)
            run(clang, *common, "-O2", "-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened",
                "-S", "-emit-llvm", source / "fixture.cpp", "-o", out / "fixture.ll")
            ir = (out / "fixture.ll").read_text(encoding="utf-8")
            capacities = re.findall(r"call void @ndkp_cse_decode_v1\(ptr [^,]+, i32 (\d+),", ir)
            if not capacities or any(int(n) + 16 < 32 or (int(n) + 16) & (int(n) + 15) for n in capacities):
                raise RuntimeError("decoder exposes actual length instead of bucket capacity")

            def execute(path, success, name=None):
                if args.compile_only:
                    return "compile-only"
                device("push", path, remote + "/test.so")
                command = [remote + "/loader", remote + "/test.so"]
                if name:
                    command = ["exec", "-a", name, *command]
                result = device("shell", *command, check=False)
                if success and (result.returncode or "result=0" not in result.stdout):
                    raise RuntimeError(f"expected success: {result.stdout} {result.stderr}")
                if not success and (result.returncode != 127 or "CSE validation failed" not in result.stderr + result.stdout):
                    raise RuntimeError(f"expected controlled rejection: {result.returncode}: {result.stdout} {result.stderr}")
                return result.stdout.strip()

            for name in ("fixture", "other"):
                run(clang, *common, "-O2", "-c", source / f"{name}.cpp", "-o", out / f"{name}.o")
            run(clang, *common, "--driver-mode=g++", "-static-libstdc++", "-shared", "-Wl,--gc-sections,--no-undefined",
                out / "fixture.o", out / "other.o", "-ldl", "-o", out / "plain.so")
            print(f"[baseline] size={(out / 'plain.so').stat().st_size} {execute(out / 'plain.so', True)}", flush=True)

            for optimization, lto in (("O0", ""), ("O2", ""), ("Oz", ""), ("O2", "full"), ("O2", "thin")):
                flags = ["-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened"]
                if lto:
                    flags += [f"-flto={lto}"]
                for name in ("fixture", "other"):
                    run(clang, *common, f"-{optimization}", *flags, "-c", source / f"{name}.cpp", "-o", out / f"{name}.o")
                link = [clang, *common, "--driver-mode=g++", "-static-libstdc++", "-shared", "-Wl,--gc-sections,--no-undefined",
                        out / "fixture.o", out / "other.o", out / "runtime.o", "-ldl", "-o", out / "linked.so"]
                run(*link)
                original = (out / "linked.so").read_bytes()
                execute(out / "linked.so", False)
                sealed = cse.process(original)
                cse.process(sealed, True)
                (out / "sealed.so").write_bytes(sealed)
                stats = execute(out / "sealed.so", True)
                run(prebuilt / f"bin/llvm-strip{ext}", "--strip-all", out / "sealed.so")
                cse.process((out / "sealed.so").read_bytes(), True)
                execute(out / "sealed.so", True)
                assert b"NDKP_HARDENED_secret_19a7" not in sealed
                image = cse.Elf(sealed)
                for va, size, offset in image.executable:
                    modified = bytearray(sealed)
                    modified[offset + size - 1] ^= 1
                    (out / "tampered.so").write_bytes(modified)
                    execute(out / "tampered.so", False)
                used = []
                for p, total in image.payloads():
                    blob = sealed[p:p + total]
                    key = cse.derive(blob, image.code_hash(), bytes(48))
                    for ordinal, r, capacity in cse.records(blob):
                        text = cse.decrypt(key, blob[r + 4:r + 16], cse.record_aad(blob, ordinal, capacity),
                                           blob[r + 32:r + 32 + capacity], blob[r + 16:r + 32])
                        if b"NDKP_HARDENED_secret_19a7" in text:
                            used = [p + 72, p + r + 16]
                if not used:
                    raise RuntimeError("fixture secret was optimized away")
                for offset in used:
                    modified = bytearray(sealed)
                    modified[offset] ^= 1
                    (out / "tampered.so").write_bytes(modified)
                    execute(out / "tampered.so", False)
                checks = "ELF authentication and strip" if args.compile_only else "strip, unsealed and tamper checks"
                print(f"[ok] {optimization}/{lto or 'no-lto'} size={len(sealed)} {stats}; {checks}", flush=True)

            # Actual package identity, private-process normalization and a hostile libc read.
            package = "com.ndkp.cse.fixture"
            for name in ("fixture", "other"):
                run(clang, *common, "-O2", "-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened",
                    "-mllvm", "-irobf-cse-bind", "-mllvm", f"-irobf-cse-bind-package={package}",
                    "-c", source / f"{name}.cpp", "-o", out / f"{name}.o")
            run(*link)
            bound = cse.process((out / "linked.so").read_bytes())
            cse.process(bound, True, package)
            (out / "bound.so").write_bytes(bound)
            execute(out / "bound.so", True, package)
            execute(out / "bound.so", True, package + ":worker")
            execute(out / "bound.so", False, "wrong.package")
            poison = out / "poison.cpp"
            poison.write_text('''#include <unistd.h>
#include <fcntl.h>
#include <cstring>
static int target = -1;
extern "C" int __real_open(const char*, int, ...);
extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" int __wrap_open(const char* path, int flags, ...) {
  int fd = __real_open(path, flags);
  if (!std::strcmp(path, "/proc/self/cmdline")) target = fd;
  return fd;
}
extern "C" ssize_t __wrap_read(int fd, void* data, size_t size) {
  if (fd == target && size >= 6) { std::memcpy(data, "fake!", 6); return 6; }
  return __real_read(fd, data, size);
}
''', encoding="utf-8")
            run(clang, *common, "-O2", "-c", poison, "-o", out / "poison.o")
            run(*link, out / "poison.o", "-Wl,--wrap=open,--wrap=read")
            (out / "poisoned.so").write_bytes(cse.process((out / "linked.so").read_bytes()))
            execute(out / "poisoned.so", False, package)
            print("[ok] package binding and hostile-hook fixture compiled" if args.compile_only else
                  "[ok] package, private process, wrong package and libc input forgery", flush=True)

            for target, flags in (("aarch64-linux-android21", ["-mllvm", "-irobf-cse-hardened"]),
                                  ("x86_64-linux-android21", ["-mllvm", "-irobf-cse-hardened", "-mllvm", "-irobf-cse"])):
                rejected = run(clang, *common, f"--target={target}", *flags, "-c", source / "other.cpp", "-o", out / "invalid.o", check=False)
                if rejected.returncode == 0 or "requires" not in rejected.stderr:
                    raise RuntimeError("invalid hardened mode was not diagnosed")
            print("[ok] unsupported ABI and missing CSE diagnostics", flush=True)
        finally:
            device("shell", "rm", "-rf", remote, check=False)


if __name__ == "__main__":
    main()
