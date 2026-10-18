"""Check raw response IR and register constraints on all four Android ABIs."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--host", default="windows-x86_64" if os.name == "nt" else "linux-x86_64")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / args.host
    clang = args.clang.resolve() if args.clang else base / ("bin/clang.exe" if os.name == "nt" else "bin/clang")
    resources = next((base / "lib/clang").iterdir())
    with tempfile.TemporaryDirectory(prefix="ndkp-raw-codegen-") as folder:
        out = Path(folder)
        source = out / "probe.c"
        source.write_text('int main(void) { return 0; }\n')
        for target in ("aarch64-linux-android26", "armv7a-linux-androideabi26",
                       "i686-linux-android26", "x86_64-linux-android26"):
            for opt in ("-O0", "-O2"):
                flags = [str(clang), "--target=" + target, "--sysroot=" + str(base / "sysroot"),
                         "-resource-dir", str(resources), opt, "-fPIC", "-fno-omit-frame-pointer",
                         "-mllvm", "-irobf-rootdetect", "-mllvm", "-irobf-debug"]
                subprocess.run([*flags, "-S", "-emit-llvm", str(source), "-o", str(out / "probe.ll")], check=True)
                ir = (out / "probe.ll").read_text()
                report = re.search(r"define internal void @detect_report_and_kill.*?^}", ir, re.M | re.S)
                assert report and " asm " in report[0]
                assert not re.search(r"call.*@(getpid|kill|syscall|write|abort|exit)\(", report[0])
                subprocess.run([*flags, "-c", str(source), "-o", str(out / "probe.o")], check=True)
                # Also compile the native interpreter's raw helper with a frame pointer.
                native = out / "native.c"
                native.write_text('#include "raw_syscall.h"\nvoid finish(void) { ndkp_raw_terminate(); }\n')
                subprocess.run([*flags[:8], "-I", str(root / "runtime"), "-c", str(native),
                                "-o", str(out / "native.o")], check=True)
                print(f"[ok] {target} {opt}: raw IR and object", flush=True)


if __name__ == "__main__":
    main()
