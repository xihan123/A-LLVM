"""Compile-only regression for LLVM 21 VMP strict mode and protection receipts."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--ndk", required=True, type=Path)
    args = parser.parse_args()
    import os
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk / "toolchains/llvm/prebuilt" / host
    resource = next((base / "lib/clang").glob("21*"))
    root = Path(__file__).resolve().parents[2]
    (root / "work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vmp-strict-", dir=root / "work") as directory:
        out = Path(directory)
        source = out / "input.ll"
        target = out / "output.ll"
        source.write_text('''declare i32 @__gxx_personality_v0(...)
define i32 @good(i32 %x) {
  %r = add i32 %x, 17
  ret i32 %r
}
define i32 @bad(i32 %x) personality ptr @__gxx_personality_v0 {
  ret i32 %x
}
define i64 @wide(i128 %x) {
  %r = trunc i128 %x to i64
  ret i64 %r
}
define i32 @narrow(i24 %x) {
  %r = sext i24 %x to i32
  ret i32 %r
}
''')
        common = [str(args.clang), "--target=aarch64-linux-android26",
                  "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource),
                  "-O0", "-S", "-emit-llvm", str(source), "-o", str(target)]

        def compile(*flags):
            return subprocess.run(common + list(flags), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=180)

        normal = compile()
        assert normal.returncode == 0, normal.stderr
        assert "ndkp.vmp.protected" not in target.read_text()
        flags = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vm_functions=bad"]
        compatible = compile(*flags)
        assert compatible.returncode == 0, compatible.stderr
        assert "ndkp.vmp.protected" not in target.read_text()
        rejected = compile(*flags, "-mllvm", "-irobf-vmp-strict")
        assert rejected.returncode != 0 and "VMP strict: bad" in rejected.stderr, rejected.stderr
        missing_flag = compile("-mllvm", "-irobf-vmp-strict")
        assert missing_flag.returncode != 0 and "requires -irobf-vmp" in missing_flag.stderr, missing_flag.stderr
        accepted = compile("-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict",
                           "-mllvm", "-irobf-vm_functions=good")
        assert accepted.returncode == 0, accepted.stderr
        ir = target.read_text()
        assert re.search(r"^define .*@good\(.*!ndkp.vmp.protected !\d+", ir, re.M), ir[:1000]
        assert "@gv_code_seg_good" in ir and "ptr @vm_interpreter_good" in ir
        absent = compile("-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict",
                         "-mllvm", "-irobf-vm_functions=misspelled")
        assert absent.returncode != 0 and "missing or excluded: misspelled" in absent.stderr, absent.stderr
        for name in ("wide", "narrow"):
            unsupported = compile("-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict",
                                  "-mllvm", "-irobf-vm_functions=" + name)
            assert unsupported.returncode != 0 and "VMP strict: " + name in unsupported.stderr, unsupported.stderr
        print("[ok] strict rejection, compatibility, no-flags behavior, bytecode and receipt")


if __name__ == "__main__":
    main()
