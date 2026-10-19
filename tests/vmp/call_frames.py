"""VMP caller-owned storage: pointer outputs, reentry, sret and unwind semantics."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import re
import tempfile
import uuid

from memory_ops import function, run

FUNCTIONS = ("frame_write", "frame_local", "frame_direct", "frame_vm", "frame_external",
             "frame_pointer", "frame_alias", "frame_recursive", "frame_reentrant",
             "frame_make", "frame_sret", "frame_catch", "frame_escape")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--semantic-only", action="store_true",
                        help="Skip new IR assertions when demonstrating old-compiler failure")
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / ("bin/clang.exe" if os.name == "nt" else "bin/clang")
    resource = max((base / "lib/clang").iterdir(), key=lambda p: int(p.name))
    common = ["--target=aarch64-linux-android26", f"--sysroot={base / 'sysroot'}",
              "-resource-dir", resource, f"-B{base / 'bin'}", "-std=c++17",
              "-fno-vectorize", "-fno-slp-vectorize", "-fno-optimize-sibling-calls",
              "-fno-builtin-malloc"]
    vmp = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vm_functions=" + ";".join(FUNCTIONS)]
    entry = [*vmp, "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry"]
    source = Path(__file__).parent
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/ndkp-frames-" + uuid.uuid4().hex
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
    with (nullcontext(args.work_dir) if args.work_dir else tempfile.TemporaryDirectory()) as folder:
        out = Path(folder)
        try:
            for opt in ("-O0", "-O2"):
                suffix = opt[1:]
                run(clang, *common, opt, "-DREFERENCE", "-c", source / "call_frames.cpp", "-o", out / "reference.o")
                run(clang, *common, opt, "-c", source / "call_frames_driver.cpp", "-o", out / "driver.o")
                for mode, flags in (("plain", []), ("vmp", vmp), ("protected", entry)):
                    ir_path = out / f"{mode}-{suffix}.ll"
                    run(clang, *common, opt, *flags,
                        "-S", "-emit-llvm", source / "call_frames.cpp", "-o", ir_path)
                    ir = ir_path.read_text()
                    if flags:
                        for name in FUNCTIONS:
                            assert "@gv_code_seg_" + name in ir, name
                            if mode == "protected":
                                assert "@ndkp_selfcheck_one" in function(ir, name), name
                            if not args.semantic_only:
                                assert re.search(r"@gv_data_seg_" + name + r" = .*global ptr null", ir), name
                                handler = function(ir, "vm_interpreter_callinst_dispatch_" + name)
                                assert "@malloc(" not in handler and "@free(" not in handler, name
                                if opt == "-O0":
                                    assert "switch i64" in handler, name
                                    assert "@gv_data_seg_" not in handler.split("switch i64", 1)[0], name
                        for caller, callee in (("frame_vm", "frame_write"), ("frame_sret", "frame_make"),
                                               ("frame_recursive", "frame_recursive")):
                            handler = function(ir, "vm_interpreter_callinst_dispatch_" + caller)
                            assert "@" + callee + "(" in handler, (caller, callee)
                    else:
                        assert "@gv_code_seg_" not in ir and "@gv_data_seg_" not in ir
                    run(clang, *common, "-c", ir_path, "-o", out / "case.o")
                    binary = out / f"{mode}-{suffix}"
                    run(clang, *common, "--driver-mode=g++", "-static-libstdc++",
                        "-Wl,--wrap=malloc", out / "case.o", out / "reference.o", out / "driver.o", "-o", binary)
                    if args.serial:
                        run(*adb, "push", binary, remote)
                        run(*adb, "shell", "chmod", "700", remote)
                        result = run(*adb, "shell", "timeout", "90", remote)
                        assert "VMP call frames OK" in result, result
                    print(f"[ok] {mode}/{opt}: call frames, {'device semantics' if args.serial else 'compile only'}", flush=True)
        finally:
            if args.serial:
                run(*adb, "shell", "rm", "-f", remote)


if __name__ == "__main__":
    main()
