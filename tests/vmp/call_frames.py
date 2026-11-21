"""VMP caller-owned storage: pointer outputs, reentry, sret and unwind semantics."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from memory_ops import function, run

FUNCTIONS = ("frame_write", "frame_local", "frame_direct", "frame_vm", "frame_external",
             "frame_pointer", "frame_alias", "frame_recursive", "frame_reentrant",
             "frame_make", "frame_sret", "frame_catch", "frame_escape")


def observe_frames(ir, semantic_only):
    stacks = re.findall(r"^(@_ZL13vm_call_stack(?:\.\d+)?) = .*thread_local .*global "
                        r"\[(\d+) x (%struct\.vm_call_frame_t(?:\.\d+)?)\]", ir, re.M)
    tops = re.findall(r"^(@_ZL17vm_call_stack_top(?:\.\d+)?) = .*thread_local .*global i32", ir, re.M)
    assert len(stacks) == len(tops) == 1, "expected one actual interpreter TLS call stack"
    stack, capacity, frame_type = stacks[0]
    top = tops[0]
    assert int(capacity) >= 3
    for helper in ("_ZL18vm_push_call_framev", "_ZL21vm_restore_call_framev"):
        body = function(ir, helper)
        assert stack in body and top in body, helper
    if not semantic_only:
        assert "store volatile i8 0" in body, "retired frame wipe missing"
    # Add observers after post so the tested protection and SelfCheck stay intact.
    return ir + f'''
define hidden ptr @ndkp_test_frame_stack() {{
  %address = call ptr @llvm.threadlocal.address.p0(ptr {stack})
  ret ptr %address
}}
define hidden i32 @ndkp_test_frame_top() {{
  %address = call ptr @llvm.threadlocal.address.p0(ptr {top})
  %value = load volatile i32, ptr %address, align 4
  ret i32 %value
}}
define hidden i64 @ndkp_test_frame_stride() {{
  %end = getelementptr {frame_type}, ptr null, i64 1
  %size = ptrtoint ptr %end to i64
  ret i64 %size
}}
define hidden i64 @ndkp_test_frame_padding_end() {{
  %end = getelementptr {frame_type}, ptr null, i64 0, i32 1
  %offset = ptrtoint ptr %end to i64
  ret i64 %offset
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--semantic-only", action="store_true",
                        help="Skip new IR assertions; still observe retired bytes on old compilers")
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / ("bin/clang.exe" if os.name == "nt" else "bin/clang")
    clang_major = int(run(clang, "-dumpversion").split(".", 1)[0])
    observe_wipe = clang_major == 21
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
                reference = out / f"reference-{suffix}.o"
                run(clang, *common, opt, "-DREFERENCE", "-c", source / "call_frames.cpp", "-o", reference)
                for observed in ((False, True) if observe_wipe else (False,)):
                    driver = out / f"driver-{suffix}{'-observed' if observed else ''}.o"
                    run(clang, *common, opt, *(["-DNDKP_OBSERVE_FRAMES"] if observed else []),
                        "-c", source / "call_frames_driver.cpp", "-o", driver)
                for mode, flags in (("plain", []), ("vmp", vmp), ("protected", entry)):
                    observed = bool(flags) and observe_wipe
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
                                if opt == "-O0" and clang_major == 21:
                                    assert "switch i64" in handler, name
                                    assert "@gv_data_seg_" not in handler.split("switch i64", 1)[0], name
                        for caller, callee in (("frame_vm", "frame_write"), ("frame_sret", "frame_make"),
                                               ("frame_recursive", "frame_recursive")):
                            handler = function(ir, "vm_interpreter_callinst_dispatch_" + caller)
                            assert "@" + callee + "(" in handler, (caller, callee)
                    else:
                        assert "@gv_code_seg_" not in ir and "@gv_data_seg_" not in ir
                    post = observe_wipe and mode == "protected" and opt == "-O2"
                    if post:
                        post_path = out / f"{mode}-{suffix}.post.ll"
                        run(clang, *common, "-Oz", "-mllvm", "-irobf-vmp-post",
                            "-S", "-emit-llvm", ir_path, "-o", post_path)
                        ir = post_path.read_text()
                        assert "!ndkp.vmp.post" in ir
                    if observed:
                        ir_path = out / f"{mode}-{suffix}.observed.ll"
                        ir_path.write_text(observe_frames(ir, args.semantic_only))
                    case = out / f"{mode}-{suffix}.o"
                    backend = ["-Oz", "-Xclang", "-disable-llvm-passes"] if observe_wipe else []
                    run(clang, *common, *backend, "-c", ir_path, "-o", case)
                    binary = out / f"{mode}-{suffix}"
                    driver = out / f"driver-{suffix}{'-observed' if observed else ''}.o"
                    run(clang, *common, "--driver-mode=g++", "-static-libstdc++",
                        "-Wl,--wrap=malloc", case, reference, driver, "-o", binary)
                    if args.serial:
                        run(*adb, "push", binary, remote)
                        run(*adb, "shell", "chmod", "700", remote)
                        result = subprocess.run([*adb, "shell", "timeout", "90", remote],
                                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
                        log = out / f"{mode}-{suffix}.device.log"
                        log.write_text(f"exit_code={result.returncode}\n{result.stdout}{result.stderr}", encoding="utf-8")
                        assert result.returncode == 0 and "VMP call frames OK" in result.stdout, log.read_text()
                        if observed:
                            assert "VMP retired frames OK" in result.stdout, log.read_text()
                    chain = "+post" if post else ""
                    print(f"[ok] {mode}/{opt}{chain}: call frames, {'device semantics' if args.serial else 'compile only'}", flush=True)
        finally:
            if args.serial:
                run(*adb, "shell", "rm", "-f", remote)


if __name__ == "__main__":
    main()
