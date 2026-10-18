"""Check VMP memory-operation lowering and differential arm64 semantics."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
    if result.returncode or "Skipping VMP protection" in result.stderr:
        raise RuntimeError(f"{args}\n{result.stdout}{result.stderr}")
    return result.stdout


def function(ir, name):
    match = re.search(r"^define [^\n]*@" + re.escape(name) + r"\([^\n]*\n(.*?)^}", ir, re.M | re.S)
    assert match, name
    return match[1]


def check_rejection(clang, common, out):
    source = '''declare i32 @memcmp(ptr, ptr, i64)
declare i32 @__gxx_personality_v0(...)
define i32 @rejected_eh(ptr %a, ptr %b) personality ptr @__gxx_personality_v0 {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 16)
  ret i32 %r
}
define <2 x i32> @rejected_vector(ptr %a, ptr %b, <2 x i32> %x) {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 16)
  %v = insertelement <2 x i32> %x, i32 %r, i32 0
  ret <2 x i32> %v
}
'''
    input_path = out / "rejected.ll"
    input_path.write_text(source)
    flags = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vm_functions=rejected_eh;rejected_vector"]
    outputs = []
    for extra in ([], ["-mllvm", "-irobf-vmp-memops"]):
        result = subprocess.run([str(a) for a in (clang, *common, "-O0", *flags, *extra,
                                "-S", "-emit-llvm", input_path, "-o", out / "rejected-out.ll")],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        assert result.returncode == 0, result.stderr
        assert "has a personality function" in result.stderr and "Unsupported instruction" in result.stderr
        outputs.append((out / "rejected-out.ll").read_text())
    for name in ("rejected_eh", "rejected_vector"):
        assert function(outputs[0], name) == function(outputs[1], name), name
        assert "@memcmp(" in function(outputs[1], name), name
    assert "ndkp_vmp_memops_" not in outputs[1] and "gv_code_seg_" not in outputs[1]

    # The input fits the translation limit, but 200 expanded comparisons do not.
    body = ["declare i32 @memcmp(ptr, ptr, i64)", "define i32 @too_large(ptr %a, ptr %b) {"]
    previous = "0"
    for i in range(200):
        body += [f"%r{i} = call i32 @memcmp(ptr %a, ptr %b, i64 64)",
                 f"%s{i} = add i32 {previous}, %r{i}"]
        previous = f"%s{i}"
    body += [f"ret i32 {previous}", "}"]
    input_path.write_text("\n".join(body))
    result = subprocess.run([str(a) for a in (clang, *common, "-O0", "-mllvm", "-irobf-vmp",
                            "-mllvm", "-irobf-vmp-memops", "-mllvm", "-irobf-vm_functions=too_large",
                            "-S", "-emit-llvm", input_path, "-o", out / "too-large-out.ll")],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    assert result.returncode != 0, "expanded but unprotected function was accepted"
    assert "VMP: translation failed after memory-operation lowering" in result.stderr, result.stderr
    print("[ok] rejected functions unchanged; late translation failure rejects compilation", flush=True)


def check_boundaries(clang, common, out):
    source = '''declare i32 @memcmp(ptr, ptr, i64)
declare ptr @memcpy(ptr, ptr, i64)
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)
define i32 @small(ptr %a, ptr %b) {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 64)
  ret i32 %r
}
define i32 @dynamic(ptr %a, ptr %b, i64 %n) {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 %n)
  ret i32 %r
}
define ptr @large(ptr %a, ptr %b) {
  %r = call ptr @memcpy(ptr %a, ptr %b, i64 65)
  ret ptr %r
}
define i32 @no_builtin(ptr %a, ptr %b) {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 16) nobuiltin
  ret i32 %r
}
define void @volatile_copy(ptr %a, ptr %b) {
  call void @llvm.memcpy.p0.p0.i64(ptr %a, ptr %b, i64 16, i1 true)
  ret void
}
define i32 @unselected(ptr %a, ptr %b) {
  %r = call i32 @memcmp(ptr %a, ptr %b, i64 16)
  ret i32 %r
}
'''
    (out / "boundaries.ll").write_text(source)
    flags = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-memops", "-mllvm",
             "-irobf-vm_functions=small;dynamic;large;no_builtin;volatile_copy"]
    run(clang, *common, "-O0", *flags, "-S", "-emit-llvm", out / "boundaries.ll", "-o", out / "checked.ll")
    ir = (out / "checked.ll").read_text()
    assert "@ndkp_vmp_memops_small_cmp1_copy0" in ir
    for name in ("dynamic", "large", "no_builtin", "volatile_copy", "unselected"):
        assert "@ndkp_vmp_memops_" + name not in ir, name
    assert "@memcmp(" in function(ir, "unselected")
    # A same-named application function is not a libc builtin.
    custom = source.replace("declare i32 @memcmp(ptr, ptr, i64)",
                            "define i32 @memcmp(ptr %a, ptr %b, i64 %n) { ret i32 123 }")
    (out / "custom.ll").write_text(custom)
    run(clang, *common, "-O0", *flags, "-S", "-emit-llvm", out / "custom.ll", "-o", out / "checked.ll")
    assert "@ndkp_vmp_memops_small_" not in (out / "checked.ll").read_text()
    run(clang, *common, "-O0", *flags, "-mllvm", "-irobf-vmp-memops=false", "-S", "-emit-llvm",
        out / "boundaries.ll", "-o", out / "checked.ll")
    assert "@ndkp_vmp_memops_" not in (out / "checked.ll").read_text()
    print("[ok] 64-byte boundary, dynamic/large/volatile/nobuiltin/custom/unselected and opt-out", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / ("bin/clang.exe" if os.name == "nt" else "bin/clang")
    resource = max((base / "lib/clang").iterdir(), key=lambda p: int(p.name))
    common = ["--target=aarch64-linux-android26", f"--sysroot={base / 'sysroot'}",
              "-resource-dir", resource, f"-B{base / 'bin'}", "-fno-vectorize", "-fno-slp-vectorize"]
    flags = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-memops", "-mllvm",
             "-irobf-vm_functions=compare_block;copy_block;compare_lengths;copy_lengths",
             "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry"]
    source = Path(__file__).parent
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/ndkp-memory-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        try:
            check_rejection(clang, common, out)
            check_boundaries(clang, common, out)
            for opt in ("-O0", "-O2"):
                run(clang, *common, opt, "-DREFERENCE", "-c", source / "memory_ops.c", "-o", out / "reference.o")
                run(clang, *common, opt, "-c", source / "memory_ops_driver.c", "-o", out / "driver.o")
                run(clang, *common, opt, *flags, "-S", "-emit-llvm", source / "memory_ops.c", "-o", out / "protected.ll")
                ir = (out / "protected.ll").read_text()
                for name in ("compare_block", "copy_block", "compare_lengths", "copy_lengths"):
                    assert "@gv_code_seg_" + name in ir, name
                    assert "@ndkp_selfcheck_one" in function(ir, name), name
                for name in ("compare_block", "copy_block"):
                    handler = function(ir, "vm_interpreter_callinst_dispatch_" + name)
                    assert not re.search(r"@(?:memcmp|memcpy|llvm\.memcpy)[.(]", handler), handler
                if opt == "-O0":
                    assert "@ndkp_vmp_memops_compare_block_cmp1_copy0" in ir
                    assert "@ndkp_vmp_memops_copy_block_cmp0_copy1" in ir
                # The new option alone must not select or transform functions.
                run(clang, *common, opt, "-mllvm", "-irobf-vmp-memops", "-S", "-emit-llvm",
                    source / "memory_ops.c", "-o", out / "plain.ll")
                plain = (out / "plain.ll").read_text()
                assert "ndkp_vmp_memops_" not in plain and "gv_code_seg_" not in plain
                run(clang, *common, "-c", out / "protected.ll", "-o", out / "protected.o")
                run(clang, *common, "--driver-mode=g++", "-static-libstdc++", out / "protected.o",
                    out / "reference.o", out / "driver.o", "-o", out / "test")
                if args.serial:
                    run(*adb, "push", out / "test", remote)
                    run(*adb, "shell", "chmod", "700", remote)
                    assert "VMP memory operations OK" in run(*adb, "shell", "timeout", "90", remote)
                print(f"[ok] {opt}: VMP memory operations, {'device semantics' if args.serial else 'compile only'}", flush=True)
        finally:
            if args.serial:
                run(*adb, "shell", "rm", "-f", remote)


if __name__ == "__main__":
    main()
