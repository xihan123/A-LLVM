"""Exercise native VMP post protection and its fail-closed receipts (LLVM 21)."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk / "toolchains/llvm/prebuilt" / host
    root = Path(__file__).resolve().parents[2]
    (root / "work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vmp-post-", dir=root / "work") as directory:
        out = Path(directory)
        source, raw, final = (out / n for n in ("source.c", "raw.ll", "post.ll"))
        source.write_text('''
__attribute__((noinline)) int ordinary(int x) { return x ? 101 : 31; }
__attribute__((annotate("vmp"))) int protected(int x) {
  switch(x) { case 3: return ordinary(x)+73; case 11: return 45;
    case 91: return 113; default: return x < 0 ? -x : x+9; }
}
''')
        common = [str(args.clang), "--target=aarch64-linux-android26",
                  "--sysroot=" + str(base / "sysroot"),
                  "-resource-dir=" + str(base / "lib/clang/21"), "-S", "-emit-llvm"]

        def compile(input_path, output_path, *flags, error=None):
            result = subprocess.run(common + [str(input_path), "-o", str(output_path), *flags],
                                    capture_output=True, text=True, timeout=180)
            if error:
                assert result.returncode and error in result.stderr, result.stderr
            else:
                assert result.returncode == 0, result.stderr

        post = ["-Oz", "-mllvm", "-irobf-vmp-post"]
        compile(source, final, *post, error="requires VMP protection receipts")
        compile(source, raw, "-O1", "-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict")
        original = raw.read_text()
        assert "ndkp.vmp.protected" in original and "ndkp.vmp.post" not in original
        # Each private interpreter resolves TLS locations once, while reads and
        # writes remain live across recursive/native callbacks.
        for header, body in re.findall(r"^(define [^\n]+)\n([\s\S]*?)^}", original, re.M):
            if "@vm_interpreter_" not in header or "callinst_dispatch" in header:
                continue
            addresses = re.findall(r"call ptr @llvm.threadlocal.address.p0\(ptr (@[^)]+)\)", body)
            assert addresses and len(addresses) == len(set(addresses)), header
            for address in addresses:
                uses = [line for line in body.splitlines() if re.search(re.escape(address) + r"(?=[, )])", line)]
                assert len(uses) == 1 and "@llvm.threadlocal.address" in uses[0], (header, address, uses)
        # The binding marker may be on a later XOR than the literal key operand.
        original += '''
define hidden i64 @entry_key_probe(i64 %x) "aproc-vmp-artifact" {
  %key = xor i64 %x, 12345678901234567
  ret i64 %key
}
'''
        raw.write_text(original)
        compile(raw, final, *post, "-mllvm", "-irobf-vmp", error="without -irobf-vmp")
        compile(raw, final, *post)
        hardened = final.read_text()
        code = r'^@gv_code_seg_\w+ = .*? c"([^"\n]+)"'
        assert re.findall(code, original, re.M) == re.findall(code, hardened, re.M)
        counts = []
        for header, body in re.findall(r"^(define [^\n]+)\n([\s\S]*?)^}", hardened, re.M):
            target = '@protected(' in header or '@entry_key_probe(' in header or 'section ".s0"' in header
            marker = re.search(r"!ndkp.vmp.post !(\d+)", header)
            if not target:
                assert not marker, header
                continue
            assert marker, header
            assert not re.search(r"^\s*(switch\s|br\s+i1\s)", body, re.M), header
            receipt = re.search(r'^!' + marker[1] + r' = !\{i32 (\d+), i32 (\d+)}', hardened, re.M)
            count = len(re.findall(r"^\s*indirectbr ", body, re.M))
            assert receipt and int(receipt[1]) == int(receipt[2]) == count, header
            counts.append(count)
        assert len(counts) > 2 and sum(counts) > 50, counts
        probe = re.search(r'^define .*@entry_key_probe\([^\n]*\n([\s\S]*?)^}', hardened, re.M)[1]
        assert '12345678901234567' not in probe and 'load volatile i64' in probe
        assert ".post.targets" in hardened and "dso_local_equivalent" in hardened
        # Global blockaddresses must use names: printing an unnamed target
        # rebuilds the giant function's SlotTracker once per table element.
        addresses = re.findall(r'blockaddress\(@[^,]+, %([^)]*)\)', hardened)
        assert addresses and all(not name.isdigit() for name in addresses), addresses[:5]
        # The relative label expressions must survive the real ELF backend too.
        result = subprocess.run(common[:-2] + ["-Oz", "-Xclang", "-disable-llvm-passes",
                                "-c", str(final), "-o", str(out / "post.o")],
                                capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stderr
        assert (out / "post.o").read_bytes().startswith(b"\x7fELF")
        compile(final, out / "twice.ll", *post, error="cannot be applied twice")
        # A no-flags compile must still leave ordinary source unprotected.
        compile(source, out / "plain.ll", "-O1")
        assert "ndkp.vmp.post" not in (out / "plain.ll").read_text()
        print(f"[ok] {len(counts)} native targets, {sum(counts)} indirect branches; bytecode unchanged; strict rejection and opt-in isolation")


if __name__ == "__main__":
    main()
