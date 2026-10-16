import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH = os.environ.get("BASH", "bash")


class GenerateBitcodeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vm bitcode test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/gen_vm_bitcode.sh",
                        self.root / "scripts/gen_vm_bitcode.sh")
        self.headers = {}
        for major in (20, 21):
            header = self.root / f"obfuscation/llvm-{major}/include/aVMP/vm.h"
            header.parent.mkdir(parents=True)
            header.write_bytes(b"original\n")
            self.headers[major] = header

    def generate(self, producer, *selection):
        compiler = self.root / "fake-clang"
        compiler.write_text(
            '#!/usr/bin/env bash\n'
            f'if [[ "$1" == -dumpversion ]]; then echo {producer}.0.0; exit; fi\n'
            'touch compiled\n'
            'while [[ "$1" != -o ]]; do shift; done\n'
            'printf "BCfixture" > "$2"\n', encoding="utf-8", newline="\n")
        compiler.chmod(0o755)
        return subprocess.run([BASH, "scripts/gen_vm_bitcode.sh", "./fake-clang",
                               "aarch64", *selection], cwd=self.root,
                              capture_output=True, text=True)

    def test_new_producer_rejected_before_compile_or_write(self):
        result = self.generate(21)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("LLVM 21 bitcode cannot target LLVM 20", result.stderr)
        self.assertFalse((self.root / "compiled").exists())
        for header in self.headers.values():
            self.assertEqual(header.read_bytes(), b"original\n")

    def test_selected_overlay_preserves_other_header(self):
        for major, other in ((20, 21), (21, 20)):
            with self.subTest(major=major):
                before = self.headers[other].read_bytes()
                result = self.generate(major, str(major))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"binary_ir_length = 9;", self.headers[major].read_bytes())
                self.assertEqual(self.headers[other].read_bytes(), before)

    def test_compatible_default_updates_both(self):
        result = self.generate(20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.headers[20].read_bytes(), self.headers[21].read_bytes())
        self.assertIn(b"binary_ir_length = 9;", self.headers[20].read_bytes())


if __name__ == "__main__":
    unittest.main()
