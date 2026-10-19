"""Reject the wrong LLVM base before applying an overlay or touching the NDK."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH = os.environ.get("BASH", "bash")


class BuildClangLocalTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="local clang test ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(ROOT / "scripts/build_clang_local.sh", scripts / "build_clang_local.sh")
        (scripts / "apply_overlay.sh").write_text("echo reached-overlay\nexit 91\n")
        (self.root / "android-ndk-test/toolchains/llvm/prebuilt/linux-x86_64").mkdir(parents=True)
        (self.root / "obfuscation/llvm-21/Transforms/Obfuscation").mkdir(parents=True)
        self.llvm = self.root / "llvm-project"
        (self.llvm / "llvm").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.llvm)], check=True)
        subprocess.run(["git", "-C", str(self.llvm), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "--allow-empty", "-qm", "base"], check=True)
        self.base = subprocess.check_output(["git", "-C", str(self.llvm), "rev-parse", "HEAD"], text=True).strip()
        self.env = os.environ.copy()
        # These checks must finish before any build command can run.
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name in ("cmake", "ninja"):
            tool = bin_dir / name
            tool.write_text(f"#!/usr/bin/env bash\necho reached-{name}\nexit 92\n")
            tool.chmod(0o755)
        self.env["PATH"] = str(bin_dir) + os.pathsep + self.env["PATH"]

    def run_build(self, base):
        metadata = {"llvm_major": 21, "base_commit": base}
        (self.root / "scripts/locate_llvm.py").write_text("print(" + repr(json.dumps(metadata)) + ")\n")
        return subprocess.run([BASH, "scripts/build_clang_local.sh", "--host", "linux-x86_64"],
                              cwd=self.root, env=self.env, capture_output=True,
                              text=True, encoding="utf-8", timeout=30)

    def test_default_ndk_discovery_and_matching_base_reach_overlay(self):
        result = self.run_build(self.base)
        self.assertEqual(result.returncode, 91, result.stdout + result.stderr)
        self.assertIn("reached-overlay", result.stdout)

    def test_wrong_base_is_rejected_before_overlay(self):
        result = self.run_build("0" * 40)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Base revision=", result.stderr)
        self.assertNotIn("reached-overlay", result.stdout)

    def test_missing_base_is_rejected_before_overlay(self):
        result = self.run_build(None)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("base commit", result.stderr)
        self.assertNotIn("reached-overlay", result.stdout)

    def test_cached_build_still_configures_before_ninja(self):
        (self.root / "scripts/apply_overlay.sh").write_text("exit 0\n")
        (self.root / "build").mkdir()
        (self.root / "build/build.ninja").touch()
        result = self.run_build(self.base)
        self.assertEqual(result.returncode, 92, result.stdout + result.stderr)
        self.assertIn("reached-cmake", result.stdout)
        self.assertNotIn("reached-ninja", result.stdout)


if __name__ == "__main__":
    unittest.main()
