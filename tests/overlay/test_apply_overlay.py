import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[2]
# On Windows set BASH to Git Bash's bash.exe, rather than the WSL launcher.
BASH = os.environ.get("BASH", "bash")
BEFORE = b"add_subdirectory(Coroutines)\nadd_subdirectory(CFGuard)\nadd_subdirectory(HipStdPar)\n"
AFTER = BEFORE + b"add_subdirectory(Obfuscation)\n"


class ApplyOverlayTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="apply overlay test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.llvm = self.root / "llvm-project"
        self.repo = self.root / "repo with spaces"
        self.cmake = self.llvm / "llvm/lib/Transforms/CMakeLists.txt"
        self.cmake.parent.mkdir(parents=True)
        self.cmake.write_bytes(BEFORE)
        subprocess.run(["git", "init", "-q", str(self.llvm)], check=True)
        subprocess.run(["git", "-C", str(self.llvm), "config", "core.autocrlf", "false"],
                       check=True)
        self.overlay = self.repo / "obfuscation/llvm-21"
        self.sources = self.overlay / "Transforms/Obfuscation"
        self.sources.mkdir(parents=True)
        (self.sources / "Pass.cpp").write_bytes(b"pass\n")
        self.patch = self.overlay / "registration.patch"
        self.patch.write_bytes((ROOT / "obfuscation/llvm-21/registration.patch").read_bytes())

    def apply(self, success=True, major="21"):
        result = subprocess.run([
            BASH, str(ROOT / "scripts/apply_overlay.sh"),
            "--llvm-src", "llvm-project", "--repo-root", "repo with spaces",
            "--major", major,
        ], cwd=self.root, capture_output=True, text=True, encoding="utf-8")
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_both_major_patches_apply_and_repeat_without_mtime_changes(self):
        for major in ("20", "21"):
            with self.subTest(major=major):
                self.cmake.write_bytes(BEFORE)
                self.patch.write_bytes((ROOT / f"obfuscation/llvm-{major}/registration.patch").read_bytes())
                if self.overlay.name != f"llvm-{major}":
                    destination = self.overlay.with_name(f"llvm-{major}")
                    self.overlay.rename(destination)
                    self.overlay = destination
                    self.patch = self.overlay / "registration.patch"
                self.apply(major=major)
                self.assertEqual(self.cmake.read_bytes(), AFTER)
                tracked = [self.cmake, self.cmake.parent / "Obfuscation/Pass.cpp"]
                for path in tracked:
                    os.utime(path, ns=(1_600_000_000_000_000_000,) * 2)
                before = [path.stat().st_mtime_ns for path in tracked]
                self.apply(major=major)
                self.assertEqual(before, [path.stat().st_mtime_ns for path in tracked])
                self.assertEqual(self.cmake.read_bytes(), AFTER)

    def test_repeat_still_syncs_changed_and_deleted_sources(self):
        (self.sources / "Removed.cpp").write_bytes(b"remove")
        self.apply()
        (self.sources / "Removed.cpp").unlink()
        (self.sources / "Pass.cpp").write_bytes(b"changed")
        self.apply()
        destination = self.cmake.parent / "Obfuscation"
        self.assertEqual((destination / "Pass.cpp").read_bytes(), b"changed")
        self.assertFalse((destination / "Removed.cpp").exists())

    def test_conflicting_patch_fails_before_sync(self):
        self.cmake.write_bytes(b"conflicting upstream\n")
        self.apply(success=False)
        self.assertEqual(self.cmake.read_bytes(), b"conflicting upstream\n")
        self.assertFalse((self.cmake.parent / "Obfuscation").exists())

    def test_partially_applied_patch_fails_before_sync(self):
        second = self.llvm / "llvm/second.txt"
        second.write_bytes(b"before\n")
        with self.patch.open("ab") as stream:
            stream.write(b"diff --git a/llvm/second.txt b/llvm/second.txt\n"
                         b"--- a/llvm/second.txt\n+++ b/llvm/second.txt\n"
                         b"@@ -1 +1 @@\n-before\n+after\n")
        self.cmake.write_bytes(AFTER)
        self.apply(success=False)
        self.assertEqual(second.read_bytes(), b"before\n")
        self.assertFalse((self.cmake.parent / "Obfuscation").exists())

    def test_missing_overlay_fails_even_after_successful_application(self):
        self.apply()
        self.overlay.rename(self.overlay.with_name("removed"))
        self.apply(success=False)
        self.assertEqual(self.cmake.read_bytes(), AFTER)

    def test_missing_or_empty_patch_fails(self):
        self.patch.unlink()
        self.apply(success=False)
        self.patch.write_bytes(b"")
        self.apply(success=False)
        self.assertFalse((self.cmake.parent / "Obfuscation").exists())

    def test_missing_source_directory_fails(self):
        self.sources.rename(self.sources.with_name("removed"))
        self.apply(success=False)
        self.assertEqual(self.cmake.read_bytes(), BEFORE)


if __name__ == "__main__":
    unittest.main()
