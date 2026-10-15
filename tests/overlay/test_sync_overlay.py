import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[2] / "scripts" / "sync_overlay.py"
SPEC = importlib.util.spec_from_file_location("sync_overlay", SCRIPT)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)
OLD_TIME = 1_600_000_000_000_000_000


class SyncOverlayTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="overlay test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.llvm = self.root / "llvm-project"
        self.overlay = self.root / "overlay"
        self.sources = self.overlay / "Transforms/Obfuscation"
        self.sources.mkdir(parents=True)
        (self.llvm / "llvm").mkdir(parents=True)
        self.destination = self.llvm / sync.DIRECTORIES[0][1]
        self.headers = self.llvm / sync.DIRECTORIES[1][1]
        self.write(self.sources / "Pass.cpp", b"original\x00\r\n")
        self.write(self.overlay / "include/sub/Pass.h", b"header\n")

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def run_sync(self):
        sync.sync_overlay(self.llvm, self.overlay)

    def write_manifest(self, data):
        self.write(self.destination / sync.MANIFEST, json.dumps(data).encode())

    def link(self, path, target, directory=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        self.addCleanup(path.unlink)

    def test_unchanged_files_and_manifest_keep_mtime(self):
        self.run_sync()
        tracked = [self.destination / "Pass.cpp", self.headers / "sub/Pass.h",
                   self.destination / sync.MANIFEST, self.headers / sync.MANIFEST]
        for path in tracked:
            os.utime(path, ns=(OLD_TIME, OLD_TIME))
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in tracked}
        self.run_sync()
        self.assertEqual(before, {
            path: (path.read_bytes(), path.stat().st_mtime_ns) for path in tracked
        })

    def test_changed_files_get_fresh_mtime_even_with_old_source_time(self):
        self.run_sync()
        for source, destination in (
            (self.sources / "Pass.cpp", self.destination / "Pass.cpp"),
            (self.overlay / "include/sub/Pass.h", self.headers / "sub/Pass.h"),
        ):
            os.utime(destination, ns=(OLD_TIME, OLD_TIME))
            source.write_bytes(b"modified\x00\n")
            os.utime(source, ns=(OLD_TIME - 10_000, OLD_TIME - 10_000))
        self.run_sync()
        for path in (self.destination / "Pass.cpp", self.headers / "sub/Pass.h"):
            self.assertEqual(path.read_bytes(), b"modified\x00\n")
            self.assertGreater(path.stat().st_mtime_ns, OLD_TIME)

    def test_add_rename_and_delete_only_managed_files(self):
        self.run_sync()
        unrelated = self.destination / "local.txt"
        outside = self.llvm / "llvm/lib/Transforms/CMakeLists.txt"
        self.write(unrelated, b"keep local")
        self.write(outside, b"keep upstream")
        (self.sources / "Pass.cpp").rename(self.sources / "Renamed.cpp")
        self.write(self.sources / "sub/New.cpp", b"new")
        self.run_sync()
        self.assertFalse((self.destination / "Pass.cpp").exists())
        self.assertEqual((self.destination / "Renamed.cpp").read_bytes(), b"original\x00\r\n")
        self.assertEqual((self.destination / "sub/New.cpp").read_bytes(), b"new")
        self.assertEqual(unrelated.read_bytes(), b"keep local")
        self.assertEqual(outside.read_bytes(), b"keep upstream")
        self.assertEqual(sync.read_manifest(self.destination), {"Renamed.cpp", "sub/New.cpp"})

    def test_removing_optional_headers_removes_tracked_files(self):
        self.run_sync()
        (self.overlay / "include").rename(self.overlay / "removed-include")
        self.run_sync()
        self.assertFalse((self.headers / "sub/Pass.h").exists())
        self.assertEqual(sync.read_manifest(self.headers), set())

    def test_case_only_rename_keeps_the_file(self):
        self.run_sync()
        (self.sources / "Pass.cpp").rename(self.sources / "PASS.cpp")
        (self.sources / "PASS.cpp").write_bytes(b"renamed")
        self.run_sync()
        self.run_sync()
        self.assertEqual((self.destination / "PASS.cpp").read_bytes(), b"renamed")
        self.assertEqual(sync.read_manifest(self.destination), {"PASS.cpp"})

    def test_interrupted_copy_still_tracks_new_files_for_later_deletion(self):
        self.run_sync()
        (self.sources / "Added.cpp").write_bytes(b"added")
        original_write = sync.write_changed

        def fail_on_pass(path, content):
            if path.name == "Pass.cpp":
                raise OSError("interrupted copy")
            original_write(path, content)

        with mock.patch.object(sync, "write_changed", side_effect=fail_on_pass):
            with self.assertRaisesRegex(OSError, "interrupted"):
                self.run_sync()
        self.assertTrue((self.destination / "Added.cpp").exists())
        (self.sources / "Added.cpp").unlink()
        self.run_sync()
        self.assertFalse((self.destination / "Added.cpp").exists())
        self.assertEqual(sync.read_manifest(self.destination), {"Pass.cpp"})

    def test_existing_unmanaged_directory_is_adopted_without_pruning(self):
        self.write(self.destination / "local.cpp", b"keep")
        self.write(self.destination / "Pass.cpp", b"original\x00\r\n")
        os.utime(self.destination / "Pass.cpp", ns=(OLD_TIME, OLD_TIME))
        self.run_sync()
        self.assertEqual((self.destination / "Pass.cpp").stat().st_mtime_ns, OLD_TIME)
        self.assertEqual((self.destination / "local.cpp").read_bytes(), b"keep")

    def test_missing_required_overlay_fails_before_deleting(self):
        self.run_sync()
        self.sources.rename(self.overlay / "removed-sources")
        with self.assertRaisesRegex(ValueError, "missing overlay"):
            self.run_sync()
        self.assertTrue((self.destination / "Pass.cpp").is_file())

    def test_corrupt_or_unsupported_manifest_fails_before_changes(self):
        self.run_sync()
        (self.sources / "Pass.cpp").write_bytes(b"changed")
        for data in (b"not json", b"[]", b'{"version":2,"files":[]}',
                     b'{"version":1,"files":null}',
                     b'{"version":1,"files":[12]}'):
            with self.subTest(data=data):
                (self.destination / sync.MANIFEST).write_bytes(data)
                with self.assertRaises(ValueError):
                    self.run_sync()
                self.assertEqual((self.destination / "Pass.cpp").read_bytes(), b"original\x00\r\n")

    def test_unsafe_manifest_paths_are_rejected_before_deleting(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"keep")
        for name in ("../outside.txt", "a/../../outside.txt", "/outside.txt",
                     "C:/outside.txt", "a\\..\\outside.txt", "a//b", "./Pass.cpp",
                     ".. /outside.txt", "a.", "NUL", "x:stream", "", sync.MANIFEST):
            with self.subTest(name=name):
                self.write_manifest({"version": 1, "files": [name]})
                with self.assertRaises(ValueError):
                    self.run_sync()
                self.assertFalse((self.destination / "Pass.cpp").exists())
                self.assertEqual(outside.read_bytes(), b"keep")

    def test_duplicate_manifest_entries_fail(self):
        self.write_manifest({"version": 1, "files": ["Pass.cpp", "Pass.cpp"]})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_sync()

    def test_source_link_is_rejected(self):
        self.link(self.sources / "linked.cpp", self.sources / "Pass.cpp")
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertFalse(self.destination.exists())

    def test_destination_directory_link_cannot_escape(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.link(self.destination, outside, directory=True)
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertEqual(list(outside.iterdir()), [])

    def test_stale_file_link_cannot_delete_external_file(self):
        self.run_sync()
        outside = self.root / "outside.txt"
        outside.write_bytes(b"keep")
        (self.sources / "Pass.cpp").unlink()
        (self.destination / "Pass.cpp").unlink()
        self.link(self.destination / "Pass.cpp", outside)
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_manifest_link_is_rejected(self):
        outside = self.root / "outside.json"
        outside.write_bytes(b'{"version":1,"files":[]}')
        self.link(self.destination / sync.MANIFEST, outside)
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertEqual(outside.read_bytes(), b'{"version":1,"files":[]}')

    def test_header_link_fails_before_source_changes(self):
        self.run_sync()
        (self.sources / "Pass.cpp").write_bytes(b"changed")
        (self.headers / "sub/Pass.h").unlink()
        self.link(self.headers / "sub/Pass.h", self.root / "missing")
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertEqual((self.destination / "Pass.cpp").read_bytes(), b"original\x00\r\n")

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_windows_junction_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.destination.parent.mkdir(parents=True)
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.destination), str(outside)],
                       check=True, capture_output=True)
        self.addCleanup(self.destination.rmdir)
        with self.assertRaisesRegex(ValueError, "links"):
            self.run_sync()
        self.assertEqual(list(outside.iterdir()), [])

    def test_hardlinked_file_is_replaced_without_modifying_external_content(self):
        outside = self.root / "outside.cpp"
        outside.write_bytes(b"keep")
        self.destination.mkdir(parents=True)
        os.link(outside, self.destination / "Pass.cpp")
        self.run_sync()
        self.assertEqual(outside.read_bytes(), b"keep")
        self.assertEqual((self.destination / "Pass.cpp").read_bytes(), b"original\x00\r\n")


if __name__ == "__main__":
    unittest.main()
