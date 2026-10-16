import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("build_snapshot", ROOT / "scripts/build_snapshot.py")
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snapshot test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        original_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, original_cwd)
        self.environment = mock.patch.dict(os.environ, {"GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": "",
                                                      "GITHUB_SHA": "b" * 40})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.capture = mock.patch.object(snapshot, "capture", return_value="a" * 40)
        self.capture.start()
        self.addCleanup(self.capture.stop)
        tools = {name: {"path": "/host/" + name} for name in ("clang", "clang++", "cmake", "python")}
        self.identity = {"format": snapshot.FORMAT, "base_commit": "a" * 40, "llvm_major": 21,
                         "root": str(self.root), "host": "linux-x86_64", "image_version": "test-1",
                         "tools": tools, "cmake_args": snapshot.cmake_args(self.root, "AArch64;ARM;X86", tools)}
        self.write("llvm-project/.git/HEAD", b"ref: refs/heads/main\n")
        for name in ("llvm-project/llvm/CMakeLists.txt",
                     "llvm-project/llvm/lib/Transforms/Obfuscation/.ndkp-overlay-files.json",
                     "llvm-project/llvm/include/llvm/Transforms/Obfuscation/.ndkp-overlay-files.json",
                     "build/build.ninja", "build/.ninja_log", "build/.ninja_deps", "build/bin/clang",
                     "build/lib/clang/21/include/stddef.h", "build/Pass.cpp.o", "build/libObfuscation.a"):
            self.write(name, b"fixture\n")
        settings = {"CMAKE_HOME_DIRECTORY": str(self.root / "llvm-project/llvm"),
                    "CMAKE_CACHEFILE_DIR": str(self.root / "build"), "CMAKE_GENERATOR": "Ninja"}
        settings.update(option[2:].split("=", 1) for option in self.identity["cmake_args"] if option.startswith("-D"))
        self.write("build/CMakeCache.txt", "\n".join(f"{k}:STRING={v}" for k, v in settings.items()).encode())
        snapshot.write_json(snapshot.STATE_DIR / "expected.json", self.identity)
        self.reset_state()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def reset_state(self):
        snapshot.write_json(snapshot.STATE_DIR / "state.json", {
            "requested": True, "hit": False, "key": snapshot.cache_key(self.identity),
            "source_commit": "b" * 40, "overlay_sha256": "c" * 64, "restore_started_at": 0,
        })

    def validate(self, hit="true"):
        with contextlib.redirect_stdout(io.StringIO()):
            snapshot.validate(argparse.Namespace(cache_hit=hit))
        return snapshot.read_json(snapshot.STATE_DIR / "state.json")

    def test_complete_snapshot_is_reused(self):
        snapshot.seal()
        result = self.validate()
        self.assertTrue(result["hit"])
        self.assertEqual(result["snapshot_origin"]["repository_commit"], "b" * 40)
        self.assertTrue((self.root / "build/Pass.cpp.o").is_file())

    def test_missing_cache_discards_partial_restoration_only(self):
        self.write("keep.txt", b"keep workspace")
        result = self.validate("false")
        self.assertFalse(result["hit"])
        self.assertFalse((self.root / "build").exists())
        self.assertFalse((self.root / "llvm-project").exists())
        self.assertEqual((self.root / "keep.txt").read_bytes(), b"keep workspace")
        self.assertTrue((snapshot.STATE_DIR / "expected.json").exists())

    def test_same_size_corruption_with_preserved_mtime_is_detected(self):
        snapshot.seal()
        path = self.root / "build/Pass.cpp.o"
        before = path.stat()
        path.write_bytes(b"corrupt\n")
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        result = self.validate()
        self.assertFalse(result["hit"])
        self.assertIn("contents or timestamps", result["reason"])

    def test_missing_object_is_detected(self):
        snapshot.seal()
        (self.root / "build/Pass.cpp.o").unlink()
        self.assertFalse(self.validate()["hit"])

    def test_changed_timestamp_is_detected(self):
        snapshot.seal()
        path = self.root / "build/Pass.cpp.o"
        before = path.stat()
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        self.assertFalse(self.validate()["hit"])

    def test_incompatible_identity_is_rejected(self):
        snapshot.seal()
        manifest = snapshot.read_json(snapshot.MANIFEST)
        manifest["identity"]["base_commit"] = "d" * 40
        snapshot.write_json(snapshot.MANIFEST, manifest)
        self.assertIn("compatibility", self.validate()["reason"])

    def test_malformed_manifest_falls_back(self):
        self.write(snapshot.MANIFEST, b"not json")
        self.assertFalse(self.validate()["hit"])

    def test_corrupt_inventory_falls_back(self):
        snapshot.seal()
        manifest = snapshot.read_json(snapshot.MANIFEST)
        manifest["inventory"] = []
        snapshot.write_json(snapshot.MANIFEST, manifest)
        self.assertFalse(self.validate()["hit"])

    def test_snapshot_cannot_be_sealed_without_dependency_database(self):
        (self.root / "build/.ninja_deps").unlink()
        with self.assertRaisesRegex(ValueError, "incomplete snapshot"):
            snapshot.seal()

    def test_actual_cmake_configuration_must_match_identity(self):
        path = self.root / "build/CMakeCache.txt"
        path.write_text(path.read_text().replace("=Release", "=Debug"))
        with self.assertRaisesRegex(ValueError, "CMAKE_BUILD_TYPE"):
            snapshot.seal()

    def test_actual_base_revision_must_match(self):
        with mock.patch.object(snapshot, "capture", return_value="d" * 40):
            with self.assertRaisesRegex(ValueError, "Base revision"):
                snapshot.seal()

    def test_actual_python_path_must_match(self):
        path = self.root / "build/CMakeCache.txt"
        path.write_text(path.read_text().replace("=/host/python", "=/another/python"))
        with self.assertRaisesRegex(ValueError, "Python3_EXECUTABLE"):
            snapshot.seal()

    def test_compatibility_key_changes_for_build_environment(self):
        original = snapshot.cache_key(self.identity)
        for field, value in (("base_commit", "d" * 40), ("root", "/another/root"),
                             ("host", "windows-x86_64"), ("image_version", "test-2"),
                             ("tools", {"clang": {"path": "/new/clang"}}),
                             ("cmake_args", ["-DCMAKE_BUILD_TYPE=Debug"])):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.identity)
                changed[field] = value
                self.assertNotEqual(original, snapshot.cache_key(changed))

    def test_prepare_excludes_pass_content_commit_and_patchset_from_key(self):
        for name in ("obfuscation/llvm-21/registration.patch",
                     "obfuscation/llvm-21/Transforms/Obfuscation/CMakeLists.txt",
                     "obfuscation/llvm-21/Transforms/Obfuscation/Pass.cpp",
                     "scripts/apply_overlay.sh", "scripts/sync_overlay.py", "scripts/build_snapshot.py", "host-tool", "python-tool"):
            self.write(name, b"original")
        args = argparse.Namespace(base="a" * 40, major=21, targets="AArch64;ARM;X86", enabled=True,
                                  host="linux-x86_64")
        original_read = Path.read_text
        with mock.patch.object(snapshot.platform, "system", return_value="Linux"), \
                mock.patch.object(snapshot.platform, "machine", return_value="x86_64"), \
                mock.patch.object(snapshot.shutil, "which", return_value=str(self.root / "host-tool")), \
                mock.patch.object(snapshot.sys, "executable", str(self.root / "python-tool")), \
                mock.patch.object(snapshot, "capture", return_value="GNU tar test"), \
                mock.patch.object(Path, "read_text", autospec=True, side_effect=lambda p, **k: "Linux" if p.as_posix() == "/etc/os-release" else original_read(p, **k)), \
                mock.patch.dict(os.environ, {"ImageOS": "ubuntu24", "ImageVersion": "20261015.1"}), \
                contextlib.redirect_stdout(io.StringIO()):
            snapshot.prepare(args)
            first = snapshot.read_json(snapshot.STATE_DIR / "state.json")
            self.write("obfuscation/llvm-21/Transforms/Obfuscation/Pass.cpp", b"changed pass")
            with mock.patch.dict(os.environ, {"GITHUB_SHA": "e" * 40, "PATCHSET_VERSION": "p99"}):
                snapshot.prepare(args)
            second = snapshot.read_json(snapshot.STATE_DIR / "state.json")
            self.assertEqual(first["key"], second["key"])
            self.assertNotEqual(first["overlay_sha256"], second["overlay_sha256"])
            for filename in ("obfuscation/llvm-21/registration.patch",
                             "obfuscation/llvm-21/Transforms/Obfuscation/CMakeLists.txt", "host-tool", "python-tool"):
                self.write(filename, b"changed configuration")
                snapshot.prepare(args)
                third = snapshot.read_json(snapshot.STATE_DIR / "state.json")
                self.assertNotEqual(second["key"], third["key"])
                second = third
            self.write("another-python", (self.root / "python-tool").read_bytes())
            with mock.patch.object(snapshot.sys, "executable", str(self.root / "another-python")):
                snapshot.prepare(args)
            self.assertNotEqual(second["key"], snapshot.read_json(snapshot.STATE_DIR / "state.json")["key"])

    def test_failed_build_is_recorded_and_propagated(self):
        result = snapshot.run_timed("compile", [sys.executable, "-c", "raise SystemExit(13)"])
        self.assertEqual(result, 13)
        data = snapshot.read_json(snapshot.STATE_DIR / "timings.json")
        self.assertEqual(data[0]["exit_code"], 13)
        self.assertTrue((self.root / "build").exists())

    def test_release_metadata_records_current_commit_and_snapshot_origin(self):
        state = snapshot.read_json(snapshot.STATE_DIR / "state.json")
        state.update(hit=True, reason="validated", snapshot_origin={"repository_commit": "d" * 40})
        snapshot.write_json(snapshot.STATE_DIR / "state.json", state)
        self.write("ndk/source.properties", b"Pkg.Revision = 29.0.14206865\n")
        subprocess.run([sys.executable, str(ROOT / "scripts/make_release_meta.py"),
                        "--ndk-dir", str(self.root / "ndk"), "--patchset", "p2",
                        "--snapshot-state", str(snapshot.STATE_DIR / "state.json")],
                       check=True, capture_output=True)
        info = snapshot.read_json(self.root / "ndk/NDKP-build-info.json")
        self.assertEqual(info["repository_commit"], "b" * 40)
        self.assertEqual(info["build_snapshot"]["snapshot_origin"]["repository_commit"], "d" * 40)
        self.assertTrue(info["build_snapshot"]["hit"])
        self.assertEqual(info["patchset"], "p2")

    def test_ninja_records_only_new_compile_and_link_outputs(self):
        before = "# ninja log v5\n0\t500\t10\told.o\thash\n"
        after = before + "0\t900\t11\tPass.cpp.o\thash2\n900\t1200\t12\tlib.a\thash3\n1200\t2500\t13\tbin/clang\thash4\n"
        measured = snapshot.ninja_measurements(before, after)
        self.assertEqual(measured["compile_edges"], 1)
        self.assertEqual(measured["link_edges"], 2)
        self.assertAlmostEqual(measured["compile_work_seconds"], 0.9)
        self.assertAlmostEqual(measured["link_work_seconds"], 1.6)
        self.assertEqual(snapshot.ninja_measurements(after, after)["compile_edges"], 0)

    def test_actions_posix_tar_roundtrip_preserves_snapshot_timestamps(self):
        # actions/cache uses --posix, which retains nanosecond mtimes through PAX.
        tar = os.environ.get("SNAPSHOT_TAR") or shutil.which("tar")
        if not tar or b"GNU tar" not in subprocess.check_output([tar, "--version"]):
            self.skipTest("GNU tar required; set SNAPSHOT_TAR on Windows")
        path = self.root / "build/Pass.cpp.o"
        os.utime(path, ns=(1_600_000_000_123_456_789,) * 2)
        self.write("llvm-project/.git/objects/readonly", b"git object")
        (self.root / "llvm-project/.git/objects/readonly").chmod(0o444)
        self.write("build/bin/clang.exe", b"executable fixture")
        snapshot.seal()
        subprocess.run([tar, "--posix", "-cf", "cache.tar", *snapshot.TREES, snapshot.MANIFEST], check=True)
        snapshot.discard(self.root)
        subprocess.run([tar, "-xf", "cache.tar"], check=True)
        self.assertTrue(self.validate()["hit"])
        snapshot.discard(self.root)

    def test_windows_configuration_paths_and_executable(self):
        self.identity["host"] = "windows-x86_64"
        self.write("build/bin/clang.exe", b"windows clang")
        cache_path = self.root / "build/CMakeCache.txt"
        cache_path.write_text(cache_path.read_text().replace("/host/", "C:/Host/"))
        self.identity["cmake_args"] = [arg.replace("/host/", "c:\\host\\") for arg in self.identity["cmake_args"]]
        snapshot.check_build(self.root, self.identity)
        (self.root / "build/bin/clang.exe").unlink()
        with self.assertRaisesRegex(ValueError, "clang.exe"):
            snapshot.check_build(self.root, self.identity)

    def test_windows_prepare_tracks_sdk_and_tools(self):
        for name in ("obfuscation/llvm-21/registration.patch",
                     "obfuscation/llvm-21/Transforms/Obfuscation/CMakeLists.txt",
                     "scripts/apply_overlay.sh", "scripts/sync_overlay.py", "scripts/build_snapshot.py",
                     "host-tool", "python-tool", "link.exe", "lib.exe"):
            self.write(name, b"original")
        environment = {name: "fixture" for name in (
            "VCToolsInstallDir", "VCToolsVersion", "WindowsSdkDir", "WindowsSDKVersion",
            "UniversalCRTSdkDir", "UCRTVersion", "INCLUDE", "LIB", "LIBPATH",
            "VSCMD_ARG_HOST_ARCH", "VSCMD_ARG_TGT_ARCH")}
        environment.update(ImageOS="win25", ImageVersion="20261015.1", SNAPSHOT_TAR="")
        args = argparse.Namespace(base="a" * 40, major=21, targets="AArch64;ARM;X86", enabled=True,
                                  host="windows-x86_64")
        with mock.patch.object(snapshot.platform, "system", return_value="Windows"), \
                mock.patch.object(snapshot.platform, "machine", return_value="AMD64"), \
                mock.patch.object(snapshot.shutil, "which", return_value=str(self.root / "host-tool")), \
                mock.patch.object(snapshot.sys, "executable", str(self.root / "python-tool")), \
                mock.patch.object(snapshot, "capture", return_value="GNU tar test"), \
                mock.patch.dict(os.environ, environment), contextlib.redirect_stdout(io.StringIO()):
            snapshot.prepare(args)
            first = snapshot.read_json(snapshot.STATE_DIR / "expected.json")
            self.assertIn("cl", first["tools"])
            self.assertNotIn("-DLLVM_USE_LINKER=lld", first["cmake_args"])
            for variable in ("WindowsSDKVersion", "VCToolsVersion", "LIB", "INCLUDE"):
                with mock.patch.dict(os.environ, {variable: "changed"}):
                    snapshot.prepare(args)
                    self.assertNotEqual(snapshot.cache_key(first),
                                        snapshot.read_json(snapshot.STATE_DIR / "state.json")["key"])
            self.write("host-tool", b"changed compiler binary")
            snapshot.prepare(args)
            self.assertNotEqual(snapshot.cache_key(first), snapshot.read_json(snapshot.STATE_DIR / "state.json")["key"])
            with mock.patch.dict(os.environ, {"WindowsSDKVersion": ""}):
                with self.assertRaisesRegex(ValueError, "WindowsSDKVersion"):
                    snapshot.prepare(args)

    @unittest.skipUnless(os.name == "nt", "Windows junction")
    def test_junction_is_rejected_and_discard_does_not_follow_it(self):
        outside = self.root / "keep"
        outside.mkdir()
        (outside / "data").write_bytes(b"keep")
        shutil.rmtree(self.root / "build")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.root / "build"), str(outside)],
                       check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "linked snapshot"):
            snapshot.inventory(self.root)
        snapshot.discard(self.root)
        self.assertEqual((outside / "data").read_bytes(), b"keep")

    def test_discard_does_not_follow_linked_tree(self):
        outside = self.root / "keep"
        outside.mkdir()
        (outside / "data").write_bytes(b"keep")
        shutil.rmtree(self.root / "build")
        try:
            (self.root / "build").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        snapshot.discard(self.root)
        self.assertEqual((outside / "data").read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
