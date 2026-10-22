"""Release safety checks without credentials, network access or a Gradle installation."""

import importlib.util
import io
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import urllib.error


SPEC = importlib.util.spec_from_file_location("publish_dex2c", Path(__file__).resolve().parents[2] / "scripts/publish_dex2c.py")
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.version = "0.1.2"

    def stage(self):
        for path in publish.version_files(self.version):
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            extension = path.rsplit(".", 1)[-1]
            data = (hashlib.new(extension, file.with_suffix("").read_bytes()).hexdigest().encode()
                    if extension in publish.CHECKSUMS else b"artifact")
            file.write_bytes(data)

    def metadata(self, *versions):
        return {a: (set(versions), versions[-1] if versions else None) for a in publish.ARTIFACTS}

    def test_checkout_dependency_versions_are_synchronized(self):
        publish.release_version()

    def test_release_version_and_dependency_consistency(self):
        java = self.root / "gradle-plugin/src/main/java/io/github/xihan123/dex2c/gradle/Dex2cPlugin.java"
        sample = self.root / "samples/xposed/shared/build.gradle"
        strings = self.root / "samples/strings/build.gradle"
        for file in (java, sample, strings):
            file.parent.mkdir(parents=True)
        for version in ("0.1.2", "0.1.10-qseg2", "0.1.11-verify1", "1.2.3-rc.1"):
            with self.subTest(version=version):
                java.write_text(f'"{publish.GROUP}:annotations:{version}" "{publish.GROUP}:runtime:{version}"')
                sample.write_text(f"'{publish.GROUP}:annotations:{version}'")
                strings.write_text(f"'{publish.GROUP}:annotations:{version}'")
                (self.root / "build.gradle").write_text(f"version = '{version}'")
                self.assertEqual(publish.release_version(self.root), version)
        for invalid in ("0.1.2-SNAPSHOT", "0.1.2-snapshot", "0.1.2-rc1-SNAPSHOT", "../0.1.2",
                        "01.1.2", "0.1", "0.1.2-", "0.1.2-rc..1", "0.1.2-rc.01",
                        "0.1.2-verify1/other", "0.1.2+build1"):
            (self.root / "build.gradle").write_text(f"version = '{invalid}'")
            with self.assertRaisesRegex(ValueError, "release version"):
                publish.release_version(self.root)
        (self.root / "build.gradle").write_text("version = '0.1.3'")
        with self.assertRaisesRegex(ValueError, "Synchronize"):
            publish.release_version(self.root)
        (self.root / "build.gradle").write_text("version = '0.1.2'\nversion = '0.1.2'")
        with self.assertRaisesRegex(ValueError, "release version"):
            publish.release_version(self.root)

    def test_new_version_requires_absence_of_all_files(self):
        before = self.metadata("0.1.0", "0.1.1")
        with patch.object(publish, "read_metadata", return_value=before), patch.object(publish, "fetch", return_value=None) as fetch:
            self.assertEqual(publish.require_new_version(self.version), before)
            self.assertEqual(fetch.call_count, 90)

    def test_existing_metadata_rejects_publish(self):
        with patch.object(publish, "read_metadata", return_value=self.metadata("0.1.2")), patch.object(publish, "fetch") as fetch:
            with self.assertRaisesRegex(ValueError, "already exists"):
                publish.require_new_version(self.version)
            fetch.assert_not_called()

    def test_partial_checksum_upload_rejects_publish(self):
        orphan = next(p for p in publish.version_files(self.version) if p.endswith(".jar.sha256"))
        with patch.object(publish, "read_metadata", return_value=self.metadata()), patch.object(publish, "fetch", side_effect=lambda p: b"" if p == orphan else None):
            with self.assertRaisesRegex(ValueError, "partially published"):
                publish.require_new_version(self.version)

    def test_candidate_staging_and_overwrite_guards(self):
        self.version = "0.1.11-verify1"
        self.stage()
        self.assertEqual(len(publish.staged_manifest(self.root, self.version)), 90)
        with patch.object(publish, "read_metadata", return_value=self.metadata(self.version)), patch.object(publish, "fetch") as fetch:
            with self.assertRaisesRegex(ValueError, "already exists"):
                publish.require_new_version(self.version)
            fetch.assert_not_called()
        orphan = next(p for p in publish.version_files(self.version) if p.endswith(".jar.sha256"))
        with patch.object(publish, "read_metadata", return_value=self.metadata()), patch.object(publish, "fetch", side_effect=lambda p: b"" if p == orphan else None):
            with self.assertRaisesRegex(ValueError, "partially published"):
                publish.require_new_version(self.version)

    def test_only_http_404_means_absent(self):
        for status in (403, 401, 500, 404):
            with patch.object(publish.urllib.request, "urlopen", side_effect=urllib.error.HTTPError("url", status, "error", {}, None)):
                if status == 404:
                    self.assertIsNone(publish.fetch("a.pom"))
                else:
                    with self.assertRaisesRegex(RuntimeError, f"HTTP {status}"):
                        publish.fetch("a.pom")

    def test_complete_stage_and_corrupt_checksum(self):
        self.stage()
        self.assertEqual(len(publish.staged_manifest(self.root, self.version)), 90)
        checksum = next(self.root.rglob("*.sha256"))
        checksum.write_text("bad")
        with self.assertRaisesRegex(ValueError, "Invalid staging checksum"):
            publish.staged_manifest(self.root, self.version)

    def test_missing_stage_file_rejected(self):
        self.stage()
        next(self.root.rglob("*.pom")).unlink()
        with self.assertRaisesRegex(ValueError, "Incomplete staging"):
            publish.staged_manifest(self.root, self.version)

    def test_remote_bytes_and_metadata_preserve_old_versions(self):
        self.stage()
        before = self.metadata("0.1.0", "0.1.1")
        with patch.object(publish, "fetch", side_effect=lambda p: (self.root / p).read_bytes()), patch.object(publish, "read_metadata", return_value=self.metadata("0.1.0", "0.1.1", "0.1.2")):
            report = publish.verify_remote(self.root, self.version, before)
            self.assertEqual(len(report["verified"]), 90)
        with patch.object(publish, "fetch", return_value=b"wrong"):
            with self.assertRaisesRegex(ValueError, "differs from staging"):
                publish.verify_remote(self.root, self.version)
        with patch.object(publish, "fetch", side_effect=lambda p: (self.root / p).read_bytes()), patch.object(publish, "read_metadata", return_value=self.metadata("0.1.2")):
            with self.assertRaisesRegex(ValueError, "lost versions"):
                publish.verify_remote(self.root, self.version, before)

    def test_release_pointer_checked_after_publish(self):
        self.stage()
        with patch.object(publish, "fetch", side_effect=lambda p: (self.root / p).read_bytes()), patch.object(publish, "read_metadata", return_value=self.metadata("0.1.2", "0.1.1")):
            with self.assertRaisesRegex(ValueError, "release pointer"):
                publish.verify_remote(self.root, self.version, self.metadata("0.1.1"))

    def test_metadata_identity_checked(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            publish.metadata_versions(b"<metadata><groupId>wrong</groupId></metadata>", "core")

    def test_missing_or_skipped_native_tests_reject_release(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            publish.check_test_results(self.root)
        file = self.root / "core/build/test-results/test/TEST-fixture.xml"
        file.parent.mkdir(parents=True)
        cases = "".join(f'<testcase name="{name}()"/>' for name in publish.NATIVE_TESTS)
        file.write_text(f'<testsuite skipped="1">{cases}</testsuite>')
        with self.assertRaisesRegex(ValueError, "zero failed/skipped"):
            publish.check_test_results(self.root)
        file.write_text(f'<testsuite>{cases}</testsuite>')
        self.assertEqual(publish.check_test_results(self.root), len(publish.NATIVE_TESTS))

    def test_credentials_only_reach_publish_and_logs_are_redacted(self):
        credentials = dict(zip(publish.CREDENTIALS, ("test-user", "test-secret")))
        for publishing in (False, True):
            process = MagicMock()
            process.__enter__.return_value = process
            process.stdout = io.StringIO("test-user test-secret\n" if publishing else "check\n")
            process.wait.return_value = 0
            log = self.root / "gradle.log"
            with patch.dict(os.environ, credentials), patch.object(publish.subprocess, "Popen", return_value=process) as run:
                publish.run_gradle(["task"], log, publish=publishing)
            self.assertEqual(all(key in run.call_args.kwargs["env"] for key in publish.CREDENTIALS), publishing)
            self.assertNotIn("test-secret", log.read_text())
            self.assertNotIn("test-secret", " ".join(run.call_args.args[0]))

    def test_missing_credentials_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "Set both"):
                publish.release_credentials()
        with patch.dict(os.environ, {publish.CREDENTIALS[0]: "test-user"}, clear=True):
            with self.assertRaisesRegex(ValueError, "Set both"):
                publish.release_credentials()


if __name__ == "__main__":
    unittest.main()
