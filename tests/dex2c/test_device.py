import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import device


TOKEN = "DEX2C_testtoken"


def protocol(code=127, prefix=b""):
    return prefix + f"{TOKEN}:BEGIN\n\n{TOKEN}:EXIT:{code}\n".encode()


def completed(code=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class DeviceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.apk = self.root / "authenticated-index-32.apk"
        self.apk.write_bytes(b"exact local APK bytes\0\xff")
        self.report_path = self.root / "evidence/results.json"
        self.report = {"runId": "current", "results": [], "pushed": [], "status": "running"}
        self.adb = ["adb", "-P", "5038", "-s", "explicit-device"]
        self.remote = "/data/local/tmp/dex2c-current/" + self.apk.name

    def load_report(self):
        return json.loads(self.report_path.read_text(encoding="utf-8"))

    def negative(self, execution, codes=(127,), push=None):
        with patch.object(device.uuid, "uuid4", return_value=SimpleNamespace(hex="testtoken")), \
                patch.object(device.subprocess, "run", side_effect=[push or completed(), execution]) as runner:
            device.negative_case(self.adb, self.apk, self.remote, list(codes), self.report, self.report_path)
        return runner

    def test_exact_127_signature_records_command_apk_identity_and_raw_streams(self):
        stderr = protocol(prefix=b"non-UTF8 diagnostic: \xff\n")
        self.negative(completed(stderr=stderr))
        row = self.load_report()["results"][0]
        self.assertTrue(row["rejected"])
        self.assertEqual(row["status"], "expected-exit-signature")
        self.assertEqual(row["expectedCodes"], [127])
        self.assertEqual(row["exitCode"], 127)
        self.assertEqual(row["execution"]["returnCode"], 0)
        self.assertEqual(base64.b64decode(row["execution"]["stderrBase64"]), stderr)
        self.assertEqual(row["artifact"], {"path": str(self.apk.resolve()), "bytes": self.apk.stat().st_size,
                         "sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest()})
        self.assertEqual(row["command"][:len(self.adb) + 1], [*self.adb, "shell"])
        self.assertEqual(row["execution"]["command"], row["command"])
        self.assertEqual(row["push"]["command"], [*self.adb, "push", str(self.apk), self.remote])
        self.assertEqual(row["childArgv"][0], "/system/bin/app_process")
        self.assertEqual(row["environment"], {"CLASSPATH": self.remote})
        self.assertLessEqual(datetime.fromisoformat(row["startedAt"]), datetime.fromisoformat(row["finishedAt"]))

    def test_unexpected_1_0_139_and_qseg_137_fail_with_current_row_saved(self):
        for code in (1, 0, 139, 137):
            with self.subTest(code=code):
                self.report["results"].clear()
                with self.assertRaisesRegex(RuntimeError, "unexpected-exit"):
                    self.negative(completed(stderr=protocol(code)))
                row = self.load_report()["results"][0]
                self.assertFalse(row["rejected"])
                self.assertEqual(row["exitCode"], code)
                self.assertIn("error", row)

    def test_nonqseg_sigkill_contract_is_explicit_and_does_not_allow_crashes(self):
        self.assertEqual(device.expected_codes("authenticated-index-32", True, True), [127])
        self.assertEqual(device.expected_codes("tampered-vm", True, False), [127])
        for name in ("tampered-vm", "tampered-cse-vm", "tampered-code"):
            self.assertEqual(device.expected_codes(name, False, True), [127, 137])
        self.assertEqual(device.expected_codes("wrong-signer", False, True), [127])
        self.assertEqual(device.expected_codes("wrong-signer", False, False), [127, 137])
        for name in ("tampered-cse-tag", "tampered-cse-ciphertext", "cross-build-cse-records"):
            self.assertEqual(device.expected_codes(name, False, False), [127])
        self.negative(completed(stderr=protocol(137)), codes=(127, 137))
        self.assertTrue(self.load_report()["results"][-1]["rejected"])
        with self.assertRaisesRegex(RuntimeError, "unexpected-exit"):
            self.negative(completed(stderr=protocol(139)), codes=(127, 137))

    def test_any_business_stdout_including_whitespace_is_not_rejection(self):
        for stdout in (b"algorithm result\n", b" \r\n", b"\xff\0"):
            with self.subTest(stdout=stdout), self.assertRaisesRegex(RuntimeError, "business-stdout"):
                self.negative(completed(stdout=stdout, stderr=protocol()))
            row = self.load_report()["results"][-1]
            self.assertFalse(row["rejected"])
            self.assertEqual(base64.b64decode(row["execution"]["stdoutBase64"]), stdout)

    def test_adb_transport_127_cannot_be_confused_with_child_127(self):
        with self.assertRaisesRegex(RuntimeError, "transport-error"):
            self.negative(completed(127, stderr=protocol()))
        row = self.load_report()["results"][0]
        self.assertEqual(row["execution"]["returnCode"], 127)
        self.assertIsNone(row["exitCode"])
        self.assertFalse(row["rejected"])

    def test_missing_duplicate_or_foreign_shell_markers_do_not_pass(self):
        for stderr in (b"", f"{TOKEN}:EXIT:127\n".encode(), protocol() * 2,
                       protocol().replace(TOKEN.encode(), b"OTHER"), protocol("unknown"), protocol(256),
                       f"{TOKEN}:EXIT:127\n{TOKEN}:BEGIN\n".encode(),
                       protocol() + f"{TOKEN}:UNKNOWN\n".encode()):
            with self.subTest(stderr=stderr), self.assertRaisesRegex(RuntimeError, "protocol-error"):
                self.negative(completed(stderr=stderr))
            self.assertFalse(self.load_report()["results"][-1]["rejected"])

    def test_guard_exec_trap_and_linker_failure_diagnostics_are_not_native_rejection(self):
        for stderr in (f"{TOKEN}:LAUNCH_FAILED\n".encode(),
                       protocol(prefix=f"{TOKEN}:LAUNCH_FAILED\n".encode()),
                       protocol(prefix=b"/system/bin/sh: app_process: not found\n"),
                       protocol(prefix=b'CANNOT LINK EXECUTABLE "app_process": missing symbol\n')):
            with self.subTest(stderr=stderr), self.assertRaisesRegex(RuntimeError, "launch-error"):
                self.negative(completed(stderr=stderr))
            self.assertFalse(self.load_report()["results"][-1]["rejected"])

    def test_timeout_keeps_partial_raw_streams_and_current_failure(self):
        error = subprocess.TimeoutExpired(["adb"], 90, output=b"partial\xff", stderr=b"partial-error\0")
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.negative(error)
        row = self.load_report()["results"][0]
        self.assertEqual(row["status"], "timeout")
        self.assertFalse(row["rejected"])
        self.assertIsNone(row["execution"]["returnCode"])
        self.assertEqual(base64.b64decode(row["execution"]["stdoutBase64"]), b"partial\xff")
        self.assertEqual(base64.b64decode(row["execution"]["stderrBase64"]), b"partial-error\0")

    def test_local_adb_launch_and_push_failure_keep_artifact_and_raw_evidence(self):
        with self.assertRaises(OSError):
            self.negative(OSError("cannot start adb"))
        row = self.load_report()["results"][-1]
        self.assertEqual(row["status"], "launch-error")
        self.assertIn("cannot start adb", row["execution"]["error"])
        with self.assertRaisesRegex(RuntimeError, "push failed"):
            self.negative(completed(stderr=protocol()), push=completed(1, b"push-out", b"push-error\xff"))
        row = self.load_report()["results"][-1]
        self.assertEqual(row["status"], "push-error")
        self.assertEqual(base64.b64decode(row["push"]["stderrBase64"]), b"push-error\xff")
        self.assertNotIn("execution", row)
        self.assertIn(self.remote, self.report["pushed"])

    def test_pending_attempt_and_identity_are_on_disk_before_each_adb_call(self):
        observed = []

        def run(argv, **kwargs):
            row = self.load_report()["results"][-1]
            observed.append(row["status"])
            self.assertEqual(row[row["status"]]["command"], argv)
            self.assertEqual(row["artifact"]["bytes"], self.apk.stat().st_size)
            self.assertFalse(row["rejected"])
            return completed(stderr=protocol() if row["status"] == "execution" else b"")

        with patch.object(device.uuid, "uuid4", return_value=SimpleNamespace(hex="testtoken")), \
                patch.object(device.subprocess, "run", side_effect=run):
            device.negative_case(self.adb, self.apk, self.remote, [127], self.report, self.report_path)
        self.assertEqual(observed, ["push", "execution"])

    def arguments(self, report=True):
        args = ["--sdk", str(self.root / "sdk"), "--java", str(self.root / "java"),
                "--serial", "explicit-device", "--fixtures", str(self.root)]
        return args + (["--report", str(self.report_path)] if report else [])

    def test_report_is_reset_before_setup_and_failure_replaces_old_passed_report(self):
        for custom in (True, False):
            path = self.report_path if custom else self.root / "device-results.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"status":"passed","results":[{"mode":"old-success"}]}', encoding="utf-8")

            def fail(args, report, report_path):
                current = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(current["status"], "running")
                self.assertEqual(current["results"], [])
                raise ValueError("setup failed in this run")

            with self.subTest(custom=custom), patch.object(device, "exercise", side_effect=fail), \
                    patch.object(device, "cleanup_remote", return_value=[]), self.assertRaises(ValueError):
                device.main(self.arguments(custom))
            current = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(current["status"], "failed")
            self.assertEqual(current["error"]["message"], "setup failed in this run")
            self.assertEqual(current["results"], [])
            self.assertIn("finishedAt", current)

    def test_failed_second_case_keeps_first_case_and_cleanup_does_not_replace_original_error(self):
        def exercise(args, report, path):
            report["pushed"] = []
            device.negative_case(self.adb, self.apk, self.remote, [127], report, path)
            device.negative_case(self.adb, self.apk, self.remote + ".next", [127], report, path)

        # No remote command is actually executed; every subprocess result is supplied here.
        with patch.object(device, "exercise", side_effect=exercise), \
                patch.object(device.uuid, "uuid4", return_value=SimpleNamespace(hex="testtoken")), \
                patch.object(device.subprocess, "run", side_effect=[completed(), completed(stderr=protocol()),
                    completed(), completed(stderr=protocol(1))]), \
                patch.object(device, "cleanup_remote", return_value=[{"status": "failed", "returnCode": 1}]), \
                self.assertRaisesRegex(RuntimeError, "unexpected-exit"):
            device.main(self.arguments())
        current = self.load_report()
        self.assertEqual(current["status"], "failed")
        self.assertEqual([row["rejected"] for row in current["results"]], [True, False])
        self.assertIn("unexpected-exit", current["error"]["message"])
        self.assertEqual(current["cleanup"][0]["returnCode"], 1)

    def test_cleanup_exception_does_not_mask_primary_failure_or_leave_running_report(self):
        with patch.object(device, "exercise", side_effect=ValueError("primary failure")), \
                patch.object(device, "cleanup_remote", side_effect=RuntimeError("cleanup exception")), \
                self.assertRaisesRegex(ValueError, "primary failure"):
            device.main(self.arguments())
        current = self.load_report()
        self.assertEqual(current["status"], "failed")
        self.assertEqual(current["error"]["message"], "primary failure")
        self.assertEqual(current["cleanup"][0]["error"]["message"], "cleanup exception")

    def test_cleanup_uses_exact_current_paths_and_keeps_errors(self):
        report = {"deviceCommand": self.adb, "remote": "/data/local/tmp/dex2c-current",
                  "pushed": [self.remote]}
        with patch.object(device.subprocess, "run", side_effect=[completed(1, b"out", b"err\xff"),
                                                               OSError("adb vanished")]) as runner:
            result = device.cleanup_remote(report)
        self.assertEqual(runner.call_args_list[0].args[0], [*self.adb, "shell", "rm", "-f", self.remote])
        self.assertEqual(runner.call_args_list[1].args[0], [*self.adb, "shell", "rmdir", report["remote"]])
        self.assertEqual([row["status"] for row in result], ["failed", "launch-error"])
        self.assertEqual(base64.b64decode(result[0]["stderrBase64"]), b"err\xff")

    def test_cleanup_failure_after_otherwise_passed_run_is_reported_as_failure(self):
        with patch.object(device, "exercise"), patch.object(device, "cleanup_remote", return_value=[
                {"status": "failed", "returnCode": 1}]), self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            device.main(self.arguments())
        self.assertEqual(self.load_report()["status"], "failed")

    @unittest.skipUnless(shutil.which("sh"), "a host POSIX shell is needed for exec protocol checks")
    def test_real_host_shell_distinguishes_exec_failure_from_child_exit_127(self):
        shell = shutil.which("sh").replace("\\", "/")
        command, child = device.negative_command(self.adb, self.remote, TOKEN)
        body = command[-1].replace("[ ! -x /system/bin/app_process ]", "[ ! -x " + shlex.quote(shell) + " ]")
        for executable, expected in ((shlex.quote(shell) + " -c 'exit 127'", "expected-exit-signature"),
                                     ("/does-not-exist/dex2c-app-process", "launch-error"),
                                     (shlex.quote(shell) + " -c 'echo CANNOT LINK EXECUTABLE >&2; exit 127'",
                                      "launch-error")):
            script = body.replace(shlex.join(child), executable)
            process = subprocess.run([shell, "-c", script], capture_output=True, timeout=15)
            evidence = {"returnCode": process.returncode, **device.streams(process.stdout, process.stderr)}
            with self.subTest(executable=executable):
                self.assertEqual(device.negative_status(evidence, TOKEN, [127])[0], expected)


if __name__ == "__main__":
    unittest.main()
