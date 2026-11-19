"""Keep copy evidence tied to the final bytes, actual IR and distinct failures."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import copy_probe as probe
import test_cache_probe


def fixture():
    raw = bytes(range(probe.TARGET_BYTES))
    row = {"id": probe.TARGET_ID, "kind": 2, "chunk": 0, "lifetime": "copy-v1",
           "bytes": len(raw), "resourceSha256": probe.cache.sha256(raw), "sha256": probe.cache.sha256(raw)}
    descriptor = bytes.fromhex(probe.TARGET_ID) + struct.pack("<II", len(raw), 2)
    escaped = "".join("\\%02X" % byte for byte in descriptor)
    ir = ('@ndkp_qseg_ref.27 = private constant [24 x i8] c"' + escaped + '", align 4\n'
          '  invoke void @ndkp_qseg_copy(ptr nonnull @dec0, ptr nonnull @ndkp_qseg_ref.27, i32 0, i32 32, i32 2)\n'
          '  call void @ndkp_qseg_copy(ptr nonnull @dec1, ptr nonnull @ndkp_qseg_ref.27, i32 32, i32 17, i32 1)\n')
    return {"segments": [row]}, {(bytes.fromhex(probe.TARGET_ID), 2): raw}, ir


class CopyProbeTest(unittest.TestCase):
    def test_refuses_old_success_before_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "results.json").write_text("{}", encoding="utf-8")
            arguments = ["copy_probe.py", "--output", directory]
            for name in ("ndk", "native", "apk", "java", "apksigner", "adb", "serial"):
                arguments += ["--" + name, "unused"]
            with patch.object(sys, "argv", arguments), patch.object(probe.cache, "load_authenticated_apk") as load:
                with self.assertRaises(SystemExit) as result:
                    probe.main()
            self.assertEqual(result.exception.code, 2); load.assert_not_called()

    def test_requires_single_kind2_copy_chunk_and_final_plaintext_digest(self):
        receipt, resources, _ = fixture()
        target, raw = probe.select_target(receipt, resources)
        self.assertEqual(target["bytes"], 203)
        for key, value in (("kind", 1), ("chunk", 1), ("lifetime", "lease-v1"), ("bytes", 204),
                           ("resourceSha256", "0" * 64), ("sha256", "0" * 64)):
            changed = copy.deepcopy(receipt); changed["segments"][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "kind2 copy-v1 chunk0"):
                probe.select_target(changed, resources)
        for rows in ([], receipt["segments"] * 2):
            with self.assertRaises(ValueError):
                probe.select_target({"segments": rows}, resources)
        changed = dict(resources); changed[(bytes.fromhex(probe.TARGET_ID), 2)] = raw[:-1] + b"!"
        with self.assertRaises(ValueError):
            probe.select_target(receipt, changed)

    def test_ir_binds_invoke_and_call_to_exact_descriptor_and_expected_slices(self):
        receipt, resources, ir = fixture()
        target, raw = probe.select_target(receipt, resources)
        bound = probe.bind_ir(ir, target, raw)
        self.assertEqual(bound["descriptor"]["name"], "ndkp_qseg_ref.27")
        self.assertEqual(bound["calls"][0]["sha256"], probe.cache.sha256(raw[:32]))
        self.assertEqual(bound["calls"][1]["sha256"], probe.cache.sha256(raw[32:49]))
        for changed in (ir.replace("\\CB\\00\\00\\00\\02", "\\CA\\00\\00\\00\\02"),
                        ir.replace("\\02\\00\\00\\00\"", "\\01\\00\\00\\00\""),
                        ir.replace("ptr nonnull @ndkp_qseg_ref.27,", "ptr nonnull @unrelated,"),
                        ir.replace("i32 32, i32 17", "i32 33, i32 17"), ir + ir.splitlines()[0] + "\n"):
            with self.subTest(changed=changed[:70]), self.assertRaises(ValueError):
                probe.bind_ir(changed, target, raw)
        with self.assertRaisesRegex(ValueError, "invalid actual IR"):
            probe.bind_ir(ir.replace("i32 0, i32 32", "i32 202, i32 32"), target, raw)

    def test_llvm_hex_and_literal_descriptor_bytes(self):
        self.assertEqual(probe.ir_bytes(r"\83\F9A%~\00"), b"\x83\xf9A%~\0")
        with self.assertRaises(ValueError):
            probe.ir_bytes(r"\XX")

    def test_slices_include_legal_zero_odd_offset_and_tail(self):
        raw = bytes(range(203)); slices = {row["name"]: row for row in probe.copy_slices(raw)}
        self.assertEqual(slices["zero"]["offset"], len(raw))
        self.assertEqual(slices["zero"]["bytes"], 0)
        self.assertEqual(slices["zero"]["sha256"], probe.cache.sha256(b""))
        self.assertEqual((slices["odd-offset"]["offset"], slices["odd-offset"]["bytes"], slices["odd-offset"]["encoding"]), (1, 2, 2))
        self.assertEqual(slices["tail"]["sha256"], probe.cache.sha256(raw[-7:]))

    def test_kind2_descriptor_and_copy_symbol_must_bind_rx(self):
        image = bytearray(test_cache_probe.test_seal_cse.elf())
        descriptor = bytes.fromhex(probe.TARGET_ID) + struct.pack("<II", 203, 2)
        image[0x1100:0x1118] = descriptor
        self.assertEqual(probe.cache.descriptor_address(image, probe.TARGET_ID, 203, kind=2), 0x1100)
        with self.assertRaisesRegex(ValueError, "one exact"):
            probe.cache.descriptor_address(image, probe.TARGET_ID, 203)
        symbols = {name: 0x1200 for name in probe.SYMBOLS}
        self.assertTrue(probe.cache.bind_executable(image, image, symbols, required_symbols=probe.SYMBOLS))
        for change in (None, 0x300):
            changed = dict(symbols)
            if change is None:
                del changed["ndkp_qseg_copy"]
            else:
                changed["ndkp_qseg_copy"] = change
            with self.assertRaisesRegex(ValueError, "probe symbol: ndkp_qseg_copy"):
                probe.cache.bind_executable(image, image, changed, required_symbols=probe.SYMBOLS)

    def test_negative_process_needs_its_own_warmup_marker_and_exit127(self):
        for case in probe.NEGATIVE_CASES:
            marker = f"case={case} valid-copy=verified invalid-copy=attempt\n"
            result = subprocess.CompletedProcess([], 127, marker, "")
            self.assertIsNone(probe.check_process(case, result))
            for code, out in ((127, ""), (127, marker.replace(case, "other")), (0, marker),
                              (139, marker), (127, marker + "unexpected\n")):
                with self.subTest(case=case, code=code, out=out), self.assertRaises(RuntimeError):
                    probe.check_process(case, subprocess.CompletedProcess([], code, out, ""))
        observation = {"sourceIntervalAbsentBeforeReload": True, "retainedCopyDigestAfterSourceReclaim": True,
                       "ownBuffersWipedReadback": True}
        self.assertEqual(probe.check_process("positive", subprocess.CompletedProcess([], 0, json.dumps(observation), "")), observation)
        with self.assertRaises(ValueError):
            probe.check_process("positive", subprocess.CompletedProcess([], 0, "{}", ""))

    def test_header_contains_kind2_slices_and_copy_offset(self):
        receipt, resources, _ = fixture(); target, raw = probe.select_target(receipt, resources)
        target["address"] = 0x1100
        symbols = {name: 0x1200 for name in probe.SYMBOLS}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "copy_plan.h"
            probe.write_header(path, [target], probe.copy_slices(raw), [], symbols, 4096)
            text = path.read_text(encoding="utf-8")
        self.assertIn("{4352, 203, 2,", text)
        self.assertIn('{"odd-offset", 1, 2, 2,', text)
        self.assertIn('{"zero", 203, 0, 2,', text)
        self.assertIn("Offset_ndkp_qseg_copy = 4608", text)

    def test_actual_import_helpers_and_native_sources_are_bound(self):
        hashes = probe.source_hashes()
        for path in ("tests/qseg/copy_probe.py", "tests/qseg/copy_probe.cpp", "tests/qseg/cache_probe.py",
                     "tests/qseg/audit_apk.py", "scripts/verify_dex2c_apk.py", "scripts/dex2c_artifacts.py",
                     "scripts/seal_qseg.py", "scripts/seal_cse.py", "runtime/qseg.h", "runtime/sha256.h"):
            self.assertEqual(hashes[path], probe.cache.sha256((Path(__file__).resolve().parents[2] / path).read_bytes()))


if __name__ == "__main__":
    unittest.main()
