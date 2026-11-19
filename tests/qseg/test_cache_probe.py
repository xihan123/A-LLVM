"""Fail closed before device execution when the large-VM evidence cannot bind."""
import copy
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import cache_probe as probe
import large_fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cse-hardened"))
import test_seal_cse


def resource_fixture(target_size=70000, pressure_count=18):
    raw, entries = {}, []
    for ordinal, size in enumerate([target_size] + [58000] * pressure_count):
        identity = ordinal.to_bytes(16, "little")
        data = bytes([ordinal]) * size
        raw[(identity, 1)] = data
        for chunk, offset in enumerate(range(0, size, 65536)):
            part = data[offset:offset+65536]
            entries.append({"id": identity.hex(), "kind": 1, "chunk": chunk,
                            "bytes": len(part), "lifetime": "lease-v1", "name": "vm" + str(ordinal),
                            "resourceSha256": probe.sha256(data), "sha256": probe.sha256(part)})
    return {"segments": entries}, raw


class CacheProbeTest(unittest.TestCase):
    def test_refuses_output_with_a_prior_success(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "results.json").write_text('{"crossChunk":true}', encoding="utf-8")
            arguments = ["cache_probe.py", "--output", directory]
            for name in ("ndk", "native", "apk", "java", "apksigner", "adb", "serial"):
                arguments += ["--" + name, "unused"]
            with patch.object(sys, "argv", arguments), patch.object(probe, "verify") as verify:
                with self.assertRaises(SystemExit) as result:
                    probe.main()
            self.assertEqual(result.exception.code, 2)
            verify.assert_not_called()

    def test_page_round_pressure_excludes_target(self):
        receipt, raw = resource_fixture()
        selected = probe.select_resources(receipt, raw, 4096)
        self.assertEqual(selected[0]["bytes"], 70000)
        self.assertEqual(selected[0]["mappedBytes"], 73728)
        self.assertEqual(sum(item["mappedBytes"] for item in selected[1:]), 1105920)
        self.assertLess(sum(item["bytes"] for item in selected[1:]), probe.IDLE_BUDGET)
        receipt, raw = resource_fixture(pressure_count=17)
        with self.assertRaisesRegex(ValueError, "other lease"):
            probe.select_resources(receipt, raw, 4096)
        self.assertEqual(len(probe.select_resources(receipt, raw, 16384)), 18)

    def test_target_must_cross_chunk_and_need_post_release_pressure(self):
        for size, message in [(65536, "exceed 65536"), (probe.IDLE_BUDGET + 1, "fit the idle budget")]:
            receipt, raw = resource_fixture(size)
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, message):
                probe.select_resources(receipt, raw, 4096)
        for size in (0, 3000):
            receipt, raw = resource_fixture()
            with self.subTest(page=size), self.assertRaisesRegex(ValueError, "page size"):
                probe.select_resources(receipt, raw, size)

    def test_chunk_policy_order_completeness_and_digest(self):
        original, raw = resource_fixture()
        mutations = [("chunk", 2), ("bytes", 65535), ("lifetime", "pinned-unproven-unwind"),
                     ("resourceSha256", "0" * 64), ("sha256", "0" * 64)]
        for key, value in mutations:
            receipt = copy.deepcopy(original)
            receipt["segments"][1][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "incomplete, inconsistent or non-lease"):
                probe.select_resources(receipt, raw, 4096)
        for change in (lambda values: values.pop(1), lambda values: values.append(values[1])):
            receipt = copy.deepcopy(original)
            change(receipt["segments"])
            with self.assertRaises(ValueError):
                probe.select_resources(receipt, raw, 4096)

    def test_descriptor_must_be_unique_and_fully_rx(self):
        identity = bytes(range(16)).hex()
        descriptor = bytes.fromhex(identity) + struct.pack("<II", 70000, 1)
        image = bytearray(test_seal_cse.elf())
        image[0x1100:0x1118] = descriptor
        self.assertEqual(probe.descriptor_address(image, identity, 70000), 0x1100)
        changed = bytearray(image); changed[0x1200:0x1218] = descriptor
        with self.assertRaisesRegex(ValueError, "one exact"):
            probe.descriptor_address(changed, identity, 70000)
        image[0x1100:0x1118] = bytes(24)
        for offset in (0x300, 0x1ff0):
            changed = bytearray(image); changed[offset:offset+24] = descriptor
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "fully inside RX"):
                probe.descriptor_address(changed, identity, 70000)

    def test_hidden_offsets_require_exact_final_executable_bytes(self):
        image = test_seal_cse.elf()
        symbols = {name: 0x1000 + ordinal * 4 for ordinal, name in enumerate(
            ("ndkp_qseg_acquire_v1", "ndkp_qseg_release_v1", "ndkp_qseg_stats_v1", "JNI_OnLoad"))}
        spans = probe.bind_executable(image, image, symbols)
        self.assertEqual(spans[0]["address"], 0x1000)
        changed = bytearray(image); changed[0x1100] ^= 1
        with self.assertRaisesRegex(ValueError, "load bytes differ"):
            probe.bind_executable(image, changed, symbols)
        symbols["ndkp_qseg_acquire_v1"] = 0x300
        with self.assertRaisesRegex(ValueError, "non-RX"):
            probe.bind_executable(image, image, symbols)

    def test_generated_header_preserves_target_chunks(self):
        receipt, raw = resource_fixture()
        selected = probe.select_resources(receipt, raw, 4096)
        for ordinal, item in enumerate(selected):
            item["address"] = 0x1100 + ordinal * 24
        symbols = {name: 0x1200 for name in
                   ("ndkp_qseg_acquire_v1", "ndkp_qseg_release_v1", "ndkp_qseg_stats_v1", "JNI_OnLoad")}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache_plan.h"
            probe.write_header(path, selected, [{"address": 0x1000, "bytes": 4096, "sha256": "ab" * 32}], symbols, 4096)
            text = path.read_text(encoding="utf-8")
        self.assertIn("{65536, 4464,", text)
        self.assertIn("ExpectedPageSize = 4096", text)
        self.assertIn("Offset_ndkp_qseg_release_v1 = 4608", text)

    def test_fixture_is_bounded_and_has_real_string_consumption(self):
        source = large_fixture.fixture_source(14, 256)
        self.assertEqual(source.count("@dex2c"), 15)
        self.assertEqual(source.count("x = (x * 1664525 +"), 14 * 256 + 1)
        self.assertIn('return "large-vm-fixture".length()', source)
        self.assertIn("if (marker() != 16)", source)
        for methods, rounds in ((1, 256), (25, 256), (14, 63), (14, 1025)):
            with self.subTest(methods=methods, rounds=rounds), self.assertRaises(ValueError):
                large_fixture.fixture_source(methods, rounds)


if __name__ == "__main__":
    unittest.main()
