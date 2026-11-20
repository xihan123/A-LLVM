import copy
import os
import unittest

import cache_recovery as recovery
import runtime_cache as cache
import test_runtime_cache as fixtures


class CacheRecoveryTests(unittest.TestCase):
    # Reuse only the synthetic build grammar, not its unrelated inherited tests.
    setUp = fixtures.RuntimeCacheTests.setUp
    start = fixtures.RuntimeCacheTests.start
    clear_outputs = fixtures.RuntimeCacheTests.clear_outputs
    build = fixtures.RuntimeCacheTests.build

    def prepare(self):
        first, first_path = self.start("cold")
        self.build(first, 0)
        self.cold_path = self.root / "cold"
        self.cold = cache.snapshot(self.fixture, first_path, self.cold_path)
        self.clear_outputs()
        self.targets = {row["log"]: (key, row) for key, row in self.cold["runtimeTargets"].items()}
        for log in recovery.MISSES:
            artifact = self.entry(log) / "artifact"
            changed = bytearray(artifact.read_bytes())
            changed[len(changed) // 2] ^= 1
            artifact.write_bytes(changed)
        self.begin_path = self.root / "recovery-begin.json"

    def entry(self, log):
        return self.fixture / "native/runtime-cache" / self.targets[log][0]

    def rebuild(self, ticket):
        # Synthetic production outcome: four cache misses repopulate, other outputs copy2 their hits.
        for log in recovery.MISSES:
            key, _ = self.targets[log]
            original = self.cold_path / "fixture/native/runtime-cache" / key / "artifact"
            (self.entry(log) / "artifact").write_bytes(original.read_bytes())
        receipt = self.build(ticket, 1)
        for log in recovery.MISSES:
            (self.fixture / "native" / log).write_text("", encoding="utf-8")
            artifact = self.fixture / "native" / cache.RUNTIME[log]
            artifact.write_bytes(artifact.read_bytes())
        return receipt

    def pair(self):
        self.prepare()
        self.ticket = recovery.begin(self.fixture, self.cold_path, self.begin_path)
        self.receipt = self.rebuild(self.ticket)
        self.recovery_path = self.root / "recovery"
        self.recovered = recovery.snapshot(self.fixture, self.begin_path, self.cold_path, self.recovery_path)
        return recovery.compare(self.cold, self.recovered, self.cold_path)

    def test_fixed_four_misses_and_twenty_five_hits_recover_all_twenty_nine_entries(self):
        result = self.pair()
        self.assertEqual((result["coldHits"], result["recoveryHits"], result["recoveryMisses"]), (0, 25, 4))
        self.assertEqual(result["expectedMisses"], list(recovery.MISSES))
        self.assertEqual(len(result["runtimeTargets"]), 29)
        self.assertEqual(self.cold["runtimeTargets"], self.recovered["runtimeTargets"])
        self.assertEqual(cache.inventory_from_capture(self.cold["capture"]),
                         cache.inventory_from_capture(self.recovered["capture"]))
        self.assertNotEqual(self.ticket["cacheBefore"], cache.inventory_from_capture(self.cold["capture"]))
        self.assertEqual(set(result["corruptions"]), set(recovery.MISSES))
        self.assertFalse(list(self.recovery_path.rglob("*.JKS")))
        # Re-reading validates the frozen files and their manifests again.
        cold = cache.inspect_snapshot(self.cold_path)
        reread = recovery.inspect_snapshot(self.recovery_path, cold, self.cold_path)
        self.assertTrue(recovery.compare(cold, reread, self.cold_path)["passed"])

    def test_original_cold_warm_entrypoints_reject_recovery_tickets(self):
        self.pair()
        with self.assertRaisesRegex(ValueError, "dedicated"):
            cache.snapshot(self.fixture, self.begin_path, self.root / "ordinary")
        self.assertFalse((self.root / "ordinary").exists())
        with self.assertRaisesRegex(ValueError, "dedicated"):
            cache.inspect_snapshot(self.recovery_path)
        with self.assertRaisesRegex(ValueError, "dedicated"):
            cache.compare(self.cold, self.recovered)

    def test_both_ir_stages_must_hit_with_unchanged_inputs_keys_and_outputs(self):
        self.pair()
        native = self.fixture / "native"
        for log in ("cse-vmp.log", "cse-optimize.log"):
            self.assertNotIn(log, recovery.MISSES)
            key, target = self.targets[log]
            self.assertEqual(self.recovered["runtimeTargets"][key], target)
            self.assertEqual(cache.file_hash(native / target["artifact"]), target["sha256"])
            path = native / log
            original = path.read_text(encoding="utf-8")
            self.assertIsNotNone(cache.HIT.fullmatch(original))
            path.write_text("", encoding="utf-8")
            with self.subTest(log=log), self.assertRaisesRegex(ValueError, "exactly one runtime hit"):
                cache.check_cache(self.ticket, self.receipt, native, expected_misses=recovery.MISSES)
            path.write_text(original, encoding="utf-8")
            for field in ("inputs", "sha256", "command", "key"):
                changed = copy.deepcopy(self.recovered)
                row = changed["runtimeTargets"][key]
                if field == "key":
                    changed["runtimeTargets"]["0" * 64] = changed["runtimeTargets"].pop(key)
                elif field == "command":
                    row[field].append("-DCHANGED")
                else:
                    row[field] += "changed"
                with self.subTest(log=log, field=field), self.assertRaisesRegex(ValueError, "runtime command/artifact"):
                    recovery.compare(self.cold, changed, self.cold_path)

    def test_randomized_optimized_ir_and_downstream_object_key_migration_are_rejected(self):
        self.pair()
        native = self.fixture / "native"
        optimized = native / "cse-runtime.ll"
        optimized.write_bytes(optimized.read_bytes() + b"\n; different randomized post-protection\n")
        opt_hash = cache.file_hash(optimized)
        opt_entry = self.entry("cse-optimize.log")
        (opt_entry / "artifact").write_bytes(optimized.read_bytes())
        (opt_entry / "sha256").write_text(opt_hash + "\n", encoding="utf-8")
        (native / "cse-optimize.log").write_text("", encoding="utf-8")
        inputs, command = cache.runtime_commands(self.ticket, self.receipt, native)["cse-object.log"]
        new_key = cache.cache_key(inputs, command)
        self.assertNotEqual(new_key, self.targets["cse-object.log"][0])
        entry = native / "runtime-cache" / new_key
        entry.mkdir()
        artifact = native / cache.RUNTIME["cse-object.log"]
        artifact.write_bytes(b"new object for the changed optimized IR")
        (entry / "artifact").write_bytes(artifact.read_bytes())
        (entry / "sha256").write_text(cache.file_hash(artifact) + "\n", encoding="utf-8")
        self.assertEqual(len(cache.inventory(native / "runtime-cache", private=True)), 60)
        with self.assertRaisesRegex(ValueError, "exactly one runtime hit: cse-optimize.log"):
            cache.check_cache(self.ticket, self.receipt, native, expected_misses=recovery.MISSES)
        changed = copy.deepcopy(self.recovered)
        for path in entry.iterdir():
            changed["capture"]["files"]["fixture/native/runtime-cache/" + new_key + "/" + path.name] = cache.file_hash(path)
        with self.assertRaisesRegex(ValueError, "all 29 cold entries"):
            recovery.compare(self.cold, changed, self.cold_path)

    def test_begin_requires_fresh_output_absence_and_a_new_ticket(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "outside"):
            recovery.begin(self.fixture, self.cold_path, self.cold_path / "bad-ticket.json")
        self.assertFalse((self.cold_path / "bad-ticket.json").exists())
        stale = self.fixture / "native/object.log"
        stale.write_text("stale", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "regenerable"):
            recovery.begin(self.fixture, self.cold_path, self.begin_path)
        self.assertFalse(self.begin_path.exists())
        stale.unlink()
        recovery.begin(self.fixture, self.cold_path, self.begin_path)
        with self.assertRaisesRegex(ValueError, "must be new"):
            recovery.begin(self.fixture, self.cold_path, self.begin_path)

    def test_begin_requires_exactly_one_changed_byte_in_each_nonempty_artifact(self):
        self.prepare()
        log = recovery.MISSES[0]
        artifact = self.entry(log) / "artifact"
        changed = artifact.read_bytes()
        original = (self.cold_path / "fixture/native/runtime-cache" / self.targets[log][0] / "artifact").read_bytes()
        two = bytearray(changed)
        two[0] ^= 1
        for bad in (original, changed + b"x", b"", bytes(two)):
            with self.subTest(bad=bad):
                artifact.write_bytes(bad)
                with self.assertRaises(ValueError):
                    recovery.begin(self.fixture, self.cold_path, self.begin_path)
                self.assertFalse(self.begin_path.exists())
        artifact.write_bytes(changed)
        self.assertIn("cacheRecovery", recovery.begin(self.fixture, self.cold_path, self.begin_path))

    def test_begin_preserves_all_receipt_bytes_and_every_unselected_cache_file(self):
        self.prepare()
        hit = next(log for log in cache.RUNTIME if log not in recovery.MISSES)
        for path in (self.entry(recovery.MISSES[0]) / "sha256", self.entry(hit) / "artifact",
                     self.entry(hit) / "sha256", self.entry(hit) / "extra"):
            with self.subTest(path=path):
                original = path.read_bytes() if path.exists() else None
                # Even receipt whitespace changes must be retained as a failed injection.
                path.write_bytes((original or b"") + b"\n")
                with self.assertRaisesRegex(ValueError, "preserve every cold cache file"):
                    recovery.begin(self.fixture, self.cold_path, self.begin_path)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
        missing = self.entry(hit) / "artifact"
        original = missing.read_bytes()
        missing.unlink()
        with self.assertRaisesRegex(ValueError, "preserve every cold cache file"):
            recovery.begin(self.fixture, self.cold_path, self.begin_path)
        missing.write_bytes(original)

    def test_begin_and_readers_rehash_the_full_cold_snapshot(self):
        self.prepare()
        target = self.cold_path / "fixture/native/vmp.log"
        original = target.read_bytes()
        target.write_bytes(b"altered cold evidence")
        with self.assertRaisesRegex(ValueError, "manifest"):
            recovery.begin(self.fixture, self.cold_path, self.begin_path)
        target.write_bytes(original)
        ticket = recovery.begin(self.fixture, self.cold_path, self.begin_path)
        ticket["cacheRecovery"]["coldCaptureSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "snapshot digest"):
            recovery.validate_ticket(ticket, self.cold, self.cold_path)

    def test_each_compile_miss_and_every_remaining_exact_hit_is_mandatory(self):
        self.pair()
        native = self.fixture / "native"
        for log in cache.RUNTIME:
            path = native / log
            original = path.read_text(encoding="utf-8")
            if log in recovery.MISSES:
                bad = "dex2c: runtime cache hit; sha256=" + cache.file_hash(native / cache.RUNTIME[log]) + "\n"
                message = "unexpected runtime hit"
            else:
                bad, message = "", "exactly one runtime hit"
            path.write_text(bad, encoding="utf-8")
            with self.subTest(log=log), self.assertRaisesRegex(ValueError, message):
                cache.check_cache(self.ticket, self.receipt, native, expected_misses=recovery.MISSES)
            path.write_text(original, encoding="utf-8")

    def test_rebuilt_artifacts_require_new_timestamps_live_and_frozen(self):
        self.pair()
        old = self.ticket["startedNs"] - 1000000
        for log in recovery.MISSES:
            name = "native/" + cache.RUNTIME[log]
            paths = (self.fixture / name, self.recovery_path / "fixture" / name)
            previous = [(path.stat().st_atime_ns, path.stat().st_mtime_ns) for path in paths]
            for path in paths:
                os.utime(path, ns=(old, old))
            with self.subTest(log=log):
                with self.assertRaisesRegex(ValueError, "stale"):
                    recovery.snapshot(self.fixture, self.begin_path, self.cold_path, self.root / "stale")
                with self.assertRaisesRegex(ValueError, "stale"):
                    recovery.inspect_snapshot(self.recovery_path, self.cold, self.cold_path)
            for path, timestamps in zip(paths, previous):
                os.utime(path, ns=timestamps)
        for log in set(cache.RUNTIME) - set(recovery.MISSES):
            path = self.recovery_path / "fixture/native" / cache.RUNTIME[log]
            self.assertLess(path.stat().st_mtime_ns, self.ticket["startedNs"])
        self.assertTrue(recovery.compare(self.cold, self.recovered, self.cold_path)["passed"])

    def test_ticket_pins_the_exact_four_corruptions_and_full_before_inventory(self):
        self.pair()
        log = recovery.MISSES[0]
        changes = (
            lambda ticket: ticket.update(fixture=str(self.root / "another")),
            lambda ticket: ticket.update(token=self.cold["ticket"]["token"]),
            lambda ticket: ticket.update(startedNs=self.cold["capture"]["capturedNs"]),
            lambda ticket: ticket["cacheRecovery"].update(schemaVersion=1),
            lambda ticket: ticket["cacheRecovery"].update(expectedMisses=[
                "apkverify-sha256.c.log", "cse-optimize.log", "cse-object.log", "qseg-runtime.log"]),
            lambda ticket: ticket["cacheRecovery"]["expectedMisses"].pop(),
            lambda ticket: ticket["cacheRecovery"]["corruptions"].pop(log),
            lambda ticket: ticket["cacheRecovery"]["corruptions"][log].update(key="0" * 64),
            lambda ticket: ticket["cacheRecovery"]["corruptions"][log].update(offset=-1),
            lambda ticket: ticket["cacheRecovery"]["corruptions"][log].update(newByte=256),
            lambda ticket: ticket["cacheRecovery"]["corruptions"][log].update(afterSha256="0" * 64),
            lambda ticket: ticket.update(cacheBefore=cache.inventory_from_capture(self.cold["capture"])),
        )
        for change in changes:
            ticket = copy.deepcopy(self.ticket)
            change(ticket)
            with self.subTest(change=change), self.assertRaises(ValueError):
                recovery.validate_ticket(ticket, self.cold, self.cold_path)

    def test_recovery_keeps_fixed_inputs_runtime_commands_and_business_diversity_contracts(self):
        self.pair()
        symbol = next(iter(self.cold[cache.FIELDS[0]]))
        key = next(iter(self.recovered["runtimeTargets"]))
        changes = (
            lambda row: row["configuration"].update(minSdk=27),
            lambda row: row["compilerIdentity"].update(compilerSha256="changed"),
            lambda row: row["inputClasses"]["baseline"].update({"sample/Run.class": "changed"}),
            lambda row: row["runtimeTargets"][key]["command"].append("-DCHANGED"),
            lambda row: row["business"].update({"protected.raw.ll": self.cold["business"]["protected.raw.ll"]}),
        )
        for change in changes:
            row = copy.deepcopy(self.recovered)
            change(row)
            with self.subTest(change=change), self.assertRaises(ValueError):
                recovery.compare(self.cold, row, self.cold_path)
        for field in cache.FIELDS:
            row = copy.deepcopy(self.recovered)
            row[field][symbol] = self.cold[field][symbol]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "method material did not change"):
                recovery.compare(self.cold, row, self.cold_path)

    def test_failed_repopulation_and_coordinated_cache_replacement_do_not_pass(self):
        self.pair()
        log = recovery.MISSES[0]
        native = self.fixture / "native"
        entry = self.entry(log)
        original = (entry / "artifact").read_bytes()
        (entry / "artifact").write_bytes(b"corruption remains")
        with self.assertRaisesRegex(ValueError, "cache artifact/receipt"):
            cache.check_cache(self.ticket, self.receipt, native, expected_misses=recovery.MISSES)
        (entry / "artifact").write_bytes(original)
        changed = copy.deepcopy(self.recovered)
        cache_file = "fixture/native/runtime-cache/" + self.targets[log][0] + "/artifact"
        changed["capture"]["files"][cache_file] = cache.digest(b"coordinated new output")
        with self.assertRaisesRegex(ValueError, "all 29 cold entries"):
            recovery.compare(self.cold, changed, self.cold_path)

    def test_frozen_recovery_manifest_detects_later_tampering(self):
        self.pair()
        (self.recovery_path / "fixture/native/cse-object.log").write_text("forged", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest"):
            recovery.inspect_snapshot(self.recovery_path, self.cold, self.cold_path)


if __name__ == "__main__":
    unittest.main()
