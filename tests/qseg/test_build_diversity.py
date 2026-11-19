import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import build_diversity as diversity


def clone_body(symbol, key, constants=(3, 7)):
    salt = f"@vmp_interpreter_clone_salt_{symbol}_k{key}"
    text = f"  %entrysalt = load volatile i64, ptr {salt}, align 8\n  br label %c0\n"
    for index, constant in enumerate(constants):
        following = f"c{index + 1}" if index + 1 < len(constants) else "fail"
        text += f"""
c{index}:
  %a{index} = load volatile i64, ptr {salt}, align 8
  %b{index} = load volatile i64, ptr {salt}, align 8
  %c{index} = trunc i64 %a{index} to i8
  %d{index} = trunc i64 %b{index} to i8
  %e{index} = xor i8 %opcode, %c{index}
  %f{index} = xor i8 {constant}, %d{index}
  %g{index} = icmp eq i8 %e{index}, %f{index}
  br i1 %g{index}, label %h{index}, label %{following}
"""
    for index in range(len(constants)):
        text += f"\nh{index}:\n  ret void\n"
    return text + ("\nfail:\n  call void @_Z21vm_dump_fault_contextPKcmm"
                   "(ptr nonnull poison, i64 poison, i64 poison)\n  unreachable\n")


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def write_jar(path, classes):
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in classes.items():
            archive.writestr(name, value)


class BuildDiversityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        methods = ("sample/Logic.moving()I", "kfixture/Fixture.stuck()I")
        self.targets = {method: "d2c_" + diversity.digest(method.encode())[:24] for method in methods}
        self.original = {"sample/Logic.class": b"logic", "sample/Run.class": b"java-entry",
                         "kfixture/Fixture.class": b"kotlin", "kfixture/FixtureKt.class": b"kotlin-entry"}
        self.contract = {"schemaVersion": 1,
                         "methods": [{"method": method, "symbol": symbol}
                                     for method, symbol in self.targets.items()],
                         "inputClasses": {"baseline": {name: diversity.digest(raw)
                                                       for name, raw in self.original.items()},
                                          "common": {"runtime/Helper.class": diversity.digest(b"runtime")}}}
        self.contract_path = self.root / "expected.json"
        write_json(self.contract_path, self.contract)
        self.directories = []
        for build in range(3):
            directory = self.root / str(build)
            (directory / "native").mkdir(parents=True)
            (directory / "generated").mkdir()
            self.directories.append(directory)
            write_jar(directory / "original.jar", self.original)
            write_jar(directory / "protected.jar", self.original)
            write_jar(directory / "generated/classes.jar", self.original)
            write_jar(directory / "common.jar", {"runtime/Helper.class": b"runtime"})
            write_json(directory / "inputs.json", {"mains": sorted(diversity.MAINS),
                       "baseline": ["original.jar"], "protected": ["protected.jar"], "common": ["common.jar"]})
            write_json(directory / "generated/selection.json",
                       {"methods": [dict(row, protection="vmp") for row in self.contract["methods"]]})
            rows, sizes, ir = [], {}, ""
            for index, symbol in enumerate(self.targets.values()):
                content = diversity.digest(f"{build}:{index}".encode())
                rows.append({"kind": 1, "name": symbol, "id": f"{build * 10 + index:032x}",
                             "resourceSha256": content, "chunk": 0, "bytes": 17,
                             "lifetime": "lease-v1", "sha256": content})
                sizes[symbol] = 17
                key = f"{build * 10 + index + 1:x}"
                body = clone_body(symbol, key, (build + 1, build + 8))
                ir += f"define internal void @vm_interpreter_{symbol}_k{key}() {{\n{body}}}\n"
            (directory / "native/protected.raw.ll").write_text(ir, encoding="utf-8")
            write_json(directory / "native/segments.json", {"segments": rows})
            write_json(directory / "native/protection.json", {"symbols": list(self.targets.values()),
                       "methodBytecodeBytes": sizes, "certificateSha256": "same",
                       "classesSha256": diversity.digest((directory / "generated/classes.jar").read_bytes()),
                       "containerSha256": str(build), "librarySha256": str(build)})
            write_json(directory / "device-results.json", {"results": [
                {"mode": mode, "main": main, "output": main + ":ok"}
                for mode in ("baseline", "protected") for main in sorted(diversity.MAINS)]})

    def builds(self):
        return [diversity.inspect(directory, self.contract) for directory in self.directories]

    def test_complete_contract_passes(self):
        self.assertEqual(diversity.load_contract(self.contract_path), self.contract)
        self.assertEqual(diversity.compare(self.builds(), self.contract),
                         {field: 2 for field in diversity.FIELDS})

    def test_moving_target_cannot_hide_stuck_target_in_any_dimension(self):
        symbol = list(self.targets.values())[1]
        for field in diversity.FIELDS:
            with self.subTest(field=field):
                builds = self.builds()
                for row in builds:
                    row[field][symbol] = builds[0][field][symbol]
                # The former aggregate gate still passes because the first target moves.
                self.assertGreater(sum(len({row[field][name] for row in builds}) == 3
                                       for name in builds[0][field]), 0)
                with self.assertRaisesRegex(ValueError, "stuck.*" + field):
                    diversity.compare(builds, self.contract)

    def test_pairwise_collision_fails_each_dimension(self):
        symbol = next(iter(self.targets.values()))
        for field in diversity.FIELDS:
            with self.subTest(field=field):
                builds = self.builds()
                builds[2][field][symbol] = builds[1][field][symbol]
                with self.assertRaisesRegex(ValueError, "not three distinct"):
                    diversity.compare(builds, self.contract)

    def test_joint_omission_cannot_shrink_expected_denominator(self):
        builds = self.builds()
        symbol = next(iter(self.targets.values()))
        for row in builds:
            for field in diversity.FIELDS:
                del row[field][symbol]
        with self.assertRaisesRegex(ValueError, "missing="):
            diversity.compare(builds, self.contract)
        path = self.directories[0] / "generated/selection.json"
        selection = diversity.read_json(path)
        selection["methods"].pop()
        write_json(path, selection)
        with self.assertRaisesRegex(ValueError, "selection differs"):
            diversity.inspect(self.directories[0], self.contract)

    def test_contract_rejects_duplicates_empty_and_bad_symbols(self):
        for change in (lambda c: c["methods"].append(c["methods"][0]),
                       lambda c: c["methods"][0].update(symbol="d2c_wrong"),
                       lambda c: c["inputClasses"].update(baseline={}),
                       lambda c: c["inputClasses"]["baseline"].update({"bad.class": "no"})):
            contract = copy.deepcopy(self.contract)
            change(contract)
            write_json(self.contract_path, contract)
            with self.assertRaises(ValueError):
                diversity.load_contract(self.contract_path)
        self.contract_path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            diversity.load_contract(self.contract_path)

    def test_all_java_and_kotlin_classes_are_compared(self):
        for name in ("sample/Run.class", "kfixture/Fixture.class"):
            with self.subTest(name=name):
                changed = dict(self.original, **{name: b"changed"})
                write_jar(self.directories[0] / "original.jar", changed)
                with self.assertRaisesRegex(ValueError, "input class bytes differ: baseline"):
                    diversity.inspect(self.directories[0], self.contract)

    def test_duplicate_zip_entry_and_classpath_class_fail(self):
        path = self.root / "duplicate.jar"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.class", b"one")
                archive.writestr("one.class", b"two")
        with self.assertRaisesRegex(ValueError, "duplicate ZIP entry"):
            diversity.class_manifest([path])
        with self.assertRaisesRegex(ValueError, "duplicate class"):
            diversity.class_manifest([self.directories[0] / "original.jar"] * 2)

    def test_protected_snapshot_must_match_this_build_generated_receipt(self):
        directory = self.directories[0]
        write_jar(directory / "protected.jar", {"wrong.class": b"wrong"})
        with self.assertRaisesRegex(ValueError, "protected class bytes differ"):
            diversity.inspect(directory, self.contract)
        write_jar(directory / "protected.jar", self.original)
        write_jar(directory / "generated/classes.jar", {"wrong.class": b"wrong"})
        with self.assertRaisesRegex(ValueError, "protected class bytes differ"):
            diversity.inspect(directory, self.contract)

    def test_duplicate_receipt_symbol_and_clone_fail(self):
        directory = self.directories[0]
        path = directory / "native/protection.json"
        receipt = diversity.read_json(path)
        receipt["symbols"].append(receipt["symbols"][0])
        write_json(path, receipt)
        with self.assertRaisesRegex(ValueError, "duplicate receipt symbols"):
            diversity.inspect(directory, self.contract)
        ir = (directory / "native/protected.raw.ll").read_text()
        with self.assertRaisesRegex(ValueError, "duplicate VM clone"):
            diversity.clone_material(ir + ir, self.targets.values())

    def test_chunk_groups_reject_duplicates_gaps_conflicts_and_short_nonfinal(self):
        symbol = next(iter(self.targets.values()))
        row = diversity.read_json(self.directories[0] / "native/segments.json")["segments"][0]
        rows = [dict(row, bytes=65536), dict(row, chunk=1, bytes=9)]
        sizes = {symbol: 65545}
        self.assertEqual(len(diversity.resource_groups(rows, sizes, {symbol})), 1)
        for change in (lambda r: r[1].update(chunk=0), lambda r: r[1].update(chunk=2),
                       lambda r: r[1].update(id="f" * 32),
                       lambda r: r[1].update(resourceSha256="f" * 64),
                       lambda r: r[0].update(bytes=65535)):
            broken = copy.deepcopy(rows)
            change(broken)
            with self.assertRaises(ValueError):
                diversity.resource_groups(broken, sizes, {symbol})

    def test_exact_unique_baseline_and_protected_semantics_required(self):
        result = diversity.read_json(self.directories[0] / "device-results.json")
        for change in (lambda rows: rows.pop(), lambda rows: rows.append(rows[0]),
                       lambda rows: rows[0].update(main="wrong.Main"),
                       lambda rows: rows[0].update(mode="protected"),
                       lambda rows: rows[0].update(output="different")):
            broken = copy.deepcopy(result)
            change(broken["results"])
            with self.assertRaises(ValueError):
                diversity.device_semantics(broken)
        builds = self.builds()
        builds[2]["semantics"]["sample.Run"] = "different"
        with self.assertRaisesRegex(ValueError, "semantics differ"):
            diversity.compare(builds, self.contract)

    def test_dispatch_follows_chain_and_ignores_unrelated_xor(self):
        symbol = next(iter(self.targets.values()))
        body = clone_body(symbol, "1")
        self.assertEqual(diversity.dispatch_constants(body, symbol, "1"), [3, 7])
        extra = body.replace("h0:\n", "h0:\n  %unrelated = xor i8 19, %opcode\n")
        self.assertEqual(diversity.dispatch_constants(extra, symbol, "1"), [3, 7])
        for broken in (body.replace("label %c1", "label %fail"),
                       body.replace("label %fail", "label %c0"),
                       body.replace("%e1 = xor i8 %opcode", "%e1 = xor i8 %other"),
                       body.replace("%d1 = trunc i64 %b1", "%d1 = trunc i64 %a1"),
                       body.replace("label %h1", "label %missing"),
                       body.replace("ptr @vmp_interpreter_clone_salt_", "ptr @other_salt_", 1)):
            with self.assertRaises(ValueError):
                diversity.dispatch_constants(broken, symbol, "1")

    def test_dispatch_missing_salt_cannot_shorten_head_middle_or_tail(self):
        symbol = next(iter(self.targets.values()))
        body = clone_body(symbol, "1", (3, 7, 11))
        for index in range(3):
            with self.subTest(block=index):
                start = body.index(f"\nc{index}:\n")
                end = body.index("\n", body.index("  br i1", start))
                block = body[start:end]
                changed = block.replace("@vmp_interpreter_clone_salt_", "@other_salt_")
                with self.assertRaises(ValueError):
                    diversity.dispatch_constants(body[:start] + changed + body[end:], symbol, "1")
                missing_loads = "\n".join(line for line in block.split("\n") if "load volatile" not in line)
                with self.assertRaises(ValueError):
                    diversity.dispatch_constants(body[:start] + missing_loads + body[end:], symbol, "1")
        for broken in (body.replace("label %fail", "label %h0"),
                       body.replace("call void @_Z21vm_dump_fault_contextPKcmm"
                                    "(ptr nonnull poison, i64 poison, i64 poison)\n  unreachable", "ret void")):
            with self.assertRaises(ValueError):
                diversity.dispatch_constants(broken, symbol, "1")

    def test_cli_preserves_previous_report_and_writes_no_success_on_failure(self):
        output = self.root / "report.json"
        output.write_text("previous", encoding="utf-8")
        argv = ["build_diversity.py", "--expected-contract", str(self.contract_path), "--output", str(output)]
        for directory in self.directories:
            argv += ["--fixtures", str(directory)]
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(ValueError, "must be new"):
            diversity.main()
        self.assertEqual(output.read_text(), "previous")
        output.unlink()
        write_jar(self.directories[0] / "original.jar", {"changed.class": b"changed"})
        with patch.object(sys, "argv", argv), self.assertRaises(ValueError):
            diversity.main()
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
