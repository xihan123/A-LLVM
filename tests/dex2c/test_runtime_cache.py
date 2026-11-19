import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import runtime_cache as cache

# Share the LLVM clone fixture grammar with the existing diversity validator.
from test_build_diversity import clone_body, write_jar


class RuntimeCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = self.root / "scratch"
        self.contract_path = self.root / "contract.json"
        methods = ("sample/Run.first()I", "kfixture/Fixture.second()I")
        self.methods = [{"method": name, "symbol": "d2c_" + cache.digest(name.encode())[:24]}
                        for name in methods]
        self.original = {"sample/Run.class": b"java", "kfixture/Fixture.class": b"kotlin"}
        self.common_classes = {"runtime/Helper.class": b"runtime"}
        self.contract = {"schemaVersion": 1, "methods": self.methods, "inputClasses": {
            "baseline": {name: cache.digest(raw) for name, raw in self.original.items()},
            "common": {name: cache.digest(raw) for name, raw in self.common_classes.items()}}}
        cache.write_json(self.contract_path, self.contract)
        self.prebuilt = self.root / "ndk/toolchains/llvm/prebuilt" / (
            "windows-x86_64" if os.name == "nt" else "linux-x86_64")
        self.suffix = ".exe" if os.name == "nt" else ""
        for path in (self.prebuilt / ("bin/clang" + self.suffix),
                     self.prebuilt / ("bin/ld.lld" + self.suffix),
                     self.prebuilt / ("bin/llvm-strip" + self.suffix),
                     self.root / "ndk/source.properties", self.prebuilt / "lib/clang/21/include/stddef.h",
                     self.prebuilt / "sysroot/usr/include/stdio.h"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())
        self.common_jar = self.root / "shared-common.jar"
        write_jar(self.common_jar, self.common_classes)

    def start(self, phase):
        path = self.root / (phase + "-begin.json")
        ticket = cache.begin(self.fixture, phase, self.contract_path, path)
        return ticket, path

    def clear_outputs(self):
        for path in cache.fresh_files(self.fixture):
            if path.is_file():
                path.unlink()

    def build(self, ticket, number):
        self.fixture.mkdir(exist_ok=True)
        (self.fixture / "test.JKS").write_bytes(b"private-do-not-copy")
        (self.fixture / "test.p12").write_bytes(b"private-do-not-copy")
        (self.fixture / "test.der").write_bytes(b"public-certificate")
        for name in cache.FRESH_FILES:
            path = self.fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + ":" + str(number)).encode())
        native = self.fixture / "native"
        runtime = native / "a_llvm"
        runtime.mkdir(exist_ok=True)
        (runtime / "apkverify_sources.txt").write_text("\n".join(cache.MBEDTLS) + "\n", encoding="utf-8")
        (runtime / "runtime.cpp").write_bytes(b"pinned-runtime")
        (native / "signing-cert.der").write_bytes(b"public-certificate")
        (native / "compiler.log").write_text("clang version 21.1.0\n", encoding="utf-8")
        for name in cache.BUSINESS_LOGS:
            if name != "compiler":
                (native / (name + ".log")).write_text("", encoding="utf-8")
        for name in cache.RUNTIME.values():
            (native / name).write_bytes(("runtime:" + name).encode())
        write_jar(self.fixture / "original.jar", self.original)
        write_jar(self.fixture / "generated/classes.jar", {"protected/Run.class": b"protected"})
        cache.write_json(self.fixture / "inputs.json", {"mains": sorted(cache.MAINS),
            "baseline": ["original.jar"], "protected": ["generated/classes.jar"],
            "common": [str(self.common_jar)]})
        cache.write_json(self.fixture / "generated/selection.json", {"methods": [
            dict(row, protection="vmp") for row in self.methods]})
        ir, resources, sizes = "", [], {}
        for index, row in enumerate(self.methods):
            symbol = row["symbol"]
            key = f"{number * 10 + index + 1:x}"
            ir += (f"define internal void @vm_interpreter_{symbol}_k{key}() {{\n" +
                   clone_body(symbol, key, (number + 1, number + 8)) + "}\n")
            content = cache.digest(f"{number}:{symbol}".encode())
            resources.append({"kind": 1, "name": symbol, "id": f"{number * 10 + index:032x}",
                "resourceSha256": content, "chunk": 0, "bytes": 17,
                "lifetime": "lease-v1", "sha256": content})
            sizes[symbol] = 17
        (native / "protected.raw.ll").write_text(ir, encoding="utf-8")
        cache.write_json(native / "segments.json", {"segments": resources})
        library = native / "jniLibs/test-abi/libdex2c_semantics.so"
        container = native / "assets/dex2c_semantics.qseg"
        for path in (library, container, native / "staging/protected/segment.bin"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((str(number) + path.name).encode())
        identity = {"version": "clang version 21.1.0"}
        for key, path in (("compilerSha256", self.prebuilt / ("bin/clang" + self.suffix)),
                          ("linkerSha256", self.prebuilt / ("bin/ld.lld" + self.suffix)),
                          ("stripSha256", self.prebuilt / ("bin/llvm-strip" + self.suffix)),
                          ("ndkPropertiesSha256", self.root / "ndk/source.properties")):
            identity[key] = cache.file_hash(path)
        trees = [cache.inventory(path) for path in (runtime, self.prebuilt / "lib/clang/21/include",
                                                   self.prebuilt / "sysroot/usr/include")]
        identity["runtimeFingerprint"] = cache.fingerprint_value({"prefix": [identity["compilerSha256"],
            identity["ndkPropertiesSha256"], cache.file_hash(native / "signing-cert.der")], "trees": trees}, os.sep)
        common = [str(self.prebuilt / ("bin/clang" + self.suffix)), "--driver-mode=g++",
            "--target=aarch64-linux-android26", "--sysroot=" + str(self.prebuilt / "sysroot"),
            "-resource-dir=" + str(self.prebuilt / "lib/clang/21"), "-std=gnu++17", "-fPIC",
            "-fvisibility=hidden", "-fno-exceptions", "-frtti", "-fno-fast-math", "-ffp-contract=off",
            "-ffunction-sections", "-fdata-sections", "-I" + str(self.fixture / "generated"), "-DNDKP_APK_VERIFY"]
        receipt = {"schemaVersion": 7, "segmentedData": True, "apkSignatureVerification": True,
            "nativeSymbols": [], "stringSymbols": [], "abi": "test-abi", "compilerIdentity": identity,
            "configuration": {"minSdk": 26, "library": "dex2c_semantics", "segmentedData": True,
                              "apkSignatureVerification": True, "commonArguments": common},
            "symbols": [row["symbol"] for row in self.methods], "methodBytecodeBytes": sizes}
        for key, path in (("certificateSha256", native / "signing-cert.der"),
                          ("classesSha256", self.fixture / "generated/classes.jar"),
                          ("selectionSha256", self.fixture / "generated/selection.json"),
                          ("irSha256", native / "protected.ll"), ("objectSha256", native / "protected.o"),
                          ("cseRuntimeIrSha256", native / "cse-runtime.ll"),
                          ("librarySha256", library), ("containerSha256", container),
                          ("segmentsReceiptSha256", native / "segments.json")):
            receipt[key] = cache.file_hash(path)
        cache.write_json(native / "protection.json", receipt)
        for log, (inputs, command) in cache.runtime_commands(ticket, receipt, native).items():
            key = cache.cache_key(inputs, command)
            artifact = native / cache.RUNTIME[log]
            entry = native / "runtime-cache" / key
            if ticket["phase"] == "cold":
                entry.mkdir(parents=True)
                (entry / "artifact").write_bytes(artifact.read_bytes())
                (entry / "sha256").write_text(cache.file_hash(artifact) + "\n", encoding="utf-8")
                (native / log).write_text("", encoding="utf-8")
            else:
                shutil.copy2(entry / "artifact", artifact)
                (native / log).write_text("dex2c: runtime cache hit; sha256=" + cache.file_hash(artifact) + "\n",
                                        encoding="utf-8")
        return receipt

    def pair(self):
        first, first_path = self.start("cold")
        self.build(first, 0)
        cold_path = self.root / "cold"
        cold = cache.snapshot(self.fixture, first_path, cold_path)
        self.clear_outputs()
        second, second_path = self.start("warm")
        self.build(second, 1)
        warm_path = self.root / "warm"
        warm = cache.snapshot(self.fixture, second_path, warm_path)
        return cold, warm, cold_path, warm_path

    def test_complete_same_path_pair_passes_and_freezes_shared_inputs_without_keys(self):
        cold, warm, cold_path, warm_path = self.pair()
        result = cache.compare(cold, warm)
        self.assertEqual((result["coldHits"], result["warmHits"]), (0, 29))
        self.assertEqual(len(result["perMethod"]["resourceIds"]), 2)
        self.assertFalse(list(cold_path.rglob("*.JKS")))
        self.assertFalse(list(warm_path.rglob("*.p12")))
        self.assertTrue((cold_path / "fixture/test.der").is_file())
        self.common_jar.write_bytes(b"shared Gradle JAR overwritten after snapshot")
        self.assertTrue(cache.compare(cache.inspect_snapshot(cold_path), cache.inspect_snapshot(warm_path))["passed"])

    def test_begin_rejects_stale_log_and_business_output_and_cold_cache(self):
        for name in ("native/cse-vmp.log", "native/vmp.log", "native/protected.raw.ll",
                     "native/runtime-cache/left/artifact"):
            with self.subTest(name=name):
                path = self.fixture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"leftover")
                with self.assertRaises(ValueError):
                    self.start("cold")
                path.unlink()

    def test_snapshot_rejects_inside_fixture_and_reuse_of_existing_evidence(self):
        ticket, path = self.start("cold")
        self.build(ticket, 0)
        with self.assertRaisesRegex(ValueError, "outside"):
            cache.snapshot(self.fixture, path, self.fixture / "cold")
        out = self.root / "cold"
        cache.snapshot(self.fixture, path, out)
        with self.assertRaisesRegex(ValueError, "must be new"):
            cache.snapshot(self.fixture, path, out)

    def test_snapshot_rejects_stale_or_missing_regenerated_files(self):
        ticket, path = self.start("cold")
        self.build(ticket, 0)
        for name in ("native/cse-vmp.log", "native/vmp.log", "native/protected.raw.ll"):
            with self.subTest(name=name):
                target = self.fixture / name
                original = target.stat().st_mtime_ns
                os.utime(target, ns=(ticket["startedNs"] - 1000000, ticket["startedNs"] - 1000000))
                with self.assertRaisesRegex(ValueError, "stale"):
                    cache.snapshot(self.fixture, path, self.root / "stale")
                os.utime(target, ns=(original, original))
        (self.fixture / "native/object.log").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            cache.snapshot(self.fixture, path, self.root / "missing")

    def test_warm_cache_restore_with_cold_mtime_passes_live_and_frozen_checks(self):
        cold, warm, cold_path, warm_path = self.pair()
        self.assertTrue(all((self.fixture / "native" / name).stat().st_mtime_ns <
                            warm["ticket"]["startedNs"] for name in cache.RUNTIME.values()))
        self.assertTrue(cache.compare(cache.inspect_snapshot(cold_path),
                                      cache.inspect_snapshot(warm_path))["passed"])
        # Being a cache target does not exempt cold compilation from freshness.
        target = cold_path / "fixture/native" / next(iter(cache.RUNTIME.values()))
        old = cold["ticket"]["startedNs"] - 1000000
        os.utime(target, ns=(old, old))
        with self.assertRaisesRegex(ValueError, "stale"):
            cache.inspect_snapshot(cold_path)

    def test_warm_old_logs_or_business_outputs_still_fail_live_and_frozen_checks(self):
        _, warm, _, warm_path = self.pair()
        old = warm["ticket"]["startedNs"] - 1000000
        for name in ("native/cse-vmp.log", "native/vmp.log", "native/protected.raw.ll",
                     "native/protected.ll", "native/protected.o", "native/registration.o"):
            with self.subTest(name=name):
                live, frozen = self.fixture / name, warm_path / "fixture" / name
                previous = [(path.stat().st_atime_ns, path.stat().st_mtime_ns) for path in (live, frozen)]
                os.utime(live, ns=(old, old))
                os.utime(frozen, ns=(old, old))
                with self.assertRaisesRegex(ValueError, "stale"):
                    cache.snapshot(self.fixture, self.root / "warm-begin.json", self.root / "stale-warm")
                with self.assertRaisesRegex(ValueError, "stale"):
                    cache.inspect_snapshot(warm_path)
                for path, timestamps in zip((live, frozen), previous):
                    os.utime(path, ns=timestamps)

    def test_exact_29_source_command_and_key_denominator(self):
        ticket, _ = self.start("cold")
        receipt = self.build(ticket, 0)
        native = self.fixture / "native"
        commands = cache.runtime_commands(ticket, receipt, native)
        self.assertEqual(len(commands), 29)
        c_flags = commands["apkverify-sha256.c.log"][1]
        self.assertNotIn("--driver-mode=g++", c_flags)
        self.assertNotIn("-frtti", c_flags)
        self.assertEqual(c_flags[-7:-4], ["-x", "c", "-std=c11"])
        self.assertIn("--driver-mode=g++", commands["apkverify-apkverify.cpp.log"][1])
        self.assertEqual(commands["cse-optimize.log"][0], receipt["compilerIdentity"]["runtimeFingerprint"] +
                         cache.file_hash(native / "cse-runtime.raw.ll"))
        import hashlib
        self.assertEqual(cache.cache_key("input", ["a", "b"]), hashlib.sha256(b"input\0a\0b").hexdigest())
        entry = next((native / "runtime-cache").iterdir())
        (entry / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "exactly the 29"):
            cache.check_cache(ticket, receipt, native)
        (entry / "extra").unlink()
        (entry / "artifact").unlink()
        with self.assertRaises(FileNotFoundError):
            cache.check_cache(ticket, receipt, native)

    def test_corrupt_cache_receipt_artifact_and_coordinated_replacement_fail(self):
        ticket, _ = self.start("cold")
        receipt = self.build(ticket, 0)
        native = self.fixture / "native"
        entry = next((native / "runtime-cache").iterdir())
        for name in ("artifact", "sha256"):
            path = entry / name
            original = path.read_bytes()
            path.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "cache artifact/receipt"):
                cache.check_cache(ticket, receipt, native)
            path.write_bytes(original)
        (entry / "artifact").write_bytes(b"new-cache-artifact")
        (entry / "sha256").write_text(cache.file_hash(entry / "artifact") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cache artifact/receipt"):
            cache.check_cache(ticket, receipt, native)

    def test_partial_duplicate_foreign_digest_and_cold_hits_fail(self):
        cold, warm, _, warm_path = self.pair()
        native = warm_path / "fixture/native"
        log = native / next(iter(cache.RUNTIME))
        original = log.read_text(encoding="utf-8")
        receipt = cache.read_json(native / "protection.json")
        for value in ("", original * 2, "prefix\n" + original,
                      "dex2c: runtime cache hit; sha256=" + "0" * 64 + "\n"):
            with self.subTest(value=value):
                log.write_text(value, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "exactly one runtime hit"):
                    cache.check_cache(warm["ticket"], receipt, native)
        log.write_text(original, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cold runtime hit"):
            cache.check_cache(cold["ticket"], receipt, native)

    def test_command_change_cannot_bind_to_old_cache(self):
        ticket, _ = self.start("cold")
        receipt = self.build(ticket, 0)
        receipt["configuration"]["commonArguments"].insert(1, "-DCHANGED")
        with self.assertRaises(FileNotFoundError):
            cache.check_cache(ticket, receipt, self.fixture / "native")

    def test_snapshot_recomputes_fingerprint_from_actual_tool_and_header_bytes(self):
        ticket, _ = self.start("cold")
        receipt = self.build(ticket, 0)
        cache.tool_evidence(self.fixture, receipt, ticket)
        header = self.prebuilt / "sysroot/usr/include/stdio.h"
        header.write_bytes(b"changed-sysroot-header")
        with self.assertRaisesRegex(ValueError, "runtimeFingerprint"):
            cache.tool_evidence(self.fixture, receipt, ticket)

    @unittest.skipUnless(os.name == "nt", "WindowsPath ordering only")
    def test_windows_fingerprint_uses_uppercase_order_including_separators(self):
        ticket, _ = self.start("cold")
        receipt = self.build(ticket, 0)
        include = self.prebuilt / "lib/clang/21/include"
        (include / "a").mkdir()
        (include / "aZ.h").write_bytes(b"uppercase-before-separator")
        (include / "a/x.h").write_bytes(b"separator-before-lowercase")
        original = receipt["compilerIdentity"]["runtimeFingerprint"]
        # Obtain the manifest even when testing a deliberately stale declared fingerprint.
        with patch.object(cache, "fingerprint_value", return_value=original):
            evidence = cache.tool_evidence(self.fixture, receipt, ticket)
        self.assertEqual(list(evidence["trees"][1])[:2], ["aZ.h", "a/x.h"])
        receipt["compilerIdentity"]["runtimeFingerprint"] = cache.fingerprint_value(evidence, "\\")
        self.assertEqual(cache.tool_evidence(self.fixture, receipt, ticket), evidence)

    def test_external_input_file_and_directory_roots_reject_symlinks(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(ValueError, "symlinks"):
                cache.files(self.root)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                cache.copy_public(self.common_jar, self.root / "copied.jar")

    def test_changed_fixture_input_tool_certificate_or_business_material_fails(self):
        cold, warm, _, _ = self.pair()
        for change in (lambda row: row["ticket"].update(fixture="elsewhere"),
                       lambda row: row["ticket"].update(token=cold["ticket"]["token"]),
                       lambda row: row["ticket"].update(startedNs=cold["capture"]["capturedNs"]),
                       lambda row: row.update(certificateSha256="different"),
                       lambda row: row["compilerIdentity"].update(compilerSha256="different"),
                       lambda row: row["configuration"].update(minSdk=27),
                       lambda row: row["inputClasses"]["baseline"].update({"sample/Run.class": "changed"}),
                       lambda row: row["ticket"]["cacheBefore"].clear(),
                       lambda row: row["business"].update({"protected.raw.ll": cold["business"]["protected.raw.ll"]})):
            changed = copy.deepcopy(warm)
            change(changed)
            with self.assertRaises(ValueError):
                cache.compare(cold, changed)
        for field in cache.FIELDS:
            changed = copy.deepcopy(warm)
            symbol = self.methods[0]["symbol"]
            changed[field][symbol] = cold[field][symbol]
            with self.assertRaisesRegex(ValueError, "method material did not change"):
                cache.compare(cold, changed)

    def test_coordinated_cache_and_output_replacement_cannot_equal_cold_snapshot(self):
        cold, warm, _, _ = self.pair()
        changed = copy.deepcopy(warm)
        key = next(iter(changed["runtimeTargets"]))
        changed["runtimeTargets"][key]["sha256"] = cache.digest(b"replacement")
        with self.assertRaisesRegex(ValueError, "runtime command/artifact"):
            cache.compare(cold, changed)

    def test_frozen_file_tamper_duplicate_json_and_private_key_are_rejected(self):
        _, _, cold_path, _ = self.pair()
        path = cold_path / "fixture/native/vmp.log"
        original = path.read_bytes()
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "manifest"):
            cache.inspect_snapshot(cold_path)
        path.write_bytes(original)
        (cold_path / "secret.PFX").write_bytes(b"secret")
        with self.assertRaisesRegex(ValueError, "private"):
            cache.inspect_snapshot(cold_path)
        (cold_path / "secret.PFX").unlink()
        (cold_path / "capture.json").write_text('{"files":{},"files":{}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            cache.inspect_snapshot(cold_path)


if __name__ == "__main__":
    unittest.main()
