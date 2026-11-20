"""Freeze and check a real DeviceFixtures runtime-cache cold/warm pair."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qseg"))
from build_diversity import (FIELDS, MAINS, class_manifest, clone_material,
                             digest, exact_targets, load_contract, method_targets,
                             read_json, require, resource_groups)


MBEDTLS = ("asn1parse asn1write bignum bignum_core bignum_mod bignum_mod_raw "
           "constant_time ecdsa ecp ecp_curves md oid pk pk_ecc pk_wrap pkparse "
           "pkwrite platform_util rsa rsa_alt_helpers sha256 sha512").split()
VERIFIER = [name + ".c" for name in MBEDTLS] + ["apkverify.cpp", "ndkp_apkverify.cpp"]
RUNTIME = {"apkverify-" + name + ".log": "apkverify-" + name + ".o" for name in VERIFIER}
RUNTIME.update({"ndkp_apkcert.log": "ndkp_apkcert.o", "cse-vmp.log": "cse-runtime.raw.ll",
                "cse-optimize.log": "cse-runtime.ll", "cse-object.log": "ndkp_cse_runtime.o",
                "qseg-runtime.log": "qseg-runtime.o"})
BUSINESS_LOGS = ("compiler vmp optimize object registration registration-object dex2c_runtime "
                 "dex2c_runtime-object qseg-prepare qseg-image link seal strip seal-verify").split()
BUSINESS_FILES = ("protected.raw.ll protected.ll protected.o registration.ll registration.o "
                  "dex2c_runtime.ll dex2c_runtime.o qseg-image.cpp qseg-image.o linked.so "
                  "protection.json segments.json signing-cert.der").split()
FRESH_FILES = sorted({"native/" + name for name in
                      list(RUNTIME) + list(RUNTIME.values()) + BUSINESS_FILES +
                      [name + ".log" for name in BUSINESS_LOGS]} |
                     {"inputs.json", "original.jar", "generated/classes.jar", "generated/selection.json"})
FRESH_TREES = ("native/assets", "native/jniLibs", "native/staging")
PRIVATE_SUFFIXES = {".jks", ".p12", ".pfx", ".keystore"}
HIT = re.compile(r"dex2c: runtime cache hit; sha256=([0-9a-f]{64})\r?\n\Z")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def file_hash(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def outside(fixture, output):
    require(not output.is_relative_to(fixture) and not fixture.is_relative_to(output),
            "evidence must be outside the fixture directory")


def files(directory):
    require(not directory.is_symlink() and not getattr(directory, "is_junction", lambda: False)(),
            "snapshot does not follow symlinks/junctions: " + str(directory))
    if not directory.exists():
        return []
    paths = sorted(directory.rglob("*"))
    require(not any(path.is_symlink() or getattr(path, "is_junction", lambda: False)() for path in paths),
            "snapshot does not follow symlinks/junctions: " + str(directory))
    return [path for path in paths if path.is_file()]


def inventory(directory, private=False):
    return {path.relative_to(directory).as_posix(): file_hash(path) for path in files(directory)
            if private or path.suffix.lower() not in PRIVATE_SUFFIXES}


def fresh_files(fixture):
    result = [fixture / name for name in FRESH_FILES]
    for name in FRESH_TREES:
        result.extend(files(fixture / name))
    return result


def check_freshness(fixture, ticket, *, expected_misses=()):
    restored = {"native/" + artifact for log, artifact in RUNTIME.items()
                if log not in expected_misses} if ticket["phase"] == "warm" else set()
    for path in fresh_files(fixture):
        # Windows Files.copy may preserve the cache artifact's old LastWriteTime.
        require(path.is_file() and (path.relative_to(fixture).as_posix() in restored or
                path.stat().st_mtime_ns >= ticket["startedNs"]),
                "missing or stale regenerated file: " + str(path))


def begin(fixture, phase, contract_path, output):
    fixture, output = fixture.resolve(), output.resolve()
    outside(fixture, output)
    require(not output.exists(), "begin output must be new")
    contract = load_contract(contract_path)
    stale = [str(path.relative_to(fixture)) for path in fresh_files(fixture) if path.exists()]
    require(not stale, "remove only the documented regenerable files before begin: " + repr(stale))
    cache = inventory(fixture / "native/runtime-cache", private=True)
    require(phase in ("cold", "warm"), "invalid phase")
    require(not cache if phase == "cold" else bool(cache), "cold requires empty cache; warm requires cache")
    ticket = {"schemaVersion": 1, "phase": phase, "fixture": str(fixture),
              "separator": os.sep, "token": uuid.uuid4().hex, "startedNs": time.time_ns(),
              "contract": contract, "contractSha256": file_hash(contract_path),
              "contractText": contract_path.read_bytes().decode("utf-8"),
              "freshFiles": FRESH_FILES, "emptyTrees": list(FRESH_TREES), "cacheBefore": cache}
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, ticket)
    return ticket


def runtime_commands(ticket, receipt, native):
    """Mirror only the 29 cachedRun call sites, including their exact argv order."""
    path_type = PureWindowsPath if ticket["separator"] == "\\" else PurePosixPath
    output = path_type(ticket["fixture"]) / "native"
    runtime = output / "a_llvm"
    common = receipt["configuration"]["commonArguments"]
    require(isinstance(common, list) and common and all(isinstance(arg, str) for arg in common),
            "invalid commonArguments")
    require(common[-1] == "-DNDKP_APK_VERIFY" and
            "-I" + str(path_type(ticket["fixture"]) / "generated") in common,
            "commonArguments do not belong to the original fixture")
    flags = common + ["-Oz", "-fno-lto", "-I" + str(runtime),
                      "-I" + str(runtime / "third_party/mbedtls/include"),
                      "-include", str(runtime / "apkverify_build.h")]
    commands = {}
    runtime_key = receipt["compilerIdentity"]["runtimeFingerprint"]
    for name in VERIFIER:
        source = runtime / ("third_party/mbedtls/library/" + name if name.endswith(".c") else name)
        args = flags
        if name.endswith(".c"):
            args = [arg for arg in flags if arg not in
                    ("--driver-mode=g++", "-std=gnu++17", "-fno-exceptions", "-frtti")]
            args += ["-x", "c", "-std=c11"]
        commands["apkverify-" + name + ".log"] = (runtime_key, args +
            ["-c", str(source), "-o", str(output / ("apkverify-" + name + ".o"))])
    commands["ndkp_apkcert.log"] = (runtime_key, common + ["-Oz", "-fno-lto", "-c",
        str(runtime / "ndkp_apkcert.cpp"), "-o", str(output / "ndkp_apkcert.o")])
    commands["cse-vmp.log"] = (runtime_key, common + ["-DNDKP_QSEG", "-O1", "-fno-lto",
        "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops", "-DNDKP_CSE_VMP",
        "-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict", "-mllvm", "-irobf-vmp-memops",
        "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry", "-S", "-emit-llvm",
        str(runtime / "ndkp_cse_runtime.cpp"), "-o", str(output / "cse-runtime.raw.ll")])
    commands["cse-optimize.log"] = (runtime_key + file_hash(native / "cse-runtime.raw.ll"),
        common + ["-Oz", "-mllvm", "-irobf-vmp-post", "-S", "-emit-llvm",
                  str(output / "cse-runtime.raw.ll"), "-o", str(output / "cse-runtime.ll")])
    commands["cse-object.log"] = (runtime_key + file_hash(native / "cse-runtime.ll"),
        common + ["-Oz", "-fno-lto", "-Xclang", "-disable-llvm-passes", "-c",
                  str(output / "cse-runtime.ll"), "-o", str(output / "ndkp_cse_runtime.o")])
    commands["qseg-runtime.log"] = (runtime_key, common + ["-Oz", "-fno-lto", "-c",
        str(runtime / "ndkp_qseg_runtime.cpp"), "-o", str(output / "qseg-runtime.o")])
    return commands


def cache_key(inputs, command):
    return digest(inputs.encode("utf-8") + b"".join(b"\0" + arg.encode("utf-8") for arg in command))


def check_cache(ticket, receipt, native, *, expected_misses=()):
    require(set(expected_misses) <= RUNTIME.keys(), "unknown runtime miss target")
    commands = runtime_commands(ticket, receipt, native)
    exact_targets(commands, RUNTIME, "runtime commands")
    expected, targets = {}, {}
    for log, artifact in RUNTIME.items():
        inputs, command = commands[log]
        key = cache_key(inputs, command)
        require(key not in targets, "duplicate runtime cache key")
        value = file_hash(native / artifact)
        require((native / artifact).stat().st_size > 0, "empty runtime artifact: " + artifact)
        entry = native / "runtime-cache" / key
        require(file_hash(entry / "artifact") == value and
                (entry / "sha256").read_text(encoding="utf-8").strip() == value,
                "cache artifact/receipt differs: " + artifact)
        text = (native / log).read_text(encoding="utf-8")
        if ticket["phase"] == "warm" and log not in expected_misses:
            match = HIT.fullmatch(text)
            require(match is not None and match[1] == value, "expected exactly one runtime hit: " + log)
        else:
            require("runtime cache hit" not in text, "unexpected runtime hit for compile miss: " + log
                    if log in expected_misses else "cold runtime hit: " + log)
        expected[key + "/artifact"] = value
        expected[key + "/sha256"] = file_hash(entry / "sha256")
        targets[key] = {"log": log, "artifact": artifact, "sha256": value, "command": command,
                        "inputs": inputs}
    require(inventory(native / "runtime-cache", private=True) == expected,
            "runtime cache entries must cover exactly the 29 commands")
    return targets


def fingerprint_value(evidence, separator):
    hasher = hashlib.sha256()
    for value in evidence["prefix"]:
        hasher.update(value.encode("utf-8"))
    for group in evidence["trees"]:
        for name, value in group.items():
            hasher.update(name.replace("/", separator).encode("utf-8"))
            hasher.update(value.encode("utf-8"))
    return hasher.hexdigest()


def tool_evidence(fixture, receipt, ticket):
    common = receipt["configuration"]["commonArguments"]
    compiler = Path(common[0])
    sysroots = [Path(arg.removeprefix("--sysroot=")) for arg in common if arg.startswith("--sysroot=")]
    resources = [Path(arg.removeprefix("-resource-dir=")) for arg in common if arg.startswith("-resource-dir=")]
    require(len(sysroots) == len(resources) == 1, "expected one sysroot and resource directory")
    prebuilt = sysroots[0].parent
    properties = prebuilt.parents[3] / "source.properties"
    suffix = ".exe" if ticket["separator"] == "\\" else ""
    identity = receipt["compilerIdentity"]
    for key, path in (("compilerSha256", compiler), ("ndkPropertiesSha256", properties),
                      ("linkerSha256", prebuilt / "bin" / ("ld.lld" + suffix)),
                      ("stripSha256", prebuilt / "bin" / ("llvm-strip" + suffix))):
        require(file_hash(path) == identity[key], "tool identity differs: " + key)
    require((fixture / "native/compiler.log").read_text(encoding="utf-8").strip() == identity["version"],
            "compiler version log differs")
    trees = []
    for directory in (fixture / "native/a_llvm", resources[0] / "include", sysroots[0] / "usr/include"):
        rows = inventory(directory, private=True)
        if directory == fixture / "native/a_llvm":
            rows = {name: value for name, value in rows.items() if name.split("/")[0] != "__pycache__"}
        require(bool(rows), "empty runtime fingerprint tree: " + str(directory))
        # WindowsPath.compareTo compares uppercase characters, including against separators.
        trees.append(dict(sorted(rows.items(), key=lambda row:
            row[0].replace("/", ticket["separator"]).upper() if suffix else row[0])))
    evidence = {"prefix": [identity["compilerSha256"], identity["ndkPropertiesSha256"],
                            file_hash(fixture / "native/signing-cert.der")], "trees": trees}
    require(fingerprint_value(evidence, ticket["separator"]) == identity["runtimeFingerprint"],
            "runtimeFingerprint differs from actual runtime/tool/header inputs")
    return evidence


def inspect(fixture, ticket, contract, inputs, *, expected_misses=()):
    native = fixture / "native"
    receipt = read_json(native / "protection.json")
    require(receipt["schemaVersion"] == 7 and receipt["segmentedData"] is True and
            receipt["apkSignatureVerification"] is True and receipt["nativeSymbols"] == [] and
            receipt["stringSymbols"] == [], "requires the standard segmented+verified VMP fixture")
    configuration = receipt["configuration"]
    require(configuration["segmentedData"] is True and configuration["apkSignatureVerification"] is True and
            configuration["library"] == "dex2c_semantics" and configuration["minSdk"] == 26,
            "unexpected fixture configuration")
    expected = method_targets(contract["methods"])
    symbols = set(expected.values())
    actual = method_targets([row for row in read_json(fixture / "generated/selection.json")["methods"]
                             if row["protection"] == "vmp"])
    require(actual == expected, "selection differs from expected methods")
    require(len(receipt["symbols"]) == len(set(receipt["symbols"])), "duplicate receipt symbols")
    exact_targets(receipt["symbols"], symbols, "receipt symbols")
    require(set(inputs["mains"]) == MAINS and len(inputs["mains"]) == len(MAINS), "unexpected mains")
    classes = {mode: class_manifest(paths) for mode, paths in inputs.items() if mode != "mains"}
    exact_targets(classes, ("baseline", "protected", "common"), "input class paths")
    for mode in ("baseline", "common"):
        require(classes[mode] == contract["inputClasses"][mode], "input class bytes differ: " + mode)
    require(classes["protected"] == class_manifest([fixture / "generated/classes.jar"]),
            "protected classes differ from generated JAR")
    library = native / "jniLibs" / receipt["abi"] / "libdex2c_semantics.so"
    for key, path in (("certificateSha256", native / "signing-cert.der"),
                      ("classesSha256", fixture / "generated/classes.jar"),
                      ("selectionSha256", fixture / "generated/selection.json"),
                      ("irSha256", native / "protected.ll"), ("objectSha256", native / "protected.o"),
                      ("cseRuntimeIrSha256", native / "cse-runtime.ll"),
                      ("librarySha256", library), ("containerSha256", native / "assets/dex2c_semantics.qseg"),
                      ("segmentsReceiptSha256", native / "segments.json")):
        require(file_hash(path) == receipt[key], "output/receipt digest differs: " + key)
    manifest = (native / "a_llvm/apkverify_sources.txt").read_text(encoding="utf-8").splitlines()
    require(manifest == MBEDTLS, "verifier source denominator differs from pinned 22-source profile")
    logs = {path.name for path in native.glob("*.log")}
    exact_targets(logs, set(RUNTIME) | {name + ".log" for name in BUSINESS_LOGS}, "compiler logs")
    for name in BUSINESS_LOGS:
        require("runtime cache hit" not in (native / (name + ".log")).read_text(encoding="utf-8"),
                "business/helper log claims runtime reuse: " + name)
    resources = resource_groups(read_json(native / "segments.json")["segments"],
                                receipt["methodBytecodeBytes"], symbols)
    keys, dispatch = clone_material((native / "protected.raw.ll").read_text(encoding="utf-8"), symbols)
    return {"compilerIdentity": receipt["compilerIdentity"], "configuration": configuration,
            "certificateSha256": receipt["certificateSha256"], "inputClasses": classes,
            "runtimeTargets": check_cache(ticket, receipt, native, expected_misses=expected_misses),
            "business": {name: file_hash(native / name) for name in BUSINESS_FILES},
            "resourceIds": {name: row[0] for name, row in resources.items()},
            "resourceContentSha256": {name: row[1] for name, row in resources.items()},
            "functionKeySha256": keys, "dispatchCompareConstantSequenceSha256": dispatch}


def copy_public(source, destination):
    require(not source.is_symlink() and not getattr(source, "is_junction", lambda: False)(),
            "snapshot does not follow symlinks/junctions: " + str(source))
    require(source.suffix.lower() not in PRIVATE_SUFFIXES, "private input is not an evidence input")
    if source.is_dir():
        destination.mkdir(parents=True)
        for path in files(source):
            if path.suffix.lower() not in PRIVATE_SUFFIXES:
                target = destination / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def snapshot(fixture, begin_path, output, *, expected_misses=()):
    fixture, output = fixture.resolve(), output.resolve()
    outside(fixture, output)
    require(not output.exists(), "snapshot output must be new; preserve previous evidence")
    ticket = read_json(begin_path)
    require(("cacheRecovery" in ticket) == bool(expected_misses),
            "recovery tickets require the dedicated cache_recovery.py entrypoint")
    require(ticket["fixture"] == str(fixture), "begin fixture path differs")
    require(ticket["freshFiles"] == FRESH_FILES and ticket["emptyTrees"] == list(FRESH_TREES),
            "begin fresh-file contract differs")
    check_freshness(fixture, ticket, expected_misses=expected_misses)
    output.mkdir(parents=True)
    copy_public(fixture, output / "fixture")
    require(inventory(fixture) == inventory(output / "fixture"), "fixture changed during snapshot")
    write_json(output / "begin.json", ticket)
    (output / "expected-contract.json").write_bytes(ticket["contractText"].encode("utf-8"))
    require(file_hash(output / "expected-contract.json") == ticket["contractSha256"], "contract changed")
    original_inputs = read_json(fixture / "inputs.json")
    frozen_inputs = {"mains": original_inputs["mains"]}
    for mode in ("baseline", "protected", "common"):
        frozen_inputs[mode] = []
        for index, name in enumerate(original_inputs[mode]):
            source = Path(name)
            if not source.is_absolute():
                source = fixture / source
            target = Path("inputs") / mode / (str(index) + (source.suffix if source.is_file() else ""))
            copy_public(source, output / target)
            require((file_hash(source) == file_hash(output / target)) if source.is_file() else
                    inventory(source) == inventory(output / target), "input changed during snapshot")
            frozen_inputs[mode].append(target.as_posix())
    write_json(output / "inputs.json", frozen_inputs)
    receipt = read_json(output / "fixture/native/protection.json")
    write_json(output / "tool-inputs.json", tool_evidence(fixture, receipt, ticket))
    write_json(output / "capture.json", {"schemaVersion": 1, "capturedNs": time.time_ns(),
        "beginSha256": file_hash(output / "begin.json"), "files": inventory(output)})
    return inspect_snapshot(output, expected_misses=expected_misses)


def inspect_snapshot(directory, *, expected_misses=()):
    require(not any(path.suffix.lower() in PRIVATE_SUFFIXES for path in files(directory)),
            "snapshot contains a private keystore")
    capture = read_json(directory / "capture.json")
    actual = inventory(directory)
    del actual["capture.json"]
    require(actual == capture["files"], "snapshot file manifest differs")
    require(capture["beginSha256"] == file_hash(directory / "begin.json"), "begin digest differs")
    ticket = read_json(directory / "begin.json")
    require(("cacheRecovery" in ticket) == bool(expected_misses),
            "recovery tickets require the dedicated cache_recovery.py entrypoint")
    outside(Path(ticket["fixture"]).resolve(), directory.resolve())
    require(ticket["startedNs"] < capture["capturedNs"], "invalid capture chronology")
    contract_path = directory / "expected-contract.json"
    require(file_hash(contract_path) == ticket["contractSha256"], "snapshot contract differs")
    contract = load_contract(contract_path)
    require(contract == ticket["contract"], "begin contract differs")
    inputs = read_json(directory / "inputs.json")
    for mode in ("baseline", "protected", "common"):
        inputs[mode] = [directory / name for name in inputs[mode]]
    fixture = directory / "fixture"
    check_freshness(fixture, ticket, expected_misses=expected_misses)
    result = inspect(fixture, ticket, contract, inputs, expected_misses=expected_misses)
    evidence = read_json(directory / "tool-inputs.json")
    runtime = inventory(fixture / "native/a_llvm", private=True)
    runtime = {name: value for name, value in runtime.items() if name.split("/")[0] != "__pycache__"}
    require(runtime == evidence["trees"][0], "frozen runtime fingerprint inputs differ")
    require(evidence["prefix"] == [result["compilerIdentity"]["compilerSha256"],
            result["compilerIdentity"]["ndkPropertiesSha256"], result["certificateSha256"]] and
            fingerprint_value(evidence, ticket["separator"]) == result["compilerIdentity"]["runtimeFingerprint"],
            "frozen runtime/tool/header fingerprint differs")
    result.update(ticket=ticket, capture=capture, toolInputs=evidence)
    return result


def compare(cold, warm):
    first, second = cold["ticket"], warm["ticket"]
    require("cacheRecovery" not in first and "cacheRecovery" not in second,
            "recovery tickets require the dedicated cache_recovery.py entrypoint")
    require((first["phase"], second["phase"]) == ("cold", "warm"), "requires a cold then warm pair")
    require(first["fixture"] == second["fixture"], "cold/warm must use the same absolute fixture path")
    require(first["token"] != second["token"] and cold["capture"]["capturedNs"] < second["startedNs"],
            "cold must be frozen before warm begin with a new token")
    require(not first["cacheBefore"], "cold began with a populated cache")
    cache_files = inventory_from_capture(cold["capture"])
    require(second["cacheBefore"] == cache_files == inventory_from_capture(warm["capture"]),
            "warm must preserve exactly the cold runtime cache")
    return {"passed": True, "coldHits": 0, "warmHits": len(RUNTIME), **compare_outputs(cold, warm),
            "scope": "runtime artifact reuse correctness; not business reuse or a performance comparison"}


def compare_outputs(cold, warm):
    """The fixed inputs and fresh business material required by both cache protocols."""
    first, second = cold["ticket"], warm["ticket"]
    for key in ("contractSha256", "contract", "separator", "freshFiles", "emptyTrees"):
        require(first[key] == second[key], "begin inputs differ: " + key)
    for key in ("compilerIdentity", "configuration", "certificateSha256", "toolInputs"):
        require(cold[key] == warm[key], "fixed input/tool/config identity differs: " + key)
    for mode in ("baseline", "common"):
        require(cold["inputClasses"][mode] == warm["inputClasses"][mode], "input classes differ: " + mode)
    require(cold["runtimeTargets"] == warm["runtimeTargets"], "runtime command/artifact material differs")
    differences = {}
    for field in FIELDS:
        exact_targets(warm[field], cold[field], field)
        differences[field] = {name: {"cold": value, "warm": warm[field][name],
                                     "changed": value != warm[field][name]}
                              for name, value in cold[field].items()}
        require(all(row["changed"] for row in differences[field].values()),
                "business method material did not change: " + field)
    for name in ("protected.raw.ll", "protected.ll", "protected.o"):
        require(cold["business"][name] != warm["business"][name], "business output did not change: " + name)
    return {"runtimeTargets": warm["runtimeTargets"],
            "expectedMethods": first["contract"]["methods"], "perMethod": differences,
            "business": {name: {"cold": value, "warm": warm["business"][name]}
                         for name, value in cold["business"].items()}}


def inventory_from_capture(capture):
    prefix = "fixture/native/runtime-cache/"
    return {name.removeprefix(prefix): value for name, value in capture["files"].items() if name.startswith(prefix)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("begin", help="record absence of regenerated files; never delete anything")
    start.add_argument("--fixture", type=Path, required=True)
    start.add_argument("--phase", choices=("cold", "warm"), required=True)
    start.add_argument("--expected-contract", type=Path, required=True)
    start.add_argument("--output", type=Path, required=True)
    freeze = commands.add_parser("snapshot", help="copy public fixture evidence into a new external directory")
    freeze.add_argument("--fixture", type=Path, required=True)
    freeze.add_argument("--begin", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("compare", help="re-read frozen cold/warm evidence")
    check.add_argument("--cold", type=Path, required=True)
    check.add_argument("--warm", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "begin":
        result = begin(args.fixture, args.phase, args.expected_contract, args.output)
        print(json.dumps({"phase": result["phase"], "token": result["token"], "fixture": result["fixture"]}))
    elif args.command == "snapshot":
        result = snapshot(args.fixture, args.begin, args.output)
        print(json.dumps({"phase": result["ticket"]["phase"], "runtimeTargets": len(result["runtimeTargets"])}))
    else:
        require(not args.output.exists(), "report output must be new")
        result = compare(inspect_snapshot(args.cold), inspect_snapshot(args.warm))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.output, result)
        print(json.dumps({"passed": True, "coldHits": result["coldHits"], "warmHits": result["warmHits"]}))


if __name__ == "__main__":
    main()
