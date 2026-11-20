"""Check four corrupt runtime-cache objects while both CSE IR stages stay cached."""
import argparse
import json
from pathlib import Path

import runtime_cache as cache


MISSES = ("apkverify-sha256.c.log", "ndkp_apkcert.log", "cse-object.log", "qseg-runtime.log")


def validate_ticket(ticket, cold, cold_path):
    first = cold["ticket"]
    cache.require(first["phase"] == "cold" and "cacheRecovery" not in first,
                  "recovery requires an ordinary frozen cold baseline")
    cache.require(ticket["phase"] == "warm" and ticket["fixture"] == first["fixture"],
                  "recovery must use the cold fixture's same absolute path")
    cache.require(ticket["token"] != first["token"] and
                  cold["capture"]["capturedNs"] < ticket["startedNs"],
                  "cold must be frozen before recovery begin with a new token")
    for name in ("contractSha256", "contract", "separator", "freshFiles", "emptyTrees"):
        cache.require(ticket[name] == first[name], "recovery begin inputs differ: " + name)
    recovery = ticket["cacheRecovery"]
    cache.require(recovery["schemaVersion"] == 2 and recovery["expectedMisses"] == list(MISSES),
                  "recovery must use the fixed four miss targets")
    cache.require(recovery["coldCaptureSha256"] == cache.file_hash(cold_path / "capture.json"),
                  "recovery cold snapshot digest differs")
    cache.exact_targets(recovery["corruptions"], MISSES, "corrupted runtime targets")
    by_log = {row["log"]: (key, row) for key, row in cold["runtimeTargets"].items()}
    before = cache.inventory_from_capture(cold["capture"])
    expected = dict(before)
    for log in MISSES:
        fault = recovery["corruptions"][log]
        key, target = by_log[log]
        cache.require(fault["key"] == key and fault["artifact"] == target["artifact"],
                      "corruption target identity differs: " + log)
        original = (cold_path / "fixture/native/runtime-cache" / key / "artifact").read_bytes()
        offset, old, new = fault["offset"], fault["oldByte"], fault["newByte"]
        cache.require(type(offset) is int and 0 <= offset < len(original) and
                      type(old) is int and type(new) is int and 0 <= new <= 255 and
                      original[offset] == old != new and fault["bytes"] == len(original),
                      "invalid single-byte corruption: " + log)
        changed = bytearray(original)
        changed[offset] = new
        after = cache.digest(changed)
        cache.require(fault["beforeSha256"] == before[key + "/artifact"] and
                      fault["afterSha256"] == after,
                      "corruption digest differs: " + log)
        expected[key + "/artifact"] = after
    cache.require(ticket["cacheBefore"] == expected,
                  "recovery cache before must differ only by the four single-byte artifacts")


def begin(fixture, cold_path, output):
    fixture, cold_path, output = fixture.resolve(), cold_path.resolve(), output.resolve()
    cache.outside(fixture, output)
    cache.outside(cold_path, output)
    cache.require(not output.exists(), "begin output must be new")
    cold = cache.inspect_snapshot(cold_path)
    cache.require(cold["ticket"]["fixture"] == str(fixture), "cold fixture path differs")
    cache.require(cold["ticket"]["phase"] == "cold", "requires a frozen cold baseline")
    before = cache.inventory_from_capture(cold["capture"])
    current = cache.inventory(fixture / "native/runtime-cache", private=True)
    expected = dict(before)
    faults = {}
    by_log = {row["log"]: (key, row) for key, row in cold["runtimeTargets"].items()}
    for log in MISSES:
        key, target = by_log[log]
        original = (cold_path / "fixture/native/runtime-cache" / key / "artifact").read_bytes()
        changed = (fixture / "native/runtime-cache" / key / "artifact").read_bytes()
        cache.require(bool(original) and len(original) == len(changed),
                      "corruption must preserve the nonempty artifact's byte size: " + log)
        offset = next((index for index, value in enumerate(original) if value != changed[index]), None)
        cache.require(offset is not None and original[offset + 1:] == changed[offset + 1:],
                      "exactly one artifact byte must change: " + log)
        after = cache.digest(changed)
        expected[key + "/artifact"] = after
        faults[log] = {"key": key, "artifact": target["artifact"], "bytes": len(original),
                       "offset": offset, "oldByte": original[offset], "newByte": changed[offset],
                       "beforeSha256": before[key + "/artifact"], "afterSha256": after}
    cache.require(current == expected,
                  "preserve every cold cache file except the four single-byte artifact changes")
    ticket = cache.begin(fixture, "warm", cold_path / "expected-contract.json", output)
    ticket["cacheRecovery"] = {"schemaVersion": 2, "expectedMisses": list(MISSES),
                               "coldCaptureSha256": cache.file_hash(cold_path / "capture.json"),
                               "corruptions": faults}
    validate_ticket(ticket, cold, cold_path)
    cache.write_json(output, ticket)
    return ticket


def snapshot(fixture, begin_path, cold_path, output):
    cache.outside(cold_path.resolve(), output.resolve())
    cold = cache.inspect_snapshot(cold_path)
    ticket = cache.read_json(begin_path)
    validate_ticket(ticket, cold, cold_path)
    result = cache.snapshot(fixture, begin_path, output, expected_misses=MISSES)
    compare(cold, result, cold_path)
    return result


def inspect_snapshot(directory, cold, cold_path):
    result = cache.inspect_snapshot(directory, expected_misses=MISSES)
    validate_ticket(result["ticket"], cold, cold_path)
    return result


def compare(cold, recovery, cold_path):
    validate_ticket(recovery["ticket"], cold, cold_path)
    cache.require(not cold["ticket"]["cacheBefore"], "cold began with a populated cache")
    cache.require(cache.inventory_from_capture(cold["capture"]) ==
                  cache.inventory_from_capture(recovery["capture"]),
                  "recovered cache must equal all 29 cold entries, including unchanged receipts")
    material = cache.compare_outputs(cold, recovery)
    return {"passed": True, "coldHits": 0, "recoveryHits": len(cache.RUNTIME) - len(MISSES),
            "recoveryMisses": len(MISSES), "expectedMisses": list(MISSES), **material,
            "corruptions": recovery["ticket"]["cacheRecovery"]["corruptions"],
            "scope": "four-object runtime cache corruption recovery; raw and optimized CSE IR stay cached; "
                     "not randomized IR recompilation/key migration, business reuse or a performance comparison"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("begin", help="record four existing single-byte corruptions; never mutate")
    start.add_argument("--fixture", type=Path, required=True)
    start.add_argument("--cold", type=Path, required=True)
    start.add_argument("--output", type=Path, required=True)
    freeze = commands.add_parser("snapshot", help="freeze and validate the mixed-hit recovery build")
    freeze.add_argument("--fixture", type=Path, required=True)
    freeze.add_argument("--begin", type=Path, required=True)
    freeze.add_argument("--cold", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("compare", help="re-read frozen cold and recovery evidence")
    check.add_argument("--cold", type=Path, required=True)
    check.add_argument("--recovery", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "begin":
        result = begin(args.fixture, args.cold, args.output)
        print(json.dumps({"phase": "recovery", "token": result["token"], "expectedMisses": list(MISSES)}))
    elif args.command == "snapshot":
        result = snapshot(args.fixture, args.begin, args.cold, args.output)
        print(json.dumps({"phase": "recovery", "runtimeTargets": len(result["runtimeTargets"])}))
    else:
        cache.require(not args.output.exists(), "report output must be new")
        cache.outside(args.cold.resolve(), args.output.resolve())
        cache.outside(args.recovery.resolve(), args.output.resolve())
        cold = cache.inspect_snapshot(args.cold)
        result = compare(cold, inspect_snapshot(args.recovery, cold, args.cold), args.cold)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        cache.write_json(args.output, result)
        print(json.dumps({name: result[name] for name in ("passed", "recoveryHits", "recoveryMisses")}))


if __name__ == "__main__":
    main()
