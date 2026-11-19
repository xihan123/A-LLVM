"""Check caller-owned copies and source reclamation in the frozen signed APK."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid

import cache_probe as cache


TARGET_ID = "83f9a7802590faea85342a4234ccff7e"
TARGET_BYTES = 203
SYMBOLS = ("ndkp_qseg_copy", "ndkp_qseg_acquire_v1", "ndkp_qseg_release_v1", "ndkp_qseg_stats_v1", "JNI_OnLoad")
NEGATIVE_CASES = ("null-out", "kind1", "encoding0", "encoding3", "odd-length", "offset", "length", "length-max")


def select_target(receipt, resources):
    raw = resources.get((bytes.fromhex(TARGET_ID), 2))
    entries = [row for row in receipt["segments"] if row["id"] == TARGET_ID]
    if (raw is None or len(raw) != TARGET_BYTES or len(entries) != 1 or
            any(row["kind"] != 2 or row["chunk"] != 0 or row["lifetime"] != "copy-v1" or
                row["bytes"] != len(raw) or row["resourceSha256"] != cache.sha256(raw) or
                row["sha256"] != cache.sha256(raw) for row in entries)):
        raise ValueError("target must be one complete authenticated 203-byte kind2 copy-v1 chunk0")
    return {"id": TARGET_ID, "kind": 2, "bytes": len(raw), "sha256": cache.sha256(raw), "chunks": entries}, raw


def ir_bytes(value):
    output = bytearray()
    cursor = 0
    while cursor < len(value):
        if value[cursor] == "\\":
            token = value[cursor+1:cursor+3]
            if len(token) != 2 or not re.fullmatch("[0-9A-Fa-f]{2}", token):
                raise ValueError("unsupported IR byte escape")
            output.append(int(token, 16)); cursor += 3
        else:
            output.append(ord(value[cursor])); cursor += 1
    return bytes(output)


def bind_ir(text, target, raw):
    descriptor = bytes.fromhex(target["id"]) + struct.pack("<II", target["bytes"], 2)
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r'^@([A-Za-z0-9_.$-]+) = .*constant \[24 x i8\] c"([^"\n]*)"', line)
        if match and ir_bytes(match[2]) == descriptor:
            found.append({"name": match[1], "line": number, "text": line})
    if len(found) != 1:
        raise ValueError("expected one IR descriptor matching authenticated kind2 ID/size/kind")
    binding = found[0]
    pattern = re.compile(r'^\s*(?:call|invoke) void @ndkp_qseg_copy\(ptr(?:\s+\w+)*\s+@([A-Za-z0-9_.$-]+), '
                         r'ptr(?:\s+\w+)*\s+@' + re.escape(binding["name"]) +
                         r', i32 (\d+), i32 (\d+), i32 (\d+)\)')
    calls = []
    for number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if match:
            offset, length, encoding = map(int, match.group(2, 3, 4))
            if encoding not in (1, 2) or length % encoding or offset > len(raw) or length > len(raw) - offset:
                raise ValueError("invalid actual IR copy bounds/encoding")
            calls.append({"destination": match[1], "offset": offset, "bytes": length, "encoding": encoding,
                          "sha256": cache.sha256(raw[offset:offset+length]), "line": number, "text": line.strip()})
    if not {(0, 32, 2), (32, 17, 1)} <= {(row["offset"], row["bytes"], row["encoding"]) for row in calls}:
        raise ValueError("missing actual UTF16/bytes copy calls on the authenticated descriptor")
    return {"descriptor": binding, "calls": calls}


def copy_slices(raw):
    cases = (("full", 0, len(raw), 1), ("actual-utf16-bytes", 0, 32, 2),
             ("actual-bytes", 32, 17, 1), ("tail", len(raw)-7, 7, 1),
             ("zero", len(raw), 0, 2), ("odd-offset", 1, 2, 2))
    return [{"name": name, "offset": offset, "bytes": length, "encoding": encoding,
             "sha256": cache.sha256(raw[offset:offset+length])} for name, offset, length, encoding in cases]


def source_hashes():
    root = Path(__file__).resolve().parents[2]
    paths = {Path(__file__).with_suffix(".cpp").resolve(), root / "runtime/qseg.h", root / "runtime/sha256.h"}
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename:
            path = Path(filename).resolve()
            if path.is_relative_to(root) and path.suffix == ".py":
                paths.add(path)
    return {path.relative_to(root).as_posix(): cache.sha256(path.read_bytes()) for path in sorted(paths)}


def write_header(path, resources, slices, spans, symbols, page_size):
    def array(value):
        return "{" + ",".join("0x" + value[i:i+2] for i in range(0, len(value), 2)) + "}"
    lines = ["// Generated from authenticated final APK bytes, test-only.", "#include <cstdint>",
             "struct ProbeResource { uint64_t address; uint32_t size, kind; uint8_t id[16], digest[32]; };",
             "struct ProbeSpan { uint64_t address, size; uint8_t digest[32]; };",
             "struct ProbeSlice { const char* name; uint32_t offset, size, encoding; uint8_t digest[32]; };",
             f"constexpr uint64_t ExpectedPageSize = {page_size};", "const ProbeResource Resources[] = {"]
    for row in resources:
        lines.append("  {%d, %d, %d, %s, %s}," % (row["address"], row["bytes"], row["kind"], array(row["id"]), array(row["sha256"])))
    lines += ["};", "const ProbeSlice Slices[] = {"]
    for row in slices:
        lines.append('  {"%s", %d, %d, %d, %s},' % (row["name"], row["offset"], row["bytes"], row["encoding"], array(row["sha256"])))
    lines += ["};", "const ProbeSpan ExecutableSpans[] = {"]
    for row in spans:
        lines.append("  {%d, %d, %s}," % (row["address"], row["bytes"], array(row["sha256"])))
    lines += ["};"]
    lines += [f"constexpr uint64_t Offset_{name} = {symbols[name]};" for name in SYMBOLS]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_process(mode, result):
    if mode == "positive":
        if result.returncode != 0:
            raise RuntimeError(f"positive copy probe failed ({result.returncode}): {result.stdout}\n{result.stderr}")
        observation = json.loads(result.stdout)
        if (observation.get("sourceIntervalAbsentBeforeReload") is not True or
                observation.get("retainedCopyDigestAfterSourceReclaim") is not True or
                observation.get("ownBuffersWipedReadback") is not True):
            raise ValueError("incomplete positive observation")
        return observation
    marker = f"case={mode} valid-copy=verified invalid-copy=attempt"
    if mode not in NEGATIVE_CASES or result.returncode != 127 or result.stdout.splitlines() != [marker]:
        raise RuntimeError(f"copy refusal {mode} needs warmup marker and exit127 ({result.returncode}): {result.stdout}\n{result.stderr}")
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ndk", "native", "apk", "java", "apksigner", "adb", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("--output must be new or empty; preserve each run's evidence separately")
    args.output.mkdir(parents=True, exist_ok=True)
    protection, audited, library_entry, library, raw_resources = cache.load_authenticated_apk(
        args.apk, args.native, args.java, args.apksigner, args.output)
    adb = [str(args.adb), "-P", str(args.server_port), "-s", args.serial]

    def run(*command):
        return subprocess.run([*adb, *map(str, command)], capture_output=True, text=True, timeout=180)

    page_result = run("shell", "getconf", "PAGESIZE"); page_result.check_returncode()
    page_size = int(page_result.stdout.strip())
    receipt = json.loads((args.native / "segments.json").read_text(encoding="utf-8"))
    target, raw = select_target(receipt, raw_resources)
    ir_path = args.native / "protected.ll"
    ir = bind_ir(ir_path.read_text(encoding="utf-8"), target, raw)
    pressure = cache.select_resources(receipt, raw_resources, page_size)
    for row in pressure:
        row["kind"] = 1
    resources = [target, *pressure]
    linked = (args.native / "linked.so").read_bytes()
    base = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    nm = subprocess.check_output([str(base / "bin/llvm-nm.exe"), "--defined-only", str(args.native / "linked.so")], text=True)
    symbols = {line.split()[-1]: int(line.split()[0], 16) for line in nm.splitlines() if len(line.split()) >= 3}
    spans = cache.bind_executable(linked, library, symbols, required_symbols=SYMBOLS)
    for row in resources:
        row["address"] = cache.descriptor_address(library, row["id"], row["bytes"], kind=row["kind"])
        if cache.descriptor_address(linked, row["id"], row["bytes"], kind=row["kind"]) != row["address"]:
            raise ValueError("linked/final descriptor address differs")
    slices = copy_slices(raw)
    header = args.output / "copy_plan.h"
    write_header(header, resources, slices, spans, symbols, page_size)
    sources = source_hashes()
    plan = {"schemaVersion": 1, "apkSha256": audited["apkSha256"], "libraryEntry": library_entry,
            "librarySha256": protection["librarySha256"], "linkedSha256": cache.sha256(linked),
            "containerSha256": protection["containerSha256"], "segmentsReceiptSha256": protection["segmentsReceiptSha256"],
            "protectionSha256": cache.sha256((args.native / "protection.json").read_bytes()),
            "irSha256": cache.sha256(ir_path.read_bytes()), "irBinding": ir,
            "pageSize": page_size, "idleBudgetBytes": cache.IDLE_BUDGET,
            "pressureMappedBytes": sum(row["mappedBytes"] for row in pressure),
            "resources": resources, "slices": slices, "executableSpans": spans,
            "symbols": {name: symbols[name] for name in SYMBOLS}, "sourceSha256": sources}
    plan_path = args.output / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    executable = args.output / "copy-probe"
    subprocess.run([str(base / "bin/clang++.exe"), "--target=aarch64-linux-android26", "--sysroot=" + str(base / "sysroot"),
                    "-Oz", "-static-libstdc++", "-I" + str(args.output), str(Path(__file__).with_suffix(".cpp")),
                    "-ldl", "-o", str(executable)], check=True)
    remote = "/data/local/tmp/ndkp-qseg-copy-" + uuid.uuid4().hex
    run("shell", "mkdir", remote).check_returncode()
    try:
        run("push", args.apk, remote + "/protected.apk").check_returncode()
        run("push", executable, remote + "/probe").check_returncode()
        run("shell", "chmod", "755", remote + "/probe").check_returncode()
        results, observation = [], None
        for mode in ("positive", *NEGATIVE_CASES):
            result = run("shell", remote + "/probe", remote + "/protected.apk!/" + library_entry, mode)
            checked = check_process(mode, result)
            results.append({"case": mode, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
            if mode == "positive":
                observation = checked
        if source_hashes() != sources:
            raise ValueError("probe/helper sources changed during this run")
        report = {"schemaVersion": 1, "scope": "signed-apk-production-copy-probe", "serial": args.serial,
                  "pageSize": page_size, "apkSha256": audited["apkSha256"], "targetId": target["id"],
                  "targetSha256": target["sha256"], "resourceBytes": target["bytes"], "lifetime": "copy-v1",
                  "sourceSha256": sources, "planSha256": cache.sha256(plan_path.read_bytes()),
                  "headerSha256": cache.sha256(header.read_bytes()), "executableSha256": cache.sha256(executable.read_bytes()),
                  "observation": observation, "results": results, "directSourceWipeObservation": False,
                  "callerOwnedBufferWipeOnly": True, "productionWrapperExecution": False,
                  "javaOrInternedCopiesValidated": False, "copyPerformsUtf16Decoding": False}
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))
    finally:
        run("shell", "rm", "-f", remote + "/probe", remote + "/protected.apk").check_returncode()
        run("shell", "rmdir", remote).check_returncode()


if __name__ == "__main__":
    main()
