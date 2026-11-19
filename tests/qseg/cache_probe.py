"""Verify large authenticated VM leases and target reclamation in a signed APK."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import seal_qseg as qseg
from verify_dex2c_apk import verify
from audit_apk import audit


IDLE_BUDGET = 1 << 20


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def select_resources(receipt, resources, page_size):
    """Require enough distinct authenticated lease VMs for both pressure phases."""
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("invalid device page size")
    grouped = {}
    for entry in receipt["segments"]:
        if entry["kind"] == 1:
            grouped.setdefault(entry["id"], []).append(entry)
    selected = []
    for identity, chunks in grouped.items():
        raw = resources[(bytes.fromhex(identity), 1)]
        chunks = sorted(chunks, key=lambda item: item["chunk"])
        if (not raw or [item["chunk"] for item in chunks] != list(range((len(raw) + 65535) // 65536)) or
                any(item["lifetime"] != "lease-v1" or item["resourceSha256"] != sha256(raw) or
                    item["bytes"] != len(raw[item["chunk"]*65536:(item["chunk"]+1)*65536]) or
                    item["sha256"] != sha256(raw[item["chunk"]*65536:(item["chunk"]+1)*65536])
                    for item in chunks)):
            raise ValueError("incomplete, inconsistent or non-lease VM chunks: " + identity)
        selected.append({"id": identity, "bytes": len(raw), "sha256": sha256(raw),
                         "mappedBytes": (len(raw) + page_size - 1) // page_size * page_size,
                         "chunks": chunks})
    if not selected:
        raise ValueError("fixture has no lease VM resources")
    selected.sort(key=lambda item: (-item["bytes"], item["id"]))
    target, pressure = selected[0], selected[1:]
    if target["bytes"] <= 65536:
        raise ValueError("target VM must exceed 65536 bytes; use large_fixture.py")
    if target["mappedBytes"] > IDLE_BUDGET:
        raise ValueError("target must fit the idle budget to require post-release pressure")
    if sum(item["mappedBytes"] for item in pressure) <= IDLE_BUDGET:
        raise ValueError("other lease VM mappings must exceed the 1 MiB idle budget")
    return [target, *pressure]


def descriptor_address(image, identity, size):
    ref = bytes.fromhex(identity) + struct.pack("<II", size, 1)
    offset = image.find(ref)
    if offset < 0 or image.find(ref, offset + 1) >= 0:
        raise ValueError("expected one exact VM descriptor: " + identity)
    for flags, start, va, count, _ in qseg.Elf(image).loads:
        if flags == 5 and start <= offset and offset + len(ref) <= start + count:
            return va + offset - start
    raise ValueError("VM descriptor is not fully inside RX PT_LOAD")


def bind_executable(linked, library, symbols):
    """Hidden offsets are usable only when every final RX load byte matches."""
    def rx(image):
        return [(va, size, image[offset:offset+size])
                for flags, offset, va, size, _ in qseg.Elf(image).loads if flags == 5]
    original, final = rx(linked), rx(library)
    if not final or original != final:
        raise ValueError("linked.so and final SO executable load bytes differ")
    names = ("ndkp_qseg_acquire_v1", "ndkp_qseg_release_v1", "ndkp_qseg_stats_v1", "JNI_OnLoad")
    for name in names:
        if name not in symbols or not any(va <= symbols[name] < va + size for va, size, _ in final):
            raise ValueError("missing or non-RX probe symbol: " + name)
    return [{"address": va, "bytes": size, "sha256": sha256(raw)} for va, size, raw in final]


def write_header(path, resources, spans, symbols, page_size):
    def array(value):
        return "{" + ",".join("0x" + value[i:i+2] for i in range(0, len(value), 2)) + "}"
    lines = ["// Generated from the authenticated final APK, test-only.", "#include <cstdint>",
             "struct ProbeResource { uint64_t address; uint32_t size; uint8_t id[16], digest[32]; };",
             "struct ProbeSpan { uint64_t address, size; uint8_t digest[32]; };",
             "struct ProbeChunk { uint32_t offset, size; uint8_t digest[32]; };",
             f"constexpr uint64_t ExpectedPageSize = {page_size};",
             "const ProbeResource Resources[] = {"]
    for item in resources:
        lines.append("  {%d, %d, %s, %s}," % (item["address"], item["bytes"], array(item["id"]), array(item["sha256"])))
    lines += ["};", "const ProbeSpan ExecutableSpans[] = {"]
    for item in spans:
        lines.append("  {%d, %d, %s}," % (item["address"], item["bytes"], array(item["sha256"])))
    lines += ["};", "const ProbeChunk TargetChunks[] = {"]
    for item in resources[0]["chunks"]:
        lines.append("  {%d, %d, %s}," % (item["chunk"]*65536, item["bytes"], array(item["sha256"])))
    lines += ["};"]
    for name in ("ndkp_qseg_acquire_v1", "ndkp_qseg_release_v1", "ndkp_qseg_stats_v1", "JNI_OnLoad"):
        lines.append(f"constexpr uint64_t Offset_{name} = {symbols[name]};")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--apksigner", type=Path, required=True)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("--output must be new or empty; preserve each run's evidence separately")
    args.output.mkdir(parents=True, exist_ok=True)
    # The ordinary verifier checks real APK signatures and selection/wrapper identity.
    verify([args.apk], args.native, args.native.parent / "generated", args.java,
           args.apksigner, 26, args.output / "apk-verification.json")
    protection = json.loads((args.native / "protection.json").read_text(encoding="utf-8"))
    if (protection.get("qsegLifetimeAbi") != 1 or protection.get("idlePlaintextBudgetBytes") != IDLE_BUDGET or
            protection.get("apkSignatureVerification") is not True):
        raise ValueError("probe requires production APK signature verification and lifetime ABI 1")
    certificate = args.native / "signing-cert.der"
    audited = audit(args.apk, args.native / "protection.json", args.native / "segments.json", certificate)
    with zipfile.ZipFile(args.apk) as archive:
        library_entry = next(item["name"] for item in audited["libraries"] if item["sha256"] == protection["librarySha256"])
        library = archive.read(library_entry)
        _, offset = qseg.locate_image(library)
        asset = library[offset+256:offset+384].split(b"\0", 1)[0].decode("utf-8")
        raw_resources = qseg.unpack(library, archive.read(asset), certificate.read_bytes())
    adb = [str(args.adb), "-P", str(args.server_port), "-s", args.serial]

    def run(*command):
        return subprocess.run([*adb, *map(str, command)], capture_output=True, text=True, timeout=180)

    page_result = run("shell", "getconf", "PAGESIZE")
    page_result.check_returncode()
    page_size = int(page_result.stdout.strip())
    receipt = json.loads((args.native / "segments.json").read_text(encoding="utf-8"))
    resources = select_resources(receipt, raw_resources, page_size)
    linked = (args.native / "linked.so").read_bytes()
    base = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    nm = subprocess.check_output([str(base / "bin/llvm-nm.exe"), "--defined-only", str(args.native / "linked.so")], text=True)
    symbols = {line.split()[-1]: int(line.split()[0], 16) for line in nm.splitlines() if len(line.split()) >= 3}
    spans = bind_executable(linked, library, symbols)
    for item in resources:
        item["address"] = descriptor_address(library, item["id"], item["bytes"])
        if descriptor_address(linked, item["id"], item["bytes"]) != item["address"]:
            raise ValueError("linked/final VM descriptor address differs")
    write_header(args.output / "cache_plan.h", resources, spans, symbols, page_size)
    plan = {"apkSha256": audited["apkSha256"], "libraryEntry": library_entry,
            "librarySha256": protection["librarySha256"], "linkedSha256": sha256(linked),
            "containerSha256": protection["containerSha256"], "segmentsReceiptSha256": protection["segmentsReceiptSha256"],
            "protectionSha256": sha256((args.native / "protection.json").read_bytes()),
            "pageSize": page_size, "idleBudgetBytes": IDLE_BUDGET,
            "pressureMappedBytes": sum(item["mappedBytes"] for item in resources[1:]),
            "resources": resources, "executableSpans": spans, "symbols": symbols}
    (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    executable = args.output / "cache-probe"
    subprocess.run([str(base / "bin/clang++.exe"), "--target=aarch64-linux-android26", "--sysroot=" + str(base / "sysroot"),
                    "-Oz", "-static-libstdc++", "-I" + str(args.output), str(Path(__file__).with_suffix(".cpp")),
                    "-ldl", "-o", str(executable)], check=True)
    remote = "/data/local/tmp/ndkp-qseg-probe-" + uuid.uuid4().hex
    run("shell", "mkdir", remote).check_returncode()
    try:
        run("push", args.apk, remote + "/protected.apk").check_returncode()
        run("push", executable, remote + "/probe").check_returncode()
        run("shell", "chmod", "755", remote + "/probe").check_returncode()
        results = []
        for mode in ("read", "write"):
            result = run("shell", remote + "/probe", remote + "/protected.apk!/" + library_entry, mode)
            expected = result.returncode == 0 if mode == "read" else result.returncode == 139 and "write=attempt" in result.stdout
            if not expected:
                raise RuntimeError(f"probe {mode} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
            results.append({"mode": mode, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        observation = json.loads(results[0]["stdout"])
        report = {"schemaVersion": 1, "scope": "signed-apk-production-lease-probe", "serial": args.serial,
                  "pageSize": page_size, "apkSha256": audited["apkSha256"], "targetId": resources[0]["id"],
                  "targetSha256": resources[0]["sha256"], "resourceBytes": resources[0]["bytes"],
                  "crossChunk": True, "lifetimeAbi": 1, "pressureMappedBytes": plan["pressureMappedBytes"],
                  "planSha256": sha256((args.output / "plan.json").read_bytes()),
                  "headerSha256": sha256((args.output / "cache_plan.h").read_bytes()),
                  "sourceSha256": {path.name: sha256(path.read_bytes()) for path in
                                   (Path(__file__), Path(__file__).with_suffix(".cpp"))},
                  "executableSha256": sha256(executable.read_bytes()), "observation": observation,
                  "directWipeObservation": False, "copyValidated": False, "productionWrapperExecution": False,
                  "results": results}
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))
    finally:
        run("shell", "rm", "-f", remote + "/probe", remote + "/protected.apk").check_returncode()
        run("shell", "rmdir", remote).check_returncode()


if __name__ == "__main__":
    main()
