"""Build and run explicit sensitive native borrows in a real signed QSEG fixture.

NDKP_APK_VERIFY is intentionally off. The device uses production certificate
binding and QSEG authentication; apksigner performs the host signature check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import seal_qseg as qseg
from cache_probe import descriptor_address

ASSET = "assets/scoped.qseg"
LIBRARY = "lib/arm64-v8a/libscoped.so"
SOURCE_FILES = ("runtime/ndkp_qseg_runtime.cpp", "runtime/qseg.h", "runtime/ndkp_cse_runtime.cpp",
                "runtime/cse_crypto.h", "runtime/cse_region.h", "runtime/apkcert.h",
                "runtime/apkcert_io.h", "runtime/sha256.h", "scripts/seal_qseg.py",
                "scripts/seal_cse.py", "tests/qseg/cache_probe.py", "tests/qseg/scoped_sensitive.cpp",
                "tests/qseg/scoped_sensitive.py")
APK_NAMES = ("pristine", "observed", "wrong-cert", "tampered-asset", "tampered-last-block")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    path = Path(path).resolve()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def fresh_output(path):
    path = path.resolve()
    require(not path.exists() or path.is_dir() and not any(path.iterdir()), "output must be new or empty")
    path.mkdir(parents=True, exist_ok=True)
    return path


def command(argv, output, records, timeout=300):
    argv = list(map(str, argv))
    number = len(records) + 1
    process = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
    stdout, stderr = output / f"command-{number:02d}.stdout", output / f"command-{number:02d}.stderr"
    stdout.write_bytes(process.stdout); stderr.write_bytes(process.stderr)
    records.append({"argv": argv, "returnCode": process.returncode,
                    "stdout": identity(stdout), "stderr": identity(stderr)})
    write_json(output / "commands.json", records)
    require(process.returncode == 0, f"command {number} failed ({process.returncode}); see {stderr}")
    return process.stdout, process.stderr


def resources():
    result = []
    for name, kind, size, seed in (("native-record", 1, 700003, 17), ("string-block", 2, 203, 29)):
        raw = bytes(1 + (i * 73 + (i >> 8) * 29 + (i >> 16) * 17 + seed * 41) % 255 for i in range(size))
        identifier = hashlib.sha256(("ndkp-scoped-fixture-v1:" + name).encode("ascii")).digest()[:16]
        result.append((identifier, kind, raw, name))
    return result


def stage_fixture(output, staged):
    stage = output / "staging"; stage.mkdir()
    manifest, assembly = [], ['.section .text.ndkp.qseg.refs,"ax",%progbits', '.balign 8',
                              '.global ndkp_scoped_refs', '.hidden ndkp_scoped_refs', 'ndkp_scoped_refs:']
    header = ["// Generated test expectations; payload stays in staging, outside the SO.", "#include <cstdint>",
              "struct ScopedResource { uint32_t size; uint8_t digest[32]; };", "constexpr ScopedResource Resources[] = {"]
    for identifier, kind, raw, name in staged:
        item = {"id": identifier.hex(), "kind": kind, "bytes": len(raw), "name": name}
        manifest.append(item); (stage / (identifier.hex() + ".bin")).write_bytes(raw)
        descriptor = identifier + struct.pack("<II", len(raw), kind)
        assembly.append(".byte " + ",".join(map(str, descriptor)))
        header.append("  {%d,{%s}}," % (len(raw), ",".join(map(str, hashlib.sha256(raw).digest()))))
    header.append("};")
    write_json(stage / "manifest.json", manifest)
    (output / "scoped_refs.S").write_text("\n".join(assembly) + "\n", encoding="utf-8")
    (output / "scoped_plan.h").write_text("\n".join(header) + "\n", encoding="utf-8")


def tamper_last_chunk(library, container, certificate, staged):
    _, position = qseg.locate_image(library); header = library[position:position + 512]
    root = qseg.derive(header, header[152:184], qseg.expected_inputs(2, certificate=certificate))
    size = qseg.u32(container, 12)
    directory = qseg.decrypt(qseg.index_key(root, header), bytes(12), container[:16] + header[24:40],
                             container[16:16 + size], container[16 + size:32 + size])
    entries = [qseg.ENTRY.unpack_from(directory, offset) for offset in range(0, size, qseg.ENTRY.size)]
    target = [entry for entry in entries if entry[0] == staged[0][0]]
    require(len(target) > 1, "native target must have multiple authenticated chunks")
    last = target[-1]; offset = last[3] + last[4] - 1
    changed = bytearray(container); changed[offset] ^= 1
    image = bytearray(library); image[position + 384:position + 416] = hashlib.sha256(changed).digest()
    try:
        qseg.unpack(image, changed, certificate)
    except ValueError as error:
        require("authentication" in str(error), "tampered chunk must fail AEAD after its outer digest passes")
    else:
        raise ValueError("tampered last chunk was accepted")
    return bytes(image), bytes(changed), {"resource": staged[0][0].hex(), "chunk": last[2],
                                        "offset": offset, "outerDigestUpdated": True}


def verify_certificate(stdout, certificate):
    # Same accepted apksigner labels and single-signer gate as verify_dex2c_apk.py.
    digests = set(value.lower() for value in re.findall(
        rb"^(?:Signer #\d+|V[0-9.]+ Signer(?: #\d+)?):? certificate SHA-256 digest: ([0-9a-fA-F]{64})\r?$",
        stdout, re.M))
    counts = re.findall(rb"^Number of signers: (\d+)\s*$", stdout, re.M)
    require(counts == [b"1"] and digests == {hashlib.sha256(certificate).hexdigest().encode("ascii")},
            "host signature certificate mismatch")


def build(args):
    output = fresh_output(args.output); records = []
    sources = {name: identity(ROOT / name) for name in SOURCE_FILES}
    suffix = ".exe" if os.name == "nt" else ""
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    prebuilt = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    resource = sorted(path for path in (prebuilt / "lib/clang").iterdir() if path.is_dir() and path.name.startswith("21"))
    require(len(resource) == 1, "expected one NDK Clang 21 resource directory")
    compiler = args.clang.resolve(); java = args.java.resolve()
    tools = args.sdk.resolve() / "build-tools/37.0.0"
    apksigner = tools / "lib/apksigner.jar"
    platform = args.sdk.resolve() / "platforms/android-37.0/android.jar"
    keytool = java.with_name("keytool" + suffix)
    for label in ("test", "wrong"):
        command([keytool, "-genkeypair", "-keystore", output / (label + ".jks"), "-storepass", "android",
                 "-keypass", "android", "-alias", "test", "-keyalg", "RSA", "-dname",
                 "CN=qseg scoped " + label, "-validity", "3650", "-noprompt"], output, records)
        command([keytool, "-exportcert", "-keystore", output / (label + ".jks"), "-storepass", "android",
                 "-alias", "test", "-file", output / (label + ".der")], output, records)
    certificate = (output / "test.der").read_bytes(); staged = resources(); stage_fixture(output, staged)
    common = [compiler, "--driver-mode=g++", "--target=aarch64-linux-android26",
              "--sysroot=" + str(prebuilt / "sysroot"), "-resource-dir=" + str(resource[0]),
              "--ld-path=" + str(prebuilt / ("bin/ld.lld" + suffix)), "-std=gnu++17", "-fPIC",
              "-fvisibility=hidden", "-fno-exceptions", "-frtti", "-fno-fast-math", "-ffp-contract=off",
              "-ffunction-sections", "-fdata-sections", "-fno-lto", "-I" + str(output)]
    command([*common, "-O1", "-DNDKP_QSEG", "-DNDKP_CSE_VMP", "-fno-vectorize", "-fno-slp-vectorize",
             "-fno-unroll-loops", "-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict", "-mllvm",
             "-irobf-vmp-memops", "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry",
             "-S", "-emit-llvm", ROOT / "runtime/ndkp_cse_runtime.cpp", "-o", output / "cse.raw.ll"], output, records)
    command([*common, "-Oz", "-mllvm", "-irobf-vmp-post", "-S", "-emit-llvm", output / "cse.raw.ll",
             "-o", output / "cse.ll"], output, records)
    command([*common, "-Oz", "-Xclang", "-disable-llvm-passes", "-c", output / "cse.ll",
             "-o", output / "cse.o"], output, records)
    command([*common, "-Oz", "-c", ROOT / "runtime/ndkp_qseg_runtime.cpp", "-o", output / "qseg.o"], output, records)
    command([*common, "-c", output / "scoped_refs.S", "-o", output / "refs.o"], output, records)
    command([*common, "-Oz", "-DNDKP_SCOPED_RUNNER", ROOT / "tests/qseg/scoped_sensitive.cpp",
             "-static-libstdc++", "-ldl", "-o", output / "runner"], output, records)
    exports = output / "exports.map"; exports.write_text("{ global: ndkp_scoped_test; local: *; };\n", encoding="utf-8")
    candidates, bindings = {}, {}
    for label, observed in (("pristine", False), ("observed", True)):
        directory = output / label; directory.mkdir()
        image = qseg.prepare(staged, ASSET, certificate)
        source = directory / "image.cpp"
        source.write_text('extern "C" { __attribute__((visibility("hidden"),section(".rodata.ndkp.qseg"),used)) '
                          'extern const unsigned char ndkp_qseg_image[512]={' + ','.join(map(str, image)) + '}; }\n', encoding="utf-8")
        command([*common, "-Oz", "-c", source, "-o", directory / "image.o"], output, records)
        command([*common, "-Oz", *(["-DNDKP_SCOPED_OBSERVER"] if observed else []), "-c",
                 ROOT / "tests/qseg/scoped_sensitive.cpp", "-o", directory / "caller.o"], output, records)
        command([*common, output / "qseg.o", output / "cse.o", output / "refs.o", directory / "image.o",
                 directory / "caller.o", "-shared", "-static-libstdc++", "-lz", "-ldl", "-lm",
                 "-Wl,--rosegment", "-Wl,--gc-sections", "-Wl,--exclude-libs,ALL", "-Wl,--no-undefined",
                 "-Wl,--version-script=" + str(exports), "-Wl,-z,max-page-size=16384", "-Wl,-z,common-page-size=16384",
                 *(["-Wl,--wrap=mmap", "-Wl,--wrap=munmap"] if observed else []),
                 "-o", directory / "linked.so"], output, records)
        library, container, receipt = qseg.pack((directory / "linked.so").read_bytes(), staged)
        require(qseg.unpack(library, container, certificate) == {(i, k): raw for i, k, raw, _ in staged},
                "authenticated resource recovery mismatch")
        addresses = [descriptor_address(library, i.hex(), len(raw), kind) for i, kind, raw, _ in staged]
        (directory / "libscoped.so").write_bytes(library); (directory / "scoped.qseg").write_bytes(container)
        write_json(directory / "segments.json", receipt)
        candidates[label] = library, container
        bindings[label] = {"descriptors": addresses, "codeSha256": qseg.Elf(library).code_hash().hex(),
                           "observer": observed, "ordinaryReceiptPolicyUnchanged": True}
    original, payload = candidates["pristine"]
    changed = bytearray(payload); changed[-1] ^= 1
    candidates["wrong-cert"] = original, payload
    candidates["tampered-asset"] = original, bytes(changed)
    bad_image, bad_payload, tamper = tamper_last_chunk(original, payload, certificate, staged)
    candidates["tampered-last-block"] = bad_image, bad_payload
    manifest = output / "AndroidManifest.xml"
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.ndkp.scoped">'
                        '<application android:extractNativeLibs="false"/></manifest>\n', encoding="utf-8")
    command([tools / ("aapt2" + suffix), "link", "-o", output / "manifest.apk", "--manifest", manifest,
             "-I", platform, "--min-sdk-version", "26", "--target-sdk-version", "28"], output, records)
    with zipfile.ZipFile(output / "manifest.apk") as archive:
        binary_manifest = archive.read("AndroidManifest.xml")
    for label, (library, container) in candidates.items():
        unsigned, aligned, apk = (output / (label + ending) for ending in ("-unsigned.apk", "-aligned.apk", ".apk"))
        with zipfile.ZipFile(unsigned, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("AndroidManifest.xml", binary_manifest); archive.writestr(LIBRARY, library)
            archive.writestr(ASSET, container)
        command([tools / ("zipalign" + suffix), "-P", "16", "-f", "4", unsigned, aligned], output, records)
        key = "wrong" if label == "wrong-cert" else "test"
        command([java, "-jar", apksigner, "sign", "--ks", output / (key + ".jks"), "--ks-key-alias", "test",
                 "--ks-pass", "pass:android", "--min-sdk-version", "26", "--out", apk, aligned], output, records)
        verified, _ = command([java, "-jar", apksigner, "verify", "--verbose", "--print-certs", apk], output, records)
        verify_certificate(verified, (output / (key + ".der")).read_bytes())
    require(sources == {name: identity(ROOT / name) for name in SOURCE_FILES}, "source changed during build")
    artifacts = {path.relative_to(output).as_posix(): identity(path) for path in output.rglob("*")
                 if path.is_file() and not path.name.startswith("command-") and path.name != "commands.json"}
    report = {"status": "built", "sources": sources, "compiler": identity(compiler),
              "ndk": identity(args.ndk.resolve() / "source.properties"), "artifacts": artifacts,
              "resources": [{"id": i.hex(), "kind": k, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                            for i, k, raw, _ in staged], "bindings": bindings, "tamperedLastChunk": tamper,
              "apkVerifyMacro": False, "commands": records}
    write_json(output / "build.json", report)
    print(json.dumps({"status": report["status"], "output": str(output), "apkVerifyMacro": False}), flush=True)


def parse_records(stderr, token):
    records = []
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        if not line.startswith("SCOPED:"):
            require("LOAD_ERROR:" not in line, "native fixture failed to load")
            continue
        require(line.startswith("SCOPED:" + token + ":"), "foreign run token")
        payload = line[len(token) + 8:]
        pieces = payload.split(" "); name, fields = pieces[0], {}
        require(name and all(re.fullmatch(r"[a-z_]+=[A-Za-z0-9_.-]+", value) for value in pieces[1:]), "bad record syntax")
        for value in pieces[1:]:
            key, field = value.split("=", 1); require(key not in fields, "duplicate record field"); fields[key] = field
        records.append((name, fields))
    return records


def validate_run(stdout, stderr, token, mode, observer, page, authentication_failure=None):
    records = parse_records(stderr, token); cursor = 0

    def take(name, **fields):
        nonlocal cursor
        require(cursor < len(records), "missing " + name)
        actual_name, actual_fields = records[cursor]; cursor += 1
        require(actual_name == name and actual_fields == {key: str(value) for key, value in fields.items()}, "unexpected " + name)

    def phase(name, index, reject=False):
        size = (700003, 203)[index]; rounded = (size + page - 1) // page * page
        require(cursor < len(records), "missing phase " + name)
        begin = records[cursor][1].get("begin", "")
        require(re.fullmatch(r"0x[0-9a-f]+", begin) and int(begin, 16) > 0 and int(begin, 16) % page == 0, "bad mapping address")
        if observer:
            take("POISON", phase=name, resource=index, begin=begin, bytes=size, mapped=rounded, padding=rounded-size, value=165)
        take("ACQUIRED", phase=name, resource=index, begin=begin, bytes=size, mapped=rounded,
             padding=rounded-size, padding_value=165 if observer else 0)
        if name == "concurrent":
            take("NESTED", leases=3, owner_live=1)
            take("CONCURRENT", borrowers=8, same_pointer=1, owner_live_after_release=1)
        if mode == "write":
            take("ATTEMPT", mode="write"); return
        take("RELEASE_ATTEMPT", phase=name, resource=index, begin=begin, mapped=rounded)
        if observer:
            if reject:
                take("INJECT_PADDING", offset=rounded-1, value=123)
            take("ZERO_SCAN", phase=name, resource=index, begin=begin, mapped=rounded, checked=rounded,
                 padding=rounded-size, nonzero=1 if reject else 0, first=rounded-1 if reject else rounded,
                 value=123 if reject else 0)
            if reject:
                take("REJECT_NONZERO", real_unmaps=0, code=123); return
            take("REAL_UNMAP", phase=name, resource=index, begin=begin, mapped=rounded, result=0)
        take("ABSENT", phase=name, resource=index, begin=begin, mapped=rounded)

    take("CHILD_BEGIN", mode=mode); take("AUTH_ATTEMPT", apk_verify=0)
    code, signal = 0, 0
    if authentication_failure == "initialization":
        code = 127
    else:
        take("AUTH_OK")
        if authentication_failure == "last-chunk":
            take("ATTEMPT", mode="auth"); code = 127
        elif mode == "positive":
            for name, index in (("concurrent", 0), ("reload", 0), ("mixed", 1), ("mixed-reload", 1)):
                phase(name, index)
            rounded = (203 + page - 1) // page * page
            take("MIXED", separate=1, ordinary_pinned=rounded, ordinary_peak=rounded, copy_bytes=203, copy_wiped=1)
            take("COMPLETE", observer=int(observer), releases=4, scans=4 if observer else 0,
                 real_unmaps=4 if observer else 0, page=page)
        elif mode == "enomem":
            require(observer, "ENOMEM requires the isolated observer")
            phase("warmup", 1); take("ATTEMPT", mode="enomem")
            take("MMAP_ENOMEM", phase="enomem", bytes=700003, hits=1, errno=12); code = 127
        else:
            phase("negative", 0, mode == "reject-padding")
            if mode == "write":
                signal = 11
            elif mode == "reject-padding":
                require(observer, "padding control requires the isolated observer"); code = 123
            else:
                require(mode in ("double-release", "invalid-ref"), "unknown fixture mode")
                take("ATTEMPT", mode=mode); code = 127
    require(cursor == len(records), "extra or out-of-order events")
    match = re.fullmatch(rb"SCOPED:" + token.encode("ascii") + rb":WAIT status=(\d+) exited=(\d) code=(-?\d+) signal=(\d+)\r?\n", stdout)
    require(match is not None, "missing exact child wait status")
    status, exited, actual_code, actual_signal = map(int, match.groups())
    if signal:
        require(exited == 0 and actual_code == -1 and actual_signal == signal and status in (signal, signal | 128), "wrong signal")
    else:
        require(exited == 1 and actual_code == code and actual_signal == 0 and status == code << 8, "wrong child exit")
    return {"childStatus": status, "exitCode": actual_code, "signal": actual_signal, "events": len(records)}


def run(args):
    output = fresh_output(args.output); fixtures = args.fixtures.resolve(); records = []
    build_report = json.loads((fixtures / "build.json").read_text(encoding="utf-8"))
    require(build_report["status"] == "built" and build_report["apkVerifyMacro"] is False, "unsupported fixture build")
    paths = {**{name: ROOT / name for name in build_report["sources"]},
             **{"fixture/" + name: fixtures / name for name in build_report["artifacts"]}}
    expected = {**build_report["sources"], **{"fixture/" + name: value for name, value in build_report["artifacts"].items()}}
    require({name: identity(path) for name, path in paths.items()} == expected, "fixture/source changed before run")
    require(args.serial and not re.search(r"\s", args.serial) and not args.serial.startswith("-"), "invalid serial")
    require(1 <= args.server_port <= 65535, "invalid adb port")
    adb = [args.adb.resolve(), "-P", str(args.server_port), "-s", args.serial]
    device = {}
    for name, argv in (("api", ["getprop", "ro.build.version.sdk"]), ("abi", ["getprop", "ro.product.cpu.abi"]),
                       ("page", ["getconf", "PAGESIZE"]), ("fingerprint", ["getprop", "ro.build.fingerprint"])):
        raw, _ = command([*adb, "shell", *argv], output, records); device[name] = raw.decode("utf-8").strip()
    page = int(device["page"])
    require(int(device["api"]) >= 26 and device["abi"] == "arm64-v8a" and page > 0 and not page & (page-1), "unsupported device")
    remote = "/data/local/tmp/qseg-scoped-" + uuid.uuid4().hex
    remote_files = [remote + "/runner", *(remote + "/" + name + ".apk" for name in APK_NAMES)]
    cases, error, cleanup_errors = [], None, []
    try:
        command([*adb, "shell", "mkdir", remote], output, records)
        for source, destination in zip([fixtures / "runner", *(fixtures / (name + ".apk") for name in APK_NAMES)], remote_files):
            command([*adb, "push", source, destination], output, records)
        command([*adb, "shell", "chmod", "755", remote_files[0]], output, records)
        specifications = (("pristine", "positive", False, None), ("observed", "positive", True, None),
                          ("pristine", "write", False, None), ("pristine", "double-release", False, None),
                          ("pristine", "invalid-ref", False, None), ("observed", "reject-padding", True, None),
                          ("observed", "enomem", True, None), ("wrong-cert", "auth", False, "initialization"),
                          ("tampered-asset", "auth", False, "initialization"),
                          ("tampered-last-block", "auth", False, "last-chunk"))
        for apk, mode, observer, failure in specifications:
            token = uuid.uuid4().hex
            argv = [*adb, "shell", remote + "/runner", remote + "/" + apk + ".apk!/" + LIBRARY, mode, token]
            stdout, stderr = command(argv, output, records, 180)
            cases.append({"apk": apk, "mode": mode, "observer": observer, "token": token,
                          "authenticationFailure": failure,
                          **validate_run(stdout, stderr, token, mode, observer, page, failure),
                          "command": len(records)})
    except Exception as caught:
        error = str(caught)
    finally:
        for argv in ([*adb, "shell", "rm", "-f", *remote_files], [*adb, "shell", "rmdir", remote]):
            try:
                command(argv, output, records, 60)
            except Exception as caught:
                cleanup_errors.append(str(caught))
    require({name: identity(path) for name, path in paths.items()} == expected, "fixture/source changed during run")
    report = {"status": "failed" if error or cleanup_errors else "passed", "fixtures": str(fixtures),
              "build": identity(fixtures / "build.json"), "device": device, "apkVerifyMacro": False,
              "cases": cases, "commands": records, "error": error, "cleanupErrors": cleanup_errors}
    write_json(output / ("failure.json" if error or cleanup_errors else "results.json"), report)
    require(report["status"] == "passed", "scoped fixture failed; see " + str(output / "failure.json"))
    print(json.dumps({"status": report["status"], "cases": len(cases), "device": device, "output": str(output)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__); subparsers = parser.add_subparsers(dest="mode", required=True)
    builder = subparsers.add_parser("build")
    for name in ("output", "ndk", "clang", "java", "sdk"):
        builder.add_argument("--" + name, type=Path, required=True)
    runner = subparsers.add_parser("run")
    for name in ("fixtures", "output", "adb"):
        runner.add_argument("--" + name, type=Path, required=True)
    runner.add_argument("--serial", required=True); runner.add_argument("--server-port", type=int, default=5037)
    args = parser.parse_args(); (build if args.mode == "build" else run)(args)


if __name__ == "__main__":
    main()
