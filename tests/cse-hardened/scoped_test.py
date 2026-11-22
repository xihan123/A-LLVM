"""Observe scoped CSE mappings, optionally from signed, package/certificate-bound APKs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/cse-hardened"
SIGNED_PACKAGE = "test.ndkp.cse.scoped"
SIGNED_LIBRARY = "lib/arm64-v8a/libscoped.so"
sys.path.insert(0, str(ROOT / "scripts"))
import seal_cse as cse


def digest(path):
    data = Path(path).read_bytes()
    return {"path": str(Path(path).resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Commands:
    def __init__(self, out, phase):
        self.folder = out / (phase + "-commands")
        self.folder.mkdir()
        self.index = 0

    def run(self, *argv, check=True, artifact=None):
        argv = [str(part) for part in argv]
        self.index += 1
        folder = self.folder / f"{self.index:03}"
        folder.mkdir()
        input_paths = [part.split("=", 1)[1] if part.startswith("-irobf-cert-file=") else part for part in argv]
        inputs = [digest(path) for path in dict.fromkeys(input_paths) if Path(path).is_file()]
        started = datetime.now(timezone.utc).isoformat()
        try:
            process = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=180)
            stdout, stderr, rc = process.stdout, process.stderr, process.returncode
            status = "finished"
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, rc = exc.stdout or b"", exc.stderr or b"", None
            status = "timeout"
        streams = {}
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            path = folder / (name + ".log")
            path.write_bytes(data)
            streams[name] = digest(path)
        receipt = {"argv": argv, "cwd": str(ROOT), "startedUtc": started,
                   "finishedUtc": datetime.now(timezone.utc).isoformat(), "returnCode": rc,
                   "status": status, "timeoutSeconds": 180, "inputs": inputs, **streams}
        if artifact:
            receipt["executedArtifact"] = digest(artifact)
        (folder / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        if check and rc != 0:
            raise RuntimeError(f"command receipt {folder / 'receipt.json'}: rc={rc}\n"
                               + stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace"))
        return subprocess.CompletedProcess(argv, rc, stdout.decode("utf-8", "replace"),
                                           stderr.decode("utf-8", "replace"))


def function(ir, name):
    match = re.search(r"^define [^\n]*@" + re.escape(name) + r"\(.*?^}", ir, re.M | re.S)
    assert match, name
    return match[0]


def inspect_static(ir, shared, name="scoped_static_value"):
    static = function(ir, name)
    assert "cse.scoped" not in static and "@ndkp_cse_module_acquire" not in static, static
    returned = re.findall(r"^\s*ret ptr (@dec[\w.$]+)", static, re.M)
    assert len(returned) == 1, static
    buffer = returned[0]
    storage = re.search(r"^" + re.escape(buffer) + r" = private global \[(\d+) x i8\] zeroinitializer", ir, re.M)
    assert storage and int(storage[1]) >= 26, buffer
    wrappers = re.findall(r"@ndkp_decrypt_string_[0-9a-fA-F]+", static)
    if wrappers:
        assert len(wrappers) == 1 and int(wrappers[0].rsplit("_", 1)[1], 16) == shared, wrappers
        assert re.search(re.escape(wrappers[0]) + r"\(ptr " + re.escape(buffer) + r",", static), static
        ordinary = function(ir, wrappers[0][1:])
        parameters = re.search(re.escape(wrappers[0]) + r"\(ptr (%[\w.]+),", ordinary)
        assert parameters, ordinary
        destination = parameters[1]
    else:
        ordinary, destination = static, buffer
    calls = re.findall(r"call void @ndkp_cse_module_decode\([^\n]+", ordinary)
    assert len(calls) == 1 and calls[0].startswith("call void @ndkp_cse_module_decode(ptr " + destination + ","), ordinary
    region = re.search(r"ptr @ndkp_cse_v1_regions, i(?:32|64) 0, i(?:32|64) (\d+)\)\)", calls[0])
    if region:
        assert int(region[1]) == shared, calls[0]
    else:
        assert shared == 0 and calls[0].endswith(", ptr @ndkp_cse_v1_regions)"), calls[0]
    status = "@dec_status_" + buffer[len("@dec"):]
    assert re.search(r"cmpxchg ptr " + re.escape(status) + r", i32 0, i32 1", ordinary), ordinary
    assert re.search(r"store atomic i32 2, ptr " + re.escape(status) + r" release", ordinary), ordinary
    print(f"[ir] {name}: region {shared}, independent static buffer, ordinary once decode chain", flush=True)


def inspect_scoped(ir, optimization):
    guard = function(ir, "ndkp_cse_module_acquire")
    assert guard.count("load volatile") == 5 and "@ndkp_cse_acquire_region_v1" in guard
    assert 'section ".text.ndkp.cse.regions"' in ir and "call void @llvm.sideeffect" not in ir
    ids = {}
    for name, count in (("scoped_multi", 2), ("scoped_recursive", 1), ("scoped_thread", 1), ("scoped_unused_gate", 1)):
        body = function(ir, name)
        leases = re.findall(r"(%cse\.scoped\.lease\.\d+) = alloca \{ ptr, i64, i32 }", body)
        releases = re.findall(r"call void @ndkp_cse_release_region_v1\(ptr (%cse\.scoped\.lease\.\d+)\)", body)
        returns = len(re.findall(r"^\s*ret ", body, re.M))
        assert len(leases) == count and body.count("call ptr @ndkp_cse_module_acquire") == count, (name, leases)
        assert releases == list(reversed(leases)) * returns, (name, releases, returns)
        assert "@ndkp_cse_module_decode" not in body and "@dec" not in body
        ids[name] = [int(re.search(r"\.(\d+)$", lease)[1]) for lease in leases]
    shared = ids["scoped_unused_gate"][0]
    assert shared in ids["scoped_multi"] and ids["scoped_recursive"] == [shared] and ids["scoped_thread"] == [shared]
    inspect_static(ir, shared)
    if optimization == "O2":
        driver = function(ir, "scoped_unused_driver")
        assert len(re.findall(r"\bcall\b[^\n]*@scoped_relay_outer\(", driver)) == 2, driver
        assert "@scoped_relay_inner" in function(ir, "scoped_relay_outer")
        assert "@scoped_unused_gate" in function(ir, "scoped_relay_inner")
    print(f"[ir] {optimization}: private leases, reverse releases, shared/static isolation, caller preservation", flush=True)
    return ids["scoped_multi"][0]


def ir_fixture(body, *, params="", result="i32", declarations="", globals="", root_align=1,
               attributes="nounwind", extra_annotation=None):
    annotations = ["ndkp.cse_scoped"] + ([extra_annotation] if extra_annotation else [])
    ann_globals = []
    ann_entries = []
    for index, text in enumerate(annotations):
        ann_globals.append(f'@ann{index} = private constant [{len(text) + 1} x i8] c"{text}\\00"')
        ann_entries.append(f'{{ ptr, ptr, ptr, i32, ptr }} {{ ptr @scope_case, ptr @ann{index}, ptr @file, i32 1, ptr null }}')
    return '\n'.join([
        'target triple = "aarch64-unknown-linux-android29"',
        f'@lit = private constant [26 x i8] c"NDKP_CORE_SCOPED_p30_9b6d\\00", align {root_align}',
        '@other = private constant [6 x i8] c"other\\00", align 1',
        '@file = private constant [8 x i8] c"case.ll\\00"', *ann_globals,
        f'@llvm.global.annotations = appending global [{len(annotations)} x {{ ptr, ptr, ptr, i32, ptr }}] ['
        + ', '.join(ann_entries) + '], section "llvm.metadata"',
        globals, 'declare i32 @sink(ptr captures(none)) nounwind', declarations,
        f'define {result} @scope_case({params}) {attributes} {{', 'entry:', body, '}', ''])


def negative_cases():
    return {
        "local-pointer-store": ir_fixture('%slot = alloca ptr\nstore ptr @lit, ptr %slot\nret i32 0'),
        "global-pointer": ir_fixture('%p = load ptr, ptr @holder\n%r = call i32 @sink(ptr %p)\nret i32 %r',
                                     globals='@holder = internal global ptr @lit'),
        "aggregate": ir_fixture('%p = load ptr, ptr @holder\n%r = call i32 @sink(ptr %p)\nret i32 %r',
                                globals='@holder = internal global { ptr } { ptr @lit }'),
        "pointer-return": ir_fixture('ret ptr @lit', result="ptr"),
        "unknown-capture": ir_fixture('%r = call i32 @unknown(ptr @lit)\nret i32 %r',
                                      declarations='declare i32 @unknown(ptr) nounwind'),
        "missing-nounwind": ir_fixture('%r = call i32 @sink(ptr @lit)\nret i32 %r', attributes=""),
        "throwing-call": ir_fixture('%r = call i32 @throws(ptr @lit)\nret i32 %r',
                                    declarations='declare i32 @throws(ptr captures(none))'),
        "eh": ir_fixture('%r = invoke i32 @throws(ptr @lit) to label %done unwind label %error\n'
                         'done:\nret i32 %r\nerror:\n%e = landingpad {ptr, i32} cleanup\nresume {ptr, i32} %e',
                         declarations='declare i32 @throws(ptr captures(none))\ndeclare i32 @personality(...)',
                         attributes='nounwind personality ptr @personality'),
        "musttail": ir_fixture('%r = musttail call i32 @sink(ptr @lit)\nret i32 %r', params="ptr %arg"),
        "returns-twice": ir_fixture('%r = call i32 @again(ptr @lit)\nret i32 %r',
                                    declarations='declare i32 @again(ptr captures(none)) nounwind returns_twice'),
        "indirect-call": ir_fixture('%r = call i32 %target(ptr @lit) nounwind\nret i32 %r', params="ptr %target"),
        "operand-bundle": ir_fixture('%r = call i32 @sink(ptr @lit) ["deopt"(i32 0)]\nret i32 %r'),
        "ptrtoint": ir_fixture('%p = ptrtoint ptr @lit to i64\n%r = trunc i64 %p to i32\nret i32 %r'),
        "different-region-equality": ir_fixture('%eq = icmp eq ptr @lit, @other\n%r = zext i1 %eq to i32\nret i32 %r'),
        "pointer-ordering": ir_fixture('%eq = icmp ult ptr @lit, @other\n%r = zext i1 %eq to i32\nret i32 %r'),
        "external-select-equality": ir_fixture('%a = select i1 %which, ptr @lit, ptr %external\n'
                                              '%b = select i1 %which, ptr %external, ptr @lit\n'
                                              '%eq = icmp eq ptr %a, %b\n%r = zext i1 %eq to i32\nret i32 %r',
                                              params="ptr %external, i1 %which"),
        "non-inbounds-null": ir_fixture('%p = getelementptr i8, ptr @lit, i64 %offset\n'
                                        '%eq = icmp eq ptr %p, null\n%r = zext i1 %eq to i32\nret i32 %r',
                                        params="i64 %offset"),
        "high-root-align": ir_fixture('%v = load volatile i8, ptr @lit, align 65536\n%r = zext i8 %v to i32\nret i32 %r', root_align=65536),
        "high-load-align": ir_fixture('%v = load volatile i8, ptr @lit, align 65536\n%r = zext i8 %v to i32\nret i32 %r'),
        "high-callsite-align": ir_fixture('%r = call i32 @sink(ptr align 65536 @lit)\nret i32 %r'),
        "high-callee-align": ir_fixture('%r = call i32 @aligned(ptr @lit)\nret i32 %r',
                                        declarations='declare i32 @aligned(ptr captures(none) align 65536) nounwind'),
        "high-memcpy-align": ir_fixture('call void @llvm.memcpy.p0.p0.i64(ptr align 1 %out, ptr align 65536 @lit, i64 26, i1 false)\nret i32 0',
                                        params="ptr %out", declarations='declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1) nounwind'),
        "assume-align-bundle": ir_fixture('call void @llvm.assume(i1 true) ["align"(ptr @lit, i64 65536)]\nret i32 0',
                                          declarations='declare void @llvm.assume(i1) nounwind'),
        "vmp-annotation": ir_fixture('%r = call i32 @sink(ptr @lit)\nret i32 %r', extra_annotation="ndkp.vmp"),
    }


def module_and_tags(data, package=None, certificate=None):
    image = cse.Elf(data)
    assert len(image.payloads()) == 1
    payload, total = image.payloads()[0]
    blob = data[payload:payload + total]
    key = cse.derive(blob, image.code_hash(), cse.expected_inputs(cse.u32(blob, 16), package, certificate))
    regions = bytearray()
    tags = {}
    for ordinal, offset, capacity in cse.records(blob):
        plain = cse.decrypt(key, blob[offset + 4:offset + 16], cse.record_aad(blob, ordinal, capacity),
                            blob[offset + 32:offset + 32 + capacity], blob[offset + 16:offset + 32])
        encoding = struct.unpack_from("<I", plain, 4)[0]
        regions += struct.pack("<III", offset, capacity - 16, encoding)
        tags[ordinal] = payload + offset + 16
    table = data.find(regions)
    assert table >= 0 and data.find(regions, table + 1) == -1
    assert any(start <= table and table + len(regions) <= start + size for _, size, start in image.executable)

    def virtual(offset):
        return next(va + offset - start for _, start, va, size, _ in image.loads if start <= offset < start + size)

    def position(address):
        return next(start + address - va for _, start, va, size, _ in image.loads if va <= address < va + size)

    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count = struct.unpack_from("<HH", data, 58)
    relocations = {}
    for index in range(count):
        entry = shoff + index * entsize
        if struct.unpack_from("<I", data, entry + 4)[0] != 4:
            continue
        offset, size = struct.unpack_from("<QQ", data, entry + 24)
        for cursor in range(offset, offset + size, 24):
            address, info, addend = struct.unpack_from("<QQq", data, cursor)
            if info == 1027:
                relocations[address] = addend
    modules = [address for address, addend in relocations.items() if addend == virtual(payload)
               and relocations.get(address + 16) == virtual(table)]
    assert len(modules) == 1
    return position(modules[0]), tags


def signing_tools(args, out, commands, extension):
    folder = out / "signed"
    folder.mkdir()
    java = args.java.resolve()
    tools = args.sdk.resolve() / "build-tools/37.0.0"
    keytool = java.with_name("keytool" + extension)
    for label in ("test", "wrong"):
        commands.run(keytool, "-genkeypair", "-keystore", folder / (label + ".jks"), "-storepass", "android",
                     "-keypass", "android", "-alias", "test", "-keyalg", "RSA", "-dname",
                     "CN=cse scoped " + label, "-validity", "3650", "-noprompt")
        commands.run(keytool, "-exportcert", "-keystore", folder / (label + ".jks"), "-storepass", "android",
                     "-alias", "test", "-file", folder / (label + ".der"))
    return {"folder": folder, "java": java, "tools": tools, "extension": extension,
            "platform": args.sdk.resolve() / "platforms/android-37.0/android.jar",
            "certificate": folder / "test.der"}


def signed_apks(signing, candidates, commands):
    folder, tools, extension = signing["folder"], signing["tools"], signing["extension"]
    manifest = folder / "AndroidManifest.xml"
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="'
                        + SIGNED_PACKAGE + '"><application android:hasCode="false" '
                        'android:extractNativeLibs="false"/></manifest>\n', encoding="utf-8")
    commands.run(tools / ("aapt2" + extension), "link", "-o", folder / "manifest.apk", "--manifest", manifest,
                 "-I", signing["platform"], "--min-sdk-version", "29", "--target-sdk-version", "29")
    with zipfile.ZipFile(folder / "manifest.apk") as archive:
        binary_manifest = archive.read("AndroidManifest.xml")
    apksigner = tools / "lib/apksigner.jar"
    apks = []
    for label, library, key in (("O0", candidates["O0"], "test"), ("O2", candidates["O2"], "test"),
                                ("wrong-cert", candidates["O2"], "wrong"),
                                ("tag", candidates["tag"], "test"), ("guard", candidates["guard"], "test")):
        unsigned, aligned, apk = (folder / (label + suffix) for suffix in ("-unsigned.apk", "-aligned.apk", ".apk"))
        with zipfile.ZipFile(unsigned, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("AndroidManifest.xml", binary_manifest)
            archive.writestr(SIGNED_LIBRARY, library.read_bytes())
        commands.run(tools / ("zipalign" + extension), "-P", "16", "-f", "4", unsigned, aligned)
        commands.run(signing["java"], "-jar", apksigner, "sign", "--ks", folder / (key + ".jks"),
                     "--ks-key-alias", "test", "--ks-pass", "pass:android", "--min-sdk-version", "29",
                     "--out", apk, aligned)
        result = commands.run(signing["java"], "-jar", apksigner, "verify", "--verbose", "--print-certs", apk)
        certificate = folder / (key + ".der")
        certificate_hash = hashlib.sha256(certificate.read_bytes()).hexdigest()
        digests = set(value.lower() for value in re.findall(
            r"^(?:Signer #\d+|V[0-9.]+ Signer(?: #\d+)?):? certificate SHA-256 digest: ([0-9a-fA-F]{64})\r?$",
            result.stdout, re.M))
        counts = re.findall(r"^Number of signers: (\d+)\s*$", result.stdout, re.M)
        assert counts == ["1"] and digests == {certificate_hash}, (label, counts, digests, certificate_hash)
        with zipfile.ZipFile(apk) as archive:
            assert archive.read(SIGNED_LIBRARY) == library.read_bytes(), label
        apks.append({"label": label, "apk": digest(apk), "library": digest(library),
                     "libraryEntry": SIGNED_LIBRARY, "signerCertificate": digest(certificate),
                     "signatureVerified": True, "verificationCommand": commands.index})
        print(f"[signed-apk] {label}: real signature verified, exact native entry, signer={certificate_hash}", flush=True)
    return {"package": SIGNED_PACKAGE, "expectedCertificate": digest(signing["certificate"]),
            "apkVerifyMacro": False, "apks": apks}


def build(args):
    out = args.work_dir
    out.mkdir(parents=True)
    commands = Commands(out, "build")
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    extension = ".exe" if os.name == "nt" else ""
    prebuilt = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else prebuilt / f"bin/clang{extension}"
    resource = Path(commands.run(clang, "--print-resource-dir").stdout.strip())
    assert resource.is_absolute() and (resource / "include").is_dir()
    common = ["--target=aarch64-linux-android29", f"--sysroot={prebuilt / 'sysroot'}", "-resource-dir", resource,
              f"-B{prebuilt / 'bin'}", "--driver-mode=g++", "-std=c++17", "-fPIC", "-fno-lto", "-femulated-tls",
              "-fno-exceptions", "-frtti", "-fno-discard-value-names", "-I", ROOT / "include", "-I", ROOT / "runtime"]
    inputs = [__file__, SOURCE / "scoped_fixture.cpp", SOURCE / "scoped_fixture.h", SOURCE / "scoped_observer.cpp",
              SOURCE / "scoped_loader.cpp", ROOT / "include/ndkp.h", ROOT / "runtime/ndkp_cse_runtime.cpp",
              *[ROOT / "runtime" / name for name in ("cse_region.h", "cse_crypto.h", "sha256.h", "apkcert.h", "apkcert_io.h", "raw_syscall.h")],
              ROOT / "scripts/seal_cse.py", clang, prebuilt / f"bin/llvm-strip{extension}",
              prebuilt / f"bin/ld.lld{extension}", args.ndk.resolve() / "source.properties"]
    if args.signed:
        tools = args.sdk.resolve() / "build-tools/37.0.0"
        inputs += [args.java.resolve(), args.java.resolve().with_name("keytool" + extension),
                   tools / ("aapt2" + extension), tools / ("zipalign" + extension), tools / "lib/apksigner.jar",
                   args.sdk.resolve() / "platforms/android-37.0/android.jar"]
    input_records = [digest(path) for path in inputs]
    (out / "inputs.json").write_text(json.dumps(input_records, indent=2) + "\n", encoding="utf-8")
    commands.run(clang, *common, "-O2", "-Wall", "-Wextra", "-Werror", "-c", SOURCE / "scoped_observer.cpp", "-o", out / "observer.o")
    commands.run(clang, *common, "-O2", "-static-libstdc++", SOURCE / "scoped_loader.cpp", "-ldl", "-o", out / "loader")
    raw, final = out / "runtime.raw.ll", out / "runtime.ll"
    vmp = ["-DNDKP_CSE_VMP", "-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict", "-mllvm", "-irobf-vmp-memops",
           "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry"]
    commands.run(clang, *common, "-O1", "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops", *vmp,
                 "-S", "-emit-llvm", ROOT / "runtime/ndkp_cse_runtime.cpp", "-o", raw)
    commands.run(clang, *common, "-Oz", "-mllvm", "-irobf-vmp-post", "-S", "-emit-llvm", raw, "-o", final)
    original, hardened = raw.read_text(encoding="utf-8"), final.read_text(encoding="utf-8")
    names = re.findall(r'^define [^\n]*@(_ZN8ndkp_cse\w+)\([^\n]*!ndkp.vmp.protected', hardened, re.M)
    code = r'^@gv_code_seg_\w+ = .*? c"([^"\n]+)"'
    assert len(names) == 2 and "ndkp_selfcheck_one" in hardened and "ndkp.vmp.post" in hardened, names
    assert re.findall(code, original, re.M) == re.findall(code, hardened, re.M)
    assert "ndkp_certbind_mix" not in hardened
    commands.run(clang, *common, "-Oz", "-Xclang", "-disable-llvm-passes", "-c", final, "-o", out / "runtime.o")
    print("[runtime] exactly two crypto entries, unchanged VM bytecode, selfcheck-entry and real post", flush=True)
    cse_flags = ["-mllvm", "-irobf-cse", "-mllvm", "-irobf-cse-hardened"]
    scoped_flags = [*cse_flags, "-mllvm", "-irobf-cse-scoped"]
    wrap = "-Wl," + ",".join("--wrap=" + name for name in ("mmap", "mprotect", "munmap", "ndkp_cse_acquire_region_v1", "ndkp_cse_release_region_v1"))
    libraries, signed_candidates = [], {}
    signing = signing_tools(args, out, commands, extension) if args.signed else None
    specifications = [("O0", "O0", scoped_flags, False), ("O2", "O2", scoped_flags, False),
                      ("plain", "O2", [], False), ("annotation-only", "O2", cse_flags, False),
                      ("flag-only", "O2", [*scoped_flags, "-DNDKP_SCOPED_NO_ANNOTATION"], False)]
    if signing:
        bound_flags = [*scoped_flags, "-mllvm", "-irobf-cse-bind", "-mllvm", "-irobf-cse-bind-package=" + SIGNED_PACKAGE,
                       "-mllvm", "-irobf-cert-bind", "-mllvm", "-irobf-cert-file=" + str(signing["certificate"])]
        specifications += [("signed-O0", "O0", bound_flags, True), ("signed-O2", "O2", bound_flags, True)]
    for label, optimization, flags, bound in specifications:
        ir, obj = out / (label + ".ll"), out / (label + ".o")
        commands.run(clang, *common, "-" + optimization, *flags, "-S", "-emit-llvm", SOURCE / "scoped_fixture.cpp", "-o", ir)
        text = ir.read_text(encoding="utf-8")
        first_region = inspect_scoped(text, optimization) if label in ("O0", "O2") or bound else None
        if first_region is None:
            assert "cse.scoped.lease" not in text and "@ndkp_cse_module_acquire" not in text
        commands.run(clang, *common, "-" + optimization, "-Xclang", "-disable-llvm-passes", "-c", ir, "-o", obj)
        linked = out / (label + ".linked.so")
        commands.run(clang, *common, "-shared", "-static-libstdc++", "-Wl,--no-rosegment,--no-undefined,--pack-dyn-relocs=none",
                     "-Wl,-z,max-page-size=16384", wrap, obj, out / "observer.o", out / "runtime.o", "-ldl", "-o", linked)
        sealed = out / (label + ".so")
        verification_inputs = ["--package", SIGNED_PACKAGE, "--cert-file", signing["certificate"]] if bound else []
        if flags:
            commands.run(sys.executable, "-B", ROOT / "scripts/seal_cse.py", "--input", linked, "--output", sealed, *verification_inputs)
            commands.run(sys.executable, "-B", ROOT / "scripts/seal_cse.py", "--input", sealed, "--verify", *verification_inputs)
        else:
            sealed.write_bytes(linked.read_bytes())
        if not bound:
            libraries.append({"label": label, "path": str(sealed), "mode": "0" if first_region is not None else "100"})
        if first_region is not None:
            data = sealed.read_bytes()
            stripped = out / (label + "-stripped.so")
            stripped.write_bytes(data)
            commands.run(prebuilt / f"bin/llvm-strip{extension}", "--strip-all", stripped)
            commands.run(sys.executable, "-B", ROOT / "scripts/seal_cse.py", "--input", stripped, "--verify", *verification_inputs)
            assert cse.Elf(data).code_hash() == cse.Elf(stripped.read_bytes()).code_hash()
            if bound:
                signed_candidates[optimization] = stripped
                data = stripped.read_bytes()
                assert cse.u32(data, cse.Elf(data).payloads()[0][0] + 16) == 3
            else:
                libraries.append({"label": label + "-stripped", "path": str(stripped), "mode": "0"})
            if not bound or optimization == "O2":
                module, tags = module_and_tags(data, SIGNED_PACKAGE if bound else None,
                                               signing["certificate"].read_bytes() if bound else None)
                for attack, offset in (("tag", tags[first_region]), ("guard", module + 24)):
                    modified = bytearray(data)
                    modified[offset] ^= 1
                    path = out / (label + "-" + attack + ".so")
                    path.write_bytes(modified)
                    if bound:
                        signed_candidates[attack] = path
    signed = signed_apks(signing, signed_candidates, commands) if signing else None
    negative = out / "negative"
    negative.mkdir()
    for name, text in negative_cases().items():
        path = negative / (name + ".ll")
        path.write_text(text, encoding="utf-8", newline="\n")
        extra = ["-mllvm", "-irobf-vmp"] if name == "vmp-annotation" else []
        result = commands.run(clang, *common, "-O2", *scoped_flags, *extra, "-c", path, "-o", negative / (name + ".o"), check=False)
        assert result.returncode and "NDKP_CSE_SCOPED" in result.stderr, (name, result.returncode, result.stderr)
        print(f"[reject] {name}", flush=True)
    high = negative / "high-alignment.cpp"
    high.write_text('#include "ndkp.h"\nalignas(65536) static const char text[] = "high alignment";\n'
                    'extern "C" NDKP_CSE_SCOPED int high(unsigned index) noexcept {\n'
                    '  return reinterpret_cast<const volatile char*>(text)[index % sizeof text];\n}\n', encoding="utf-8")
    result = commands.run(clang, *common, "-O2", *scoped_flags, "-c", high, "-o", negative / "high-alignment.o", check=False)
    assert result.returncode and "literal alignment exceeds" in result.stderr, result.stderr
    branches = out / "return-blocks.input.ll"
    branches.write_text(ir_fixture('br i1 %which, label %left, label %right\nleft:\n'
                                   '%a = call i32 @sink(ptr @lit)\nret i32 %a\nright:\n'
                                   '%b = call i32 @sink(ptr @other)\nret i32 %b',
                                   params="i1 %which", attributes="nounwind noinline optnone"), encoding="utf-8")
    returns = out / "return-blocks.ll"
    commands.run(clang, *common, "-O0", *scoped_flags, "-S", "-emit-llvm", branches, "-o", returns)
    body = function(returns.read_text(encoding="utf-8"), "scope_case")
    assert len(re.findall(r"^\s*ret ", body, re.M)) == 2 and body.count("call void @ndkp_cse_release_region_v1") == 4
    for block in re.split(r"^\w+:.*$", body, flags=re.M):
        if re.search(r"^\s*ret ", block, re.M):
            release = re.findall(r"@ndkp_cse_release_region_v1\(ptr (%cse\.scoped\.lease\.\d+)\)", block)
            assert len(release) == 2 and int(release[0].rsplit(".", 1)[1]) > int(release[1].rsplit(".", 1)[1])
    print("[ir] two original return blocks each release both leases in reverse order", flush=True)
    assert [digest(path) for path in inputs] == input_records, "build input changed during compilation"
    artifacts = [digest(path) for path in sorted(out.rglob("*")) if path.is_file() and "commands" not in str(path.parent)
                 and path.name != "build.json"]
    manifest = {"kind": "actual-compiler-build-artifacts", "ndk": str(args.ndk.resolve()), "compiler": digest(clang),
                "loader": str(out / "loader"), "libraries": libraries, "nativeBinding": "none", "signed": signed,
                "artifacts": artifacts}
    (out / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[build] retained {len(artifacts)} artifacts; no device execution claimed", flush=True)
    return manifest


def check_lifecycle(stdout, label, baseline=False):
    if baseline:
        assert "lifecycle mapped=0 published=0 retired=0" in stdout, label
        assert "real-mmap " not in stdout and "publish ordinal=" not in stdout, label
        return
    assert "lifecycle mapped=13 published=13 retired=13" in stdout, label
    for text in ("ro-write-fault signal=", "padding-nonzero", "whole-mapping-zero", "mincore=-1",
                 "unused-caller mapping-events=2", "thread-leases distinct=1 simultaneously-live=2", "static-stable=1"):
        assert text in stdout, (label, text)
    assert stdout.count("real-mmap ") == stdout.count("publish ordinal=") == stdout.count("retire ordinal=") == 13, label


def check_auth_failure(stdout, label, mappings):
    assert stdout.count("acquire-attempt") == 1 and stdout.count("real-mmap ") == mappings, label
    for text in ("publish ordinal=", "business-read", "attack-continued", "real-mprotect", "scoped-result=", "observer-reject"):
        assert text not in stdout, (label, text)


def device(args, manifest):
    out = args.work_dir
    for record in manifest["artifacts"]:
        assert digest(record["path"]) == record, record["path"]
    commands = Commands(out, "device")
    adb = str(args.adb.resolve()) if args.adb else str(Path(shutil.which("adb") or "adb").resolve())
    remote = "/data/local/tmp/ndkp-scoped-" + uuid.uuid4().hex
    base = [adb, "-P", str(args.server_port), "-s", args.serial]
    facts, cases = {}, []
    for name, argv in (("api", ("getprop", "ro.build.version.sdk")), ("abi", ("getprop", "ro.product.cpu.abi")),
                       ("page", ("getconf", "PAGESIZE")), ("model", ("getprop", "ro.product.model")),
                       ("fingerprint", ("getprop", "ro.build.fingerprint"))):
        facts[name] = commands.run(*base, "shell", *argv).stdout.strip()
    page = int(facts["page"])
    assert int(facts["api"]) >= 29 and facts["abi"] == "arm64-v8a" and page > 0 and not page & (page - 1), facts
    commands.run(*base, "shell", "mkdir", remote)
    try:
        loader = Path(manifest["loader"])
        commands.run(*base, "push", loader, remote + "/loader")
        assert commands.run(*base, "shell", "sha256sum", remote + "/loader").stdout.split()[0] == digest(loader)["sha256"]
        commands.run(*base, "shell", "chmod", "700", remote + "/loader")

        def execute(path, mode, expected=0, marker=None, process_name=None, label=None):
            destination = remote + ("/fixture.apk" if process_name else "/fixture.so")
            commands.run(*base, "push", path, destination)
            assert commands.run(*base, "shell", "sha256sum", destination).stdout.split()[0] == digest(path)["sha256"]
            if process_name:
                script = shlex.join(["exec", "-a", process_name, remote + "/loader", destination + "!/" + SIGNED_LIBRARY, mode])
                shell = shlex.join(["timeout", "30", "/system/bin/sh", "-c", script])
                result = commands.run(*base, "shell", shell, check=False, artifact=path)
            else:
                result = commands.run(*base, "shell", "timeout", "30", remote + "/loader", destination, mode,
                                      check=False, artifact=path)
            cases.append({"label": label or path.stem + "/" + mode, "artifact": digest(path), "mode": mode,
                          "processName": process_name, "expectedReturnCode": expected, "returnCode": result.returncode,
                          "commandReceipt": digest(commands.folder / f"{commands.index:03}" / "receipt.json")})
            assert result.returncode == expected, (path, mode, expected, result.returncode, result.stdout, result.stderr)
            if marker:
                assert marker in result.stdout, (marker, result.stdout)
            assert "scoped-result=0" not in result.stdout if expected else "scoped-result=0" in result.stdout
            return result

        for library in manifest["libraries"]:
            result = execute(Path(library["path"]), library["mode"], label=library["label"])
            check_lifecycle(result.stdout, library["label"], library["mode"] == "100")
            print(f"[device] {library['label']}: lifecycle and results verified", flush=True)
        for optimization in ("O0", "O2"):
            for attack in ("guard", "tag"):
                result = execute(out / (optimization + "-" + attack + ".so"), "attack", 127)
                check_auth_failure(result.stdout, optimization + "/" + attack, 0 if attack == "guard" else 1)
                print(f"[device] {optimization}/{attack}: no publish or business continuation", flush=True)
        for mode, reason in ((1, "whole-mapping-wipe-missed-a-byte"), (2, "mapping-still-mapped-after-release"),
                             (3, "read-only-write-did-not-fault"), (4, "lease-not-retired")):
            execute(out / "O2.so", str(mode), 90, "observer-reject " + reason)
            print(f"[observer-control] injected defect {mode} rejected: {reason}", flush=True)
        if manifest.get("signed"):
            signed = manifest["signed"]
            assert signed["apkVerifyMacro"] is False and signed["package"] == SIGNED_PACKAGE
            apks = {record["label"]: record for record in signed["apks"]}
            for label, process_name in (("O0", SIGNED_PACKAGE), ("O2", SIGNED_PACKAGE), ("O2", SIGNED_PACKAGE + ":worker")):
                result = execute(Path(apks[label]["apk"]["path"]), "0", process_name=process_name,
                                 label="signed/" + label + "/" + process_name)
                check_lifecycle(result.stdout, label)
                print(f"[signed-device] {label}/{process_name}: full lifecycle and production inputs verified", flush=True)
            for label, apk, process_name in (("wrong-cert", "wrong-cert", SIGNED_PACKAGE),
                                              ("wrong-package", "O2", "test.ndkp.cse.wrong"),
                                              ("tag", "tag", SIGNED_PACKAGE), ("guard", "guard", SIGNED_PACKAGE)):
                result = execute(Path(apks[apk]["apk"]["path"]), "attack", 127, process_name=process_name,
                                 label="signed/" + label)
                check_auth_failure(result.stdout, label, 0 if label == "guard" else 1)
                print(f"[signed-device] {label}: legitimate signature, no publish or business continuation", flush=True)
    finally:
        commands.run(*base, "shell", "rm", "-rf", remote, check=False)
    for record in manifest["artifacts"]:
        assert digest(record["path"]) == record, record["path"]
    report = {"kind": "actual-device-execution", "status": "passed", "serial": args.serial, "device": facts,
              "build": digest(out / "build.json"), "nativeBinding": manifest["nativeBinding"],
              "signed": manifest.get("signed"), "cases": cases}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[device] passed {len(cases)} cases; api={facts['api']} abi={facts['abi']} page={page}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--signed", action="store_true", help="add signed APKs with real package/certificate binding")
    parser.add_argument("--sdk", type=Path, help="Android SDK with build-tools 37.0.0 and platform android-37")
    parser.add_argument("--java", type=Path, help="java executable with adjacent keytool")
    parser.add_argument("--work-dir", type=Path, required=True, help="new retained artifact directory; reuse only with --device-only")
    parser.add_argument("--serial")
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--server-port", type=int, default=5037)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--compile-only", action="store_true")
    modes.add_argument("--device-only", action="store_true")
    args = parser.parse_args()
    args.work_dir = args.work_dir.resolve()
    if not args.device_only and not args.ndk:
        parser.error("--ndk is required for compilation")
    if not args.device_only and args.signed and (not args.sdk or not args.java):
        parser.error("--signed requires --sdk and --java")
    if not args.compile_only and not args.serial:
        parser.error("--serial is required for device execution")
    if args.serial and (args.serial.startswith("-") or re.search(r"\s", args.serial)):
        parser.error("invalid --serial")
    if not 1 <= args.server_port <= 65535:
        parser.error("invalid --server-port")
    manifest = json.loads((args.work_dir / "build.json").read_text(encoding="utf-8")) if args.device_only else build(args)
    if not args.compile_only:
        device(args, manifest)


if __name__ == "__main__":
    main()
