"""Run baseline/native VMP DEX under ART with CheckJNI on one explicit device."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shlex
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile


def run(command, timeout=300):
    result = subprocess.run([str(value) for value in command], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout[-8000:]}{result.stderr[-8000:]}")
    return result.stdout.strip()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + report["runId"] + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def streams(stdout, stderr):
    return {"stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "stdoutBase64": base64.b64encode(stdout).decode("ascii"),
            "stderrBase64": base64.b64encode(stderr).decode("ascii")}


def expected_codes(label, segmented, verified):
    # Nonsegmented self-check / VM termination tries SIGKILL before exit_group(127).
    if not segmented and (label in {"tampered-vm", "tampered-cse-vm", "tampered-code"} or
                          (label == "wrong-signer" and not verified)):
        return [127, 137]
    return [127]


def negative_command(device, target, token):
    child = ["/system/bin/app_process", "-Xcheck:jni",
             "-Djava.library.path=" + target + "!/lib/arm64-v8a", "/system/bin", "sample.Run"]
    launch_failed = "printf '%s\\n' " + shlex.quote(token + ":LAUNCH_FAILED") + " >&2"
    # The EXIT trap must be installed in the same subshell as exec. Successful exec replaces it.
    shell = ("if [ ! -x /system/bin/app_process ]; then " + launch_failed + "; exit 0; fi\n" +
             "printf '%s\\n' " + shlex.quote(token + ":BEGIN") + " >&2\n" +
             "( trap " + shlex.quote(launch_failed) + " 0\n" +
             "  CLASSPATH=" + shlex.quote(target) + " exec " + shlex.join(child) + "\n)\n" +
             "child_status=$?\nprintf '\\n%s:%s\\n' " + shlex.quote(token + ":EXIT") +
             " \"$child_status\" >&2\nexit 0")
    return [str(value) for value in [*device, "shell", shell]], child


def negative_status(execution, token, codes):
    if execution["returnCode"] != 0:
        return "transport-error", None
    lines = execution["stderr"].splitlines()
    markers = [line for line in lines if line.startswith(token + ":")]
    endings = [re.fullmatch(re.escape(token) + r":EXIT:(\d+)", line) for line in markers]
    exits = [int(match[1]) for match in endings if match]
    actual = exits[0] if len(exits) == 1 else None
    if token + ":LAUNCH_FAILED" in markers or re.search(
            r"(?im)(?:not found|no such file or directory|permission denied|exec format error|"
            r"cannot link executable|cannot execute|inaccessible or not found)", execution["stderr"]):
        return "launch-error", actual
    if actual is None or not 0 <= actual <= 255 or markers != [token + ":BEGIN", token + ":EXIT:" + str(actual)]:
        return "protocol-error", actual
    if execution["stdoutBase64"]:
        return "business-stdout", actual
    return ("expected-exit-signature" if actual in codes else "unexpected-exit"), actual


def negative_case(device, file, target, codes, report, report_path):
    token = "DEX2C_" + uuid.uuid4().hex
    command, child = negative_command(device, target, token)
    row = {"mode": file.stem, "rejected": False, "status": "preparing", "expectedCodes": codes,
           "exitCode": None, "startedAt": utc_now(), "protocolToken": token,
           "childArgv": child, "environment": {"CLASSPATH": target}, "remoteApk": target,
           "artifact": {"path": str(file.resolve())}, "command": command,
           "evidenceScope": "expected exit signature only; does not identify a unique native failure cause"}
    report["results"].append(row)
    save_report(report_path, report)
    try:
        raw = file.read_bytes()
        row["artifact"].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        report["pushed"].append(target)  # A failed push may still leave this exact file behind.
        for stage, argv, timeout in (("push", [str(value) for value in [*device, "push", file, target]], 300),
                                     ("execution", command, 90)):
            evidence = {"command": argv, "startedAt": utc_now(), "returnCode": None,
                        "status": "running", **streams(b"", b"")}
            row[stage] = evidence
            row["status"] = stage
            save_report(report_path, report)
            start = time.monotonic()
            try:
                process = subprocess.run(argv, capture_output=True, timeout=timeout)
                evidence.update(returnCode=process.returncode, status="completed",
                                **streams(process.stdout, process.stderr))
            except subprocess.TimeoutExpired as error:
                evidence.update(status="timeout", timeoutSeconds=timeout,
                                **streams(error.stdout or b"", error.stderr or b""))
                row["status"] = "timeout"
                raise RuntimeError("negative " + file.stem + " " + stage + " timed out") from error
            except OSError as error:
                evidence.update(status="launch-error", error=str(error))
                row["status"] = "launch-error"
                raise
            finally:
                evidence.update(finishedAt=utc_now(), seconds=round(time.monotonic() - start, 6))
                save_report(report_path, report)
            if stage == "push" and process.returncode:
                row["status"] = "push-error"
                raise RuntimeError("negative APK push failed: " + file.stem)
        row["status"], row["exitCode"] = negative_status(row["execution"], token, codes)
        row["rejected"] = row["status"] == "expected-exit-signature"
        if not row["rejected"]:
            raise RuntimeError("negative " + file.stem + " failed: " + row["status"])
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
        if row["status"] == "preparing":
            row["status"] = "artifact-error"
        raise
    finally:
        row["finishedAt"] = utc_now()
        save_report(report_path, report)


def cleanup_remote(report):
    results = []
    if "remote" not in report:
        return results
    device, remote = report["deviceCommand"], report["remote"]
    commands = ([[*device, "shell", "rm", "-f", *report["pushed"]]] if report["pushed"] else [])
    commands.append([*device, "shell", "rmdir", remote])
    for command in commands:
        evidence = {"command": command, "startedAt": utc_now(), "returnCode": None, **streams(b"", b"")}
        try:
            process = subprocess.run(command, capture_output=True, timeout=60)
            evidence.update(returnCode=process.returncode, status="completed" if process.returncode == 0 else "failed",
                            **streams(process.stdout, process.stderr))
        except subprocess.TimeoutExpired as error:
            evidence.update(status="timeout", **streams(error.stdout or b"", error.stderr or b""))
        except OSError as error:
            evidence.update(status="launch-error", error=str(error))
        evidence["finishedAt"] = utc_now()
        results.append(evidence)
    return results


def exercise(args, report, report_path):
    if args.ndk:
        if args.native_reference:
            raise ValueError("choose --ndk or --native-reference")
        host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
        suffix = ".exe" if os.name == "nt" else ""
        base = args.ndk / "toolchains/llvm/prebuilt" / host
        compiler = args.clang or base / ("bin/clang" + suffix)
        generated = args.fixtures / "generated"
        args.native_reference = args.fixtures / "libdex2c_semantics_reference.so"
        run([compiler, "--driver-mode=g++", "--target=aarch64-linux-android26",
             "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(base / "lib/clang/21"),
             "--ld-path=" + str(base / ("bin/ld.lld" + suffix)), "-O1", "-fPIC", "-fno-exceptions",
             "-fno-fast-math", "-ffp-contract=off", "-shared", "-static-libstdc++",
             *(generated / name for name in ("protected.cpp", "native.cpp", "registration.cpp", "dex2c_runtime.cpp") if (generated / name).exists()),
             "-lm", "-o", args.native_reference])
    adb = args.sdk / "platform-tools/adb.exe"
    if not adb.exists():
        adb = adb.with_suffix("")
    device = [adb, "-P", str(args.server_port), "-s", args.serial]
    remote = "/data/local/tmp/dex2c-" + uuid.uuid4().hex
    report.update(deviceCommand=[str(value) for value in device], remote=remote, pushed=[])
    save_report(report_path, report)
    manifest = json.loads((args.fixtures / "inputs.json").read_text())
    compiler = args.sdk / "build-tools/37.0.0/lib/d8.jar"
    platform = args.sdk / "platforms/android-37.0/android.jar"
    for kind in ("baseline", "protected"):
        output = args.fixtures / (kind + ".zip")
        output.unlink(missing_ok=True)
        run([args.java, "-cp", compiler, "com.android.tools.r8.D8", "--min-api", "26", "--lib", platform,
             "--output", output, *manifest[kind], *manifest["common"]])
    # Load the bound library directly from a signed APK, as in ART/LSPosed.
    build_tools=args.sdk / "build-tools/37.0.0"
    manifest_xml = args.fixtures / 'AndroidManifest.xml'
    manifest_xml.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.ndkp.dex2c"><application/></manifest>')
    manifest_apk = args.fixtures / 'manifest.apk'
    run([build_tools / 'aapt2.exe', 'link', '-o', manifest_apk, '--manifest', manifest_xml,
         '-I', platform, '--min-sdk-version', '26', '--target-sdk-version', '28'])
    segment_path = args.fixtures / "native/assets/dex2c_semantics.qseg"
    segments = segment_path.read_bytes() if segment_path.exists() else None
    def signed_apk(label, library, store, payload=segments, method=zipfile.ZIP_STORED):
        unsigned=args.fixtures / (label+"-unsigned.apk")
        aligned=args.fixtures / (label+"-aligned.apk")
        result=args.fixtures / (label+".apk")
        with zipfile.ZipFile(args.fixtures / "protected.zip") as dex, zipfile.ZipFile(unsigned,"w") as archive:
            with zipfile.ZipFile(manifest_apk) as binary_manifest:
                archive.writestr('AndroidManifest.xml', binary_manifest.read('AndroidManifest.xml'))
            for name in dex.namelist():
                archive.writestr(name,dex.read(name))
            archive.writestr("lib/arm64-v8a/libdex2c_semantics.so",library,compress_type=zipfile.ZIP_STORED)
            if payload is not None:
                archive.writestr("assets/dex2c_semantics.qseg",payload,compress_type=method)
        run([build_tools / "zipalign.exe","-P","16","-f","4",unsigned,aligned])
        run([args.java,"-jar",build_tools / "lib/apksigner.jar","sign","--ks",store,"--ks-key-alias","test",
             "--ks-pass","pass:android","--min-sdk-version","26","--out",result,aligned])
        return result
    library=(args.fixtures / "native/jniLibs/arm64-v8a/libdex2c_semantics.so").read_bytes()
    protected_apk=signed_apk("protected",library,args.fixtures / "test.jks")
    run([*device, "shell", "mkdir", remote])
    pushed = report["pushed"]
    for file in (args.fixtures / "baseline.zip", protected_apk, args.fixtures / "protected.zip",
                 args.fixtures / "native/jniLibs/arm64-v8a/libdex2c_semantics.so"):
        target = remote + "/" + file.name
        pushed.append(target)
        save_report(report_path, report)
        run([*device, "push", file, target])
    outcomes = report["results"]
    for main_class in manifest.get("mains", ("sample.Run", "kfixture.FixtureKt")):
        observed = {}
        for kind in (("baseline", "native", "protected") if args.native_reference else ("baseline", "protected")):
            if kind != "baseline":
                library_file = args.native_reference if kind == "native" else args.fixtures / "native/jniLibs/arm64-v8a/libdex2c_semantics.so"
                run([*device, "push", library_file, remote + "/libdex2c_semantics.so"])
            start = time.monotonic()
            dex = "baseline.zip" if kind == "baseline" else ("protected.apk" if kind == "protected" else "protected.zip")
            library_path=remote+"/protected.apk!/lib/arm64-v8a" if kind=="protected" else remote
            output = run([*device, "shell", "env", f"CLASSPATH={remote}/{dex}", "app_process",
                          "-Xcheck:jni", "-Djava.library.path=" + library_path, "-Ddex2c.trace=" + str(args.trace).lower(), "/system/bin", main_class], timeout=600)
            observed[kind] = output
            outcomes.append({"main": main_class, "mode": kind, "seconds": round(time.monotonic()-start, 3), "output": output})
            save_report(report_path, report)
        if any(value != observed["baseline"] for value in observed.values()):
            raise AssertionError(f"ART semantic mismatch for {main_class}: {observed}")
        if "WARNING" in observed["protected"] or "JNI DETECTED ERROR" in observed["protected"]:
            raise AssertionError(observed["protected"])
        print("[ok]", main_class, observed["protected"], flush=True)
    wrong_store=args.fixtures / "wrong.jks"
    if not wrong_store.exists():
        run([args.java.parent / "keytool.exe","-genkeypair","-keystore",wrong_store,"-storepass","android","-keypass","android",
             "-alias","test","-keyalg","RSA","-dname","CN=wrong signer","-validity","3650","-noprompt"])
    wrong=signed_apk("wrong-signer",library,wrong_store)
    negatives = [wrong]
    if segments is not None:
        for label, offset in (("tampered-index", 16), ("tampered-segment", len(segments)-1)):
            changed=bytearray(segments);changed[offset]^=1
            negatives.append(signed_apk(label,library,args.fixtures / "test.jks",changed))
        negatives.append(signed_apk("missing-segments",library,args.fixtures / "test.jks",None))
        negatives.append(signed_apk("compressed-container",library,args.fixtures / "test.jks",segments,zipfile.ZIP_DEFLATED))
        # Re-pin the outer digest to exercise AEAD and authenticated parser failures.
        sys.path.insert(0, str(args.fixtures / "native/a_llvm"))
        import seal_qseg as qseg
        import hashlib
        import struct
        _, image_offset = qseg.locate_image(library)
        header = library[image_offset:image_offset+512]
        root = qseg.derive(header, header[152:184], qseg.expected_inputs(2,
            certificate=(args.fixtures / "native/signing-cert.der").read_bytes()))
        directory_size = qseg.u32(segments, 12)
        index_key = qseg.index_key(root, header)
        index_aad = segments[:16] + header[24:40]
        original = qseg.decrypt(index_key, bytes(12), index_aad, segments[16:16+directory_size],
                                segments[16+directory_size:32+directory_size])
        def repinned(label, blob):
            changed_library = bytearray(library)
            changed_library[image_offset+384:image_offset+416] = hashlib.sha256(blob).digest()
            negatives.append(signed_apk(label, changed_library, args.fixtures / "test.jks", blob))
        for label, offset in (("index-aead", 16), ("segment-aead", len(segments)-1)):
            changed = bytearray(segments); changed[offset] ^= 1
            repinned(label, changed)
        for field, value in ((16, 3), (20, 1), (24, 0xffffffff), (32, 0xffffffff), (36, 1), (40, 2)):
            changed = bytearray(original); struct.pack_into("<I", changed, field, value)
            ciphertext, tag = qseg.encrypt(index_key, bytes(12), index_aad, changed)
            repinned("authenticated-index-"+str(field), segments[:16]+ciphertext+tag+segments[32+directory_size:])
        for ordinal in range(directory_size // qseg.ENTRY.size):
            entry = original[ordinal*64:(ordinal+1)*64]
            identity, kind, chunk, offset, stored, plain, total, codec, order, tag = qseg.ENTRY.unpack(entry)
            if codec == 1:
                key = qseg.segment_key(root, header, identity, kind, chunk)
                ciphertext, tag = qseg.encrypt(key, bytes(12), header[24:40]+entry[:48], bytes([255])*stored)
                directory = bytearray(original); directory[ordinal*64+48:ordinal*64+64] = tag
                encrypted_index, index_tag = qseg.encrypt(index_key, bytes(12), index_aad, directory)
                changed = bytearray(segments); changed[16:32+directory_size] = encrypted_index+index_tag
                changed[offset:offset+stored] = ciphertext
                repinned("authenticated-invalid-deflate", changed)
                break
        else:
            raise AssertionError("Fixture lacks a compressed block for negative coverage")
    elif json.loads((args.fixtures / "native/protection.json").read_text())["vmpMethods"]:
        ir=(args.fixtures / "native/protected.ll").read_text()
        encoded=re.search(r'^@gv_code_seg_d2c_\w+ = .*? c"([^"\n]+)"',ir,re.M).group(1)
        bytecode=bytes((92 if escape=='\\' else int(escape,16)) if escape else ord(char)
                       for escape,char in re.findall(r'\\([A-Fa-f0-9]{2}|\\)|([^\\])',encoded))
        offset=library.find(bytecode)
        if offset < 0 or library.find(bytecode, offset + 1) >= 0:
            raise ValueError("VM bytecode must occur exactly once in the fixture library")
        changed=bytearray(library);changed[offset]^=1
        negatives.append(signed_apk("tampered-vm",changed,args.fixtures / "test.jks"))
    receipt=json.loads((args.fixtures / "native/protection.json").read_text())
    if receipt.get('protectedStrings', 0) and segments is None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
        import seal_cse as cse
        elf=cse.Elf(library)
        for label, delta in (('tampered-cse-tag', 16), ('tampered-cse-ciphertext', 32)):
            changed=bytearray(library)
            for pos, _ in elf.payloads():
                changed[pos+cse.HEADER+delta] ^= 1
            negatives.append(signed_apk(label,changed,args.fixtures / 'test.jks'))
        changed=bytearray(library)
        _, size, offset=elf.executable[-1]
        changed[offset+size-1] ^= 1
        negatives.append(signed_apk('tampered-code',changed,args.fixtures / 'test.jks'))
        ir=(args.fixtures / 'native/cse-runtime.ll').read_text()
        encoded=re.search(r'^@gv_code_seg_\S+ = .*? c"([^"\n]+)"',ir,re.M).group(1)
        bytecode=bytes((92 if escape=='\\' else int(escape,16)) if escape else ord(char)
                       for escape,char in re.findall(r'\\([A-Fa-f0-9]{2}|\\)|([^\\])',encoded))
        offset=library.find(bytecode)
        if offset < 0 or library.find(bytecode, offset + 1) >= 0:
            raise ValueError("CSE VM bytecode must occur exactly once in the fixture library")
        changed=bytearray(library);changed[offset]^=1
        negatives.append(signed_apk('tampered-cse-vm',changed,args.fixtures / 'test.jks'))
        # A separately sealed build has fresh build_nonce/key material, even with identical code/certificate.
        alternate=cse.process((args.fixtures / 'native/linked.so').read_bytes())
        changed=bytearray(library)
        for pos, total in elf.payloads():
            changed[pos+cse.HEADER:pos+total]=alternate[pos+cse.HEADER:pos+total]
        negatives.append(signed_apk('cross-build-cse-records',changed,args.fixtures / 'test.jks'))
    report["negativeCases"] = [{"mode": file.stem, "expectedCodes": expected_codes(
        file.stem, segments is not None, receipt.get("apkSignatureVerification", False))} for file in negatives]
    save_report(report_path, report)
    for file, contract in zip(negatives, report["negativeCases"]):
        negative_case(device, file, remote + "/" + file.name, contract["expectedCodes"], report, report_path)
        print("[ok] rejected",file.stem,flush=True)
    report.update(sdk=run([*device, "shell", "getprop", "ro.build.version.sdk"]),
                  pageSize=run([*device, "shell", "getconf", "PAGESIZE"]))
    save_report(report_path, report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--report", type=Path, help="Current-run JSON report; defaults to fixtures/device-results.json")
    parser.add_argument("--native-reference", type=Path)
    parser.add_argument("--ndk", type=Path, help="Build an additional unprotected JNI reference with this NDK")
    parser.add_argument("--clang", type=Path, help="Optional Clang for the unprotected reference")
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args(argv)
    report_path = args.report or args.fixtures / "device-results.json"
    report = {"schemaVersion": 2, "runId": uuid.uuid4().hex, "startedAt": utc_now(), "status": "running",
              "serial": args.serial, "fixtures": str(args.fixtures.resolve()), "results": [],
              "invocation": [sys.executable, str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)]}
    save_report(report_path, report)  # Invalidate a stale success before any setup or execution.
    try:
        exercise(args, report, report_path)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        try:
            cleanup = cleanup_remote(report)
        except BaseException as error:
            cleanup = [{"status": "error", "error": {"type": type(error).__name__, "message": str(error)}}]
        report["cleanup"] = cleanup
        cleanup_failed = any(row["status"] != "completed" for row in cleanup)
        failed_before_cleanup = report["status"] != "passed"
        if cleanup_failed and not failed_before_cleanup:
            report.update(status="failed", error={"type": "RuntimeError", "message": "device cleanup failed"})
        report["finishedAt"] = utc_now()
        save_report(report_path, report)
        if cleanup_failed and not failed_before_cleanup:
            raise RuntimeError("device cleanup failed; see current-run report")


if __name__ == "__main__":
    main()
