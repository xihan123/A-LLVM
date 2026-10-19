"""Run baseline/native VMP DEX under ART with CheckJNI on one explicit device."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import time
import uuid
import zipfile


def run(command, timeout=300):
    result = subprocess.run([str(value) for value in command], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout[-8000:]}{result.stderr[-8000:]}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--native-reference", type=Path)
    parser.add_argument("--ndk", type=Path, help="Build an additional unprotected JNI reference with this NDK")
    parser.add_argument("--clang", type=Path, help="Optional Clang for the unprotected reference")
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    if args.ndk:
        if args.native_reference:
            parser.error("choose --ndk or --native-reference")
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
             *(generated / name for name in ("protected.cpp", "registration.cpp", "dex2c_runtime.cpp")),
             "-lm", "-o", args.native_reference])
    adb = args.sdk / "platform-tools/adb.exe"
    if not adb.exists():
        adb = adb.with_suffix("")
    device = [adb, "-s", args.serial]
    remote = "/data/local/tmp/dex2c-" + uuid.uuid4().hex
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
    def signed_apk(label, library, store):
        unsigned=args.fixtures / (label+"-unsigned.apk")
        aligned=args.fixtures / (label+"-aligned.apk")
        result=args.fixtures / (label+".apk")
        with zipfile.ZipFile(args.fixtures / "protected.zip") as dex, zipfile.ZipFile(unsigned,"w") as archive:
            for name in dex.namelist():
                archive.writestr(name,dex.read(name))
            archive.writestr("lib/arm64-v8a/libdex2c_semantics.so",library,compress_type=zipfile.ZIP_STORED)
        run([build_tools / "zipalign.exe","-P","16","-f","4",unsigned,aligned])
        run([args.java,"-jar",build_tools / "lib/apksigner.jar","sign","--ks",store,"--ks-key-alias","test",
             "--ks-pass","pass:android","--min-sdk-version","26","--out",result,aligned])
        return result
    library=(args.fixtures / "native/jniLibs/arm64-v8a/libdex2c_semantics.so").read_bytes()
    protected_apk=signed_apk("protected",library,args.fixtures / "test.jks")
    run([*device, "shell", "mkdir", remote])
    pushed = []
    for file in (args.fixtures / "baseline.zip", protected_apk, args.fixtures / "protected.zip",
                 args.fixtures / "native/jniLibs/arm64-v8a/libdex2c_semantics.so"):
        target = remote + "/" + file.name
        run([*device, "push", file, target]); pushed.append(target)
    outcomes = []
    for main_class in ("sample.Run", "kfixture.FixtureKt"):
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
    ir=(args.fixtures / "native/protected.ll").read_text()
    encoded=re.search(r'^@gv_code_seg_d2c_\w+ = .*? c"([^"\n]+)"',ir,re.M).group(1)
    bytecode=bytes((92 if escape=='\\' else int(escape,16)) if escape else ord(char)
                   for escape,char in re.findall(r'\\([A-Fa-f0-9]{2}|\\)|([^\\])',encoded))
    offset=library.find(bytecode)
    assert offset>=0 and library.find(bytecode,offset+1)<0
    changed=bytearray(library);changed[offset]^=1
    tampered=signed_apk("tampered-vm",changed,args.fixtures / "test.jks")
    for file in (wrong,tampered):
        target=remote+"/"+file.name;run([*device,"push",file,target]);pushed.append(target)
        result=subprocess.run([str(v) for v in [*device,"shell","env",f"CLASSPATH={target}","app_process",
                "-Xcheck:jni","-Djava.library.path="+target+"!/lib/arm64-v8a","/system/bin","sample.Run"]],
                capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=90)
        assert result.returncode!=0,(file,result.stdout,result.stderr)
        assert not result.stdout.strip(),(file,"algorithm ran despite invalid protection",result.stdout)
        outcomes.append({"mode":file.stem,"rejected":True,"exitCode":result.returncode})
        print("[ok] rejected",file.stem,flush=True)
    report = {"serial": args.serial,
              "sdk": run([*device, "shell", "getprop", "ro.build.version.sdk"]),
              "pageSize": run([*device, "shell", "getconf", "PAGESIZE"]),
              "results": outcomes}
    (args.fixtures / "device-results.json").write_text(json.dumps(report, indent=2)+"\n")
    # Only remove the exact files uploaded by this invocation.
    run([*device, "shell", "rm", "-f", *pushed])
    run([*device, "shell", "rmdir", remote])


if __name__ == "__main__":
    main()
