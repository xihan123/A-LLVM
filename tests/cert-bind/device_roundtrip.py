"""Build a disposable APK and test real certificate binding on an arm64 device.

Requires a patched NDK, Android build-tools, android.jar, JDK 17+ and OpenSSL.
Installs only a fresh random package name; removes that test package on exit.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import zipfile


def run(*args, check=True, timeout=90):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            errors="replace", timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed:\n{result.stdout}\n{result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--android-jar", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    ext = ".exe" if os.name == "nt" else ""
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    clang = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host / f"bin/clang{ext}"
    java = args.java_home / "bin" / f"java{ext}"
    javac = args.java_home / "bin" / f"javac{ext}"
    root = Path(__file__).resolve().parents[2]
    package = "com.ndkp.stability.p" + uuid.uuid4().hex[:12]

    def adb(*parts, **kwargs):
        return run("adb", "-s", args.serial, *parts, **kwargs)

    # Never replace a pre-existing package, even in the unlikely event of a collision.
    if "package:" in adb("shell", "pm", "path", package, check=False).stdout:
        raise RuntimeError(f"test package already exists: {package}")
    installed = False
    try:
        with tempfile.TemporaryDirectory(prefix="ndkp-cert-") as tmp:
            out = Path(tmp)
            (out / "classes").mkdir()
            (out / "dex").mkdir()
            activity = out / "CheckActivity.java"
            activity.write_text('''package com.ndkp.stability;
public class CheckActivity extends android.app.Activity {
  static { System.loadLibrary("check"); }
  private static native void check(String path);
  public void onCreate(android.os.Bundle state) {
    super.onCreate(state);
    check(new java.io.File(getFilesDir(), "result").getAbsolutePath());
    finish();
  }
}
''', encoding="utf-8")
            manifest = out / "AndroidManifest.xml"
            manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">
<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/>
<application android:debuggable="true" android:extractNativeLibs="true" android:label="NDKP regression">
<activity android:name="com.ndkp.stability.CheckActivity" android:exported="true"/>
</application></manifest>''', encoding="utf-8")
            run(javac, "-source", "8", "-target", "8", "-classpath", args.android_jar,
                "-d", out / "classes", activity)
            run(java, "-cp", args.build_tools / "lib/d8.jar", "com.android.tools.r8.D8",
                "--lib", args.android_jar, "--min-api", "21", "--output", out / "dex",
                out / "classes/com/ndkp/stability/CheckActivity.class")
            run(args.build_tools / f"aapt{ext}", "package", "-f", "-M", manifest,
                "-I", args.android_jar, "-F", out / "base.apk")
            for signer in ("good", "bad"):
                run(args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=ndkp-regression",
                    "-keyout", out / f"{signer}.pem", "-outform", "DER",
                    "-out", out / f"{signer}.der")
                run(args.openssl, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER",
                    "-in", out / f"{signer}.pem", "-out", out / f"{signer}.pk8")
            protected = out / "protected.c"
            protected.write_text('''const char *protected_secret(void) { return "certificate roundtrip"; }
int protected_compute(int x) { return x * 7 + 5; }
''', encoding="utf-8")
            entry = out / "entry.c"
            entry.write_text('''#include <jni.h>
#include <stdio.h>
#include <string.h>
const char *protected_secret(void);
int protected_compute(int);
JNIEXPORT void JNICALL Java_com_ndkp_stability_CheckActivity_check(JNIEnv *env, jclass cls, jstring path) {
  const char *name = (*env)->GetStringUTFChars(env, path, 0);
  FILE *f = fopen(name, "w");
  if (!f) return;
  fputs("START", f); fclose(f);
  volatile int input = 7;
  int ok = strcmp(protected_secret(), "certificate roundtrip") == 0;
  ok &= protected_compute(input) == 54;
  f = fopen(name, "w");
  if (f) { fputs(ok ? "OK" : "BAD", f); fclose(f); }
  (*env)->ReleaseStringUTFChars(env, path, name);
}
''', encoding="utf-8")
            common = ["--target=aarch64-linux-android21", "-O2", "-fPIC"]
            run(clang, *common, "-std=c++17", "-fno-lto", "-c",
                root / "runtime/ndkp_apkcert.cpp", "-o", out / "helper.o")
            run(clang, *common, "-c", entry, "-o", out / "entry.o")
            for mode in ("cse", "vmp", "combined"):
                flags = ["-mllvm", "-irobf-cert-bind", "-mllvm",
                         f"-irobf-cert-file={out / 'good.der'}"]
                if mode != "vmp":
                    flags += ["-mllvm", "-irobf-cse"]
                if mode != "cse":
                    flags += ["-mllvm", "-irobf-vmp", "-mllvm",
                              "-irobf-vm_functions=protected_compute"]
                if mode == "combined":
                    flags += ["-mllvm", "-irobf-selfcheck"]
                run(clang, *common, *flags, "-c", protected, "-o", out / "protected.o")
                run(clang, *common, "--driver-mode=g++", "-static-libstdc++", "-shared",
                    "-Wl,--no-undefined", out / "entry.o", out / "helper.o",
                    out / "protected.o", "-o", out / "libcheck.so")
                unsigned = out / "unsigned.apk"
                unsigned.write_bytes((out / "base.apk").read_bytes())
                with zipfile.ZipFile(unsigned, "a", zipfile.ZIP_DEFLATED) as apk:
                    apk.write(out / "dex/classes.dex", "classes.dex")
                    apk.write(out / "libcheck.so", "lib/arm64-v8a/libcheck.so")
                run(args.build_tools / f"zipalign{ext}", "-f", "4", unsigned, out / "aligned.apk")
                for signer in ("good", "bad"):
                    apk = out / "signed.apk"
                    run(java, "-jar", args.build_tools / "lib/apksigner.jar", "sign",
                        "--key", out / f"{signer}.pk8", "--cert", out / f"{signer}.der",
                        "--out", apk, out / "aligned.apk")
                    adb("install", "--no-streaming", apk)
                    installed = True
                    adb("shell", "am", "start", "-W", "-n", package + "/com.ndkp.stability.CheckActivity")
                    result = ""
                    for _ in range(40):
                        result = adb("shell", "run-as", package, "cat", "files/result", check=False).stdout.strip()
                        if result in ("OK", "BAD"):
                            break
                        time.sleep(0.25)
                    if signer == "good" and result != "OK":
                        raise RuntimeError(f"{mode}: matching certificate failed: {result!r}")
                    if signer == "bad" and result not in ("START", "BAD"):
                        raise RuntimeError(f"{mode}: mismatched certificate result: {result!r}")
                    print(f"[ok] {mode}/{signer}: {result}", flush=True)
                    adb("uninstall", package)
                    installed = False
    finally:
        if installed:
            adb("uninstall", package, check=False)


if __name__ == "__main__":
    main()
