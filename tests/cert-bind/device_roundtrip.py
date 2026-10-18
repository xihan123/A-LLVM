"""Build a disposable APK and test real certificate binding on an arm64 device.

Requires a patched NDK, Android build-tools, android.jar, JDK 17+ and OpenSSL.
Installs only a fresh random package name; removes that test package on exit.
"""
import argparse
import hashlib
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
    parser.add_argument("--clang", type=Path, help="test a local patched clang with the NDK sysroot")
    parser.add_argument("--hardened", action="store_true", help="exercise sealed CSE and dual-path certificate I/O")
    args = parser.parse_args()
    ext = ".exe" if os.name == "nt" else ""
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    prebuilt = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else prebuilt / f"bin/clang{ext}"
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
  private static native void check(String path, String module);
  public void onCreate(android.os.Bundle state) {
    super.onCreate(state);
    java.io.File module = new java.io.File(getFilesDir(), "module.apk");
    try (java.io.InputStream in = getAssets().open("module.apk");
         java.io.OutputStream out = new java.io.FileOutputStream(module)) {
      byte[] buffer = new byte[8192]; int n;
      while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
    } catch (java.io.IOException error) { throw new RuntimeException(error); }
    check(new java.io.File(getFilesDir(), "result").getAbsolutePath(), module.getAbsolutePath());
    finish();
  }
}
''', encoding="utf-8")
            run(javac, "-source", "8", "-target", "8", "-classpath", args.android_jar,
                "-d", out / "classes", activity)
            run(java, "-cp", args.build_tools / "lib/d8.jar", "com.android.tools.r8.D8",
                "--lib", args.android_jar, "--min-api", "21", "--output", out / "dex",
                out / "classes/com/ndkp/stability/CheckActivity.class")
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
            entry = root / "tests/cert-bind/device_origin_entry.cpp"
            common = ["--target=aarch64-linux-android21", "-O2", "-fPIC"]
            if args.clang:
                resource = max((prebuilt / "lib/clang").iterdir(), key=lambda p: int(p.name))
                common += [f"--sysroot={prebuilt / 'sysroot'}", "-resource-dir", resource, f"-B{prebuilt / 'bin'}"]
            run(clang, *common, "-std=c++17", "-fno-lto", "-c",
                root / "runtime/ndkp_apkcert.cpp", "-o", out / "helper.o")
            if args.hardened:
                run(clang, *common, "-std=c++17", "-fno-lto", "-fno-exceptions", "-c",
                    root / "runtime/ndkp_cse_runtime.cpp", "-o", out / "cse-runtime.o")
            run(clang, *common, "-std=c++17", "-I", root / "runtime", "-c",
                entry, "-o", out / "entry.o")
            run(clang, *common, "-std=c++17", "--driver-mode=g++", "-static-libstdc++",
                "-shared", "-I", root / "runtime", "-Wl,--no-undefined",
                root / "tests/cert-bind/device_origin_module.cpp", out / "helper.o",
                "-o", out / "libmodule.so")

            def align(unsigned, aligned):
                run(args.build_tools / f"zipalign{ext}", "-f", "-P", "16", "4", unsigned, aligned)

            def sign(aligned, signed, signer):
                run(java, "-jar", args.build_tools / "lib/apksigner.jar", "sign",
                    "--min-sdk-version", "23", "--key", out / f"{signer}.pk8",
                    "--cert", out / f"{signer}.der", "--out", signed, aligned)

            # A separately signed archive loaded with dlopen, without ART opening its dex.
            with zipfile.ZipFile(out / "module-unsigned.apk", "w", zipfile.ZIP_STORED) as module:
                module.write(out / "libmodule.so", "lib/arm64-v8a/libmodule.so")
            align(out / "module-unsigned.apk", out / "module-aligned.apk")
            sign(out / "module-aligned.apk", out / "module.apk", "bad")
            module_sha = hashlib.sha256((out / "bad.der").read_bytes()).hexdigest()

            def skeleton(path, extracted, split=False):
                manifest = out / "AndroidManifest.xml"
                split_attribute = ' split="config.arm64_v8a"' if split else ""
                application = ('<application android:hasCode="false"/>' if split else
                    f'<application android:debuggable="true" android:extractNativeLibs="{str(extracted).lower()}" '
                    'android:label="NDKP regression"><activity android:name="com.ndkp.stability.CheckActivity" '
                    'android:exported="true"/></application>')
                manifest.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                    f'package="{package}" android:versionCode="1"{split_attribute}>'
                    '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>'
                    f'{application}</manifest>', encoding="utf-8")
                run(args.build_tools / f"aapt{ext}", "package", "-f", "-M", manifest,
                    "-I", args.android_jar, "-F", path)

            for mode in (("cse",) if args.hardened else ("cse", "vmp", "combined")):
                flags = ["-mllvm", "-irobf-cert-bind", "-mllvm",
                         f"-irobf-cert-file={out / 'good.der'}"]
                if mode != "vmp":
                    flags += ["-mllvm", "-irobf-cse"]
                if mode != "cse":
                    flags += ["-mllvm", "-irobf-vmp", "-mllvm",
                              "-irobf-vm_functions=protected_compute"]
                if args.hardened:
                    flags += ["-mllvm", "-irobf-cse-hardened", "-mllvm", "-irobf-cse-bind",
                              "-mllvm", f"-irobf-cse-bind-package={package}"]
                if mode == "combined":
                    flags += ["-mllvm", "-irobf-selfcheck"]
                run(clang, *common, *flags, "-c", protected, "-o", out / "protected.o")
                extra = [out / "cse-runtime.o"] if args.hardened else []
                run(clang, *common, "--driver-mode=g++", "-static-libstdc++", "-shared",
                    "-Wl,--no-undefined", out / "entry.o", out / "helper.o",
                    out / "protected.o", *extra, "-o", out / "libcheck.so")
                if args.hardened:
                    import sys
                    sys.path.insert(0, str(root / "scripts"))
                    import seal_cse
                    sealed = seal_cse.process((out / "libcheck.so").read_bytes())
                    seal_cse.process(sealed, True, package, (out / "good.der").read_bytes())
                    (out / "libcheck.so").write_bytes(sealed)
                for loading in ("base-extracted", "base-direct", "split-extracted", "split-direct"):
                    extracted = loading.endswith("extracted")
                    split = loading.startswith("split")
                    unsigned = out / "unsigned.apk"
                    skeleton(unsigned, extracted)
                    compression = zipfile.ZIP_DEFLATED if extracted else zipfile.ZIP_STORED
                    with zipfile.ZipFile(unsigned, "a", compression) as apk:
                        apk.write(out / "dex/classes.dex", "classes.dex")
                        apk.write(out / "module.apk", "assets/module.apk")
                        # Stored assets exercise zipalign's raw local-header padding even in extracted mode.
                        apk.writestr("assets/a", b"alignment regression", compress_type=zipfile.ZIP_STORED)
                        if not split:
                            apk.write(out / "libcheck.so", "lib/arm64-v8a/libcheck.so")
                    align(unsigned, out / "aligned.apk")
                    if split:
                        skeleton(out / "split-unsigned.apk", extracted, split=True)
                        with zipfile.ZipFile(out / "split-unsigned.apk", "a", compression) as apk:
                            apk.write(out / "libcheck.so", "lib/arm64-v8a/libcheck.so")
                        align(out / "split-unsigned.apk", out / "split-aligned.apk")
                    for signer in ("good", "bad"):
                        apk = out / "signed.apk"
                        sign(out / "aligned.apk", apk, signer)
                        if split:
                            sign(out / "split-aligned.apk", out / "split-signed.apk", signer)
                            adb("install-multiple", "--no-streaming", apk, out / "split-signed.apk")
                        else:
                            adb("install", "--no-streaming", apk)
                        installed = True
                        adb("shell", "am", "start", "-W", "-n", package + "/com.ndkp.stability.CheckActivity")
                        result = ""
                        for _ in range(40):
                            result = adb("shell", "run-as", package, "cat", "files/result", check=False).stdout.strip()
                            if result in ("OK", "BAD"):
                                break
                            time.sleep(0.25)
                        origin = adb("shell", "run-as", package, "cat", "files/result.origin", check=False).stdout.strip()
                        own_sha = hashlib.sha256((out / f"{signer}.der").read_bytes()).hexdigest()
                        if origin != own_sha + "\n" + module_sha:
                            raise RuntimeError(f"{mode}/{loading}/{signer}: wrong library origins: {origin!r}")
                        if signer == "good" and result != "OK":
                            raise RuntimeError(f"{mode}/{loading}: matching certificate failed: {result!r}")
                        if signer == "bad" and result not in ("START", "BAD"):
                            raise RuntimeError(f"{mode}/{loading}: mismatched certificate result: {result!r}")
                        print(f"[ok] {mode}/{loading}/{signer}: {result}; own/module SHA-256 verified", flush=True)
                        adb("uninstall", package)
                        installed = False

    finally:
        if installed:
            adb("uninstall", package, check=False)


if __name__ == "__main__":
    main()
