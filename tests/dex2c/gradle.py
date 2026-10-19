"""Build a private sample copy and check R8, native coexistence, caching and annotation removal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time
import zipfile
from artifacts import verify_wrappers


def inspect_apk(apk, protected):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        assert "classes.dex" in names, "AGP did not consume the transformed classes"
        assert "lib/arm64-v8a/libcoexist.so" in names, "existing native library was lost"
        libraries = [name for name in names if name.startswith("lib/arm64-v8a/") and name.endswith(".so") and not name.endswith("/libcoexist.so")]
        assert len(libraries) == int(protected), (apk, libraries)
        for name in libraries:
            info = archive.getinfo(name)
            assert info.compress_type == zipfile.ZIP_STORED
            with apk.open("rb") as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
                lengths = struct.unpack_from("<HH", header, 26)
                assert (info.header_offset + 30 + sum(lengths)) % 16384 == 0, "APK alignment"
            elf = archive.read(name)
            assert elf[:5] == b"\x7fELF\x02"
            offset = struct.unpack_from("<Q", elf, 32)[0]
            size, count = struct.unpack_from("<HH", elf, 54)
            for index in range(count):
                header = offset + index * size
                if struct.unpack_from("<I", elf, header)[0] == 1:
                    assert struct.unpack_from("<Q", elf, header + 48)[0] >= 16384, "ELF alignment"
        return {"apkBytes": apk.stat().st_size,
                "nativeBytes": sum(archive.getinfo(name).file_size for name in libraries),
                "nativeSha256": [hashlib.sha256(archive.read(name)).hexdigest() for name in libraries]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.work_dir.resolve()
    if out.exists():
        raise ValueError("work directory must be new to preserve existing build evidence")
    shutil.copytree(repo / "dex2c/samples/xposed", out,
                    ignore=shutil.ignore_patterns("build", ".gradle", ".cxx", "local.properties"))
    settings = out / "settings.gradle"
    settings.write_text(settings.read_text().replace("'../..'", repr((repo / "dex2c").as_posix())))
    (out / "local.properties").write_text("sdk.dir=" + args.sdk.resolve().as_posix() + "\n")
    # The sample Release uses the standard debug signer. Only its public cert enters dex2c.
    certificate=out / "debug.der"
    subprocess.run([str(Path(os.environ["JAVA_HOME"]) / "bin/keytool.exe"),"-exportcert","-keystore",
                    str(Path.home() / ".android/debug.keystore"),"-storepass","android","-alias","androiddebugkey",
                    "-file",str(certificate)],check=True,capture_output=True)
    reports = []

    def build(label, *tasks, success=True):
        start = time.monotonic()
        command = [str(args.gradle.resolve()), "-p", str(out), *tasks, "--console=plain", "--build-cache",
                   "-Pdex2c.clang=" + str(args.clang.resolve()),"-Pdex2c.certificate="+str(certificate)]
        log = out / (label + ".log")
        with log.open("w", encoding="utf-8") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
        text = log.read_text(encoding="utf-8", errors="replace")
        assert (result.returncode == 0)==success, text[-10000:]
        reports.append({"phase": label, "seconds": round(time.monotonic() - start, 3)})
        return text

    release = out / "module/build/outputs/apk/release/module-release.apk"
    debug = out / "module/build/outputs/apk/debug/module-debug.apk"
    build("initial", ":module:assembleRelease", ":module:assembleDebug")
    release_info = inspect_apk(release, True)
    debug_info = inspect_apk(debug, False)
    report = json.loads((out / "module/build/intermediates/dex2c/release/generated/selection.json").read_text())
    assert len(report["methods"]) >= 5 and any("lambda" in m["method"] for m in report["methods"])
    assert report["bytecodeVerified"]
    verify_wrappers(release, report)
    text = build("up-to-date", ":module:assembleRelease")
    assert ":module:compileReleaseDex2cNative UP-TO-DATE" in text
    build("clean", ":module:clean", ":shared:clean")
    text = build("restored", ":module:assembleRelease")
    assert ":module:compileReleaseDex2cNative FROM-CACHE" in text, text[-10000:]
    assert inspect_apk(release, True)["nativeSha256"] == release_info["nativeSha256"]
    source = out / "shared/src/main/kotlin/io/github/xihan123/dex2c/sample/shared/HookImplementation.kt"
    annotated = source.read_text()
    source.write_text(annotated.replace("@dex2c\n", ""))
    build("annotation-removed", ":module:assembleRelease")
    removed_info = inspect_apk(release, False)
    protection = json.loads((out / "module/build/intermediates/dex2c/release/native/protection.json").read_text())
    assert protection["protectedMethods"] == 0
    source.write_text(annotated)
    module_build = out / "module/build.gradle"
    module_build.write_text(module_build.read_text() + "\ndex2c { buildTypes.set(['debug'] as Set) }\n")
    build("configured-types", ":module:assembleDebug", ":module:assembleRelease")
    inspect_apk(debug, True)
    inspect_apk(release, False)
    module_build.write_text(module_build.read_text()+"\ndex2c { certificateFile.unset() }\n")
    text=build("missing-certificate", ":module:assembleDebug",success=False)
    assert "certificateFile must contain the APK signing certificate" in text
    assert not list((out / "module/build/intermediates/dex2c/debug/native/jniLibs").rglob("*.so"))
    (out / "results.json").write_text(json.dumps({"release": release_info, "debug": debug_info,
            "removed": removed_info, "builds": reports}, indent=2) + "\n")
    print("[ok] Debug, R8 Release, dependency callbacks, existing SO, 16 KB ELF/APK alignment, "
          "DEX wrappers, up-to-date, native cache restore, annotation removal, buildTypes, missing-cert refusal; " + str(out / "results.json"))


if __name__ == "__main__":
    main()
