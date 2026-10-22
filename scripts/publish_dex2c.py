#!/usr/bin/env python3
"""Check, publish, or verify a dex2c Maven release (Python 3.11+, Windows/JDK 21)."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DEX2C = ROOT / "dex2c"
REPOSITORY = "https://mirrors.xihan.website/repository/maven-releases/"
GROUP = "io.github.xihan123.dex2c"
ARTIFACTS = ("annotations", "runtime", "core", "gradle-plugin", GROUP + ".gradle.plugin", "io.github.xihan123.strings.gradle.plugin")
CREDENTIALS = ("ORG_GRADLE_PROJECT_xihanUsername", "ORG_GRADLE_PROJECT_xihanPassword")
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
NATIVE_TESTS = {"nativeAndJvmSemanticsMatchWithCheckJni", "kotlinNativeMatchesJvm",
                "generatedKotlinCompilesToVerifiedArm64Vmp", "stringsNativeMatchesJvm", "stringsCompileToVerifiedArm64"}


def release_version(root=DEX2C):
    matches = re.findall(r"^\s*version\s*=\s*'([^']+)'", (root / "build.gradle").read_text("utf-8"), re.M)
    number = r"(?:0|[1-9][0-9]*)"
    identifier = rf"(?:{number}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    pattern = rf"{number}\.{number}\.{number}(?:-{identifier}(?:\.{identifier})*)?"
    if (len(matches) != 1 or not re.fullmatch(pattern, matches[0]) or
            matches[0].upper().endswith("-SNAPSHOT")):
        raise ValueError("build.gradle must declare one major.minor.patch release version "
                         "with an optional prerelease suffix (no SNAPSHOT)")
    version = matches[0]
    for file, expected in (
        (root / "gradle-plugin/src/main/java/io/github/xihan123/dex2c/gradle/Dex2cPlugin.java", 2),
        (root / "samples/xposed/shared/build.gradle", 1),
        (root / "samples/strings/build.gradle", 1),
    ):
        dependencies = re.findall(re.escape(GROUP) + r":(?:annotations|runtime):([^\"'\s]+)", file.read_text("utf-8"))
        if dependencies != [version] * expected:
            raise ValueError(f"Synchronize annotations/runtime dependency versions in {file}")
    return version


def artifact_path(artifact):
    return ("io.github.xihan123.strings" if artifact == "io.github.xihan123.strings.gradle.plugin" else GROUP).replace(".", "/") + "/" + artifact


def version_files(version):
    files = []
    for artifact in ARTIFACTS:
        suffixes = (".pom",) if artifact.endswith(".gradle.plugin") else (".jar", "-sources.jar", ".pom", ".module")
        for suffix in suffixes:
            name = f"{artifact_path(artifact)}/{version}/{artifact}-{version}{suffix}"
            files.extend([name] + [name + "." + checksum for checksum in CHECKSUMS])
    return sorted(files)


def fetch(path):
    # Anonymous reads also check that consumers can resolve the published files.
    request = urllib.request.Request(REPOSITORY + path, headers={"Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise RuntimeError(f"Repository HTTP {error.code}: {path}") from None
    except urllib.error.URLError:
        raise RuntimeError(f"Repository connection failed: {path}") from None


def metadata_versions(data, artifact):
    if data is None:
        return set(), None
    doc = ET.fromstring(data)
    if doc.findtext("groupId") != ("io.github.xihan123.strings" if artifact == "io.github.xihan123.strings.gradle.plugin" else GROUP) or doc.findtext("artifactId") != artifact:
        raise ValueError(f"Unexpected Maven metadata identity: {artifact}")
    versions = {item.text for item in doc.findall("versioning/versions/version")}
    if not versions or None in versions:
        raise ValueError(f"Empty Maven version list: {artifact}")
    return versions, doc.findtext("versioning/release")


def read_metadata():
    with ThreadPoolExecutor(max_workers=5) as pool:
        data = list(pool.map(fetch, (artifact_path(a) + "/maven-metadata.xml" for a in ARTIFACTS)))
    return {a: metadata_versions(value, a) for a, value in zip(ARTIFACTS, data)}


def require_new_version(version):
    before = read_metadata()
    if any(version in versions for versions, _ in before.values()):
        raise ValueError(f"Release {version} already exists; choose a new version, never overwrite it")
    # Check every expected file, including orphaned checksum/JAR files from a partial upload.
    paths = version_files(version)
    with ThreadPoolExecutor(max_workers=8) as pool:
        existing = [path for path, data in zip(paths, pool.map(fetch, paths)) if data is not None]
    if existing:
        raise ValueError(f"Release is partially published; refusing to overwrite {existing[0]}")
    return before


def staged_manifest(staging, version):
    expected = set(version_files(version))
    actual = {p.relative_to(staging).as_posix() for p in staging.rglob("*")
              if p.is_file() and p.parent.name == version}
    if actual != expected:
        raise ValueError(f"Incomplete staging: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
    manifest = []
    for path in sorted(expected):
        data = (staging / path).read_bytes()
        extension = path.rsplit(".", 1)[-1]
        if extension in CHECKSUMS:
            original = (staging / path.rsplit(".", 1)[0]).read_bytes()
            if data.decode("ascii").strip() != hashlib.new(extension, original).hexdigest():
                raise ValueError(f"Invalid staging checksum: {path}")
        manifest.append({"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return manifest


def verify_remote(staging, version, before=None):
    manifest = staged_manifest(staging, version)
    with ThreadPoolExecutor(max_workers=8) as pool:
        for entry, data in zip(manifest, pool.map(fetch, (m["path"] for m in manifest))):
            if data != (staging / entry["path"]).read_bytes():
                raise ValueError(f"Published file missing or differs from staging: {entry['path']}")
    after = read_metadata()
    for artifact, (versions, release) in after.items():
        previous = before[artifact][0] if before is not None else set()
        if not (previous | {version}) <= versions:
            raise ValueError(f"Maven metadata lost versions: {artifact}")
        if before is not None and release != version:
            raise ValueError(f"Maven release pointer does not match {version}: {artifact}")
    return {"version": version, "repository": REPOSITORY, "verified": manifest,
            "metadata": {a: {"versions": sorted(v), "release": r} for a, (v, r) in after.items()}}


def check_test_results(root=DEX2C):
    tests = 0
    names = set()
    for file in root.glob("*/build/test-results/test/TEST-*.xml"):
        suite = ET.parse(file).getroot()
        if any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped")):
            raise ValueError(f"Release requires zero failed/skipped tests: {file}")
        cases = suite.findall("testcase")
        tests += len(cases)
        names.update(case.get("name", "").removesuffix("()") for case in cases)
    if not NATIVE_TESTS <= names:
        raise ValueError("JNI/VMP differential test results are missing")
    return tests


def run_gradle(arguments, log, publish=False):
    # Windows normalizes environment keys to uppercase; filter without case sensitivity.
    env = {key: value for key, value in os.environ.items()
           if key.casefold() not in {name.casefold() for name in CREDENTIALS}}
    if publish:
        env.update(release_credentials())
    # TestSigning needs the same Python runtime on PATH as this entry point.
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    secrets = [env[key] for key in CREDENTIALS if env.get(key)]
    if len(secrets) == 2:
        secrets.append(base64.b64encode(":".join(secrets).encode()).decode())
    command = [str(DEX2C / "gradlew.bat"), *arguments, "--no-daemon", "--no-configuration-cache", "--console=plain"]
    print(f"Gradle running; log: {log}", flush=True)
    with log.open("w", encoding="utf-8") as output:
        with subprocess.Popen(command, cwd=DEX2C, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as process:
            for line in process.stdout:
                for secret in secrets:
                    line = line.replace(secret, "<redacted>")
                output.write(line)
                output.flush()
            if process.wait():
                raise RuntimeError(f"Gradle failed; inspect {log}")


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {path}", flush=True)


def release_credentials():
    credentials = {key: os.environ.get(key, "") for key in CREDENTIALS}
    if not all(credentials.values()):
        raise ValueError("Set both " + " and ".join(CREDENTIALS) + " in the process environment")
    return credentials


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="Run host JNI/VMP tests and stage all six publications; no upload")
    modes.add_argument("--publish", action="store_true", help="Check, stage, publish a NEW release and verify remote bytes")
    modes.add_argument("--verify-only", action="store_true", help="Compare existing staging with Maven; no build/upload")
    parser.add_argument("--clang", type=Path, help="A-LLVM LLVM 21 clang.exe with strict/post support (check/publish)")
    parser.add_argument("--ndk", type=Path, help="NDK r30 directory (check/publish)")
    parser.add_argument("--staging", type=Path, help="Existing Maven staging directory (verify-only; default dex2c/build/maven-staging)")
    args = parser.parse_args(argv)
    version = release_version()
    if args.verify_only:
        staging = (args.staging or DEX2C / "build/maven-staging").resolve()
        report = verify_remote(staging, version)
        write_report(staging.parent / f"verified-{version}.json", report)
        print(f"Verified {len(report['verified'])} files for {version}")
        return
    if args.staging:
        parser.error("--staging is only for --verify-only; check/publish always create a fresh directory")
    if os.name != "nt":
        parser.error("dex2c release checks currently require Windows")
    if args.clang is None or not args.clang.is_file() or args.ndk is None or not args.ndk.is_dir():
        parser.error("--clang and --ndk must point to the release toolchain")
    if args.publish:
        release_credentials()
        print(f"Checking that {version} is not already published...", flush=True)
        require_new_version(version)
    (DEX2C / "build").mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=f"release-{version}-", dir=DEX2C / "build"))
    staging = directory / "maven"
    property_arg = "-Pdex2c.stagingRepository=" + staging.as_posix()
    run_gradle(["check", ":gradle-plugin:validatePlugins", "--rerun-tasks", "--no-build-cache",
                "-Pdex2c.hostCompiler=" + str(args.clang.resolve()), "-Pdex2c.ndk=" + str(args.ndk.resolve())], directory / "check.log")
    tests = check_test_results()
    run_gradle(["publishAllPublicationsToStagingRepository", property_arg], directory / "staging.log")
    manifest = staged_manifest(staging, version)
    write_report(directory / "manifest.json", {"version": version, "repository": REPOSITORY,
                 "staging": str(staging), "tests": tests, "files": manifest})
    if args.publish:
        # Recheck after the build to catch concurrent publishers and preserve their metadata.
        before = require_new_version(version)
        try:
            run_gradle(["publishAllPublicationsToXihanRepository"], directory / "publish.log", publish=True)
            report = verify_remote(staging, version, before)
        except (RuntimeError, ValueError) as error:
            raise RuntimeError(f"{error}. Some files may have been uploaded; do not overwrite a partial release") from None
        write_report(directory / "published.json", report)
    print(f"{'Published and verified' if args.publish else 'Checked and staged'} {version}: {tests} tests, {len(manifest)} files", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, ET.ParseError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
