#!/usr/bin/env python3
"""LLVM snapshot identity, integrity checks and build measurements on both hosts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time


FORMAT = 2
STATE_DIR = Path(".snapshot")
MANIFEST = ".llvm-build-snapshot.json"
TREES = ("llvm-project", "build")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(*command):
    return subprocess.check_output(command, text=True, encoding="utf-8").strip()


def output(name, value):
    print(f"{name}={value}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"{name}={value}\n")


def cache_key(identity):
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return f"llvm-build-v{FORMAT}-" + hashlib.sha256(encoded).hexdigest()


def cmake_args(root, targets, tools, host="linux-x86_64"):
    windows = host == "windows-x86_64"
    return [
        "-S", (root / "llvm-project/llvm").as_posix(), "-B", (root / "build").as_posix(), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DLLVM_ENABLE_ASSERTIONS=OFF",
        f"-DCMAKE_C_COMPILER={tools['cl' if windows else 'clang']['path']}",
        f"-DCMAKE_CXX_COMPILER={tools['cl' if windows else 'clang++']['path']}",
        f"-DPython3_EXECUTABLE={tools['python']['path']}",
        *([] if windows else ["-DLLVM_USE_LINKER=lld", "-DLLVM_PARALLEL_LINK_JOBS=1"]),
        "-DLLVM_OBFUSCATION_LINK_INTO_TOOLS=ON", "-DLLVM_ENABLE_PROJECTS=clang",
        f"-DLLVM_TARGETS_TO_BUILD={targets}",
    ]


def prepare(args):
    host = args.host
    windows = host == "windows-x86_64"
    if platform.system() != ("Windows" if windows else "Linux") or platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError(f"the snapshot requires a native {host} host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.base):
        raise ValueError("an exact 40-character LLVM Base revision is required")
    root = Path.cwd().resolve()
    overlay = root / f"obfuscation/llvm-{args.major}"
    for path in (overlay / "registration.patch", overlay / "Transforms/Obfuscation/CMakeLists.txt"):
        if not path.is_file():
            raise ValueError(f"missing overlay input: {path}")
    tools = {}
    names = ("cl", "link", "lib", "rc", "mt") if windows else ("clang", "clang++", "ld.lld")
    for name in (*names, "cmake", "ninja", "tar"):
        executable = os.environ.get("SNAPSHOT_TAR") if name == "tar" else None
        executable = executable or shutil.which(name)
        if windows and name in ("link", "lib"):
            executable = str(Path(tools["cl"]["path"]).parent / (name + ".exe"))
        if not executable:
            raise ValueError(f"missing host tool: {name}")
        if windows and name in names:
            quoted = executable.replace("'", "''")
            version = capture("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                              f"(Get-Item -LiteralPath '{quoted}').VersionInfo.ProductVersion")
            if not version:
                raise ValueError(f"missing Windows tool version: {executable}")
        else:
            version = capture(executable, "--version")
        tools[name] = {"path": Path(executable).as_posix(), "resolved_path": Path(executable).resolve().as_posix(),
                       "version": version, "sha256": digest(executable)}
    if args.enabled and "GNU tar" not in tools["tar"]["version"]:
        raise ValueError("snapshot archives require GNU tar with PAX timestamp support")
    tools["python"] = {"path": Path(sys.executable).as_posix(), "resolved_path": Path(sys.executable).resolve().as_posix(),
                       "version": sys.version, "sha256": digest(sys.executable)}
    environment = {}
    if windows:
        for name in ("VCToolsInstallDir", "VCToolsVersion", "WindowsSdkDir", "WindowsSDKVersion",
                     "UniversalCRTSdkDir", "UCRTVersion", "INCLUDE", "LIB", "LIBPATH",
                     "VSCMD_ARG_HOST_ARCH", "VSCMD_ARG_TGT_ARCH"):
            environment[name] = os.environ.get(name, "")
            if not environment[name]:
                raise ValueError(f"missing MSVC/SDK environment: {name}")
    config_files = [overlay / "registration.patch", *overlay.rglob("CMakeLists.txt"),
                    *overlay.rglob("*.cmake"), root / "scripts/apply_overlay.sh",
                    root / "scripts/sync_overlay.py", root / "scripts/build_snapshot.py"]
    identity = {
        "format": FORMAT, "base_commit": args.base, "llvm_major": args.major,
        "host": host, "architecture": "x86_64", "root": root.as_posix(),
        "image_os": os.environ.get("ImageOS", ""),
        "image_version": os.environ.get("ImageVersion", ""),
        "os_release": platform.version() if windows else Path("/etc/os-release").read_text(),
        "packages": None if windows else capture("dpkg-query", "-W", "-f=${Package}=${Version}\n"),
        "environment": environment,
        "tools": tools, "cmake_args": cmake_args(root, args.targets, tools, host),
        "configuration_files": {p.relative_to(root).as_posix(): digest(p) for p in config_files},
    }
    if args.enabled and (not identity["image_os"] or not identity["image_version"]):
        raise ValueError("runner ImageOS and ImageVersion are required for snapshot reuse")
    overlay_hash = hashlib.sha256()
    for path in sorted(p for p in overlay.rglob("*") if p.is_file()):
        overlay_hash.update(path.relative_to(overlay).as_posix().encode() + b"\0")
        overlay_hash.update(bytes.fromhex(digest(path)))
    write_json(STATE_DIR / "expected.json", identity)
    state = {"requested": args.enabled, "hit": False, "key": cache_key(identity),
             "reason": "not restored" if args.enabled else "disabled",
             "source_commit": os.environ.get("GITHUB_SHA", capture("git", "rev-parse", "HEAD")),
             "overlay_sha256": overlay_hash.hexdigest(), "snapshot_origin": None,
             "probe": os.environ.get("SNAPSHOT_PROBE", "none"),
             "restore_started_at": time.time()}
    write_json(STATE_DIR / "state.json", state)
    output("key", state["key"])


def inventory(root):
    result = {}
    for name in TREES:
        tree = root / name
        if is_reparse_point(tree) or tree.is_symlink() or not tree.is_dir():
            raise ValueError(f"missing or linked snapshot tree: {tree}")
        for directory, dirs, files in os.walk(tree, followlinks=False):
            for entry in sorted(dirs + files):
                path = Path(directory) / entry
                info = path.lstat()
                key = path.relative_to(root).as_posix()
                if stat.S_ISLNK(info.st_mode):
                    result[key] = {"kind": "link", "target": os.readlink(path)}
                elif getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError(f"unsupported snapshot reparse point: {path}")
                elif stat.S_ISDIR(info.st_mode):
                    result[key] = {"kind": "directory"}
                elif stat.S_ISREG(info.st_mode):
                    result[key] = {"kind": "file", "size": info.st_size,
                                   "mtime_ns": info.st_mtime_ns, "mode": stat.S_IMODE(info.st_mode),
                                   "sha256": digest(path)}
                else:
                    raise ValueError(f"unsupported snapshot entry: {path}")
    return result


def check_build(root, expected):
    major = expected["llvm_major"]
    windows = expected["host"] == "windows-x86_64"
    required = ["llvm-project/.git/HEAD", "llvm-project/llvm/CMakeLists.txt",
                "llvm-project/llvm/lib/Transforms/Obfuscation/.ndkp-overlay-files.json",
                "llvm-project/llvm/include/llvm/Transforms/Obfuscation/.ndkp-overlay-files.json",
                "build/CMakeCache.txt", "build/build.ninja", "build/.ninja_log", "build/.ninja_deps",
                "build/bin/clang" + (".exe" if windows else ""), f"build/lib/clang/{major}/include/stddef.h"]
    for name in required:
        if not (root / name).is_file():
            raise ValueError(f"incomplete snapshot: {name}")
    if capture("git", "-C", str(root / "llvm-project"), "rev-parse", "HEAD") != expected["base_commit"]:
        raise ValueError("restored LLVM Base revision differs")
    cache = {}
    for line in (root / "build/CMakeCache.txt").read_text().splitlines():
        match = re.match(r"([^:#/][^:]*):[^=]+=(.*)", line)
        if match:
            cache[match[1]] = match[2]
    wanted = {"CMAKE_HOME_DIRECTORY": str(root / "llvm-project/llvm"),
              "CMAKE_CACHEFILE_DIR": str(root / "build"), "CMAKE_GENERATOR": "Ninja"}
    wanted.update(option[2:].split("=", 1) for option in expected["cmake_args"] if option.startswith("-D"))
    for name, value in wanted.items():
        actual = cache.get(name)
        if name in ("CMAKE_HOME_DIRECTORY", "CMAKE_CACHEFILE_DIR", "CMAKE_C_COMPILER",
                    "CMAKE_CXX_COMPILER", "Python3_EXECUTABLE") and actual is not None:
            actual, value = (v.replace("\\", "/").rstrip("/") for v in (actual, value))
            if windows:
                actual, value = actual.casefold(), value.casefold()
        if actual != value:
            raise ValueError(f"restored CMake configuration differs: {name}")


def is_reparse_point(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def remove_readonly(function, path, exc_info):
    if os.name != "nt" or not isinstance(exc_info[1], PermissionError):
        raise exc_info[1]
    os.chmod(path, stat.S_IWRITE)
    function(path)


def discard(root):
    # Only the two fixed build trees are removable; never take paths from a manifest.
    root = root.resolve()
    for name in TREES:
        path = root / name
        if path.is_symlink():
            path.unlink()
        elif is_reparse_point(path):
            path.rmdir()
        elif path.exists():
            if path.resolve().parent != root or not path.is_dir():
                raise ValueError(f"refusing to remove unexpected snapshot path: {path}")
            shutil.rmtree(path, onerror=remove_readonly)
    (root / MANIFEST).unlink(missing_ok=True)


def validate(args):
    root = Path.cwd().resolve()
    expected = read_json(STATE_DIR / "expected.json")
    state = read_json(STATE_DIR / "state.json")
    state["restore_seconds"] = round(time.time() - state.pop("restore_started_at"), 3)
    started = time.monotonic()
    try:
        if args.cache_hit != "true":
            raise ValueError("exact cache key was not restored")
        manifest = read_json(root / MANIFEST)
        if not isinstance(manifest, dict) or manifest.get("identity") != expected:
            raise ValueError("snapshot compatibility manifest differs")
        actual = inventory(root)
        saved = manifest.get("inventory")
        if not isinstance(saved, dict) or actual != saved:
            changed = next((name for name in actual if saved is None or not isinstance(saved, dict)
                            or actual[name] != saved.get(name)), "missing entry")
            raise ValueError(f"snapshot contents or timestamps differ: {changed}")
        check_build(root, expected)
        state.update(hit=True, reason="validated", snapshot_origin=manifest["origin"])
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"[snapshot] cold build: {error}", file=sys.stderr)
        discard(root)
        state.update(hit=False, reason=str(error), snapshot_origin=None)
    state["validation_seconds"] = round(time.monotonic() - started, 3)
    write_json(STATE_DIR / "state.json", state)
    output("hit", str(state["hit"]).lower())


def seal():
    started = time.monotonic()
    root = Path.cwd().resolve()
    expected = read_json(STATE_DIR / "expected.json")
    state = read_json(STATE_DIR / "state.json")
    check_build(root, expected)
    files = inventory(root)
    write_json(root / MANIFEST, {
        "identity": expected, "inventory": files,
        "origin": {"repository_commit": state["source_commit"],
                   "overlay_sha256": state["overlay_sha256"],
                   "run_id": os.environ.get("GITHUB_RUN_ID", ""), "created_at": time.time()},
    })
    state.update(snapshot_bytes=sum(item.get("size", 0) for item in files.values()),
                 snapshot_entries=len(files), seal_seconds=round(time.monotonic() - started, 3),
                 save_started_at=time.time())
    write_json(STATE_DIR / "state.json", state)


def ninja_measurements(before, after):
    previous = set(before.splitlines())
    measurements = {"compile_edges": 0, "link_edges": 0, "other_edges": 0,
                    "compile_work_seconds": 0.0, "link_work_seconds": 0.0,
                    "compile_outputs": [], "link_outputs": []}
    for line in after.splitlines():
        if line in previous or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        start, end, _, filename, _ = fields
        seconds = (int(end) - int(start)) / 1000
        if filename.endswith((".o", ".obj")):
            measurements["compile_edges"] += 1
            measurements["compile_work_seconds"] += seconds
            measurements["compile_outputs"].append(filename)
        elif filename.endswith((".a", ".lib", ".so", ".exe")) or re.fullmatch(r"bin/clang(?:-[0-9]+)?", filename):
            measurements["link_edges"] += 1
            measurements["link_work_seconds"] += seconds
            measurements["link_outputs"].append(filename)
        else:
            measurements["other_edges"] += 1
    return measurements


def run_timed(phase, command):
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise ValueError("a command to measure is required")
    ninja_log = Path("build/.ninja_log")
    before = ninja_log.read_text() if phase == "compile" and ninja_log.exists() else ""
    started = time.monotonic()
    result = subprocess.run(command)
    item = {"phase": phase, "seconds": round(time.monotonic() - started, 3),
            "exit_code": result.returncode}
    if phase == "compile" and ninja_log.exists():
        item.update(ninja_measurements(before, ninja_log.read_text()))
    path = STATE_DIR / "timings.json"
    measurements = read_json(path) if path.exists() else []
    measurements.append(item)
    write_json(path, measurements)
    return result.returncode


def report(args):
    state_path = STATE_DIR / "state.json"
    state = read_json(state_path) if state_path.exists() else {"requested": False, "hit": False}
    if "save_started_at" in state:
        state["save_seconds"] = round(time.time() - state.pop("save_started_at"), 3)
        state["save_outcome"] = args.save_outcome
        write_json(state_path, state)
    timings_path = STATE_DIR / "timings.json"
    timings = read_json(timings_path) if timings_path.exists() else []
    data = {"snapshot": state, "timings": timings, "repository_commit": os.environ.get("GITHUB_SHA", "")}
    write_json(STATE_DIR / "report.json", data)
    lines = ["### LLVM build measurements", "", f"Snapshot hit: `{state['hit']}`",
             "", "| Phase | Seconds | Exit |", "| --- | ---: | ---: |"]
    lines += [f"| {item['phase']} | {item['seconds']} | {item['exit_code']} |" for item in timings]
    lines += [f"| snapshot-{phase} | {state[phase + '_seconds']} | |"
              for phase in ("restore", "validation", "seal", "save") if phase + "_seconds" in state]
    if "snapshot_bytes" in state:
        lines += ["", f"Uncompressed snapshot: {state['snapshot_bytes'] / (1024 ** 3):.2f} GiB"]
    for item in timings:
        if item["phase"] == "compile":
            lines += ["", f"Ninja outputs: {item.get('compile_edges', 0)} compiled, {item.get('link_edges', 0)} linked."]
    lines += ["", "Compile/link work seconds in report.json sum Ninja edges; parallel work is not wall time."]
    print("\n".join(lines))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--base", required=True)
    prepare_parser.add_argument("--major", required=True, type=int)
    prepare_parser.add_argument("--targets", required=True)
    prepare_parser.add_argument("--host", choices=("linux-x86_64", "windows-x86_64"),
                                default="windows-x86_64" if os.name == "nt" else "linux-x86_64")
    prepare_parser.add_argument("--enabled", action="store_true")
    sub.add_parser("validate").add_argument("--cache-hit", default="false")
    sub.add_parser("seal")
    sub.add_parser("configure")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--phase", required=True)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("report").add_argument("--save-outcome", default="skipped")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args)
        elif args.action == "validate":
            validate(args)
        elif args.action == "seal":
            seal()
        elif args.action == "configure":
            expected = read_json(STATE_DIR / "expected.json")
            return run_timed("configure", [expected["tools"]["cmake"]["path"], *expected["cmake_args"]])
        elif args.action == "run":
            return run_timed(args.phase, args.command)
        else:
            report(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"[error] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
