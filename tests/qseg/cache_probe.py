"""Validate concurrent first restoration and read-only VM caching in a signed APK."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from seal_cse import Elf


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    nm = subprocess.check_output([str(base/"bin/llvm-nm.exe"), "--defined-only", str(args.native/"linked.so")], text=True)
    symbols = {line.split()[-1]: line.split()[0] for line in nm.splitlines() if len(line.split()) >= 3}
    receipt = json.loads((args.native/"segments.json").read_text(encoding="utf-8"))
    sizes = {}
    for entry in receipt["segments"]:
        if entry["kind"] == 1:
            sizes[entry["id"]] = sizes.get(entry["id"], 0) + entry["bytes"]
    identity = max(sizes, key=sizes.get)
    ref = bytes.fromhex(identity) + struct.pack("<II", sizes[identity], 1)
    image = (args.native/"linked.so").read_bytes()
    offset = image.find(ref)
    assert offset >= 0 and image.find(ref, offset+1) < 0
    address = next(va+offset-start for _, start, va, size, _ in Elf(image).loads if start <= offset < start+size)
    library = next((args.native/"jniLibs/arm64-v8a").glob("*.so")).name
    args.output.mkdir(parents=True, exist_ok=True)
    executable = args.output/"cache-probe"
    subprocess.run([str(base/"bin/clang++.exe"), "--target=aarch64-linux-android26", "--sysroot="+str(base/"sysroot"),
        "-Oz", "-static-libstdc++", str(Path(__file__).with_suffix(".cpp")), "-ldl", "-o", str(executable)], check=True)
    adb = [str(args.adb), "-P", str(args.server_port), "-s", args.serial]
    def run(*command):
        return subprocess.run([*adb, *map(str, command)], capture_output=True, text=True, timeout=90)
    remote = "/data/local/tmp/ndkp-qseg-probe-"+uuid.uuid4().hex
    run("shell", "mkdir", remote).check_returncode()
    try:
        run("push", args.apk, remote+"/protected.apk").check_returncode()
        run("push", executable, remote+"/probe").check_returncode()
        run("shell", "chmod", "755", remote+"/probe").check_returncode()
        results = []
        for mode in ("read", "write"):
            result = run("shell", remote+"/probe", remote+"/protected.apk!/lib/arm64-v8a/"+library,
                         symbols["ndkp_qseg_get"], hex(address), mode)
            assert (result.returncode == 0 if mode == "read" else result.returncode == 139), result
            results.append({"mode": mode, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        report = {"resourceBytes": sizes[identity], "crossChunk": sizes[identity] > 65536, "results": results}
        (args.output/"results.json").write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps(report))
    finally:
        run("shell", "rm", "-f", remote+"/probe", remote+"/protected.apk").check_returncode()
        run("shell", "rmdir", remote).check_returncode()


if __name__ == "__main__":
    main()
