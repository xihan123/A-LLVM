"""在指定 arm64 设备验证 release/debug 自校验成功及篡改终止；只创建临时原生程序。"""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import uuid


def run(*args):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=60)


def tamper(data):
    result = bytearray(data)
    shoff = struct.unpack_from("<Q", data, 40)[0]
    size, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<II样例应用样例应用II样例应用", data, shoff + i * size) for i in range(count)]
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        for pos in range(section[4], section[4] + section[5], section[9]):
            name, _, _, index, address, length = struct.unpack_from("<IBBH样例应用", data, pos)
            if names[name:names.index(b"\0", name)].startswith(b"gv_code_seg_guarded") and length:
                segment = sections[index]
                offset = segment[4] + address - segment[3]
                result[offset] ^= 1
                return result
    raise RuntimeError("protected bytecode symbol missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    ext = ".exe" if os.name == "nt" else ""
    clang = args.ndk / "toolchains/llvm/prebuilt" / args.host / ("bin/clang" + ext)
    remote = "/data/local/tmp/ndkp-fingerprint-" + uuid.uuid4().hex
    def checked(*parts):
        result = run(*parts)
        if result.returncode:
            raise RuntimeError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return result
    with tempfile.TemporaryDirectory(prefix="ndkp-fingerprint-") as folder:
        out = Path(folder)
        source = out / "check.c"
        source.write_text('#include <stdio.h>\nint guarded(int x) { return x*7+5; }\n'
                          'int main(void) { int ok=guarded(7)==54; puts(ok?"OK":"BAD"); return !ok; }\n')
        try:
            for debug in (False, True):
                flags = ["--target=aarch64-linux-android26", "-O2", "-mllvm", "-irobf-vmp",
                         "-mllvm", "-irobf-vm_functions=guarded", "-mllvm", "-irobf-selfcheck"]
                if debug:
                    flags += ["-mllvm", "-irobf-debug"]
                checked(clang, *flags, "-c", source, "-o", out / "check.o")
                checked(clang, "--target=aarch64-linux-android26", "--driver-mode=g++", "-static-libstdc++",
                        out / "check.o", "-o", out / "check")
                clean = (out / "check").read_bytes()
                for modified in (False, True):
                    (out / "test").write_bytes(tamper(clean) if modified else clean)
                    checked("adb", "-s", args.serial, "push", out / "test", remote)
                    checked("adb", "-s", args.serial, "shell", "chmod", "700", remote)
                    result = run("adb", "-s", args.serial, "shell", "timeout", "10", remote)
                    output = result.stdout + result.stderr
                    if modified:
                        assert result.returncode == 137, (debug, result.returncode, output)
                        assert (b"A-Protector" in output) == debug, output
                        assert (b"Protection v1.2.0" in output) == debug, output
                    else:
                        assert result.returncode == 0 and b"OK" in output, output
                    print(f"[ok] debug={debug} tampered={modified} exit={result.returncode}", flush=True)
        finally:
            checked("adb", "-s", args.serial, "shell", "rm", "-f", remote)


if __name__ == "__main__":
    main()
