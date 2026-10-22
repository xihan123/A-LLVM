"""编译并在独立设备进程验证生产缓存的引用、LRU、清零与旧接口固定驻留。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ndk', 'adb', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    base = args.ndk / 'toolchains/llvm/prebuilt' / host
    clang = base / ('bin/clang++.exe' if os.name == 'nt' else 'bin/clang++')
    args.output.mkdir(parents=True, exist_ok=True)
    adb = [str(args.adb), '-s', args.serial]
    remote = '/data/local/tmp/qseg-lifetime-' + uuid.uuid4().hex
    def run(command):
        return subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=180, check=True)
    run([*adb, 'shell', 'mkdir', remote])
    results = []
    try:
        for optimization in ('O0', 'O2'):
            target = args.output / ('lifetime-' + optimization)
            command = [clang, '--target=aarch64-linux-android26', '--sysroot=' + str(base / 'sysroot'),
                       '-' + optimization, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-static-libstdc++',
                       Path(__file__).with_suffix('.cpp'), '-ldl', '-lz', '-o', target]
            compiled = run(command)
            (args.output / (optimization + '-compile.log')).write_text(compiled.stdout + compiled.stderr, 'utf-8')
            run([*adb, 'push', target, remote + '/test'])
            run([*adb, 'shell', 'chmod', '755', remote + '/test'])
            result = run([*adb, 'shell', remote + '/test', remote + '/chunks.bin'])
            results.append({'optimization': optimization, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n', 'utf-8')
        print(json.dumps(results))
    finally:
        run([*adb, 'shell', 'rm', '-f', remote + '/test', remote + '/chunks.bin'])
        run([*adb, 'shell', 'rmdir', remote])


if __name__ == '__main__':
    main()
