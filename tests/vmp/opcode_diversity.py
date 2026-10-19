"""Check that LLVM 21 wire semantics cannot be derived from the payload key alone."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def legacy_decode_map(key):
    mask = (1 << 64) - 1
    state = key ^ 0x6d2b79f5aa17c3e9 or 0x9e3779b97f4a7c15
    result = list(range(29))
    for i in range(28, 1, -1):
        state = (state + 0x9e3779b97f4a7c15) & mask
        value = state
        value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & mask
        value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & mask
        value ^= value >> 31
        j = value % i + 1
        result[i], result[j] = result[j], result[i]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    args = parser.parse_args()
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    base = args.ndk / 'toolchains/llvm/prebuilt' / host
    with tempfile.TemporaryDirectory(prefix='vmp-opcodes-') as directory:
        out = Path(directory)
        source = out / 'input.c'
        source.write_text('''
__attribute__((annotate("vmp"), noinline)) int first(int x) {
  return x < 0 ? -x + 7 : x * 3 + 11;
}
__attribute__((annotate("vmp"), noinline)) int second(int x) {
  return x < 0 ? -x + 7 : x * 3 + 11;
}
''')
        common = [str(args.clang), '--target=aarch64-linux-android26',
                  '--sysroot=' + str(base / 'sysroot'),
                  '-resource-dir=' + str(base / 'lib/clang/21'), '-O1',
                  '-S', '-emit-llvm', str(source)]
        mappings = set()
        for iteration in range(2):
            ir = out / f'protected-{iteration}.ll'
            process = subprocess.run(common + ['-o', str(ir), '-mllvm', '-irobf-vmp',
                '-mllvm', '-irobf-vmp-strict', '-mllvm', '-irobf-debug'],
                capture_output=True, text=True, timeout=180)
            assert process.returncode == 0, process.stderr
            rows = re.findall(r'\[VMP_VARIANT\] function=(\S+) key=0x([0-9a-fA-F]+) '
                              r'semantic_to_ordinal=([0-9:,]+)', process.stderr)
            assert {r[0] for r in rows} == {'first', 'second'}, process.stderr
            handlers = re.findall(r'\[VMP_DISPATCH_RANDOMIZE\] clone=\S+ cases=(\d+)', process.stderr)
            assert len(handlers) == 2 and all(0 < int(n) < 28 for n in handlers), process.stderr
            for name, key, mapping in rows:
                mappings.add(mapping)
                encode = dict(tuple(map(int, pair.split(':'))) for pair in mapping.split(','))
                assert sorted(encode) == sorted(encode.values()) == list(range(1, 29))
                legacy = legacy_decode_map(int(key, 16))
                assert all(legacy[encode[semantic]] != semantic for semantic in encode), name
            text = ir.read_text()
            assert text.count('!ndkp.vmp.protected') == 2
            assert 'opcode_dispatch_map' not in text
        assert len(mappings) == 4, 'opcode mappings repeated across methods/builds'
        plain = out / 'plain.ll'
        subprocess.run(common + ['-o', str(plain)], check=True, capture_output=True, timeout=180)
        assert 'ndkp.vmp.protected' not in plain.read_text()
    print('[ok] all 28 opcode semantics differ from key-only decoding; two methods, two builds; opt-in preserved')


if __name__ == '__main__':
    main()
