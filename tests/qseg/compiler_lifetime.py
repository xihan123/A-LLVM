"""核对实际编译器只对无展开契约的 VM 发出借用，对未知异常出口固定驻留。"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cert-file', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = args.output / 'input.cpp'
    source.write_text('extern "C" int externalCall(int);\n'
                      'extern "C" int safe(int x) noexcept { return x * 7 + 9; }\n'
                      'extern "C" int risky(int x) { return externalCall(x); }\n', 'utf-8')
    ir = args.output / 'output.ll'
    command = [str(args.clang.resolve()), '--target=aarch64-linux-android26', '-O1', '-fno-vectorize',
               '-fno-slp-vectorize', '-S', '-emit-llvm', str(source.resolve()), '-o', str(ir.resolve()),
               '-mllvm', '-irobf-vmp', '-mllvm', '-irobf-vmp-strict', '-mllvm', '-irobf-vm_functions=safe;risky',
               '-mllvm', '-irobf-selfcheck', '-mllvm', '-irobf-selfcheck-entry',
               '-mllvm', '-irobf-cse', '-mllvm', '-irobf-cse-hardened',
               '-mllvm', '-irobf-cert-bind', '-mllvm', '-irobf-cert-file=' + str(args.cert_file.resolve()),
               '-mllvm', '-irobf-segmented-data', '-mllvm', '-irobf-segmented-output=' + str((args.output / 'staging').resolve())]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (args.output / 'compiler.log').write_text(result.stdout + result.stderr, 'utf-8'); result.check_returncode()
    text = ir.read_text('utf-8')
    rows = json.loads((args.output / 'staging/manifest.json').read_text('utf-8'))
    modes = {row['name']: row['lifetime'] for row in rows if row['kind'] == 1}
    assert modes == {'safe': 'lease-v1', 'risky': 'pinned-unproven-unwind'}, modes
    report = {}
    for name, mode in modes.items():
        body = re.search(r'^define [^\n]*@' + name + r'\([^\n]*\{\n(.*?)\n}', text, re.M | re.S)[1]
        acquired, released = body.count('@ndkp_qseg_acquire_v1('), body.count('@ndkp_qseg_release_v1(')
        assert acquired == released and acquired > 0
        assert ('@ndkp_qseg_get(' in body) == (mode == 'pinned-unproven-unwind')
        report[name] = {'mode': mode, 'acquireCalls': acquired, 'releaseCalls': released}
    (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
