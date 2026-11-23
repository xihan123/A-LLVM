"""Build real zero-pool checkpoints and test their authenticated sibling-TU contexts."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import uuid

from descriptor_test import descriptor_locations
from scoped_test import Commands, digest
from device_test import ROOT, cse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--clang', type=Path)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--serial')
    parser.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    if not args.compile_only and not args.serial:
        parser.error('--serial is required unless --compile-only is used')
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = Commands(out, 'build')
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    ext = '.exe' if os.name == 'nt' else ''
    base = args.ndk.resolve() / 'toolchains/llvm/prebuilt' / host
    clang = args.clang.resolve() if args.clang else base / ('bin/clang' + ext)
    resource = base / 'lib/clang/21'
    common = [clang, '--driver-mode=g++', '--target=aarch64-linux-android29',
              '--sysroot=' + str(base / 'sysroot'), '-resource-dir', resource,
              '-B' + str(base / 'bin'), '-std=c++17', '-fPIC', '-fno-exceptions',
              '-I', ROOT / 'include', '-I', ROOT / 'runtime']
    flags = ['-mllvm', '-irobf-cse', '-mllvm', '-irobf-cse-hardened']
    source = ROOT / 'tests/cse-hardened'
    commands.run(*common, '-O2', '-Wall', '-Wextra', '-Werror', '-fno-lto', '-c',
                 ROOT / 'runtime/ndkp_cse_runtime.cpp', '-o', out / 'runtime.o')
    commands.run(*common, '-O2', '-c', source / 'image_identity.cpp', '-o', out / 'identity.o')
    for loader in ('recheck_loader', 'image_identity_loader'):
        commands.run(*common, '-O2', '-static-libstdc++', source / (loader + '.cpp'),
                     '-ldl', '-Wl,--export-dynamic', '-o', out / loader)
    public_source = out / 'public-counter.cpp'
    public_source.write_text('extern "C" __attribute__((annotate("api-data"))) int public_counter = 42;\n', encoding='utf-8')
    public_ir = out / 'public-counter.ll'
    commands.run(*common, '-O2', *flags, '-S', '-emit-llvm', public_source, '-o', public_ir)
    public_text = public_ir.read_text(encoding='utf-8')
    assert re.search(r'^@public_counter = [^\n]*global i32 42', public_text, re.M)
    assert 'ptr @public_counter' in public_text
    public_object = out / 'public-counter.o'
    commands.run(*common, '-O2', '-Xclang', '-disable-llvm-passes', '-c', public_ir, '-o', public_object)
    consumer = out / 'public-consumer.cpp'
    consumer.write_text('extern "C" int public_counter;\nextern "C" int read_public_counter() { return public_counter; }\n', encoding='utf-8')
    public_library = out / 'public-counter.so'
    commands.run(*common, '-O2', '-shared', '-Wl,--no-undefined', public_object, consumer, '-o', public_library)
    symbols = commands.run(base / ('bin/llvm-nm' + ext), '--dynamic', '--defined-only', public_library).stdout
    assert re.search(r'\bD public_counter$', symbols, re.M)
    assert re.search(r'\bT read_public_counter$', symbols, re.M)
    callback = out / 'constructor-callback.cpp'
    callback.write_text('#include <unistd.h>\nextern "C" int image_constructor_checkpoint(int);\n'
                        '__attribute__((constructor)) static void recheck() {\n'
                        '  for (unsigned i = 0; i < 8; ++i) if (image_constructor_checkpoint(5) != 22) _exit(20);\n}\n', encoding='utf-8')
    callback_library = out / 'constructor-callback.so'
    commands.run(*common, '-O2', '-shared', '-static-libstdc++', callback, '-o', callback_library)
    shared_source = out / 'shared-annotation.cpp'
    shared_source.write_text('#include "ndkp.h"\nextern "C" NDKP_CSE_RECHECK '
                             'const char* shared_annotation() { return "ndkp.cse_recheck"; }\n', encoding='utf-8')
    shared_ir = out / 'shared-annotation.ll'
    commands.run(*common, '-O2', *flags, '-S', '-emit-llvm', shared_source, '-o', shared_ir)
    shared_text = shared_ir.read_text(encoding='utf-8')
    assert 'section ".ndkp.cse"' in shared_text and 'call void @ndkp_cse_module_recheck()' in shared_text
    assert not re.search(r'^@\.str[^\n]*constant[^\n]*c"', shared_text, re.M)
    assert 'ret ptr @dec' in shared_text and 'ndkp_decrypt_string_' in shared_text
    # Force one underlying global to serve both metadata and business, unlike
    # Clang's separately sectioned annotation copy of the same string content.
    shared_input = out / 'shared-global-input.ll'
    shared_input.write_text('@.ann = private constant [17 x i8] c"ndkp.cse_recheck\\00"\n'
                            '@llvm.global.annotations = appending global [1 x {ptr, ptr, ptr, i32, ptr}] '
                            '[{ptr, ptr, ptr, i32, ptr} {ptr @shared_global, ptr @.ann, ptr null, i32 1, ptr null}], section "llvm.metadata"\n'
                            'define ptr @shared_global() {\n ret ptr @.ann\n}\n', encoding='utf-8')
    shared_global_ir = out / 'shared-global.ll'
    commands.run(*common, '-O2', *flags, '-S', '-emit-llvm', shared_input, '-o', shared_global_ir)
    shared_global = shared_global_ir.read_text(encoding='utf-8')
    assert 'c"ndkp.cse_recheck\\00"' not in shared_global
    assert 'ret ptr @dec' in shared_global and 'section ".ndkp.cse"' in shared_global
    plain_ir = out / 'plain.ll'
    commands.run(*common, '-O2', '-S', '-emit-llvm', source / 'image_fixture.cpp', '-o', plain_ir)
    assert 'ndkp_cse_image_recheck' not in plain_ir.read_text(encoding='utf-8')
    cases = []
    for opt in ('O0', 'O2'):
        for label, fixture, extra in (('zero', 'image_fixture.cpp', []),
                                      ('pool', 'descriptor_fixture.cpp', ['-DNDKP_TEST_NO_RECHECK', '-Dcheckpoint=pool_checkpoint'])):
            ir = out / (opt + '-' + label + '.ll')
            commands.run(*common, '-' + opt, *flags, *extra, '-S', '-emit-llvm', source / fixture, '-o', ir)
            text = ir.read_text(encoding='utf-8')
            if label == 'zero':
                assert '.ndkp.cse' not in text and 'ndkp_cse_v1_payload' not in text
                assert re.search(r'define private void @ndkp_cse_image_recheck\(\)', text)
                assert 'i32 103, ptr @ndkp_cse_image_recheck' in text
                assert 'ndkp_cse_recheck_image_v1(ptr @ndkp_cse_image_recheck)' in text
                assert 'call void @ndkp_cse_image_recheck()' in text
                # Final APK verifier consumes the actual emitted IR, not a synthetic model.
                from verify_dex2c_apk import recheck_ir_guard
                assert recheck_ir_guard(text, 'checkpoint', False) == 'ndkp_cse_image_recheck'
                assert recheck_ir_guard(text, 'image_unused_gate', False) == 'ndkp_cse_image_recheck'
                for caller, callee in (('image_relay_inner', 'image_unused_gate'),
                                       ('image_relay_outer', 'image_relay_inner'),
                                       ('image_unchecked_caller', 'image_relay_outer')):
                    body = re.search(r'define [^\n]*@' + caller + r'\(.*?^}', text, re.M | re.S)
                    assert body and '@' + callee + '(' in body[0], (opt, caller, callee)
            else:
                assert re.search(r'define private void @ndkp_cse_module_register\(\)', text)
                assert 'i32 102, ptr @ndkp_cse_module_register' in text
                guard = re.search(r'define private void @ndkp_cse_module_register\(\).*?^}', text, re.M | re.S)
                assert guard and guard[0].count('load volatile') == 5
            # Parsing and codegen run LLVM verification, and use this exact inspected IR.
            commands.run(*common, '-' + opt, '-Xclang', '-disable-llvm-passes', '-c', ir,
                         '-o', out / (opt + '-' + label + '.o'))
        link = [*common, '-shared', '-static-libstdc++', '-Wl,--no-undefined,--pack-dyn-relocs=none',
                out / (opt + '-zero.o'), out / 'identity.o', out / 'runtime.o']
        linked = out / (opt + '-linked.so')
        commands.run(*link, out / (opt + '-pool.o'), '-ldl', '-o', linked)
        sealed = out / (opt + '.so')
        sealed.write_bytes(cse.process(linked.read_bytes()))
        cse.process(sealed.read_bytes(), True)
        stripped = out / (opt + '-stripped.so')
        shutil.copyfile(sealed, stripped)
        commands.run(base / ('bin/llvm-strip' + ext), '--strip-all', stripped)
        cse.process(stripped.read_bytes(), True)
        missing = out / (opt + '-missing.so')
        commands.run(*link, '-ldl', '-o', missing)
        try:
            cse.Elf(missing.read_bytes()).payloads()
        except ValueError as error:
            assert str(error) == 'no CSE v1 payloads'
        else:
            raise AssertionError('missing-context fixture unexpectedly contains a payload')
        cases.extend([(opt, sealed, 0), (opt + '-stripped', stripped, 0), (opt + '-missing', missing, 127)])
    report = {'compiler': digest(clang), 'ndk': str(args.ndk.resolve()),
              'scope': 'LLVM21 non-segmented; runtime statically linked into each DSO',
              'publicGlobal': {'symbol': 'public_counter', 'ir': digest(public_ir), 'library': digest(public_library),
                               'crossTranslationUnitLink': 'passed'},
              'constructorConcurrency': {'callbackLibrary': digest(callback_library), 'deviceRuntime': 'not-run'},
              'artifacts': [{'label': name, **digest(path), 'expected': expected} for name, path, expected in cases],
              'deviceRuntime': 'not-run'}
    if not args.compile_only:
        device = Commands(out, 'device')
        remote = '/data/local/tmp/ndkp-image-recheck-' + uuid.uuid4().hex
        adb = ['adb', '-s', args.serial]
        device.run(*adb, 'shell', 'mkdir', remote)
        results = []
        def run_case(label, loader, arguments, expected):
            result = device.run(*adb, 'shell', 'timeout', '30', remote + '/' + loader,
                                *arguments, check=False)
            rc = result.returncode
            results.append({'label': label, 'expected': expected, 'actual': rc})
            assert rc == expected, (label, expected, rc, result.stdout, result.stderr)
        for loader in ('recheck_loader', 'image_identity_loader'):
            device.run(*adb, 'push', out / loader, remote + '/' + loader)
            device.run(*adb, 'shell', 'chmod', '700', remote + '/' + loader)
        for name, path, expected in cases:
            device.run(*adb, 'push', path, remote + '/test.so')
            run_case(name, 'recheck_loader', [remote + '/test.so', 'clean', '0', '3', 'xor'], expected)
        sealed = out / 'O2.so'
        data = sealed.read_bytes()
        image, table, _, _, module, pointers = descriptor_locations(data)
        def virtual(offset):
            return next(va + offset - start for _, start, va, size, _ in image.loads if start <= offset < start + size)
        payload, total = image.payloads()[0]
        sentinel = list(cse.records(data[payload:payload + total]))[-1][1]
        attacks = [('regions', virtual(table), 5), ('permissions', virtual(table), 5),
                   ('cache-hash', pointers[1][1] + 4, 3), ('cache-inputs', pointers[1][1] + 36, 3),
                   ('sentinel', virtual(payload + sentinel + 32), 3)]
        attacks += [('descriptor-' + str(offset), virtual(module + offset), 1) for offset in (0, 8, 16, 24, 28)]
        device.run(*adb, 'push', sealed, remote + '/test.so')
        for name, address, protection in attacks:
            run_case('warm-' + name, 'recheck_loader', [remote + '/test.so', 'warm', f'{address:x}', str(protection),
                                                       'permissions' if name == 'permissions' else 'xor'], 127)
        device.run(*adb, 'push', out / 'O0.so', remote + '/other.so')
        for action, expected in (('two-dsos', 0), ('foreign', 127), ('foreign-mutation', 0)):
            run_case(action, 'image_identity_loader', [remote + '/test.so', remote + '/other.so', action], expected)
        device.run(*adb, 'push', callback_library, remote + '/callback.so')
        run_case('constructor-concurrency', 'image_identity_loader',
                 [remote + '/test.so', remote + '/callback.so', 'constructor-concurrency'], 0)
        report['constructorConcurrency']['deviceRuntime'] = 'passed'
        report['deviceRuntime'] = 'passed'
        report['results'] = results
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'scope': report['scope'], 'deviceRuntime': report['deviceRuntime'], 'artifacts': len(cases)}))


if __name__ == '__main__':
    main()
