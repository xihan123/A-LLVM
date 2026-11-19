"""Check TU-scoped main-only diagnostics; only the no-main SO may run on a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import uuid


DETECTIONS = {
    'idadetect': 'check_debugger_port',
    'timedetect': 'time_check',
    'rootdetect': 'check_root',
    'vmdetect': 'vmprotect_check',
    'bandump': 'ban_dump',
    'hidemaps': 'hide_maps',
    'fakemaps': 'generate_fake_maps_content',
}
STRICT = '-irobf-main-entry-strict'


def flags(options):
    return [part for option in options for part in ('-mllvm', option)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True, help='persist IR, objects, SO, command logs and report.json')
    parser.add_argument('--serial', help='optional Android arm64 device; only runs the no-main SO loader')
    parser.add_argument('--adb', default='adb')
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError('test requires Python assertions; do not use -O')
    here = Path(__file__).resolve().parent
    out = args.work_dir.resolve(); out.mkdir(parents=True, exist_ok=True)
    clang, ndk = args.clang.resolve(), args.ndk.resolve()
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    suffix = '.exe' if os.name == 'nt' else ''
    base = ndk / 'toolchains/llvm/prebuilt' / host
    all_options = ['-irobf-' + name for name in DETECTIONS]
    report = {'schemaVersion': 1, 'scope': 'main-only-options-per-translation-unit', 'validationStatus': 'failed',
              'clang': str(clang), 'clangSha256': hashlib.sha256(clang.read_bytes()).hexdigest(),
              'ndk': str(ndk), 'resourceDirectory': None, 'serial': args.serial,
              'deviceRuntimeValidation': 'unverified', 'commands': [], 'checks': []}

    def run(label, command, success=True, cwd=out):
        command = [str(value) for value in command]
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=180)
        log = out / (label + '.log')
        log.write_text(result.stdout + result.stderr, encoding='utf-8')
        report['commands'].append({'label': label, 'argv': command, 'cwd': str(cwd),
                                   'returncode': result.returncode, 'log': str(log)})
        assert (result.returncode == 0) == success, label + ':\n' + result.stdout + result.stderr
        return result

    def diagnostic(result, options, source):
        lines = [line for line in result.stderr.splitlines() if '[A-LLVM] warning:' in line]
        assert len(lines) == len(options), result.stderr
        for option in options:
            matches = [line for line in lines if ': ' + option + ' skipped:' in line]
            assert len(matches) == 1 and source.as_posix() in matches[0].replace('\\', '/'), result.stderr
            assert 'no defined main in this translation unit (TU scope)' in matches[0], result.stderr

    def ir(label, source, options=(), optimization='-O0', success=True):
        target = out / (label + '.ll'); target.unlink(missing_ok=True)
        result = run(label, common + [optimization, '-S', '-emit-llvm', str(source), '-o', str(target)] + flags(options), success)
        if success:
            return result, target.read_bytes()
        assert STRICT in result.stderr and 'no defined main' in result.stderr and '(TU scope)' in result.stderr, result.stderr
        return result, None

    try:
        version = run('version', [clang, '--version'])
        report['clangVersion'] = version.stdout.strip()
        query = run('resource-directory', [clang, '--print-resource-dir'])
        resource = Path(query.stdout.strip())
        assert resource.is_absolute(), 'Clang did not report an absolute resource directory: ' + query.stdout
        resource = resource.resolve()
        assert resource.is_relative_to((base / 'lib/clang').resolve()) and (resource / 'include').is_dir(), \
            'Clang resource directory must contain include and belong to the supplied NDK: ' + str(resource)
        report['resourceDirectory'] = str(resource)
        common = [str(clang), '--target=aarch64-linux-android26', '--sysroot=' + str(base / 'sysroot'),
                  '-resource-dir=' + str(resource), '-fPIC']
        library, declared, entry = (here / name for name in ('library.c', 'declared-main.c', 'main.c'))
        for optimization in ('-O0', '-O2'):
            for source in (library, entry):
                label = source.stem + optimization
                baseline, plain = ir(label + '-plain', source, optimization=optimization)
                strict, unchanged = ir(label + '-strict-alone', source, [STRICT], optimization)
                assert '[A-LLVM] warning:' not in baseline.stderr + strict.stderr
                assert unchanged == plain, 'strict alone changed IR: ' + label
            result, skipped = ir('library' + optimization + '-all-skipped', library, all_options, optimization)
            diagnostic(result, all_options, library)
            _, plain = ir('library' + optimization + '-comparison', library, optimization=optimization)
            assert skipped == plain, 'skipped detections changed IR'
        report['checks'].append('O0/O2 no-option and strict-alone are identical; skipped detections preserve no-main IR')

        for options in ([option] for option in all_options):
            name = options[0].removeprefix('-irobf-')
            for source in (library, declared):
                result, _ = ir(source.stem + '-' + name, source, options)
                diagnostic(result, options, source)
                rejected, _ = ir(source.stem + '-' + name + '-strict', source, options + [STRICT], success=False)
                diagnostic(rejected, options, source)
            accepted, transformed = ir('main-' + name + '-strict', entry, options + [STRICT])
            assert '[A-LLVM] warning:' not in accepted.stderr
            assert re.search(rb'\bcall void @' + DETECTIONS[name].encode() + rb'\(', transformed), name
        for source in (library, declared):
            result, _ = ir(source.stem + '-combined-strict', source, all_options + [STRICT], success=False)
            diagnostic(result, all_options, source)
        accepted, transformed = ir('main-combined-strict', entry, all_options + [STRICT])
        assert '[A-LLVM] warning:' not in accepted.stderr
        assert all(re.search(rb'\bcall void @' + helper.encode() + rb'\(', transformed) for helper in DETECTIONS.values())
        report['checks'].append('all seven options separately and together: defined main injects; absent/declaration main warns or strict fails')

        multi = out / 'multitu'; multi.mkdir(exist_ok=True)
        for strict in (False, True):
            result = run('multitu-' + ('strict' if strict else 'compatible'),
                         common + ['-O0', '-c', str(entry), str(library)] + flags(all_options + ([STRICT] if strict else [])),
                         success=not strict, cwd=multi)
            diagnostic(result, all_options, library)
            if strict:
                assert STRICT in result.stderr and library.as_posix() in result.stderr.replace('\\', '/'), result.stderr
        report['checks'].append('multi-TU compile diagnoses only the auxiliary TU; a main in another TU does not satisfy strict')

        objects = []
        for mode, options in (('plain', []), ('strict-alone', [STRICT]), ('skipped', all_options)):
            obj = out / ('no-main-' + mode + '.o')
            result = run('no-main-object-' + mode, common + ['-O2', '-c', str(library), '-o', str(obj)] + flags(options))
            diagnostic(result, all_options if mode == 'skipped' else [], library)
            objects.append(obj.read_bytes())
        assert objects[0] == objects[1] == objects[2], 'no-main object changed'
        report['checks'].append('no-main object is byte-identical for plain, strict-alone and all skipped options')

        shared = out / 'libmain_entry.so'
        result = run('no-main-shared', common + ['-O2', '-shared', '--ld-path=' + str(base / ('bin/ld.lld' + suffix)),
                                              str(library), '-o', str(shared)] + flags(all_options))
        diagnostic(result, all_options, library)
        binary = shared.read_bytes()
        assert binary[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 183
        for mode, options in (('plain', []), ('strict-alone', [STRICT])):
            target = out / ('libmain_entry-' + mode + '.so')
            result = run('no-main-shared-' + mode, common + ['-O2', '-shared', '--ld-path=' + str(base / ('bin/ld.lld' + suffix)),
                                                          str(library), '-o', str(target)] + flags(options))
            diagnostic(result, [], library)
            assert target.read_bytes() == binary, 'no-main shared library changed: ' + mode
        report['sharedLibrarySha256'] = hashlib.sha256(binary).hexdigest()
        report['checks'].append('real arm64 no-main SO links and is byte-identical for plain, strict-alone and all skipped options')

        if args.serial:
            loader = out / 'no-main-loader'
            run('loader-build', common + ['-O2', '--ld-path=' + str(base / ('bin/ld.lld' + suffix)),
                                         str(here / 'loader.c'), '-ldl', '-o', str(loader)])
            adb = [args.adb, '-s', args.serial]
            remote = '/data/local/tmp/ndkp-main-entry-' + uuid.uuid4().hex
            run('device-mkdir', adb + ['shell', 'mkdir', remote])
            try:
                run('device-push', adb + ['push', str(shared), str(loader), remote + '/'])
                run('device-chmod', adb + ['shell', 'chmod', '700', remote + '/no-main-loader'])
                result = run('device-no-main-semantics', adb + ['shell', remote + '/no-main-loader', remote + '/libmain_entry.so'])
                assert 'main-entry no-main SO semantics OK' in result.stdout, result.stdout
                report['deviceRuntimeValidation'] = 'passed-no-main-fixture-only'
                report['checks'].append('device dlopen, existing constructor, explicit JNI_OnLoad and ordinary function results preserved')
            finally:
                run('device-clean-files', adb + ['shell', 'rm', '-f', remote + '/no-main-loader', remote + '/libmain_entry.so'])
                run('device-clean-directory', adb + ['shell', 'rmdir', remote])
        report['validationStatus'] = 'passed'
        print('[ok] ' + '; '.join(report['checks']))
        print('[report] ' + str(out / 'report.json'))
    finally:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
