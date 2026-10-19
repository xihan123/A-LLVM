"""Bootstrap origin, split, replacement and reentry tests using disposable paths on a rooted device.

Uses a fresh /data/app/ndkp-verify-* directory to exercise Android installation
layouts without replacing or installing any user package. Requires su access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def run(command, check=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
    if check and result.returncode:
        raise RuntimeError(f'{command[0]}: {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'java-home', 'ndk', 'fixtures', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    native = args.fixtures.resolve() / 'native'
    base = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64'
    java = args.java_home / 'bin/java.exe'
    flags = [base / 'bin/clang++.exe', '--target=aarch64-linux-android26', '--sysroot=' + str(base / 'sysroot'),
             '-std=c++17', '-Oz', '-fPIC', '-fno-lto', '-fvisibility=hidden', '-fno-exceptions', '-static-libstdc++',
             '-I' + str(ROOT / 'runtime'), '-I' + str(out), '-Wl,--no-undefined', '-Wl,-z,max-page-size=16384']
    objects = sorted(p for p in native.glob('apkverify-*.o') if p.name != 'apkverify-ndkp_apkverify.cpp.o')
    if len(objects) != 23:
        raise ValueError('build a verified native fixture first')
    for label, store in (('module', 'test.jks'), ('host', 'wrong.jks'), ('reenter', 'test.jks')):
        cert = out / (label + '.der')
        run([java.with_name('keytool.exe'), '-exportcert', '-keystore', args.fixtures / store,
             '-storepass', 'android', '-alias', 'test', '-file', cert])
        pin = hashlib.sha256(cert.read_bytes()).digest()
        (out / 'apkverify_policy.h').write_text('#include <cstdint>\nstatic const uint8_t ndkp_expected_certificate[32]={' + ','.join(map(str, pin)) + '};\n')
        run([*flags, '-shared', *(['-DTEST_REENTER', '-Wl,-Bsymbolic'] if label == 'reenter' else []),
             ROOT / 'runtime/ndkp_apkverify.cpp', ROOT / 'tests/apkverify/runtime_probe.cpp', *objects,
             '-lz', '-ldl', '-o', out / (label + '.so')])
    run([*flags, ROOT / 'tests/apkverify/runtime_driver.cpp', '-ldl', '-o', out / 'driver'])
    tools = args.sdk / 'build-tools/37.0.0'

    def apk(label, library=None, signer='test.jks', compressed=False):
        raw, aligned, signed = (out / (label + suffix) for suffix in ('-raw.apk', '-aligned.apk', '.apk'))
        with zipfile.ZipFile(raw, 'w') as z:
            z.writestr('assets/test', b'disposable origin test')
            if library:
                z.write(out / (library + '.so'), 'lib/arm64-v8a/libcheck.so',
                        compress_type=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED)
        run([tools / 'zipalign.exe', '-P', '16', '-f', '4', raw, aligned])
        run([java, '-jar', tools / 'lib/apksigner.jar', 'sign', '--ks', args.fixtures / signer,
             '--ks-key-alias', 'test', '--ks-pass', 'pass:android', '--min-sdk-version', '26', '--out', signed, aligned])
        return signed

    files = {'module.apk': apk('module', 'module'), 'compressed.apk': apk('compressed', 'module', compressed=True),
             'host.apk': apk('host', 'host', 'wrong.jks'), 'base.apk': apk('base'),
             'bad.apk': apk('bad', signer='wrong.jks'), 'reenter.apk': apk('reenter', 'reenter'),
             'module.so': out / 'module.so', 'driver': out / 'driver'}
    adb = [args.sdk / 'platform-tools/adb.exe', '-s', args.serial]
    def shell(*command, root=False, check=True):
        text = shlex.join(map(str, command))
        return run([*adb, 'shell', *(['su', '-c'] if root else []), text], check=check)
    if 'uid=0' not in shell('id', root=True).stdout:
        raise RuntimeError('rooted test device required')
    token = uuid.uuid4().hex
    remote = '/data/local/tmp/ndkp-verify-' + token
    installed = '/data/app/ndkp-verify-' + token
    results = []
    try:
        shell('mkdir', remote)
        shell('mkdir', '-p', installed + '/lib/arm64', root=True)
        for name, path in files.items():
            run([*adb, 'push', path, remote + '/' + name])
        shell('chmod', '755', remote + '/driver')

        def copy(source, destination):
            shell('cp', remote + '/' + source, installed + '/' + destination, root=True)
        def probe(label, path, expected=0, *extra):
            result = shell(remote + '/driver', path, *extra, root=True, check=False)
            if result.returncode != expected or (result.stdout.strip() == 'verified') != (expected == 0):
                raise AssertionError((label, expected, result.returncode, result.stdout, result.stderr))
            results.append({'case': label, 'exitCode': result.returncode})
            print('[ok]', label, flush=True)
        direct = '!/lib/arm64-v8a/libcheck.so'
        probe('standalone-concurrent', remote + '/module.apk' + direct)
        probe('different-host-certificate', remote + '/module.apk' + direct, 0, 'host', remote + '/host.apk' + direct)
        probe('initialization-reentry', remote + '/reenter.apk' + direct, 127)
        copy('module.apk', 'base.apk')
        probe('base-direct', installed + '/base.apk' + direct)
        probe('split-added-after-verification', installed + '/base.apk' + direct, 127,
              'add', installed + '/base.apk', installed + '/split_added.apk')
        shell('rm', installed + '/split_added.apk', root=True)
        copy('base.apk', 'base.apk'); copy('module.apk', 'split_config.arm64.apk')
        probe('split-direct', installed + '/split_config.arm64.apk' + direct)
        copy('bad.apk', 'base.apk')
        probe('wrong-base-signer', installed + '/split_config.arm64.apk' + direct, 127)
        copy('base.apk', 'base.apk'); copy('bad.apk', 'split_extra.apk')
        probe('wrong-sibling-signer', installed + '/split_config.arm64.apk' + direct, 127)
        shell('rm', installed + '/split_extra.apk', root=True)
        shell('rm', installed + '/base.apk', root=True)
        probe('missing-base', installed + '/split_config.arm64.apk' + direct, 127)
        copy('base.apk', 'base.apk'); copy('module.so', 'lib/arm64/libcheck.so')
        probe('split-extracted-stored', installed + '/lib/arm64/libcheck.so')
        copy('compressed.apk', 'split_config.arm64.apk')
        probe('split-extracted-deflate', installed + '/lib/arm64/libcheck.so')
        probe('extracted-file-modified-after-verification', installed + '/lib/arm64/libcheck.so', 127,
              'change', installed + '/lib/arm64/libcheck.so')
        probe('extracted-file-substitution', installed + '/lib/arm64/libcheck.so', 127)
        copy('module.so', 'lib/arm64/libcheck.so')
        copy('bad.apk', 'replacement.bin')
        probe('base-file-replacement', installed + '/lib/arm64/libcheck.so', 127,
              'replace', installed + '/replacement.bin', installed + '/base.apk')
        shell('rm', installed + '/split_config.arm64.apk', root=True)
        copy('compressed.apk', 'base.apk')
        probe('base-extracted-deflate', installed + '/lib/arm64/libcheck.so')
    finally:
        # Only these two fresh UUID paths are owned by this test. Never remove /data/app itself.
        assert installed.startswith('/data/app/ndkp-verify-') and installed.endswith(token)
        shell('rm', '-r', installed, root=True, check=False)
        shell('rm', '-r', remote, check=False)
        (out / 'results.json').write_text(json.dumps({'serial': args.serial, 'results': results}, indent=2) + '\n')


if __name__ == '__main__':
    main()
