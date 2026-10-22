"""Build an isolated strings sample: R8, plugin orders, cache restore and zero-selection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
import zipfile


MARKERS = ('java-string-marker-d3d7cf46', 'kotlin-string-marker-53f17942', 'native-string-marker-538bf047')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gradle', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--no-configuration-cache', action='store_true')
    parser.add_argument('--serial', help='Also execute each R8 Release APK under ART without installing an application')
    parser.add_argument('--staging', type=Path, help='Consume a local Maven staging repository instead of a composite build')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.work_dir.resolve()
    if out.exists():
        raise ValueError('Use a new work directory to preserve build evidence')
    shutil.copytree(root / 'dex2c/samples/strings', out,
                    ignore=shutil.ignore_patterns('build', '.gradle', '.kotlin', 'local.properties'))
    settings = out / 'settings.gradle'
    if args.staging:
        text = re.sub(r'^\s*includeBuild\([^\n]+\)\s*$', '', settings.read_text(), flags=re.M)
        repository = args.staging.resolve().as_uri()
        settings.write_text(text.replace('repositories {', "repositories { maven { url = '" + repository + "' };"))
        version = re.search(r"version = '([^']+)'", (root / 'dex2c/build.gradle').read_text())[1]
        build_file = out / 'build.gradle'
        text = build_file.read_text()
        for plugin in ('io.github.xihan123.strings', 'io.github.xihan123.dex2c'):
            text = text.replace("id '" + plugin + "' apply false", "id '" + plugin + "' version '" + version + "' apply false")
        build_file.write_text(text)
    else:
        settings.write_text(settings.read_text().replace("'../..'", repr((root / 'dex2c').as_posix())))
    (out / 'local.properties').write_text('sdk.dir=' + args.sdk.resolve().as_posix() + '\n')
    certificate = out / 'debug.der'
    java_home = Path(os.environ['JAVA_HOME'])
    keytool = java_home / ('bin/keytool.exe' if os.name == 'nt' else 'bin/keytool')
    subprocess.run([str(keytool), '-exportcert', '-keystore', str(Path.home() / '.android/debug.keystore'),
                    '-storepass', 'android', '-alias', 'androiddebugkey', '-file', str(certificate)], check=True, capture_output=True)
    results = []

    def build(label, mode='strings', extra=(), success=True, certificate_required=True, tasks=('assembleRelease',)):
        command = [str(args.gradle.resolve()), '-p', str(out), *tasks, '--console=plain', '--build-cache',
                   '-Pkotlin.internal.collectFUSMetrics=false',
                   '--no-configuration-cache' if args.no_configuration_cache else '--configuration-cache',
                   '-Pprotection.mode=' + mode, '-Pprotection.clang=' + str(args.clang.resolve())]
        if certificate_required:
            command.append('-Pprotection.certificate=' + str(certificate))
        command.extend(extra)
        start = time.monotonic()
        log = out / (label + '.log')
        with log.open('w', encoding='utf-8') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
        text = log.read_text(encoding='utf-8', errors='replace')
        if (result.returncode == 0) != success:
            raise AssertionError(text[-14000:])
        results.append({'phase': label, 'seconds': round(time.monotonic() - start, 3)})
        print('[ok]', label, flush=True)
        return text

    apk = out / 'build/outputs/apk/release/allvm-strings-sample-release.apk'

    def device_smoke(label):
        if not args.serial:
            return
        suffix = '.exe' if os.name == 'nt' else ''
        adb = [str(args.sdk / ('platform-tools/adb' + suffix)), '-s', args.serial]
        target = '/data/local/tmp/strings-r8-' + uuid.uuid4().hex + '.apk'
        def run(*arguments):
            result = subprocess.run([*adb, *map(str, arguments)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            assert result.returncode == 0, result.stdout + result.stderr
            return result.stdout.strip()
        run('push', apk, target)
        try:
            output = run('shell', 'env', 'CLASSPATH=' + target, 'app_process', '-Xcheck:jni',
                         '-Djava.library.path=' + target + '!/lib/arm64-v8a', '/system/bin',
                         'io.github.xihan123.strings.sample.MainActivity')
            assert output == '87', output
            results.append({'phase': label, 'artCheckJni': True, 'output': output})
        finally:
            run('shell', 'rm', '-f', target)

    def inspect(protected, methods):
        with zipfile.ZipFile(apk) as archive:
            libraries = [n for n in archive.namelist() if n.startswith('lib/') and n.endswith('.so')]
            assert len(libraries) == int(protected), libraries
            dex = b''.join(archive.read(n) for n in archive.namelist() if n.endswith('.dex'))
            if protected:
                binary = archive.read(libraries[0])
                for marker in MARKERS:
                    if methods == 'dex2c' and marker != MARKERS[2]:
                        continue
                    assert marker.encode() not in dex, 'DEX plaintext: ' + marker
                    assert marker.encode() not in binary and marker.encode('utf-16-le') not in binary, 'SO plaintext: ' + marker
                generated = out / 'build/intermediates/dex2c/release/generated'
                selection = json.loads((generated / 'selection.json').read_text())
                assert len(selection['methods']) == (0 if methods == 'strings' else 1)
                receipt = json.loads((out / 'build/reports/dex2c/release/apk-verification.json').read_text())
                assert receipt['protectedStrings'] > 0 if methods != 'dex2c' else receipt['protectedStrings'] == 0
                identity = hashlib.sha256((generated / 'classes.jar').read_bytes()).hexdigest()
                return {'apkBytes': apk.stat().st_size, 'soBytes': len(binary), 'classesSha256': identity,
                        'soSha256': hashlib.sha256(binary).hexdigest()}
            return {'apkBytes': apk.stat().st_size}

    build('baseline', 'baseline', certificate_required=False, tasks=('assembleRelease', 'assembleDebug'))
    baseline = inspect(False, 'baseline')
    device_smoke('baseline-art')
    build('strings', tasks=('assembleRelease', 'assembleDebug'))
    standalone = inspect(True, 'strings')
    device_smoke('strings-art')
    with zipfile.ZipFile(out / 'build/outputs/apk/debug/allvm-strings-sample-debug.apk') as archive:
        assert not any(n.endswith('.so') for n in archive.namelist()), 'Debug transformed unexpectedly'
    text = build('up-to-date')
    assert ':compileReleaseDex2cNative UP-TO-DATE' in text
    text = build('configuration-reuse')
    if not args.no_configuration_cache:
        assert 'Reusing configuration cache.' in text
    build('clean', tasks=('clean',))
    text = build('restored')
    assert ':compileReleaseDex2cNative FROM-CACHE' in text
    assert inspect(True, 'strings')['soSha256'] == standalone['soSha256']
    build('combined-strings-first', 'combined')
    combined = inspect(True, 'combined')
    device_smoke('combined-art')
    build('combined-dex2c-first', 'combined', ('-Pprotection.order=dex2c-first',))
    assert inspect(True, 'combined')['classesSha256'] == combined['classesSha256']
    build('dex2c-only', 'dex2c')
    inspect(True, 'dex2c')
    device_smoke('dex2c-art')
    build('zero-without-certificate', extra=('-Pstrings.include=unmatched.package',), certificate_required=False)
    inspect(False, 'strings')
    text = build('missing-certificate', success=False, certificate_required=False)
    assert 'certificateFile must contain the APK signing certificate' in text
    assert not list((out / 'build/intermediates/dex2c/release/native/jniLibs').rglob('*.so'))
    build('full-verification', extra=('-Pprotection.verifyApkSignature=true',))
    inspect(True, 'strings')
    device_smoke('full-verification-art')
    (out / 'results.json').write_text(json.dumps({'baseline': baseline, 'strings': standalone,
                                                'combined': combined, 'builds': results}, indent=2) + '\n')
    print(out / 'results.json')


if __name__ == '__main__':
    main()
