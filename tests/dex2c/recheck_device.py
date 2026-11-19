"""Warm generated JNI checkpoints after safe in-process RX/permission mutation (stdlib only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from seal_cse import Elf
from verify_dex2c_apk import check_integrity_recheck


DRIVER = r'''package sample;
public final class RecheckDriver {
    private static native String mutate(String library, long address, int expected, int action);
    private static void checkpoint(String target) {
        String result = target.equals("initialize") ? Run.initialize(" warm ") : Run.commit("warm");
        String expected = target.equals("initialize") ? "initialized:warm" : "committed:warm";
        if (!result.equals(expected)) throw new AssertionError(result);
    }
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        checkpoint("initialize"); checkpoint("commit");
        if (Run.hot(7) != 22) throw new AssertionError("warm hot");
        checkpoint("initialize"); checkpoint("commit");
        System.out.println("warm-before=initialize,commit,hot:ok"); System.out.flush();
        int action = Integer.parseInt(args[4]);
        if (action != 0) {
            System.out.println(mutate(args[1], Long.parseLong(args[2], 16), Integer.parseInt(args[3]), action));
            System.out.flush();
        }
        if (Run.hot(7) != 22) throw new AssertionError("mutated hot");
        System.out.println("hot-after=22"); System.out.flush();
        String target = args[5];
        if (!target.equals("hot")) {
            System.out.println("checkpoint-next=" + target); System.out.flush();
            checkpoint(target);
            System.out.println("checkpoint-after=" + target + ":ok"); System.out.flush();
        }
        if (action == 0) {
            java.util.concurrent.atomic.AtomicReference<Throwable> failure = new java.util.concurrent.atomic.AtomicReference<>();
            Thread[] workers = new Thread[4];
            for (int i = 0; i < workers.length; ++i) {
                workers[i] = new Thread(() -> {
                    try { for (int n = 0; n < 4; ++n) { checkpoint("initialize"); checkpoint("commit"); } }
                    catch (Throwable error) { failure.compareAndSet(null, error); }
                }); workers[i].start();
            }
            for (Thread worker : workers) worker.join();
            if (failure.get() != null) throw new AssertionError(failure.get());
            System.out.println("clean-concurrent=ok");
        }
        System.out.println("completed=" + target); System.out.flush();
    }
}
'''


HELPER = r'''#include <jni.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Only mutate the caller's disposable fixture SO, at host-verified unused RX padding.
struct Target { const char* name; uintptr_t relative, address; unsigned matches; };
static int locate(dl_phdr_info* image, size_t, void* opaque) {
  auto& target = *static_cast<Target*>(opaque);
  const char* slash = std::strrchr(image->dlpi_name, '/');
  if (std::strcmp(slash ? slash + 1 : image->dlpi_name, target.name)) return 0;
  for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
    const auto& p = image->dlpi_phdr[i];
    if (p.p_type == PT_LOAD && p.p_flags == (PF_R | PF_X) &&
        target.relative >= p.p_vaddr && target.relative - p.p_vaddr < p.p_filesz) {
      target.address = image->dlpi_addr + target.relative; ++target.matches;
    }
  }
  return 0;
}
static jstring reject(JNIEnv* env, const char* reason) {
  jclass cls = env->FindClass("java/lang/IllegalStateException");
  if (cls) { env->ThrowNew(cls, reason); env->DeleteLocalRef(cls); }
  return nullptr;
}
extern "C" JNIEXPORT jstring JNICALL Java_sample_RecheckDriver_mutate(
    JNIEnv* env, jclass, jstring name, jlong relative, jint expected, jint action) {
  if (!name || relative < 0 || expected < 0 || expected > 255 || (action != 1 && action != 2))
    return reject(env, "invalid mutation arguments");
  const char* text = env->GetStringUTFChars(name, nullptr); if (!text) return nullptr;
  Target target{text, uintptr_t(relative), 0, 0}; dl_iterate_phdr(locate, &target);
  env->ReleaseStringUTFChars(name, text);
  if (target.matches != 1) return reject(env, "fixture RX mapping not unique");
  auto* byte = reinterpret_cast<volatile unsigned char*>(target.address);
  if (*byte != expected) return reject(env, "mapped padding differs from final SO");
  long pageSize = sysconf(_SC_PAGESIZE);
  if (pageSize <= 0 || (pageSize & (pageSize - 1))) return reject(env, "invalid page size");
  uintptr_t page = target.address & ~(uintptr_t(pageSize) - 1);
  if (mprotect(reinterpret_cast<void*>(page), size_t(pageSize), PROT_READ | PROT_WRITE | PROT_EXEC))
    return reject(env, "mprotect RWX failed");
  if (action == 1) {
    *byte ^= 1;
    __builtin___clear_cache(reinterpret_cast<char*>(page), reinterpret_cast<char*>(page + pageSize));
    if (mprotect(reinterpret_cast<void*>(page), size_t(pageSize), PROT_READ | PROT_EXEC))
      return reject(env, "mprotect RX restore failed");
  }
  char permissions[5] = {}; FILE* maps = std::fopen("/proc/self/maps", "re");
  if (!maps) return reject(env, "maps read failed");
  char line[4096];
  while (std::fgets(line, sizeof line, maps)) {
    unsigned long long start, stop; char flags[5] = {};
    if (std::sscanf(line, "%llx-%llx %4s", &start, &stop, flags) == 3 &&
        target.address >= start && target.address < stop) { std::memcpy(permissions, flags, 5); break; }
  }
  std::fclose(maps);
  if (permissions[0] != 'r' || permissions[2] != 'x' || permissions[1] != (action == 1 ? '-' : 'w'))
    return reject(env, "live permissions differ from mutation");
  char evidence[256];
  std::snprintf(evidence, sizeof evidence,
      "mutation=%s relative=0x%llx before=%u after=%u permissions=%s pageSize=%ld",
      action == 1 ? "rx" : "permissions", static_cast<unsigned long long>(relative),
      unsigned(expected), unsigned(*byte), permissions, pageSize);
  return env->NewStringUTF(evidence);
}
'''


def elf_sections(data):
    Elf(data)
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count = struct.unpack_from('<HH', data, 58)
    if size != 64 or not 0 < count < 65536 or offset + size * count > len(data):
        raise ValueError('fixture needs a valid ELF section table for safe RX padding selection')
    return [struct.unpack_from('<IIQQQQIIQQ', data, offset + size * index) for index in range(count)]


def select_anchor(data):
    """Only mutate padding outside all allocated sections, inside a measured RX segment."""
    elf, sections = Elf(data), elf_sections(data)
    padding = (bytes(4), bytes.fromhex('1f2003d5'), bytes.fromhex('000020d4'))

    def candidate(start, stop, reason):
        start = (start + 3) & ~3
        for va, length, offset in elf.executable:
            end = min(stop, va + length)
            if va <= start and start + 4 <= end:
                pos = offset + start - va
                if data[pos:pos + 4] in padding:
                    return {'relativeAddress': start, 'fileOffset': pos, 'expectedByte': data[pos],
                            'originalHex': data[pos:pos + 4].hex(), 'reason': reason}
        return None

    for va, length, _ in elf.executable:
        allocated = sorted((max(va, row[3]), min(va + length, row[3] + row[5])) for row in sections
                           if row[2] & 2 and row[3] < va + length and row[3] + row[5] > va)
        if not allocated:
            continue
        cursor = allocated[0][1]
        for start, stop in allocated[1:]:
            found = candidate(cursor, start, 'RX gap between allocated ELF sections')
            if found:
                return found
            cursor = max(cursor, stop)
    raise ValueError('no proven unused RX padding found; do not mutate an arbitrary instruction')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'java', 'fixtures', 'ndk'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--clang', type=Path)
    parser.add_argument('--serial')
    parser.add_argument('--server-port', type=int, default=5037)
    parser.add_argument('--build-tools', default='37.0.0')
    parser.add_argument('--platform', default='android-37.0')
    parser.add_argument('--work-dir', type=Path)
    parser.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    if not args.compile_only and not args.serial:
        parser.error('--serial is required unless --compile-only is used')
    out = args.work_dir or ROOT / 'work/m2-integrity' / ('recheck-device-' + uuid.uuid4().hex)
    out.mkdir(parents=True, exist_ok=True)
    report = {'scope': 'generated-jni-disposable-fixture', 'status': 'running', 'commands': [], 'cases': []}

    def invoke(label, command, check=True, timeout=300):
        values = [str(value) for value in command]
        result = subprocess.run(values, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        (out / (label + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        report['commands'].append({'label': label, 'arguments': values, 'exitCode': result.returncode})
        if check and result.returncode:
            raise RuntimeError(label + ' failed: ' + result.stdout[-2000:] + result.stderr[-2000:])
        return result

    try:
        native, generated = args.fixtures / 'native', args.fixtures / 'generated'
        receipt = json.loads((native / 'protection.json').read_bytes())
        selection = json.loads((generated / 'selection.json').read_bytes())
        check_integrity_recheck(receipt, selection, native)
        required = {'sample/Run.initialize(Ljava/lang/String;)Ljava/lang/String;': 'vmp',
                    'sample/Run.commit(Ljava/lang/String;)Ljava/lang/String;': 'native-cse'}
        for method, protection in required.items():
            if not any(row['method'] == method and row['protection'] == protection and row.get('integrityRecheck') is True
                       for row in selection['methods']):
                raise ValueError('use prepareDeviceFixtures -Pdex2c.integrityRecheck=true: ' + method)
        soname = 'lib' + selection['library'] + '.so'
        protected = args.fixtures / 'protected.apk'
        with zipfile.ZipFile(protected) as apk:
            binary = apk.read('lib/arm64-v8a/' + soname)
            if hashlib.sha256(binary).hexdigest() != receipt['librarySha256']:
                raise ValueError('protected.apk differs from fixture SO; run tests/dex2c/device.py first')
            if receipt['segmentedData'] and hashlib.sha256(apk.read('assets/' + selection['library'] + '.qseg')).hexdigest() != receipt['containerSha256']:
                raise ValueError('protected.apk QSEG differs')
        anchor = select_anchor(binary)
        report.update(anchor=anchor, segmentedData=receipt['segmentedData'], librarySha256=receipt['librarySha256'],
                      apkSha256=hashlib.sha256(protected.read_bytes()).hexdigest(),
                      selectionSha256=hashlib.sha256((generated / 'selection.json').read_bytes()).hexdigest())
        suffix = '.exe' if os.name == 'nt' else ''
        base = args.ndk / ('toolchains/llvm/prebuilt/' + ('windows-x86_64' if os.name == 'nt' else 'linux-x86_64'))
        clang = args.clang or base / ('bin/clang' + suffix)
        resource = Path(invoke('resource-dir', [clang, '--print-resource-dir']).stdout.strip())
        if not resource.is_absolute() or not (resource / 'include').is_dir():
            raise ValueError('invalid compiler resource directory')
        source, helper = out / 'RecheckDriver.java', out / 'mutation.cpp'
        source.write_text(DRIVER, encoding='utf-8'); helper.write_text(HELPER, encoding='utf-8')
        library = out / 'librecheck_mutation.so'
        invoke('helper', [clang, '--driver-mode=g++', '--target=aarch64-linux-android26', '--sysroot=' + str(base / 'sysroot'),
                         '-resource-dir=' + str(resource), '--ld-path=' + str(base / ('bin/ld.lld' + suffix)),
                         '-std=c++17', '-O2', '-fPIC', '-fno-exceptions', '-fno-rtti', '-fvisibility=hidden', '-static-libstdc++',
                         '-Wall', '-Wextra', '-Werror', '-shared', helper, '-ldl', '-o', library])
        classes = out / 'classes'; classes.mkdir(exist_ok=True)
        inputs = json.loads((args.fixtures / 'inputs.json').read_bytes())
        classpath = os.pathsep.join([str(generated / 'classes.jar'), *inputs['common']])
        invoke('javac', [args.java.with_name('javac' + suffix), '-classpath', classpath, '-d', classes, source])
        tools = args.sdk / 'build-tools' / args.build_tools
        dex = out / 'driver.zip'; dex.unlink(missing_ok=True)
        invoke('d8', [args.java, '-cp', tools / 'lib/d8.jar', 'com.android.tools.r8.D8', '--min-api', '26',
                      '--lib', args.sdk / 'platforms' / args.platform / 'android.jar', '--classpath', generated / 'classes.jar',
                      '--output', dex, classes / 'sample/RecheckDriver.class'])
        if args.compile_only:
            report['status'] = 'compile-only'; return
        adb = args.sdk / 'platform-tools' / ('adb' + suffix)
        device = [adb, '-P', str(args.server_port), '-s', args.serial]
        remote = '/data/local/tmp/dex2c-recheck-' + uuid.uuid4().hex
        report.update(serial=args.serial, sdk=invoke('sdk', [*device, 'shell', 'getprop', 'ro.build.version.sdk']).stdout.strip(),
                      pageSize=invoke('pagesize', [*device, 'shell', 'getconf', 'PAGESIZE']).stdout.strip())
        invoke('mkdir', [*device, 'shell', 'mkdir', remote]); pushed = []
        try:
            for file in (protected, dex, library):
                target = remote + '/' + file.name
                invoke('push-' + file.stem, [*device, 'push', file, target]); pushed.append(target)
            for action, targets in ((0, ('initialize', 'commit')), (1, ('hot', 'initialize', 'commit')), (2, ('hot', 'initialize', 'commit'))):
                for target in targets:
                    label = ('clean', 'rx', 'permissions')[action] + '-' + target
                    result = invoke(label, [*device, 'shell', 'env', 'CLASSPATH=' + remote + '/driver.zip:' + remote + '/protected.apk',
                        'app_process', '-Xcheck:jni', '-Djava.library.path=' + remote + '/protected.apk!/lib/arm64-v8a',
                        '/system/bin', 'sample.RecheckDriver', remote + '/' + library.name, soname,
                        format(anchor['relativeAddress'], 'x'), anchor['expectedByte'], action, target], check=False, timeout=180)
                    expected = 127 if action and target != 'hot' else 0
                    outcome = {'case': label, 'expectedExitCode': expected, 'exitCode': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr}
                    report['cases'].append(outcome)
                    lines = result.stdout.splitlines()
                    needed = ['warm-before=initialize,commit,hot:ok']
                    mutation = [line for line in lines if line.startswith('mutation=' + ('rx' if action == 1 else 'permissions') + ' ')]
                    if action and len(mutation) == 1: needed.append(mutation[0])
                    needed.append('hot-after=22')
                    if target != 'hot': needed.append('checkpoint-next=' + target)
                    if expected == 0 and target != 'hot': needed.append('checkpoint-after=' + target + ':ok')
                    if action == 0: needed.append('clean-concurrent=ok')
                    if expected == 0: needed.append('completed=' + target)
                    if result.returncode != expected or any(line not in lines for line in needed) or (
                            action and len(mutation) != 1) or (
                            expected == 127 and any(line.startswith('checkpoint-after=') or line.startswith('completed=') for line in lines)) or (
                            all(line in lines for line in needed) and [lines.index(line) for line in needed] != sorted(lines.index(line) for line in needed)) or (
                            'JNI DETECTED ERROR' in result.stdout + result.stderr or 'WARNING' in result.stdout + result.stderr):
                        raise AssertionError('warm checkpoint outcome differs: ' + label + '\n' + result.stdout + result.stderr)
                    outcome['validated'] = True
                    print('[ok]', label, 'exit=' + str(result.returncode), flush=True)
            report['status'] = 'passed'
        finally:
            if pushed: invoke('cleanup-files', [*device, 'shell', 'rm', '-f', *pushed], check=False)
            invoke('cleanup-directory', [*device, 'shell', 'rmdir', remote], check=False)
    except Exception as error:
        report['status'] = 'failed'; report['error'] = str(error); raise
    finally:
        (out / 'recheck-device-results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('recheck evidence:', out / 'recheck-device-results.json', flush=True)


if __name__ == '__main__':
    main()
