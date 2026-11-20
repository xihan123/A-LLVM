"""Build, run and replay a fixed signed-APK ART/JNI wrapper lifetime fixture."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid
import zipfile

import cache_probe as cache
import compiler_lifetime as compiler_contract
import large_fixture
from lifetime_test import Commands, identity, read_json, require, utc_now, write_json


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/dex2c'))
import device as device_helper
BUDGET = 1 << 20
PAGE = 4096
PRESSURE_COUNT = 14
EXPECTED = b'wrapper-lifetime:nested=71,recursive=342,pressure=14\n'
TARGETS = ('outer', 'inner', 'recursive')
METHODS = {name: 'sample/Run.' + name + ('(II)I' if name == 'recursive' else '(I)I')
           for name in (*TARGETS, *(f'work{i}' for i in range(PRESSURE_COUNT)))}
METHODS['marker'] = 'sample/Run.marker()I'
SYMBOLS = {name: 'd2c_' + hashlib.sha256(method.encode()).hexdigest()[:24]
           for name, method in METHODS.items()}
EVENTS = {'nested': [(1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (9, 0)],
          'recursive': [(6, 3), (6, 2), (6, 1), (6, 0), (8, 0), (7, 1),
                        (8, 1), (7, 2), (8, 2), (7, 3), (8, 3), (9, 0)]}
DEVICE_QUERIES = {'model': ['getprop', 'ro.product.model'], 'sdk': ['getprop', 'ro.build.version.sdk'],
                  'pageSize': ['getconf', 'PAGESIZE'], 'arch': ['uname', '-m']}
NEGATIVES = ('wrong-signer', 'tampered-index', 'tampered-segment', 'missing-segments',
             'compressed-container', 'index-aead', 'segment-aead',
             *(f'authenticated-index-{offset}' for offset in (16, 20, 24, 32, 36, 40)),
             'authenticated-invalid-deflate')
SOURCE_FILES = (
    'tests/qseg/wrapper_lifetime.py', 'tests/qseg/wrapper_lifetime.cpp',
    'tests/qseg/test_wrapper_lifetime.py', 'tests/qseg/README.md',
    'tests/qseg/large_fixture.py', 'tests/qseg/cache_probe.py',
    'tests/qseg/compiler_lifetime.py', 'tests/qseg/lifetime_test.py',
    'tests/dex2c/device.py', 'scripts/seal_qseg.py', 'scripts/seal_cse.py',
    'scripts/verify_dex2c_apk.py', 'tests/qseg/audit_apk.py', 'scripts/dex2c_artifacts.py',
    'runtime/qseg.h', 'runtime/sha256.h', 'runtime/ndkp_qseg_runtime.cpp',
    'dex2c/core/build.gradle', 'dex2c/build.gradle', 'dex2c/settings.gradle',
    'dex2c/gradle/wrapper/gradle-wrapper.jar',
    'dex2c/gradle/wrapper/gradle-wrapper.properties',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/NativeCompiler.java',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/CppEmitter.java',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/RuntimeLayout.java',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/Transformer.java',
    'obfuscation/llvm-21/Transforms/Obfuscation/aVMP/aVMP.cpp',
    'obfuscation/llvm-21/Transforms/Obfuscation/SegmentedData.cpp',
    'obfuscation/llvm-21/Transforms/Obfuscation/StringEncryption.cpp',
    'obfuscation/llvm-21/Transforms/Obfuscation/ObfuscationPassManager.cpp',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fresh(path):
    path = Path(path).resolve()
    require(not path.exists() or (path.is_dir() and not any(path.iterdir())),
            'output must be new or empty; preserve earlier attempts')
    path.mkdir(parents=True, exist_ok=True)
    return path


def identities(paths):
    return {str(Path(path).resolve()): identity(path) for path in sorted(set(map(Path, paths)))}


def unchanged(rows):
    require(rows == identities(rows), 'bound input or artifact changed')


def tree_files(path):
    path = Path(path)
    return sorted(p for p in path.rglob('*') if p.is_file() and '__pycache__' not in p.parts)


def fixture_sources():
    source = large_fixture.fixture_source(PRESSURE_COUNT, 256)
    source = source.replace('public static void main(String[] args) {', 'static void pressureChecks() {', 1)
    source = source.replace('    System.out.println("large-vm=" + checksum);', '', 1)
    extra = r'''
  @dex2c static int inner(int x) {
    Probe.hit(2,0); int v=x*3+5; Probe.hit(3,0); return v;
  }
  @dex2c static int outer(int x) {
    Probe.hit(1,0); int v=inner(x+2); Probe.hit(4,0);
    v=v*2+7; Probe.hit(5,0); return v;
  }
  @dex2c static int recursive(int depth,int x) {
    Probe.hit(6,depth); int v=x*2+depth+1;
    if(depth>0) { int child=recursive(depth-1,v+1); Probe.hit(7,depth); v=v+child+depth*3; }
    Probe.hit(8,depth); return v^(depth+17);
  }
  public static void main(String[] args) throws Exception {
    if(args.length==0) {
      pressureChecks();
      if(outer(7)!=71 || recursive(3,7)!=342) throw new AssertionError();
      System.out.println("wrapper-lifetime:nested=71,recursive=342,pressure=14"); return;
    }
    if(args.length!=3 || !(args[0].equals("nested") || args[0].equals("recursive")))
      throw new IllegalArgumentException();
    if(marker()!=16 || outer(7)!=71 || recursive(3,7)!=342) throw new AssertionError();
    int mode=args[0].equals("nested")?1:2;
    Probe.configure(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[2])),args[1],mode);
    Probe.enabled=true;
    int first=mode==1?outer(7):recursive(3,7);
    Probe.enabled=false;
    Probe.observe(9,0);
    int again=mode==1?outer(7):recursive(3,7);
    Probe.finish(first,again);
  }
'''
    require(source.endswith('}\n'), 'unexpected large fixture source')
    source = source[:-2] + extra + '}\n'
    probe = '''package sample;
final class Probe {
  static boolean enabled;
  static void hit(int event,int depth) { if(enabled) observe(event,depth); }
  static native void configure(byte[] plan,String token,int mode);
  static native void observe(int event,int depth);
  static native void finish(int first,int again);
}
'''
    return source, probe


REGISTRATION_END = ('jint status=env->RegisterNatives(cls,methods,2);env->DeleteLocalRef(cls);'
                    'return status==0?JNI_VERSION_1_6:JNI_ERR;')


def inject_registration(text):
    require(text.count(REGISTRATION_END) == 1 and text.count('jint JNICALL JNI_OnLoad(') == 1,
            'unknown or ambiguous JNI_OnLoad registration insertion point')
    require('wrapper_lifetime' not in text, 'probe already inserted')
    return '#include "wrapper_lifetime.cpp"\n' + text.replace(
        REGISTRATION_END, 'jint status=env->RegisterNatives(cls,methods,2);env->DeleteLocalRef(cls);'
        'if(status!=0 || wrapper_lifetime_register(env)!=0)return JNI_ERR;return JNI_VERSION_1_6;', 1)


RUNNER = r'''
import io.github.xihan123.dex2c.core.Transformer;
import io.github.xihan123.dex2c.core.NativeCompiler;
import io.github.xihan123.dex2c.runtime.Dex2cRuntime;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import javax.tools.ToolProvider;
public class WrapperFixture {
  static void classpath(Path file) throws Exception {
    List<String> rows=new ArrayList<>();
    for(String item:System.getProperty("java.class.path").split(java.io.File.pathSeparator)) {
      Path root=Path.of(item).toAbsolutePath();
      List<Path> files;
      if(Files.isDirectory(root)) try(var paths=Files.walk(root)) {files=paths.filter(Files::isRegularFile).sorted().toList();}
      else files=List.of(root);
      for(Path path:files) rows.add(path+"\t"+Files.size(path)+"\t"+
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))));
    }
    Files.write(file,rows);
  }
  public static void main(String[] args) throws Exception {
    Path out=Path.of(args[0]), classes=Files.createDirectories(out.resolve("classes"));
    classpath(out.resolve("classpath-before.tsv"));
    int status=ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-classpath",
      System.getProperty("java.class.path"),"-d",classes.toString(),out.resolve("Run.java").toString(),out.resolve("Probe.java").toString());
    if(status!=0)throw new IllegalStateException("fixture javac failed");
    Path generated=out.resolve("generated");
    new Transformer().transform(List.of(classes),generated,"dex2c_semantics");
    Path registration=generated.resolve("registration.cpp");
    String text=Files.readString(registration), end=__END__;
    if(text.indexOf(end)<0 || text.indexOf(end)!=text.lastIndexOf(end) || text.contains("wrapper_lifetime"))
      throw new IllegalStateException("unknown registration insertion point");
    Files.writeString(out.resolve("registration-before.cpp"),text);
    String changed="#include \"wrapper_lifetime.cpp\"\n"+text.replace(end,__AFTER__);
    Files.writeString(registration,changed);
    for(String name:List.of("wrapper_lifetime.cpp","qseg.h","sha256.h"))
      Files.copy(out.resolve(name),generated.resolve(name));
    Files.writeString(out.resolve("runtime-path.txt"),Path.of(Dex2cRuntime.class.getProtectionDomain()
      .getCodeSource().getLocation().toURI()).toString());
    new NativeCompiler().compile(generated,out.resolve("native"),Path.of(args[1]),Path.of(args[2]),
      "dex2c_semantics",26,out.resolve("test.der"),Path.of(args[3]),true,true);
    classpath(out.resolve("classpath-after.tsv"));
  }
}
'''


def long_build(commands, argv):
    """Only Gradle/NativeCompiler needs a longer deadline than the shared recorder."""
    stem = 'commands/{:02d}-gradle'.format(len(commands.records) + 1)
    row = {'label': 'gradle', 'argv': list(map(str, argv)), 'cwd': str(ROOT / 'dex2c'),
           'started': utc_now(), 'timeoutSeconds': 1200}
    out, err = b'', b''
    try:
        result = subprocess.run(row['argv'], cwd=row['cwd'], capture_output=True, timeout=1200)
        out, err = result.stdout, result.stderr
        row.update(status='completed', returncode=result.returncode)
    except subprocess.TimeoutExpired as error:
        out, err = error.output or b'', error.stderr or b''
        row.update(status='timeout', returncode=None)
    except OSError as error:
        row.update(status='launch-error', returncode=None, error=str(error))
    row['ended'] = utc_now()
    for name, data in (('stdout', out), ('stderr', err)):
        path = commands.output / (stem + '.' + name + '.bin')
        path.write_bytes(data)
        row[name] = identity(path)
    reference = stem + '.json'
    write_json(commands.output / reference, row)
    commands.records.append(reference)
    require(row['status'] == 'completed' and row['returncode'] == 0, 'fixture Gradle build failed')


def snapshot_runtime(source, target):
    source = Path(source)
    with zipfile.ZipFile(target, 'x') as archive:
        if source.is_dir():
            for path in tree_files(source):
                archive.writestr(path.relative_to(source).as_posix(), path.read_bytes())
        else:
            with zipfile.ZipFile(source) as original:
                require(len(original.namelist()) == len(set(original.namelist())), 'duplicate runtime ZIP entry')
                for name in sorted(original.namelist()):
                    archive.writestr(name, original.read(name))


def build(args):
    output = fresh(args.output)
    commands = Commands(output, ROOT)
    report = {'schemaVersion': 1, 'checkerRevision': 1, 'commands': commands.records}
    try:
        ndk, clang, java = map(lambda path: path.resolve(), (args.ndk, args.clang, args.java))
        prebuilt = ndk / 'toolchains/llvm/prebuilt/windows-x86_64'
        tools = [clang, java, java.with_name('keytool.exe'), java.parent.parent / 'lib/modules',
                 Path(sys.executable), ndk / 'source.properties',
                 *(prebuilt / 'bin' / name for name in ('ld.lld.exe', 'llvm-strip.exe', 'llvm-nm.exe'))]
        fixed = identities([*(ROOT / path for path in SOURCE_FILES), *tools])
        report.update(inputsBefore=fixed, ndk=str(ndk), clang=str(clang), java=str(java))
        version, _ = commands.checked('compiler-version', [clang, '--version'])
        require(re.search(rb'clang version 21\.', version), 'Clang 21 required')
        source, probe = fixture_sources()
        (output / 'Run.java').write_text(source, 'utf-8')
        (output / 'Probe.java').write_text(probe, 'utf-8')
        after = REGISTRATION_END.split('return status')[0] + ('if(status!=0 || wrapper_lifetime_register(env)!=0)'
                'return JNI_ERR;return JNI_VERSION_1_6;')
        runner = RUNNER.replace('__END__', json.dumps(REGISTRATION_END)).replace('__AFTER__', json.dumps(after))
        (output / 'WrapperFixture.java').write_text(runner, 'utf-8')
        for source_path, name in ((Path(__file__).with_suffix('.cpp'), 'wrapper_lifetime.cpp'),
                                  (ROOT / 'runtime/qseg.h', 'qseg.h'), (ROOT / 'runtime/sha256.h', 'sha256.h')):
            (output / name).write_bytes(source_path.read_bytes())
        commands.checked('keytool-generate', [java.with_name('keytool.exe'), '-genkeypair', '-keystore', output / 'test.jks',
                         '-storepass', 'android', '-keypass', 'android', '-alias', 'test', '-keyalg', 'RSA',
                         '-dname', 'CN=qseg wrapper lifetime fixture', '-validity', '3650', '-noprompt'])
        commands.checked('keytool-export', [java.with_name('keytool.exe'), '-exportcert', '-keystore', output / 'test.jks',
                         '-storepass', 'android', '-alias', 'test', '-file', output / 'test.der'])
        task_args = [output, ndk, clang, Path(sys.executable).resolve()]
        init = output / 'fixture.init.gradle'
        init.write_text('''gradle.projectsEvaluated {
    def core = gradle.rootProject.project(':core')
    core.tasks.register('qsegWrapperFixture', JavaExec) {
        dependsOn core.tasks.named('testClasses')
        classpath = core.sourceSets.test.runtimeClasspath
        executable = %s
        mainClass = %s
        args %s
    }
}
''' % (json.dumps(str(java)), json.dumps(str(output / 'WrapperFixture.java')),
       ', '.join(json.dumps(str(value)) for value in task_args)), 'utf-8')
        # JAVA_HOME is set directly; no shared Gradle/project configuration is edited.
        old_java_home = os.environ.get('JAVA_HOME')
        os.environ['JAVA_HOME'] = str(java.parent.parent)
        try:
            long_build(commands, [ROOT / 'dex2c/gradlew.bat', '-I', init, ':core:qsegWrapperFixture',
                                  '--no-daemon', '--console=plain'])
        finally:
            if old_java_home is None:
                os.environ.pop('JAVA_HOME', None)
            else:
                os.environ['JAVA_HOME'] = old_java_home
        require((output / 'classpath-before.tsv').read_bytes() == (output / 'classpath-after.tsv').read_bytes(),
                'actual Gradle classpath changed during NativeCompiler')
        classpath_rows = {}
        for line in (output / 'classpath-before.tsv').read_text('utf-8').splitlines():
            path, size, digest = line.rsplit('\t', 2)
            row = identity(path)
            require(row['bytes'] == int(size) and row['sha256'] == digest, 'classpath identity differs')
            classpath_rows[path] = row
        report['classpathInputs'] = classpath_rows
        require((output / 'generated/registration.cpp').read_text('utf-8') ==
                inject_registration((output / 'registration-before.cpp').read_text('utf-8')),
                'registration modification differs from fixed insertion')
        with zipfile.ZipFile(output / 'original.jar', 'x') as archive:
            for path in tree_files(output / 'classes'):
                archive.writestr(path.relative_to(output / 'classes').as_posix(), path.read_bytes())
        snapshot_runtime((output / 'runtime-path.txt').read_text('utf-8'), output / 'runtime-snapshot.jar')
        write_json(output / 'inputs.json', {'mains': ['sample.Run'], 'baseline': [str(output / 'original.jar')],
                   'protected': [str(output / 'generated/classes.jar')], 'common': [str(output / 'runtime-snapshot.jar')]})
        report['contract'] = bind_wrappers(output)
        report['inputsAfter'] = identities(fixed)
        unchanged(fixed)
        unchanged(classpath_rows)
        # device.py legitimately adds signing/D8 products later; bind only this stable build subset.
        artifacts = [p for p in tree_files(output) if 'commands' not in p.relative_to(output).parts
                     and 'runtime-cache' not in p.relative_to(output).parts]
        report['artifacts'] = identities(artifacts)
        write_json(output / 'build.json', report)
        print(json.dumps({'fixture': str(output), 'methods': len(METHODS), 'leaseTargets': list(TARGETS)}))
    except BaseException as error:
        write_json(output / 'failure.json', {'phase': 'build', 'type': type(error).__name__, 'message': str(error), **report})
        raise


def nounwind(ir, header):
    groups = re.findall(r' #(\d+)', header)
    require(len(groups) == 1, 'unknown function attribute shape')
    attrs = re.findall(r'^attributes #' + groups[0] + r' = \{(.*)}$', ir, re.M)
    require(len(attrs) == 1, 'missing/duplicate function attribute group')
    # Hardened CSE invalidates NoUnwind after aVMP already chose the lease policy.
    return bool(re.search(r'\bnounwind\b', attrs[0]))


def final_wrapper_paths(body, ref, interpreter):
    """Check the actual LLVM 21 post-pass three-block indirectbr wrapper."""
    ident, value = compiler_contract.IDENT, compiler_contract.VALUE
    cfg = compiler_contract.blocks(body, limit=3)
    require(len(cfg) == 3, 'unsupported final wrapper block count')
    entry_name, entry = next(iter(cfg.items()))
    branch = re.fullmatch(r'indirectbr ptr ' + value + r', \[label %(' + ident +
                          r'), label %(' + ident + r')\]', entry[-1])
    require(branch is not None and len(set(branch.groups())) == 2 and
            {entry_name, *branch.groups()} == set(cfg), 'unsupported final indirectbr successors')
    lines = [line for group in cfg.values() for line in group]
    call_lines = [line for line in lines if re.search(r'\bcall\b', line)]
    calls = {line: compiler_contract.call(line) for line in call_lines}
    expected = {'ndkp_qseg_acquire_v1': 2, 'ndkp_qseg_release_v1': 2,
                'ndkp_selfcheck_one': 1, 'llvm.memset.p0.i64': 1, interpreter: 1,
                'vmp_resume_unwind_shared': 1}
    require({name: sum(calls[line][1] == name for line in call_lines) for name in expected} == expected and
            all(callee in expected for _, callee, _ in calls.values()), 'final wrapper call denominator differs')
    require(len(call_lines) == sum(expected.values()), 'duplicate final wrapper call')
    borrowed = set()
    for line, (result, callee, args) in calls.items():
        if callee not in ('ndkp_qseg_acquire_v1', 'ndkp_qseg_release_v1'):
            continue
        argument = re.fullmatch(r'ptr(?: nonnull)? @(' + ident + r')', args)
        require(argument is not None and argument[1] == ref and
                (result is None) == (callee == 'ndkp_qseg_release_v1'), 'final QSEG descriptor or result differs')
        if result is not None:
            require(result not in borrowed, 'duplicate final borrow result')
            borrowed.add(result)
    stores = [line for line in lines if '@vmp_shared_code_seg_addr' in line]
    require(len(stores) == 1, 'missing/duplicate final bytecode slot')
    stored = re.fullmatch(r'store i64 (' + value + r'), ptr @vmp_shared_code_seg_addr, align 8', stores[0])
    require(stored is not None, 'unsupported final bytecode pointer store')
    casts = [re.fullmatch(re.escape(stored[1]) + r' = ptrtoint ptr (' + value + r') to i64', line) for line in lines]
    origins = [match[1] for match in casts if match]
    require(len(origins) == 1 and origins[0] in borrowed, 'final bytecode pointer origin differs')
    main = origins[0]; temporary = borrowed - {main}
    require(len(temporary) == 1, 'missing/distinct final SelfCheck borrow')
    for pointer in borrowed:
        require(sum(bool(re.search(re.escape(pointer) + r'(?![-a-zA-Z$._0-9])', line)) for line in lines) == 2,
                'final borrowed pointer escaped or has unexpected use')
    loans, prepared, ran, checked = [], False, False, set()
    for index, line in enumerate(entry[:-1]):
        opcode = re.sub(r'^' + value + r' = ', '', line).split(' ', 1)[0]
        require(opcode in {'alloca', 'load', 'store', 'getelementptr', 'ptrtoint', 'xor', 'icmp',
                           'call', 'add', 'sub', 'select', 'sext'}, 'unsupported final wrapper instruction')
        if line in calls:
            result, callee, args = calls[line]
            if callee == 'llvm.memset.p0.i64':
                initializer = re.fullmatch(r'ptr noundef nonnull align 16 dereferenceable\((\d+)\) (' +
                    value + r'), i8 0, i64 (\d+), i1 false', args)
                require(result is None and initializer is not None and initializer[1] == initializer[3] and index and
                        entry[index - 1] == initializer[2] + ' = alloca [' + initializer[1] + ' x i8], align 16',
                        'unsupported final frame memset')
            elif callee == 'ndkp_qseg_acquire_v1':
                require(not ran and result not in loans, 'late/duplicate final borrow')
                loans.append(result)
            elif callee == 'ndkp_qseg_release_v1':
                require(loans and ((loans[-1] == main and ran) or
                        (loans[-1] in temporary and loans[-1] in checked)),
                        'final release before interpreter or unchecked SelfCheck')
                loans.pop()
            elif callee == 'ndkp_selfcheck_one':
                argument = re.fullmatch(r'ptr (' + value + r'), i64 \d+, i64 -?\d+', args)
                require(argument is not None and argument[1] in temporary and loans and
                        loans[-1] == argument[1] and argument[1] not in checked,
                        'final SelfCheck not covered by temporary lease')
                checked.add(argument[1])
            elif callee == interpreter:
                require(prepared and not ran and checked == temporary and loans == [main] and args == '',
                        'final interpreter bypasses main lease or temporary closure')
                ran = True
            else:
                require(False, 'final resume before indirectbr')
        if line == stores[0]:
            require(not prepared and not ran and main in loans, 'final main prepared without lease')
            prepared = True
        require(not (prepared and not ran) or main in loans, 'final main released before interpreter returned')
    require(prepared and ran and not loans and checked == temporary,
            'final indirectbr bypasses paired main release')
    paths = []
    for target in branch.groups():
        group = cfg[target]
        for line in group[:-1]:
            if line in calls:
                result, callee, args = calls[line]
                require(result is None and callee == 'vmp_resume_unwind_shared' and args == '' and
                        line == group[-2] and group[-1] == 'unreachable', 'unsupported final exit call')
            else:
                opcode = re.sub(r'^' + value + r' = ', '', line).split(' ', 1)[0]
                require(opcode in {'load', 'store'}, 'unsupported final exit instruction')
        terminal = group[-1]
        require(re.fullmatch(r'ret i32 ' + value, terminal) or terminal == 'unreachable', 'unsupported final exit')
        if terminal == 'unreachable':
            require(len(group) > 1 and group[-2] in calls and calls[group[-2]][1] == 'vmp_resume_unwind_shared',
                    'unknown final unreachable exit')
        paths.append({'blocks': [entry_name, target], 'exit': 'resume' if terminal == 'unreachable' else 'return',
                      'interpreterLeaseDepth': 1, 'exitLeaseDepth': 0})
    require({row['exit'] for row in paths} == {'return', 'resume'}, 'missing final return/resume successor')
    return {'mainPointer': main, 'selfCheckPointers': sorted(temporary), 'paths': paths,
            'branchKind': 'indirectbr', 'scope': 'interpreter normal return and subsequent resume dispatch'}


def bind_wrappers(fixture):
    generated, native = fixture / 'generated', fixture / 'native'
    selection, protection = read_json(generated / 'selection.json'), read_json(native / 'protection.json')
    expected = {METHODS[name]: SYMBOLS[name] for name in METHODS}
    rows = selection['methods']
    selected = {row['method']: row['symbol'] for row in rows if row['protection'] == 'vmp'}
    require(selected == expected and len(rows) == len(expected), 'selection differs from exact fixture denominator')
    require(set(protection['symbols']) == set(expected.values()) and len(protection['symbols']) == len(expected),
            'receipt VM symbols differ')
    require(protection['vmLifetimePolicies'] == dict.fromkeys(expected.values(), 'lease-v1'),
            'fresh generated JNI wrapper is pinned or has unknown lifetime')
    raw = (native / 'protected.raw.ll').read_text('utf-8')
    final = (native / 'protected.ll').read_text('utf-8')
    manifest = read_json(native / 'staging/protected/manifest.json')
    vm_rows = [row for row in manifest if row['kind'] == 1]
    require(len(vm_rows) == len(expected) and {row['name'] for row in vm_rows} == set(expected.values()),
            'staging VM denominator differs')
    bound = {}
    for name, symbol in SYMBOLS.items():
        row, = [row for row in vm_rows if row['name'] == symbol]
        require(row['lifetime'] == 'lease-v1', 'staged resource is not lease-v1')
        entries = []
        for text, label in ((raw, 'raw'), (final, 'final')):
            header, body = compiler_contract.function(text, symbol)
            has_nounwind = nounwind(text, header)
            require(compiler_contract.metadata(text, header, 'ndkp.qseg.lifetime') == '!"lease-v1"',
                    label + ' wrapper lifetime differs')
            receipt = compiler_contract.metadata(text, header, 'ndkp.vmp.protected')
            match = re.fullmatch(r'ptr @(\S+), ptr @(\S+)', receipt)
            require(match is not None and match[1] == 'gv_code_seg_' + symbol, 'VM receipt binding differs')
            ref = compiler_contract.metadata(text, compiler_contract.global_line(text, match[1]), 'ndkp.qseg')
            require(re.fullmatch(r'ptr @\S+', ref), 'invalid descriptor metadata')
            ref = ref[5:]
            descriptor_line = compiler_contract.global_line(text, ref)
            descriptor = compiler_contract.decode_descriptor(descriptor_line)
            require(descriptor == bytes.fromhex(row['id']) + struct.pack('<II', row['bytes'], 1),
                    label + ' descriptor/staging identity differs')
            require(compiler_contract.metadata(text, descriptor_line, 'ndkp.qseg.lifetime') == '!"lease-v1"',
                    label + ' descriptor policy differs')
            check = (compiler_contract.wrapper_paths(body, ref, match[2], 'lease-v1') if label == 'raw' else
                     final_wrapper_paths(body, ref, match[2]))
            entries.append({'ir': label, 'descriptor': ref, 'interpreter': match[2],
                            'nounwind': has_nounwind, 'paths': check})
        staged = (native / 'staging/protected' / (row['id'] + '.bin')).read_bytes()
        require(len(staged) == row['bytes'] and staged ==
                (native / 'staging/protected' / (symbol + '.bin')).read_bytes(), 'staged bytes differ')
        bound[name] = {'method': METHODS[name], 'symbol': symbol, 'id': row['id'], 'bytes': row['bytes'],
                       'sha256': sha(staged), 'irBindings': entries}
    require(len({item['id'] for item in bound.values()}) == len(bound), 'duplicate VM resource IDs')
    return bound


def select_resources(contract, receipt, resources):
    selected = []
    for name in (*TARGETS, *(f'work{i}' for i in range(PRESSURE_COUNT))):
        item = dict(contract[name])
        raw = resources.get((bytes.fromhex(item['id']), 1))
        require(raw is not None and len(raw) == item['bytes'] and len(raw) >= 32 and sha(raw) == item['sha256'],
                'authenticated resource/staging bytes differ: ' + name)
        chunks = sorted((row for row in receipt['segments'] if row['id'] == item['id']), key=lambda row: row['chunk'])
        require([row['chunk'] for row in chunks] == list(range((len(raw) + 65535) // 65536)), 'incomplete VM chunks')
        for row in chunks:
            chunk = raw[row['chunk'] * 65536:(row['chunk'] + 1) * 65536]
            require(row['name'] == item['symbol'] and row['kind'] == 1 and row['lifetime'] == 'lease-v1' and
                    row['bytes'] == len(chunk) and row['sha256'] == sha(chunk) and
                    row['resourceSha256'] == sha(raw), 'chunk binding or policy differs')
        item.update(name=name, mappedBytes=(len(raw) + PAGE - 1) // PAGE * PAGE,
                    prefix=raw[:32].hex(), chunks=chunks)
        selected.append(item)
    require(selected[0]['mappedBytes'] + selected[1]['mappedBytes'] <= BUDGET and
            selected[2]['mappedBytes'] <= BUDGET, 'target set exceeds idle budget')
    require(sum(item['mappedBytes'] for item in selected[3:]) > BUDGET, 'other pressure VMs must exceed idle budget')
    require(any(row['codec'] == 1 for row in receipt['segments']), 'fixture needs a compressed chunk for auth negatives')
    return selected


def encode_plan(plan):
    resources, spans = plan['resources'], plan['executableSpans']
    require(len(resources) == 17 and 0 < len(spans) <= 8, 'unexpected fixed plan counts')
    data = bytearray(struct.pack('<8sIIIIQ', b'QWRAP01\0', PAGE, BUDGET, len(resources), len(spans), plan['onloadRva']))
    for item in resources:
        require(32 <= item['bytes'] <= 16 << 20 and 0 < len(item['chunks']) <= 256, 'resource bounds')
        data += struct.pack('<QII', item['address'], item['bytes'], len(item['chunks']))
        data += bytes.fromhex(item['id'] + item['sha256'] + item['prefix'])
        for chunk in item['chunks']:
            data += struct.pack('<II', chunk['chunk'] * 65536, chunk['bytes']) + bytes.fromhex(chunk['sha256'])
    for span in spans:
        data += struct.pack('<QQ', span['address'], span['bytes']) + bytes.fromhex(span['sha256'])
    require(len(data) <= 1 << 20, 'binary plan too large')
    return bytes(data)


def rebuild_plan(fixture, nm_raw):
    """Reconstruct the whole plan from bound final bytes without launching tools."""
    native = fixture / 'native'
    contract, protection = bind_wrappers(fixture), read_json(native / 'protection.json')
    require(protection.get('qsegLifetimeAbi') == 1 and protection.get('idlePlaintextBudgetBytes') == BUDGET and
            protection.get('apkSignatureVerification') is True, 'plan requires verified APK lifetime ABI 1')
    apk, certificate = fixture / 'protected.apk', native / 'signing-cert.der'
    audited = cache.audit(apk, native / 'protection.json', native / 'segments.json', certificate)
    entry, = [row['name'] for row in audited['libraries'] if row['sha256'] == protection['librarySha256']]
    with zipfile.ZipFile(apk) as archive:
        library = archive.read(entry)
        _, offset = cache.qseg.locate_image(library)
        asset = library[offset + 256:offset + 384].split(b'\0', 1)[0].decode('utf-8')
        raw = cache.qseg.unpack(library, archive.read(asset), certificate.read_bytes())
    resources = select_resources(contract, read_json(native / 'segments.json'), raw)
    required = {'ndkp_qseg_acquire_v1', 'ndkp_qseg_release_v1', 'ndkp_qseg_stats_v1', 'JNI_OnLoad'}
    symbols = {}
    for line in nm_raw.decode('ascii').splitlines():
        parts = line.split()
        if parts and parts[-1] in required:
            require(len(parts) == 3 and re.fullmatch('[0-9a-fA-F]+', parts[0]) and parts[-1] not in symbols,
                    'missing/duplicate/malformed required llvm-nm symbol')
            symbols[parts[-1]] = int(parts[0], 16)
    require(symbols.keys() == required, 'required llvm-nm symbol denominator differs')
    linked = (native / 'linked.so').read_bytes()
    spans = cache.bind_executable(linked, library, symbols)
    for item in resources:
        item['address'] = cache.descriptor_address(library, item['id'], item['bytes'])
        require(cache.descriptor_address(linked, item['id'], item['bytes']) == item['address'],
                'linked/final descriptor address differs')
    return {'schemaVersion': 1, 'apkSha256': audited['apkSha256'], 'libraryEntry': entry,
            'librarySha256': protection['librarySha256'], 'containerSha256': protection['containerSha256'],
            'pageSize': PAGE, 'idleBudgetBytes': BUDGET, 'resources': resources,
            'executableSpans': spans, 'onloadRva': symbols['JNI_OnLoad']}


def check_jni(stdout, stderr):
    require(not re.search(rb'WARNING|JNI DETECTED ERROR|JNI WARNING|CheckJNI[^\r\n]*(?:error|failure)',
                          stdout + b'\n' + stderr, re.I), 'CheckJNI diagnostic in raw output')


def expected_active(case, event, plan):
    resources = plan['resources']
    indices = [] if event == 9 else ([2] if case == 'recursive' else ([0, 1] if event in (2, 3) else [0]))
    return sum(resources[index]['mappedBytes'] for index in indices)


def validate_run(stdout, stderr, token, case, plan):
    require(re.fullmatch('[0-9a-f]{32}', token) and case in EVENTS, 'invalid run identity')
    check_jni(stdout, stderr)
    rows = []
    for line in stdout.splitlines():
        require(line.startswith(b'QSEG_WRAPPER:'), 'unexpected observer stdout')
        row = json.loads(line[len(b'QSEG_WRAPPER:'):], object_pairs_hook=compiler_contract.unique_object)
        require(row.get('token') == token and row.get('case') == case and row.get('seq') == len(rows), 'event identity/order differs')
        rows.append(row)
    require(len(rows) == len(EVENTS[case]) + 2 and rows[0]['event'] == 0 and rows[-1]['event'] == 10,
            'missing configure/events/COMPLETE')
    require([(row['event'], row['depth']) for row in rows[1:-1]] == EVENTS[case], 'wrapper event sequence differs')
    require(rows[0]['active'] == 0 and rows[0]['pinned'] == 0 and rows[0]['targetLoans'] == 0,
            'configure retains target loan')
    reclaimed = []
    last_evictions = rows[0]['evictions']
    for row in rows[1:-1]:
        require(row['active'] == expected_active(case, row['event'], plan) and row['pinned'] == 0 and
                0 <= row['idle'] <= BUDGET and row['evictions'] > last_evictions and row['readonly'] is True and
                row['digests'] is True and row['targetLoans'] == 0, 'pressure/lease/mapping evidence differs')
        last_evictions = row['evictions']
        reclaim = row['event'] == 9 or (case == 'nested' and row['event'] == 4)
        require((1 <= row['steps'] <= PRESSURE_COUNT) if reclaim else row['steps'] == PRESSURE_COUNT,
                'pressure coverage differs')
        if reclaim:
            index = (1 if row['event'] == 4 else 0) if case == 'nested' else 2
            require(row['reclaimed'] == plan['resources'][index]['id'] and row['absent'] is True and
                    re.fullmatch('0x[0-9a-f]+', row['oldBegin']) and int(row['oldBegin'], 16) % PAGE == 0 and
                    row['oldBytes'] == plan['resources'][index]['mappedBytes'] and row['releasedReadonly'] is True,
                    'missing exact released target interval absence')
            reclaimed.append(row['reclaimed'])
    require(len(reclaimed) == (2 if case == 'nested' else 1) and len(set(reclaimed)) == len(reclaimed), 'target reclamation coverage differs')
    last = rows[-1]
    expected = 71 if case == 'nested' else 342
    require(last['first'] == expected and last['again'] == expected and last['active'] == 0 and last['pinned'] == 0 and
            last['semanticReentry'] is True and last['targetLoans'] == 0 and 0 <= last['idle'] <= BUDGET,
            'real wrapper reentry failed')
    return rows


def verify_device_report(path, fixture, sdk, java, serial, port):
    report = read_json(path)
    require(report.get('schemaVersion') == 2 and report.get('status') == 'passed', 'device.py did not pass')
    invocation = report['invocation']
    require(len(invocation) >= 2 and Path(invocation[0]).resolve() == Path(sys.executable).resolve() and
            Path(invocation[1]).resolve() == ROOT / 'tests/dex2c/device.py', 'device.py executable differs')
    options = invocation[2:]
    require(len(options) % 2 == 0, 'device.py invocation is not fixed option/value pairs')
    pairs = list(zip(options[::2], options[1::2]))
    parameters = dict(pairs)
    required = {'--fixtures', '--sdk', '--java', '--serial'}
    require(len(parameters) == len(pairs) and required <= parameters.keys() and
            parameters.keys() <= required | {'--server-port', '--report'}, 'device.py invocation options differ')
    require(Path(parameters['--fixtures']).resolve() == fixture and Path(parameters['--sdk']).resolve() == sdk and
            Path(parameters['--java']).resolve() == java and parameters['--serial'] == serial and
            parameters.get('--server-port', '5037') == str(port) and
            Path(parameters.get('--report', fixture / 'device-results.json')).resolve() == Path(path).resolve(),
            'device.py invocation fixture/JDK/SDK/serial/port/report differs')
    adb = [str(sdk / 'platform-tools/adb.exe'), '-P', str(port), '-s', serial]
    require(report['fixtures'] == str(fixture) and report['serial'] == serial and report['deviceCommand'] == adb,
            'device.py fixture/serial/port/tool binding differs')
    require(re.fullmatch('/data/local/tmp/dex2c-[0-9a-f]{32}', report['remote']), 'device.py remote identity differs')
    negatives = [row for row in report['results'] if 'rejected' in row]
    require([row['mode'] for row in negatives] == list(NEGATIVES) and report['negativeCases'] ==
            [{'mode': name, 'expectedCodes': [127]} for name in NEGATIVES],
            'auth negative denominator differs')
    require(len({row['protocolToken'] for row in negatives}) == len(NEGATIVES), 'negative token reused')
    for row in negatives:
        require(row['rejected'] is True and row['status'] == 'expected-exit-signature' and row['expectedCodes'] == [127] and
                row['exitCode'] == 127 and re.fullmatch('DEX2C_[0-9a-f]{32}', row['protocolToken']) and
                'error' not in row, 'authentication negative failed')
        target = report['remote'] + '/' + row['mode'] + '.apk'
        command, child = device_helper.negative_command(adb, target, row['protocolToken'])
        require(row['command'] == command and row['childArgv'] == child and row['remoteApk'] == target and
                row['environment'] == {'CLASSPATH': target} and row['execution']['command'] == command and
                row['push']['command'] == [*adb, 'push', str(fixture / (row['mode'] + '.apk')), target] and
                row['push']['status'] == 'completed' and row['push']['returnCode'] == 0,
                'negative actual argv or push differs')
        execution = row['execution']
        for stage in (execution, row['push']):
            for stream in ('stdout', 'stderr'):
                raw = base64.b64decode(stage[stream + 'Base64'], validate=True)
                require(raw.decode('utf-8', 'replace') == stage[stream], 'negative raw stream differs')
        require(execution['status'] == 'completed' and device_helper.negative_status(execution, row['protocolToken'], [127]) ==
                ('expected-exit-signature', 127), 'negative raw protocol did not prove child exit 127')
        artifact = row['artifact']
        require(Path(artifact['path']) == fixture / (row['mode'] + '.apk') and
                identity(artifact['path']) == artifact, 'negative signed artifact changed')
    positive = [row for row in report['results'] if 'rejected' not in row]
    require([(row['main'], row['mode'], row['output']) for row in positive] ==
            [('sample.Run', name, EXPECTED.decode().strip()) for name in ('baseline', 'protected')], 'device.py positive semantics differ')
    pushed = [report['remote'] + '/' + name for name in
              ('baseline.zip', 'protected.apk', 'protected.zip', 'libdex2c_semantics.so',
               *(mode + '.apk' for mode in NEGATIVES))]
    require(report['pushed'] == pushed and len(report['cleanup']) == 2 and
            [row['command'] for row in report['cleanup']] ==
            [[*adb, 'shell', 'rm', '-f', *pushed], [*adb, 'shell', 'rmdir', report['remote']]] and
            all(row['status'] == 'completed' and row['returnCode'] == 0 for row in report['cleanup']),
            'device cleanup failed or exact command differs')
    return report


def app_argv(adb, remote, dex, arguments=()):
    return [*map(str, adb), 'shell', 'env', 'CLASSPATH=' + remote + '/' + dex, 'app_process', '-Xcheck:jni',
            '-Djava.library.path=' + remote + '/protected.apk!/lib/arm64-v8a', '/system/bin', 'sample.Run', *arguments]


def expected_commands(report, output):
    fixture, sdk = Path(report['fixture']), Path(report['sdk'])
    adb = [str(sdk / 'platform-tools/adb.exe'), '-P', str(report['serverPort']), '-s', report['serial']]
    remote = report['remote']
    expected = {'device-' + name: [*adb, 'shell', *argv] for name, argv in DEVICE_QUERIES.items()}
    expected['llvm-nm'] = [str(Path(report['ndk']) / 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe'),
                           '--defined-only', str(fixture / 'native/linked.so')]
    expected['remote-mkdir'] = [*adb, 'shell', 'mkdir', remote]
    for source, name in ((fixture / 'protected.apk', 'protected.apk'), (fixture / 'baseline.zip', 'baseline.zip'),
                          (output / 'plan.bin', 'plan.bin')):
        expected['push-' + name.replace('.', '-')] = [*adb, 'push', str(source), remote + '/' + name]
    for name, dex in (('baseline', 'baseline.zip'), ('protected', 'protected.apk')):
        expected['normal-' + name] = app_argv(adb, remote, dex)
    for row in report['runs']:
        expected[row['case']] = app_argv(adb, remote, 'protected.apk', [row['case'], row['token'], remote + '/plan.bin'])
    expected['remote-remove'] = [*adb, 'shell', 'rm', '-f', *(remote + '/' + name for name in ('protected.apk', 'baseline.zip', 'plan.bin'))]
    expected['remote-rmdir'] = [*adb, 'shell', 'rmdir', remote]
    return expected


def run(args):
    output, fixture = fresh(args.output), args.fixtures.resolve()
    commands = Commands(output, ROOT)
    report = {'schemaVersion': 1, 'checkerRevision': 1, 'scope': 'signed APK normal ART/JNI wrapper lifetime',
              'productionWrapperExecution': True, 'callRoute': 'ART/JNI', 'nativeDirectHandlerExecution': False,
              'directWipeObservation': False, 'commands': commands.records, 'runs': [], 'cleanup': []}
    pushed, remote, adb = [], None, []
    error = None
    try:
        build_report = read_json(fixture / 'build.json')
        unchanged(build_report['inputsBefore'])
        unchanged(build_report['artifacts'])
        require(str(args.java.resolve()) == build_report['java'], 'JDK differs from fixture build')
        sdk, java = args.sdk.resolve(), args.java.resolve()
        device_report = verify_device_report(fixture / 'device-results.json', fixture, sdk, java, args.serial, args.server_port)
        sdk_tools = sdk / 'build-tools/37.0.0'
        adb_path = sdk / 'platform-tools/adb.exe'
        fixed = identities([*(ROOT / path for path in SOURCE_FILES), fixture / 'build.json', fixture / 'device-results.json',
                            fixture / 'protected.apk', fixture / 'baseline.zip', fixture / 'protected.zip', java, Path(sys.executable),
                            adb_path, *(sdk_tools / path for path in ('aapt2.exe', 'zipalign.exe', 'lib/d8.jar', 'lib/apksigner.jar')),
                            sdk / 'platforms/android-37.0/android.jar',
                            *(row['artifact']['path'] for row in device_report['results'] if 'artifact' in row)])
        report.update(inputsBefore=fixed, serial=args.serial, serverPort=args.server_port, fixture=str(fixture),
                      sdk=str(sdk), java=str(java), ndk=build_report['ndk'])
        adb = [adb_path, '-P', str(args.server_port), '-s', args.serial]
        device = {}
        for name, argv in DEVICE_QUERIES.items():
            raw, _ = commands.checked('device-' + name, [*adb, 'shell', *argv])
            device[name] = raw.decode('ascii').strip()
        require(device['pageSize'] == str(PAGE) and device['arch'] == 'aarch64' and int(device['sdk']) >= 26,
                'fixed fixture requires aarch64 and actual 4096-byte pages')
        report['device'] = device
        cache.verify([fixture / 'protected.apk'], fixture / 'native', fixture / 'generated', java,
                     sdk_tools / 'lib/apksigner.jar', 26, output / 'apk-verification.json')
        linked_path = fixture / 'native/linked.so'
        nm = Path(build_report['ndk']) / 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe'
        nm_raw, _ = commands.checked('llvm-nm', [nm, '--defined-only', linked_path])
        plan = rebuild_plan(fixture, nm_raw)
        write_json(output / 'plan.json', plan)
        (output / 'plan.bin').write_bytes(encode_plan(plan))
        report['plan'] = identity(output / 'plan.json')
        report['binaryPlan'] = identity(output / 'plan.bin')
        remote = '/data/local/tmp/qseg-wrapper-' + uuid.uuid4().hex
        report['remote'] = remote
        commands.checked('remote-mkdir', [*adb, 'shell', 'mkdir', remote])
        for path, name in ((fixture / 'protected.apk', 'protected.apk'), (fixture / 'baseline.zip', 'baseline.zip'),
                           (output / 'plan.bin', 'plan.bin')):
            pushed.append(remote + '/' + name)
            commands.checked('push-' + name.replace('.', '-'), [*adb, 'push', path, pushed[-1]])
        normal = []
        for mode, dex in (('baseline', 'baseline.zip'), ('protected', 'protected.apk')):
            argv = app_argv(adb, remote, dex)
            stdout, stderr = commands.checked('normal-' + mode, argv)
            check_jni(stdout, stderr)
            require(stdout.replace(b'\r\n', b'\n') == EXPECTED, 'fixed baseline/protected semantics differ')
            normal.append({'mode': mode, 'command': commands.records[-1]})
        report['normal'] = normal
        for case in EVENTS:
            token = uuid.uuid4().hex
            argv = app_argv(adb, remote, 'protected.apk', [case, token, remote + '/plan.bin'])
            stdout, stderr = commands.checked(case, argv)
            rows = validate_run(stdout, stderr, token, case, plan)
            report['runs'].append({'case': case, 'token': token, 'command': commands.records[-1], 'events': rows})
        unchanged(fixed)
        unchanged(build_report['artifacts'])
    except BaseException as caught:
        error = caught
        report['error'] = {'type': type(caught).__name__, 'message': str(caught)}
    finally:
        if remote:
            for label, argv in [('remote-remove', [*adb, 'shell', 'rm', '-f', *pushed]),
                                ('remote-rmdir', [*adb, 'shell', 'rmdir', remote])]:
                row, _, _ = commands.run(label, argv)
                report['cleanup'].append(commands.records[-1])
                if row['status'] != 'completed' or row['returncode'] != 0:
                    report.setdefault('cleanupErrors', []).append(label)
        if error is not None or report.get('cleanupErrors'):
            write_json(output / 'failure.json', report)
        else:
            try:
                unchanged(fixed)
                unchanged(build_report['artifacts'])
                report['inputsAfter'] = identities(fixed)
                report['status'] = 'passed'
                report['artifacts'] = identities(tree_files(output))
                verify_report(output, report)
                write_json(output / 'results.pending.json', report)
                (output / 'results.pending.json').replace(output / 'results.json')
            except BaseException as caught:
                error = caught
                report.update(status='failed', error={'type': type(caught).__name__, 'message': str(caught)})
                write_json(output / 'failure.json', report)
    if error:
        raise error
    require(not report.get('cleanupErrors'), 'remote cleanup failed')
    print(json.dumps({'output': str(output), 'cases': [row['case'] for row in report['runs']], 'callRoute': 'ART/JNI'}))


def verify_report(output, report):
    require(not (output / 'failure.json').exists(), 'failure report accompanies success')
    require(report['schemaVersion'] == 1 and report['checkerRevision'] == 1 and report['callRoute'] == 'ART/JNI' and
            report.get('status') == 'passed' and
            report['productionWrapperExecution'] is True and report['nativeDirectHandlerExecution'] is False and
            report['directWipeObservation'] is False, 'report scope differs')
    require(report['inputsBefore'] == report['inputsAfter'], 'input identities changed')
    unchanged(report['inputsBefore'])
    unchanged(report['artifacts'])
    require(identity(report['plan']['path']) == report['plan'] and identity(report['binaryPlan']['path']) == report['binaryPlan'],
            'plan bytes changed')
    plan = read_json(report['plan']['path'])
    require(Path(report['binaryPlan']['path']).read_bytes() == encode_plan(plan), 'binary/JSON plans differ')
    require(re.fullmatch('/data/local/tmp/qseg-wrapper-[0-9a-f]{32}', report['remote']) and report['serial'] and
            type(report['serverPort']) is int and 1 <= report['serverPort'] <= 65535, 'invalid device/remote identity')
    records = {}
    for reference in report['commands']:
        path = (output / reference).resolve()
        require(path.parent == output / 'commands' and path.suffix == '.json', 'command reference escapes output')
        row = read_json(path)
        require(reference not in records and row['status'] == 'completed' and row['returncode'] == 0 and
                row['cwd'] == str(ROOT) and row['timeoutSeconds'] == 180 and row['started'] <= row['ended'],
                'failed/duplicate command or execution metadata differs')
        for stream in ('stdout', 'stderr'):
            require(Path(row[stream]['path']).parent == output / 'commands' and identity(row[stream]['path']) == row[stream],
                    'command raw bytes changed')
        records[reference] = row
    require(len(report['normal']) == 2 and {row['mode'] for row in report['normal']} == {'baseline', 'protected'}, 'normal denominator differs')
    for run_row in report['normal']:
        row = records[run_row['command']]
        out, err = (Path(row[stream]['path']).read_bytes() for stream in ('stdout', 'stderr'))
        check_jni(out, err)
        require(out.replace(b'\r\n', b'\n') == EXPECTED and row['label'] == 'normal-' + run_row['mode'], 'normal semantics differ')
    require([row['case'] for row in report['runs']] == list(EVENTS), 'observer case denominator differs')
    require(len({row['token'] for row in report['runs']}) == 2, 'observer token reused')
    for run_row in report['runs']:
        row = records[run_row['command']]
        events = validate_run(*(Path(row[stream]['path']).read_bytes() for stream in ('stdout', 'stderr')),
                              run_row['token'], run_row['case'], plan)
        require(events == run_row['events'], 'saved events differ from raw bytes')
        require(row['label'] == run_row['case'] and run_row['token'] in row['argv'], 'observer argv identity differs')
    require(len(report['cleanup']) == 2 and all(reference in records for reference in report['cleanup']), 'cleanup incomplete')
    expected = expected_commands(report, output)
    require([row['label'] for row in records.values()] == list(expected), 'missing/duplicate/out-of-order command label')
    require(all(row['argv'] == expected[row['label']] for row in records.values()), 'exact command argv differs')
    by_label = {row['label']: row for row in records.values()}
    require(plan == rebuild_plan(Path(report['fixture']), Path(by_label['llvm-nm']['stdout']['path']).read_bytes()),
            'plan differs from final APK, exact wrappers or recorded llvm-nm bytes')
    require(report['cleanup'] == report['commands'][-2:] and [records[ref]['label'] for ref in report['cleanup']] ==
            ['remote-remove', 'remote-rmdir'], 'cleanup command binding differs')
    device = {name: Path(by_label['device-' + name]['stdout']['path']).read_bytes().decode('ascii').strip()
              for name in DEVICE_QUERIES}
    require(device == report['device'] and device['model'] and device['pageSize'] == str(PAGE) and device['arch'] == 'aarch64' and
            int(device['sdk']) >= 26, 'raw device identity differs')
    build_report = read_json(Path(report['fixture']) / 'build.json')
    unchanged(build_report['inputsBefore'])
    unchanged(build_report['artifacts'])
    verify_device_report(Path(report['fixture']) / 'device-results.json', Path(report['fixture']), Path(report['sdk']),
                         Path(report['java']), report['serial'], report['serverPort'])
    return report


def verify_results(output):
    output = Path(output).resolve()
    return verify_report(output, read_json(output / 'results.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='phase', required=True)
    build_parser = sub.add_parser('build')
    for name in ('output', 'ndk', 'clang', 'java'):
        build_parser.add_argument('--' + name, type=Path, required=True)
    run_parser = sub.add_parser('run')
    for name in ('fixtures', 'sdk', 'java', 'output'):
        run_parser.add_argument('--' + name, type=Path, required=True)
    run_parser.add_argument('--serial', required=True)
    run_parser.add_argument('--server-port', type=int, default=5037)
    verify_parser = sub.add_parser('verify')
    verify_parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.phase == 'build':
        build(args)
    elif args.phase == 'run':
        run(args)
    else:
        report = verify_results(args.output)
        print(json.dumps({'verified': True, 'cases': [row['case'] for row in report['runs']]}))


if __name__ == '__main__':
    main()
