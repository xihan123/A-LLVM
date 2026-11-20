"""Build, run and replay a signed-APK Java catch/rethrow wrapper lease fixture."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import shlex
import subprocess
import sys
import uuid
import zipfile

import cache_probe as cache
import compiler_lifetime as compiler_contract
import large_fixture
import wrapper_lifetime as wrapper
from lifetime_test import Commands, identity, read_json, require, utc_now, write_json


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/dex2c'))
import device as device_helper
BUDGET = 1 << 20
PAGE = 4096
PRESSURE_COUNT = 14
CPP_FRAME_SLOT_LIMIT = 200000  # Frozen production d2c_open allocation limit.
EXPECTED = b'java-exception:caught=73,rethrown=sentinel,pressure=14\n'
TARGETS = ('exceptionLeaf', 'caughtOuter', 'rethrowOuter')
METHODS = {name: 'sample/Run.' + name + '(Ljava/lang/IllegalStateException;)I' for name in TARGETS}
METHODS.update({f'work{i}': f'sample/Run.work{i}(I)I' for i in range(PRESSURE_COUNT)})
METHODS['marker'] = 'sample/Run.marker()I'
SYMBOLS = {name: 'd2c_' + hashlib.sha256(method.encode()).hexdigest()[:24] for name, method in METHODS.items()}
EVENTS = {'caught': [(1, 0), (2, 1), (3, 0), (4, 0)],
          'rethrow': [(1, 0), (2, 1), (3, 0), (4, 0)]}
CONTROLS = {'reject-substitute': 'sentinel identity differs',
            'reject-pending': 'pending exception at observer entry'}
MESSAGE = 'qseg-java-exception-sentinel-v1'
DEVICE_QUERIES = {'model': ['getprop', 'ro.product.model'], 'sdk': ['getprop', 'ro.build.version.sdk'],
                  'pageSize': ['getconf', 'PAGESIZE'], 'arch': ['uname', '-m']}
NEGATIVES = ('wrong-signer', 'tampered-index', 'tampered-segment', 'missing-segments',
             'compressed-container', 'index-aead', 'segment-aead',
             *(f'authenticated-index-{offset}' for offset in (16, 20, 24, 32, 36, 40)),
             'authenticated-invalid-deflate')
SOURCE_FILES = tuple(dict.fromkeys((*wrapper.SOURCE_FILES,
    'tests/qseg/java_exception.py', 'tests/qseg/java_exception.cpp', 'tests/qseg/test_java_exception.py',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/MethodKey.java',
    'dex2c/core/src/main/java/io/github/xihan123/dex2c/core/Selector.java',
    'dex2c/core/src/main/resources/native/dex2c_runtime.cpp',
    'dex2c/core/src/main/resources/native/dex2c_runtime.h')))



sha = wrapper.sha
fresh = wrapper.fresh
identities = wrapper.identities
unchanged = wrapper.unchanged
tree_files = wrapper.tree_files

def fixture_sources():
    source = large_fixture.fixture_source(PRESSURE_COUNT, 256)
    source = source.replace('public static void main(String[] args) {', 'static void pressureChecks() {', 1)
    source = source.replace('    System.out.println("large-vm=" + checksum);', '', 1)
    extra = r'''  @dex2c static int exceptionLeaf(IllegalStateException supplied) {
    Probe.hit(2,supplied,null); throw supplied;
  }
  @dex2c static int caughtOuter(IllegalStateException supplied) {
    Probe.hit(1,supplied,null);
    try { return exceptionLeaf(supplied); }
    catch(IllegalArgumentException wrong) { return -11; }
    catch(IllegalStateException caught) {
      if(caught!=supplied) return -12;
      Probe.hit(3,supplied,caught); return 73;
    }
  }
  @dex2c static int rethrowOuter(IllegalStateException supplied) {
    Probe.hit(1,supplied,null);
    try { return exceptionLeaf(supplied); }
    catch(IllegalArgumentException wrong) { return -11; }
    catch(IllegalStateException caught) {
      if(caught!=supplied) return -12;
      Probe.hit(3,supplied,caught); throw caught;
    }
  }
  static void checkSentinel(Throwable caught,IllegalStateException supplied) {
    if(caught!=supplied || caught.getClass()!=IllegalStateException.class ||
       !"qseg-java-exception-sentinel-v1".equals(caught.getMessage())) throw new AssertionError("sentinel");
  }
  static int rethrown(IllegalStateException supplied) {
    try { rethrowOuter(supplied); }
    catch(IllegalStateException caught) { checkSentinel(caught,supplied); return 91; }
    throw new AssertionError("outer returned normally");
  }
  public static void main(String[] args) throws Exception {
    IllegalStateException sentinel=new IllegalStateException("qseg-java-exception-sentinel-v1");
    if(args.length==0) {
      pressureChecks();
      if(caughtOuter(sentinel)!=73 || rethrown(sentinel)!=91) throw new AssertionError();
      System.out.println("java-exception:caught=73,rethrown=sentinel,pressure=14"); return;
    }
    if(args.length!=3 || !(args[0].equals("caught") || args[0].equals("rethrow") ||
         args[0].equals("reject-substitute") || args[0].equals("reject-pending")))
      throw new IllegalArgumentException();
    if(marker()!=16 || caughtOuter(sentinel)!=73 || rethrown(sentinel)!=91) throw new AssertionError();
    int mode=args[0].equals("caught")?1:2;
    Probe.configure(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[2])),args[1],mode,sentinel);
    if(args[0].startsWith("reject-")) {
      Probe.reject(args[0].equals("reject-substitute")?1:2,
          args[0].equals("reject-substitute")?new IllegalStateException("qseg-java-exception-sentinel-v1"):sentinel);
      throw new AssertionError("rejection returned");
    }
    Probe.enabled=true;
    int first=mode==1?caughtOuter(sentinel):rethrown(sentinel);
    Probe.enabled=false;
    if(first!=(mode==1?73:91)) throw new AssertionError("first semantics");
    Probe.observe(4,sentinel,mode==1?null:sentinel);
    int again=mode==1?caughtOuter(sentinel):rethrown(sentinel);
    Probe.finish(first,again);
  }
'''
    require(source.endswith('}\n'), 'unexpected large fixture source')
    source = source[:-2] + extra + '}\n'
    probe = '''package sample;
final class Probe {
  static boolean enabled;
  static void hit(int event,Throwable supplied,Throwable caught) { if(enabled) observe(event,supplied,caught); }
  static native void configure(byte[] plan,String token,int mode,Throwable sentinel);
  static native void observe(int event,Throwable supplied,Throwable caught);
  static native void finish(int first,int again);
  static native void reject(int kind,Throwable value);
}
'''
    return source, probe


REGISTRATION_END = ('jint status=env->RegisterNatives(cls,methods,2);env->DeleteLocalRef(cls);'
                    'return status==0?JNI_VERSION_1_6:JNI_ERR;')


def inject_registration(text):
    require(text.count(REGISTRATION_END) == 1 and text.count('jint JNICALL JNI_OnLoad(') == 1,
            'unknown or ambiguous JNI_OnLoad registration insertion point')
    require('java_exception' not in text, 'probe already inserted')
    return '#include "java_exception.cpp"\n' + text.replace(
        REGISTRATION_END, 'jint status=env->RegisterNatives(cls,methods,2);env->DeleteLocalRef(cls);'
        'if(status!=0 || java_exception_register(env)!=0)return JNI_ERR;return JNI_VERSION_1_6;', 1)


RUNNER = r'''
import io.github.xihan123.dex2c.core.Transformer;
import io.github.xihan123.dex2c.core.NativeCompiler;
import io.github.xihan123.dex2c.runtime.Dex2cRuntime;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import javax.tools.ToolProvider;
public class JavaExceptionFixture {
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
    if(text.indexOf(end)<0 || text.indexOf(end)!=text.lastIndexOf(end) || text.contains("java_exception"))
      throw new IllegalStateException("unknown registration insertion point");
    Files.writeString(out.resolve("registration-before.cpp"),text);
    String changed="#include \"java_exception.cpp\"\n"+text.replace(end,__AFTER__);
    Files.writeString(registration,changed);
    for(String name:List.of("java_exception.cpp","qseg.h","sha256.h"))
      Files.copy(out.resolve(name),generated.resolve(name));
    Files.writeString(out.resolve("runtime-path.txt"),Path.of(Dex2cRuntime.class.getProtectionDomain()
      .getCodeSource().getLocation().toURI()).toString());
    new NativeCompiler().compile(generated,out.resolve("native"),Path.of(args[1]),Path.of(args[2]),
      "dex2c_semantics",26,out.resolve("test.der"),Path.of(args[3]),true,true);
    classpath(out.resolve("classpath-after.tsv"));
  }
}
'''


long_build = wrapper.long_build
snapshot_runtime = wrapper.snapshot_runtime

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
        after = REGISTRATION_END.split('return status')[0] + ('if(status!=0 || java_exception_register(env)!=0)'
                'return JNI_ERR;return JNI_VERSION_1_6;')
        runner = RUNNER.replace('__END__', json.dumps(REGISTRATION_END)).replace('__AFTER__', json.dumps(after))
        (output / 'JavaExceptionFixture.java').write_text(runner, 'utf-8')
        for source_path, name in ((Path(__file__).with_suffix('.cpp'), 'java_exception.cpp'),
                                  (ROOT / 'runtime/qseg.h', 'qseg.h'), (ROOT / 'runtime/sha256.h', 'sha256.h')):
            (output / name).write_bytes(source_path.read_bytes())
        commands.checked('keytool-generate', [java.with_name('keytool.exe'), '-genkeypair', '-keystore', output / 'test.jks',
                         '-storepass', 'android', '-keypass', 'android', '-alias', 'test', '-keyalg', 'RSA',
                         '-dname', 'CN=qseg Java exception fixture', '-validity', '3650', '-noprompt'])
        commands.checked('keytool-export', [java.with_name('keytool.exe'), '-exportcert', '-keystore', output / 'test.jks',
                         '-storepass', 'android', '-alias', 'test', '-file', output / 'test.der'])
        task_args = [output, ndk, clang, Path(sys.executable).resolve()]
        init = output / 'fixture.init.gradle'
        init.write_text('''gradle.projectsEvaluated {
    def core = gradle.rootProject.project(':core')
    core.tasks.register('qsegJavaExceptionFixture', JavaExec) {
        dependsOn core.tasks.named('testClasses')
        classpath = core.sourceSets.test.runtimeClasspath
        executable = %s
        mainClass = %s
        args %s
    }
}
''' % (json.dumps(str(java)), json.dumps(str(output / 'JavaExceptionFixture.java')),
       ', '.join(json.dumps(str(value)) for value in task_args)), 'utf-8')
        # JAVA_HOME is set directly; no shared Gradle/project configuration is edited.
        old_java_home = os.environ.get('JAVA_HOME')
        os.environ['JAVA_HOME'] = str(java.parent.parent)
        try:
            long_build(commands, [ROOT / 'dex2c/gradlew.bat', '-I', init, ':core:qsegJavaExceptionFixture',
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


nounwind = wrapper.nounwind
final_wrapper_paths = wrapper.final_wrapper_paths


def cpp_function(text, signature):
    """Extract one exact emitted function, retaining its complete source binding."""
    require(text.count(signature) == 1, 'missing/duplicate generated C++ function: ' + signature)
    start = text.index(signature)
    opening = start + len(signature) - 1
    require(text[opening] == '{', 'function signature must include opening brace')
    depth, quote, escaped = 1, None, False
    for end in range(opening + 1, len(text)):
        char = text[end]
        if quote:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if not depth:
                return text[start:end + 1], text[opening + 1:end]
    raise ValueError('unterminated generated C++ function')


def cpp_compact(raw):
    """Remove layout whitespace without changing any quoted C++ literal bytes."""
    output, quote, escaped = [], None, False
    for char in raw:
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
            output.append(char)
        elif not char.isspace():
            output.append(char)
    require(quote is None, 'unterminated generated C++ literal')
    return ''.join(output)


def cpp_program(body):
    """Recognize only the scalar/reference subset emitted for these three methods."""
    code, labels = [], {}
    patterns = (
        ('open', r'd2c_frame\*f=d2c_open\(env,owner,(0|[1-9][0-9]*)\);'),
        ('guard', r'if\(!f\)return0;'),
        ('argument', r'd2c_ref\(f,0,env->NewLocalRef\(a0\)\);'),
        ('check', r'if\(env->ExceptionCheck\(\)\)goto(E\d+|failed);'),
        ('copy', r'd2c_copy\(f,(0|[1-9][0-9]*),(0|[1-9][0-9]*)\);'),
        ('int', r'd2c_i\(f,(0|[1-9][0-9]*),(0|-?[1-9][0-9]*)\);'),
        ('null', r'd2c_ref\(f,(0|[1-9][0-9]*),nullptr\);'),
        ('invoke', r'd2c_invoke\(f,(0|[1-9][0-9]*),"([^"]+)","([^"]+)","([^"]+)",(0|[1-9][0-9]*),(0|[1-9][0-9]*)\);'),
        ('throw', r'd2c_throw\(f,f->slots\[(0|[1-9][0-9]*)\]\.v\.l\);'),
        ('catch', r'if\(d2c_catch\(f,"([^"]+)",(0|[1-9][0-9]*)\)\)goto(L\d+);'),
        ('identity', r'if\((!?)env->IsSameObject\(f->slots\[(0|[1-9][0-9]*)\]\.v\.l,f->slots\[(0|[1-9][0-9]*)\]\.v\.l\)\)goto(L\d+);'),
        ('goto', r'goto(L\d+|failed);'),
        ('return', r'\{jintresult=\(jint\)f->slots\[(0|[1-9][0-9]*)\]\.v\.i;d2c_close\(f,nullptr\);returnresult;\}'),
        ('failed', r'failed:d2c_close\(f,nullptr\);return0;'),
    )
    current_label = None
    for raw in body.splitlines():
        line = cpp_compact(raw)
        if not line:
            continue
        if re.fullmatch(r'[LE]\d+:;', line):
            current_label = line[:-2]
            require(current_label not in labels, 'duplicate C++ block label')
            labels[current_label] = len(code)
            continue
        found = [(kind, match.groups()) for kind, pattern in patterns
                 if (match := re.fullmatch(pattern, line))]
        require(len(found) == 1, 'unknown generated C++ statement: ' + raw)
        kind, operands = found[0]
        code.append((kind, operands, current_label))
        if kind == 'failed':
            require('failed' not in labels, 'duplicate C++ failed block')
            labels['failed'] = len(code) - 1
    require([row[0] for row in code[:4]] == ['open', 'guard', 'argument', 'check'] and
            code[3][1] == ('failed',) and code[-1][0] == 'failed', 'generated C++ entry/exit differs')
    require(sum(row[0] == 'open' for row in code) == 1 and
            sum(row[0] == 'guard' for row in code) == 1 and
            sum(row[0] == 'argument' for row in code) == 1 and
            sum(row[0] == 'failed' for row in code) == 1, 'generated C++ entry/exit repeated')
    frame_count = int(code[0][1][0])
    require(0 <= frame_count <= CPP_FRAME_SLOT_LIMIT, 'generated C++ frame exceeds production limit')
    for index, (kind, operands, label) in enumerate(code):
        used_slots = ()
        if kind == 'argument':
            used_slots = (0,)
        elif kind == 'copy':
            used_slots = tuple(map(int, operands))
        elif kind in ('int', 'null', 'throw', 'return'):
            used_slots = (int(operands[0]),)
        elif kind == 'catch':
            used_slots = (int(operands[1]),)
        elif kind == 'identity':
            used_slots = (int(operands[1]), int(operands[2]))
        elif kind == 'invoke':
            target, call_kind, count = int(operands[0]), int(operands[4]), int(operands[5])
            require(call_kind == 0, 'fixture call is not static')
            require(0 <= target < frame_count and count <= frame_count - target,
                    'generated C++ invocation slots outside frame')
            used_slots = (target,)
        require(all(0 <= slot < frame_count for slot in used_slots), 'generated C++ slot outside frame')
        if kind in ('check', 'catch', 'identity', 'goto'):
            require(operands[-1] in labels, 'missing generated C++ branch label')
        if kind in ('copy', 'invoke', 'throw'):
            require(label and label.startswith('L') and index + 1 < len(code) and
                    code[index + 1][:2] == ('check', ('E' + label[1:],)),
                    'missing immediate generated ExceptionCheck edge')
    return code, labels


def cpp_trace(program, leaf_outcome):
    """Replay recognized statements; JNI references keep object identity, not pointer spelling."""
    code, labels = program
    slots, origins, pending, events, event_sources, dispatch, thrown, throw_sources = {}, {}, None, [], [], [], [], []
    pc, steps = 0, 0
    while True:
        require(0 <= pc < len(code) and steps < len(code) * 3, 'nonterminating generated C++ path')
        steps += 1
        kind, operands, _ = code[pc]
        pc += 1
        if kind in ('open', 'guard'):
            continue
        if kind == 'argument':
            slots[0] = 'sentinel'
            origins[0] = 'supplied'
        elif kind == 'copy':
            target, source = map(int, operands)
            require(source in slots, 'generated C++ reads undefined slot')
            slots[target] = slots[source]
            origins[target] = origins[source]
        elif kind == 'int':
            slots[int(operands[0])] = int(operands[1])
            origins[int(operands[0])] = None
        elif kind == 'null':
            slots[int(operands[0])] = None
            origins[int(operands[0])] = None
        elif kind == 'invoke':
            target, owner, name, descriptor, call_kind, count = operands
            target, call_kind, count = int(target), int(call_kind), int(count)
            require(call_kind == 0, 'fixture call is not static')
            require(all(target + i in slots for i in range(count)), 'undefined generated invocation argument')
            arguments = [slots[target + i] for i in range(count)]
            if (owner, name, descriptor, count) == ('sample/Probe', 'hit', '(ILjava/lang/Throwable;Ljava/lang/Throwable;)V', 3):
                require(pending is None, 'Probe hit with pending exception')
                events.append(arguments)
                event_sources.append([origins[target + i] for i in range(count)])
            else:
                require((owner, name, descriptor, count) ==
                        ('sample/Run', 'exceptionLeaf', '(Ljava/lang/IllegalStateException;)I', 1) and
                        arguments == ['sentinel'] and origins[target] == 'supplied' and pending is None,
                        'wrong leaf invocation binding')
                slots[target] = 0
                origins[target] = None
                pending = None if leaf_outcome == 'normal' else leaf_outcome
        elif kind == 'throw':
            pending = slots.get(int(operands[0]))
            require(pending in ('sentinel', 'substitute', 'wrong-type'), 'wrong generated rethrow reference')
            thrown.append(pending)
            throw_sources.append(origins[int(operands[0])])
        elif kind == 'check':
            if pending is not None:
                pc = labels[operands[0]]
        elif kind == 'catch':
            exception_type, slot, target = operands
            require(pending is not None and exception_type in
                    ('java/lang/IllegalArgumentException', 'java/lang/IllegalStateException'), 'unknown catch dispatch')
            actual = 'java/lang/IllegalArgumentException' if pending == 'wrong-type' else 'java/lang/IllegalStateException'
            matched = actual == exception_type
            dispatch.append([exception_type, matched])
            if matched:
                slots[int(slot)], pending = pending, None
                origins[int(slot)] = 'caught'
                pc = labels[target]
        elif kind == 'identity':
            negate, left, right, target = operands
            require(int(left) in slots and int(right) in slots and pending is None, 'invalid identity comparison')
            require({origins[int(left)], origins[int(right)]} == {'supplied', 'caught'},
                    'identity branch is not caught versus supplied')
            same = slots[int(left)] == slots[int(right)]
            if same != bool(negate):
                pc = labels[target]
        elif kind == 'goto':
            pc = labels[operands[0]]
        elif kind == 'return':
            require(pending is None and int(operands[0]) in slots, 'return with pending/undefined value')
            return {'exit': 'return', 'value': slots[int(operands[0])], 'pending': pending,
                    'events': events, 'eventSources': event_sources, 'dispatch': dispatch,
                    'throws': thrown, 'throwSources': throw_sources}
        elif kind == 'failed':
            return {'exit': 'failed', 'value': 0, 'pending': pending,
                    'events': events, 'eventSources': event_sources, 'dispatch': dispatch,
                    'throws': thrown, 'throwSources': throw_sources}


def bind_exception_cpp(text, name):
    signature = 'extern "C" D2C_PROTECTED jint ' + SYMBOLS[name] + '(JNIEnv* env, jclass owner, jobject a0) {'
    full, body = cpp_function(text, signature)
    program = cpp_program(body)
    code, labels = program
    throws = [i for i, row in enumerate(code) if row[0] == 'throw']
    invokes = [i for i, row in enumerate(code) if row[0] == 'invoke']
    require(len(throws) == (0 if name == 'caughtOuter' else 1) and
            len(invokes) == (1 if name == 'exceptionLeaf' else 3), 'exception method call/throw denominator differs')
    for index in throws:
        edge = code[index + 1][1][0]
        require(code[labels[edge]][:2] == ('goto', ('failed',)), 'throw edge must close failed frame')
    traces = {}
    if name == 'exceptionLeaf':
        require(not any(row[0] in ('catch', 'identity', 'return') for row in code), 'leaf gained handler/success return')
        trace = cpp_trace(program, 'sentinel')
        require(trace == {'exit': 'failed', 'value': 0, 'pending': 'sentinel',
                          'events': [[2, 'sentinel', None]], 'eventSources': [[None, 'supplied', None]],
                          'dispatch': [], 'throws': ['sentinel'], 'throwSources': ['supplied']},
                'leaf must hit event2 then throw supplied sentinel')
        traces['sentinel'] = trace
    else:
        require(sum(row[0] == 'identity' for row in code) == 1, 'missing/duplicate caught identity branch')
        leaf_calls = [i for i in invokes if code[i][1][1:4] ==
                      ('sample/Run', 'exceptionLeaf', '(Ljava/lang/IllegalStateException;)I')]
        require(len(leaf_calls) == 1, 'missing/duplicate exact leaf call')
        edge = code[leaf_calls[0] + 1][1][0]
        at = labels[edge]
        require([row[0] for row in code[at:at + 3]] == ['catch', 'catch', 'goto'] and
                [row[1][0] for row in code[at:at + 2]] ==
                ['java/lang/IllegalArgumentException', 'java/lang/IllegalStateException'] and
                code[at][1][1] == code[at + 1][1][1] and code[at + 2][1] == ('failed',),
                'leaf ExceptionCheck handler order/types differ')
        for outcome in ('sentinel', 'wrong-type', 'substitute', 'normal'):
            trace = cpp_trace(program, outcome)
            success = outcome == 'sentinel'
            expected_exit = 'failed' if success and name == 'rethrowOuter' else 'return'
            expected_value = 0 if expected_exit == 'failed' or outcome == 'normal' else 73 if success else -11 if outcome == 'wrong-type' else -12
            expected_pending = 'sentinel' if expected_exit == 'failed' else None
            expected_dispatch = ([] if outcome == 'normal' else
                                 [['java/lang/IllegalArgumentException', True]] if outcome == 'wrong-type' else
                                 [['java/lang/IllegalArgumentException', False], ['java/lang/IllegalStateException', True]])
            require(trace == {'exit': expected_exit, 'value': expected_value, 'pending': expected_pending,
                              'events': [[1, 'sentinel', None]] + ([[3, 'sentinel', 'sentinel']] if success else []),
                              'eventSources': [[None, 'supplied', None]] + ([[None, 'supplied', 'caught']] if success else []),
                              'dispatch': expected_dispatch,
                              'throws': ['sentinel'] if expected_exit == 'failed' else [],
                              'throwSources': ['caught'] if expected_exit == 'failed' else []},
                    'generated catch/identity/return/rethrow path differs: ' + name + '/' + outcome)
            traces[outcome] = trace
    return {'sha256': sha(full.encode()), 'source': full, 'paths': traces}


def bind_generated_cpp(fixture):
    generated = fixture / 'generated'
    source, probe = fixture_sources()
    require((fixture / 'Run.java').read_text('utf-8') == source and
            (fixture / 'Probe.java').read_text('utf-8') == probe, 'preserved Java fixture source differs')
    before = (fixture / 'classpath-before.tsv').read_bytes()
    require(before == (fixture / 'classpath-after.tsv').read_bytes(), 'actual compilation classpath changed')
    runtime_resource = 'native/dex2c_runtime.cpp'
    resources, seen = [], set()
    for line in before.decode('utf-8').splitlines():
        path, size, digest = line.rsplit('\t', 2)
        bound = identity(path)
        require(path not in seen and bound['bytes'] == int(size) and bound['sha256'] == digest,
                'classpath file missing/duplicate/changed')
        seen.add(path)
        file = Path(path)
        if file.as_posix().endswith('/' + runtime_resource):
            resources.append(({'path': str(file), 'sha256': digest}, file.read_bytes()))
        elif file.suffix.lower() == '.jar':
            with zipfile.ZipFile(file) as archive:
                require(len(archive.namelist()) == len(set(archive.namelist())), 'duplicate classpath JAR member')
                if runtime_resource in archive.namelist():
                    resources.append(({'path': str(file), 'entry': runtime_resource, 'sha256': digest}, archive.read(runtime_resource)))
    require(len(resources) == 1, 'actual classpath runtime resource missing/ambiguous')
    actual_identity, actual_bytes = resources[0]
    production = ROOT / 'dex2c/core/src/main/resources/native/dex2c_runtime.cpp'
    require(actual_bytes == production.read_bytes(), 'actual classpath runtime differs from frozen production resource')
    emitted = (generated / 'protected.cpp').read_text('utf-8')
    runtime = (generated / 'dex2c_runtime.cpp').read_text('utf-8')
    runtime_bindings = {}
    for name, signature in (('d2c_throw', 'void d2c_throw(d2c_frame* f,jobject throwable) {'),
                            ('d2c_catch', 'bool d2c_catch(d2c_frame* f,const char* type,int slot) {')):
        actual, _ = cpp_function(actual_bytes.decode('utf-8').replace('\r\n', '\n'), signature)
        generated_function, _ = cpp_function(runtime, signature)
        require(generated_function == actual, 'generated exception runtime differs: ' + name)
        runtime_bindings[name] = {'sha256': sha(actual.encode()), 'source': actual}
    common = {'generated': identity(generated / 'protected.cpp'),
              'runtimeGenerated': identity(generated / 'dex2c_runtime.cpp'),
              'runtimeProduction': identity(production), 'runtimeClasspath': actual_identity,
              'runtimeFunctions': runtime_bindings,
              'classes': identities([fixture / 'classes/sample/Run.class', fixture / 'classes/sample/Probe.class'])}
    return {name: {**bind_exception_cpp(emitted, name), **common} for name in TARGETS}


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
    cpp = bind_generated_cpp(fixture)
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
        if name in cpp:
            bound[name]['cppBinding'] = cpp[name]
    require(len({item['id'] for item in bound.values()}) == len(bound), 'duplicate VM resource IDs')
    return bound


def authenticated_methods(contract, receipt, resources):
    require(set(contract) == set(METHODS), 'authenticated method denominator differs')
    selected = {}
    for name in METHODS:
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
        selected[name] = item
    require(len({item['id'] for item in selected.values()}) == len(METHODS), 'duplicate authenticated method ID')
    vm_chunks = [row for row in receipt['segments'] if row['kind'] == 1]
    require(len(vm_chunks) == sum(len(item['chunks']) for item in selected.values()) and
            {row['id'] for row in vm_chunks} == {item['id'] for item in selected.values()},
            'authenticated VM chunk denominator differs')
    return selected


def observed_resources(methods, receipt):
    selected = [dict(methods[name]) for name in (*TARGETS, *(f'work{i}' for i in range(PRESSURE_COUNT)))]
    require(all(selected[0]['mappedBytes'] + selected[index]['mappedBytes'] <= BUDGET for index in (1, 2)),
            'target set exceeds idle budget')
    require(all(0 < item['mappedBytes'] <= BUDGET for item in selected[3:]), 'pressure resource exceeds budget')
    require(sum(item['mappedBytes'] for item in selected[3:]) > BUDGET, 'other pressure VMs must exceed idle budget')
    require(any(row['codec'] == 1 for row in receipt['segments']), 'fixture needs a compressed chunk for auth negatives')
    return selected


def select_resources(contract, receipt, resources):
    return observed_resources(authenticated_methods(contract, receipt, resources), receipt)


def encode_plan(plan):
    resources, spans = plan['resources'], plan['executableSpans']
    require(len(resources) == 17 and 0 < len(spans) <= 8, 'unexpected fixed plan counts')
    data = bytearray(struct.pack('<8sIIIIQ', b'QJEX01\0\0', PAGE, BUDGET, len(resources), len(spans), plan['onloadRva']))
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
    receipt = read_json(native / 'segments.json')
    methods = authenticated_methods(contract, receipt, raw)
    resources = observed_resources(methods, receipt)
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
            'pageSize': PAGE, 'idleBudgetBytes': BUDGET, 'methodBindings': methods, 'resources': resources,
            'executableSpans': spans, 'onloadRva': symbols['JNI_OnLoad']}


check_jni = wrapper.check_jni

def expected_active(case, event, plan):
    resources = plan['resources']
    require(case in EVENTS and event in (0, 1, 2, 3, 4, 10), 'unknown expected event')
    outer = 1 if case == 'caught' else 2
    indices = [outer, 0] if event == 2 else [outer] if event in (1, 3) else []
    return sum(resources[index]['mappedBytes'] for index in indices)


def event_records(stdout, token, case):
    require(re.fullmatch('[0-9a-f]{32}', token) and case in EVENTS, 'invalid run identity')
    stdout = stdout.replace(b'\r\n', b'\n')
    require(stdout.endswith(b'\n') and b'\r' not in stdout, 'incomplete observer stdout')
    rows = []
    for line in stdout.split(b'\n')[:-1]:
        require(line.startswith(b'QSEG_JAVA_EXCEPTION:'), 'unexpected observer stdout')
        row = json.loads(line[len(b'QSEG_JAVA_EXCEPTION:'):], object_pairs_hook=compiler_contract.unique_object)
        require(type(row) is dict and row.get('token') == token and row.get('case') == case and
                row.get('seq') == len(rows), 'event identity/order differs')
        keys = {'token', 'case', 'seq', 'event', 'depth', 'active', 'idle', 'pinned', 'peak', 'evictions',
                'targetLoans', 'pendingClear', 'sentinelIdentity', 'caughtIdentity'}
        event = row.get('event')
        if event in (1, 2, 3, 4):
            keys |= {'steps', 'readonly', 'digests'}
        if event in (1, 2):
            keys |= {'discovered', 'discoveredBegin', 'discoveredBytes'}
        if event in (3, 4):
            keys |= {'reclaimed', 'oldBegin', 'oldBytes', 'releasedReadonly', 'absent'}
        if event == 10:
            keys |= {'first', 'again', 'semanticReentry'}
        require(row.keys() == keys, 'observer event field denominator differs')
        for field in ('seq', 'event', 'depth', 'active', 'idle', 'pinned', 'peak', 'evictions', 'targetLoans'):
            require(type(row[field]) is int and row[field] >= 0, 'invalid observer numeric field: ' + field)
        require(row['pendingClear'] is True and row['sentinelIdentity'] is True and
                row['caughtIdentity'] is (event == 3 or (event == 4 and case == 'rethrow')),
                'pending exception or sentinel/caught identity differs')
        require(row['pinned'] == 0 and row['targetLoans'] == 0 and row['idle'] <= BUDGET and
                row['peak'] >= row['active'] + row['idle'], 'cache/target loan evidence differs')
        rows.append(row)
    return rows


def validate_run(stdout, stderr, token, case, plan):
    check_jni(stdout, stderr)
    rows = event_records(stdout, token, case)
    require(len(rows) == len(EVENTS[case]) + 2 and rows[0]['event'] == 0 and rows[-1]['event'] == 10,
            'missing configure/events/COMPLETE')
    require([(row['event'], row['depth']) for row in rows[1:-1]] == EVENTS[case], 'wrapper event sequence differs')
    require(rows[0]['active'] == 0 and rows[0]['depth'] == 0 and rows[-1]['depth'] == 0,
            'configure/finish active/depth differs')
    discovered, reclaimed, intervals = {}, [], []
    last_evictions = rows[0]['evictions']
    last_peak = rows[0]['peak']
    for row in rows[1:-1]:
        require(row['active'] == expected_active(case, row['event'], plan) and
                row['evictions'] > last_evictions and row['peak'] >= last_peak and
                row['readonly'] is True and row['digests'] is True, 'pressure/lease/mapping evidence differs')
        last_evictions, last_peak = row['evictions'], row['peak']
        reclaim = row['event'] in (3, 4)
        require(type(row['steps']) is int and
                ((1 <= row['steps'] <= PRESSURE_COUNT) if reclaim else row['steps'] == PRESSURE_COUNT),
                'pressure coverage differs')
        if row['event'] in (1, 2):
            index = 0 if row['event'] == 2 else 1 if case == 'caught' else 2
            resource = plan['resources'][index]
            require(row['discovered'] == resource['id'] and type(row['discoveredBegin']) is str and
                    re.fullmatch('0x[0-9a-f]+', row['discoveredBegin']) and
                    0 < int(row['discoveredBegin'], 16) < 1 << 64 and
                    int(row['discoveredBegin'], 16) % PAGE == 0 and type(row['discoveredBytes']) is int and
                    row['discoveredBytes'] == resource['mappedBytes'], 'first discovered target interval differs')
            begin = int(row['discoveredBegin'], 16)
            require(begin + row['discoveredBytes'] <= 1 << 64, 'discovered interval overflows')
            discovered[resource['id']] = (begin, row['discoveredBytes'])
        if reclaim:
            index = 0 if row['event'] == 3 else 1 if case == 'caught' else 2
            require(row['reclaimed'] == plan['resources'][index]['id'] and row['absent'] is True and
                    type(row['oldBegin']) is str and re.fullmatch('0x[0-9a-f]+', row['oldBegin']) and
                    0 < int(row['oldBegin'], 16) < 1 << 64 and
                    int(row['oldBegin'], 16) % PAGE == 0 and type(row['oldBytes']) is int and
                    row['oldBytes'] == plan['resources'][index]['mappedBytes'] and row['releasedReadonly'] is True,
                    'missing exact released target interval absence')
            reclaimed.append(row['reclaimed'])
            begin = int(row['oldBegin'], 16)
            require(begin + row['oldBytes'] <= 1 << 64, 'released interval overflows')
            require(discovered.get(row['reclaimed']) == (begin, row['oldBytes']),
                    'released interval differs from first discovered target')
            intervals.append((begin, begin + row['oldBytes']))
    require(len(reclaimed) == 2 and len(set(reclaimed)) == 2 and
            (intervals[0][1] <= intervals[1][0] or intervals[1][1] <= intervals[0][0]),
            'target reclamation coverage/intervals differ')
    last = rows[-1]
    expected = 73 if case == 'caught' else 91
    require(type(last['first']) is int and type(last['again']) is int and
            last['first'] == expected and last['again'] == expected and last['active'] == 0 and
            last['semanticReentry'] is True and last['evictions'] >= last_evictions and last['peak'] >= last_peak,
            'real wrapper reentry failed')
    return rows


def control_command(adb, remote, case, token):
    require(case in CONTROLS and re.fullmatch('[0-9a-f]{32}', token), 'invalid control identity')
    target = remote + '/protected.apk'
    child = ['/system/bin/app_process', '-Xcheck:jni', '-Djava.library.path=' + target + '!/lib/arm64-v8a',
             '/system/bin', 'sample.Run', case, token, remote + '/plan.bin']
    failed = "printf '%s\\n' " + shlex.quote(token + ':LAUNCH_FAILED') + ' >&2'
    shell = ('if [ ! -x /system/bin/app_process ]; then ' + failed + '; exit 0; fi\n' +
             "printf '%s\\n' " + shlex.quote(token + ':BEGIN') + ' >&2\n' +
             '( trap ' + shlex.quote(failed) + ' 0\n' +
             '  CLASSPATH=' + shlex.quote(target) + ' exec ' + shlex.join(child) + '\n)\n' +
             "child_status=$?\nprintf '\\n%s:%s\\n' " + shlex.quote(token + ':EXIT') +
             ' "$child_status" >&2\nexit 0')
    return [*map(str, adb), 'shell', shell], child


def validate_control(stdout, stderr, token, case):
    require(case in CONTROLS, 'unknown observer control')
    check_jni(stdout, stderr)
    rows = event_records(stdout, token, 'rethrow')
    require(len(rows) == 1 and rows[0]['event'] == 0 and rows[0]['depth'] == 0 and rows[0]['active'] == 0,
            'control did not complete exact hooks-off configure')
    normalized = stderr.replace(b'\r\n', b'\n')
    expected = [token + ':BEGIN', 'QSEG_JAVA_EXCEPTION_CONTROL:' + token + ':' + case + ':ATTEMPT',
                'QSEG_JAVA_EXCEPTION_FAIL:' + token + ':' + CONTROLS[case], '', token + ':EXIT:125']
    require(normalized.endswith(b'\n') and normalized.decode('utf-8', 'strict').splitlines() == expected,
            'control launch/attempt/diagnostic/child exit protocol differs')
    return {'case': case, 'token': token, 'rejected': True, 'status': 'expected-exit-signature',
            'exitCode': 125, 'diagnostic': CONTROLS[case], 'configure': rows[0]}


def verify_device_report(path, fixture, sdk, java, serial, port):
    path, fixture, sdk, java = (Path(value).resolve() for value in (path, fixture, sdk, java))
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
            streams = []
            for stream in ('stdout', 'stderr'):
                raw = base64.b64decode(stage[stream + 'Base64'], validate=True)
                require(raw.decode('utf-8', 'replace') == stage[stream], 'negative raw stream differs')
                streams.append(raw)
            check_jni(*streams)
        require(execution['status'] == 'completed' and device_helper.negative_status(execution, row['protocolToken'], [127]) ==
                ('expected-exit-signature', 127), 'negative raw protocol did not prove child exit 127')
        artifact = row['artifact']
        require(Path(artifact['path']).resolve() == fixture / (row['mode'] + '.apk') and
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


app_argv = wrapper.app_argv

def expected_commands(report, output):
    output = Path(output).resolve()
    fixture, sdk = Path(report['fixture']).resolve(), Path(report['sdk']).resolve()
    adb = [str(sdk / 'platform-tools/adb.exe'), '-P', str(report['serverPort']), '-s', report['serial']]
    remote = report['remote']
    expected = {'device-' + name: [*adb, 'shell', *argv] for name, argv in DEVICE_QUERIES.items()}
    expected['llvm-nm'] = [str(Path(report['ndk']).resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe'),
                           '--defined-only', str(fixture / 'native/linked.so')]
    expected['remote-mkdir'] = [*adb, 'shell', 'mkdir', remote]
    for source, name in ((fixture / 'protected.apk', 'protected.apk'), (fixture / 'baseline.zip', 'baseline.zip'),
                          (output / 'plan.bin', 'plan.bin')):
        expected['push-' + name.replace('.', '-')] = [*adb, 'push', str(source), remote + '/' + name]
    for name, dex in (('baseline', 'baseline.zip'), ('protected', 'protected.apk')):
        expected['normal-' + name] = app_argv(adb, remote, dex)
    for row in report['runs']:
        expected[row['case']] = app_argv(adb, remote, 'protected.apk', [row['case'], row['token'], remote + '/plan.bin'])
    for row in report['controlNegatives']:
        expected[row['case']] = control_command(adb, remote, row['case'], row['token'])[0]
    expected['remote-remove'] = [*adb, 'shell', 'rm', '-f', *(remote + '/' + name for name in ('protected.apk', 'baseline.zip', 'plan.bin'))]
    expected['remote-rmdir'] = [*adb, 'shell', 'rmdir', remote]
    return expected


def run(args):
    output, fixture = fresh(args.output), args.fixtures.resolve()
    commands = Commands(output, ROOT)
    report = {'schemaVersion': 1, 'checkerRevision': 1, 'scope': 'signed APK Java catch/rethrow ART/JNI wrapper lease',
              'productionWrapperExecution': True, 'callRoute': 'ART/JNI', 'nativeDirectHandlerExecution': False,
              'directWipeObservation': False, 'commands': commands.records, 'runs': [], 'controlNegatives': [], 'cleanup': []}
    pushed, remote, adb = [], None, []
    error = None
    try:
        build_report = read_json(fixture / 'build.json')
        unchanged(build_report['inputsBefore'])
        unchanged(build_report['artifacts'])
        unchanged(build_report['classpathInputs'])
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
        remote = '/data/local/tmp/qseg-java-exception-' + uuid.uuid4().hex
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
        for case in CONTROLS:
            token = uuid.uuid4().hex
            argv, child = control_command(adb, remote, case, token)
            stdout, stderr = commands.checked(case, argv)
            control = validate_control(stdout, stderr, token, case)
            report['controlNegatives'].append({**control, 'command': commands.records[-1], 'childArgv': child,
                                               'environment': {'CLASSPATH': remote + '/protected.apk'}})
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
    output = Path(output).resolve()
    require(not (output / 'failure.json').exists(), 'failure report accompanies success')
    require(report['schemaVersion'] == 1 and report['checkerRevision'] == 1 and report['callRoute'] == 'ART/JNI' and
            report['scope'] == 'signed APK Java catch/rethrow ART/JNI wrapper lease' and
            report.get('status') == 'passed' and
            report['productionWrapperExecution'] is True and report['nativeDirectHandlerExecution'] is False and
            report['directWipeObservation'] is False, 'report scope differs')
    require(report['inputsBefore'] == report['inputsAfter'], 'input identities changed')
    unchanged(report['inputsBefore'])
    unchanged(report['artifacts'])
    require(Path(report['plan']['path']).resolve() == output / 'plan.json' and
            Path(report['binaryPlan']['path']).resolve() == output / 'plan.bin',
            'plan path differs from exact output')
    require(identity(report['plan']['path']) == report['plan'] and identity(report['binaryPlan']['path']) == report['binaryPlan'],
            'plan bytes changed')
    plan = read_json(report['plan']['path'])
    require(Path(report['binaryPlan']['path']).read_bytes() == encode_plan(plan), 'binary/JSON plans differ')
    require(re.fullmatch('/data/local/tmp/qseg-java-exception-[0-9a-f]{32}', report['remote']) and report['serial'] and
            type(report['serverPort']) is int and 1 <= report['serverPort'] <= 65535, 'invalid device/remote identity')
    records = {}
    for reference in report['commands']:
        path = (output / reference).resolve()
        require(path.parent == output / 'commands' and path.suffix == '.json',
                'command reference escapes output')
        row = read_json(path)
        require(reference not in records and row['status'] == 'completed' and row['returncode'] == 0 and
                row['cwd'] == str(ROOT) and row['timeoutSeconds'] == 180 and row['started'] <= row['ended'],
                'failed/duplicate command or execution metadata differs')
        for stream in ('stdout', 'stderr'):
            stream_path = Path(row[stream]['path']).resolve()
            require(stream_path.parent == output / 'commands' and identity(stream_path) == row[stream],
                    'command raw bytes changed')
        records[reference] = row
    require([row['mode'] for row in report['normal']] == ['baseline', 'protected'], 'normal denominator differs')
    for run_row in report['normal']:
        row = records[run_row['command']]
        out, err = (Path(row[stream]['path']).read_bytes() for stream in ('stdout', 'stderr'))
        check_jni(out, err)
        require(out.replace(b'\r\n', b'\n') == EXPECTED and row['label'] == 'normal-' + run_row['mode'], 'normal semantics differ')
    require([row['case'] for row in report['runs']] == list(EVENTS), 'observer case denominator differs')
    require([row['case'] for row in report['controlNegatives']] == list(CONTROLS), 'control denominator differs')
    require(len({row['token'] for row in report['runs'] + report['controlNegatives']}) == 4, 'observer/control token reused')
    for run_row in report['runs']:
        row = records[run_row['command']]
        events = validate_run(*(Path(row[stream]['path']).read_bytes() for stream in ('stdout', 'stderr')),
                              run_row['token'], run_row['case'], plan)
        require(events == run_row['events'], 'saved events differ from raw bytes')
        require(row['label'] == run_row['case'] and run_row['token'] in row['argv'], 'observer argv identity differs')
    adb = [str(Path(report['sdk']) / 'platform-tools/adb.exe'), '-P', str(report['serverPort']), '-s', report['serial']]
    for control in report['controlNegatives']:
        row = records[control['command']]
        expected_control = validate_control(*(Path(row[stream]['path']).read_bytes() for stream in ('stdout', 'stderr')),
                                            control['token'], control['case'])
        argv, child = control_command(adb, report['remote'], control['case'], control['token'])
        require(control == {**expected_control, 'command': control['command'], 'childArgv': child,
                            'environment': {'CLASSPATH': report['remote'] + '/protected.apk'}} and
                row['label'] == control['case'] and row['argv'] == argv, 'saved observer control differs')
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
    unchanged(build_report['classpathInputs'])
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
