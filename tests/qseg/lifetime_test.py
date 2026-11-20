"""验证缓存生命周期、冷 kind1 分配失败及定向源擦零与调用方副本所有权。"""
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


SOURCE_FILES = (
    'tests/qseg/lifetime_test.py', 'tests/qseg/lifetime_test.cpp',
    'tests/qseg/test_lifetime_test.py', 'tests/qseg/README.md',
    'runtime/ndkp_qseg_runtime.cpp', 'runtime/qseg.h', 'runtime/cse_crypto.h',
    'runtime/apkcert.h', 'runtime/apkcert_io.h', 'runtime/sha256.h',
)
DEVICE_COMMANDS = {
    'model': ['getprop', 'ro.product.model'],
    'sdk': ['getprop', 'ro.build.version.sdk'],
    'pageSize': ['getconf', 'PAGESIZE'],
    'arch': ['uname', '-m'],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def exact_json(actual, expected):
    """JSON equality with exact types, including bool versus int and int versus float."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_json(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact_json(a, b) for a, b in zip(actual, expected))
    return actual == expected


def read_json(path):
    return json.loads(Path(path).read_text('utf-8'), object_pairs_hook=unique_object, parse_constant=reject_constant)


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def identity(path):
    path = Path(path).resolve()
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': size, 'sha256': digest}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Commands:
    """Persist bytes and command status before callers inspect the result."""
    def __init__(self, output, cwd):
        self.output, self.cwd = Path(output), Path(cwd)
        self.records = []
        (self.output / 'commands').mkdir()

    def run(self, label, argv):
        stem = 'commands/{:02d}-{}'.format(len(self.records) + 1, label)
        record = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(self.cwd),
                  'started': utc_now(), 'timeoutSeconds': 180}
        stdout, stderr = b'', b''
        try:
            result = subprocess.run(record['argv'], cwd=self.cwd, capture_output=True,
                                    timeout=record['timeoutSeconds'], check=False)
            stdout, stderr = result.stdout, result.stderr
            record.update(status='completed', returncode=result.returncode)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or b'', error.stderr or b''
            record.update(status='timeout', returncode=None, error=str(error))
        except OSError as error:
            record.update(status='launch-error', returncode=None, error=str(error))
        record['ended'] = utc_now()
        for name, data in (('stdout', stdout), ('stderr', stderr)):
            path = self.output / (stem + '.' + name + '.bin')
            path.write_bytes(data)
            record[name] = identity(path)
        reference = stem + '.json'
        write_json(self.output / reference, record)
        self.records.append(reference)
        return record, stdout, stderr

    def checked(self, label, argv):
        record, stdout, stderr = self.run(label, argv)
        require(record['status'] == 'completed' and record['returncode'] == 0,
                label + ': ' + record['status'] + ' exit=' + str(record['returncode']))
        return stdout, stderr


def expected_events(token):
    require(re.fullmatch('[0-9a-f]{32}', token) is not None, 'invalid run token')
    events = (
        'control:BEGIN', 'control:WARMUP_OK', 'control:COLD_TARGET bytes=2097152',
        'control:TARGET_ATTEMPT', 'control:MMAP_REAL attempts=1 hits=0 bytes=2097152',
        'control:TARGET_OK attempts=1 hits=0', 'control:WAIT status=0 exited=1 code=0 signal=0',
        'enomem:BEGIN', 'enomem:WARMUP_OK', 'enomem:COLD_TARGET bytes=2097152',
        'enomem:ARMED', 'enomem:TARGET_ATTEMPT',
        'enomem:MMAP_ENOMEM attempts=1 hits=1 bytes=2097152 errno=' + str(errno.ENOMEM),
        'enomem:WAIT status=32512 exited=1 code=127 signal=0', 'suite:COMPLETE',
    )
    return [('QSEG_MMAP:' + token + ':' + event).encode('ascii') for event in events]


def validate_copy_wipe(stderr, token, page_size):
    """Bind both forked cases to their source interval, caller buffer and real wait status."""
    require(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None, 'invalid copy wipe run token')
    require(type(page_size) is int and 0 < page_size <= 65536 and page_size & (page_size - 1) == 0,
            'invalid copy wipe page size')
    size, budget = 700000, 1 << 20
    mapped = (size + page_size - 1) // page_size * page_size
    require(size < mapped < budget < 2 * mapped, 'invalid copy wipe padding/pressure sizes')
    prefix = b'QSEG_COPY_WIPE:'
    records = [json.loads(line[len(prefix):].decode('ascii'), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
               for line in stderr.splitlines() if line.startswith(prefix)]
    require(len(records) == 27 and all(type(record) is dict for record in records),
            'missing/duplicate copy wipe events')
    source_id, pressure_id = '05' + '00' * 15, '01' + '00' * 15
    # active, idle and peak are mapped-size multiples; lastUsed/clock follow the real LRU transitions.
    stages = (
        (0, 0, 0, 0, False, 0, 0, False, 0, 0, 0),
        (1, 0, 1, 0, True, 1, 1, False, 0, 0, 1),
        (0, 1, 1, 0, True, 0, 2, False, 0, 0, 2),
        (1, 1, 2, 0, True, 0, 2, True, 1, 3, 3),
        (0, 2, 2, 0, True, 0, 2, True, 0, 4, 4),
        (0, 1, 2, 1, False, 0, 2, True, 0, 4, 4),
    )
    first_events = [('BEGIN', 0), ('SOURCE_HELD', 1), ('COPY_BEFORE', 1), ('COPY_AFTER', 1),
                    ('SOURCE_RELEASED', 2), ('PRESSURE_ACQUIRED', 3), ('PRESSURE_RELEASE_ATTEMPT', 3),
                    ('TARGET_ENTER', 4)]
    payload = {'payloadCheckedBytes': 64, 'payloadValue': 69, 'leadingCheckedBytes': 16,
               'trailingCheckedBytes': 16, 'canaryValue': 165}
    source = {'sourceCheckedBytes': size, 'sourceValue': 69, 'paddingCheckedBytes': mapped - size, 'paddingValue': 0}
    summaries = []
    start = 0
    for case, reject in (('positive', False), ('reject-padding', True)):
        tail = ([('INJECTED', 4), ('ZERO_SCAN', 4), ('REJECT_SOURCE_NONZERO', 4)] if reject else
                [('ZERO_SCAN', 4), ('REAL_MUNMAP', 4), ('EVICTED', 5), ('COPY_RETAINED', 5),
                 ('COPY_WIPED', 5), ('COMPLETE', 5)])
        events = first_events + tail
        observed = records[start:start + len(events) + 1]
        start += len(observed)
        base, buffer = observed[1].get('sourceBase'), observed[0].get('bufferBase')
        pressure = observed[5].get('pressure')
        require(type(pressure) is dict, 'missing copy wipe pressure identity')
        pressure_base = pressure.get('data')
        for address, length, alignment in ((base, mapped, page_size), (buffer, 96, 1),
                                           (pressure_base, mapped, page_size)):
            require(type(address) is int and 0 < address <= (1 << 64) - 1 - length and address % alignment == 0,
                    'invalid copy wipe address/interval')
        require(base + mapped <= buffer or buffer + 96 <= base, 'copy wipe source/caller buffer overlap')
        require(base + mapped <= pressure_base or pressure_base + mapped <= base,
                'copy wipe source/pressure mapping overlap')
        interval = {'unmapBase': base, 'unmapBytes': mapped}
        extras = {
            'SOURCE_HELD': source,
            'COPY_BEFORE': {'offset': 65520, 'length': 64, 'encoding': 2, 'bufferBytes': 96, 'payloadOffset': 16,
                            'leadingCanaryBytes': 16, 'trailingCanaryBytes': 16,
                            'initialCheckedBytes': 96, 'initialValue': 165, 'disjoint': True},
            'COPY_AFTER': payload,
            'SOURCE_RELEASED': source,
            'PRESSURE_ACQUIRED': {'pressureCheckedBytes': size, 'pressureValue': 65},
            'TARGET_ENTER': interval,
            'INJECTED': {**interval, 'offset': mapped - 1, 'oldValue': 0, 'newValue': 123},
            'ZERO_SCAN': {**interval, 'checkedBytes': mapped, 'nonzeroBytes': int(reject),
                          'firstBadOffset': mapped - 1 if reject else -1, 'firstBadValue': 123 if reject else 0},
            'REAL_MUNMAP': {**interval, 'result': 0},
            'REJECT_SOURCE_NONZERO': {**interval, 'exitCode': 123},
            'COPY_RETAINED': payload,
            'COPY_WIPED': {**payload, 'payloadValue': 0, 'wipeOffset': 16, 'wipedBytes': 64},
            'COMPLETE': {'apkOnlyRecoveryPrevented': False},
        }
        for seq, (name, stage) in enumerate(events):
            active, idle, peak, evictions, resident, refs, last, pressure_resident, pressure_refs, pressure_last, clock = stages[stage]
            expected = {
                'runToken': token, 'case': case, 'seq': seq, 'event': name,
                'target': {'id': source_id, 'kind': 2, 'size': size, 'data': base if resident else 0,
                           'mapped': mapped if resident else 0, 'references': refs, 'pinned': False, 'lastUsed': last},
                'pressure': {'id': pressure_id, 'kind': 1, 'size': size,
                             'data': pressure_base if pressure_resident else 0, 'mapped': mapped if pressure_resident else 0,
                             'references': pressure_refs, 'pinned': False, 'lastUsed': pressure_last},
                'pageSize': page_size, 'mappedBytes': mapped, 'sourceBase': 0 if stage == 0 else base, 'bufferBase': buffer,
                'cache': {'activeBytes': active * mapped, 'idleBytes': idle * mapped, 'pinnedBytes': 0,
                          'peakResidentBytes': peak * mapped, 'evictions': evictions},
                'clock': clock, 'otherResourcesCold': True, 'targetMatches': int(seq >= 7),
                'injectHits': int(reject and seq >= 8), 'realMunmapCalls': int(not reject and seq >= 9),
                'armed': name == 'PRESSURE_RELEASE_ATTEMPT' or stage == 4,
                **extras.get(name, {}),
            }
            require(exact_json(observed[seq], expected), 'invalid copy wipe event: ' + case + '/' + name)
        wait = {'runToken': token, 'case': case, 'seq': len(events), 'event': 'WAIT',
                'status': 31488 if reject else 0, 'exited': True, 'code': 123 if reject else 0, 'signal': 0}
        require(exact_json(observed[-1], wait), 'invalid copy wipe wait: ' + case)
        summaries.append({'case': case, 'sourceBase': base, 'bufferBase': buffer, 'pressureBase': pressure_base,
                          'eventCount': len(observed), 'checkedBytes': mapped, 'nonzeroBytes': int(reject),
                          'firstBadOffset': mapped - 1 if reject else -1, 'targetMatches': 1,
                          'injectHits': int(reject), 'realMunmapCalls': int(not reject), 'wait': wait,
                          'copyRetainedObserved': not reject, 'payloadWipedBytes': 0 if reject else 64})
    return {'targetId': source_id, 'targetKind': 2, 'sourceBytes': size, 'pageSize': page_size, 'mappedBytes': mapped,
            'offset': 65520, 'length': 64, 'encoding': 2, 'bufferBytes': 96, 'payloadOffset': 16,
            'canaryBytes': 16, 'apkOnlyRecoveryPrevented': False, 'cases': summaries}


def validate_run(stdout, stderr, token, page_size):
    """Validate one exit-zero parent process's raw bytes; no Python assertions."""
    observed = [line for line in stderr.splitlines() if line.startswith(b'QSEG_MMAP:')]
    require(observed == expected_events(token), 'missing, duplicate, foreign or out-of-order mmap events')
    validate_copy_wipe(stderr, token, page_size)
    copy_lines = [line for line in stderr.splitlines() if line.startswith(b'QSEG_COPY_WIPE:')]
    protocol = [line for line in stderr.splitlines() if line.startswith((b'QSEG_COPY_WIPE:', b'QSEG_MMAP:'))]
    require(protocol == copy_lines + observed, 'early/interleaved suite completion or copy wipe events')
    match = re.fullmatch(rb'page=(\d+) active=(\d+) idle=(\d+) pinned=(\d+) peak=(\d+) '
                         rb'evictions=(\d+) wiped=(\d+)\r?\n', stdout)
    require(match is not None, 'missing/invalid full lifetime suite statistics')
    stats = dict(zip(('page', 'active', 'idle', 'pinned', 'peak', 'evictions', 'wiped'),
                     map(int, match.groups())))
    require(stats['page'] == page_size and stats['active'] == 0 and stats['idle'] <= 1 << 20 and
            stats['pinned'] == (700000 + page_size - 1) // page_size * page_size and
            stats['peak'] >= 2 << 20 and stats['evictions'] > 0 and
            stats['evictions'] == stats['wiped'], 'invalid full lifetime suite statistics')
    return stats


def device_identity(outputs):
    values = {name: data.decode('utf-8').strip() for name, data in outputs.items()}
    require(set(values) == set(DEVICE_COMMANDS) and values['model'] and
            '\n' not in values['model'] and values['arch'] == 'aarch64', 'invalid device identity')
    require(re.fullmatch('[0-9]+', values['sdk']) is not None and
            re.fullmatch('[0-9]+', values['pageSize']) is not None, 'invalid SDK/page size')
    values['sdk'], values['pageSize'] = int(values['sdk']), int(values['pageSize'])
    require(values['sdk'] >= 26 and 0 < values['pageSize'] <= 65536 and
            values['pageSize'] & (values['pageSize'] - 1) == 0, 'unsupported SDK/page size')
    return values


def compiler_path(ndk):
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    return Path(ndk) / 'toolchains/llvm/prebuilt' / host / ('bin/clang++.exe' if os.name == 'nt' else 'bin/clang++')


def compile_argv(clang, source, optimization, binary):
    base = Path(clang).parent.parent
    return list(map(str, [clang, '--target=aarch64-linux-android26', '--sysroot=' + str(base / 'sysroot'),
                         '-' + optimization, '-UNDEBUG', '-fno-lto', '-std=c++17', '-Wall', '-Wextra',
                         '-Werror', '-static-libstdc++', source, '-ldl', '-lz', '-o', binary]))


def verify_results(output):
    """Revalidate results.json, all command bytes/argv, identities and O0/O2 evidence."""
    output = Path(output).resolve()
    report = read_json(output / 'results.json')
    return verify_report(output, report)


def verify_report(output, report):
    require(type(report['schemaVersion']) is int and report['schemaVersion'] == 1 and
            type(report['checkerRevision']) is int and report['checkerRevision'] == 2 and
            report['status'] == 'passed' and report.get('apkOnlyRecoveryPrevented') is False, 'invalid results schema/status')
    require(not (output / 'failure.json').exists(), 'failure report accompanies success')
    require(re.fullmatch('[0-9a-f]{32}', report['runId']) is not None and
            report['remoteDirectory'] == '/data/local/tmp/qseg-lifetime-' + report['runId'], 'invalid remote identity')
    require(isinstance(report['serial'], str) and report['serial'] and
            type(report['serverPort']) is int and 1 <= report['serverPort'] <= 65535, 'invalid adb identity')
    require(report['inputsBefore'] == report['inputsAfter'] and
            set(report['inputsBefore']) == set(SOURCE_FILES) | {'compiler', 'adb', 'ndk/source.properties'},
            'source/tool identities changed or incomplete')
    for item in report['inputsBefore'].values():
        require(identity(item['path']) == item, 'input identity changed: ' + item['path'])
    records = {}
    for reference in report['commands']:
        path = output / reference
        require(path.resolve().parent == output / 'commands' and path.suffix == '.json', 'invalid command path')
        record = read_json(path)
        require(record['label'] not in records and record['cwd'] == report['repository'] and
                record['status'] == 'completed' and record['returncode'] == 0 and
                record['timeoutSeconds'] == 180 and record['started'] <= record['ended'], 'failed/duplicate command')
        for name in ('stdout', 'stderr'):
            item = record[name]
            require(Path(item['path']).resolve().parent == output / 'commands' and
                    identity(item['path']) == item, 'command bytes changed')
        records[record['label']] = record
    adb = [report['inputsBefore']['adb']['path'], '-P', str(report['serverPort']), '-s', report['serial']]
    remote = report['remoteDirectory']
    expected = {('device-' + name): [*adb, 'shell', *command] for name, command in DEVICE_COMMANDS.items()}
    expected['remote-mkdir'] = [*adb, 'shell', 'mkdir', remote]
    require([run['optimization'] for run in report['runs']] == ['O0', 'O2'], 'missing O0/O2 run')
    require(len({run['token'] for run in report['runs']}) == 2, 'reused execution token')
    device = device_identity({name: Path(records['device-' + name]['stdout']['path']).read_bytes()
                              for name in DEVICE_COMMANDS})
    require(device == report['device'], 'device identity mismatch')
    for run in report['runs']:
        optimization, binary = run['optimization'], run['binaryBefore']
        require(binary == run['binaryAfter'] and identity(binary['path']) == binary and
                Path(binary['path']) == output / ('lifetime-' + optimization), 'binary changed')
        expected[optimization + '-compile'] = compile_argv(report['inputsBefore']['compiler']['path'],
            report['inputsBefore']['tests/qseg/lifetime_test.cpp']['path'], optimization, binary['path'])
        expected[optimization + '-push'] = [*adb, 'push', binary['path'], remote + '/test']
        expected[optimization + '-chmod'] = [*adb, 'shell', 'chmod', '755', remote + '/test']
        expected[optimization + '-run'] = [*adb, 'shell', remote + '/test', remote + '/chunks.bin', run['token']]
        record = records[optimization + '-run']
        stdout, stderr = Path(record['stdout']['path']).read_bytes(), Path(record['stderr']['path']).read_bytes()
        stats = validate_run(stdout, stderr, run['token'], device['pageSize'])
        require(exact_json(stats, run['stats']), 'statistics mismatch')
        require(exact_json(validate_copy_wipe(stderr, run['token'], device['pageSize']), run.get('copyWipe')),
                'copy wipe proof mismatch')
    expected['cleanup-files'] = [*adb, 'shell', 'rm', '-f', remote + '/test', remote + '/chunks.bin']
    expected['cleanup-directory'] = [*adb, 'shell', 'rmdir', remote]
    require(list(records) == list(expected), 'missing/duplicate/out-of-order command')
    for label, argv in expected.items():
        require(records[label]['argv'] == argv, 'command arguments changed: ' + label)
    return report


def execute(args):
    output = args.output.resolve()
    # Refuse stale evidence before creating any logs or overwriting existing files.
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),
            'output directory must be new or empty')
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    commands = Commands(output, root)
    run_id = uuid.uuid4().hex
    remote = '/data/local/tmp/qseg-lifetime-' + run_id
    report = {'schemaVersion': 1, 'checkerRevision': 2, 'status': 'running', 'runId': run_id,
              'apkOnlyRecoveryPrevented': False,
              'repository': str(root), 'serial': args.serial, 'serverPort': args.server_port,
              'remoteDirectory': remote, 'inputsBefore': {}, 'inputsAfter': {}, 'runs': [],
              'commands': commands.records}
    error, cleanup_errors, remote_attempted = None, [], False
    try:
        require(args.serial and not re.search(r'\s', args.serial) and not args.serial.startswith('-'), 'invalid serial')
        require(1 <= args.server_port <= 65535, 'invalid adb server port')
        paths = {name: root / name for name in SOURCE_FILES}
        paths.update(compiler=compiler_path(args.ndk).resolve(), adb=args.adb.resolve())
        paths['ndk/source.properties'] = args.ndk.resolve() / 'source.properties'
        for name, path in paths.items():
            report['inputsBefore'][name] = identity(path)
        adb = [str(args.adb.resolve()), '-P', str(args.server_port), '-s', args.serial]
        outputs = {name: commands.checked('device-' + name, [*adb, 'shell', *command])[0]
                   for name, command in DEVICE_COMMANDS.items()}
        report['device'] = device_identity(outputs)
        remote_attempted = True
        commands.checked('remote-mkdir', [*adb, 'shell', 'mkdir', remote])
        for optimization in ('O0', 'O2'):
            binary = output / ('lifetime-' + optimization)
            run = {'optimization': optimization, 'token': uuid.uuid4().hex}
            report['runs'].append(run)
            commands.checked(optimization + '-compile', compile_argv(paths['compiler'],
                paths['tests/qseg/lifetime_test.cpp'], optimization, binary))
            run['binaryBefore'] = identity(binary)
            commands.checked(optimization + '-push', [*adb, 'push', binary, remote + '/test'])
            commands.checked(optimization + '-chmod', [*adb, 'shell', 'chmod', '755', remote + '/test'])
            stdout, stderr = commands.checked(optimization + '-run',
                [*adb, 'shell', remote + '/test', remote + '/chunks.bin', run['token']])
            run['stats'] = validate_run(stdout, stderr, run['token'], report['device']['pageSize'])
            run['copyWipe'] = validate_copy_wipe(stderr, run['token'], report['device']['pageSize'])
    except Exception as caught:
        error = {'type': type(caught).__name__, 'message': str(caught)}
    finally:
        if remote_attempted:
            for label, argv in (
                ('cleanup-files', [*adb, 'shell', 'rm', '-f', remote + '/test', remote + '/chunks.bin']),
                ('cleanup-directory', [*adb, 'shell', 'rmdir', remote]),
            ):
                try:
                    commands.checked(label, argv)
                except Exception as caught:
                    cleanup_errors.append({'type': type(caught).__name__, 'message': str(caught)})
        try:
            report['inputsAfter'] = {name: identity(item['path']) for name, item in report['inputsBefore'].items()}
            require(report['inputsBefore'] == report['inputsAfter'], 'source/tool inputs changed during run')
            for run in report['runs']:
                if 'binaryBefore' in run:
                    run['binaryAfter'] = identity(run['binaryBefore']['path'])
                    require(run['binaryBefore'] == run['binaryAfter'], 'binary changed during run')
        except Exception as caught:
            cleanup_errors.append({'type': type(caught).__name__, 'message': str(caught)})
    if error or cleanup_errors:
        report.update(status='failed', error=error, cleanupErrors=cleanup_errors)
        write_json(output / 'failure.json', report)
        raise ValueError('lifetime validation failed; see ' + str(output / 'failure.json'))
    report['status'] = 'passed'
    try:
        verify_report(output, report)
    except Exception as caught:
        report.update(status='failed', error={'type': type(caught).__name__, 'message': str(caught)}, cleanupErrors=[])
        write_json(output / 'failure.json', report)
        raise
    # Publish only after both optimization levels, all old checks, cleanup and identities succeed.
    write_json(output / 'results.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ndk', 'adb', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--server-port', type=int, default=5037)
    args = parser.parse_args()
    report = execute(args)
    print(json.dumps({'status': report['status'], 'output': str(args.output.resolve()), 'device': report['device']}))


if __name__ == '__main__':
    main()
