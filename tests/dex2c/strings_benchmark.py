"""Collect fresh-process ART P50/P95 samples from prepared and device-validated string fixtures."""
import argparse
import json
import math
from pathlib import Path
import statistics
import subprocess
import time
import uuid


REFERENCE_BUDGETS = {
    'strings': {'firstNanos': 45_000_000, 'cold256Nanos': 50_000_000,
                'hotNanosPerRead': 35, 'javaHeapDeltaBytes': 160 * 1024},
    'combined': {'firstNanos': 55_000_000, 'cold256Nanos': 60_000_000,
                 'hotNanosPerRead': 35, 'javaHeapDeltaBytes': 160 * 1024},
}


def check_reference_budgets(summary):
    for mode, limits in REFERENCE_BUDGETS.items():
        for metric, limit in limits.items():
            actual = summary[mode][metric]['p95']
            if actual > limit:
                raise ValueError(f'{mode} {metric} P95 {actual} exceeds reference budget {limit}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--strings', type=Path, required=True, help='prepareStringDeviceFixtures output after device.py')
    parser.add_argument('--combined', type=Path, required=True, help='Fixture built with -Pstrings.combined=true after device.py')
    parser.add_argument('--samples', type=int, default=20)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--enforce-reference-budgets', action='store_true', help='Enforce STRINGS_VALIDATION.md reference-device P95 budgets')
    args = parser.parse_args()
    if args.samples < 5:
        parser.error('at least five samples required')
    device = [str(args.adb.resolve()), '-s', args.serial]

    def run(*command):
        result = subprocess.run([*device, *map(str, command)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout.strip()

    remote = '/data/local/tmp/strings-benchmark-' + uuid.uuid4().hex
    run('shell', 'mkdir', remote)
    files = {'baseline': args.strings / 'baseline.zip', 'strings': args.strings / 'protected.apk', 'combined': args.combined / 'protected.apk'}
    pushed = []
    results = {mode: [] for mode in files}
    try:
        for mode, file in files.items():
            if not file.is_file():
                raise ValueError('Run device.py first: ' + str(file))
            target = remote + '/' + mode + ('.zip' if mode == 'baseline' else '.apk')
            run('push', file.resolve(), target)
            pushed.append(target)
        # Interleave modes to reduce temperature/order bias. Each invocation creates a new process.
        for index in range(args.samples):
            for mode in files:
                target = remote + '/' + mode + ('.zip' if mode == 'baseline' else '.apk')
                start = time.monotonic_ns()
                output = run('shell', 'env', 'CLASSPATH=' + target, 'app_process', '-Xcheck:jni',
                             '-Djava.library.path=' + target + '!/lib/arm64-v8a', '/system/bin', 'sample.Benchmark')
                row = json.loads(output)
                row['processWallNanos'] = time.monotonic_ns() - start
                results[mode].append(row)
            print('[ok] samples', index + 1, '/', args.samples, flush=True)
    finally:
        if pushed:
            run('shell', 'rm', '-f', *pushed)
        run('shell', 'rmdir', remote)
    summary = {}
    for mode, rows in results.items():
        summary[mode] = {}
        for metric in rows[0]:
            values = sorted(row[metric] for row in rows)
            summary[mode][metric] = {'p50': statistics.median(values), 'p95': values[math.ceil(len(values) * .95) - 1]}
        file = files[mode]
        summary[mode]['artifactBytes'] = file.stat().st_size
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'serial': args.serial, 'model': run('shell', 'getprop', 'ro.product.model'), 'sdk': run('shell', 'getprop', 'ro.build.version.sdk'),
                                      'pageSize': run('shell', 'getconf', 'PAGESIZE'), 'samples': args.samples,
                                      'strings': 256, 'checkJni': True, 'referenceBudgets': REFERENCE_BUDGETS if args.enforce_reference_budgets else None,
                                      'summary': summary, 'raw': results}, indent=2) + '\n')
    if args.enforce_reference_budgets:
        check_reference_budgets(summary)
    print(args.report)


if __name__ == '__main__':
    main()
