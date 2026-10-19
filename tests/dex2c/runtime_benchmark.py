"""Alternate signed fixture APKs and measure a warmed VM workload inside ART."""
import argparse
import hashlib
import json
import random
from pathlib import Path
import statistics
import subprocess
import uuid
import math
import zipfile


SOURCE = r'''package sample;
public class Bench {
    static long work(Logic logic, int count) {
        long sum = 0;
        for (int i=0; i<count; i++) {
            sum += logic.math(i, 123456789L, 1.25f, 2.5, (byte)i, (short)i, (char)i, true);
            sum += logic.recurse(5);
            sum += logic.text(65, "item").length();
            if (!logic.interned()) throw new AssertionError();
        }
        return sum;
    }
    public static void main(String[] args) {
        Logic logic = new Logic();
        work(logic, 200);
        long start = System.nanoTime();
        long checksum = work(logic, 1000);
        System.out.println((System.nanoTime()-start)+":"+checksum);
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--baseline-fixtures", required=True, type=Path)
    parser.add_argument("--candidate-fixtures", required=True, type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.samples < 30:
        parser.error('performance acceptance requires at least 30 alternating pairs')
    source_hashes = {}
    for name, fixture in (('baseline', args.baseline_fixtures), ('candidate', args.candidate_fixtures)):
        with zipfile.ZipFile(fixture / 'original.jar') as z:
            source_hashes[name] = hashlib.sha256(z.read('sample/Logic.class')).hexdigest()
    if source_hashes['baseline'] != source_hashes['candidate']:
        raise ValueError('benchmark business class differs between baseline and candidate')
    args.output.mkdir(parents=True, exist_ok=True)
    def run(command):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120)
        if result.returncode:
            raise RuntimeError(f"Command failed: {command}\n{result.stdout}\n{result.stderr}")
        return result.stdout.strip()
    java = args.java_home / "bin/java.exe"
    source = args.output / "Bench.java"
    source.write_text(SOURCE, encoding="utf-8")
    classes = args.output / "classes"
    classes.mkdir(exist_ok=True)
    run([args.java_home/"bin/javac.exe", "--release", "21", "-cp",
         args.candidate_fixtures/"original.jar", "-d", classes, source])
    dex = args.output / "bench.zip"
    dex.unlink(missing_ok=True)
    run([java, "-cp", args.sdk/"build-tools/37.0.0/lib/d8.jar", "com.android.tools.r8.D8",
         "--min-api", "26", "--lib", args.sdk/"platforms/android-37.0/android.jar",
         "--classpath", args.candidate_fixtures/"original.jar", "--output", dex,
         classes/"sample/Bench.class"])
    adb = [args.sdk/"platform-tools/adb.exe", "-P", args.server_port, "-s", args.serial]
    remote = "/data/local/tmp/ndkp-qseg-perf-" + uuid.uuid4().hex
    run([*adb, "shell", "mkdir", remote])
    files = {"bench.zip": dex, "baseline.apk": args.baseline_fixtures/"protected.apk",
             "candidate.apk": args.candidate_fixtures/"protected.apk"}
    rows = []
    try:
        for name, path in files.items():
            run([*adb, "push", path, remote+"/"+name])
        checksum = None
        for index in range(args.samples):
            row = {}
            for mode in (("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")):
                apk = remote+"/"+mode+".apk"
                output = run([*adb, "shell", "env", "CLASSPATH="+remote+"/bench.zip:"+apk,
                              "app_process", "-Xcheck:jni", "-Djava.library.path="+apk+"!/lib/arm64-v8a",
                              "/system/bin", "sample.Bench"])
                nanos, observed = map(int, output.split(":"))
                if checksum is not None and checksum != observed:
                    raise AssertionError("VM semantic difference")
                checksum = observed
                row[mode] = nanos/1e6
            rows.append(row)
            (args.output/"samples.json").write_text(json.dumps(rows, indent=2)+"\n")
            print(index+1, row, flush=True)
    finally:
        run([*adb, "shell", "rm", "-f", *(remote+"/"+name for name in files)])
        run([*adb, "shell", "rmdir", remote])
    ratios = [r["candidate"]/r["baseline"] for r in rows]
    rng = random.Random(0)
    boot = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(2000))
    result = {"samples": rows, "checksum": checksum,
              "businessClassSha256": source_hashes,
              "apkSha256": {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in files.items()},
              "medianMillis": {m: statistics.median(r[m] for r in rows) for m in ("baseline", "candidate")},
              "medianPairedRatio": statistics.median(ratios), "pairedRatioCI95": [boot[49], boot[1949]],
              "scope": "1000 warmed math/recursion/string iterations per ART process with CheckJNI; excludes startup"}
    result['p95Millis'] = {m: sorted(r[m] for r in rows)[math.ceil(len(rows) * .95) - 1] for m in ('baseline', 'candidate')}
    result['p95RegressionPercent'] = (result['p95Millis']['candidate'] / result['p95Millis']['baseline'] - 1) * 100
    result['warmP95GatePassed'] = result['p95RegressionPercent'] <= 5
    (args.output/"results.json").write_text(json.dumps(result, indent=2)+"\n")


if __name__ == "__main__":
    main()
