"""Build an isolated large-VM fixture through the existing dex2c compiler.

Then run tests/dex2c/device.py against the output to reuse signing/ART checks.
No source or configuration in the production Java build is changed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def fixture_source(methods=14, rounds=256):
    if not 2 <= methods <= 24 or not 64 <= rounds <= 1024:
        raise ValueError("use 2..24 methods and 64..1024 rounds for bounded calibration")
    lines = ["package sample;", "import io.github.xihan123.dex2c.annotation.dex2c;",
             "public class Run {"]
    for method in range(methods):
        lines += [f"  @dex2c static int work{method}(int x) {{"]
        for step in range(rounds):
            constant = (method + 1) * 65537 + step * 101 + 17
            lines += [f"    x = (x * 1664525 + {constant}) ^ (x >>> 13);"]
        lines += ["    return x;", "  }"]
    lines += ['  @dex2c static int marker() { return "large-vm-fixture".length(); }',
              "  static int reference(int x, int method) {",
              f"    for (int step = 0; step < {rounds}; step++)",
              "      x = (x * 1664525 + (method + 1) * 65537 + step * 101 + 17) ^ (x >>> 13);",
              "    return x;", "  }", "  public static void main(String[] args) {",
              "    if (marker() != 16) throw new AssertionError();",
              "    int checksum = marker();"]
    for method in range(methods):
        lines += [f"    for (int seed : new int[]{{0, 1, -1, 0x12345678}}) {{",
                  f"      int value = work{method}(seed);",
                  f"      if (value != reference(seed, {method})) throw new AssertionError({method});",
                  "      checksum = checksum * 31 + value;", "    }"]
    lines += ['    System.out.println("large-vm=" + checksum);', "  }", "}"]
    return "\n".join(lines) + "\n"


RUNNER = r'''
import io.github.xihan123.dex2c.core.Transformer;
import io.github.xihan123.dex2c.core.NativeCompiler;
import io.github.xihan123.dex2c.runtime.Dex2cRuntime;
import java.nio.file.*;
import java.util.*;
import javax.tools.ToolProvider;
public class LargeFixture {
    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0]);
        Path classes = Files.createDirectories(out.resolve("classes"));
        int status = ToolProvider.getSystemJavaCompiler().run(null, null, null,
            "-g", "-classpath", System.getProperty("java.class.path"),
            "-d", classes.toString(), out.resolve("Run.java").toString());
        if (status != 0) throw new IllegalStateException("fixture javac failed");
        new Transformer().transform(List.of(classes), out.resolve("generated"), "dex2c_semantics");
        Files.writeString(out.resolve("runtime-path.txt"),
            Path.of(Dex2cRuntime.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        new NativeCompiler().compile(out.resolve("generated"), out.resolve("native"),
            Path.of(args[1]), Path.of(args[2]), "dex2c_semantics", 26,
            out.resolve("test.der"), Path.of(args[3]), true, true);
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--methods", type=int, default=14)
    parser.add_argument("--rounds", type=int, default=256)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("--output must be new or empty; keep each calibration independent")
    source = fixture_source(args.methods, args.rounds)
    out.mkdir(parents=True, exist_ok=True)
    (out / "Run.java").write_text(source, encoding="utf-8")
    (out / "LargeFixture.java").write_text(RUNNER, encoding="utf-8")
    suffix = ".exe" if os.name == "nt" else ""
    keytool = args.java.with_name("keytool" + suffix)

    def run(command, **kwargs):
        subprocess.run([str(value) for value in command], check=True, **kwargs)

    run([keytool, "-genkeypair", "-keystore", out / "test.jks", "-storepass", "android",
         "-keypass", "android", "-alias", "test", "-keyalg", "RSA", "-dname",
         "CN=qseg large fixture", "-validity", "3650", "-noprompt"])
    run([keytool, "-exportcert", "-keystore", out / "test.jks", "-storepass", "android",
         "-alias", "test", "-file", out / "test.der"])
    # Source-file launch reuses the existing test classpath without a new Java task/config.
    init = out / "fixture.init.gradle"
    task_args = [str(out), str(args.ndk.resolve()), str(args.clang.resolve()),
                 str(Path(__import__("sys").executable).resolve())]
    init.write_text("""gradle.projectsEvaluated {
    def core = gradle.rootProject.project(':core')
    core.tasks.register('qsegLargeFixture', JavaExec) {
        dependsOn core.tasks.named('testClasses')
        classpath = core.sourceSets.test.runtimeClasspath
        executable = %s
        mainClass = %s
        args %s
    }
}
""" % (json.dumps(str(args.java.resolve())), json.dumps(str(out / "LargeFixture.java")),
       ", ".join(json.dumps(value) for value in task_args)), encoding="utf-8")
    gradle = ROOT / "dex2c" / ("gradlew.bat" if os.name == "nt" else "gradlew")
    env = dict(os.environ, JAVA_HOME=str(args.java.resolve().parent.parent))
    run([gradle, "-I", init, ":core:qsegLargeFixture", "--no-daemon", "--console=plain"],
        cwd=ROOT / "dex2c", env=env)
    import zipfile
    with zipfile.ZipFile(out / "original.jar", "w") as archive:
        for path in sorted((out / "classes").rglob("*.class")):
            archive.write(path, path.relative_to(out / "classes").as_posix())
    inputs = {"mains": ["sample.Run"], "baseline": [str(out / "original.jar")],
              "protected": [str(out / "generated/classes.jar")],
              "common": [(out / "runtime-path.txt").read_text(encoding="utf-8")]}
    (out / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    (out / "fixture.json").write_text(json.dumps({"methods": args.methods, "rounds": args.rounds}, indent=2) + "\n")
    print("large QSEG fixture:", out, flush=True)


if __name__ == "__main__":
    main()
