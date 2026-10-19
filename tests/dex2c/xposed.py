"""Install the sample APKs and assert LibXposed 102 behavior in two processes/loaders."""
import argparse
import json
from pathlib import Path
import re
import time

from device import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    adb = args.sdk / "platform-tools/adb.exe"
    if not adb.exists():
        adb = adb.with_suffix("")
    device = [adb, "-s", args.serial]
    for apk in ("module/build/outputs/apk/release/module-release.apk", "host/build/outputs/apk/debug/host-debug.apk"):
        run([*device, "install", "-r", repo / "dex2c/samples/xposed" / apk])
    # LSPosed must already have this module enabled for this test host.
    since = run([*device, "shell", "date", "+%m-%d\\ %H:%M:%S.000"])
    run([*device, "shell", "am", "force-stop", "io.github.xihan123.dex2c.sample.host"])
    run([*device, "shell", "am", "start", "-n", "io.github.xihan123.dex2c.sample.host/.MainActivity"])
    started = time.monotonic()
    text = ""
    while time.monotonic() - started < 60:
        text = run([*device, "logcat", "-d", "-T", since, "-v", "brief", "-s", "dex2c-sample:*"])
        hosts = set(re.findall(r"pid=(\d+) calculate=37 exception=-99", text))
        loaders = set(re.findall(r"isolated-loader=OK existing-native=102 pid=(\d+)", text))
        if "Hook initialization failed" in text:
            raise AssertionError(text)
        if len(hosts & loaders) >= 2:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({"serial": args.serial, "processes": sorted(hosts & loaders),
                    "seconds": round(time.monotonic() - started, 3), "log": text}, indent=2) + "\n")
            print("[ok] LibXposed 102: main/worker, isolated host loaders, repeat registration, "
                  "argument/result/exception hooks and existing native library; " + str(args.report))
            return
        time.sleep(1)
    raise AssertionError("Enable the sample module for the sample host in LSPosed, then retry.\n" + text)


if __name__ == "__main__":
    main()
