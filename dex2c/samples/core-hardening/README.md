# Core hardening sample

This sample packages a LibXposed 102 module and a separate host app. The module hooks the host's arithmetic probes and delegates them to protected code. Its declared scope is only `io.github.xihan123.corehardening.sample.host`; the native module build currently targets `arm64-v8a`.

## Build

Run these commands from the repository root in PowerShell. Prerequisites are Android SDK Platform 37, NDK `30.0.16248370`, CMake `4.1.2`, JDK 21, Python 3, and the self-built LLVM 21 `clang.exe` at `build/bin/clang.exe`. The native module build targets `arm64-v8a`.

The module's release build uses the local Android debug signing configuration, so `dex2c.certificate` must point to the public DER certificate for that same debug keystore. With the default Android debug keystore:

```powershell
$env:ANDROID_HOME = 'F:\Android\Sdk'
$certificate = 'F:/Project/android/LLVM-Patch/work/core-hardening-sample/debug-certificate.der'
New-Item -ItemType Directory -Force 'work/core-hardening-sample' | Out-Null
$debugKeystore = Join-Path $env:USERPROFILE '.android\debug.keystore'
keytool -exportcert -alias androiddebugkey -keystore $debugKeystore -storepass android `
    -file $certificate
```

If the keystore does not exist yet, assemble the host debug APK once to let Android Gradle Plugin create it. If the local debug signing configuration uses another keystore, export that keystore's public certificate instead. Keep the keystore private and out of version control; only the public DER is passed to dex2c.

Build both APKs with the same certificate:

```powershell
.\dex2c\gradlew.bat -p dex2c/samples/core-hardening `
    :host:assembleDebug :module:assembleRelease `
    -Pdex2c.clang=F:/Project/android/LLVM-Patch/build/bin/clang.exe `
    -Pdex2c.certificate=F:/Project/android/LLVM-Patch/work/core-hardening-sample/debug-certificate.der `
    -Pdex2c.pythonExecutable=F:/Python/Python314/python.exe `
    --console=plain
```

The APKs are written to:

- `dex2c/samples/core-hardening/host/build/outputs/apk/debug/host-debug.apk`
- `dex2c/samples/core-hardening/module/build/outputs/apk/release/module-release.apk`

## Install and enable

Install both packages on an ARM64 device running a compatible LSPosed environment:

```powershell
$adb = 'F:\Android\Sdk\platform-tools\adb.exe'
$serial = '<目标设备序列号>'
& $adb -s $serial install -r dex2c/samples/core-hardening/host/build/outputs/apk/debug/host-debug.apk
& $adb -s $serial install -r dex2c/samples/core-hardening/module/build/outputs/apk/release/module-release.apk
```

In LSPosed, enable **Core hardening module** and set its scope to only `io.github.xihan123.corehardening.sample.host`. Apply the manager's activation request, then stop and relaunch the host. Launching the host runs the main-process checks and starts the `:worker` process; the **Run checks** button repeats them.

## Inspect logs

Use the same device serial from installation. This captures only logs from the target device and leaves its shared log buffer intact. Record the device time before restarting the host:

```powershell
$since = (& $adb -s $serial shell date '+%m-%d\ %H:%M:%S.000').Trim()
& $adb -s $serial shell am force-stop io.github.xihan123.corehardening.sample.host
& $adb -s $serial shell am start -W -n io.github.xihan123.corehardening.sample.host/.MainActivity
```

Wait for fresh output from both processes before collecting the bounded log window. Keep the live log open until both results appear; then stop it with Ctrl+C and dump the same time window:

```powershell
& $adb -s $serial logcat -T $since -v threadtime -s 'core-hardening:*' 'AndroidRuntime:E'
& $adb -s $serial logcat -d -T $since -v threadtime -s 'core-hardening:*' 'AndroidRuntime:E'
```

With the module active, look for `hooks-installed package=io.github.xihan123.corehardening.sample.host` and fresh `PASS process=main` and `PASS process=worker` lines, each with `cases=39 intCases=8 nativeIntCases=8 longCases=21 exceptionCases=2`. Each process has its own PID. If the worker result has not appeared yet, keep waiting or query the same bounded window again after it completes. Without the module active, both processes should report `FAIL` with `LibXposed module is not active`; this is the host's inactive-hook sentinel.

## Verified result and artifact checks

The final build in `work/core-hardening-sample/build-passthrough.log` succeeded. On 2026-11-21, OnePlus 7 / API 37 / ARM64 / 4 KiB pages / LSPosed 2.2.1 API 102 produced these results:

| Run | Main / worker PID | Result per process | Log under `work/core-hardening-sample/` |
| --- | --- | --- | --- |
| Enabled, 19:55 | 7514 / 7544 | 39 PASS | `final-device-pass.log` |
| Disabled, 19:55 | 7597 / 7614 | FAIL, module not active | `final-disabled.log` |
| Restored, 19:57 | 7679 / 7710 | 39 PASS | `final-restored.log` |

The 39 checks comprise 8 dex2c integer cases, 21 dex2c long cases, 8 native integer cases, and 2 invalid-`rounds` exception cases. The common `Entry` hook helper explicitly sets API 102 `ExceptionMode.PASSTHROUGH`; `rounds=-1` and `129` assert both the exception type and message.

The dex2c protection receipt is `module/build/intermediates/dex2c/release/native/protection.json`; the final signed APK check is `module/build/reports/dex2c/release/apk-verification.json`, both relative to this sample. Its two `criticalMethods` passed the signed-APK static check. The dex2c methods use strict VMP, post, hardened CSE, certificate binding and entry self-check. `segmentedData` and runtime `apkSignatureVerification` are disabled.

The final native `core_fusion_calculate` has four fusion blocks in both raw and post IR. Its 363-byte bytecode is identical across those files and is present in the APK's `lib/arm64-v8a/libcore_fusion.so`. This native path uses strict VMP/post and does not claim dex2c CSE or certificate protection. The release build no longer passes `-irobf-debug`, and the post IR contains no runtime debug helpers.

The native build IR is at `module/.cxx/RelWithDebInfo/<configuration-id>/arm64-v8a/arithmetic.raw.ll` and `arithmetic.ll`; dex2c build IR is at `module/build/intermediates/dex2c/release/native/protected.raw.ll` and `protected.ll`. After rebuilding, inspect the current Gradle outputs from the repository root:

```powershell
$module = 'dex2c/samples/core-hardening/module'
Get-Content "$module/build/intermediates/dex2c/release/native/protection.json" | ConvertFrom-Json |
    Select-Object protectedMethods, vmpStrict, vmpPost, cseHardened, certificateBound, selfCheckEntry
(Get-Content "$module/build/reports/dex2c/release/apk-verification.json" | ConvertFrom-Json).criticalMethods |
    Select-Object method, validationStatus
Get-ChildItem -LiteralPath "$module/.cxx/RelWithDebInfo" -Filter arithmetic.raw.ll -Recurse
```

Choose the current build's configuration directory from that listing, replace `<current-configuration-id>` below, and count its raw/post fusion blocks:

```powershell
$nativeDir = "$module/.cxx/RelWithDebInfo/<current-configuration-id>/arm64-v8a"
@(Select-String -Path "$nativeDir/arithmetic.raw.ll" -Pattern '^vmp\.fusion\.[^:]+:').Count
@(Select-String -Path "$nativeDir/arithmetic.ll" -Pattern '^vmp\.fusion\.[^:]+:').Count
```

Expect `protectedMethods=2`, all five protection flags `true`, two `passed` statuses and native fusion counts `4`/`4`. Java/dex2c fusion remains `0`: generated `d2c_i`, `d2c_j` and `d2c_copy` runtime calls separate adjacent arithmetic instructions. To avoid a false zero from LLVM discarding value names, the same generated source and recorded compilation arguments were recompiled with only `-fno-discard-value-names` added. That separate inspection IR is `work/core-hardening-sample/dex2c-inspection.raw.ll`; it is not the IR used to produce the APK.

`work/core-hardening-sample/final-artifacts/` is the local archive of this run's native IR, inspection IR, APKs and receipts. Neither that archive nor the inspection IR is checked into Git or generated by Gradle; a fresh clone will not contain them. If this local archive is available, the historical inspection can be reviewed as follows:

```powershell
$artifacts = 'work/core-hardening-sample/final-artifacts'
Select-String -Path "$artifacts/dex2c-inspection.raw.ll" -Pattern '^define .*@vm_interpreter_d2c_'
@(Select-String -Path "$artifacts/dex2c-inspection.raw.ll" -Pattern '^vmp\.fusion\.[^:]+:').Count
```

The final host/module APK sizes are 883129/326860 bytes; native/dex2c SO sizes are 31456/258536 bytes. Installed APK hashes match these final APKs. The evidence report is `work/core-hardening-sample/validation-report.json`. Randomized builds can change these sizes and hashes; this single build is not a before/after performance or size comparison. M1-specific tests and the native sample are complete; Java fusion benefits and complete QDReadHook business coverage remain outstanding. Device validation covers the ARM64 API 37 device with 4 KiB pages stated above.
