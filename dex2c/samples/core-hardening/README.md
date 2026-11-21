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

The p24 build in `work/dex2c-primitive-lowering-p24/build-sample.log` succeeded. The comparison starts at `ad6d19d367445be83ad5f5577caad4d89ad09b56`; the sample algorithms, 39 assertions, source files and configuration are unchanged. On 2026-11-21, the candidate APKs produced these results on OnePlus 7 / API 37 / ARM64 / 4 KiB pages / LSPosed 2.2.1 API 102:

| Run | Main / worker PID | Result per process | Log under `work/dex2c-primitive-lowering-p24/` |
| --- | --- | --- | --- |
| Enabled, 20:53 | 8315 / 8342 | 39 PASS | `device-enabled.log` |
| Disabled, 20:54 | 8392 / 8410 | FAIL, module not active | `device-disabled.log` |
| Restored, 20:54 | 8465 / 8490 | 39 PASS | `device-restored.log` |

The 39 checks comprise 8 dex2c integer cases, 21 dex2c long cases, 8 native integer cases, and 2 invalid-`rounds` exception cases. The common `Entry` hook helper explicitly sets API 102 `ExceptionMode.PASSTHROUGH`; `rounds=-1` and `129` assert both the exception type and message. Installed APK SHA-256 values match the frozen candidates, and the module is enabled at the end of the test.

The dex2c protection receipt is `module/build/intermediates/dex2c/release/native/protection.json`; the final signed APK check is `module/build/reports/dex2c/release/apk-verification.json`, both relative to this sample. Its two `criticalMethods` passed the signed-APK static check. The dex2c methods use strict VMP, post, hardened CSE, certificate binding and entry self-check. `segmentedData` and runtime `apkSignatureVerification` are disabled.

p24 lowers call-free int/long regions to scalar temporaries. It writes values back before helpers, JNI calls and real control-flow boundaries, including exception handlers. Dead numeric slots still release old JNI references and clear their uninitialized tags through the original runtime helpers. Floating-point, reference and throwing operations keep their existing lowering. Both unchanged Java methods now have four fusion groups in the actual raw and post IR used to produce the packaged SO:

| Method | Baseline groups | p24 raw / post groups | Baseline → p24 bytecode |
| --- | --- | --- | --- |
| `accumulate(JI)J` | 0 | 4 / 4 | 7013 → 4158 bytes |
| `calculate(III)I` | 0 | 4 / 4 | 3848 → 1351 bytes |

Each method's raw/post bytecode is identical and is present in the final dex2c SO. `NativeCompiler` now passes `-fno-discard-value-names` on the actual protected raw/post steps, so fusion counts can be checked on the packaged compilation chain. The baseline's zero groups were confirmed by its separate named inspection IR; that historical inspection is not used to establish the p24 result.

The native `core_fusion_calculate` still has four groups and 363 bytes of bytecode. Its 31456-byte `lib/arm64-v8a/libcore_fusion.so` is byte-for-byte identical to p23. This native path uses strict VMP/post and does not claim dex2c CSE or certificate protection. The release build does not pass `-irobf-debug`, and the post IR contains no runtime debug helpers.

The native build IR is at `module/.cxx/RelWithDebInfo/<configuration-id>/arm64-v8a/arithmetic.raw.ll` and `arithmetic.ll`; dex2c build IR is at `module/build/intermediates/dex2c/release/native/protected.raw.ll` and `protected.ll`. After rebuilding, inspect the current Gradle outputs from the repository root:

```powershell
$module = 'dex2c/samples/core-hardening/module'
Get-Content "$module/build/intermediates/dex2c/release/native/protection.json" | ConvertFrom-Json |
    Select-Object protectedMethods, vmpStrict, vmpPost, cseHardened, certificateBound, selfCheckEntry
(Get-Content "$module/build/reports/dex2c/release/apk-verification.json" | ConvertFrom-Json).criticalMethods |
    Select-Object method, validationStatus
Get-ChildItem -LiteralPath "$module/.cxx/RelWithDebInfo" -Filter arithmetic.raw.ll -Recurse
```

Choose the current build's configuration directory from that listing, replace `<current-configuration-id>` below, and count the native raw/post fusion blocks:

```powershell
$nativeDir = "$module/.cxx/RelWithDebInfo/<current-configuration-id>/arm64-v8a"
@(Select-String -Path "$nativeDir/arithmetic.raw.ll" -Pattern '^vmp\.fusion\.[^:]+:').Count
@(Select-String -Path "$nativeDir/arithmetic.ll" -Pattern '^vmp\.fusion\.[^:]+:').Count
```

Expect `protectedMethods=2`, all five protection flags `true`, two `passed` statuses and native fusion counts `4`/`4`. Count Java fusion groups separately in each method's private interpreter clone:

```powershell
$protectedDir = "$module/build/intermediates/dex2c/release/native"
$symbols = (Get-Content "$protectedDir/protection.json" | ConvertFrom-Json).symbols
foreach ($file in 'protected.raw.ll', 'protected.ll') {
    $ir = Get-Content -LiteralPath "$protectedDir/$file" -Raw
    foreach ($symbol in $symbols) {
        $pattern = '(?ms)^define [^\r\n]*@vm_interpreter_' + [regex]::Escape($symbol) + '_k[0-9a-f]+\([^\r\n]*\).*?^}'
        $clone = [regex]::Match($ir, $pattern)
        if (-not $clone.Success) { throw "Missing interpreter clone: $symbol in $file" }
        [pscustomobject]@{
            File = $file; Symbol = $symbol
            FusionGroups = [regex]::Matches($clone.Value, '(?m)^vmp\.fusion\.[^:]+:').Count
        }
    }
}
```

Expect `FusionGroups=4` for each of the four Java rows. The current protection receipt also records bytecode lengths under `methodBytecodeBytes` and `bytecodeVerifiedInLibrary=true`; the signed-APK report binds the packaged SO to that receipt.

Local evidence is under `work/dex2c-primitive-lowering-p24/`: `baseline/` preserves the original generated sources, raw/post IR, named inspection and APKs; `candidate/` contains the current generated source, actual raw/post IR, APKs and receipts. `artifact-evidence.json` records per-method fusion and bytecode correspondence, and `validation-report.json` joins the build, artifact and device results. These archives are not checked into Git or generated by Gradle; a fresh clone will not contain them. The older p23 archive under `work/core-hardening-sample/` remains a historical record.

The current host/module APK sizes are 878174/335372 bytes. The dex2c SO grew from 258536 to 267048 bytes while the two VM bytecode blobs became shorter; this is not evidence of an overall size or performance improvement. The 45 core tests passed, including the existing host differential fixture and a separate O1 `-Xcheck:jni` fixture for shared reference/int/long locals, category-2 copies, exception-handler locals and control-flow boundaries. M1 Java/native sample validation is complete; full QDReadHook business coverage and performance comparisons remain outstanding. Device validation covers the ARM64 API 37 device with 4 KiB pages stated above.
