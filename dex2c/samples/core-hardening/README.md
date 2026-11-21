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

## p26 verified result and artifact checks

The p26 build in `work/m3-frame-wipe-p26/build-sample.log` succeeded against the frozen p25 tree at `3133e3589e18a11a8cb7b0a534ba7f12cc84fafd`. The sample algorithms, 39 assertions, configuration and all 22 non-README source files are unchanged. On 2026-11-21, the frozen candidates passed this sequence on OnePlus 7 / API 37 / ARM64 / 4 KiB pages / LSPosed 2.2.1 API 102:

| Run | Main / worker PID | Result per process | Log under `work/m3-frame-wipe-p26/` |
| --- | --- | --- | --- |
| Enabled, 23:24 | 10771 / 10800 | 39 PASS | `device-enabled.log` |
| Disabled, 23:24 | 10850 / 10868 | FAIL, module not active | `device-disabled.log` |
| Restored, 23:24 | 10923 / 10949 | 39 PASS | `device-restored.log` |

The installed APK hashes match the frozen candidates. The declared scope is unchanged before and after the sequence, and the module is enabled at the end. Each passing process covers 8 dex2c int, 21 long, 8 native int and 2 invalid-`rounds` exception cases. The signed-APK static check passed for both critical methods, with strict VMP, post, hardened CSE, certificate binding and entry self-check enabled. `segmentedData` and runtime `apkSignatureVerification` remain disabled.

p26 erases each retired VM control frame after restoring all caller state. The actual `protected.raw.ll` and post `protected.ll` both restore 11 fields before a volatile byte loop clears the full 88-byte slot, including 4 bytes of padding. The real `protected.o` restore helper matches all 64 non-relocated AArch64 instructions in its 440-byte `linked.so` function; 46 relocated instructions are excluded from that object/link comparison. The full 440 bytes match the packaged SO, whose full contents match the library inside the APK. Two local restore symbols share the same name in `linked.so`; the evidence resolves the matching one by its length and all non-relocated instructions.

Both unchanged Java methods still have four fusion groups in the actual raw/post IR and 4158/1351 bytes of bytecode. The native arithmetic path retains four groups and 363 bytecode bytes. Its call-free IR has no restore helper; the restore-code binding above applies to `protected.o`.

| Artifact | Frozen p25 bytes | p26 bytes | Change |
| --- | --- | --- | --- |
| Host APK | 878174 | 878174 | 0 |
| Module APK | 336380 | 337764 | +1384 |
| dex2c SO | 268056 | 269440 | +1384 |
| Native SO | 31544 | 31600 | +56 |

Local p26 evidence is under `work/m3-frame-wipe-p26/`: `candidate/` retains the 15 actual artifacts; `artifact-evidence.json` records hashes, sizes and unchanged sample sources; `device-results.json` records the three device phases; `sol/machine-evidence.json` and `sol/machine-evidence-notes.md` bind the actual restore code; `validation-report.json` joins the results. The LLVM 21 call-frame regression passed all six device modes, including real O2 protected post, and two frozen p25 negative controls failed with exit 38. The shared test also passed all six default LLVM 20 compile/link modes; the wipe itself is only shipped for LLVM 21 in this batch. No separate p26 wipe timing was measured. Cache cleanup and scoped CSE/QSEG buffers remain later M3 work. These local evidence archives are not checked into Git or generated by Gradle.

## Historical p25 result and artifact checks

The p25 build in `work/m2-variants-p25/build-sample.log` succeeded. The frozen comparison is p24 commit `b9c71b78bb11358a49f6dc6f59d61d2a8f452a78`; the sample algorithms, 39 assertions, configuration and 22 non-README source files are unchanged. On 2026-11-21, the candidate APKs produced these results on OnePlus 7 / API 37 / ARM64 / 4 KiB pages / LSPosed 2.2.1 API 102:

| Run | Main / worker PID | Result per process | Log under `work/m2-variants-p25/` |
| --- | --- | --- | --- |
| Enabled, 21:32 | 8892 / 8919 | 39 PASS | `device-enabled.log` |
| Disabled, 21:33 | 9039 / 9057 | FAIL, module not active | `device-disabled.log` |
| Restored, 21:33 | 9111 / 9137 | 39 PASS | `device-restored.log` |

The 39 checks comprise 8 dex2c integer cases, 21 dex2c long cases, 8 native integer cases, and 2 invalid-`rounds` exception cases. The common `Entry` hook helper explicitly sets API 102 `ExceptionMode.PASSTHROUGH`; `rounds=-1` and `129` assert both the exception type and message. Installed APK SHA-256 values match the frozen candidates, and the module is enabled at the end of the test.

The dex2c protection receipt is `module/build/intermediates/dex2c/release/native/protection.json`; the final signed APK check is `module/build/reports/dex2c/release/apk-verification.json`, both relative to this sample. Its two `criticalMethods` passed the signed-APK static check. The dex2c methods use strict VMP, post, hardened CSE, certificate binding and entry self-check. `segmentedData` and runtime `apkSignatureVerification` are disabled.

p24's call-free int/long scalar lowering remains active. Values synchronize before helpers, JNI calls and real control-flow boundaries, including exception handlers; reference cleanup, floating-point and throwing operations retain their original paths. p25 independently chooses native or same-width carry/borrow computation and target-first or target-last field order for each fusion group at compile time. At most the first add/sub in each group is replaced; zero pending bits exit immediately and propagation takes at most the original bit width in rounds. Both unchanged Java methods retain four groups in the actual raw/post IR used to produce the packaged SO:

| Method | p24 → p25 groups | p25 raw / post carry loops | p24 → p25 bytecode |
| --- | --- | --- | --- |
| `accumulate(JI)J` | 4 → 4 | 1 / 1 | 4158 → 4158 bytes |
| `calculate(III)I` | 4 → 4 | 1 / 1 | 1351 → 1351 bytes |

Each method's raw/post bytecode is identical and present in the final dex2c SO. `NativeCompiler` retains value names on the actual protected steps, so counts come from the packaged compilation chain. Each actual `protected.o` clone matches all non-relocated instructions in `linked.so`; the corresponding 41080/36896 code bytes match the packaged SO. This uses the real directly compiled objects.

The native `core_fusion_calculate` has four groups, one carry/borrow loop and 363 bytes of bytecode. Its `lib/arm64-v8a/libcore_fusion.so` is 31544 bytes versus p24's 31456; its actual `arithmetic.o` clone matches all non-relocated instructions in the final library. This path uses strict VMP/post and does not claim dex2c CSE or certificate protection. Release builds do not pass `-irobf-debug`, and post IR contains no runtime debug helpers.

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

Expect `FusionGroups=4` for each of the four Java rows. The protection receipt also records bytecode lengths under `methodBytecodeBytes` and `bytecodeVerifiedInLibrary=true`; the signed-APK report binds the packaged SO to that receipt.

Review added two i64 vectors whose high-bit results survive the final `& y`. New semantic drivers passed against all 15 original shared libraries, with device SO hashes unchanged; `work/m2-variants-p25/semantic-highbits/results.json` records this separate check without timing.

Local p25 evidence is under `work/m2-variants-p25/`: `baseline/` freezes the p24 compiler, sample APK/IR and receipts; `candidate/` contains the actual p25 objects, IR, SOs, APKs and receipts. `artifact-evidence.json` records per-method fusion/bytecode correspondence, `sol/machine-evidence.json` binds the actual code, and `validation-report.json` joins the build, artifact and device results. The release-only `fusion-device/results.json` records 14 candidates covering 16 groups and all 60 valid handler/layout combinations with independent device references. These archives are not checked into Git or generated by Gradle; a fresh clone will not contain them. The p23/p24 archives remain historical records.

The p25 host/module APK sizes are 878174/336380 bytes. The dex2c SO is 267048→268056 bytes versus p24, with executable sections totaling 209420→210468 bytes; bytecode lengths are unchanged. Five interleaved repeats of fixed standalone VM artifacts use identical frozen drivers, 100 warmup calls and 2000 calls per metric; checksums match. The two high-bit-observing vectors added after review are a separate semantic regression and do not replace these timing drivers or records. The i64 H1/L0 representative has 4.270/4.167/4.184 microsecond medians for typical/worst carry/worst borrow inputs versus p24's 3.203/3.211/3.224. A p25 H0/L0 representative also changes to 4.136/4.144/4.075. These are coarse whole-VM timings without CPU affinity or frequency locks, so the roughly 30% difference cannot be attributed entirely to the new loop. p25 kept the one-add/sub-per-group scope; full QDReadHook business coverage and a production performance budget remain outstanding. See the [M2 cost record](../../../docs/CORE_HARDENING_ROADMAP.md#m2-handler-与操作数布局变体). Device validation covers the ARM64 API 37 device with 4 KiB pages stated above.
