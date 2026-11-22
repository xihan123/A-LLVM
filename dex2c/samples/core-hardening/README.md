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

## p30 scoped CSE probe

Add `-PcoreHardening.cseScoped=true` to the build command above to include the independent
`libcore_cse.so` probe. The property defaults to `false`. It compiles `scoped.cpp` with LLVM 21
hardened CSE, `-irobf-cse-scoped` and `NDKP_CSE_SCOPED`, binds the library to the host process
`io.github.xihan123.corehardening.sample.host` (including `:worker`) and the module APK's signer
certificate, and seals/verifies the linked library before strip and APK signing. The separate CSE
crypto runtime retains its two strict VMP entries, memops, entry SelfCheck and real post pass.
The JNI bridge and byte/UTF-16 consumers are ordinary separate translation units; hidden scoped
runtime helpers are not dynamically exported. The original arithmetic/JNI algorithms, host probes
and 39 assertions retain their behavior.

When fresh hooks are installed, each active process logs `cse-scoped-probe result=0` with its PID.
The probe calls a `noexcept` business function that directly consumes immutable byte and UTF-16
literals. Each invocation authenticates new independent mappings and releases them before its
ordinary return. It does not turn the existing Java arithmetic methods or their string storage
into scoped CSE. The supported pointer/exit contract and full mapping cleanup checks are described
in [CSE hardened](../../../runtime/CSE_HARDENED.md#函数作用域明文p30llvm-21可选).

This sample's native target is Android 26. Its successful linked layout places the runtime's active
8-byte format Magic in R-X `PT_LOAD` and the real CSE payload in R-W. The independent Android 29
fixture explicitly links with `--no-rosegment` to obtain that layout: a separate nonexecuting
read-only segment would make the unchanged strict sealer identify Magic as a malformed payload.
The actual constant remains authenticated as executable-segment bytes; it is not removed or hidden
from the sealer. API 26 is a compilation target here, not an API 26 device result.

The p30 build uses frozen p29 baseline `81337e0c3d8b7707e2cc600751eb9900d4250a0c` and the
compiler-freeze-3 production source. On 2026-11-22, the final signed candidates passed this sequence
on OnePlus 7 / GM1901 / API 37 / ARM64 / 4 KiB / LSPosed 2.2.1 API 102:

| Run | Main / worker PID | Original checks per process | Scoped probe per process |
| --- | --- | --- | --- |
| Enabled, 15:32:44 | 6852 / 6887 | 39 PASS | 0 |
| Disabled, 15:32:49 | 7040 / 7058 | FAIL, module not active | Not executed |
| Restored, 15:32:53 | 7194 / 7228 | 39 PASS | 0 |

The installed host APK SHA-256 is `bd9eb23d71f59c150ac0f2dd81abd3c8352b3b385c6da7f1afb2fabf0a64cd58`;
the module APK is `aaa898a0ace5c1df781d7253a1014f6ffaf8d826afa9424938197e96507a5c2b`.
Both use the verified signer SHA-256 `441562e5d5a37c56ec87baec57433ac84208726039b549be177bba67762e37b3`.
Scope is unchanged and the module is enabled at the end. The final Clang SHA-256 is
`fa8d40519babab6260ec474bca8132ea4e1872111c34f8a097684c23b0b057a9`.

Local p30 evidence is under `work/m3-cse-scoped-p30/`: `candidate/` retains the final actual artifacts,
`sample-artifact-evidence.json` binds their build/package bytes, `sample-signature-binding.json`
records signature and hidden-helper checks, and `sample-device-final/results.json` joins the
three fresh log windows and installed APK hashes. The independent fixture-freeze-4 execution is
under `scoped-fixture-3/`, with `build.json`, `results.json` and per-command raw streams. Its 22
device cases prove real RO publication, full page-padding wipe, actual unmap and observer defect
detection separately from these sample regression logs; signed O0/O2/main, O2 `:worker`, wrong
certificate/package and tag/guard cases use five legitimately signed APKs and the real production
input paths. `NDKP_APK_VERIFY` remains undefined: host apksigner verification is separate from
runtime certificate extraction/binding. The ordinary CSE runtime, descriptor and recheck device
regressions also passed with the final compiler.

Source freezes are snapshots, not execution receipts; compiler-freeze-2 has only snapshot evidence.
The failed `scoped-fixture-1` and `scoped-fixture-2` directories remain separate from the successful
third build. No new p30 performance measurement, physical 16 KiB device, API 26/29 device, Linux
runtime or complete QDReadHook business coverage is claimed. Scoped mappings and leases are the
cleanup boundary; copies, stack/register/spill plaintext and other crypto locals remain outside it.
These local evidence archives are not checked into Git or generated by Gradle.

## Historical p28 verified sample result

The p28 build in `work/m3-inline-wipe-p28/build-sample.log` succeeded against frozen p27 commit `117ef36e16a13295ec8277ed9682f1f5de775364`. The algorithms, original 39 assertions, configuration and all 22 non-README sample source files are unchanged. On 2026-11-22, the frozen candidates completed this sequence on the same OnePlus 7 / API 37 / ARM64 / 4 KiB / LSPosed 2.2.1 API 102 environment:

| Run | Main / worker PID | Result per process | Log under `work/m3-inline-wipe-p28/` |
| --- | --- | --- | --- |
| Enabled, 02:04:45 | 15623 / 15653 | 39 PASS | `device-enabled.log` |
| Disabled, 02:04:49 | 15706 / 15724 | FAIL, module not active | `device-disabled.log` |
| Restored, 02:04:52 | 15777 / 15806 | 39 PASS | `device-restored.log` |

Installed APK hashes match `candidate-artifact-evidence.json`, scope is unchanged, and the module is enabled at the end. Both critical methods passed the signed-APK static check. Strict VMP, post, hardened CSE, certificate binding and entry SelfCheck remain enabled; `segmentedData` and runtime `apkSignatureVerification` remain disabled.

p28 wipes the three owned heap inline-constant buffers used by VM store, insertvalue and extractvalue after their final consumption and before free, using the original malloc length. Borrowed data-frame values remain live. The extractvalue source address is only computed when allocation or borrowing provided a nonnull source. Allocation failure still consumes the full inline operand and continues with its existing zero-result behavior.

The sample's four pristine raw/post IR artifacts contain no malloc/free sites, so these sample results establish overall regression coverage. The separate `tests/vmp/inline_constants.ll` fixture uses `noinline optnone` to preserve three actual VM allocation paths of 17, 24 and 31 bytes. It verifies the real compiler's bytecode and schedule, then XORs only the first inline payload into a legal nonzero VM input. This does not extend emitter support for nonzero aggregates. The observer reads the actual allocation at free and never writes poison after decoding; a separate oracle checks nonzero results, live borrowed data after insert/extract/store, and marker continuation after malloc failure. Pristine SelfCheck tests remain independent of the modified-input branch. `malloc(0)` is inspected statically and has no dynamic fixture coverage.

The four pristine and two observed O0/O2-post binaries all exited 0. Each observed binary produced six rows covering normal and failed allocation for all three sizes: normal frees had zero residual bytes and intact guards, failure made one malloc attempt and no free, and every output and continuation marker was correct. The two frozen p27 observed binaries exited 60 with all 17/24/31 payload bytes still nonzero, while guards and outputs remained correct. `sol/machine-evidence.json` traces all 12 owned allocation sites across six pristine clones through their original lengths, consumption, volatile wipe and merged free. Pristine and observed object function bytes are identical; the clones total 136,628 bytes, and each object-to-executed-binary set matches 31,346 non-relocated ARM64 instructions. Formal fixture artifacts are under `work/m3-inline-wipe-p28/memory-ops/inline-constants/`, with negative controls under `p27-negative/` and machine evidence under the batch's `sol/` directory.

| Artifact | Frozen p27 bytes | p28 bytes | Change |
| --- | --- | --- | --- |
| Host APK | 878174 | 878174 | 0 |
| Module APK | 340260 | 354724 | +14464 |
| dex2c SO | 271936 | 270016 | -1920 |
| Native SO | 32640 | 33096 | +456 |

These are sizes of frozen actual artifacts from randomized builds; they do not establish an overall size or performance benefit. No new p28 timing was measured. The final compiler SHA-256 is `3f7a8140fb439599a69001da01dad4678c9c1d5f2d8c1cdcad08c0326e989c6f`. The LLVM 21 bitcode contains no test hooks. LLVM 20 only receives compile/link compatibility checks of its existing default tests, without the new fixture, heap observer or post. At p28, scoped CSE/QSEG buffers, crypto locals and other M3 lifecycle work were future batches; stack/register/spill plaintext is outside that batch. Local evidence archives are not checked into Git or generated by Gradle.

## Historical p27 result and artifact checks

The final p27 build in `work/m3-cache-wipe-p27/build-sample-final.log` succeeded against frozen p26 commit `4e68950401953c81f8501c983c011ba25a96c31a`. The algorithms, 39 assertions, configuration and all 22 non-README sample source files are unchanged. On 2026-11-22, the frozen final candidates passed the following sequence on the same OnePlus 7 / API 37 / ARM64 / 4 KiB / LSPosed 2.2.1 API 102 environment:

| Run | Main / worker PID | Result per process | Log under `work/m3-cache-wipe-p27/` |
| --- | --- | --- | --- |
| Enabled, 01:20:39 | 11785 / 11819 | 39 PASS | `device-enabled.log` |
| Disabled, 01:20:43 | 11879 / 11898 | FAIL, module not active | `device-disabled.log` |
| Restored, 01:20:46 | 11952 / 11981 | 39 PASS | `device-restored.log` |

Installed APK hashes match the final frozen candidates, the scope is unchanged, and the module is enabled at the end. Both critical methods passed the signed-APK static check with strict VMP, post, hardened CSE, certificate binding and entry self-check. `segmentedData` and runtime `apkSignatureVerification` remain disabled.

p27 clears three persistent interpreter cache families immediately before native dispatch and at the common normal/native-exception exit: the 152-byte ChaCha object, including 2 bytes of internal padding; the 8-byte opcode key and 29-byte decode map; and the 8-byte layout key plus three layout IDs. New BBs and live material mismatches clear the full ChaCha object. When only the block changes, offsets 28–39, 41 and 88–151 are cleared, totaling 77 bytes; valid key/nonce bytes at offsets 44–87 remain available. Cache hits keep their existing path.

The pristine final `protected.raw.ll` and real post `protected.ll` retain three full 152-byte loops in each Java interpreter clone, for new BBs, native dispatch and common exit. The other 48 cache bytes are cleared before each native call and return. The call-free native arithmetic clone has new-BB and exit loops. Both actual ChaCha helpers retain the full wipe before KDF and the exact block-only byte stores. These checks use the uninstrumented sample artifacts. The separate runtime observer test reads the real TLS caches and actual helper paths; material refill proves KDF rebuilding but does not establish runtime coverage of a live old-tuple mismatch, since ordinary lifecycle boundaries clear the cache earlier.

All 9630/8639 non-relocated AArch64 instructions in the actual Java clones match `linked.so`; 536/502 relocated instructions are excluded from that comparison. Their complete 40664/36564 bytes match the packed library at the linked addresses. The actual 904-byte ChaCha helper and 444-byte retired-frame helper are also uniquely bound despite duplicate local names, and their full bytes match the packed library. The entire packed library equals its APK entry. In the stripped native library, a unique relocation-free instruction window locates each function before comparing all non-relocated instructions: 4755 for the 19760-byte arithmetic clone and 223 for its 908-byte ChaCha helper.

The 11 caller fields are still restored before the complete 88-byte retired-frame wipe. Both Java methods and the native path retain four fusion groups each, with raw/post field-consumption and carry dataflow matching; bytecode lengths remain 4158/1351/363 bytes. p27 also fixes LLVM 21 fusion continuation state extraction: it snapshots the real scalar handler's normal exits before specializing fusion, requiring equal PHI inputs and valid SSA dominance. This removes the optimized unreachable NOP edge dependency exposed by the `frame_sret` regression.

| Artifact | Frozen p26 bytes | p27 bytes | Change |
| --- | --- | --- | --- |
| Host APK | 878174 | 878174 | 0 |
| Module APK | 337764 | 340260 | +2496 |
| dex2c SO | 269440 | 271936 | +2496 |
| Native SO | 31600 | 32640 | +1040 |

Final local evidence is under `work/m3-cache-wipe-p27/`: `candidate/` contains the 15 actual final artifacts, `candidate-artifact-evidence.json` verifies their hashes and all 22 unchanged sample sources, `device-results.json` records the three phases, and `sol/machine-evidence.json` binds pristine IR, objects, libraries and APK. The final compiler hash is recorded in the protection receipt and `clang-candidate.json`; `candidate-initial/` is the earlier diagnostic candidate and is separate from these final artifacts.

All six call-frame device modes passed, including O2 protected with real post. The two frozen p26 controls using the final observer attributes exited 50 with `bits=102`, detecting residual caches before KDF/block generation, at native dispatch and after exit. Strict, post, fusion, string protection, ABI and build-system checks passed, as did device roundtrip's four callback and eight globals/TLS combinations. LLVM 20 passed its six default compile/link modes; this batch ships the wipes and fusion correction for LLVM 21. No separate p27 timing was measured. The three heap inline-constant buffers, crypto locals and scoped CSE/QSEG buffers remain future M3 work. These local evidence archives are not checked into Git or generated by Gradle.

## Historical p26 result and artifact checks

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

Local p26 evidence is under `work/m3-frame-wipe-p26/`: `candidate/` retains the 15 actual artifacts; `artifact-evidence.json` records hashes, sizes and unchanged sample sources; `device-results.json` records the three device phases; `sol/machine-evidence.json` and `sol/machine-evidence-notes.md` bind the actual restore code; `validation-report.json` joins the results. The LLVM 21 call-frame regression passed all six device modes, including real O2 protected post, and two frozen p25 negative controls failed with exit 38. The shared test also passed all six default LLVM 20 compile/link modes; the wipe itself is only shipped for LLVM 21 in this batch. No separate p26 wipe timing was measured. At that stage, cache cleanup and scoped CSE/QSEG buffers remained later M3 work. These local evidence archives are not checked into Git or generated by Gradle.

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
