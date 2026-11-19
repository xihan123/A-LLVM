# NativeCompiler runtime artifact cache check

`runtime_cache.py` checks one real, standard `DeviceFixtures` build twice at the
**same absolute fixture path**, with segmented data and APK signature verification
enabled. It does not build, delete files, invoke a device, audit an APK, or measure
performance. Keep the existing three-build M4 fixtures unchanged.

Use Python 3.11+, the same compiler/NDK, configuration, signing certificate and
frozen `build_diversity.py` expected contract in both rounds. The contract fixes
the complete method list and original Java/Kotlin/common class bytes. For the M4
standard fixture it contains 55 methods, 17 baseline and 998 common classes.
This checker is deliberately limited to that fixture shape (`nativeSymbols` and
`stringSymbols` empty, library `dex2c_semantics`, minSdk 26).

## Protocol

1. Create a new scratch fixture. Copy only the fixed local signing keystore and
   public certificate if necessary. Do not copy a cache or prior native outputs.
2. Run `begin` **before** the cold build. It reads the fixture and writes a new
   JSON ticket outside it; all documented regenerated files must be absent and
   `native/runtime-cache` empty or absent.
3. Run `:core:prepareDeviceFixtures` to completion and save the actual Gradle log
   outside the fixture. Run `snapshot` to a new external directory.
4. Only after the cold snapshot succeeds, delete the exact regenerated files
   below from the scratch fixture. Keep its absolute path, `test.jks`, generated
   sources and the entire `native/runtime-cache` unchanged.
5. Run a new `begin --phase warm`, run the same Gradle task to completion, save its
   log, then `snapshot` to another new directory. Never rerun into either frozen
   snapshot. Compare the two snapshots to a new report path.

Example (PowerShell, from the repository root; substitute your new evidence root,
fixed expected contract, NDK and compiler paths):

```powershell
$python = 'F:/Python/Python314/python.exe'
$fixture = '<new-evidence-root>/accepted-fixture'
$contract = '<existing-frozen-evidence>/expected-contract.json'
$coldBegin = '<new-evidence-root>/cold-begin.json'
$warmBegin = '<new-evidence-root>/warm-begin.json'
$cold = '<new-evidence-root>/cold'
$warm = '<new-evidence-root>/warm'
& $python tests/dex2c/runtime_cache.py begin --fixture $fixture --phase cold --expected-contract $contract --output $coldBegin
# Stop if any command fails. Preserve this same command/configuration for warm:
& dex2c/gradlew.bat -p dex2c --no-daemon --console=plain --no-build-cache --rerun-tasks `
    :core:prepareDeviceFixtures "-Pdex2c.fixtureDirectory=$fixture" `
    '-Pdex2c.segmentedData=true' '-Pdex2c.verifyApkSignature=true' `
    '-Pdex2c.nativeOnly=false' '-Pdex2c.integrityRecheck=false' `
    '-Pdex2c.ndk=<NDK>' '-Pdex2c.hostCompiler=<compiler>'
& $python tests/dex2c/runtime_cache.py snapshot --fixture $fixture --begin $coldBegin --output $cold
# Remove only FRESH_FILES and files under FRESH_TREES below, in this scratch fixture.
& $python tests/dex2c/runtime_cache.py begin --fixture $fixture --phase warm --expected-contract $contract --output $warmBegin
# Run the identical Gradle command above, then:
& $python tests/dex2c/runtime_cache.py snapshot --fixture $fixture --begin $warmBegin --output $warm
& $python tests/dex2c/runtime_cache.py compare --cold $cold --warm $warm --output '<new-evidence-root>/comparison.json'
```

All output paths must be new. Both snapshots and begin tickets must be outside
the fixture. `begin` is an absence observation, not permission to delete any
directory. It cannot retroactively validate a build already started. The caller
retains the real Gradle command, log and exit status as separate build evidence.

### Exact regenerable cleanup scope

The script exports `FRESH_FILES`, `FRESH_TREES`, and `RUNTIME`; obtain their exact
JSON list without changing anything:

```powershell
& $python -c "import json,sys; sys.path.insert(0,'tests/dex2c'); import runtime_cache as r; print(json.dumps({'files':r.FRESH_FILES,'trees':r.FRESH_TREES,'runtime':r.RUNTIME},indent=2))"
```

`FRESH_FILES` contains the 29 runtime logs and their 29 output artifacts, the 14
uncached logs, and these regenerated files:

```text
inputs.json
original.jar
generated/classes.jar
generated/selection.json
native/protected.raw.ll
native/protected.ll
native/protected.o
native/registration.ll
native/registration.o
native/dex2c_runtime.ll
native/dex2c_runtime.o
native/qseg-image.cpp
native/qseg-image.o
native/linked.so
native/protection.json
native/segments.json
native/signing-cert.der
```

`FRESH_TREES` means **files inside** `native/assets`, `native/jniLibs`, and
`native/staging`. Preserve all directories and every other file, especially
`native/runtime-cache` and `test.jks`. The 14 uncached logs are `compiler`, `vmp`,
`optimize`, `object`, `registration`, `registration-object`, `dex2c_runtime`,
`dex2c_runtime-object`, `qseg-prepare`, `qseg-image`, `link`, `seal`, `strip`, and
`seal-verify`, each with `.log`. There is no optional native-only branch here.

## Independent cache denominator and keys

The pinned 22 Mbed TLS names are:

```text
asn1parse asn1write bignum bignum_core bignum_mod bignum_mod_raw
constant_time ecdsa ecp ecp_curves md oid pk pk_ecc pk_wrap pkparse
pkwrite platform_util rsa rsa_alt_helpers sha256 sha512
```

Each has log `native/apkverify-{name}.c.log`, output
`native/apkverify-{name}.c.o`, and source
`native/a_llvm/third_party/mbedtls/library/{name}.c`. The copied source manifest
must exactly match this list. The remaining seven mappings are:

| Log under `native/` | Artifact under `native/` |
| --- | --- |
| `apkverify-apkverify.cpp.log` | `apkverify-apkverify.cpp.o` |
| `apkverify-ndkp_apkverify.cpp.log` | `apkverify-ndkp_apkverify.cpp.o` |
| `ndkp_apkcert.log` | `ndkp_apkcert.o` |
| `cse-vmp.log` | `cse-runtime.raw.ll` |
| `cse-optimize.log` | `cse-runtime.ll` |
| `cse-object.log` | `ndkp_cse_runtime.o` |
| `qseg-runtime.log` | `qseg-runtime.o` |

For every target the checker independently rebuilds the exact command from
`NativeCompiler` / `ApkVerifierBuild` and the original fixture path. Its cache
directory is `native/runtime-cache/SHA256(inputs UTF8 + each argv prefixed by NUL)`.
`inputs` is the runtime fingerprint except for CSE optimize (append raw IR SHA256)
and CSE object (append optimized IR SHA256). Every cache entry must contain only
`artifact` and `sha256`; the 29 keys must exactly cover the fixed denominator.
This does not infer cache ownership from an observed digest or an intersection.

## What passes

Snapshots copy the public fixture files, every baseline/protected/common input
JAR or class directory (including shared Gradle outputs), the begin ticket,
contract and tool/header hash evidence. `.jks`, `.p12`, `.pfx`, and `.keystore`
files are excluded case-insensitively; public DER files remain. Symlinks and
junctions are rejected. Snapshot file hashes and regenerated-file timestamps are
checked again when reading, with the cache-restore timestamp exception below.
Do not modify the frozen evidence or its timestamps.

The runtime fingerprint is recomputed from actual compiler/properties/certificate
hashes and all runtime/resource/sysroot header inputs, following Java's path
ordering and separators. Tool binaries and external headers are identified by
their complete hash manifest rather than copied. Runtime files and input JARs
are copied. The fixed tool/configuration/class/certificate identities and these
manifests must agree across rounds.

Cold must have zero hits. Each warm log must be exactly one NativeCompiler hit
line, with the digest equal to its named final output, cache artifact and cache
receipt. Warm begins after cold was frozen, with a new token, and its cache before
and after must be identical to the cold snapshot. All 43 logs and regenerated
business/helper outputs must have been absent at begin and newly written after it.
Cold runtime artifacts also require timestamps at or after cold begin. For warm
only, the 29 exact runtime artifacts may retain their cold cache timestamps:
Windows `Files.copy` can preserve `LastWriteTime` while restoring an absent file.
Their absence at warm begin, fresh exact hit logs, and matching cache key, output
digest and receipt establish the restoration. This exception never applies to
logs or uncached business/helper outputs; snapshot capture and re-reading use the
same freshness check. Do not touch timestamps or rerun a build to satisfy it.
All expected methods are rechecked using the existing QSEG diversity helpers;
the report retains each method's cold/warm resource ID, content hash, function
key hash and dispatch sequence hash. Every dimension and business raw IR, final
IR and object must change. The native protection receipt's output hashes are
also checked.

This is evidence of runtime **artifact reuse correctness**, while the business
pipeline still executes. Equal bootstrap runtime material is expected. It does
not establish business reuse, wall-clock speedup, APK/device semantics, or close
the independent M3 runtime gates. Keep the existing APK verifier and device
checks for those claims.

Host regression tests (no Clang, Gradle or device):

```powershell
& $python -m unittest discover -s tests/dex2c -p test_runtime_cache.py
```

# Device negative-case evidence protocol

`device.py` still builds/signs its APK variants and runs the baseline/protected
semantic checks against one explicit serial. Run it only against a disposable
copy of a frozen fixture and its fixed signing key. `--report <path>` selects an
external evidence file; the default remains `<fixtures>/device-results.json`.
The selected report is replaced with the current run's `running` record before
setup starts, then atomically updated after each result and negative-case stage.
A failed run has `status: failed` and retains completed cases plus the failing
attempt; an interrupted process may leave `running`, which is not a pass.
Preserve prior evidence at a different path before invoking this script.

Schema version 2 retains the existing `serial`, `sdk`, `pageSize` and `results`
fields on a successful run. Negative rows retain `mode`, `rejected` and
`exitCode`, and add `expectedCodes`, the exact APK path/SHA256/byte size, UTC
timestamps, the local ADB argv, remote child argv/environment and separate push
and execution evidence. `returnCode` in each stage is the local ADB process
status; negative-row `exitCode` is the child status from the validated shell
protocol. Each stream has readable UTF-8 replacement text and a lossless Base64
copy (`stdoutBase64` / `stderrBase64`). Timeouts retain available partial bytes
and no invented return status. ADB transport, local launch, remote launch,
protocol, unexpected-exit and business-stdout failures cannot set `rejected`.

The negative shell command uses an invocation-specific token on stderr. It
guards the absolute `/system/bin/app_process`, emits `BEGIN`, installs an EXIT
trap in the same child subshell as `exec`, and reports the child's status with
`EXIT:<code>` from its parent. A failed exec emits `LAUNCH_FAILED`; a successful
exec replaces the shell and its trap. Acceptance requires local ADB status 0,
one ordered `BEGIN`/`EXIT` pair, no launch-failure marker or recognized launcher
diagnostic, byte-empty stdout and a child status in that case's `expectedCodes`.
Whitespace-only stdout also fails. Cleanup runs in `finally`, records failures
without replacing the primary error, and removes only exact uploaded paths in
this invocation's UUID directory before trying `rmdir` on that directory.

All 14 segmented/QSEG negative cases require **127**. For nonsegmented fixtures,
`tampered-vm`, `tampered-cse-vm` and `tampered-code` allow **127 or 137**, because
the existing self-check/VM path tries SIGKILL before its exit-group fallback.
`wrong-signer` allows **127** when APK signature verification is enabled, or
**127 or 137** when it is disabled. `tampered-cse-tag`,
`tampered-cse-ciphertext` and `cross-build-cse-records` require **127**. No case
accepts arbitrary nonzero status or 139. These contracts follow the existing
QSEG/CSE/APK-verifier exit-group paths and raw-syscall self-check fallback; they
do not change the APK construction or runtime. The nonsegmented exit contracts
have host regression coverage but were not device-validated in this change.

`expected-exit-signature` means exactly the observed command/stream/status
signature. It does not uniquely establish a native rejection cause: a process
can exit 127 after successful exec for another reason. Keep the raw evidence,
positive semantic results and fixture identities together, and do not infer a
new root cause from older reports that accepted any nonzero status.

Pure host regression checks, including malformed markers, ADB failure,
stdout contamination, partial-byte timeouts and report/cleanup failure paths:

```powershell
& $python -B -m unittest discover -s tests/dex2c -p test_device.py -v
& $python -B -O -m unittest discover -s tests/dex2c -p test_device.py -v
```

The exec/trap control also runs when a POSIX `sh` is on PATH; otherwise that
single control is explicitly skipped. Host checks do not replace Android mksh,
ADB transport or real-device validation of all generated APK cases.
