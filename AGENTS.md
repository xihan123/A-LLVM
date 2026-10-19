# Repository Guidelines

## Project Structure & Module Organization

A-LLVM packages patched Clang toolchains into Android NDK layouts.

- `obfuscation/llvm-20/` and `obfuscation/llvm-21/`: version-specific passes, headers, and `registration.patch` files.
- `obfuscation/aVMPInterpreter/`: shared VMP interpreter source.
- `include/ndkp.h`: public annotation macros; `runtime/`: app-side certificate-binding helpers.
- `scripts/`: NDK discovery, LLVM lookup, overlay application, and packaging utilities.
- `tests/`: Python unit tests, Bash integration checks, and C/C++ fixtures grouped by feature.
- `.github/workflows/`: validation, builds, and release automation; `config/`: channels and patchset version.

## Build, Test, and Development Commands

Run from the repository root. Use Python 3 (3.11 in CI), Bash/Git Bash, and CMake/Ninja. Python scripts use only the standard library.

```bash
python scripts/discover_ndk.py --dry-run --channels stable,beta,rc
python tests/discover/test_discover.py
python tests/locate-llvm/test_locate_llvm.py
bash tests/build-system-smoke/test_run.sh
```

These preview discovery and test scripts without a built NDK.

For local builds, check out the NDK's exact LLVM `Base revision` into `llvm-project/`, then apply its matching overlay (21 shown):

```bash
bash scripts/apply_overlay.sh --llvm-src "$PWD/llvm-project" --major 21
cmake -S llvm-project/llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_OBFUSCATION_LINK_INTO_TOOLS=ON \
  -DLLVM_TARGETS_TO_BUILD="AArch64;ARM;X86"
ninja -C build clang clang-resource-headers
```

Or let `scripts/build_clang_local.sh` do all of it (auto-detects the unpacked NDK and LLVM major, sets up MSVC on Windows, incremental and idempotent, refreshes the NDK afterwards):

```bash
bash scripts/build_clang_local.sh --init   # first cold build (shallow-clones llvm-project at the base commit; honors HTTPS_PROXY)
bash scripts/build_clang_local.sh          # incremental rebuild after overlay edits
bash scripts/build_clang_local.sh --test   # also run the build-mode test suites
```

See `.github/workflows/build.yml` for host-specific configuration and NDK assembly. Run `bash tests/string-enc/check.sh <ndk_dir> <host>` against the assembled NDK; hosts are `linux-x86_64` or `windows-x86_64`.

## Coding Style & Naming Conventions

Follow surrounding code: two-space indentation for LLVM C++ and Bash, four spaces for Python. Use descriptive pass names such as `SelfCheck.cpp`, Python `snake_case`, and `NDKP_*` public macros. No repository-wide formatter or linter is configured. Preserve `.gitattributes` line endings and patch bytes. Regenerate `aVMP/vm.h` with `scripts/gen_vm_bitcode.sh`; do not edit generated arrays manually.

## Testing Guidelines

Python tests use `unittest`, `test_*.py` files, and `test_*` methods; integration checks use Bash assertions. No numeric coverage threshold is configured. Add regression cases to the relevant feature directory.

For overlay changes, validate `git apply --check` against each affected major's base revision, build Clang, and run string-encryption plus affected ABI/build-system tests. Run certificate-binding, anti-tamper, or fingerprint checks when relevant. VMP runtime changes require device semantic validation before release.

## Commit & Pull Request Guidelines

Follow the prevalent `type(scope): summary` convention, e.g. `fix(cert-bind): handle MSYS paths`; Chinese and English summaries both appear. PRs should explain behavior changes, link relevant issues, and report test commands, LLVM majors, hosts, and device results when applicable.

Keep obfuscation opt-in: no flags means no IR transformations. Preserve the NDK tool whitelist. Increment `config/patchset.env` for artifact-changing updates as described in `CONTRIBUTING.md`; never overwrite existing releases.
