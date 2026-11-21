"""Regression coverage for LLVM 21 adjacent integer-operation fusion."""

import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from opcode_diversity import inspect_fusion_structure


IR = r"""
define i32 @multi_cap(i32 %x, i32 %y, i32 %z) {
entry:
  %a1 = add i32 %x, %y
  %b1 = xor i32 %a1, %z
  %a2 = sub i32 %x, %z
  %b2 = and i32 %a2, %y
  %a3 = mul i32 %x, %y
  %b3 = or i32 %a3, %z
  %a4 = add i32 %y, %z
  %b4 = xor i32 %a4, %x
  %a5 = sub i32 %z, %y
  %b5 = and i32 %a5, %x
  %s12 = add i32 %b1, %b2
  %s34 = add i32 %b3, %b4
  %s1234 = add i32 %s12, %s34
  %result = add i32 %s1234, %b5
  ret i32 %result
}

define i32 @reserved_fence(i32 %x, i32 %y, i32 %z) {
entry:
  fence seq_cst
  %a1 = add i32 %x, %y
  %b1 = xor i32 %a1, %z
  %a2 = sub i32 %x, %z
  %b2 = and i32 %a2, %y
  %a3 = mul i32 %x, %y
  %b3 = or i32 %a3, %z
  %a4 = add i32 %y, %z
  %b4 = xor i32 %a4, %x
  %s12 = add i32 %b1, %b2
  %s34 = add i32 %b3, %b4
  %s123 = add i32 %s12, %s34
  %result = add i32 %s123, %b3
  ret i32 %result
}

define i32 @overlap(i32 %x, i32 %y, i32 %z) {
entry:
  %a = add i32 %x, %y
  %b = xor i32 %a, %z
  %c = or i32 %b, %y
  ret i32 %c
}

define i32 @zero(i32 %x, i32 %y, i32 %z) {
entry:
  %a = add i32 %x, %y
  %cmp = icmp eq i32 %a, 0
  %b = xor i32 %x, %z
  %result = select i1 %cmp, i32 %a, i32 %b
  ret i32 %result
}

define i8 @narrow8(i8 %x, i8 %y, i8 %z) {
entry:
  %a = add i8 %x, %y
  %b = xor i8 %a, %z
  ret i8 %b
}

define i16 @narrow16(i16 %x, i16 %y, i16 %z) {
entry:
  %a = sub i16 %x, %y
  %b = and i16 %z, %a
  ret i16 %b
}

define i32 @order(i32 %x, i32 %y, i32 %z) {
entry:
  %a = sub i32 %x, %y
  %b = sub i32 %z, %a
  ret i32 %b
}

define i32 @order_lhs(i32 %x, i32 %y, i32 %z) {
entry:
  %a = xor i32 %x, %y
  %b = sub i32 %a, %z
  ret i32 %b
}

define i32 @order_rhs(i32 %x, i32 %y, i32 %z) {
entry:
  %a = xor i32 %x, %y
  %b = sub i32 %z, %a
  ret i32 %b
}

define i32 @loop(i32 %x) {
entry:
  br label %body

body:
  %result = phi i32 [ 0, %entry ], [ %second, %body ]
  %count = phi i32 [ 0, %entry ], [ %next_count, %body ]
  %first = add i32 %result, %x
  %second = mul i32 %first, 3
  %next_count = add i32 %count, 1
  %cond = icmp eq i32 %next_count, 4
  br i1 %cond, label %exit, label %body

exit:
  ret i32 %second
}

define i64 @i64_chain(i64 %x, i64 %y, i64 %z, i64 %w) {
entry:
  %a = add i64 %x, %y
  %b = xor i64 %a, %z
  %c = sub i64 %b, %w
  %d = and i64 %c, %y
  ret i64 %d
}
"""

FUNCTIONS = (
    "multi_cap", "reserved_fence", "overlap", "zero", "narrow8",
    "narrow16", "order", "order_lhs", "order_rhs", "loop", "i64_chain",
)

# Selection order in the IR above; the tuple retains the semantic pair and width
# when comparing native and carry implementations across randomized builds.
FUSIONS = {
    "multi_cap": [("add", "xor", 32), ("sub", "and", 32),
                  ("mul", "or", 32), ("add", "xor", 32)],
    "reserved_fence": [("add", "xor", 32), ("sub", "and", 32), ("mul", "or", 32)],
    "overlap": [("add", "xor", 32)],
    "narrow8": [("add", "xor", 8)],
    "narrow16": [("sub", "and", 16)],
    "order": [("sub", "sub", 32)],
    "order_lhs": [("xor", "sub", 32)],
    "order_rhs": [("xor", "sub", 32)],
    "loop": [("add", "mul", 32)],
    "i64_chain": [("add", "xor", 64), ("sub", "and", 64)],
}


def command(*args, timeout=180):
    result = subprocess.run([str(arg) for arg in args], capture_output=True,
                            text=True, encoding="utf-8", errors="replace",
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError("command failed ({}):\n{}{}".format(
            result.returncode, result.stdout, result.stderr))
    return result


def resource_dir(ndk):
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = ndk.resolve() / "toolchains" / "llvm" / "prebuilt" / host
    versions = list((base / "lib" / "clang").iterdir())
    resource = max(versions, key=lambda path: int(path.name))
    return base, resource


def fusion_lines(stderr):
    pattern = re.compile(
        r"^\[VMP_FUSION\] function=(\w+) opcode=(\d+) "
        r"first=(\w+) second=(\w+) width=(\d+) first_is_lhs=(\d+)"
        r"(?: handler=(\d+) layout=(\d+))?$",
        re.M,
    )
    return [
        {"function": function, "opcode": int(opcode), "first": first,
         "second": second, "width": int(width),
         "first_is_lhs": int(first_is_lhs), "handler": int(handler or 0),
         "layout": int(layout or 0)}
        for function, opcode, first, second, width, first_is_lhs, handler, layout
        in pattern.findall(stderr)
    ]


def byte_lengths(ir):
    pattern = re.compile(
        r"^@gv_code_seg_(\w+) = .*?\[(\d+) x i8\]", re.M)
    return {name: int(length) for name, length in pattern.findall(ir)}


def protected(clang, base, resource, source, output, functions, debug, strict=True):
    flags = ["-mllvm", "-irobf-vmp"]
    if strict:
        flags += ["-mllvm", "-irobf-vmp-strict"]
    flags += ["-mllvm",
             "-irobf-vm_functions=" + ";".join(functions)]
    if debug:
        flags += ["-mllvm", "-irobf-debug"]
    result = command(
        clang, "--target=aarch64-linux-android26",
        "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource),
        "-O0", "-fno-discard-value-names", "-fPIC", *flags,
        "-S", "-emit-llvm", source, "-o", output,
    )
    return result


def check_fusions(stderr, ir, functions=FUNCTIONS):
    lines = fusion_lines(stderr)
    counts = {name: 0 for name in FUNCTIONS}
    for line in lines:
        counts[line["function"]] += 1
    expected = {
        "multi_cap": 4,
        "reserved_fence": 3,
        "overlap": 1,
        "zero": 0,
        "narrow8": 1,
        "narrow16": 1,
        "order": 1,
        "order_lhs": 1,
        "order_rhs": 1,
        "loop": 1,
        "i64_chain": 2,
    }
    expected = {name: count if name in functions else 0 for name, count in expected.items()}
    assert counts == expected, counts
    assert len(re.findall(r"^\[VMP_FUSION_SPECIALIZE\]", stderr, re.M)) == sum(expected.values())
    by_function = {name: [line for line in lines if line["function"] == name]
                   for name in FUNCTIONS}
    for name, field, value in (("narrow8", "width", 8), ("narrow16", "width", 16),
                               ("order", "first_is_lhs", 0), ("order", "first", "sub"),
                               ("order", "second", "sub"), ("order_lhs", "first_is_lhs", 1),
                               ("order_lhs", "second", "sub"), ("i64_chain", "width", 64)):
        if name in functions:
            assert by_function[name][0][field] == value, (name, field)
    lengths = byte_lengths(ir)
    for name in functions:
        assert name in lengths and lengths[name] > 0, name
    return counts, lengths


def build_device_binary(clang, base, resource, obj, output, timings=False):
    driver = output.with_suffix(".c")
    driver.write_text(r'''#include <stdint.h>
#include <stdio.h>
#include <time.h>

extern uint32_t multi_cap(uint32_t, uint32_t, uint32_t);
extern uint32_t reserved_fence(uint32_t, uint32_t, uint32_t);
extern uint32_t overlap(uint32_t, uint32_t, uint32_t);
extern uint32_t zero(uint32_t, uint32_t, uint32_t);
extern uint8_t narrow8(uint8_t, uint8_t, uint8_t);
extern uint16_t narrow16(uint16_t, uint16_t, uint16_t);
extern uint32_t order(uint32_t, uint32_t, uint32_t);
extern uint32_t order_lhs(uint32_t, uint32_t, uint32_t);
extern uint32_t order_rhs(uint32_t, uint32_t, uint32_t);
extern uint32_t loop(uint32_t);
extern uint64_t i64_chain(uint64_t, uint64_t, uint64_t, uint64_t);

static uint32_t reference_multi_cap(uint32_t x, uint32_t y, uint32_t z) {
  uint32_t a1 = x + y;
  uint32_t b1 = a1 ^ z;
  uint32_t a2 = x - z;
  uint32_t b2 = a2 & y;
  uint32_t a3 = x * y;
  uint32_t b3 = a3 | z;
  uint32_t a4 = y + z;
  uint32_t b4 = a4 ^ x;
  uint32_t a5 = z - y;
  uint32_t b5 = a5 & x;
  uint32_t s12 = b1 + b2;
  uint32_t s34 = b3 + b4;
  uint32_t s1234 = s12 + s34;
  return s1234 + b5;
}

static uint32_t reference_reserved_fence(uint32_t x, uint32_t y,
                                         uint32_t z) {
  uint32_t a1 = x + y;
  uint32_t b1 = a1 ^ z;
  uint32_t a2 = x - z;
  uint32_t b2 = a2 & y;
  uint32_t a3 = x * y;
  uint32_t b3 = a3 | z;
  uint32_t a4 = y + z;
  uint32_t b4 = a4 ^ x;
  uint32_t s12 = b1 + b2;
  uint32_t s34 = b3 + b4;
  uint32_t s123 = s12 + s34;
  return s123 + b3;
}

static uint32_t reference_overlap(uint32_t x, uint32_t y, uint32_t z) {
  return ((x + y) ^ z) | y;
}

static uint32_t reference_zero(uint32_t x, uint32_t y, uint32_t z) {
  uint32_t a = x + y;
  return a == 0 ? a : x ^ z;
}

static uint8_t reference_narrow8(uint8_t x, uint8_t y, uint8_t z) {
  uint8_t a = (uint8_t)(x + y);
  return (uint8_t)(a ^ z);
}

static uint16_t reference_narrow16(uint16_t x, uint16_t y, uint16_t z) {
  uint16_t a = (uint16_t)(x - y);
  return (uint16_t)(z & a);
}

static uint32_t reference_order(uint32_t x, uint32_t y, uint32_t z) {
  uint32_t a = x - y;
  return z - a;
}

static uint32_t reference_order_lhs(uint32_t x, uint32_t y, uint32_t z) {
  return (x ^ y) - z;
}

static uint32_t reference_order_rhs(uint32_t x, uint32_t y, uint32_t z) {
  return z - (x ^ y);
}

static uint32_t reference_loop(uint32_t x) {
  uint32_t result = 0;
  for (unsigned i = 0; i < 4; ++i)
    result = (result + x) * 3;
  return result;
}

static uint64_t reference_i64_chain(uint64_t x, uint64_t y, uint64_t z,
                                    uint64_t w) {
  uint64_t a = x + y;
  uint64_t b = a ^ z;
  uint64_t c = b - w;
  uint64_t d = c & y;
  return d;
}

static int check32(const char *name, unsigned index, uint32_t got,
                   uint32_t expected) {
  if (got == expected)
    return 1;
  printf("failed: %s[%u] got=0x%08x expected=0x%08x\n", name, index,
         (unsigned)got, (unsigned)expected);
  return 0;
}

static int check8(const char *name, unsigned index, uint8_t got,
                  uint8_t expected) {
  if (got == expected)
    return 1;
  printf("failed: %s[%u] got=0x%02x expected=0x%02x\n", name, index,
         (unsigned)got, (unsigned)expected);
  return 0;
}

static int check16(const char *name, unsigned index, uint16_t got,
                   uint16_t expected) {
  if (got == expected)
    return 1;
  printf("failed: %s[%u] got=0x%04x expected=0x%04x\n", name, index,
         (unsigned)got, (unsigned)expected);
  return 0;
}

static int check64(const char *name, unsigned index, uint64_t got,
                   uint64_t expected) {
  if (got == expected)
    return 1;
  printf("failed: %s[%u] got=0x%016llx expected=0x%016llx\n", name, index,
         (unsigned long long)got, (unsigned long long)expected);
  return 0;
}

static uint64_t nanoseconds(void) {
  struct timespec stamp;
  clock_gettime(CLOCK_MONOTONIC_RAW, &stamp);
  return (uint64_t)stamp.tv_sec * UINT64_C(1000000000) + stamp.tv_nsec;
}

static void timing(const char *name, uint32_t (*call)(uint32_t, uint32_t, uint32_t),
                   uint32_t x, uint32_t y, uint32_t z) {
  const unsigned calls = 2000;
  uint32_t checksum = 0;
  for (unsigned i = 0; i < 100; ++i) checksum ^= call(x, y, z) + i;
  uint64_t start = nanoseconds();
  for (unsigned i = 0; i < calls; ++i) checksum += call(x, y, z) ^ i;
  uint64_t elapsed = nanoseconds() - start;
  printf("VMP fusion timing name=%s calls=%u ns=%llu checksum=%u\n", name,
         calls, (unsigned long long)elapsed, (unsigned)checksum);
}

static void timing64(const char *name, uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
  const unsigned calls = 2000;
  uint64_t checksum = 0;
  for (unsigned i = 0; i < 100; ++i) checksum ^= i64_chain(x, y, z, w) + i;
  uint64_t start = nanoseconds();
  for (unsigned i = 0; i < calls; ++i) checksum += i64_chain(x, y, z, w) ^ i;
  uint64_t elapsed = nanoseconds() - start;
  printf("VMP fusion timing name=%s calls=%u ns=%llu checksum=%llu\n", name,
         calls, (unsigned long long)elapsed, (unsigned long long)checksum);
}

int main(void) {
  static const uint32_t vectors[][3] = {
      {0, 0, 0},
      {1, 2, 3},
      {10, 3, 20},
      {UINT32_MAX, 0, 1},
      {UINT32_MAX, UINT32_MAX, UINT32_MAX},
      {INT32_MAX, 1, 0},
      {INT32_MAX - 1, 2, UINT32_MAX},
      {INT32_MAX + 1U, UINT32_MAX, 1},
      {0xfffffff0U, 0x20U, 0x10U},
      {0x80000000U, UINT32_MAX, 1},
  };
  for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    uint32_t x = vectors[i][0];
    uint32_t y = vectors[i][1];
    uint32_t z = vectors[i][2];
    if (!check32("multi_cap", i, multi_cap(x, y, z),
                 reference_multi_cap(x, y, z)))
      return 1;
    if (!check32("reserved_fence", i, reserved_fence(x, y, z),
                 reference_reserved_fence(x, y, z)))
      return 1;
    if (!check32("overlap", i, overlap(x, y, z),
                 reference_overlap(x, y, z)))
      return 1;
    if (!check32("zero", i, zero(x, y, z), reference_zero(x, y, z)))
      return 1;
    if (!check32("order", i, order(x, y, z), reference_order(x, y, z)))
      return 1;
    if (!check32("order_lhs", i, order_lhs(x, y, z), reference_order_lhs(x, y, z)))
      return 1;
    if (!check32("order_rhs", i, order_rhs(x, y, z), reference_order_rhs(x, y, z)))
      return 1;
    if (!check32("loop", i, loop(x), reference_loop(x)))
      return 1;
    if (!check8("narrow8", i,
                narrow8((uint8_t)x, (uint8_t)y, (uint8_t)z),
                reference_narrow8((uint8_t)x, (uint8_t)y, (uint8_t)z)))
      return 1;
    if (!check16("narrow16", i,
                 narrow16((uint16_t)x, (uint16_t)y, (uint16_t)z),
                 reference_narrow16((uint16_t)x, (uint16_t)y, (uint16_t)z)))
      return 1;
  }

  static const uint64_t wide_vectors[][4] = {
      {0, 0, 0, 0},
      {1, 2, 3, 4},
      {UINT64_MAX, 1, 0, 2},
      {0, 1, 1, 1},
      {UINT64_MAX, UINT64_C(0x8000000000000001), 0, 0},
      {0, UINT64_C(0x8000000000000001), UINT64_C(0x8000000000000001), 1},
      {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX},
      {UINT64_C(0x7fffffffffffffff), 1,
       UINT64_C(0x8000000000000000), 0},
      {UINT64_C(0x7ffffffffffffffe), 2, UINT64_MAX, 3},
      {UINT64_C(0xfffffffffffffff0), UINT64_C(0x20),
       UINT64_C(0x10), UINT64_C(0x8000000000000000)},
  };
  for (unsigned i = 0; i < sizeof(wide_vectors) / sizeof(wide_vectors[0]);
       ++i) {
    uint64_t x = wide_vectors[i][0];
    uint64_t y = wide_vectors[i][1];
    uint64_t z = wide_vectors[i][2];
    uint64_t w = wide_vectors[i][3];
    if (!check64("i64_chain", i, i64_chain(x, y, z, w),
                 reference_i64_chain(x, y, z, w)))
      return 1;
  }
#if FUSION_TIMING
  timing("order-typical", order, 10, 3, 20);
  timing("order-borrow32", order, 0, 1, 0);
  timing("order-lhs-typical", order_lhs, 10, 3, 20);
  timing("order-lhs-borrow32", order_lhs, 0, 0, 1);
  timing("multi-typical", multi_cap, 10, 3, 20);
  timing64("i64-typical", 1, 2, 3, 4);
  timing64("i64-carry64", UINT64_MAX, 1, 0, 0);
  timing64("i64-borrow64", 0, 1, 1, 1);
#endif
  puts("VMP fusion OK");
  return 0;
}
''')
    linker = base / "bin" / ("ld.lld.exe" if os.name == "nt" else "ld.lld")
    command(
        clang, "--target=aarch64-linux-android26",
        "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource),
        "--driver-mode=g++", "--ld-path=" + str(linker),
        "-static-libstdc++", "-DFUSION_TIMING=" + str(int(timings)),
        "-Wl,-rpath,$ORIGIN", "-x", "c", str(driver), "-x", "none", str(obj),
        "-o", output,
    )


def run_variant_coverage(args, out, base, resource):
    linker = base / "bin" / ("ld.lld.exe" if os.name == "nt" else "ld.lld")
    expected = {(name, index): ({(0, 0), (0, 1), (1, 0), (1, 1)}
                               if first in ("add", "sub") or second in ("add", "sub")
                               else {(0, 0), (0, 1)})
                for name, specs in FUSIONS.items()
                for index, (first, second, width) in enumerate(specs)}
    seen = {key: set() for key in expected}
    rounds = []
    source = out / "fusion.ll"
    source.write_text(IR)
    for iteration in range(-int(bool(args.baseline_clang)), 32):
        clang = (args.baseline_clang if iteration < 0 else args.clang).resolve()
        common = [clang, "--target=aarch64-linux-android26",
                  "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource)]
        folder = out / ("baseline" if iteration < 0 else "build-" + str(iteration))
        folder.mkdir()
        raw, final, assembly, obj, library = (folder / name for name in
                                             ("raw.ll", "post.ll", "post.s", "post.o", "libfusion.so"))
        compiled = protected(clang, base, resource, source, raw, FUNCTIONS, False)
        (folder / "raw.stderr").write_text(compiled.stderr)
        raw_text = raw.read_text()
        structures = inspect_fusion_structure(raw_text)
        require_names = {re.fullmatch(r"vm_interpreter_(\w+)_k[0-9a-f]{16}", clone)[1]
                         for clone in structures}
        assert require_names == set(FUSIONS), require_names
        post = command(*common, "-Oz", "-fno-discard-value-names", "-fPIC", "-mllvm",
                       "-irobf-vmp-post", "-S", "-emit-llvm", raw, "-o", final)
        (folder / "post.stderr").write_text(post.stderr)
        final_text = final.read_text()
        assert "!ndkp.vmp.post" in final_text
        assert inspect_fusion_structure(final_text) == structures, "post changed fusion structure"
        assert re.findall(r'^@gv_code_seg_\w+ = .*? c"([^"\n]+)"', raw_text, re.M) == re.findall(
            r'^@gv_code_seg_\w+ = .*? c"([^"\n]+)"', final_text, re.M), "post changed bytecode"
        # Assemble this exact backend output once; both the final SO and device
        # program use this object, so assembly comments can locate actual code.
        command(*common, "-Oz", "-fPIC", "-Xclang", "-disable-llvm-passes", "-S", final, "-o", assembly)
        command(*common, "-c", "-Wa,-L", assembly, "-o", obj)
        command(*common, "--driver-mode=g++", "--ld-path=" + str(linker),
                "-static-libstdc++", "-shared", "-Wl,-soname,libfusion.so", obj, "-o", library)
        assert library.read_bytes().startswith(b"\x7fELF")
        record = {"build": iteration, "structures": structures, "deviceExecuted": False}
        if args.serial:
            binary = folder / "fusion-test"
            build_device_binary(clang, base, resource, library, binary, timings=True)
            remote = "/data/local/tmp/ndkp-vmp-fusion-" + uuid.uuid4().hex
            adb = ["adb", "-s", args.serial]
            command(*adb, "shell", "mkdir", remote)
            try:
                command(*adb, "push", library, remote + "/libfusion.so")
                command(*adb, "push", binary, remote + "/fusion-test")
                command(*adb, "shell", "chmod", "700", remote + "/fusion-test")
                device = command(*adb, "shell", "timeout", "90", remote + "/fusion-test")
                (folder / "device.log").write_text(device.stdout + device.stderr)
                assert "VMP fusion OK" in device.stdout, device.stdout
                record["deviceExecuted"] = True
                record["timings"] = re.findall(
                    r"VMP fusion timing name=(\S+) calls=(\d+) ns=(\d+) checksum=(\d+)", device.stdout)
                assert len(record["timings"]) == 8, record["timings"]
            finally:
                command(*adb, "shell", "rm", "-f", remote + "/fusion-test", remote + "/libfusion.so")
                command(*adb, "shell", "rmdir", remote)
        for clone, groups in structures.items():
            name = re.fullmatch(r"vm_interpreter_(\w+)_k[0-9a-f]{16}", clone)[1]
            assert len(groups) == len(FUSIONS[name]), (name, len(groups))
            for index, group in enumerate(groups):
                first, second, width = FUSIONS[name][index]
                assert group.get("width", width) == width, (name, index)
                if iteration >= 0:
                    seen[name, index].add((group["handler"], group["layout"]))
                else:
                    assert group["handler"] == group["layout"] == 0, "baseline is not the p24 native/layout0 chain"
        rounds.append(record)
        (folder / "structure.json").write_text(json.dumps(record, indent=2) + "\n")
        complete = all(seen[key] >= values for key, values in expected.items())
        print("[variants] build={} observed={} complete={} device={}".format(
            iteration, sum(map(len, seen.values())), complete, bool(args.serial)), flush=True)
        if complete:
            break
    assert complete, "fusion variant/layout coverage incomplete after 32 builds"
    result = {"passed": True, "buildCount": iteration + 1, "deviceExecuted": bool(args.serial),
              "coverage": {name + ":" + str(index): sorted(values) for (name, index), values in seen.items()},
              "rounds": rounds}
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--baseline-clang", type=Path)
    parser.add_argument("--output", type=Path, help="new evidence directory; preserve previous runs")
    parser.add_argument("--variant-coverage", action="store_true",
                        help="release builds until each fusion pair covers both handlers/layouts (at most 32)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    (root / "work").mkdir(exist_ok=True)
    base, resource = resource_dir(args.ndk)
    if args.output:
        if args.output.exists():
            raise ValueError("--output must be new; preserve previous evidence")
        args.output.mkdir(parents=True)
    context = nullcontext(args.output) if args.output else tempfile.TemporaryDirectory(prefix="vmp-fusion-", dir=root / "work")
    with context as folder:
        out = Path(folder)
        if args.variant_coverage:
            run_variant_coverage(args, out, base, resource)
            return
        source = out / "fusion.ll"
        protected_ir = out / "protected.ll"
        final_ir = out / "final.ll"
        final_obj = out / "final.o"
        source.write_text(IR)
        protected_result = protected(args.clang.resolve(), base, resource, source,
                                     protected_ir, FUNCTIONS, True)
        (out / "protected.stderr").write_text(protected_result.stderr)
        counts, lengths = check_fusions(protected_result.stderr, protected_ir.read_text())
        assert "!ndkp.vmp.protected" in protected_ir.read_text()

        post = command(
            args.clang.resolve(), "--target=aarch64-linux-android26",
            "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource),
            "-Oz", "-mllvm", "-irobf-vmp-post", "-S", "-emit-llvm",
            protected_ir, "-o", final_ir,
        )
        (out / "post.stderr").write_text(post.stderr)
        final_text = final_ir.read_text()
        assert "!ndkp.vmp.protected" in final_text
        assert "!ndkp.vmp.post" in final_text
        command(
            args.clang.resolve(), "--target=aarch64-linux-android26",
            "--sysroot=" + str(base / "sysroot"), "-resource-dir=" + str(resource),
            "-Oz", "-Xclang", "-disable-llvm-passes", "-c", final_ir,
            "-o", final_obj,
        )
        assert final_obj.read_bytes().startswith(b"\x7fELF")

        if args.baseline_clang:
            baseline_ir = out / "baseline.ll"
            baseline_result = protected(
                args.baseline_clang.resolve(), base, resource, source, baseline_ir,
                ["multi_cap"], True, strict=False,
            )
            baseline_lines = fusion_lines(baseline_result.stderr)
            baseline_counts = sum(line["function"] == "multi_cap"
                                  for line in baseline_lines)
            baseline_lengths = byte_lengths(baseline_ir.read_text())
            assert baseline_counts == 1, baseline_lines
            assert counts["multi_cap"] == 4
            print("[baseline] multi_cap count={} bytes={} -> count={} bytes={}"
                  .format(baseline_counts, baseline_lengths["multi_cap"],
                          counts["multi_cap"], lengths["multi_cap"]), flush=True)
            assert lengths["multi_cap"] < baseline_lengths["multi_cap"], (
                lengths, baseline_lengths,
            )

        if args.serial:
            binary = out / "fusion-test"
            build_device_binary(args.clang.resolve(), base, resource, final_obj, binary)
            remote = "/data/local/tmp/ndkp-vmp-fusion-" + uuid.uuid4().hex
            adb = ["adb", "-s", args.serial]
            try:
                command(*adb, "push", binary, remote)
                command(*adb, "shell", "chmod", "700", remote)
                result = command(*adb, "shell", "timeout", "90", remote)
                assert "VMP fusion OK" in result.stdout, result.stdout
            finally:
                command(*adb, "shell", "rm", "-f", remote)

        print("[ok] VMP fusion counts={}, byte_lengths={}, post IR, object path{}".format(
            counts, lengths, ", device semantics" if args.serial else "",
        ), flush=True)


if __name__ == "__main__":
    main()
