"""Check three-build per-method opcode diversity and failure of key-only decoding."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


METHODS = {"first", "second"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def legacy_decode_map(key):
    mask = (1 << 64) - 1
    state = key ^ 0x6d2b79f5aa17c3e9 or 0x9e3779b97f4a7c15
    result = list(range(29))
    for i in range(28, 1, -1):
        state = (state + 0x9e3779b97f4a7c15) & mask
        value = state
        value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & mask
        value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & mask
        value ^= value >> 31
        j = value % i + 1
        result[i], result[j] = result[j], result[i]
    return result


def parse_mapping(text):
    pairs = [tuple(map(int, pair.split(":"))) for pair in text.split(",")]
    require(len(pairs) == 28 and all(len(pair) == 2 for pair in pairs), "expected 28 mapping pairs")
    semantics, ordinals = zip(*pairs)
    require(len(set(semantics)) == len(set(ordinals)) == 28,
            "duplicate semantic or ordinal before mapping conversion")
    require(set(semantics) == set(ordinals) == set(range(1, 29)), "mapping must be a 1..28 bijection")
    encode = dict(pairs)
    return tuple(encode[semantic] for semantic in range(1, 29))


def inspect_variant(stderr, ir):
    rows = re.findall(r"\[VMP_VARIANT\] function=(\S+) key=0x([0-9a-fA-F]+) "
                      r"semantic_to_ordinal=([0-9:,]+)", stderr)
    require(len(rows) == stderr.count("[VMP_VARIANT]") == len(METHODS), "expected one variant row per method")
    variants = {}
    for name, key_text, text in rows:
        require(name in METHODS and name not in variants, "duplicate/unexpected variant method: " + name)
        key = int(key_text, 16)
        require(key < 1 << 64, "function key exceeds 64 bits")
        mapping = parse_mapping(text)
        legacy = legacy_decode_map(key)
        require(all(legacy[ordinal] != semantic for semantic, ordinal in enumerate(mapping, 1)),
                "legacy key-only decoder still recovers a semantic: " + name)
        variants[name] = (key, mapping)
    handlers = re.findall(r"\[VMP_DISPATCH_RANDOMIZE\] clone=(\S+) cases=(\d+)", stderr)
    require(len(handlers) == stderr.count("[VMP_DISPATCH_RANDOMIZE]") == len(METHODS),
            "expected one dispatch row per method")
    clones = set()
    for clone, cases in handlers:
        require(clone not in clones and 0 < int(cases) < 28, "duplicate/invalid dispatch clone: " + clone)
        clones.add(clone)
    require(clones == {f"vm_interpreter_{name}_k{key:016x}" for name, (key, _) in variants.items()},
            "dispatch clones differ from variant methods/keys")
    require(ir.count("!ndkp.vmp.protected") == 2 and "opcode_dispatch_map" not in ir,
            "protected IR markers/dispatch map differ")
    return variants


def compare_variants(builds):
    require(len(builds) == 3, "requires exactly three builds")
    for build in builds:
        require(set(build) == METHODS, "variant method coverage differs")
    for method in sorted(METHODS):
        require(len({build[method][1] for build in builds}) == 3,
                "opcode mapping not distinct across three builds: " + method)
    require(len({value[1] for build in builds for value in build.values()}) == 6,
            "opcode mappings repeated across methods/builds")


def check_plain(ir):
    require("ndkp.vmp.protected" not in ir and "vm_interpreter_" not in ir,
            "no-flag compilation unexpectedly transformed IR")


def inspect_fusion_structure(ir):
    """Read actual decoder CFG and carry dataflow, without debug diagnostics."""
    result = {}
    for name, body in re.findall(r"^define [^\n]*@(vm_interpreter_\w+)\([^\n]*\n(.*?)^}", ir, re.M | re.S):
        blocks = dict(re.findall(r"^([\w.$-]+):[^\n]*\n(.*?)(?=^[\w.$-]+:|\Z)", body, re.M | re.S))
        entries = [label for label in blocks if re.fullmatch(r"vmp\.fusion\.[0-9a-f]+", label)]
        groups = []
        for entry in entries:
            current = entry
            readers = []
            for _ in range(4):
                pending = re.findall(r"label %([\w.$-]+)", blocks[current])
                seen = {current}
                exits = set()
                while pending:
                    label = pending.pop()
                    if label in seen:
                        continue
                    seen.add(label)
                    match = re.fullmatch(r"vmp_fusion_read_(target|value)\.exit\d*", label)
                    if match:
                        exits.add(label)
                        continue
                    require(label in blocks, "missing decoder CFG block: " + label)
                    pending.extend(re.findall(r"label %([\w.$-]+)", blocks[label]))
                require(len(exits) == 1, "decoder does not have a unique next reader: " + current)
                current = exits.pop()
                readers.append("target" if "_target." in current else "value")
            require(readers in (["target", "value", "value", "value"],
                                ["value", "value", "value", "target"]),
                    "unexpected fusion field consumption: " + str(readers))
            carry = [label for label in re.findall(r"label %([\w.$-]+)", blocks[current])
                     if re.fullmatch(r"vmp\.fusion\.carry\d*", label)]
            record = {"entry": entry, "layout": int(readers[0] != "target"),
                      "readers": readers, "handler": int(bool(carry))}
            if carry:
                require(len(carry) == 1, "multiple carry headers")
                header = blocks[carry[0]]
                phis = re.findall(r"(%[\w.$-]+) = phi i(8|16|32|64) ", header)
                require(len(phis) == 2 and phis[0][1] == phis[1][1], "carry PHI widths differ")
                width = phis[0][1]
                steps = [label for label in re.findall(r"label %([\w.$-]+)", header)
                         if label.startswith("vmp.fusion.carry.step")]
                require(len(steps) == 1, "missing carry step")
                step = blocks[steps[0]]
                require(re.search(r"icmp eq i" + width + r" " + re.escape(phis[1][0]) + r", 0", header),
                        "carry does not terminate on zero pending bits")
                for opcode in ("and", "xor", "shl"):
                    require(re.search(r" = " + opcode + " i" + width + " ", step),
                            "carry operation/width missing: " + opcode)
                require("label %" + carry[0] in step and not re.search(r"\b(nsw|nuw|exact)\b", step),
                        "carry lost its backedge or acquired wrap flags")
                record.update(width=int(width), carryHeader=carry[0], carryStep=steps[0],
                              carryDataflow=re.sub(r"%[\w.$-]+", "%v", "\n".join(
                                  line.strip() for line in step.splitlines()
                                  if re.search(r" = (and|xor|shl) ", line))))
            groups.append(record)
        if groups:
            result[name] = groups
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='new evidence directory; otherwise use temporary files')
    args = parser.parse_args()
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    base = args.ndk / 'toolchains/llvm/prebuilt' / host
    if args.output is not None:
        require(not args.output.exists(), '--output must be new; preserve previous evidence')
        args.output.mkdir(parents=True)
    context = nullcontext(args.output) if args.output is not None else tempfile.TemporaryDirectory(prefix='vmp-opcodes-')
    with context as directory:
        out = Path(directory)
        source = out / 'input.c'
        source.write_text('''
__attribute__((annotate("vmp"), noinline)) int first(int x) {
  return x < 0 ? -x + 7 : x * 3 + 11;
}
__attribute__((annotate("vmp"), noinline)) int second(int x) {
  return x < 0 ? -x + 7 : x * 3 + 11;
}
''', encoding='utf-8')
        common = [str(args.clang), '--target=aarch64-linux-android26',
                  '--sysroot=' + str(base / 'sysroot'),
                  '-resource-dir=' + str(base / 'lib/clang/21'), '-O1',
                  '-S', '-emit-llvm', str(source)]
        builds = []
        for iteration in range(3):
            ir = out / f'protected-{iteration}.ll'
            process = subprocess.run(common + ['-o', str(ir), '-mllvm', '-irobf-vmp',
                '-mllvm', '-irobf-vmp-strict', '-mllvm', '-irobf-debug'],
                capture_output=True, text=True, timeout=180)
            (out / f'protected-{iteration}.stdout.txt').write_text(process.stdout, encoding='utf-8')
            (out / f'protected-{iteration}.stderr.txt').write_text(process.stderr, encoding='utf-8')
            require(process.returncode == 0, process.stderr)
            builds.append(inspect_variant(process.stderr, ir.read_text(encoding='utf-8')))
        compare_variants(builds)
        plain = out / 'plain.ll'
        process = subprocess.run(common + ['-o', str(plain)], capture_output=True, text=True, timeout=180)
        (out / 'plain.stdout.txt').write_text(process.stdout, encoding='utf-8')
        (out / 'plain.stderr.txt').write_text(process.stderr, encoding='utf-8')
        require(process.returncode == 0, process.stderr)
        check_plain(plain.read_text(encoding='utf-8'))
        (out / 'results.json').write_text(json.dumps({'passed': True, 'buildCount': 3,
            'methods': sorted(METHODS), 'opcodesPerMethod': 28, 'variants': builds}, indent=2) + '\n', encoding='utf-8')
    print('[ok] all 28 semantics fail key-only decoding per method; two methods, three builds; opt-in preserved')


if __name__ == '__main__':
    main()
