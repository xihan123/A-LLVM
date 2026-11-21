"""Exercise real LLVM 21 inline-aggregate allocations and observe bytes at free."""
import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import uuid

from memory_ops import function, run


CASES = (("inline_store", 3, 17, 7), ("inline_insert", 12, 24, 17),
         ("inline_extract", 13, 31, 17))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def chacha_block(key, nonce, counter):
    # Standard ChaCha20 block, with the actual compiler's logged material.
    initial = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, *key, counter, *nonce]
    words = initial[:]

    def quarter(a, b, c, d):
        for x, y, z, shift in ((a, b, d, 16), (c, d, b, 12),
                               (a, b, d, 8), (c, d, b, 7)):
            words[x] = (words[x] + words[y]) & 0xffffffff
            value = words[z] ^ words[x]
            words[z] = ((value << shift) | (value >> (32 - shift))) & 0xffffffff

    for _ in range(10):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            quarter(*indices)
    return struct.pack("<16I", *((a + b) & 0xffffffff for a, b in zip(initial, words)))


def code_constant(ir, name):
    token = r'\\(?:[0-9A-Fa-f]{2}|\\)|[^"\\]'
    match = re.search(r'^@gv_code_seg_' + re.escape(name) + r' = [^\n]*\[(\d+) x i8\] c"('
                      + r'(?:' + token + r')*)"', ir, re.M)
    assert match, name
    data = bytes(92 if part == "\\\\" else int(part[1:], 16) if part.startswith("\\") else ord(part)
                 for part in re.findall(token, match[2]))
    assert len(data) == int(match[1]), name
    return match, data


def rotl64(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & 0xffffffffffffffff


def mix64(value):
    value &= 0xffffffffffffffff
    value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & 0xffffffffffffffff
    value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & 0xffffffffffffffff
    return value ^ (value >> 31)


def compiler_material(log, name):
    section = log.split("[Translator] Starting for function: " + name + "\n", 1)[1]
    section = section.split("[Translator] Starting for function:", 1)[0]
    opcode = re.search(r"\[pack_op\] op=(\d+) ordinal=\d+ res=(\d+)", section)
    words = re.search(r"\[VM_BB0_MATERIAL\] key=([0-9a-f ]+) nonce=([0-9a-f ]+) block=([0-9a-f ]+)", section)
    seeds = re.search(r"\[VM_BB0_ENCRYPT\] function_key=(0x[0-9a-f]+) vm_seed=(0x[0-9a-f]+) "
                      r"chain_seed=(0x[0-9a-f]+) first_plain=(0x[0-9a-f]+) "
                      r"first_key=(0x[0-9a-f]+) first_cipher=(0x[0-9a-f]+)", section)
    prefix = re.search(r"\[VM_BB0_PLAINTEXT\] begin=(\d+) end=(\d+) bytes=([0-9a-f ]+)", section)
    assert opcode and words and seeds and prefix, name
    key, nonce = ([int(word, 16) for word in words[group].split()] for group in (1, 2))
    assert len(key) == 8 and len(nonce) == 3
    assert chacha_block(key, nonce, 0)[:4] == bytes.fromhex(words[3]), name
    function_key, payload_seed, chain_seed, first_plain, first_key, first_cipher = (
        int(value, 16) for value in seeds.groups())
    begin, end = int(prefix[1]), int(prefix[2])
    assert begin == 4 and end > begin, name
    material = {"functionKey": function_key, "payloadSeed": payload_seed, "chainSeed": chain_seed,
                "bbOffset": begin - 4, "keyWords": key, "nonceWords": nonce,
                "firstPlain": first_plain, "firstKey": first_key, "firstCipher": first_cipher,
                "codeEnd": end, "plaintextPrefix": prefix[3].strip()}
    state = (function_key ^ rotl64(payload_seed, 17) ^ rotl64(chain_seed, 29)
             ^ (material["bbOffset"] * 0x9e3779b97f4a7c15) ^ 0x6a09e667f3bcc909)
    derived_key, derived_nonce = [], []
    for index in range(7):
        state = (state + 0x9e3779b97f4a7c15) & 0xffffffffffffffff
        word = mix64(state)
        if index < 4:
            derived_key.extend((word & 0xffffffff, word >> 32))
        else:
            derived_nonce.append(word & 0xffffffff)
    assert key == derived_key and nonce == derived_nonce, name
    return tuple(map(int, opcode.groups())), material


def decrypt(code, material):
    # BB0's tag is clear; the scheduled keystream depends on position and logged seeds.
    function_key, payload_seed, chain_seed, bb_offset = (
        material[key] for key in ("functionKey", "payloadSeed", "chainSeed", "bbOffset"))
    assert len(code) == material["codeEnd"]
    result = bytearray(code[:4])
    for offset in range(4, len(code), 64):
        block_index = (offset - 4) // 64
        block = chacha_block(material["keyWords"], material["nonceWords"], block_index)
        seed = mix64(function_key ^ rotl64(payload_seed, 9) ^ rotl64(chain_seed, 23)
                     ^ (bb_offset * 0xd6e8feb86659fd93) ^ (block_index * 0xa0761d6478bd642f)
                     ^ 0xe7037ed1a0b428db)
        add_a, add_b = seed & 63, (seed >> 8) & 63
        multiplier, rotation, mode = (((seed >> 16) & 31) << 1) | 1, ((seed >> 24) % 6) + 1, (seed >> 57) & 7

        def bitrev6(value):
            return int(f"{value & 63:06b}"[::-1], 2)

        def rotl6(value):
            value &= 63
            shift = rotation % 6
            return ((value << shift) | (value >> (6 - shift))) & 63 if shift else value

        for lane, byte in enumerate(code[offset:offset + 64]):
            scheduled = (lane ^ add_a, (lane + add_a) & 63, (lane * multiplier + add_b) & 63,
                         bitrev6(lane) ^ add_a, bitrev6(lane + add_a), (rotl6(lane) + add_b) & 63,
                         rotl6(lane * multiplier + add_a), (bitrev6(lane ^ add_b) * multiplier + add_a) & 63)[mode]
            payload_index = offset - 4 + lane
            mask = mix64(seed ^ (payload_index * 0x9e3779b97f4a7c15)
                         ^ rotl64(seed ^ function_key, (lane & 31) + 1)
                         ^ ((lane + 1) * 0x94d049bb133111eb))
            mask = (mask ^ (mask >> 8) ^ (mask >> 16) ^ (mask >> 24)
                    ^ (mask >> 32) ^ (mask >> 40) ^ (mask >> 48) ^ (mask >> 56)) & 255
            result.append(byte ^ block[scheduled] ^ mask)
    return bytes(result)


def mutate_operands(ir, raw, log):
    records = []
    for tag, (name, semantic, size, start) in enumerate(CASES, 1):
        _, original = code_constant(raw, name)
        match, candidate = code_constant(ir, name)
        assert original == candidate, "post changed the fixture bytecode: " + name
        opcode, material = compiler_material(log, name)
        plain = decrypt(candidate, material)
        prefix = bytes.fromhex(material["plaintextPrefix"])
        assert plain[4:4 + len(prefix)] == prefix, name
        assert (plain[4], candidate[4], plain[4] ^ candidate[4]) == (
            material["firstPlain"], material["firstCipher"], material["firstKey"]), name
        assert opcode[0] == semantic and plain[4] == opcode[1], name
        assert plain[start - 2:start] == bytes((size, 1)), name
        assert plain[start:start + size] == bytes(size), name
        pattern = bytes(0x31 + tag * 11 + index * 5 for index in range(size))
        changed = bytearray(candidate)
        for index, byte in enumerate(pattern, start):
            changed[index] ^= byte
        changed = bytes(changed)
        offsets = [index for index, (a, b) in enumerate(zip(candidate, changed)) if a != b]
        assert offsets == list(range(start, start + size)), name
        decoded = decrypt(changed, material)
        assert decoded[:start] == plain[:start] and decoded[start + size:] == plain[start + size:]
        assert decoded[start:start + size] == pattern
        records.append({"function": name, "semanticOpcode": semantic, "allocationSize": size,
                        "codeBytes": len(candidate), "payloadStart": start, "payloadEnd": start + size,
                        "changedOffsets": offsets, "originalCiphertext": candidate[start:start + size].hex(),
                        "mutatedCiphertext": changed[start:start + size].hex(),
                        "originalPlaintext": plain[start:start + size].hex(), "mutatedPlaintext": pattern.hex(),
                        "decodedPrefix": plain[:start].hex(), "encodedOpcode": opcode[1],
                        "compilerMaterial": material,
                        "originalCodeSha256": hashlib.sha256(candidate).hexdigest(),
                        "mutatedCodeSha256": hashlib.sha256(changed).hexdigest()})
        encoded = "".join(f"\\{byte:02X}" for byte in changed)
        ir = ir[:match.start(2)] + encoded + ir[match.end(2):]
    return ir, records


def observer_allocator_attributes(ir):
    # Wrappers record observations in driver globals. Preserve production IR;
    # relax allocator contracts only in this observed, non-LTO backend input.
    next_group = max(map(int, re.findall(r"^attributes #(\d+) =", ir, re.M))) + 1
    groups, additions = {}, []

    def replace(match):
        nonlocal next_group
        group = match[2]
        if group not in groups:
            attributes = re.search(r"^attributes #" + group + r" = \{ (.*) \}", ir, re.M)[1]
            cleaned = re.sub(r'memory\([^)]*\)|allockind\("[^"]*"\)|allocsize\([^)]*\)|'
                             r'\b(?:nofree|nosync|norecurse|nounwind|willreturn|mustprogress)\b', "", attributes)
            groups[group] = next_group if cleaned.strip() else None
            if groups[group] is not None:
                additions.append(f"attributes #{next_group} = {{ {cleaned} }}")
                next_group += 1
        return match[1] + (" #" + str(groups[group]) if groups[group] is not None else "") + match[3]

    ir = re.sub(r"^([^\n]*(?:declare|call)[^\n]*@(?:malloc|free)\([^\n]*?) #(\d+)([^\n]*)$",
                replace, ir, flags=re.M)
    assert groups, "allocator declarations missing"
    return ir + "\n" + "\n".join(additions) + "\n"


def compile_ir(clang, common, flags, source, output):
    result = subprocess.run([str(arg) for arg in (clang, *common, *flags, "-S", "-emit-llvm", source,
                                                 "-o", output)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
    log = result.stdout + result.stderr
    output.with_suffix(".compile.log").write_text(log, encoding="utf-8")
    assert result.returncode == 0 and "Skipping VMP protection" not in log, log
    return output.read_text(encoding="utf-8"), log


def check_inline_constants(clang, common, out, serial=None):
    if int(run(clang, "-dumpversion").split(".", 1)[0]) != 21:
        print("[skip] inline-constant heap observations require the LLVM 21 interpreter", flush=True)
        return
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).parent
    fixture = source / "inline_constants.ll"
    reference_ir = out / "reference.ll"
    reference_ir.write_text(fixture.read_text(encoding="utf-8").replace("@inline_", "@reference_inline_"), encoding="utf-8")
    vmp = ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vm_functions=" + ";".join(case[0] for case in CASES)]
    backend = ["-Oz", "-Xclang", "-disable-llvm-passes"]
    adb = ["adb", "-s", serial] if serial else []
    remote = "/data/local/tmp/ndkp-inline-" + uuid.uuid4().hex
    manifest = {"compiler": str(clang), "compilerSha256": sha256(clang),
                "fixtureSha256": sha256(fixture), "driverSha256": sha256(source / "inline_constants_driver.c"),
                "scope": "test-only VM bytecode inputs; production emitter nonzero-aggregate support is unchanged",
                "cases": []}

    def execute(binary):
        if not serial:
            return
        run(*adb, "push", binary, remote)
        run(*adb, "shell", "chmod", "700", remote)
        result = subprocess.run([*adb, "shell", "timeout", "90", remote], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120)
        log = out / (binary.name + ".device.log")
        log.write_text(f"exit_code={result.returncode}\n{result.stdout}{result.stderr}", encoding="utf-8")
        assert result.returncode == 0 and "VMP inline constants OK" in result.stdout, log.read_text(encoding="utf-8")

    try:
        for opt in ("-O0", "-O2"):
            suffix = opt[1:]
            reference = out / f"reference-{suffix}.o"
            run(clang, *common, opt, "-c", reference_ir, "-o", reference)
            for observed in (False, True):
                driver = out / f"driver-{suffix}{'-observed' if observed else ''}.o"
                run(clang, *common, opt, *(["-DNDKP_OBSERVE_INLINE"] if observed else []), "-c",
                    source / "inline_constants_driver.c", "-o", driver)
            for protected in (False, True):
                mode = "protected" if protected else "vmp"
                raw_path = out / f"{mode}-{suffix}.raw.ll"
                flags = [opt, *vmp]
                if protected:
                    flags += ["-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry"]
                else:
                    flags += ["-mllvm", "-irobf-debug"]
                raw, log = compile_ir(clang, common, flags, fixture, raw_path)
                for name, *_ in CASES:
                    assert "@gv_code_seg_" + name in raw
                    if protected:
                        assert "@ndkp_selfcheck_one" in function(raw, name), name
                pristine_path = raw_path
                ir = raw
                if opt == "-O2":
                    pristine_path = out / f"{mode}-{suffix}.post.ll"
                    ir, _ = compile_ir(clang, common, ["-Oz", "-mllvm", "-irobf-vmp-post"], raw_path, pristine_path)
                    assert "!ndkp.vmp.post" in ir
                chain = suffix + ("-post" if opt == "-O2" else "")
                case = out / f"pristine-{mode}-{chain}.o"
                run(clang, *common, *backend, "-c", pristine_path, "-o", case)
                binary = case.with_suffix("")
                run(clang, *common, "--driver-mode=g++", "-static-libstdc++", case, reference,
                    out / f"driver-{suffix}.o", "-o", binary)
                execute(binary)
                if not protected:
                    assert "@ndkp_selfcheck_one" not in ir
                    mutated, records = mutate_operands(ir, raw, log)
                    observed_path = out / f"observed-{chain}.ll"
                    observed_path.write_text(observer_allocator_attributes(mutated), encoding="utf-8")
                    case = observed_path.with_suffix(".o")
                    run(clang, *common, *backend, "-c", observed_path, "-o", case)
                    binary = case.with_suffix("")
                    run(clang, *common, "--driver-mode=g++", "-static-libstdc++", "-Wl,--wrap=malloc",
                        "-Wl,--wrap=free", case, reference, out / f"driver-{suffix}-observed.o", "-o", binary)
                    manifest["cases"].append({"mode": chain, "rawSha256": sha256(raw_path),
                                              "pristineSha256": sha256(pristine_path),
                                              "observedSha256": sha256(observed_path),
                                              "compilerLogSha256": sha256(raw_path.with_suffix(".compile.log")),
                                              "operands": records})
                    (out / "mutation-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
                    execute(binary)
                checks = "device semantics" if protected else "device semantics and full-allocation free observations"
                print(f"[ok] inline constants/{mode}/{chain}: {checks if serial else 'compile only'}", flush=True)
    finally:
        if serial:
            run(*adb, "shell", "rm", "-f", remote)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    base = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host
    clang = args.clang.resolve() if args.clang else base / ("bin/clang.exe" if os.name == "nt" else "bin/clang")
    resource = max((base / "lib/clang").iterdir(), key=lambda path: int(path.name))
    common = ["--target=aarch64-linux-android26", f"--sysroot={base / 'sysroot'}", "-resource-dir", resource,
              f"-B{base / 'bin'}", "-fno-vectorize", "-fno-slp-vectorize"]
    with (nullcontext(args.work_dir) if args.work_dir else tempfile.TemporaryDirectory()) as folder:
        check_inline_constants(clang, common, Path(folder), args.serial)


if __name__ == "__main__":
    main()
