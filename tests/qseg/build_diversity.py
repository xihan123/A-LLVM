"""Check every expected VM target across three independent, identical-input builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


MAINS = {"sample.Run", "kfixture.FixtureKt"}
FIELDS = ("resourceIds", "resourceContentSha256", "functionKeySha256",
          "dispatchCompareConstantSequenceSha256")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def exact_targets(actual, expected, label):
    require(set(actual) == set(expected),
            f"{label}: missing={sorted(set(expected) - set(actual))}, "
            f"unexpected={sorted(set(actual) - set(expected))}")


def method_targets(rows):
    require(isinstance(rows, list) and rows, "expected nonempty method list")
    targets, symbols = {}, set()
    for row in rows:
        method, symbol = row["method"], row["symbol"]
        require(isinstance(method, str) and re.fullmatch(r"[^.\s]+\.[^(\s]+\([^)]*\).+", method),
                "invalid method: " + repr(method))
        require(symbol == "d2c_" + digest(method.encode("utf-8"))[:24],
                "method/symbol mismatch: " + method)
        require(method not in targets and symbol not in symbols, "duplicate method/symbol: " + method)
        targets[method] = symbol
        symbols.add(symbol)
    return targets


def class_manifest(paths):
    """Hash all original class bytes, independent of JAR timestamps and paths."""
    result = {}
    require(bool(paths), "empty class path")
    for path in paths:
        path = Path(path)
        if path.is_dir():
            entries = [(item.relative_to(path).as_posix(), item.read_bytes())
                       for item in sorted(path.rglob("*.class"))]
        else:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                require(len(names) == len(set(names)), "duplicate ZIP entry: " + str(path))
                entries = [(name, archive.read(name)) for name in names if name.endswith(".class")]
        require(bool(entries), "no classes in input: " + str(path))
        for name, raw in entries:
            require(name not in result, "duplicate class: " + name)
            result[name] = digest(raw)
    return dict(sorted(result.items()))


def load_contract(path):
    contract = read_json(path)
    require(contract["schemaVersion"] == 1, "unsupported expected contract schema")
    method_targets(contract["methods"])
    exact_targets(contract["inputClasses"], ("baseline", "common"), "contract class paths")
    for mode, classes in contract["inputClasses"].items():
        require(isinstance(classes, dict) and classes, "empty contract classes: " + mode)
        require(all(isinstance(name, str) and name.endswith(".class") and
                    isinstance(value, str) and SHA256.fullmatch(value)
                    for name, value in classes.items()), "invalid contract classes: " + mode)
    return contract


def resource_groups(rows, method_bytes, symbols):
    groups = {}
    for row in rows:
        if row["kind"] == 1:
            groups.setdefault(row["name"], []).append(row)
    exact_targets(groups, symbols, "kind1 resources")
    exact_targets(method_bytes, symbols, "method bytecode sizes")
    resources, identities = {}, set()
    for name, chunks in groups.items():
        first = chunks[0]
        identity, content_hash = first["id"], first["resourceSha256"]
        require(isinstance(identity, str) and re.fullmatch(r"[0-9a-f]{32}", identity),
                "invalid resource ID: " + name)
        require(identity not in identities, "duplicate resource ID: " + name)
        identities.add(identity)
        require(isinstance(content_hash, str) and SHA256.fullmatch(content_hash),
                "invalid resource digest: " + name)
        require(all(type(row["chunk"]) is int for row in chunks), "invalid chunk index: " + name)
        chunks = sorted(chunks, key=lambda row: row["chunk"])
        require([row["chunk"] for row in chunks] == list(range(len(chunks))),
                "duplicate or noncontiguous chunks: " + name)
        for index, row in enumerate(chunks):
            require((row["id"], row["resourceSha256"], row["lifetime"]) ==
                    (identity, content_hash, "lease-v1"), "conflicting chunks: " + name)
            require(type(row["bytes"]) is int and 0 < row["bytes"] <= 65536 and
                    (index == len(chunks) - 1 or row["bytes"] == 65536),
                    "invalid chunk size: " + name)
            require(isinstance(row["sha256"], str) and SHA256.fullmatch(row["sha256"]),
                    "invalid chunk digest: " + name)
        require(type(method_bytes[name]) is int and
                sum(row["bytes"] for row in chunks) == method_bytes[name],
                "bytecode size differs: " + name)
        require(len(chunks) != 1 or chunks[0]["sha256"] == content_hash,
                "single chunk/content digest differs: " + name)
        resources[name] = (identity, content_hash)
    return resources


def dispatch_constants(body, symbol, key):
    """Follow only the raw LLVM 21 clone's salt-masked compare/false-edge chain."""
    salt = "vmp_interpreter_clone_salt_" + symbol + "_k" + key
    pieces = re.split(r"^([-a-zA-Z$._0-9]+):[^\n]*\n", body, flags=re.M)
    blocks = {"<entry>": pieces[0]}
    for index in range(1, len(pieces), 2):
        require(pieces[index] not in blocks, "duplicate IR block: " + symbol)
        blocks[pieces[index]] = pieces[index + 1]
    require(blocks["<entry>"].count("@vmp_interpreter_clone_salt_") == 1 and
            ("@" + salt + ",") in blocks["<entry>"], "invalid entry salt: " + symbol)
    value = r"%[-a-zA-Z$._0-9]+"
    label = r"[-a-zA-Z$._0-9]+"
    load = r" = load volatile i64, ptr @" + re.escape(salt) + r", align 8"
    pattern = re.compile(
        r"(?P<a>" + value + r")" + load + r"\n"
        r"(?P<b>" + value + r")" + load + r"\n"
        r"(?P<c>" + value + r") = trunc i64 (?P=a) to i8\n"
        r"(?P<d>" + value + r") = trunc i64 (?P=b) to i8\n"
        r"(?P<e>" + value + r") = xor i8 (?P<opcode>" + value + r"), (?P=c)\n"
        r"(?P<f>" + value + r") = xor i8 (?P<constant>\d+), (?P=d)\n"
        r"(?P<g>" + value + r") = icmp eq i8 (?P=e), (?P=f)\n"
        r"br i1 (?P=g), label %(?P<handler>" + label + r"), label %(?P<next>" + label + r")")
    normalized = {name: "\n".join(line.split(";", 1)[0].strip() for line in text.splitlines()
                                 if line.split(";", 1)[0].strip()) for name, text in blocks.items()}
    default = re.compile(r"call void @_Z21vm_dump_fault_contextPKcmm\([^\n]*\)\nunreachable")
    chain = {}
    for name, text in blocks.items():
        if "@vmp_interpreter_clone_salt_" not in text:
            continue
        if name == "<entry>":
            continue
        match = pattern.fullmatch(normalized[name])
        require(match is not None, "malformed dispatch block: " + symbol + ":" + name)
        chain[name] = match.groupdict()
    require(0 < len(chain) < 28, "missing/invalid dispatch chain: " + symbol)
    heads = set(chain) - {row["next"] for row in chain.values()}
    require(len(heads) == 1, "disconnected/cyclic dispatch chain: " + symbol)
    head = next(iter(heads))
    current, visited, constants, opcodes = head, set(), [], set()
    while True:
        require(current in blocks, "missing dispatch block: " + symbol)
        if default.fullmatch(normalized[current]):
            break
        require(current not in visited, "cyclic dispatch chain: " + symbol)
        match = pattern.fullmatch(normalized[current])
        require(match is not None, "malformed dispatch path/default: " + symbol + ":" + current)
        visited.add(current)
        row = match.groupdict()
        require(row["handler"] in blocks and row["handler"] not in chain,
                "invalid dispatch handler: " + symbol)
        constants.append(int(row["constant"]))
        opcodes.add(row["opcode"])
        current = row["next"]
    require(visited == set(chain) and len(opcodes) == 1 and
            len(constants) == len(set(constants)) and all(0 < number <= 28 for number in constants),
            "incomplete/inconsistent dispatch chain: " + symbol)
    incoming = []
    for name, text in blocks.items():
        for destination in re.findall(r"label %(" + label + r")", text):
            if destination in chain and name not in chain:
                incoming.append(destination)
                require(re.search(r"(?:^|\n)br label %" + re.escape(head) + r"\Z", normalized[name]),
                        "dispatch head must follow an unconditional entry edge: " + symbol)
    require(bool(incoming) and set(incoming) == {head}, "invalid dispatch entry edges: " + symbol)
    return constants


def clone_material(ir, symbols):
    clones = re.findall(r"^define [^\n]*@vm_interpreter_(d2c_[0-9a-f]+)_k([0-9a-f]+)"
                        r"\([^\n]*\{\n(.*?)^}", ir, re.M | re.S)
    require(len(clones) == len(re.findall(r"^define [^\n]*@vm_interpreter_d2c_", ir, re.M)),
            "unrecognized VM clone definition")
    keys, dispatch = {}, {}
    for name, key, body in clones:
        require(name not in keys, "duplicate VM clone: " + name)
        require(len(key) <= 16, "invalid function key: " + name)
        keys[name] = digest(int(key, 16).to_bytes(8, "big"))
        sequence = dispatch_constants(body, name, key)
        dispatch[name] = digest(",".join(map(str, sequence)).encode("ascii"))
    exact_targets(keys, symbols, "VM clones")
    return keys, dispatch


def device_semantics(result):
    rows = {}
    for row in result["results"]:
        if row["mode"] in ("baseline", "protected"):
            key = (row["mode"], row["main"])
            require(key not in rows, "duplicate device result: " + repr(key))
            require(isinstance(row["output"], str) and bool(row["output"]),
                    "empty device result: " + repr(key))
            rows[key] = row["output"]
    exact_targets(rows, {(mode, main) for mode in ("baseline", "protected") for main in MAINS},
                  "Java/Kotlin device results")
    for main in MAINS:
        require(rows["baseline", main] == rows["protected", main], "device semantic mismatch: " + main)
    return {main: rows["protected", main] for main in sorted(MAINS)}


def inspect(directory, contract):
    native = directory / "native"
    receipt = read_json(native / "protection.json")
    expected = method_targets(contract["methods"])
    symbols = set(expected.values())
    actual = method_targets([row for row in read_json(directory / "generated/selection.json")["methods"]
                             if row["protection"] == "vmp"])
    require(actual == expected, "selection differs from expected methods")
    require(isinstance(receipt["symbols"], list) and len(receipt["symbols"]) == len(set(receipt["symbols"])),
            "duplicate receipt symbols")
    exact_targets(receipt["symbols"], symbols, "receipt symbols")
    resources = resource_groups(read_json(native / "segments.json")["segments"],
                                receipt["methodBytecodeBytes"], symbols)
    keys, dispatch = clone_material((native / "protected.raw.ll").read_text(encoding="utf-8"), symbols)
    inputs = read_json(directory / "inputs.json")
    require(isinstance(inputs["mains"], list) and len(inputs["mains"]) == len(MAINS) and
            set(inputs["mains"]) == MAINS, "fixture must declare Java and Kotlin mains exactly once")
    classes = {}
    for mode in ("baseline", "protected", "common"):
        paths = [Path(path) if Path(path).is_absolute() else directory / path for path in inputs[mode]]
        classes[mode] = class_manifest(paths)
        if mode != "protected":
            require(classes[mode] == contract["inputClasses"][mode], "input class bytes differ: " + mode)
    generated = directory / "generated/classes.jar"
    require(digest(generated.read_bytes()) == receipt["classesSha256"] and
            classes["protected"] == class_manifest([generated]),
            "protected class bytes differ from this build's receipt/generated JAR")
    return {"path": str(directory.resolve()), "inputClasses": classes,
            "certificateSha256": receipt["certificateSha256"],
            "containerSha256": receipt["containerSha256"], "librarySha256": receipt["librarySha256"],
            "semantics": device_semantics(read_json(directory / "device-results.json")),
            "resourceIds": {name: value[0] for name, value in resources.items()},
            "resourceContentSha256": {name: value[1] for name, value in resources.items()},
            "functionKeySha256": keys, "dispatchCompareConstantSequenceSha256": dispatch}


def compare(builds, contract):
    require(len(builds) == 3, "requires exactly three independent builds")
    require(len({row["path"] for row in builds}) == 3, "fixture directories must be independent")
    targets = method_targets(contract["methods"])
    for key in ("certificateSha256", "semantics"):
        require(all(row[key] == builds[0][key] for row in builds), "input/semantics differ: " + key)
    for row in builds:
        for mode in ("baseline", "common"):
            require(row["inputClasses"][mode] == contract["inputClasses"][mode],
                    "input class bytes differ: " + mode)
    counts = {}
    for field in FIELDS:
        for row in builds:
            exact_targets(row[field], targets.values(), field)
        for method, symbol in targets.items():
            require(len({row[field][symbol] for row in builds}) == 3,
                    f"not three distinct values: {method} ({symbol}) {field}")
        counts[field] = len(targets)
    for key in ("containerSha256", "librarySha256"):
        require(len({row[key] for row in builds}) == 3, "no three-way diversity: " + key)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-contract', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), '--output must be new; preserve previous evidence')
    require(len(args.fixtures) == 3, 'requires exactly three independent builds')
    contract = load_contract(args.expected_contract)
    builds = [inspect(path, contract) for path in args.fixtures]
    counts = compare(builds, contract)
    report = {'expectedContractSha256': digest(args.expected_contract.read_bytes()),
              'expectedMethods': contract['methods'], 'builds': builds,
              'threeWayChangedMethods': counts, 'vmMethods': len(contract['methods']), 'passed': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(counts))


if __name__ == '__main__':
    main()
