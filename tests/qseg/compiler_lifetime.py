"""Verify LLVM 21 QSEG wrapper contracts; this is static, not device/EH reclamation evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


IDENT = r"[-a-zA-Z$._0-9]+"
VALUE = "%" + IDENT
POLICIES = {"safe": "lease-v1", "nested": "lease-v1", "recursive": "lease-v1",
            "risky": "pinned-unproven-unwind"}
EDGES = (("nested", "safe"), ("recursive", "recursive"))
SOURCE = r'''extern "C" int externalCall(int);
extern "C" __attribute__((noinline)) int safe(int x) noexcept { return x * 7 + 9; }
extern "C" __attribute__((noinline)) int nested(int x) noexcept { return safe(x) + 3; }
extern "C" __attribute__((noinline)) int recursive(int depth, int *parent) noexcept {
  int value = depth + 10;
  if (parent) *parent += 3;
  int child = depth ? recursive(depth - 1, &value) : 0;
  return value + child;
}
extern "C" int risky(int x) { return externalCall(x); }
'''
EH_SOURCE = r'''extern "C" int externalCall(int);
extern "C" __attribute__((noinline)) int rejected_eh(int x) {
  try { return externalCall(x); } catch (int value) { return value + 1; }
}
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text("utf-8"), object_pairs_hook=unique_object)


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def identity(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest}


def function(ir, name):
    matches = list(re.finditer(r"^define [^\n]*@" + re.escape(name) +
                              r"\([^\n]*\{\n(.*?)^}", ir, re.M | re.S))
    require(len(matches) == 1, "missing/duplicate function: " + name)
    return matches[0][0].split("\n", 1)[0], matches[0][1]


def metadata(ir, line, key):
    ids = re.findall(r"!" + re.escape(key) + r" !(\d+)(?!\d)", line)
    require(len(ids) == 1, "missing/duplicate metadata: " + key)
    nodes = re.findall(r"^!" + ids[0] + r" = !\{(.*)}$", ir, re.M)
    require(len(nodes) == 1, "missing/invalid metadata node: " + key)
    return nodes[0]


def global_line(ir, name):
    matches = re.findall(r"^@" + re.escape(name) + r" = [^\n]+", ir, re.M)
    require(len(matches) == 1, "missing/duplicate global: " + name)
    return matches[0]


def blocks(body, limit=64):
    pieces = re.split(r"^(" + IDENT + r"):[^\n]*\n", body, flags=re.M)
    result = {}
    for name, text in [("<entry>", pieces[0]), *zip(pieces[1::2], pieces[2::2])]:
        lines = [line.split(";", 1)[0].strip() for line in text.splitlines()]
        lines = [line for line in lines if line]
        if name == "<entry>" and not lines:
            continue
        require(name not in result and lines, "duplicate/empty IR block: " + name)
        result[name] = lines
    require(0 < len(result) <= limit, "unsupported IR block count")
    return result


def call(line):
    match = re.fullmatch(r"(?:(" + VALUE + r") = )?(?:tail |notail )?call [^@\n]+@(" +
                         IDENT + r")\((.*)\)(?: #[0-9]+)?", line)
    require(match is not None, "unsupported direct call: " + line)
    return match.groups()


def wrapper_paths(body, ref, interpreter, mode):
    """Only the raw LLVM 21 wrapper's direct calls and acyclic br/ret shape are accepted."""
    cfg = blocks(body)
    lines = [line for group in cfg.values() for line in group]
    calls = {line: call(line) for line in lines if re.search(r"\bcall\b", line)}
    allowed_calls = {"ndkp_qseg_acquire_v1", "ndkp_qseg_get", "ndkp_qseg_release_v1",
                     "ndkp_selfcheck_one", "llvm.memset.p0.i64", interpreter, "vmp_resume_unwind_shared"}
    require(all(callee in allowed_calls for _, callee, _ in calls.values()), "unexpected wrapper call")
    borrowed = {}
    for line, (value, callee, args) in calls.items():
        if callee == "llvm.memset.p0.i64":
            initializer = re.fullmatch(r"ptr align 16 (" + VALUE + r"), i8 0, i64 (\d+), i1 false", args)
            require(value is None and initializer is not None and lines.index(line) > 0 and
                    lines[lines.index(line) - 1] == initializer[1] + " = alloca [" + initializer[2] +
                    " x i8], align 16" and lines.count(line) == 1, "unsupported frame memset")
        if callee not in ("ndkp_qseg_acquire_v1", "ndkp_qseg_get", "ndkp_qseg_release_v1"):
            continue
        argument = re.fullmatch(r"ptr @(" + IDENT + r")", args)
        require(argument is not None and argument[1] == ref, "QSEG call not bound to target descriptor")
        require((value is None) == (callee == "ndkp_qseg_release_v1"), "invalid QSEG result")
        if callee != "ndkp_qseg_release_v1":
            require(value is not None and value not in borrowed, "invalid QSEG result")
            borrowed[value] = callee
    stores = [line for line in lines if "@vmp_shared_code_seg_addr" in line]
    require(len(stores) == 1, "missing/duplicate bytecode slot use")
    stored = re.fullmatch(r"store i64 (" + VALUE + r"), ptr @vmp_shared_code_seg_addr, align 8", stores[0])
    require(stored is not None, "unsupported bytecode pointer store")
    casts = [re.fullmatch(re.escape(stored[1]) + r" = ptrtoint ptr (" + VALUE + r") to i64", line)
             for line in lines]
    origins = [match[1] for match in casts if match]
    require(len(origins) == 1 and origins[0] in borrowed, "bytecode pointer not bound to target descriptor")
    main = origins[0]
    require(borrowed[main] == ("ndkp_qseg_acquire_v1" if mode == "lease-v1" else "ndkp_qseg_get"),
            "main pointer does not match lifetime policy")
    temporary = set(borrowed) - {main}
    require(len(temporary) == 1 and all(borrowed[p] == "ndkp_qseg_acquire_v1" for p in temporary),
            "expected one distinct SelfCheck temporary borrow")
    for pointer in borrowed:
        require(sum(bool(re.search(re.escape(pointer) + r"(?![-a-zA-Z$._0-9])", line)) for line in lines) == 2,
                "unexpected borrowed pointer use or escape")
    require(sum(callee == interpreter for _, callee, _ in calls.values()) == 1,
            "missing/duplicate bound interpreter call")
    visited, paths = set(), []

    def walk(block, loans=(), prepared=False, ran=False, got=False, checked=frozenset(), trail=()):
        require(block in cfg and block not in trail, "missing/cyclic wrapper successor")
        require(len(paths) < 128, "unsupported wrapper path count")
        visited.add(block)
        group = cfg[block]
        for line in group[:-1]:
            opcode = re.sub(r"^" + VALUE + r" = ", "", line).split(" ", 1)[0]
            require(opcode in {"alloca", "load", "store", "getelementptr", "ptrtoint", "xor", "icmp", "call"},
                    "unsupported wrapper instruction: " + line)
            if line in calls:
                value, callee, args = calls[line]
                if callee in ("ndkp_qseg_acquire_v1", "ndkp_qseg_get", "ndkp_qseg_release_v1") and args == "ptr @" + ref:
                    if callee == "ndkp_qseg_acquire_v1":
                        require(not ran and value not in loans, "late/duplicate borrow")
                        loans += (value,)
                    elif callee == "ndkp_qseg_get":
                        require(value == main and not got and not ran, "unexpected pinned get")
                        got = True
                    else:
                        require(loans, "target lease underflow")
                        top = loans[-1]
                        require((top == main and ran) or (top in temporary and top in checked),
                                "main lease released before interpreter or unchecked temporary")
                        loans = loans[:-1]
                elif callee == "ndkp_selfcheck_one":
                    argument = re.fullmatch(r"ptr (" + VALUE + r"), i64 \d+, i64 -?\d+", args)
                    require(argument is not None and argument[1] in temporary and
                            loans and loans[-1] == argument[1] and argument[1] not in checked,
                            "SelfCheck pointer not covered by its temporary borrow")
                    checked = checked | {argument[1]}
                elif callee == interpreter:
                    require(prepared and not ran and checked == temporary and
                            loans == ((main,) if mode == "lease-v1" else ()),
                            "interpreter bypasses prepared main lease or temporary closure")
                    require(args == "", "unsupported interpreter arguments")
                    ran = True
                elif callee == "vmp_resume_unwind_shared":
                    require(prepared and ran and not loans and line == group[-2] and group[-1] == "unreachable",
                            "resume bypasses release/interpreter")
            if line == stores[0]:
                require(not prepared and not ran and (main in loans if mode == "lease-v1" else got),
                        "main pointer prepared without a live target lease")
                prepared = True
            require(not (prepared and not ran and mode == "lease-v1") or main in loans,
                    "main mapping lost before interpreter returned")
        terminal = group[-1]
        branch = re.fullmatch(r"br (?:label %(" + IDENT + r")|i1 " + VALUE +
                              r", label %(" + IDENT + r"), label %(" + IDENT + r"))", terminal)
        if branch:
            for successor in (part for part in branch.groups() if part):
                walk(successor, loans, prepared, ran, got, checked, (*trail, block))
            return
        require(terminal.startswith("ret ") or terminal == "unreachable", "unsupported wrapper terminator")
        require(prepared and ran and not loans and checked == temporary, "exit leaks/bypasses target lease")
        if terminal == "unreachable":
            require(len(group) > 1 and group[-2] in calls and
                    calls[group[-2]][1] == "vmp_resume_unwind_shared", "unknown unreachable exit")
        paths.append({"blocks": [*trail, block], "exit": "resume" if terminal == "unreachable" else "return",
                      "interpreterLeaseDepth": int(mode == "lease-v1"), "exitLeaseDepth": 0})

    walk(next(iter(cfg)))
    require(visited == set(cfg) and {row["exit"] for row in paths} == {"return", "resume"},
            "unreachable block or missing return/resume path")
    return {"mainPointer": main, "selfCheckPointers": sorted(temporary), "paths": paths}


def i64_parameter(header, name):
    match = re.search(r"@" + re.escape(name) + r"\(i64(?: noundef)? (" + VALUE + r")\)", header)
    require(match is not None, "unsupported funcid parameter: " + name)
    return match[1]


def interpreter_bridge_block(body):
    """Check CFG connectivity, not whether the VM's dynamic opcode reaches this edge."""
    cfg = blocks(body, limit=8192)
    pending, reached, sites = [next(iter(cfg))], set(), []
    while pending:
        label = pending.pop()
        require(label in cfg, "missing interpreter successor")
        if label in reached:
            continue
        reached.add(label)
        group = cfg[label]
        for line in group:
            if "@call_handler_with_exception_handling(" in line:
                _, callee, args = call(line)
                require(callee == "call_handler_with_exception_handling" and re.fullmatch(
                    r"i64(?: noundef)? (?:" + VALUE + r"|-?\d+)", args), "unsupported interpreter bridge call")
                sites.append(label)
        terminal = re.sub(r", !llvm\.loop !\d+$", "", group[-1])
        branch = re.fullmatch(r"br (?:label %(" + IDENT + r")|i1 " + VALUE +
                              r", label %(" + IDENT + r"), label %(" + IDENT + r"))", terminal)
        if branch:
            pending.extend(part for part in branch.groups() if part)
        elif terminal == "]":
            switches = [index for index, line in enumerate(group) if line.startswith("switch ")]
            require(len(switches) == 1, "unsupported interpreter switch")
            switch = re.fullmatch(r"switch i(8|32|64) " + VALUE + r", label %(" + IDENT +
                                  r") \[ (.*) ]", " ".join(group[switches[0]:]))
            require(switch is not None and re.fullmatch(
                r"(?:i" + switch[1] + r" -?\d+, label %" + IDENT + r" ?)+", switch[3]),
                "unsupported interpreter switch cases")
            pending.extend([switch[2], *re.findall(r"label %(" + IDENT + r")", switch[3])])
        else:
            require(terminal in ("ret void", "unreachable"), "unsupported interpreter terminator")
    require(len(sites) == 1, "bound interpreter does not reach a unique handler bridge from entry")
    return sites[0]


def shared_dispatch_blocks(ir, wrappers):
    """Accept only the current connected Code compare/false-edge chain and direct handlers."""
    name = "vmp_shared_call_dispatch"
    header, body = function(ir, name)
    parameter, cfg = i64_parameter(header, name), blocks(body)
    current = next(iter(cfg))
    load = re.fullmatch(r"(" + VALUE + r") = load i64, ptr @vmp_shared_dispatch_code_seg_addr, align 8",
                        cfg[current][0])
    require(load is not None, "wrong shared dispatch selector")
    codes = {row["code"]: name for name, row in wrappers.items()}
    seen, selected, exit_block = set(), {}, None
    for index in range(len(codes)):
        require(current in cfg and current not in seen, "missing/cyclic shared dispatch chain")
        seen.add(current)
        group = cfg[current][1:] if index == 0 else cfg[current]
        require(len(group) == 2, "unsupported shared dispatch comparison block")
        compare = re.fullmatch(r"(" + VALUE + r") = icmp eq i64 " + re.escape(load[1]) +
                               r", ptrtoint \(ptr @(" + IDENT + r") to i64\)", group[0])
        require(compare is not None and compare[2] in codes, "wrong shared dispatch comparison")
        target = codes[compare[2]]
        require(target not in selected, "duplicate shared dispatch Code")
        branch = re.fullmatch(r"br i1 " + re.escape(compare[1]) + r", label %(" + IDENT +
                              r"), label %(" + IDENT + r")", group[1])
        require(branch is not None and branch[1] in cfg and branch[1] not in seen, "wrong selected handler")
        handler = "vm_interpreter_callinst_dispatch_" + target
        selected_group = cfg[branch[1]]
        require(len(selected_group) == 2 and selected_group[0] ==
                "call void @" + handler + "(i64 " + parameter + ")", "wrong selected handler")
        exit_branch = re.fullmatch(r"br label %(" + IDENT + r")", selected_group[1])
        require(exit_branch is not None and (exit_block is None or exit_block == exit_branch[1]),
                "unsupported shared dispatch exit")
        exit_block = exit_branch[1]
        seen.add(branch[1])
        selected[target] = branch[1]
        current = branch[2]
    require(current in cfg and current not in seen and cfg[current] == ["br label %" + exit_block] and
            exit_block in cfg and cfg[exit_block] == ["ret void"], "unsupported shared dispatch default/exit")
    require(seen | {current, exit_block} == set(cfg) and set(selected) == set(wrappers),
            "unreachable/skipped shared dispatch block")
    bridge_name = "call_handler_with_exception_handling"
    header, body = function(ir, bridge_name)
    parameter, bridge = i64_parameter(header, bridge_name), blocks(body)
    entry = next(iter(bridge.values()))
    first_invoke = next((index for index, line in enumerate(entry) if line.startswith("invoke ")), len(entry))
    require(all(re.fullmatch(VALUE + r" = alloca .+", line) for line in entry[:first_invoke]),
            "unsupported shared dispatch bridge entry")
    invoke = re.fullmatch(r"invoke void @vmp_shared_call_dispatch\(i64(?: noundef)? " + re.escape(parameter) +
                          r"\) to label %(" + IDENT + r") unwind label %(" + IDENT + r")",
                          " ".join(entry[first_invoke:]))
    require(invoke is not None and all(label in bridge for label in invoke.groups()),
            "shared dispatch bridge not invoked from entry")
    return selected


def handler_case(ir, name, callee):
    header, body = function(ir, name)
    parameter, cfg = i64_parameter(header, name), blocks(body)
    entry = next(iter(cfg.values()))
    slot = re.fullmatch(r"(" + VALUE + r") = alloca i64, align 8", entry[0])
    require(len(entry) >= 6 and slot is not None and entry[1] ==
            "store i64 " + parameter + ", ptr " + slot[1] + ", align 8", "handler funcid store not bound to parameter")
    selector = re.fullmatch(r"(" + VALUE + r") = load i64, ptr " + re.escape(slot[1]) + r", align 8", entry[2])
    switch = re.fullmatch(r"switch i64 (" + VALUE + r"), label %(" + IDENT + r") \[", entry[3])
    require(selector is not None and switch is not None and switch[1] == selector[1] and entry[-1] == "]",
            "handler switch selector not bound to funcid")
    cases = [re.fullmatch(r"i64 (\d+), label %(" + IDENT + r")", line) for line in entry[4:-1]]
    require(cases and all(cases), "unsupported handler switch cases")
    labels = [case[2] for case in cases]
    require(len(set(labels)) == len(labels) and len({case[1] for case in cases}) == len(cases) and
            switch[2] in cfg and cfg[switch[2]] == ["ret void"] and
            {next(iter(cfg)), switch[2], *labels} == set(cfg), "unsupported handler switch CFG")
    sites = []
    for label in labels:
        require(label in cfg and cfg[label][-1] == "ret void", "unsupported handler case exit")
        for line in cfg[label][:-1]:
            opcode = re.sub(r"^" + VALUE + r" = ", "", line).removeprefix("tail ").removeprefix("notail ").split(" ", 1)[0]
            require(opcode in {"load", "getelementptr", "store", "call"}, "unsupported handler case instruction")
            if opcode == "call" and call(line)[1] == callee:
                sites.append(label)
    require(len(sites) == 1, "missing/duplicate nested or recursive handler edge: " + name)
    return sites[0]


def decode_descriptor(line):
    match = re.search(r'constant \[24 x i8] c"((?:[^"\\]|\\[0-9A-Fa-f]{2}|\\\\)*)"', line)
    require(match is not None and 'section ".text.ndkp.qseg.refs"' in line, "invalid RX descriptor")
    raw, index = bytearray(), 0
    while index < len(match[1]):
        text = match[1]
        if text[index] == "\\":
            if text[index:index + 2] == "\\\\":
                raw.append(92); index += 2
            else:
                raw.append(int(text[index + 1:index + 3], 16)); index += 3
        else:
            raw.append(ord(text[index])); index += 1
    require(len(raw) == 24, "invalid descriptor length")
    return bytes(raw)


def verify_contract(ir, rows):
    require(isinstance(rows, list), "manifest must be an array")
    resources = {}
    for row in rows:
        require(isinstance(row, dict) and row.get("kind") in (1, 2), "invalid manifest row")
        if row["kind"] == 1:
            name = row.get("name")
            require(name in POLICIES and name not in resources, "unexpected/duplicate VM manifest row")
            require(row.get("lifetime") == POLICIES[name] and type(row.get("bytes")) is int and
                    0 < row["bytes"] <= 1 << 24 and isinstance(row.get("id"), str) and
                    re.fullmatch("[0-9a-f]{32}", row["id"]), "invalid VM manifest policy/identity")
            resources[name] = row
    require(set(resources) == set(POLICIES), "VM manifest target coverage differs")
    require(len({row["id"] for row in resources.values()}) == len(POLICIES), "duplicate VM resource ID")
    wrappers = {}
    for name, mode in POLICIES.items():
        header, body = function(ir, name)
        receipt = re.fullmatch(r"ptr @(" + IDENT + r"), ptr @(" + IDENT + r")",
                               metadata(ir, header, "ndkp.vmp.protected"))
        require(receipt is not None and receipt[1] == "gv_code_seg_" + name and
                re.fullmatch("vm_interpreter_" + name + "_k[0-9a-f]{16}", receipt[2]), "wrong VM receipt binding")
        code, interpreter = receipt.groups()
        function(ir, interpreter)
        target = re.fullmatch(r"ptr @(" + IDENT + r")", metadata(ir, global_line(ir, code), "ndkp.qseg"))
        require(target is not None, "invalid descriptor metadata")
        ref = target[1]
        descriptor_line = global_line(ir, ref)
        descriptor = decode_descriptor(descriptor_line)
        row = resources[name]
        require(descriptor[:16].hex() == row["id"] and int.from_bytes(descriptor[16:20], "little") == row["bytes"] and
                int.from_bytes(descriptor[20:], "little") == 1, "descriptor/manifest binding differs")
        for line in (header, descriptor_line):
            require(metadata(ir, line, "ndkp.qseg.lifetime") == '!"' + mode + '"', "lifetime metadata differs")
        dispatch_uses = [line.split(";", 1)[0].strip() for line in body.splitlines()
                         if "@vmp_shared_dispatch_code_seg_addr" in line.split(";", 1)[0]]
        require(dispatch_uses == ["store i64 ptrtoint (ptr @" + code +
                                 " to i64), ptr @vmp_shared_dispatch_code_seg_addr, align 8"],
                "wrapper dispatch-code binding or slot use differs")
        wrappers[name] = {"mode": mode, "descriptor": ref, "resourceId": row["id"], "bytes": row["bytes"],
                          "code": code, "interpreter": interpreter, **wrapper_paths(body, ref, interpreter, mode)}
    edges = []
    dispatcher = shared_dispatch_blocks(ir, wrappers)
    for caller, callee in EDGES:
        handler = "vm_interpreter_callinst_dispatch_" + caller
        site = handler_case(ir, handler, callee)
        bridge = interpreter_bridge_block(function(ir, wrappers[caller]["interpreter"])[1])
        edges.append({"caller": caller, "callee": callee, "handler": handler, "caseBlock": site,
                      "dispatcherBlock": dispatcher[caller], "interpreterBridgeBlock": bridge})
    return {"wrappers": wrappers, "handlerEdges": edges}


def verify_plain(ir, eh=False):
    require(not any(token in ir for token in ("ndkp.qseg", "ndkp.vmp.protected", "ndkp_qseg_", "@gv_code_seg_")),
            "no-flag control contains protection")
    if eh:
        header, body = function(ir, "rejected_eh")
        require(" personality ptr @" in header and re.search(r"\binvoke\b", body) and
                "landingpad " in body, "ineffective EH fixture: missing personality/invoke/landingpad")
        return {"function": "rejected_eh", "personality": True, "invoke": True, "landingpad": True}
    for name, mode in POLICIES.items():
        header, _ = function(ir, name)
        groups = re.findall(r" #(\d+)", header)
        require(len(groups) == 1, "unknown plain attribute shape")
        attrs = re.findall(r"^attributes #" + groups[0] + r" = \{(.*)}$", ir, re.M)
        require(len(attrs) == 1 and bool(re.search(r"\bnounwind\b", attrs[0])) == (mode == "lease-v1"),
                "plain nounwind contract differs: " + name)
    for caller, callee in EDGES:
        require(re.search(r"\bcall [^@\n]+@" + callee + r"\(", function(ir, caller)[1]), "plain call edge missing")
    return {"unprotected": True, "nounwind": {name: mode == "lease-v1" for name, mode in POLICIES.items()}}


def verify_eh_rejection(result):
    text = result["stdout"] + result["stderr"]
    require(result["exit"] != 0 and re.search(
        r"Function 'rejected_eh' (?:has a personality function \(exception handling\)|uses exception handling \([^)]+\))", text) and
        "VMP strict: rejected_eh: translation rejected; see preceding diagnostic" in text,
        "strict compilation did not explicitly reject rejected_eh for EH")
    return {"function": "rejected_eh", "exit": result["exit"], "reason": "personality/EH translation rejected"}


def run_command(output, label, command):
    record = {"command": list(map(str, command)), "cwd": str(Path.cwd()), "exit": None}
    try:
        result = subprocess.run(record["command"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        record.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        def text(value):
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
        record.update(error=type(error).__name__, stdout=text(getattr(error, "stdout", "")),
                      stderr=text(getattr(error, "stderr", "")), message=str(error))
    (output / (label + ".stdout.txt")).write_text(record.pop("stdout"), encoding="utf-8")
    (output / (label + ".stderr.txt")).write_text(record.pop("stderr"), encoding="utf-8")
    write_json(output / (label + ".json"), record)
    require("error" not in record, "compiler command failed to run: " + label)
    return {**record, "stdout": (output / (label + ".stdout.txt")).read_text("utf-8"),
            "stderr": (output / (label + ".stderr.txt")).read_text("utf-8")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cert-file", type=Path, required=True)
    args = parser.parse_args()
    output, clang, certificate = args.output.resolve(), args.clang.resolve(), args.cert_file.resolve()
    require(clang.is_file() and certificate.is_file(), "compiler/certificate must be existing files")
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())), "output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    try:
        root = Path(__file__).resolve().parents[2]
        paths = [Path(__file__).resolve(), Path(__file__).with_name("test_compiler_lifetime.py").resolve(),
                 Path(__file__).with_name("README.md").resolve()]
        paths += [root / "obfuscation/llvm-21/Transforms/Obfuscation" / name for name in
                  ("aVMP/aVMP.cpp", "aVMP/aVMPDispatcher.cpp", "SegmentedData.cpp", "SelfCheck.cpp")]
        fixed = {str(path): identity(path) for path in [clang, certificate, *paths]}
        (output / "input.cpp").write_text(SOURCE, encoding="utf-8")
        (output / "eh.cpp").write_text(EH_SOURCE, encoding="utf-8")
        fixed.update({str(output / name): identity(output / name) for name in ("input.cpp", "eh.cpp")})
        version = run_command(output, "00-version", [clang, "--version"])
        require(version["exit"] == 0 and re.search(r"clang version 21\.", version["stdout"] + version["stderr"]),
                "LLVM 21 compiler required")
        common = [clang, "--target=aarch64-linux-android26", "-std=c++17", "-O1", "-fno-vectorize",
                  "-fno-slp-vectorize", "-fno-optimize-sibling-calls", "-S", "-emit-llvm"]
        def flags(targets, stage):
            return ["-mllvm", "-irobf-vmp", "-mllvm", "-irobf-vmp-strict", "-mllvm", "-irobf-vm_functions=" + targets,
                    "-mllvm", "-irobf-selfcheck", "-mllvm", "-irobf-selfcheck-entry", "-mllvm", "-irobf-cse",
                    "-mllvm", "-irobf-cse-hardened", "-mllvm", "-irobf-cert-bind", "-mllvm", "-irobf-cert-file=" + str(certificate),
                    "-mllvm", "-irobf-segmented-data", "-mllvm", "-irobf-segmented-output=" + str(output / stage)]
        for label, source, target, extra in (
                ("01-plain", "input.cpp", "plain.ll", []),
                ("02-protected", "input.cpp", "output.ll", flags(";".join(POLICIES), "staging")),
                ("03-eh-plain", "eh.cpp", "eh-plain.ll", [])):
            result = run_command(output, label, [*common, output / source, "-o", output / target, *extra])
            require(result["exit"] == 0, "compiler command failed: " + label)
        plain = verify_plain((output / "plain.ll").read_text("utf-8"))
        eh_plain = verify_plain((output / "eh-plain.ll").read_text("utf-8"), eh=True)
        verified = {str(output / name): identity(output / name)
                    for name in ("plain.ll", "eh-plain.ll", "output.ll", "staging/manifest.json")}
        rows = read_json(output / "staging/manifest.json")
        contract = verify_contract((output / "output.ll").read_text("utf-8"), rows)
        for row in rows:
            if row["kind"] == 1:
                staged = (output / "staging" / (row["id"] + ".bin")).read_bytes()
                require(len(staged) == row["bytes"] and staged == (output / "staging" / (row["name"] + ".bin")).read_bytes(),
                        "staged VM bytes differ")
                contract["wrappers"][row["name"]]["resourceContentSha256"] = hashlib.sha256(staged).hexdigest()
                for name in (row["id"], row["name"]):
                    path = output / "staging" / (name + ".bin")
                    verified[str(path)] = identity(path)
        rejected = run_command(output, "04-eh-strict", [*common, output / "eh.cpp", "-o", output / "eh-output.ll",
                                                      *flags("rejected_eh", "eh-staging")])
        eh = {**eh_plain, **verify_eh_rejection(rejected)}
        require(fixed == {path: identity(Path(path)) for path in fixed}, "compiler/certificate/source changed during run")
        require(verified == {path: identity(Path(path)) for path in verified}, "verified compiler artifacts changed during run")
        report = {"schemaVersion": 1, "checkerRevision": 2, "scope": "LLVM21 static QSEG wrapper contract", "plain": plain,
                  "ehRejection": eh, **contract, "fixedInputs": fixed,
                  "artifacts": {path.relative_to(output).as_posix(): identity(path)
                                for path in sorted(output.rglob("*")) if path.is_file()},
                  "limits": ["No device execution, runtime nested/EH reclamation or OOM evidence.",
                             "Static entry-CFG connectivity does not prove dynamic VM opcode/funcid reachability.",
                             "Unknown native unwind remains pinned-unproven-unwind; real EH targets are rejected.",
                             "Repository source digests do not prove the compiler was built from those sources."]}
        write_json(output / "results.pending.json", report)
        print(json.dumps({"wrappers": list(contract["wrappers"]), "handlerEdges": contract["handlerEdges"], "ehRejected": True}))
        (output / "results.pending.json").replace(output / "results.json")
    except Exception as error:
        write_json(output / "failure.json", {"type": type(error).__name__, "message": str(error)})
        raise


if __name__ == "__main__":
    main()
