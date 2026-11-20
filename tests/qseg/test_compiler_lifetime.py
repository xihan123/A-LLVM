"""Mutations of the deliberately narrow LLVM 21 wrapper contract checker."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import compiler_lifetime as contract


EH_PLAIN = '''define i32 @rejected_eh(i32 %x) personality ptr @__gxx_personality_v0 {
  %r = invoke i32 @externalCall(i32 %x) to label %normal unwind label %catch
normal:
  ret i32 %r
catch:
  %exception = landingpad { ptr, i32 } catch ptr null
  ret i32 9
}
'''
EH_REASON = ("[VMP Warning] Function 'rejected_eh' has a personality function "
             "(exception handling); skipping VMP.\n"
             "LLVM ERROR: VMP strict: rejected_eh: translation rejected; see preceding diagnostic\n")


def fixture():
    text, rows, dispatch = [], [], []
    for index, (name, mode) in enumerate(contract.POLICIES.items()):
        raw = bytes([index + 1]) * 16 + (32 + index).to_bytes(4, "little") + b"\1\0\0\0"
        descriptor = "".join("\\%02X" % byte for byte in raw)
        ref, code, vm = "ref_" + name, "gv_code_seg_" + name, f"vm_interpreter_{name}_k{index:016x}"
        policy = 1 if mode == "lease-v1" else 2
        main_call = "ndkp_qseg_acquire_v1" if policy == 1 else "ndkp_qseg_get"
        release = f"  call void @ndkp_qseg_release_v1(ptr @{ref})\n" if policy == 1 else ""
        text.append(f'''@{code} = internal constant i8 0, !ndkp.qseg !{10 + index}
@{ref} = private constant [24 x i8] c"{descriptor}", section ".text.ndkp.qseg.refs", !ndkp.qseg.lifetime !{policy}
define i32 @{name}(i32 %x) !ndkp.qseg.lifetime !{policy} !ndkp.vmp.protected !{20 + index} {{
  %frame = alloca [24 x i8], align 16
  call void @llvm.memset.p0.i64(ptr align 16 %frame, i8 0, i64 24, i1 false)
  %main = call ptr @{main_call}(ptr @{ref})
  %address = ptrtoint ptr %main to i64
  store i64 %address, ptr @vmp_shared_code_seg_addr, align 8
  store i64 ptrtoint (ptr @{code} to i64), ptr @vmp_shared_dispatch_code_seg_addr, align 8
  %temporary = call ptr @ndkp_qseg_acquire_v1(ptr @{ref})
  %hash = call i64 @ndkp_selfcheck_one(ptr %temporary, i64 32, i64 123)
  call void @ndkp_qseg_release_v1(ptr @{ref})
  call void @{vm}()
{release}  %exception = load i8, ptr @vmp_shared_exception_thrown, align 1
  %thrown = icmp ne i8 %exception, 0
  br i1 %thrown, label %resume, label %normal
normal:
  ret i32 7
resume:
  call void @vmp_resume_unwind_shared(ptr null)
  unreachable
}}
define internal void @{vm}() {{
  call void @call_handler_with_exception_handling(i64 0)
  ret void
}}
!{10 + index} = !{{ptr @{ref}}}
!{20 + index} = !{{ptr @{code}, ptr @{vm}}}
''')
        callee = dict(contract.EDGES).get(name, "externalCall")
        text.append(f'''define internal void @vm_interpreter_callinst_dispatch_{name}(i64 %id) {{
  %slot = alloca i64, align 8
  store i64 %id, ptr %slot, align 8
  %funcid = load i64, ptr %slot, align 8
  switch i64 %funcid, label %default [
    i64 0, label %target
  ]
default:
  ret void
target:
  %result = tail call i32 @{callee}(i32 1)
  ret void
}}
''')
        dispatch.append(f'''  %compare{index} = icmp eq i64 %selected, ptrtoint (ptr @{code} to i64)
  br i1 %compare{index}, label %call{index}, label %next{index}
call{index}:
  call void @vm_interpreter_callinst_dispatch_{name}(i64 %id)
  br label %exit
next{index}:
''')
        rows.append({"name": name, "id": raw[:16].hex(), "bytes": 32 + index, "kind": 1, "lifetime": mode})
    text += ['!1 = !{!"lease-v1"}\n!2 = !{!"pinned-unproven-unwind"}\n',
             'define internal void @vmp_shared_call_dispatch(i64 %id) {\n'
             '  %selected = load i64, ptr @vmp_shared_dispatch_code_seg_addr, align 8\n' +
             "".join(dispatch) + '  br label %exit\nexit:\n  ret void\n}\n',
             'define internal void @call_handler_with_exception_handling(i64 %id) {\n'
             '  invoke void @vmp_shared_call_dispatch(i64 %id) to label %good unwind label %bad\n'
             'good:\n  ret void\nbad:\n  unreachable\n}\n']
    return "".join(text), rows


def plain_fixture():
    text = ""
    for name, mode in contract.POLICIES.items():
        callee = dict(contract.EDGES).get(name)
        body = f"  %result = call i32 @{callee}(i32 1)\n" if callee else ""
        text += f"define i32 @{name}(i32 %x) #{int(mode != 'lease-v1')} {{\n{body}  ret i32 1\n}}\n"
    return text + "attributes #0 = { noinline nounwind }\nattributes #1 = { noinline }\n"


class CompilerLifetimeTest(unittest.TestCase):
    def setUp(self):
        self.ir, self.rows = fixture()

    def rejects(self, ir, reason=None, rows=None):
        with self.assertRaisesRegex(ValueError, reason or ".+"):
            contract.verify_contract(ir, self.rows if rows is None else rows)

    def safe_body_change(self, old, new):
        return self.function_change("safe", old, new)

    def function_change(self, name, old, new):
        header, body = contract.function(self.ir, name)
        self.assertIn(old, body)
        return self.ir.replace(header + "\n" + body, header + "\n" + body.replace(old, new))

    def test_complete_contract_and_same_descriptor_selfcheck(self):
        report = contract.verify_contract(self.ir, self.rows)
        self.assertEqual(set(report["wrappers"]), set(contract.POLICIES))
        self.assertEqual(len(report["handlerEdges"]), 2)
        for name, row in report["wrappers"].items():
            self.assertEqual({path["exit"] for path in row["paths"]}, {"return", "resume"})
            self.assertEqual({path["interpreterLeaseDepth"] for path in row["paths"]}, {int(name != "risky")})

    def test_wrong_descriptor_code_and_interpreter_binding(self):
        for old, new in (("!10 = !{ptr @ref_safe}", "!10 = !{ptr @ref_nested}"),
                         ("!20 = !{ptr @gv_code_seg_safe,", "!20 = !{ptr @gv_code_seg_nested,"),
                         ("!20 = !{ptr @gv_code_seg_safe, ptr @vm_interpreter_safe_k0000000000000000}",
                          "!20 = !{ptr @gv_code_seg_safe, ptr @vm_interpreter_nested_k0000000000000001}")):
            with self.subTest(old=old):
                self.rejects(self.ir.replace(old, new))

    def test_manifest_duplicate_missing_policy_and_identity(self):
        for change in (lambda rows: rows.append(rows[0]), lambda rows: rows.pop(),
                       lambda rows: rows[0].update(bytes=999), lambda rows: rows[0].update(id=rows[1]["id"]),
                       lambda rows: rows[0].update(lifetime="pinned-unproven-unwind")):
            rows = copy.deepcopy(self.rows)
            change(rows)
            self.rejects(self.ir, rows=rows)

    def test_equal_counts_release_before_interpreter(self):
        vm = "  call void @vm_interpreter_safe_k0000000000000000()\n"
        release = "  call void @ndkp_qseg_release_v1(ptr @ref_safe)\n"
        broken = self.safe_body_change(vm + release, release + vm)
        self.assertEqual(broken.count("@ndkp_qseg_acquire_v1("), broken.count("@ndkp_qseg_release_v1("))
        self.rejects(broken, "before interpreter")

    def test_equal_counts_single_exit_leak(self):
        vm = "  call void @vm_interpreter_safe_k0000000000000000()\n"
        release = "  call void @ndkp_qseg_release_v1(ptr @ref_safe)\n"
        broken = self.safe_body_change(vm + release, vm)
        broken = broken.replace("normal:\n  ret i32 7", "normal:\n" + release + "  ret i32 7", 1)
        self.assertEqual(broken.count("@ndkp_qseg_acquire_v1("), broken.count("@ndkp_qseg_release_v1("))
        self.rejects(broken, "resume bypasses|exit leaks")

    def test_underflow_and_interpreter_bypass(self):
        release = "  call void @ndkp_qseg_release_v1(ptr @ref_safe)\n"
        self.rejects(self.safe_body_change("  %exception = load", release + "  %exception = load"), "underflow")
        self.rejects(self.safe_body_change("  call void @vm_interpreter_safe_k0000000000000000()\n",
                                          "  br i1 %condition, label %run, label %normal\nrun:\n"
                                          "  call void @vm_interpreter_safe_k0000000000000000()\n"), "exit leaks")

    def test_temporary_cannot_substitute_for_main_or_escape_checkone(self):
        self.rejects(self.safe_body_change("%main = call ptr @ndkp_qseg_acquire_v1(ptr @ref_safe)",
                                          "%main = call ptr @ndkp_qseg_acquire_v1(ptr @ref_nested)"), "not bound")
        self.rejects(self.safe_body_change("ptrtoint ptr %main", "ptrtoint ptr %temporary"), "borrowed pointer")
        self.rejects(self.safe_body_change("@ndkp_selfcheck_one(", "@ordinary("), "unexpected wrapper call")
        self.rejects(self.safe_body_change("@ndkp_selfcheck_one(ptr %temporary", "@ndkp_selfcheck_one(ptr %main"), "borrowed pointer")

    def test_code_and_dispatch_slots_reject_alias_overwrite_or_escape(self):
        vm = "  call void @vm_interpreter_safe_k0000000000000000()\n"
        for extra in (
                "  %slot_alias = getelementptr i64, ptr @vmp_shared_code_seg_addr, i64 0\n"
                "  store i64 0, ptr %slot_alias, align 8\n",
                "  store i64 0, ptr @vmp_shared_dispatch_code_seg_addr, align 8\n",
                "  call void @llvm.memset.p0.i64(ptr align 8 @vmp_shared_code_seg_addr, i8 0, i64 8, i1 false)\n",
                "  %dispatch_alias = getelementptr i64, ptr @vmp_shared_dispatch_code_seg_addr, i64 0\n"
                "  store i64 0, ptr %dispatch_alias, align 8\n"):
            with self.subTest(extra=extra):
                self.rejects(self.safe_body_change(vm, extra + vm))

    def test_foreign_release_and_unknown_pointer_helpers_fail(self):
        vm = "  call void @vm_interpreter_safe_k0000000000000000()\n"
        self.rejects(self.safe_body_change(vm, "  call void @ndkp_qseg_release_v1(ptr @ref_nested)\n" + vm),
                     "target descriptor")
        escaped = self.safe_body_change(vm, "  call void @review_escape(ptr %main)\n" + vm)
        self.rejects(escaped + "declare void @review_escape(ptr)\n", "unexpected wrapper call")

    def test_memset_only_initializes_its_immediate_stack_frame(self):
        vm = "  call void @vm_interpreter_safe_k0000000000000000()\n"
        redirected = self.safe_body_change("  call void @llvm.memset.p0.i64(ptr align 16 %frame, i8 0, i64 24, i1 false)\n", "")
        redirected = redirected.replace(vm, "  call void @llvm.memset.p0.i64(ptr align 16 %main, i8 0, i64 24, i1 false)\n" + vm, 1)
        self.rejects(redirected, "unsupported frame memset")
        self.rejects(self.safe_body_change("%frame = alloca [24 x i8]", "%frame = alloca [16 x i8]"),
                     "unsupported frame memset")
        escaped = self.safe_body_change(vm, "  store ptr %main, ptr @review_pointer, align 8\n" + vm)
        self.rejects("@review_pointer = global ptr null\n" + escaped, "borrowed pointer")

    def test_unknown_or_cyclic_cfg_and_dead_block_fail(self):
        self.rejects(self.safe_body_change("normal:\n  ret i32 7", "normal:\n  br label %normal"), "cyclic")
        self.rejects(self.safe_body_change("normal:\n  ret i32 7", "normal:\n  resume i32 7"), "terminator")
        self.rejects(self.safe_body_change("normal:\n  ret i32 7", "dead:\n  ret i32 7\nnormal:\n  ret i32 7"), "unreachable block")

    def test_missing_or_misrouted_handler_edge(self):
        self.rejects(self.ir.replace("tail call i32 @safe(i32 1)", "tail call i32 @externalCall(i32 1)"), "handler edge")
        self.rejects(self.ir.replace("call void @vm_interpreter_callinst_dispatch_nested(i64 %id)",
                                    "call void @vm_interpreter_callinst_dispatch_recursive(i64 %id)"), "selected handler")

    def test_dead_interpreter_bridge_is_not_an_edge(self):
        name = "vm_interpreter_nested_k0000000000000001"
        self.rejects(self.function_change(name, "  call void @call_handler_with_exception_handling(i64 0)",
                                         "  ret void\ndead_bridge:\n"
                                         "  call void @call_handler_with_exception_handling(i64 0)"), "from entry")

    def test_interpreter_entry_cfg_accepts_loops_and_integer_switch(self):
        name = "vm_interpreter_nested_k0000000000000001"
        _, body = contract.function(self.ir, name)
        replacement = ("entry:\n  %opcode = load i8, ptr @vmp_shared_exception_thrown, align 1\n"
                       "  switch i8 %opcode, label %done [\n    i8 1, label %bridge\n  ]\n"
                       "bridge:\n  call void @call_handler_with_exception_handling(i64 0)\n"
                       "  br label %entry, !llvm.loop !90\ndone:\n  ret void\n")
        report = contract.verify_contract(self.function_change(name, body, replacement) + "!90 = distinct !{!90}\n", self.rows)
        self.assertEqual(report["handlerEdges"][0]["interpreterBridgeBlock"], "bridge")

    def test_dead_shared_dispatch_chain_and_skipped_false_edge_fail(self):
        name = "vmp_shared_call_dispatch"
        _, body = contract.function(self.ir, name)
        self.rejects(self.function_change(name, body,
                     "  br label %review_return\nreview_dead:\n" + body + "review_return:\n  ret void\n"),
                     "shared dispatch selector")
        self.rejects(self.function_change(name, "br i1 %compare0, label %call0, label %next0",
                                         "br i1 %compare0, label %call0, label %next1"))

    def test_bridge_must_invoke_dispatcher_from_its_entry(self):
        name = "call_handler_with_exception_handling"
        _, body = contract.function(self.ir, name)
        self.rejects(self.function_change(name, body,
                     "  br label %review_return\nreview_dead:\n" + body + "review_return:\n  ret void\n"),
                     "bridge entry")
        self.rejects(self.function_change(name, "@vmp_shared_call_dispatch(i64 %id)",
                                         "@vmp_shared_call_dispatch(i64 0)"), "not invoked from entry")

    def test_handler_switch_selector_must_derive_from_funcid_parameter(self):
        name = "vm_interpreter_callinst_dispatch_nested"
        self.rejects(self.function_change(name, "switch i64 %funcid", "switch i64 9223372036854775807"),
                     "switch selector")
        self.rejects(self.function_change(name, "store i64 %id, ptr %slot", "store i64 1, ptr %slot"),
                     "funcid store")

    def test_descriptor_escape_and_lifetime_are_checked(self):
        self.assertEqual(contract.decode_descriptor('@r = constant [24 x i8] c"' +
                         "\\\\" + "\\00" * 23 + '", section ".text.ndkp.qseg.refs"')[0], 92)
        self.rejects(self.ir.replace('!1 = !{!"lease-v1"}', '!1 = !{!"unknown"}'), "lifetime metadata")

    def test_plain_and_effective_eh_controls(self):
        contract.verify_plain(plain_fixture())
        contract.verify_plain(EH_PLAIN, eh=True)
        for bad in (EH_PLAIN.replace("rejected_eh", "other"), EH_PLAIN.replace("invoke", "call"),
                    EH_PLAIN.replace(" personality ptr @__gxx_personality_v0", "")):
            with self.assertRaises(ValueError):
                contract.verify_plain(bad, eh=True)
        with self.assertRaisesRegex(ValueError, "no-flag"):
            contract.verify_plain(plain_fixture() + "!ndkp.qseg\n")

    def test_strict_eh_requires_same_function_and_specific_cause(self):
        self.assertEqual(contract.verify_eh_rejection({"exit": 1, "stdout": "", "stderr": EH_REASON})["exit"], 1)
        for exit_code, message in ((0, EH_REASON), (1, "out of memory"),
                                   (1, EH_REASON.replace("rejected_eh", "other")),
                                   (1, EH_REASON.split("LLVM ERROR:")[0])):
            with self.assertRaises(ValueError):
                contract.verify_eh_rejection({"exit": exit_code, "stdout": "", "stderr": message})


class CompilerLifetimeRunnerTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="qseg-contract-host-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.clang, self.cert, self.output = self.root / "clang", self.root / "cert.der", self.root / "output"
        self.clang.write_bytes(b"fake compiler, never executed")
        self.cert.write_bytes(b"fixture public certificate")
        self.argv = ["compiler_lifetime.py", "--clang", str(self.clang), "--cert-file", str(self.cert),
                     "--output", str(self.output)]

    def fake_compile(self, command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="clang version 21.1.0", stderr="")
        target = Path(command[command.index("-o") + 1])
        ir, rows = fixture()
        if target.name == "eh-output.ll":
            return SimpleNamespace(returncode=1, stdout="", stderr=EH_REASON)
        if target.name == "output.ll":
            stage = self.output / "staging"
            stage.mkdir()
            (stage / "manifest.json").write_text(json.dumps(rows), encoding="utf-8")
            for row in rows:
                for name in (row["id"], row["name"]):
                    (stage / (name + ".bin")).write_bytes(b"x" * row["bytes"])
        target.write_text({"output.ll": ir, "plain.ll": plain_fixture(), "eh-plain.ll": EH_PLAIN}[target.name], encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="compiler stdout", stderr="compiler stderr")

    def run_main(self, compiler=None):
        with patch.object(sys, "argv", self.argv), patch.object(contract.subprocess, "run", side_effect=compiler or self.fake_compile), redirect_stdout(io.StringIO()):
            contract.main()

    def test_success_binds_commands_sources_and_outputs(self):
        self.run_main()
        report = contract.read_json(self.output / "results.json")
        self.assertEqual(report["schemaVersion"], 1)
        self.assertEqual(report["checkerRevision"], 2)
        self.assertTrue(any("dynamic VM opcode/funcid" in limit for limit in report["limits"]))
        self.assertEqual(len(report["wrappers"]), 4)
        self.assertEqual(len(list(self.output.glob("0*-*.json"))), 5)
        self.assertIn("staging/manifest.json", report["artifacts"])
        self.assertEqual(report["artifacts"]["output.ll"], contract.identity(self.output / "output.ll"))
        self.assertEqual(contract.read_json(self.output / "04-eh-strict.json")["exit"], 1)

    def test_nonempty_output_preserves_old_success(self):
        self.output.mkdir()
        previous = self.output / "results.json"
        previous.write_text("old", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new or empty"):
            self.run_main()
        self.assertEqual(previous.read_text(), "old")

    def test_failure_timeout_launch_error_leave_logs_without_success(self):
        for failure in (subprocess.TimeoutExpired(["clang"], 180, output=b"partial", stderr=b"timeout"),
                        OSError("launch failed")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="qseg-command-") as folder:
                self.output = Path(folder) / "output"
                self.argv[-1] = str(self.output)
                with self.assertRaisesRegex(ValueError, "failed to run"):
                    self.run_main(lambda *args, **kwargs: (_ for _ in ()).throw(failure))
                self.assertFalse((self.output / "results.json").exists())
                self.assertTrue((self.output / "failure.json").is_file())
                self.assertTrue((self.output / "00-version.stderr.txt").is_file())

    def test_unrelated_strict_failure_never_writes_success(self):
        def unrelated(command, **kwargs):
            if "eh-output.ll" in " ".join(command):
                return SimpleNamespace(returncode=1, stdout="", stderr="out of memory")
            return self.fake_compile(command, **kwargs)
        with self.assertRaisesRegex(ValueError, "explicitly reject"):
            self.run_main(unrelated)
        self.assertFalse((self.output / "results.json").exists())
        self.assertTrue((self.output / "04-eh-strict.json").exists())


if __name__ == "__main__":
    unittest.main()
