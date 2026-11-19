import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import opcode_diversity as diversity


KEY = 7
IR = "!ndkp.vmp.protected !0\n!ndkp.vmp.protected !0\n"


def mapping(shift):
    legacy = diversity.legacy_decode_map(KEY)
    inverse = {legacy[ordinal]: ordinal for ordinal in range(1, 29)}
    return tuple(inverse[(semantic + shift - 1) % 28 + 1] for semantic in range(1, 29))


def csv(values):
    return ",".join(f"{semantic}:{ordinal}" for semantic, ordinal in enumerate(values, 1))


def log(first=1, second=2):
    return "\n".join(
        f"[VMP_VARIANT] function={name} key=0x0007 semantic_to_ordinal={csv(mapping(shift))}\n"
        f"[VMP_DISPATCH_RANDOMIZE] clone=vm_interpreter_{name}_k7 cases=8 style=volatile-xor-chain"
        for name, shift in (("first", first), ("second", second)))


class OpcodeDiversityTests(unittest.TestCase):
    def test_three_builds_and_all_legacy_semantics_fail(self):
        builds = [diversity.inspect_variant(log(index * 2 + 1, index * 2 + 2), IR) for index in range(3)]
        diversity.compare_variants(builds)
        self.assertEqual(builds[0]["first"], (KEY, mapping(1)))

    def test_csv_order_and_integer_spelling_do_not_create_diversity(self):
        text = csv(mapping(1))
        reordered = ",".join(reversed(text.split(",")))
        zero_padded = ",".join(f"{int(a):02}:{int(b):02}" for a, b in
                               (pair.split(":") for pair in text.split(",")))
        self.assertEqual(diversity.parse_mapping(text), diversity.parse_mapping(reordered))
        self.assertEqual(diversity.parse_mapping(text), diversity.parse_mapping(zero_padded))
        builds = [{"first": (KEY, diversity.parse_mapping(value)), "second": (KEY, mapping(index + 2))}
                  for index, value in enumerate((text, reordered, zero_padded))]
        with self.assertRaisesRegex(ValueError, "first"):
            diversity.compare_variants(builds)

    def test_duplicate_semantic_or_ordinal_rejected_before_dict(self):
        pairs = csv(mapping(1)).split(",")
        for changed in (pairs + [pairs[0]], [pairs[0]] + pairs[:-1],
                        [pairs[0], "2:" + pairs[0].split(":")[1]] + pairs[2:],
                        pairs[:-1], pairs[:-1] + ["29:29"]):
            with self.assertRaises(ValueError):
                diversity.parse_mapping(",".join(changed))

    def test_one_legacy_decodable_semantic_fails(self):
        values = list(mapping(1))
        legacy = diversity.legacy_decode_map(KEY)
        ordinal = legacy.index(1)
        index = values.index(ordinal)
        values[0], values[index] = values[index], values[0]
        text = log().replace(csv(mapping(1)), csv(values))
        with self.assertRaisesRegex(ValueError, "key-only.*first"):
            diversity.inspect_variant(text, IR)

    def test_missing_duplicate_or_unexpected_variant_rows_fail(self):
        text = log()
        first = text.splitlines()[0]
        for broken in (text + "\n" + first, text.replace(first + "\n", ""),
                       text.replace("function=second", "function=first"),
                       text.replace("function=second", "function=unexpected")):
            with self.assertRaises(ValueError):
                diversity.inspect_variant(broken, IR)

    def test_dispatch_clone_must_be_unique_and_bound_to_method_key(self):
        for broken in (log().replace("clone=vm_interpreter_second_k7", "clone=vm_interpreter_first_k7"),
                       log().replace("clone=vm_interpreter_second_k7", "clone=vm_interpreter_second_k8"),
                       log().replace("cases=8", "cases=28", 1)):
            with self.assertRaises(ValueError):
                diversity.inspect_variant(broken, IR)

    def test_one_frozen_method_and_two_build_only_fail(self):
        builds = [diversity.inspect_variant(log(index + 1, 9), IR) for index in range(3)]
        with self.assertRaisesRegex(ValueError, "second"):
            diversity.compare_variants(builds)
        with self.assertRaisesRegex(ValueError, "three builds"):
            diversity.compare_variants(builds[:2])

    def test_protected_ir_and_no_flag_opt_in_checks_remain(self):
        for text in (IR.splitlines()[0], IR + "opcode_dispatch_map"):
            with self.assertRaises(ValueError):
                diversity.inspect_variant(log(), text)
        diversity.check_plain("define i32 @first(i32 %x) { ret i32 %x }")
        for text in (IR, "define void @vm_interpreter_first_k7() {}"):
            with self.assertRaises(ValueError):
                diversity.check_plain(text)

    def test_output_preserves_actual_ir_logs_and_refuses_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'evidence'
            argv = ['opcode_diversity.py', '--clang', 'clang', '--ndk', 'ndk', '--output', str(output)]
            calls = []

            def compile_fixture(command, **kwargs):
                calls.append(command)
                path = Path(command[command.index('-o') + 1])
                if '-irobf-vmp' in command:
                    index = len(calls) - 1
                    path.write_text(IR, encoding='utf-8')
                    stderr = log(index * 2 + 1, index * 2 + 2)
                else:
                    path.write_text('define i32 @first(i32 %x) { ret i32 %x }', encoding='utf-8')
                    stderr = 'plain diagnostic'
                return subprocess.CompletedProcess(command, 0, 'compiler stdout', stderr)

            with patch.object(sys, 'argv', argv), patch.object(diversity.subprocess, 'run', side_effect=compile_fixture):
                diversity.main()
                with self.assertRaisesRegex(ValueError, 'must be new'):
                    diversity.main()
            self.assertEqual(len(calls), 4)
            self.assertNotIn('-irobf-vmp', calls[-1])
            self.assertTrue((output / 'input.c').exists())
            self.assertTrue(json.loads((output / 'results.json').read_text())['passed'])
            for index in range(3):
                self.assertEqual((output / f'protected-{index}.ll').read_text(), IR)
                self.assertEqual((output / f'protected-{index}.stderr.txt').read_text(),
                                 log(index * 2 + 1, index * 2 + 2))
                self.assertEqual((output / f'protected-{index}.stdout.txt').read_text(), 'compiler stdout')
            self.assertEqual((output / 'plain.stderr.txt').read_text(), 'plain diagnostic')

    def test_failed_compile_keeps_logs_without_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'failure'
            argv = ['opcode_diversity.py', '--clang', 'clang', '--ndk', 'ndk', '--output', str(output)]
            result = subprocess.CompletedProcess([], 1, 'partial stdout', 'compile failed')
            with patch.object(sys, 'argv', argv), patch.object(diversity.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'compile failed'):
                    diversity.main()
            self.assertEqual((output / 'protected-0.stderr.txt').read_text(), 'compile failed')
            self.assertEqual((output / 'protected-0.stdout.txt').read_text(), 'partial stdout')
            self.assertFalse((output / 'results.json').exists())


if __name__ == "__main__":
    unittest.main()
