"""Checkpoint coverage needs selected entries, real guarded IR and frozen requirements."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from verify_dex2c_apk import capabilities, check_integrity_recheck, check_requirements, recheck_ir_guard


def module(symbol, segmented=False):
    guard = 'ndkp_cse_module_recheck_v2' if segmented else 'ndkp_cse_module_recheck'
    runtime = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
    return ('define void @' + symbol + '() {\n call void @' + guard + '()\n ret void\n}\n'
            'define private void @' + guard + '() {\n' +
            ('' if segmented else ''.join(' %p' + str(i) + ' = load volatile ptr, ptr @module\n' for i in range(5))) +
            ' call void @' + runtime + '()\n ret void\n}\n')


class IntegrityRecheckTest(unittest.TestCase):
    def test_zero_pool_guard_requires_own_rx_anchor_and_load_constructor(self):
        ir = ('@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] '
              '[{ i32, ptr, ptr } { i32 103, ptr @ndkp_cse_image_recheck, ptr null }]\n'
              'define void @entry() {\n call void @ndkp_cse_image_recheck()\n ret void\n}\n'
              'define private void @ndkp_cse_image_recheck() !noobf !0 {\n'
              ' call void @ndkp_cse_recheck_image_v1(ptr @ndkp_cse_image_recheck)\n ret void\n}\n')
        self.assertEqual('ndkp_cse_image_recheck', recheck_ir_guard(ir, 'entry', False))
        for changed in (ir.replace('i32 103', 'i32 101'), ir.replace('!noobf !0', ''),
                        ir.replace(ir.splitlines()[0], '@llvm.global_ctors = appending global [0 x { i32, ptr, ptr }] zeroinitializer ; i32 103, ptr @ndkp_cse_image_recheck, ptr null'),
                        ir.replace('(ptr @ndkp_cse_image_recheck)', '(ptr @foreign)'),
                        ir.replace('(ptr @ndkp_cse_image_recheck)', '(ptr @entry) ; call void @ndkp_cse_recheck_image_v1(ptr @ndkp_cse_image_recheck)'),
                        ir.replace(' call void @ndkp_cse_recheck_image_v1', ' ;call void @ndkp_cse_recheck_image_v1')):
            with self.subTest(ir=changed), self.assertRaises(ValueError):
                recheck_ir_guard(changed, 'entry', False)
        with self.assertRaises(ValueError): recheck_ir_guard(ir, 'entry', True)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.native = Path(temporary.name)
        self.method = {'method': 'Example.initialize()V', 'symbol': 'vm_symbol', 'bridge': 'Bridge.call()V',
                       'protection': 'vmp', 'integrityRecheck': True}
        self.selection = {'methods': [self.method], 'registrationIntegrityRecheck': True}
        self.receipt = {'segmentedData': False, 'integrityRecheck': {'schemaVersion': 1,
                        'runtime': 'ndkp_cse_recheck_module_v1', 'entries': [], 'irSha256': {}}}
        self.configure(False)

    def configure(self, segmented):
        self.receipt['segmentedData'] = segmented
        checkpoint = self.receipt['integrityRecheck']
        checkpoint['runtime'] = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
        checkpoint['entries'] = []
        unit = 'protected' if self.method['protection'] == 'vmp' else 'native'
        checkpoint['irSha256'] = {}
        for symbol, source in ((self.method['symbol'], unit), ('JNI_OnLoad', 'registration')):
            ir = module(symbol, segmented)
            (self.native / (source + '.ll')).write_text(ir, encoding='utf-8', newline='\n')
            digest = hashlib.sha256(ir.encode()).hexdigest()
            checkpoint['irSha256'][source] = digest
            if source != 'registration':
                self.receipt['irSha256' if source == 'protected' else 'nativeIrSha256'] = digest
            checkpoint['entries'].append({'symbol': symbol, 'translationUnit': source,
                                          'guard': recheck_ir_guard(ir, symbol, segmented)})

    def check(self):
        return check_integrity_recheck(self.receipt, self.selection, self.native)

    def test_real_vm_native_and_segmented_entries_keep_runtime_unverified(self):
        for policy in ('vmp', 'native-cse'):
            self.method['protection'] = policy
            for segmented in (False, True):
                self.configure(segmented)
                self.assertEqual(self.check()['validationStatus'], 'passed')
                self.assertEqual(capabilities(self.receipt, None)['integrityRecheck']['validationStatus'], 'unverified')

    def test_missing_extra_duplicate_or_wrong_registration_entry_is_rejected(self):
        valid = copy.deepcopy(self.receipt)
        entries = valid['integrityRecheck']['entries']
        for changed in (entries[:1], entries + [entries[0]], [entries[0], {**entries[1], 'symbol': 'other'}],
                        [{**entries[0], 'translationUnit': 'registration'}, entries[1]],
                        [{**entries[0], 'guard': 'other'}, entries[1]]):
            self.receipt = copy.deepcopy(valid); self.receipt['integrityRecheck']['entries'] = changed
            with self.subTest(entries=changed), self.assertRaises(ValueError): self.check()
        self.receipt = valid; del self.receipt['integrityRecheck']
        with self.assertRaisesRegex(ValueError, 'missing integrity'): self.check()

    def test_boolean_claims_are_strict_and_legacy_does_not_gain_coverage(self):
        for value in ('true', 1, None):
            self.method['integrityRecheck'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.check()
        self.method['integrityRecheck'] = True
        for value in ('true', 1, False):
            self.selection['registrationIntegrityRecheck'] = value
            with self.subTest(registration=value), self.assertRaises(ValueError): self.check()
        self.selection = {'methods': [{k: v for k, v in self.method.items() if k != 'integrityRecheck'}]}
        self.receipt.pop('integrityRecheck')
        self.assertIsNone(self.check())
        with self.assertRaisesRegex(ValueError, 'critical method integrity'):
            check_requirements(self.selection, {'schemaVersion': 1, 'methods': [self.method]})

    def test_changed_ir_and_resealed_receipt_with_missing_call_are_rejected(self):
        path = self.native / 'protected.ll'
        changed = path.read_text().replace(' call void @ndkp_cse_module_recheck()\n', '')
        path.write_text(changed, encoding='utf-8', newline='\n')
        with self.assertRaisesRegex(ValueError, 'IR changed'): self.check()
        digest = hashlib.sha256(changed.encode()).hexdigest()
        self.receipt['irSha256'] = digest; self.receipt['integrityRecheck']['irSha256']['protected'] = digest
        with self.assertRaisesRegex(ValueError, 'entry integrity recheck'): self.check()

    def test_annotation_declaration_late_call_empty_guard_and_wrong_runtime_fail(self):
        for segmented in (False, True):
            valid = module('entry', segmented)
            guard = 'ndkp_cse_module_recheck_v2' if segmented else 'ndkp_cse_module_recheck'
            runtime = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
            bypass = valid.replace(' call void @' + runtime, ' br label %skip\ncheck:\n call void @' + runtime)
            end = bypass.rfind('\n}')
            bypass = bypass[:end] + '\nskip:\n ret void' + bypass[end:]
            bad = [valid.replace(' call void @' + guard + '()\n', ''),
                   valid.replace(' call void @' + guard, ' br label %later\nlater:\n call void @' + guard),
                   valid.replace('ndkp_qseg_recheck', 'wrong_runtime').replace('ndkp_cse_recheck_module_v1', 'wrong_runtime'),
                   valid + '!ndkp.cse.recheck.prepare !0\n', bypass]
            if not segmented: bad.append(valid.replace('load volatile', 'load'))
            for changed in bad:
                with self.subTest(segmented=segmented, changed=changed), self.assertRaises(ValueError):
                    recheck_ir_guard(changed, 'entry', segmented)
            with self.assertRaises(ValueError): recheck_ir_guard(valid, 'entry', not segmented)
            for fake in ('call void %callback(ptr @' + runtime + '())',
                         'call void asm sideeffect "call void @' + runtime + '()", ""()',
                         '; call void @' + runtime + '()'):
                changed = valid.replace('call void @' + runtime + '()', fake)
                with self.subTest(segmented=segmented, fake=fake), self.assertRaises(ValueError):
                    recheck_ir_guard(changed, 'entry', segmented)

    def test_frozen_checkpoint_and_registration_requirements_match_independently(self):
        requirements = {'schemaVersion': 1, 'methods': [dict(self.method)], 'registrationIntegrityRecheck': True}
        self.assertTrue(check_requirements(self.selection, requirements))
        for field in ('integrityRecheck',):
            for value in (False, 1, 'true'):
                requirements['methods'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    check_requirements(self.selection, requirements)
        requirements['methods'][0]['integrityRecheck'] = True
        requirements['registrationIntegrityRecheck'] = False
        with self.assertRaisesRegex(ValueError, 'registration integrity'):
            check_requirements(self.selection, requirements)

    def test_indirect_invoke_or_asm_cannot_precede_the_first_checkpoint_call(self):
        for segmented in (False, True):
            valid = module('entry', segmented).replace('@entry()', '@entry(ptr %callback)')
            guard = 'ndkp_cse_module_recheck_v2' if segmented else 'ndkp_cse_module_recheck'
            for earlier in ('call void %callback()', 'invoke void %callback() to label %next unwind label %error',
                            'invoke void @business() to label %next unwind label %error',
                            'call void asm sideeffect "", ""()',
                            'call void asm sideeffect "@' + guard + '(", ""()',
                            'call void %callback(ptr @' + guard + ')'):
                changed = valid.replace(' call void @' + guard, ' ' + earlier + '\n call void @' + guard, 1)
                with self.subTest(segmented=segmented, earlier=earlier), self.assertRaises(ValueError):
                    recheck_ir_guard(changed, 'entry', segmented)
            skipped = valid.replace(' call void @' + guard,
                ' call void @llvm.dbg.value(metadata i32 0)\n call void @llvm.lifetime.start.p0(i64 1, ptr null)\n call void @' + guard, 1)
            self.assertEqual(guard, recheck_ir_guard(skipped, 'entry', segmented))

    def test_guard_conditional_bypass_fails_and_both_checked_branches_pass(self):
        for segmented in (False, True):
            valid = module('entry', segmented)
            runtime = 'ndkp_qseg_recheck' if segmented else 'ndkp_cse_recheck_module_v1'
            split = valid.replace(' call void @' + runtime,
                ' br i1 true, label %check, label %skip\ncheck:\n call void @' + runtime)
            end = split.rfind('\n}')
            bypass = split[:end] + '\nskip:\n ret void' + split[end:]
            with self.subTest(segmented=segmented), self.assertRaises(ValueError):
                recheck_ir_guard(bypass, 'entry', segmented)
            both = bypass.replace('\nskip:\n ret void', '\nskip:\n call void @' + runtime + '()\n ret void')
            self.assertTrue(recheck_ir_guard(both, 'entry', segmented))


if __name__ == '__main__':
    unittest.main()
