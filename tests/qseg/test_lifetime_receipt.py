"""生命周期回执不能夸大回收范围或接受未知 ABI。"""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from verify_dex2c_apk import check_lifetimes


class LifetimeReceiptTest(unittest.TestCase):
    def test_policy_binding(self):
        receipt = {'qsegLifetimeAbi': 1, 'idlePlaintextBudgetBytes': 1048576,
                   'symbols': ['vm'], 'vmLifetimePolicies': {'vm': 'lease-v1'}}
        segments = {'segments': [{'name': 'vm', 'kind': 1, 'lifetime': 'lease-v1'},
                                 {'name': 'str', 'kind': 2, 'lifetime': 'copy-v1'}]}
        check_lifetimes(receipt, segments)
        for key, value in [('qsegLifetimeAbi', 2), ('qsegLifetimeAbi', True),
                           ('idlePlaintextBudgetBytes', 0), ('vmLifetimePolicies', {}),
                           ('vmLifetimePolicies', {'vm': 'pinned-legacy'})]:
            changed = copy.deepcopy(receipt); changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                check_lifetimes(changed, segments)
        for index, mode in [(0, 'pinned-legacy'), (1, 'lease-v1')]:
            changed = copy.deepcopy(segments); changed['segments'][index]['lifetime'] = mode
            with self.subTest(index=index), self.assertRaises(ValueError):
                check_lifetimes(receipt, changed)

    def test_legacy_cannot_claim_reclamation(self):
        check_lifetimes({}, {'segments': [{'kind': 1}]})
        with self.assertRaisesRegex(ValueError, 'legacy receipt claims'):
            check_lifetimes({}, {'segments': [{'kind': 1, 'lifetime': 'lease-v1'}]})

    def test_chunks_must_agree(self):
        with self.assertRaisesRegex(ValueError, 'inconsistent chunk'):
            check_lifetimes({'qsegLifetimeAbi': 1, 'idlePlaintextBudgetBytes': 1048576,
                             'symbols': ['vm'], 'vmLifetimePolicies': {'vm': 'lease-v1'}},
                            {'segments': [{'name': 'vm', 'kind': 1, 'lifetime': mode}
                                          for mode in ['lease-v1', 'pinned-legacy']]})
