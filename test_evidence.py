"""Reject plausible wrong joins without changing any saved network records."""
import copy
import unittest
from unittest.mock import patch

import verify_extensions as ext
from verify import DEDICATED, SHARED, get, load, pair_batch


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        h = load('shared-recent')['items'][0]['hash']
        rpc = pair_batch('check-rpc')
        self.shared_tx = get(rpc, 'eth_getTransactionByHash', [h])
        self.logs = get(rpc, 'eth_getTransactionReceipt', [h])['logs']
        self.call = ext.children(self.shared_tx)[0][1]

    def test_real_call_cannot_be_attributed_to_the_other_vault(self):
        ext.decode_transfer(self.call, SHARED)
        with self.assertRaisesRegex(ValueError, 'proof vault target'):
            ext.decode_transfer(self.call, DEDICATED)

    def test_same_size_ciphertext_edit_does_not_match_committed_note(self):
        body = ext.ABI(self.call[4:])
        array = body.ptr(64)
        first_note = body.ptr(array + 32, array + 32)
        edited = bytearray(self.call)
        edited[4 + first_note + 32] ^= 1
        ext.check_calls(self.call, self.logs, SHARED)
        with self.assertRaisesRegex(ValueError, 'Output notes disagree'):
            ext.check_calls(bytes(edited), self.logs, SHARED)

    def test_genuine_envelopes_from_different_registrants_cannot_be_swapped(self):
        unedited = load('registry_recheck_rpc')
        req = load('registry_recheck_rpc_request')
        pref = ext.selector('getAuditCiphertexts(address)')
        ids = [x['id'] for x in req if x['method'] == 'eth_call' and x['params'][1] == 'latest'
               and x['params'][0]['data'].startswith(pref)]
        self.assertEqual(len(ids), 2)
        edited = copy.deepcopy(unedited)
        a, b = [next(x for x in edited if x['id']==i) for i in ids]
        self.assertNotEqual(a['result'], b['result'])
        self.assertEqual(len(a['result']), len(b['result']))
        a['result'], b['result'] = b['result'], a['result']
        with patch('verify_extensions.load', side_effect=lambda name: edited if name == 'registry_recheck_rpc' else load(name)):
            with self.assertRaisesRegex(ValueError, 'Latest registry read and public registration mismatch'):
                ext.verify_registrations(load('registry-abis'))


if __name__ == '__main__':
    unittest.main()
