from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from fwagent.dynamic.isolated_http_probe import GuestClient, aes, authentication_denied, login_page, rsa_chunks, status_fields


class FunctionalProbeTests(unittest.TestCase):
    def test_http_200_login_form_is_not_authenticated_status(self):
        page = '<html><input id="pcPassword"><script>var statusPara;</script></html>'
        self.assertTrue(login_page(page))
        fields, _ = status_fields(page, None)
        self.assertEqual(fields, [])

    def test_static_status_variable_uses_do_not_prove_handler_execution(self):
        fields, _ = status_fields('if(statusPara[0]) { var mask=lanPara[2]; }',None)
        self.assertEqual(fields, [])

    def test_login_redirect_and_http_denial_are_distinguished_from_status_200(self):
        self.assertTrue(authentication_denied('',{'status':302,'redirects_to_login':True}))
        self.assertTrue(authentication_denied('',{'status':403}))
        self.assertTrue(authentication_denied('<script>window.parent.location.href="/";</script>',{'status':200}))
        self.assertFalse(authentication_denied('<html>status</html>',{'status':200}))

    def test_server_injected_array_assignments_are_observed(self):
        fields, _ = status_fields('var statusPara = new Array(1,2); var lanPara = [0,1];',None)
        self.assertEqual(fields,['lanPara','statusPara'])

    def test_secrets_and_request_bodies_are_excluded_from_evidence(self):
        class Response:
            status = 200
            def read(self, _): return b'response containing TEST_PASSWORD'
            def getheaders(self): return [('Set-Cookie','JSESSIONID=TEST_SESSION; HttpOnly')]
            def getheader(self, _): return 'text/plain'
        class Connection:
            def __init__(self,*args,**kwargs): pass
            def request(self,*args,**kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        with patch('fwagent.dynamic.isolated_http_probe.http.client.HTTPConnection',Connection):
            client = GuestClient()
            client.request('/cgi',body='pwd=TEST_PASSWORD',label='login')
        evidence = json.dumps(client.records)
        self.assertNotIn('TEST_PASSWORD',evidence)
        self.assertNotIn('TEST_SESSION',evidence)
        self.assertEqual(client.cookies['JSESSIONID'],'TEST_SESSION')

    def test_external_paths_and_request_budget_are_enforced(self):
        client = GuestClient()
        for path in ['https://example.com/','//example.com/','/x\r\nHost: example.com']:
            with self.assertRaises(ValueError): client.request(path)
        client.request_count = 48
        with self.assertRaisesRegex(ValueError,'budget'): client.request('/')

    def test_unexpected_rsa_key_cannot_exhaust_probe(self):
        with self.assertRaises(ValueError): rsa_chunks('text','f'*4096,'10001')

    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(),'OpenSSL checked in Linux worker')
    def test_aes_matches_nist_first_block_and_roundtrips_with_padding(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        encrypted = aes(plain,key,iv)
        self.assertEqual(encrypted[:16].hex(),'7649abac8119b246cee98e9b12e9197d')
        self.assertEqual(aes(encrypted,key,iv,decrypt=True),plain)


if __name__ == '__main__':
    unittest.main()
