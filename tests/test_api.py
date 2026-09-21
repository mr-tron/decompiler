import base64
import http.client
import json
import threading
import unittest
from unittest.mock import patch

from decompiler.api import Server, validate_request
from decompiler.errors import DecompilerError

EMPTY = bytes.fromhex('b5ee9c72010101010002000000')


class ApiTests(unittest.TestCase):
    def test_request_boundary(self):
        request = {'code': base64.b64encode(EMPTY).decode()}
        self.assertEqual(validate_request(request), (EMPTY, 30000))
        for bad in ({}, [], {'code': '!'}, {'code': ''},
                    {**request, 'path': '/bin/sh'}, {**request, 'max_search_time_ms': True},
                    {**request, 'max_search_time_ms': 30001}):
            with self.assertRaises(DecompilerError):
                validate_request(bad)

    def test_http_structured_errors(self):
        with Server(('127.0.0.1', 0)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                conn.request('GET', '/')
                page = conn.getresponse()
                self.assertEqual(page.status, 200)
                self.assertEqual(page.getheader('Content-Type'), 'text/html; charset=utf-8')
                html = page.read()
                self.assertIn(b'<form id="decompile-form">', html)
                self.assertIn(b'<details id="stdlib-details" hidden>', html)
                self.assertIn(b'<summary>Generated stdlib</summary>', html)
                self.assertIn(b'aria-label="Contract FunC source"', html)
                self.assertIn(b'<label for="source-view">Source view</label>', html)
                self.assertIn(b'<option value="readable">Readable FunC</option>', html)
                self.assertIn('Compiles · code hash differs'.encode(), html)
                conn.close()
                conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                conn.request('GET', '/../../todo.md')
                missing = conn.getresponse()
                self.assertEqual(missing.status, 404)
                missing.read()
                conn.close()
                conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                conn.request('POST', '/v1/decompile', '{"code":"!"}', {'Content-Type': 'application/json'})
                response = conn.getresponse()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response.read())['error']['code'], 'INVALID_BASE64')
                conn.close()
                conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                conn.request('POST', '/v1/decompile', '{}', {'Content-Type': 'text/plain'})
                response = conn.getresponse()
                self.assertEqual(response.status, 415)
                response.read()
                conn.close()
                with patch('decompiler.api.run_worker', return_value=(200, {'success': True})):
                    conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                    conn.request('POST', '/v1/decompile', '{}', {'Content-Type': 'application/json'})
                    response = conn.getresponse()
                    self.assertEqual(json.loads(response.read()), {'success': True})
                    conn.close()
            finally:
                server.shutdown()
                thread.join(2)


if __name__ == '__main__':
    unittest.main()
