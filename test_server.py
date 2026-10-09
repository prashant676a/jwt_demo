import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import jwt_core
import server


class BrowserContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.make_server()
        cls.base = 'http://127.0.0.1:%d' % cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def call(self, path, body=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(self.base + path, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read()
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            return response.status, json.loads(raw) if raw else None

    def test_static_routes_are_explicit(self):
        for path, content_type in [('/', 'text/html'), ('/app.js', 'text/javascript'), ('/style.css', 'text/css')]:
            with urllib.request.urlopen(self.base + path) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(content_type, response.headers['Content-Type'])
                self.assertTrue(response.read())
        self.assertEqual(self.call('/server.py')[0], 404)
        self.assertEqual(self.call('/static/../server.py')[0], 404)

    def test_short_lifecycle_and_logout_semantics(self):
        status, tokens = self.call('/login', {'username': 'bob', 'password': 'bob-pass', 'access_ttl': 20})
        self.assertEqual(status, 200)
        claims = jwt_core.peek(tokens['access_token'])['payload']
        self.assertEqual(claims['exp'] - claims['iat'], 20)
        self.assertEqual(tokens['refresh_expires_in'], 604800)
        self.assertEqual(self.call('/me', token=tokens['access_token'])[0], 200)
        self.assertEqual(self.call('/admin', token=tokens['access_token'])[0], 403)
        original_decode = jwt_core.decode
        with patch.object(jwt_core, 'decode', side_effect=lambda token, secret: original_decode(token, secret, now=claims['exp'] + 1)):
            self.assertEqual(self.call('/me', token=tokens['access_token']), (401, {'error': 'token expired'}))
        status, fresh = self.call('/refresh', {'refresh_token': tokens['refresh_token']})
        self.assertEqual(status, 200)
        self.assertEqual(fresh['expires_in'], 20)
        self.assertNotEqual(tokens['access_token'], fresh['access_token'])
        self.assertNotEqual(tokens['refresh_token'], fresh['refresh_token'])
        self.assertEqual(self.call('/refresh', {'refresh_token': tokens['refresh_token']})[0], 401)
        self.assertEqual(self.call('/logout', {'refresh_token': fresh['refresh_token']})[0], 204)
        self.assertEqual(self.call('/refresh', {'refresh_token': fresh['refresh_token']})[0], 401)
        self.assertEqual(self.call('/me', token=fresh['access_token'])[0], 200)

    def test_default_and_invalid_lifetimes(self):
        credentials = {'username': 'alice', 'password': 'alice-pass'}
        self.assertEqual(self.call('/login', credentials)[1]['expires_in'], 900)
        for value in [True, -1, 0, 21, '20', None, []]:
            self.assertEqual(self.call('/login', dict(credentials, access_ttl=value))[0], 400)


if __name__ == '__main__':
    unittest.main()
