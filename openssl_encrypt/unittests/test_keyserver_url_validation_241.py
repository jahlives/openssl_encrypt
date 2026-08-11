#!/usr/bin/env python3
"""Keyserver credential-bearing calls must reject non-HTTPS and unconfigured
server URLs (gitlab#241, scan F15, CWE-319).

`register` enforced https, but `login` and `register_with_email` did not, and
cert pinning only mounts for the https prefix. An `http://` URL leaks the
`client_id` (which alone yields tokens), a stored password, and returned JWTs in
cleartext; an arbitrary https host not among the configured servers would
receive them too. All three now go through a shared validator requiring https
and membership of `config.servers`.
"""

import unittest

from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin


class TestKeyserverUrlValidation(unittest.TestCase):
    def setUp(self):
        self.plugin = KeyserverPlugin(
            KeyserverConfig(enabled=True, servers=["https://keys.example.com"])
        )

    def test_http_url_is_rejected(self):
        with self.assertRaises(ValueError):
            self.plugin._validate_server_url("http://keys.example.com")

    def test_unconfigured_https_url_is_rejected(self):
        with self.assertRaises(ValueError):
            self.plugin._validate_server_url("https://evil.example.net")

    def test_configured_https_url_passes(self):
        # No exception; trailing-slash tolerant.
        self.plugin._validate_server_url("https://keys.example.com")
        self.plugin._validate_server_url("https://keys.example.com/")

    def test_login_rejects_http_before_any_request(self):
        with self.assertRaises(ValueError):
            self.plugin.login(client_id="c", server_url="http://keys.example.com")

    def test_register_with_email_rejects_unconfigured_host(self):
        with self.assertRaises(ValueError):
            self.plugin.register_with_email(email="a@b.test", server_url="https://evil.example.net")


if __name__ == "__main__":
    unittest.main()
