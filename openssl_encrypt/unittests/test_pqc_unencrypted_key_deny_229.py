#!/usr/bin/env python3
"""decrypt_file must default-deny a file that embeds an UNENCRYPTED post-quantum
private key (gitlab#229, security scan F5, CWE-287).

Background: ``pqc_key_encrypted`` defaults to ``False``. When it is false or
absent, ``decrypt_file`` used to adopt the file's own ``encryption.pqc_private_key``
verbatim as the decryption private key -- and for mayo/cross/ML-KEM hybrids the
bulk key derives *only* from it, so the password is never used. A crafted
self-contained file therefore decrypted under ANY password, printing "integrity
verified" and writing attacker-chosen plaintext. The legitimate encryptor never
emits an unencrypted embedded key (every store path marks it ``key_encrypted``),
so refusing such files breaks nothing real.

These tests pin the fix: an embedded PQC private key that is not marked
encrypted is refused BEFORE any key derivation, regardless of the password, and
the refusal can only be lifted by an explicit opt-in.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import EncryptionAlgorithm, decrypt_file, encrypt_file

_GUARD_MARKER = "unencrypted post-quantum private key"


def _split_header(path):
    with open(path, "rb") as f:
        content = f.read()
    colon = content.find(b":")
    assert colon > 0, "metadata header separator not found"
    metadata = json.loads(base64.b64decode(content[:colon]))
    return metadata, content[colon + 1 :]


def _write_header(path, metadata, payload):
    header = base64.b64encode(json.dumps(metadata).encode("utf-8"))
    with open(path, "wb") as f:
        f.write(header + b":" + payload)


class TestUnencryptedEmbeddedPqcKeyDenied(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.password = b"correct horse battery staple"
        self.plaintext = b"top secret backup contents\n"
        self.src = os.path.join(self.tmp, "plain.txt")
        self.enc = os.path.join(self.tmp, "file.enc")
        self.out = os.path.join(self.tmp, "out.txt")
        with open(self.src, "wb") as f:
            f.write(self.plaintext)
        # Cheap but real KDF config so encryption is a valid file.
        self.hash_config = {
            "sha512": 10,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
            },
        }
        encrypt_file(
            self.src,
            self.enc,
            self.password,
            self.hash_config,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _inject_unencrypted_embedded_key(self):
        """Craft the F5 attacker file: an embedded PQC private key with no
        ``pqc_key_encrypted`` flag. Only the pqc fields are added, so the
        existing hash-presence/AEAD-binding validation still passes and the
        code reaches the key-stretching-gate site."""
        metadata, payload = _split_header(self.enc)
        enc = metadata["encryption"]
        enc["pqc_public_key"] = base64.b64encode(b"attacker-public-key").decode()
        enc["pqc_private_key"] = base64.b64encode(b"attacker-private-key").decode()
        enc.pop("pqc_key_encrypted", None)  # false/absent == the vulnerable state
        _write_header(self.enc, metadata, payload)

    def test_baseline_untampered_file_decrypts(self):
        # Sanity: the honest file opens with the right password.
        decrypt_file(self.enc, self.out, self.password, quiet=True)
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), self.plaintext)

    def test_embedded_unencrypted_key_refused_with_correct_password(self):
        self._inject_unencrypted_embedded_key()
        with self.assertRaises(Exception) as ctx:
            decrypt_file(self.enc, self.out, self.password, quiet=True)
        self.assertIn(_GUARD_MARKER, str(ctx.exception).lower())
        # The gate must fire before any plaintext is produced.
        self.assertFalse(os.path.exists(self.out))

    def test_embedded_unencrypted_key_refused_with_wrong_password(self):
        # The whole point: the gate fires regardless of the password, so a
        # crafted file cannot "decrypt under any password".
        self._inject_unencrypted_embedded_key()
        with self.assertRaises(Exception) as ctx:
            decrypt_file(self.enc, self.out, b"any wrong password", quiet=True)
        self.assertIn(_GUARD_MARKER, str(ctx.exception).lower())
        self.assertFalse(os.path.exists(self.out))

    def test_explicit_opt_in_lifts_the_gate(self):
        # A trusted legacy file can still be read via the opt-in; the specific
        # default-deny gate must NOT be what stops it.
        self._inject_unencrypted_embedded_key()
        try:
            decrypt_file(
                self.enc,
                self.out,
                self.password,
                quiet=True,
                allow_unencrypted_pqc_key=True,
            )
        except Exception as e:
            self.assertNotIn(
                _GUARD_MARKER,
                str(e).lower(),
                "opt-in must bypass the default-deny gate, not trip it",
            )


if __name__ == "__main__":
    unittest.main()
