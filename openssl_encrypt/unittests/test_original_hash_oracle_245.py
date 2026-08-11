#!/usr/bin/env python3
"""New files must not store the unkeyed sha256(plaintext) plaintext-confirmation
oracle in their cleartext header (scan finding F8, gitlab#245, CWE-311).

`hashes.original_hash` was sha256(plaintext), readable without the key, letting
anyone holding the file confirm a guessed/brute-forced plaintext offline. It was
redundant: every reachable cipher path already authenticates the plaintext
before releasing it. The fix stops writing it; decrypt stays tolerant of old
files that still carry it.
"""

import base64
import json
import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
)


def _read_metadata(path):
    with open(path, "rb") as f:
        content = f.read()
    metadata_b64, _ = content.split(b":", 1)
    return json.loads(base64.b64decode(metadata_b64))


class TestOriginalHashOracleRemoved(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.plaintext = b"the quick brown fox jumps over the lazy dog\n" * 4
        self.infile = os.path.join(self.test_dir, "in.txt")
        with open(self.infile, "wb") as f:
            f.write(self.plaintext)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _roundtrip(self, algorithm):
        enc = os.path.join(self.test_dir, "enc.bin")
        dec = os.path.join(self.test_dir, "dec.txt")
        encrypt_file(self.infile, enc, b"password", algorithm=algorithm, quiet=True)
        meta = _read_metadata(enc)
        decrypt_file(enc, dec, b"password", quiet=True)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), self.plaintext)
        return meta

    def test_aead_file_has_no_original_hash(self):
        meta = self._roundtrip(EncryptionAlgorithm.AES_GCM)
        self.assertNotIn(
            "original_hash",
            meta.get("hashes", {}),
            "AEAD file must not store the plaintext-confirmation oracle",
        )

    def test_chacha_file_has_no_original_hash(self):
        meta = self._roundtrip(EncryptionAlgorithm.CHACHA20_POLY1305)
        self.assertNotIn("original_hash", meta.get("hashes", {}))

    def test_fernet_non_aead_has_no_original_hash_but_keeps_encrypted_hash(self):
        # Fernet is authenticated (AES-CBC + HMAC), so the plaintext hash is still
        # redundant; encrypted_hash is over ciphertext (already public) and stays.
        meta = self._roundtrip(EncryptionAlgorithm.FERNET)
        self.assertNotIn("original_hash", meta.get("hashes", {}))
        self.assertIn("encrypted_hash", meta.get("hashes", {}))

    def test_plaintext_hash_absent_from_entire_header(self):
        # Defense-in-depth: the sha256(plaintext) hex must not appear anywhere in
        # the cleartext metadata header, under any key.
        import hashlib

        enc = os.path.join(self.test_dir, "enc2.bin")
        encrypt_file(
            self.infile, enc, b"password", algorithm=EncryptionAlgorithm.AES_GCM, quiet=True
        )
        with open(enc, "rb") as f:
            header = f.read().split(b":", 1)[0]
        pt_hash = hashlib.sha256(self.plaintext).hexdigest().encode("ascii")
        self.assertNotIn(pt_hash, base64.b64decode(header))


if __name__ == "__main__":
    unittest.main()
