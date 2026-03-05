#!/usr/bin/env python3
"""
Integration tests for Shamir's Secret Sharing with encrypt/decrypt.

Tests the full workflow: encrypt file → split password → combine shares → decrypt.
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
)
from openssl_encrypt.modules.secret_sharing import (
    Share,
    combine_shares,
    split_secret,
)


class TestSplitSecretCLIWorkflow(unittest.TestCase):
    """Test the full encrypt → split → combine → decrypt workflow."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"integration_test_password_42!"
        self.test_content = b"Top secret information that must be split."
        self.test_file = os.path.join(self.temp_dir, "secret.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _encrypt(self, algorithm=EncryptionAlgorithm.AES_GCM):
        """Helper: encrypt test file."""
        enc_file = os.path.join(self.temp_dir, "secret.enc")
        encrypt_file(
            input_file=self.test_file,
            output_file=enc_file,
            password=self.password,
            algorithm=algorithm,
            quiet=True,
        )
        return enc_file

    def test_2_of_3_encrypt_split_combine_decrypt(self):
        """Full 2-of-3 workflow: encrypt, split, combine 2, decrypt."""
        enc_file = self._encrypt()

        # Split password into 3 shares, threshold 2
        shares = split_secret(self.password, threshold=2, num_shares=3)

        # Write shares to files
        share_files = []
        for share in shares:
            fp = os.path.join(self.temp_dir, f"share_{share.metadata.share_index}.json")
            share.to_file(fp)
            share_files.append(fp)

        # Read back 2 shares and combine
        loaded = [Share.from_file(share_files[0]), Share.from_file(share_files[2])]
        recovered_password = combine_shares(loaded)

        # Decrypt with recovered password
        dec_file = os.path.join(self.temp_dir, "recovered.txt")
        decrypt_file(
            input_file=enc_file,
            output_file=dec_file,
            password=recovered_password,
            quiet=True,
        )

        with open(dec_file, "rb") as f:
            recovered_content = f.read()
        self.assertEqual(recovered_content, self.test_content)

    def test_3_of_5_with_fernet(self):
        """3-of-5 workflow with Fernet algorithm."""
        enc_file = os.path.join(self.temp_dir, "fernet.enc")
        encrypt_file(
            input_file=self.test_file,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.FERNET,
            quiet=True,
        )

        shares = split_secret(self.password, threshold=3, num_shares=5)
        recovered = combine_shares(shares[1:4])  # Shares 2, 3, 4

        dec_file = os.path.join(self.temp_dir, "fernet_dec.txt")
        decrypt_file(
            input_file=enc_file,
            output_file=dec_file,
            password=recovered,
            quiet=True,
        )

        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_3_of_5_with_chacha20(self):
        """3-of-5 workflow with ChaCha20-Poly1305."""
        enc_file = os.path.join(self.temp_dir, "chacha.enc")
        encrypt_file(
            input_file=self.test_file,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.CHACHA20_POLY1305,
            quiet=True,
        )

        shares = split_secret(self.password, threshold=3, num_shares=5)
        recovered = combine_shares(shares[:3])

        dec_file = os.path.join(self.temp_dir, "chacha_dec.txt")
        decrypt_file(
            input_file=enc_file,
            output_file=dec_file,
            password=recovered,
            quiet=True,
        )

        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_wrong_shares_fail_decrypt(self):
        """Shares from different passwords don't decrypt the file."""
        enc_file = self._encrypt()

        # Split a DIFFERENT password
        wrong_password = b"completely_wrong_password"
        shares = split_secret(wrong_password, threshold=2, num_shares=3)
        recovered = combine_shares(shares[:2])

        self.assertNotEqual(recovered, self.password)

        # Decryption should fail
        dec_file = os.path.join(self.temp_dir, "wrong.txt")
        with self.assertRaises(Exception):
            decrypt_file(
                input_file=enc_file,
                output_file=dec_file,
                password=recovered,
                quiet=True,
            )

    def test_binary_password_roundtrip(self):
        """Binary (non-UTF8) password survives split/combine."""
        binary_password = os.urandom(32)
        enc_file = os.path.join(self.temp_dir, "binary.enc")
        encrypt_file(
            input_file=self.test_file,
            output_file=enc_file,
            password=binary_password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        shares = split_secret(binary_password, threshold=2, num_shares=3)

        # Write/read through files
        fps = []
        for s in shares:
            fp = os.path.join(self.temp_dir, f"bin_share_{s.metadata.share_index}.json")
            s.to_file(fp)
            fps.append(fp)

        loaded = [Share.from_file(fps[0]), Share.from_file(fps[1])]
        recovered = combine_shares(loaded)
        self.assertEqual(recovered, binary_password)

        dec_file = os.path.join(self.temp_dir, "binary_dec.txt")
        decrypt_file(
            input_file=enc_file,
            output_file=dec_file,
            password=recovered,
            quiet=True,
        )

        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


if __name__ == "__main__":
    unittest.main()
