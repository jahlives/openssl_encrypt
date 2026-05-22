"""
Tests for the CLI reconstruction feature of the ``info`` action.

When ``openssl_encrypt info <file>`` runs, the existing metadata
display is now followed by a reconstructed
``openssl_encrypt encrypt`` command line that would produce equivalent
encryption settings on a fresh file. Each test below exercises one
slice of the reconstructor.
"""

import unittest


class TestReconstructorScaffolding(unittest.TestCase):
    """The reconstructor helper is importable and produces sensible output."""

    def test_helper_importable(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        self.assertTrue(callable(_reconstruct_cli_from_metadata))

    def test_minimal_metadata_emits_encrypt_command(self):
        """Empty-ish metadata still produces a syntactically-valid command."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        result = _reconstruct_cli_from_metadata({})
        self.assertIsInstance(result, str)
        # Must start with the program + action so it's copy-paste-runnable.
        self.assertTrue(result.lstrip().startswith("openssl_encrypt encrypt"))


class TestReconstructCipher(unittest.TestCase):
    """Reconstruct --algorithm / --cascade from metadata['encryption']."""

    def test_symmetric_aes_gcm(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {"encryption": {"algorithm": "aes-gcm"}}
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--algorithm aes-gcm", out)
        self.assertNotIn("--cascade", out)

    def test_symmetric_chacha20(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {"encryption": {"algorithm": "chacha20-poly1305"}}
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--algorithm chacha20-poly1305", out)

    def test_cascade_two_layer(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {
            "encryption": {
                "cascade": True,
                "cipher_chain": ["aes-256-gcm", "chacha20-poly1305"],
            }
        }
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--cascade", out)
        self.assertIn("--algorithm aes-256-gcm,chacha20-poly1305", out)

    def test_cascade_three_layer(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {
            "encryption": {
                "cascade": True,
                "cipher_chain": [
                    "aes-256-gcm",
                    "chacha20-poly1305",
                    "threefish-512",
                ],
            }
        }
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn(
            "--algorithm aes-256-gcm,chacha20-poly1305,threefish-512", out
        )

    def test_missing_encryption_section_skipped(self):
        """No 'encryption' key in metadata → no algorithm/cascade in output."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata({})
        self.assertNotIn("--algorithm", out)
        self.assertNotIn("--cascade", out)


if __name__ == "__main__":
    unittest.main()
