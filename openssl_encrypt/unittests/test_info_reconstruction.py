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


if __name__ == "__main__":
    unittest.main()
