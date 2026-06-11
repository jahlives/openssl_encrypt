"""
Regression test: ML-KEM hybrid encryption via the real CLI entry point.

The ml_kem_patch module rewrites ``--algorithm ml-kem-*-hybrid`` in sys.argv
to the legacy ``kyber*-hybrid`` names before crypt_cli.main() runs. The
v1.2.0 deprecation policy hard-blocks *encryption* with kyber names. The
exemption for "user actually typed the ML-KEM name" existed only for the
advisory warning, not for the hard block — so every CLI hybrid encryption
failed regardless of spelling:

    ERROR: Encryption with algorithm 'kyber768-hybrid' is no longer
    supported in version 1.2.0. Please use ml-kem-768-hybrid instead.

These tests drive the CLI through ``python -m openssl_encrypt.crypt`` in a
subprocess because the bug only manifests via the crypt.py entry point
(where ml_kem_patch monkey-patches main and rewrites sys.argv); calling
library functions directly bypasses the broken path.
"""

import os
import subprocess
import sys
import tempfile
import unittest

try:
    import oqs  # noqa: F401

    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False


def _run_cli(*cli_args: str) -> subprocess.CompletedProcess:
    """Run the real CLI entry point in a subprocess.

    Args:
        *cli_args: Arguments appended after ``python -m openssl_encrypt.crypt``.

    Returns:
        The completed process with captured stdout/stderr.
    """
    return subprocess.run(
        [sys.executable, "-m", "openssl_encrypt.crypt", *cli_args],
        capture_output=True,
        text=True,
        timeout=300,
    )


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestMlKemCliEncryption(unittest.TestCase):
    """ML-KEM hybrid names must be usable for encryption via the CLI."""

    def setUp(self):
        fd, self.plain = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("ml-kem cli regression payload\n")
        self.encrypted = self.plain + ".enc"
        self.decrypted = self.plain + ".dec"

    def tearDown(self):
        for path in (self.plain, self.encrypted, self.decrypted):
            if os.path.exists(path):
                os.remove(path)

    def test_mlkem_768_hybrid_cli_roundtrip(self):
        """Encrypting with ml-kem-768-hybrid via the CLI must work end-to-end."""
        result = _run_cli(
            "encrypt",
            "-i",
            self.plain,
            "-o",
            self.encrypted,
            "--password",
            "testpw123",
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-store-key",
            "-q",
        )
        self.assertEqual(
            result.returncode,
            0,
            f"encrypt failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertNotIn("no longer supported", result.stderr)
        self.assertTrue(os.path.getsize(self.encrypted) > 0)

        result = _run_cli(
            "decrypt",
            "-i",
            self.encrypted,
            "-o",
            self.decrypted,
            "--password",
            "testpw123",
            "-q",
        )
        self.assertEqual(
            result.returncode,
            0,
            f"decrypt failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        with open(self.plain) as f_in, open(self.decrypted) as f_out:
            self.assertEqual(f_in.read(), f_out.read())

    def test_legacy_kyber_name_still_blocked_for_encryption(self):
        """Typing the deprecated kyber name directly must remain blocked."""
        result = _run_cli(
            "encrypt",
            "-i",
            self.plain,
            "-o",
            self.encrypted,
            "--password",
            "testpw123",
            "--algorithm",
            "kyber768-hybrid",
            "--pqc-store-key",
            "-q",
        )
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("kyber768-hybrid", combined)
        self.assertFalse(os.path.exists(self.encrypted))


if __name__ == "__main__":
    unittest.main()
