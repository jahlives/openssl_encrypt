"""Regression tests for GitLab #109 [PQC-9]: check_pqc_support fabricated lists.

On any error (or missing liboqs API), check_pqc_support 'helpfully'
returned a hardcoded list of ML-KEM/Kyber (and DSA) algorithm names,
masking a non-functional backend: callers testing membership would then
construct PQC objects that fail later in confusing ways. The function
must report the true (possibly empty) enabled-mechanism list.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules import pqc


class TestCheckPQCSupportHonest(unittest.TestCase):
    """check_pqc_support must never fabricate algorithm availability."""

    def test_error_path_returns_empty_list(self) -> None:
        """A broken oqs module must yield (False, None, []) — not a fake list."""

        class BrokenOQS:
            def __getattr__(self, name):
                raise RuntimeError("liboqs backend is broken")

        with mock.patch.object(pqc, "oqs", BrokenOQS()):
            available, version, algorithms = pqc.check_pqc_support(quiet=True)

        self.assertFalse(available)
        self.assertEqual(algorithms, [])

    def test_missing_kem_api_does_not_fabricate(self) -> None:
        """An oqs module without mechanism-listing APIs must yield no algorithms."""

        class MinimalOQS:
            pass  # no get_enabled/get_supported mechanisms at all

        with mock.patch.object(pqc, "oqs", MinimalOQS()):
            available, version, algorithms = pqc.check_pqc_support(quiet=True)

        self.assertEqual(
            algorithms,
            [],
            "algorithms were fabricated for a backend that lists none",
        )

    def test_real_backend_reports_real_mechanisms(self) -> None:
        """With a working liboqs, the list must reflect actual mechanisms."""
        if not pqc.LIBOQS_AVAILABLE:
            self.skipTest("liboqs not available")

        available, _version, algorithms = pqc.check_pqc_support(quiet=True)
        self.assertTrue(available)
        enabled = list(pqc.oqs.get_enabled_kem_mechanisms())
        for alg in enabled:
            self.assertIn(alg, algorithms)


if __name__ == "__main__":
    unittest.main()
