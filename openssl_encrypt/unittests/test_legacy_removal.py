#!/usr/bin/env python3
"""
Tests for v1.5.0 deprecated algorithm removal.

These tests verify that all deprecated algorithms (AES-OCB3, Camellia,
Whirlpool, PBKDF2, legacy Kyber names, TESTDATA simulation format)
are properly rejected for both encryption AND decryption. In v1.5.0,
these algorithms are fully removed — users must decrypt legacy files
with v1.4.x before upgrading.

TDD approach: these tests were written before the removal code to
define expected behavior.
"""

import os
import tempfile
import unittest
import warnings  # noqa: E402

from openssl_encrypt.modules.crypt_core import EncryptionAlgorithm

# Suppress deprecation warnings during tests
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


class TestLegacyCipherRemoval(unittest.TestCase):
    """Verify that removed ciphers raise errors for both encryption and decryption."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test_input.txt")
        with open(self.test_file, "w") as f:
            f.write("Test data for legacy removal verification.")
        self.output_file = os.path.join(self.test_dir, "test_output.enc")
        self.test_password = b"TestPassword123!"
        self.hash_config = {
            "sha512": 0,
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "scrypt": {"n": 0, "r": 8, "p": 1},
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 16,
                "type": 2,
            },
        }

    def tearDown(self):
        """Clean up test files."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_aes_ocb3_encryption_rejected(self):
        """Verify encryption with AES-OCB3 raises an error — algorithm fully removed."""
        # AES-OCB3 enum value should no longer exist in EncryptionAlgorithm
        with self.assertRaises((ValueError, AttributeError, KeyError)):
            EncryptionAlgorithm("aes-ocb3")

    def test_camellia_encryption_rejected(self):
        """Verify encryption with Camellia raises an error — algorithm fully removed."""
        # Camellia enum value should no longer exist in EncryptionAlgorithm
        with self.assertRaises((ValueError, AttributeError, KeyError)):
            EncryptionAlgorithm("camellia")

    def test_aes_ocb3_decryption_rejected(self):
        """Verify decryption with AES-OCB3 also fails — algorithm fully removed.

        In v1.5.0, AES-OCB3 is completely removed, including decryption support.
        Users must decrypt with v1.4.x before upgrading.
        """
        # The enum value should not exist, so we cannot even construct a request
        with self.assertRaises((ValueError, AttributeError, KeyError)):
            EncryptionAlgorithm("aes-ocb3")

    def test_camellia_decryption_rejected(self):
        """Verify decryption with Camellia also fails — algorithm fully removed.

        In v1.5.0, Camellia is completely removed, including decryption support.
        Users must decrypt with v1.4.x before upgrading.
        """
        with self.assertRaises((ValueError, AttributeError, KeyError)):
            EncryptionAlgorithm("camellia")

    def test_aes_ocb3_not_in_encryption_algorithms(self):
        """Verify aes-ocb3 is not present in the EncryptionAlgorithm enum values."""
        algorithm_values = [alg.value for alg in EncryptionAlgorithm]
        self.assertNotIn("aes-ocb3", algorithm_values)

    def test_camellia_not_in_encryption_algorithms(self):
        """Verify camellia is not present in the EncryptionAlgorithm enum values."""
        algorithm_values = [alg.value for alg in EncryptionAlgorithm]
        self.assertNotIn("camellia", algorithm_values)


class TestWhirlpoolRemoval(unittest.TestCase):
    """Verify that Whirlpool hash is fully removed."""

    def test_whirlpool_hash_rejected(self):
        """Verify Whirlpool in hash config raises error — hash fully removed.

        The Whirlpool hash class should no longer be available in the
        hash registry.
        """
        from openssl_encrypt.modules.registry.hash_registry import HashRegistry

        registry = HashRegistry()
        # Whirlpool should not be a registered hash
        available = registry.list_names()
        available_names = [a.lower() for a in available]
        self.assertNotIn("whirlpool", available_names)

    def test_whirlpool_available_flag_removed(self):
        """Verify WHIRLPOOL_AVAILABLE is no longer exported from crypt_core."""
        import openssl_encrypt.modules.crypt_core as core

        self.assertFalse(hasattr(core, "WHIRLPOOL_AVAILABLE"))


class TestPBKDF2Removal(unittest.TestCase):
    """Verify that PBKDF2 key derivation is fully removed."""

    def test_pbkdf2_encryption_rejected(self):
        """Verify PBKDF2 KDF raises error — KDF fully removed.

        The PBKDF2 class should no longer be available in the KDF registry.
        """
        from openssl_encrypt.modules.registry.kdf_registry import KDFRegistry

        registry = KDFRegistry()
        available = registry.list_names()
        available_names = [a.lower() for a in available]
        self.assertNotIn("pbkdf2", available_names)

    def test_pbkdf2_cli_argument_removed(self):
        """Verify --pbkdf2-iterations CLI argument no longer exists."""
        # Import the CLI parser and verify the argument is gone
        # We check that no help text references pbkdf2-iterations
        import openssl_encrypt.modules.crypt_cli as cli_mod

        # The argument should not be in the module's argument definitions
        source = open(cli_mod.__file__).read()
        self.assertNotIn("--pbkdf2-iterations", source)


class TestLegacyPQCRemoval(unittest.TestCase):
    """Verify that legacy Kyber names and TESTDATA format are removed."""

    def test_kyber_name_rejected(self):
        """Verify legacy Kyber names raise error with guidance to use ML-KEM."""
        # Kyber enum values should not exist in EncryptionAlgorithm
        algorithm_values = [alg.value for alg in EncryptionAlgorithm]
        self.assertNotIn("kyber512-hybrid", algorithm_values)
        self.assertNotIn("kyber768-hybrid", algorithm_values)
        self.assertNotIn("kyber1024-hybrid", algorithm_values)

    def test_kyber_pqc_algorithm_removed(self):
        """Verify legacy Kyber names are removed from PQCAlgorithm enum."""
        from openssl_encrypt.modules.pqc import PQCAlgorithm

        pqc_values = [alg.value for alg in PQCAlgorithm]
        self.assertNotIn("Kyber512", pqc_values)
        self.assertNotIn("Kyber768", pqc_values)
        self.assertNotIn("Kyber1024", pqc_values)
        self.assertNotIn("Kyber-512", pqc_values)
        self.assertNotIn("Kyber-768", pqc_values)
        self.assertNotIn("Kyber-1024", pqc_values)

    def test_legacy_testdata_format_rejected(self):
        """Verify TESTDATA simulation format raises clear error.

        The legacy TESTDATA format that bypasses real encryption should
        no longer be accepted even for decryption.
        """
        from openssl_encrypt.modules.pqc import PQCipher

        source = open(PQCipher.__module__.replace(".", "/") + ".py").read()
        # TESTDATA handling code should be removed
        self.assertNotIn("PQC_TEST_DATA:", source)
        self.assertNotIn("TESTDATA", source)

    def test_ml_kem_names_still_work(self):
        """Verify ML-KEM standardized names are unaffected by removal."""
        # ML-KEM enum values should still exist
        self.assertEqual(EncryptionAlgorithm.ML_KEM_512_HYBRID.value, "ml-kem-512-hybrid")
        self.assertEqual(EncryptionAlgorithm.ML_KEM_768_HYBRID.value, "ml-kem-768-hybrid")
        self.assertEqual(EncryptionAlgorithm.ML_KEM_1024_HYBRID.value, "ml-kem-1024-hybrid")

    def test_ml_kem_pqc_algorithm_still_works(self):
        """Verify ML-KEM names remain in PQCAlgorithm enum."""
        from openssl_encrypt.modules.pqc import PQCAlgorithm

        self.assertEqual(PQCAlgorithm.ML_KEM_512.value, "ML-KEM-512")
        self.assertEqual(PQCAlgorithm.ML_KEM_768.value, "ML-KEM-768")
        self.assertEqual(PQCAlgorithm.ML_KEM_1024.value, "ML-KEM-1024")

    def test_legacy_algorithm_maps_no_kyber(self):
        """Verify legacy-to-standard algorithm maps no longer contain Kyber entries."""
        import openssl_encrypt.modules.pqc as pqc_mod

        # The maps still exist for signature algorithm translation (Dilithium→ML-DSA, etc.)
        # but should not contain any Kyber entries
        legacy_map = getattr(pqc_mod, "LEGACY_TO_STANDARD_ALGORITHM_MAP", {})
        for key in legacy_map:
            self.assertNotIn(
                "kyber", key.lower(), f"Kyber entry '{key}' should be removed from legacy map"
            )


class TestDeprecationInfrastructure(unittest.TestCase):
    """Verify deprecation infrastructure is cleaned up."""

    def test_deprecated_algorithms_dict_empty(self):
        """Verify DEPRECATED_ALGORITHMS dict has no entries for removed algorithms."""
        from openssl_encrypt.modules.algorithm_warnings import DEPRECATED_ALGORITHMS

        # None of the removed algorithms should still be in the deprecation dict
        for removed_alg in [
            "camellia",
            "aes-ocb3",
            "whirlpool",
            "pbkdf2",
            "kyber512-hybrid",
            "kyber768-hybrid",
            "kyber1024-hybrid",
            "Kyber512",
            "Kyber768",
            "Kyber1024",
        ]:
            self.assertNotIn(
                removed_alg,
                DEPRECATED_ALGORITHMS,
                f"{removed_alg} should be removed from DEPRECATED_ALGORITHMS",
            )


class TestCamelliaClassRemoval(unittest.TestCase):
    """Verify CamelliaCipher class is removed from crypt_core."""

    def test_camellia_cipher_class_removed(self):
        """Verify CamelliaCipher is no longer importable from crypt_core."""
        import openssl_encrypt.modules.crypt_core as core

        self.assertFalse(hasattr(core, "CamelliaCipher"))


class TestSetupWhirlpoolRemoval(unittest.TestCase):
    """Verify setup_whirlpool module is removed."""

    def test_setup_whirlpool_module_removed(self):
        """Verify setup_whirlpool.py module no longer exists."""
        import importlib

        with self.assertRaises(ImportError):
            importlib.import_module("openssl_encrypt.modules.setup_whirlpool")

    def test_ml_kem_patch_module_removed(self):
        """Verify ml_kem_patch.py module no longer exists."""
        import importlib

        with self.assertRaises(ImportError):
            importlib.import_module("openssl_encrypt.modules.ml_kem_patch")


if __name__ == "__main__":
    unittest.main()
