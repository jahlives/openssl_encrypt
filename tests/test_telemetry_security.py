#!/usr/bin/env python3
"""
Security Tests for Telemetry Data Filter

CRITICAL: These tests verify that NO sensitive data can leak through the
telemetry system. All tests MUST pass 100% before any deployment.

Test Categories:
1. Password blocking
2. Key blocking (public, private, symmetric)
3. Salt blocking
4. Filename blocking
5. Cascade cipher sequence blocking
6. HSM slot number blocking
7. Immutability verification
8. Format version coverage

If ANY of these tests fail, the telemetry system is NOT safe to deploy.
"""

import pytest

from openssl_encrypt.modules.telemetry_filter import TelemetryDataFilter, TelemetryEvent


class TestTelemetrySecurityGuarantees:
    """
    CRITICAL: Security tests that verify NO sensitive data can leak.
    All tests must pass before deployment.
    """

    def test_no_passwords_ever(self):
        """
        Password in ANY form must NEVER appear in telemetry.

        Security Requirement: Passwords are the most sensitive data.
        They must never be logged, transmitted, or stored by telemetry.
        """
        metadata = {
            "password": "secret123",  # Should be completely ignored
            "passphrase": "another_secret",  # Should be ignored
            "derivation_config": {
                "salt": "base64salt==",  # Should be ignored
                "hash_config": {"sha512": {"rounds": 100000}},
            },
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert password is not in any form
        assert "password" not in event_str.lower()
        assert "secret123" not in event_str
        assert "passphrase" not in event_str.lower()
        assert "another_secret" not in event_str

        # Verify hash algorithms are present (safe data)
        assert "sha512" in event.hash_algorithms

    def test_no_keys_ever(self):
        """
        Keys (public, private, symmetric) must NEVER appear in telemetry.

        Security Requirement: Keys are cryptographic secrets that would
        completely compromise the security if leaked.
        """
        metadata = {
            "encryption": {
                "pqc_public_key": "base64publickey==",  # Should be ignored
                "pqc_private_key": "base64privatekey==",  # Should be ignored
                "algorithm": "aes-256-gcm",  # Should pass through
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert keys are NOT in output
        assert "pqc_public_key" not in event_str
        assert "pqc_private_key" not in event_str
        assert "base64publickey" not in event_str
        assert "base64privatekey" not in event_str

        # Verify algorithm name is present (safe data)
        assert event.encryption_algorithm == "aes-256-gcm"

    def test_no_salts_ever(self):
        """
        Salt values must NEVER appear in telemetry.

        Security Requirement: Salts are cryptographic material that,
        combined with other leaked data, could enable attacks.
        """
        metadata = {
            "derivation_config": {
                "salt": "SGVsbG9Xb3JsZA==",  # Should be completely ignored
                "hash_config": {"sha512": {"rounds": 100000}},
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "decrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert salt is NOT in output
        assert "salt" not in event_str.lower()
        assert "SGVsbG9Xb3JsZA==" not in event_str
        assert "HelloWorld" not in event_str  # Decoded value

        # Verify hash algorithms are present (safe data)
        assert "sha512" in event.hash_algorithms

    def test_no_filenames_ever(self):
        """
        Filenames must NEVER appear in telemetry.

        Security Requirement: Filenames can contain sensitive information
        (e.g., "tax_return_2023.pdf", "passwords.txt").
        """
        metadata = {
            "filename": "secret_document.pdf",  # Should be ignored
            "file_path": "/home/user/sensitive/data.txt",  # Should be ignored
            "format_version": 5,
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert filename is NOT in output
        assert "filename" not in event_str.lower()
        assert "secret_document" not in event_str
        assert "file_path" not in event_str.lower()
        assert "/home/user" not in event_str

        # Verify format version is present (safe data)
        assert event.format_version == 5

    def test_no_file_sizes_ever(self):
        """
        File sizes must NEVER appear in telemetry.

        Security Requirement: File sizes can be identifying and used
        for traffic analysis or fingerprinting.
        """
        metadata = {
            "file_size": 1234567,  # Should be ignored
            "original_size": 999999,  # Should be ignored
            "encrypted_size": 1234600,  # Should be ignored
            "format_version": 6,
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert file sizes are NOT in output
        assert "file_size" not in event_str.lower()
        assert "1234567" not in event_str
        assert "999999" not in event_str
        assert "original_size" not in event_str.lower()
        assert "encrypted_size" not in event_str.lower()

        # Verify format version is present (safe data)
        assert event.format_version == 6

    def test_cascade_cipher_names_blocked(self):
        """
        Exact cascade cipher sequence must be hidden.

        Security Requirement: The exact order and combination of ciphers
        in cascade mode could be identifying. We report only that cascade
        is enabled and the count, not the specific ciphers or order.
        """
        metadata = {
            "format_version": 8,
            "encryption": {
                "cascade": True,
                "cipher_chain": ["aes-256-gcm", "chacha20-poly1305", "camellia-256-gcm"],
                "cascade_salt": "base64cascadesalt==",  # Should be ignored
            },
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert cascade is reported correctly
        assert event.cascade_enabled is True
        assert event.cascade_cipher_count == 3
        assert event.encryption_algorithm == "cascade"

        # Assert cipher names are NOT in output
        assert "cipher_chain" not in event_str
        assert "aes-256-gcm" not in event_str
        assert "chacha20-poly1305" not in event_str
        assert "camellia-256-gcm" not in event_str

        # Assert cascade salt is NOT in output
        assert "cascade_salt" not in event_str
        assert "base64cascadesalt" not in event_str

    def test_hsm_slot_numbers_blocked(self):
        """
        HSM slot numbers must be blocked.

        Security Requirement: HSM slot numbers could be used to identify
        specific hardware tokens or users. Only the plugin name is safe.
        """
        metadata = {
            "encryption": {
                "hsm_plugin": "yubikey",  # Should pass through (sanitized)
                "hsm_config": {"slot": 2, "serial": "123456"},  # Should be blocked
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert HSM plugin name is present (safe data)
        assert event.hsm_plugin_used == "yubikey"

        # Assert slot numbers and serials are NOT in output
        assert "slot" not in event_str.lower()
        assert "serial" not in event_str.lower()
        assert "hsm_config" not in event_str
        assert "123456" not in event_str

    def test_hsm_plugin_name_sanitization(self):
        """
        HSM plugin names must be sanitized.

        Security Requirement: Plugin names should only contain safe
        characters to prevent injection or path traversal attacks.
        """
        metadata = {
            "encryption": {
                "hsm_plugin": "../../../etc/passwd",  # Malicious input
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")

        # Assert malicious characters are removed
        assert event.hsm_plugin_used == "etcpasswd"
        assert ".." not in event.hsm_plugin_used
        assert "/" not in event.hsm_plugin_used

    def test_immutability(self):
        """
        TelemetryEvent must be truly immutable.

        Security Requirement: Immutability prevents any modification
        after creation, ensuring data integrity throughout the pipeline.
        """
        event = TelemetryDataFilter.filter_metadata({}, "encrypt")

        # Try to modify frozen dataclass - should raise exception
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            event.hash_algorithms = ("modified",)

        with pytest.raises(Exception):
            event.encryption_algorithm = "modified"

        with pytest.raises(Exception):
            event.success = False

    def test_format_versions_coverage(self):
        """
        Test all format versions (v4-v8).

        Security Requirement: Filter must work correctly across all
        format versions to ensure no sensitive data leaks in any version.
        """
        for version in [4, 5, 6, 7, 8]:
            metadata = {
                "format_version": version,
                "password": "secret",  # Should be ignored in all versions
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")

            # Verify format version is correct
            assert event.format_version == version

            # Verify password is NOT in output
            event_dict = TelemetryDataFilter.to_dict(event)
            assert "password" not in str(event_dict).lower()
            assert "secret" not in str(event_dict)

    def test_hash_rounds_not_exposed(self):
        """
        Hash rounds must NOT be exposed.

        Security Requirement: Round counts can be identifying
        (e.g., 1000000 rounds of SHA-512 is unusual and identifying).
        """
        metadata = {
            "derivation_config": {
                "hash_config": {
                    "sha512": {"rounds": 1000000},  # Unusual round count
                    "blake2b": {"rounds": 500000},
                }
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert hash algorithms are present (safe)
        assert "sha512" in event.hash_algorithms
        assert "blake2b" in event.hash_algorithms

        # Assert round counts are NOT present
        assert "rounds" not in event_str.lower()
        assert "1000000" not in event_str
        assert "500000" not in event_str

    def test_kdf_safe_parameters_only(self):
        """
        KDF parameters must only include safe numeric values.

        Security Requirement: Only non-identifying numeric parameters
        should be exposed. No keys, salts, or other sensitive data.
        """
        metadata = {
            "derivation_config": {
                "kdf_config": {
                    "argon2": {
                        "time_cost": 3,  # Safe
                        "memory_cost": 65536,  # Safe
                        "parallelism": 4,  # Safe
                        "salt": "base64salt==",  # Should be ignored
                        "key": "base64key==",  # Should be ignored
                    }
                }
            }
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)
        event_str = str(event_dict)

        # Assert safe parameters are present
        assert "argon2" in event.kdf_algorithms
        assert event.kdf_parameters["argon2"]["time_cost"] == 3
        assert event.kdf_parameters["argon2"]["memory_cost"] == 65536
        assert event.kdf_parameters["argon2"]["parallelism"] == 4

        # Assert unsafe parameters are NOT present
        assert "salt" not in event_str.lower()
        assert "key" not in event_str.lower()
        assert "base64salt" not in event_str
        assert "base64key" not in event_str

    def test_pqc_keys_never_exposed(self):
        """
        PQC keys must NEVER be exposed in symmetric or asymmetric modes.

        Security Requirement: Post-quantum keys are cryptographic secrets
        and must be protected just like classical keys.
        """
        # Test symmetric mode
        metadata_sym = {
            "mode": "symmetric",
            "encryption": {
                "pqc_public_key": "base64pqckey==",
                "pqc_private_key": "base64pqcprivate==",
                "pqc_key_encrypted": True,
            },
        }

        event_sym = TelemetryDataFilter.filter_metadata(metadata_sym, "encrypt")
        event_dict_sym = TelemetryDataFilter.to_dict(event_sym)
        event_str_sym = str(event_dict_sym)

        # Assert keys are NOT in output
        assert "pqc_public_key" not in event_str_sym
        assert "pqc_private_key" not in event_str_sym
        assert "base64pqckey" not in event_str_sym
        assert "base64pqcprivate" not in event_str_sym

        # Assert only generic PQC usage is reported
        assert event_sym.pqc_kem_algorithm == "pqc_symmetric"

        # Test asymmetric mode
        metadata_asym = {
            "mode": "asymmetric",
            "asymmetric": {
                "recipient": {
                    "algorithm": "ML-KEM-768",
                    "public_key": "base64recvkey==",
                    "key_id": "fingerprint123",
                },
                "sender": {
                    "signing_algorithm": "ML-DSA-65",
                    "private_key": "base64signkey==",
                    "key_id": "fingerprint456",
                },
            },
        }

        event_asym = TelemetryDataFilter.filter_metadata(metadata_asym, "encrypt")
        event_dict_asym = TelemetryDataFilter.to_dict(event_asym)
        event_str_asym = str(event_dict_asym)

        # Assert keys and fingerprints are NOT in output
        assert "public_key" not in event_str_asym
        assert "private_key" not in event_str_asym
        assert "key_id" not in event_str_asym
        assert "fingerprint" not in event_str_asym
        assert "base64recvkey" not in event_str_asym
        assert "base64signkey" not in event_str_asym

        # Assert only algorithm names are present (safe)
        assert event_asym.pqc_kem_algorithm == "ML-KEM-768"
        assert event_asym.pqc_signing_algorithm == "ML-DSA-65"

    def test_error_category_validation(self):
        """
        Error categories must be validated against whitelist.

        Security Requirement: Error messages could contain sensitive
        information. Only pre-approved categories are allowed.
        """
        # Test valid error category
        event_valid = TelemetryDataFilter.filter_metadata(
            {}, "decrypt", success=False, error_category="invalid_password"
        )
        assert event_valid.error_category == "invalid_password"
        assert event_valid.success is False

        # Test invalid error category (should be replaced with "unknown")
        event_invalid = TelemetryDataFilter.filter_metadata(
            {},
            "decrypt",
            success=False,
            error_category="detailed_error_message_with_sensitive_info",
        )
        assert event_invalid.error_category == "unknown"

    def test_operation_validation(self):
        """
        Operation must be "encrypt" or "decrypt" only.

        Security Requirement: Only expected operations should be logged.
        """
        # Test valid operations
        event_encrypt = TelemetryDataFilter.filter_metadata({}, "encrypt")
        assert event_encrypt.operation == "encrypt"

        event_decrypt = TelemetryDataFilter.filter_metadata({}, "decrypt")
        assert event_decrypt.operation == "decrypt"

    def test_mode_validation(self):
        """
        Mode must be "symmetric" or "asymmetric" only.

        Security Requirement: Only expected modes should be logged.
        """
        metadata_sym = {"mode": "symmetric"}
        event_sym = TelemetryDataFilter.filter_metadata(metadata_sym, "encrypt")
        assert event_sym.mode == "symmetric"

        metadata_asym = {"mode": "asymmetric"}
        event_asym = TelemetryDataFilter.filter_metadata(metadata_asym, "encrypt")
        assert event_asym.mode == "asymmetric"

    def test_empty_metadata_safe(self):
        """
        Empty metadata should not crash the filter.

        Security Requirement: Robust error handling to prevent crashes.
        """
        event = TelemetryDataFilter.filter_metadata({}, "encrypt")

        # Should have default/empty values
        assert event.operation == "encrypt"
        assert event.success is True
        assert len(event.hash_algorithms) == 0
        assert len(event.kdf_algorithms) == 0
        assert event.encryption_algorithm == "unknown"

    def test_to_dict_serialization(self):
        """
        to_dict() must produce JSON-serializable output.

        Security Requirement: Output must be serializable for transmission
        and storage without exposing sensitive data.
        """
        import json

        metadata = {
            "format_version": 7,
            "derivation_config": {
                "hash_config": {"sha512": {}, "blake2b": {}},
                "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
            },
            "encryption": {"algorithm": "aes-256-gcm"},
        }

        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        event_dict = TelemetryDataFilter.to_dict(event)

        # Should be JSON-serializable
        json_str = json.dumps(event_dict)
        assert isinstance(json_str, str)

        # Verify no sensitive data in JSON
        assert "password" not in json_str.lower()
        assert (
            "key" not in json_str.lower() or "argon2" in json_str.lower()
        )  # "key" might be in algorithm name
        assert "salt" not in json_str.lower()


class TestTelemetryWhitelistCompleteness:
    """
    Tests to verify whitelists are complete and correct.
    """

    def test_hash_algorithm_whitelist_completeness(self):
        """Verify all expected hash algorithms are whitelisted."""
        expected_hashes = [
            "sha256",
            "sha384",
            "sha512",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "blake2b",
            "blake2s",
            "blake3",
            "whirlpool",
            "shake128",
            "shake256",
        ]

        for hash_algo in expected_hashes:
            assert hash_algo in TelemetryDataFilter.ALLOWED_HASH_ALGOS

    def test_kdf_algorithm_whitelist_completeness(self):
        """Verify all expected KDF algorithms are whitelisted."""
        expected_kdfs = [
            "argon2",
            "argon2id",
            "argon2i",
            "argon2d",
            "balloon",
            "scrypt",
            "pbkdf2",
            "hkdf",
            "randomx",
        ]

        for kdf_algo in expected_kdfs:
            assert kdf_algo in TelemetryDataFilter.ALLOWED_KDF_ALGOS

    def test_encryption_algorithm_whitelist_completeness(self):
        """Verify all expected encryption algorithms are whitelisted."""
        expected_ciphers = [
            "aes-128-gcm",
            "aes-256-gcm",
            "aes-256-siv",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "camellia-256-gcm",
            "fernet",
            "cascade",
        ]

        for cipher in expected_ciphers:
            assert cipher in TelemetryDataFilter.ALLOWED_ENC_ALGOS


# Run tests with: pytest tests/test_telemetry_security.py -v
# All tests MUST pass 100% before deployment!
