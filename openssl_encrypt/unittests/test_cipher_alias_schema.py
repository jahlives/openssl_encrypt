#!/usr/bin/env python3
"""
Regression tests: metadata schema cipher enums must accept every cipher name
the cipher registry accepts (canonical names AND aliases).

Bug: encrypting with a cipher *alias* (e.g. ``aes256-gcm`` for ``aes-256-gcm``)
persisted the raw alias into ``encryption.cipher_chain`` (cascade) or
``encryption.algorithm`` (single), but the metadata JSON schema only listed a
subset of names. Decryption then failed at schema validation:

    Schema validation failed at cipher_chain.0: 'aes256-gcm' is not one of [...]

so a file the tool had written could no longer be read.

Fix: the cipher enums in every metadata_v{N}_schema.json now include the full
registry name set (canonical + aliases). These tests pin that alignment so the
schema can never silently drift behind the registry again, while confirming the
schema still rejects genuinely unknown ciphers (no fail-open).
"""

import base64
import json
import unittest

from openssl_encrypt.modules.json_validator import (
    JSONValidationError,
    SecureJSONValidator,
)
from openssl_encrypt.modules.registry.cipher_registry import CipherRegistry

_B64 = base64.b64encode(b"x" * 32).decode("ascii")


def _cascade_metadata(version, cipher_chain):
    """Minimal schema-valid cascade metadata for the given format version."""
    return {
        "format_version": version,
        "mode": "symmetric",
        "derivation_config": {"salt": _B64},
        "encryption": {
            "cascade": True,
            "cipher_chain": cipher_chain,
            "hkdf_hash": "sha256",
            "cascade_salt": _B64,
            "layer_info": [
                {"cipher": c, "key_size": 32, "tag_size": 16} for c in cipher_chain
            ],
        },
    }


# Versions whose schema uses the cascade cipher_chain enum.
_CASCADE_VERSIONS = [8, 9, 10, 11]


class TestCipherAliasAcceptedBySchema(unittest.TestCase):
    def setUp(self):
        self.validator = SecureJSONValidator()
        self.names = CipherRegistry.default().list_names(include_aliases=True)

    def test_reported_alias_aes256_gcm_validates(self):
        """The exact reported failure: 'aes256-gcm' in a cascade chain."""
        meta = _cascade_metadata(9, ["aes256-gcm", "chacha20-poly1305"])
        # Must not raise.
        self.validator.validate_metadata(json.dumps(meta))

    def test_every_registry_cipher_name_validates_in_cascade(self):
        """Every canonical name and alias the registry accepts must validate."""
        for version in _CASCADE_VERSIONS:
            for name in self.names:
                meta = _cascade_metadata(version, [name, "chacha20-poly1305"])
                with self.subTest(version=version, cipher=name):
                    self.validator.validate_metadata(json.dumps(meta))

    def test_previously_valid_names_still_accepted(self):
        """No regression: names that worked before must still validate."""
        for chain in (
            ["aes-256-gcm", "chacha20-poly1305"],
            ["aes-gcm-siv", "aes-ocb3"],
            ["threefish-512", "threefish-1024"],
        ):
            self.validator.validate_metadata(json.dumps(_cascade_metadata(9, chain)))

    def test_unknown_cipher_still_rejected(self):
        """The enum must not fail open: a bogus cipher is still rejected."""
        meta = _cascade_metadata(9, ["totally-not-a-cipher", "aes-256-gcm"])
        with self.assertRaises(JSONValidationError):
            self.validator.validate_metadata(json.dumps(meta))


if __name__ == "__main__":
    unittest.main()
