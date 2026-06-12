#!/usr/bin/env python3
"""
Cross-device HSM decryption tests.

YubiKey and OnlyKey speak the same HMAC-SHA1 challenge-response wire
protocol, so a 20-byte secret loaded identically on both devices yields
identical peppers. Files encrypted with one device must therefore be
decryptable with the other when the user explicitly selects the plugin
via --hsm (see the cross-device compatibility promise in
plugins/hsm/onlykey_challenge_response/__init__.py).

Regression tests for two bugs that broke this:

1. decrypt_file rejected any CLI-provided HSM plugin whose plugin_id did
   not exactly match the one stored in file metadata, making cross-device
   decryption impossible.
2. --hsm-slot was printed but never passed into decrypt_file, so the slot
   stored in metadata always won and a device with the secret in a
   different slot was challenged on the wrong slot.
"""

import inspect
import unittest

from openssl_encrypt.modules.crypt_core import (
    HSM_COMPATIBLE_FAMILIES,
    _hsm_plugins_compatible,
    _resolve_hsm_slot,
    decrypt_file,
)


class TestHsmPluginCompatibility(unittest.TestCase):
    """Plugin-id validation must accept protocol-compatible families."""

    def test_identical_plugin_ids_are_compatible(self):
        self.assertTrue(_hsm_plugins_compatible("yubikey_hsm", "yubikey_hsm"))
        self.assertTrue(_hsm_plugins_compatible("onlykey_hsm", "onlykey_hsm"))

    def test_onlykey_can_decrypt_yubikey_files(self):
        """File metadata says yubikey_hsm, user passes --hsm onlykey."""
        self.assertTrue(_hsm_plugins_compatible("onlykey_hsm", "yubikey_hsm"))

    def test_yubikey_can_decrypt_onlykey_files(self):
        """File metadata says onlykey_hsm, user passes --hsm yubikey."""
        self.assertTrue(_hsm_plugins_compatible("yubikey_hsm", "onlykey_hsm"))

    def test_unrelated_plugins_are_rejected(self):
        """FIDO2 derives peppers differently — never interchangeable."""
        self.assertFalse(_hsm_plugins_compatible("fido2_hsm", "yubikey_hsm"))
        self.assertFalse(_hsm_plugins_compatible("yubikey_hsm", "fido2_hsm"))
        self.assertFalse(_hsm_plugins_compatible("fido2_hsm", "onlykey_hsm"))

    def test_unknown_plugin_ids_are_rejected(self):
        self.assertFalse(_hsm_plugins_compatible("evil_hsm", "yubikey_hsm"))
        self.assertFalse(_hsm_plugins_compatible("", "yubikey_hsm"))

    def test_family_table_contains_hmac_sha1_cr_family(self):
        """The interchangeable family is exactly {yubikey_hsm, onlykey_hsm}."""
        self.assertIn(frozenset({"yubikey_hsm", "onlykey_hsm"}), HSM_COMPATIBLE_FAMILIES)
        for family in HSM_COMPATIBLE_FAMILIES:
            self.assertNotIn("fido2_hsm", family)


class TestHsmSlotResolution(unittest.TestCase):
    """Explicit --hsm-slot must take precedence over the slot in metadata."""

    def test_cli_slot_overrides_stored_slot(self):
        self.assertEqual(_resolve_hsm_slot(1, {"slot": 2}), 1)

    def test_stored_slot_used_when_no_cli_slot(self):
        self.assertEqual(_resolve_hsm_slot(None, {"slot": 2}), 2)

    def test_no_slot_anywhere_returns_none(self):
        self.assertIsNone(_resolve_hsm_slot(None, {}))

    def test_cli_slot_used_when_metadata_has_none(self):
        self.assertEqual(_resolve_hsm_slot(3, {}), 3)


class TestDecryptFileAcceptsHsmSlot(unittest.TestCase):
    """decrypt_file must accept the CLI slot so it can reach the plugin."""

    def test_decrypt_file_signature_has_hsm_slot(self):
        params = inspect.signature(decrypt_file).parameters
        self.assertIn(
            "hsm_slot",
            params,
            msg="decrypt_file() must accept hsm_slot so --hsm-slot reaches "
            "the HSM plugin during decryption.",
        )
        self.assertIsNone(params["hsm_slot"].default)

    def test_cli_decrypt_paths_forward_hsm_slot(self):
        """Every decrypt/rekey call in the CLI that passes an HSM plugin
        must also forward the user's --hsm-slot."""
        import re

        import openssl_encrypt.modules.crypt_cli as crypt_cli

        source = inspect.getsource(crypt_cli)
        checked = 0
        for match in re.finditer(r"hsm_plugin=hsm_plugin_instance,", source):
            preceding = source[max(0, match.start() - 600) : match.start()]
            if "decrypt_file(" in preceding or "_rekey_file(" in preceding:
                following = source[match.end() : match.end() + 120]
                self.assertIn(
                    'hsm_slot=getattr(args, "hsm_slot", None)',
                    following,
                    msg="decrypt_file/_rekey_file call passing hsm_plugin "
                    "must also forward hsm_slot from CLI args.",
                )
                checked += 1
        self.assertGreaterEqual(
            checked, 4, msg="Expected 3 decrypt_file sites + 1 rekey site in the CLI."
        )


if __name__ == "__main__":
    unittest.main()
