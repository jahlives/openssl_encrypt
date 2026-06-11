#!/usr/bin/env python3
"""
Regression tests for H4: production keystore integrity protection.

The v1 keystore was plaintext JSON where only the per-key ``private_key``
fields were encrypted. Nothing authenticated the structure, so anyone with
write access to the file could swap a stored ``public_key`` for their own,
flip ``dual_encryption`` flags, change ``defaults`` or delete entries without
detection. The v2 format authenticates the whole structure with an
HMAC-SHA256 over canonical JSON, keyed by a subkey derived from the master
key. See SECURITY_REVIEW_FINDINGS.md (H4).
"""

import base64
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_errors import KeystoreError, KeystorePasswordError
from openssl_encrypt.modules.keystore_cli import KeystoreSecurityLevel, PQCKeystore


class TestKeystoreIntegrityH4(unittest.TestCase):
    """Whole-keystore integrity protection (v2 format, finding H4)."""

    def setUp(self):
        """Set up a temporary directory and a keystore with one key."""
        self.test_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.test_dir, "test_keystore.pqc")
        self.keystore_password = "TestKeystorePassword123!"
        # add_key stores opaque bytes, so no real PQC keypair (liboqs) is needed
        self.public_key = os.urandom(64)
        self.private_key = os.urandom(64)

    def tearDown(self):
        """Remove the temporary directory."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    def _create_keystore_with_key(self) -> str:
        """Create a keystore containing one master-password key, return key id."""
        keystore = PQCKeystore(self.keystore_path)
        keystore.create_keystore(self.keystore_password)
        key_id = keystore.add_key(
            algorithm="ML-KEM-768",
            public_key=self.public_key,
            private_key=self.private_key,
            description="integrity test key",
        )
        keystore.save_keystore()
        keystore.close()
        return key_id

    def _read_raw(self) -> dict:
        """Read the keystore file as plain JSON (attacker's view)."""
        with open(self.keystore_path, "r") as f:
            return json.load(f)

    def _write_raw(self, data: dict) -> None:
        """Write tampered JSON directly to the keystore file (attacker's write)."""
        with open(self.keystore_path, "w") as f:
            json.dump(data, f, indent=2)

    def _downgrade_to_v1(self) -> None:
        """Rewrite the on-disk keystore as a legacy v1 file (no integrity field)."""
        data = self._read_raw()
        data["version"] = 1
        data.pop("integrity", None)
        self._write_raw(data)

    def _assert_load_raises_integrity_error(self):
        """Assert loading the keystore fails with KeystoreIntegrityError."""
        from openssl_encrypt.modules.crypt_errors import KeystoreIntegrityError

        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystoreIntegrityError):
            keystore.load_keystore(self.keystore_password)

    # ------------------------------------------------------------------ #
    # new format
    # ------------------------------------------------------------------ #

    def test_new_keystore_is_v2_with_integrity_field(self):
        """A newly created keystore is version 2 and carries an HMAC."""
        self._create_keystore_with_key()
        data = self._read_raw()
        self.assertEqual(data["version"], 2)
        self.assertIn("integrity", data)
        self.assertEqual(data["integrity"]["alg"], "HMAC-SHA256")
        # MAC must be valid base64 of a 32-byte SHA-256 digest
        mac = base64.b64decode(data["integrity"]["mac"])
        self.assertEqual(len(mac), 32)

    def test_v2_keystore_roundtrip(self):
        """An untampered v2 keystore loads and returns the stored key."""
        key_id = self._create_keystore_with_key()
        keystore = PQCKeystore(self.keystore_path)
        keystore.load_keystore(self.keystore_password)
        public_key, private_key = keystore.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        self.assertEqual(private_key, self.private_key)
        keystore.close()

    def test_mutating_operations_keep_integrity_valid(self):
        """add/set-default/remove/change-password all re-MAC the store."""
        key_id = self._create_keystore_with_key()

        keystore = PQCKeystore(self.keystore_path)
        keystore.load_keystore(self.keystore_password)
        second_id = keystore.add_key(
            algorithm="ML-KEM-1024",
            public_key=os.urandom(64),
            private_key=os.urandom(64),
        )
        keystore.save_keystore()
        keystore.set_default_key(second_id)
        keystore.remove_key(key_id)
        keystore.save_keystore()
        new_password = "NewKeystorePassword456!"
        keystore.change_master_password(self.keystore_password, new_password)
        keystore.close()

        reloaded = PQCKeystore(self.keystore_path)
        reloaded.load_keystore(new_password)
        self.assertIn(second_id, reloaded.keystore_data["keys"])
        self.assertNotIn(key_id, reloaded.keystore_data["keys"])
        reloaded.close()

    def test_save_without_master_key_fails(self):
        """Saving without a master key must fail — the MAC could not be computed."""
        keystore = PQCKeystore(self.keystore_path)
        keystore.keystore_data = {"version": 2, "keys": {}}
        keystore.master_key = None
        with self.assertRaises(KeystoreError):
            keystore.save_keystore()

    # ------------------------------------------------------------------ #
    # tamper detection (the H4 attacks)
    # ------------------------------------------------------------------ #

    def test_tampered_public_key_rejected(self):
        """Swapping a stored public key for the attacker's must be detected."""
        key_id = self._create_keystore_with_key()
        data = self._read_raw()
        attacker_pub = base64.b64encode(os.urandom(64)).decode("utf-8")
        data["keys"][key_id]["public_key"] = attacker_pub
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_tampered_algorithm_rejected(self):
        """Changing a key's declared algorithm must be detected."""
        key_id = self._create_keystore_with_key()
        data = self._read_raw()
        data["keys"][key_id]["algorithm"] = "ML-KEM-1024"
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_deleted_key_entry_rejected(self):
        """Deleting a key entry from the file must be detected."""
        key_id = self._create_keystore_with_key()
        data = self._read_raw()
        del data["keys"][key_id]
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_tampered_dual_encryption_flag_rejected(self):
        """Stripping/adding dual-encryption flags must be detected."""
        key_id = self._create_keystore_with_key()
        data = self._read_raw()
        data["keys"][key_id]["dual_encryption"] = True
        data["keys"][key_id]["dual_encryption_salt"] = base64.b64encode(os.urandom(16)).decode(
            "utf-8"
        )
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_tampered_defaults_rejected(self):
        """Repointing the per-algorithm default key must be detected."""
        self._create_keystore_with_key()

        keystore = PQCKeystore(self.keystore_path)
        keystore.load_keystore(self.keystore_password)
        second_id = keystore.add_key(
            algorithm="ML-KEM-768",
            public_key=os.urandom(64),
            private_key=os.urandom(64),
        )
        first_id = [k for k in keystore.keystore_data["keys"] if k != second_id][0]
        keystore.set_default_key(first_id)
        keystore.close()

        data = self._read_raw()
        data["defaults"]["ML-KEM-768"] = second_id
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_stripped_integrity_field_rejected(self):
        """Removing the integrity field from a v2 store must be detected."""
        self._create_keystore_with_key()
        data = self._read_raw()
        del data["integrity"]
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_unknown_integrity_alg_rejected(self):
        """An unrecognized MAC algorithm must fail closed, not be skipped.

        The JSON schema rejects unknown alg values as corruption before the
        MAC check runs; either error is acceptable as long as loading fails.
        """
        self._create_keystore_with_key()
        data = self._read_raw()
        data["integrity"]["alg"] = "CRC32"
        self._write_raw(data)
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystoreError):
            keystore.load_keystore(self.keystore_password)

    def test_swapped_key_entries_rejected(self):
        """Swapping the entries of two key ids must be detected."""
        key_id = self._create_keystore_with_key()
        keystore = PQCKeystore(self.keystore_path)
        keystore.load_keystore(self.keystore_password)
        second_id = keystore.add_key(
            algorithm="ML-KEM-768",
            public_key=os.urandom(64),
            private_key=os.urandom(64),
        )
        keystore.save_keystore()
        keystore.close()

        data = self._read_raw()
        data["keys"][key_id], data["keys"][second_id] = (
            data["keys"][second_id],
            data["keys"][key_id],
        )
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_wrong_password_raises_password_error_not_integrity_error(self):
        """A wrong password must stay distinguishable from tampering."""
        self._create_keystore_with_key()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystorePasswordError):
            keystore.load_keystore("WrongPassword!")

    # ------------------------------------------------------------------ #
    # legacy v1 handling
    # ------------------------------------------------------------------ #

    def test_legacy_v1_loads_with_warning_and_auto_upgrades(self):
        """A v1 keystore loads (warned) and is rewritten as v2 on load."""
        key_id = self._create_keystore_with_key()
        self._downgrade_to_v1()

        keystore = PQCKeystore(self.keystore_path)
        with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
            keystore.load_keystore(self.keystore_password)
        public_key, _ = keystore.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        keystore.close()

        # the file on disk must now be v2 with a valid MAC
        data = self._read_raw()
        self.assertEqual(data["version"], 2)
        self.assertIn("integrity", data)
        reloaded = PQCKeystore(self.keystore_path)
        reloaded.load_keystore(self.keystore_password)
        reloaded.close()

    def test_legacy_v1_wrong_password_still_rejected(self):
        """v1 password verification (test_key) keeps working."""
        self._create_keystore_with_key()
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystorePasswordError):
            keystore.load_keystore("WrongPassword!")

    def test_legacy_v1_loads_even_if_upgrade_write_fails(self):
        """If the auto-upgrade save fails (read-only file), load still succeeds."""
        key_id = self._create_keystore_with_key()
        self._downgrade_to_v1()

        keystore = PQCKeystore(self.keystore_path)
        with mock.patch.object(
            PQCKeystore, "save_keystore", side_effect=OSError("read-only filesystem")
        ):
            with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
                keystore.load_keystore(self.keystore_password)
        public_key, _ = keystore.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        keystore.close()

    def test_legacy_v1_without_test_key_skips_auto_upgrade(self):
        """No test_key means the password is unverifiable - never seal the
        store under a potentially mistyped password; warn and stay v1."""
        self._create_keystore_with_key()
        data = self._read_raw()
        data["version"] = 1
        data.pop("integrity", None)
        data.pop("test_key", None)
        self._write_raw(data)

        keystore = PQCKeystore(self.keystore_path)
        with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
            keystore.load_keystore(self.keystore_password)
        keystore.close()

        on_disk = self._read_raw()
        self.assertEqual(on_disk["version"], 1)
        self.assertNotIn("integrity", on_disk)

    def test_downgrade_to_v1_is_accepted_by_design(self):
        """Documented residual risk: stripping MAC + version → v1 still loads.

        Accepted for 1.4.x backward compatibility (see SECURITY_REVIEW_FINDINGS
        H4 notes); 1.5.x may refuse v1. The load must at least warn loudly.
        """
        key_id = self._create_keystore_with_key()
        # attacker downgrade: strip integrity, rewrite version
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
            keystore.load_keystore(self.keystore_password)
        self.assertIsNotNone(keystore.keystore_data)
        public_key, _ = keystore.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        keystore.close()


if __name__ == "__main__":
    unittest.main()
