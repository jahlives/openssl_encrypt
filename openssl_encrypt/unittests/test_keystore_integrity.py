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

    def test_private_key_blob_move_between_entries_rejected(self):
        """M6: moving only the encrypted private_key blob from one entry into
        another (both wrapped under the same master key, so the blob would
        decrypt in the wrong entry without AAD binding) must be detected.

        The H4 whole-store HMAC covers every entry's private_key field, so a
        blob move changes the canonical JSON and fails the MAC on load - which
        is why per-entry AAD on the master-key wrap (M6) is not separately
        required for the without-master-key attacker.
        """
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
        # Move ONLY the encrypted private_key blob; leave algorithm/public_key
        # of the destination entry untouched (the M6 attack shape).
        data["keys"][second_id]["private_key"] = data["keys"][key_id]["private_key"]
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_wrong_password_raises_password_error_not_integrity_error(self):
        """A wrong password must stay distinguishable from tampering."""
        self._create_keystore_with_key()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystorePasswordError):
            keystore.load_keystore("WrongPassword!")

    # ------------------------------------------------------------------ #
    # version-downgrade attack (KEYSTORE-DOWNGRADE finding)
    # ------------------------------------------------------------------ #

    def test_downgrade_to_v1_rejected(self):
        """Stripping the MAC and forcing version=1 must NOT bypass integrity.

        The core vulnerability: _verify_integrity() was gated on the
        attacker-controlled `version` field, so version 2 -> 1 + drop
        `integrity` skipped authentication and let a swapped public_key load.
        Loading such a file must now fail closed.
        """
        key_id = self._create_keystore_with_key()
        # attacker downgrade: strip integrity, force version, swap the pubkey
        data = self._read_raw()
        data["version"] = 1
        data.pop("integrity", None)
        data["keys"][key_id]["public_key"] = base64.b64encode(os.urandom(64)).decode("utf-8")
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_downgrade_to_v1_rejected_even_without_other_tampering(self):
        """A bare downgrade (no field edits) is still refused - a v1 file and a
        downgraded v2 file are indistinguishable, so both fail closed."""
        self._create_keystore_with_key()
        self._downgrade_to_v1()
        self._assert_load_raises_integrity_error()

    def test_integrity_present_but_version_1_still_verified(self):
        """De-gate check: keeping `integrity` but claiming version 1 must still
        verify the MAC (a lazy downgrade that forgets to strip integrity)."""
        key_id = self._create_keystore_with_key()
        data = self._read_raw()
        data["version"] = 1  # lie about the version but leave the MAC in place
        data["keys"][key_id]["public_key"] = base64.b64encode(os.urandom(64)).decode("utf-8")
        self._write_raw(data)
        self._assert_load_raises_integrity_error()

    def test_downgrade_refused_before_password_check(self):
        """An unauthenticated (v1/downgraded) file is refused regardless of the
        password - no password oracle on a file we will not trust anyway."""
        from openssl_encrypt.modules.crypt_errors import KeystoreIntegrityError

        self._create_keystore_with_key()
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystoreIntegrityError):
            keystore.load_keystore("WrongPassword!")

    def test_downgrade_refused_without_deriving_master_key(self):
        """An unauthenticated file must be refused before any password-derived
        work runs - an attacker-supplied file must not cost the victim an
        Argon2 derivation, and key material derived from the password must
        never exist for a file we refuse to trust."""
        from openssl_encrypt.modules.crypt_errors import KeystoreIntegrityError

        self._create_keystore_with_key()
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with mock.patch.object(
            PQCKeystore,
            "_derive_master_key",
            side_effect=AssertionError("KDF must not run for a refused keystore"),
        ) as kdf:
            with self.assertRaises(KeystoreIntegrityError):
                keystore.load_keystore(self.keystore_password)
        kdf.assert_not_called()

    def test_integrity_present_but_not_an_object_fails_closed(self):
        """`integrity` set to a non-object (e.g. a string) must not load: the
        schema validator rejects it, and even without the validator it is
        treated as unauthenticated and refused."""
        self._create_keystore_with_key()
        data = self._read_raw()
        data["integrity"] = "not-a-mac-object"
        self._write_raw(data)
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystoreError):
            keystore.load_keystore(self.keystore_password)
        self.assertIsNone(keystore.keystore_data)

    def test_integrity_empty_object_fails_closed(self):
        """`integrity` present but empty ({}) must not load: the schema
        requires alg+mac, and the MAC check itself treats a missing/unknown
        alg or mac as invalid."""
        self._create_keystore_with_key()
        data = self._read_raw()
        data["integrity"] = {}
        self._write_raw(data)
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystoreError):
            keystore.load_keystore(self.keystore_password)
        self.assertIsNone(keystore.keystore_data)

    def test_default_load_does_not_auto_upgrade_v1(self):
        """A plain load must never silently rewrite a v1 file to v2 - that would
        launder a downgraded/tampered file under a fresh valid MAC."""
        self._create_keystore_with_key()
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(Exception):
            keystore.load_keystore(self.keystore_password)
        on_disk = self._read_raw()
        self.assertEqual(on_disk["version"], 1)
        self.assertNotIn("integrity", on_disk)

    # ------------------------------------------------------------------ #
    # explicit legacy migration (opt-in upgrade path)
    # ------------------------------------------------------------------ #

    def test_migrate_upgrades_legacy_v1_to_v2(self):
        """The explicit migrate path upgrades a genuine legacy v1 keystore to
        the authenticated v2 format and warns that authenticity is unverified."""
        key_id = self._create_keystore_with_key()
        self._downgrade_to_v1()

        keystore = PQCKeystore(self.keystore_path)
        with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
            keystore.migrate_legacy_keystore(self.keystore_password)
        keystore.close()

        # the file on disk must now be authenticated v2
        data = self._read_raw()
        self.assertEqual(data["version"], 2)
        self.assertIn("integrity", data)

        # and it must load normally afterwards (no allow_legacy needed)
        reloaded = PQCKeystore(self.keystore_path)
        reloaded.load_keystore(self.keystore_password)
        public_key, _ = reloaded.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        reloaded.close()

    def test_migrate_wrong_password_rejected(self):
        """Migration still requires the correct master password."""
        self._create_keystore_with_key()
        self._downgrade_to_v1()
        keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(KeystorePasswordError):
            keystore.migrate_legacy_keystore("WrongPassword!")

    def test_load_allow_legacy_true_upgrades_v1(self):
        """load_keystore(allow_legacy=True) is the low-level opt-in that the
        migrate command uses; it loads and re-seals a v1 store as v2."""
        key_id = self._create_keystore_with_key()
        self._downgrade_to_v1()

        keystore = PQCKeystore(self.keystore_path)
        with self.assertLogs("openssl_encrypt.modules.keystore_cli", level="WARNING"):
            keystore.load_keystore(self.keystore_password, allow_legacy=True)
        public_key, _ = keystore.get_key(key_id)
        self.assertEqual(public_key, self.public_key)
        keystore.close()

        self.assertEqual(self._read_raw()["version"], 2)

    def test_migrate_on_v2_is_idempotent(self):
        """Migrating an already-authenticated v2 store leaves it valid v2."""
        key_id = self._create_keystore_with_key()
        keystore = PQCKeystore(self.keystore_path)
        keystore.migrate_legacy_keystore(self.keystore_password)
        keystore.close()

        data = self._read_raw()
        self.assertEqual(data["version"], 2)
        self.assertIn("integrity", data)
        reloaded = PQCKeystore(self.keystore_path)
        reloaded.load_keystore(self.keystore_password)
        self.assertEqual(reloaded.get_key(key_id)[0], self.public_key)
        reloaded.close()


if __name__ == "__main__":
    unittest.main()
