#!/usr/bin/env python3
"""
A new USB drive must not get the weakest KDF in the tool (gitlab#205).

Every round option defaults to 0, so a plain `create-usb --usb-path X`
built an empty dict, passed `hash_config=None`, and landed on
`_derive_key_pbkdf2_fallback`: PBKDF2-HMAC-SHA256 at 100 000 iterations --
what this codebase's own comment calls "below the OWASP floor", protecting
an encrypted keystore and an integrity manifest on removable media.

Raising the hardcoded count is NOT the fix, and this file pins why: the
count is recorded nowhere readable. `security_profile` lives inside
`.integrity`, which is encrypted with the key derived from that profile,
and `verify_usb_integrity` always builds a STANDARD creator. A raised count
derives a different key, fails to decrypt `.integrity`, and reports a good
drive as tampered -- worse than the weak KDF.

So the strengthening goes through the mechanism that is honoured AND
round-trips: iterated hash rounds, which are stored in `hash_config.json`
and `.integrity` and read back on verify. New drives record a strong
config; the no-config path stays byte-identical so any drive created
through the library API still verifies.

Separately: `multi_hash_password` never reads `pbkdf2_iterations`, so
`--pbkdf2-iterations` changed nothing while still being written into the
drive's stored config -- a recorded work factor that was never applied.
"""

import hashlib
import unittest

from openssl_encrypt.modules.portable_media.usb_creator import (
    USBDriveCreator,
    default_usb_hash_config,
)
from openssl_encrypt.modules.secure_memory import SecureBytes

SALT = b"x" * 16


class TestTheDefaultConfigIsStrongAndRecorded(unittest.TestCase):
    def test_the_default_is_not_empty(self):
        config = default_usb_hash_config()
        self.assertTrue(config, "a bare create-usb still passes no config at all")

    def test_the_default_actually_changes_the_derived_key(self):
        """A config that is recorded but ignored is the gitlab#205 defect in
        its other half. This is what `pbkdf2_iterations` failed."""
        creator = USBDriveCreator()
        weak = creator._derive_encryption_key(SecureBytes(b"pw"), None, SALT)
        strong = creator._derive_encryption_key(SecureBytes(b"pw"), default_usb_hash_config(), SALT)
        self.assertNotEqual(
            bytes(weak),
            bytes(strong),
            "the default config derives the same key as no config, so it is "
            "being ignored rather than applied",
        )

    def test_the_default_is_meaningfully_more_work(self):
        """Not a timing assertion -- those are flaky. The round count itself
        has to be well above the 100k PBKDF2 it replaces."""
        config = default_usb_hash_config()
        total = sum(value for value in config.values() if isinstance(value, int))
        self.assertGreaterEqual(total, 100_000)

    def test_the_default_survives_the_validator(self):
        """It is written to hash_config.json and read back on verify, so it
        must pass the gitlab#200 allowlist -- otherwise every new drive
        would silently fall back to the weak path it just replaced."""
        self.assertEqual(
            USBDriveCreator._validated_drive_hash_config(dict(default_usb_hash_config())),
            dict(default_usb_hash_config()),
        )


class TestExistingDrivesStillVerify(unittest.TestCase):
    """The load-bearing half.

    A drive created before this change records no hash_config, so it must
    keep deriving exactly as it did -- otherwise the fix reports every good
    drive as tampered.
    """

    def test_the_no_config_path_is_byte_identical(self):
        creator = USBDriveCreator()
        key = creator._derive_encryption_key(SecureBytes(b"pw"), None, SALT)
        self.assertEqual(
            bytes(key),
            hashlib.pbkdf2_hmac("sha256", b"pw", SALT, 100_000, dklen=32),
            "the legacy no-config derivation changed; existing drives will " "no longer verify",
        )

    def test_an_explicitly_stored_config_is_still_honoured(self):
        creator = USBDriveCreator()
        first = creator._derive_encryption_key(SecureBytes(b"pw"), {"sha512": 100}, SALT)
        second = creator._derive_encryption_key(SecureBytes(b"pw"), {"sha512": 100}, SALT)
        self.assertEqual(bytes(first), bytes(second))


class TestTheIgnoredOptionNoLongerLies(unittest.TestCase):
    """`--pbkdf2-iterations` was written into the drive's stored config and
    never applied."""

    def test_pbkdf2_iterations_is_still_ignored_by_the_derivation(self):
        """Pinned as a known fact, not as desired behaviour.

        If a future change makes multi_hash_password honour it, this fails
        and the CLI refusal below should be revisited rather than silently
        left in place.
        """
        creator = USBDriveCreator()
        low = creator._derive_encryption_key(
            SecureBytes(b"pw"), {"pbkdf2_iterations": 100_000}, SALT
        )
        high = creator._derive_encryption_key(
            SecureBytes(b"pw"), {"pbkdf2_iterations": 5_000_000}, SALT
        )
        self.assertEqual(
            bytes(low),
            bytes(high),
            "multi_hash_password now honours pbkdf2_iterations -- wire it "
            "into the USB path instead of refusing it (gitlab#205)",
        )


if __name__ == "__main__":
    unittest.main()
