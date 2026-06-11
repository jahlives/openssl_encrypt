#!/usr/bin/env python3
"""
Regression tests for M8: identity import is TOFU with no key-change detection.

Three problems were fixed:
1. add_identity(overwrite=True) silently replaced a pinned contact's keys even
   when the fingerprint changed (key substitution). Now a key change raises
   IdentityKeyChangedError unless allow_key_change=True.
2. get_by_fingerprint used startswith(), so an empty/short prefix resolved to
   the first stored identity. Now it requires the full fingerprint, errors on
   empty input, and errors on an ambiguous (multi-) match.
3. verify_fingerprint() was misleadingly named (it checks internal consistency,
   not authenticity). Renamed to check_fingerprint_consistency() with a
   backward-compatible alias.

See SECURITY_REVIEW_FINDINGS.md (M8).
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules.identity import (
    Identity,
    IdentityAmbiguousError,
    IdentityError,
    IdentityKeyChangedError,
    IdentityStore,
)


class TestIdentityTofuM8(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.store = IdentityStore(base_path=Path(self.temp_dir))
        # One real identity (own) and a "contact" re-import scenario.
        self.alice = Identity.generate("alice", None, "pass")
        self.store.add_identity(self.alice, "pass")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- key-change detection (TOFU) -------------------------------------

    def test_reimport_same_key_allowed(self):
        """Re-importing the SAME identity (same fingerprint) is harmless."""
        # Same object/fingerprint, with overwrite -> allowed, no key-change error.
        self.store.add_identity(self.alice, "pass", overwrite=True)
        self.assertEqual(self.store.get_by_name("alice").fingerprint, self.alice.fingerprint)

    def test_changed_key_refused_even_with_overwrite(self):
        """A DIFFERENT key for an existing name must be refused, even with
        overwrite=True (the M8 key-substitution case)."""
        impostor = Identity.generate("alice", None, "pass")  # fresh keys, same name
        self.assertNotEqual(impostor.fingerprint, self.alice.fingerprint)
        with self.assertRaises(IdentityKeyChangedError) as ctx:
            self.store.add_identity(impostor, "pass", overwrite=True)
        # error carries old + new fingerprints
        self.assertEqual(ctx.exception.old_fingerprint, self.alice.fingerprint)
        self.assertEqual(ctx.exception.new_fingerprint, impostor.fingerprint)
        # the pinned key must be UNCHANGED
        self.assertEqual(self.store.get_by_name("alice").fingerprint, self.alice.fingerprint)

    def test_changed_key_accepted_with_allow_key_change(self):
        impostor = Identity.generate("alice", None, "pass")
        self.store.add_identity(impostor, "pass", overwrite=True, allow_key_change=True)
        self.assertEqual(self.store.get_by_name("alice").fingerprint, impostor.fingerprint)

    def test_new_name_not_affected(self):
        bob = Identity.generate("bob", None, "pass")
        self.store.add_identity(bob, "pass")  # no existing -> fine
        self.assertEqual(self.store.get_by_name("bob").fingerprint, bob.fingerprint)

    # --- fingerprint lookup safety ---------------------------------------

    def test_empty_fingerprint_rejected(self):
        with self.assertRaises(IdentityError):
            self.store.get_by_fingerprint("")

    def test_full_fingerprint_matches(self):
        found = self.store.get_by_fingerprint(self.alice.fingerprint)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "alice")

    def test_partial_prefix_does_not_match(self):
        # A short prefix that used to match via startswith now does not.
        prefix = self.alice.fingerprint[:8]
        self.assertNotEqual(prefix, self.alice.fingerprint)
        self.assertIsNone(self.store.get_by_fingerprint(prefix))

    def test_nonexistent_full_fingerprint_returns_none(self):
        self.assertIsNone(self.store.get_by_fingerprint("00:11:22:33:" + "44:" * 20))

    def test_ambiguous_fingerprint_errors(self):
        """If two identities share a fingerprint (collision), refuse to guess."""
        bob = Identity.generate("bob", None, "pass")
        # Force a collision by making two listed identities report the same fp.
        a = self.alice
        b = bob
        b.fingerprint = a.fingerprint
        with mock.patch.object(self.store, "list_identities", return_value=[a, b]):
            with self.assertRaises(IdentityAmbiguousError):
                self.store.get_by_fingerprint(a.fingerprint)

    # --- consistency-check rename ----------------------------------------

    def test_check_fingerprint_consistency(self):
        self.assertTrue(self.alice.check_fingerprint_consistency())

    def test_verify_fingerprint_alias_still_works(self):
        self.assertTrue(self.alice.verify_fingerprint())

    def test_consistency_false_on_tamper(self):
        self.alice.fingerprint = "ff:" * 31 + "ff"
        self.assertFalse(self.alice.check_fingerprint_consistency())


if __name__ == "__main__":
    unittest.main()
