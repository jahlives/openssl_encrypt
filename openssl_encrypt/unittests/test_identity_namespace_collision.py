#!/usr/bin/env python3
"""
Tests for identity/contact namespace collisions (gitlab#173).

`get_by_name` resolves `base_path/<name>` before `contacts/<name>`, but
`add_identity` chose the directory purely from `is_own_identity`. A contact
imported under an own identity's name therefore created a SHADOWED
`contacts/<name>`: harmless while the own identity exists, and a live key
substitution the moment it is deleted, because `delete_identity` removed
`base_path/<name>` and returned, leaving `get_by_name(<name>)` resolving to
the attacker's keys under a name the user trusts. Recipient resolution goes
through `get_by_name`, so the substituted key would be encrypted to.

The TOFU key-change dialogue does fire on the import, but that gate is about
a CHANGED KEY, not about the namespace: it can be passed with
`--allow-key-change`. The collision must fail closed on its own.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules.identity import (
    Identity,
    IdentityError,
    IdentityExistsError,
    IdentityNamespaceCollisionError,
    IdentityStore,
)


def _write_entry(path, name, fingerprint="aa:bb:cc:dd"):
    """Write a store entry that Identity.load can read.

    Deliberately a real on-disk entry rather than a mock: the collision this
    file is about is a property of the DIRECTORY LAYOUT, so the tests have to
    exercise the layout.
    """
    path.mkdir(parents=True, exist_ok=True)
    (path / "identity.json").write_text(
        json.dumps(
            {
                "name": name,
                "email": None,
                "fingerprint": fingerprint,
                "created_at": "2026-01-01T00:00:00Z",
                "encryption_algorithm": "ML-KEM-768",
                "signing_algorithm": "ML-DSA-65",
            }
        ),
        encoding="utf-8",
    )
    (path / "encryption_public.pem").write_bytes(b"ek")
    (path / "signing_public.pem").write_bytes(b"sk")


def _identity(name, fingerprint, own):
    """A save()-able stand-in that needs no post-quantum keypair."""
    identity = mock.Mock(spec=Identity)
    identity.name = name
    identity.fingerprint = fingerprint
    identity.is_own_identity = own
    identity.save.side_effect = lambda path, passphrase=None, overwrite=False: _write_entry(
        path, name, fingerprint
    )
    return identity


class _StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = IdentityStore(base_path=Path(self.tmp))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _add(self, identity, **kw):
        self.store.add_identity(identity, passphrase=None, **kw)


class TestContactCannotShadowOwnIdentity(_StoreTestCase):
    def test_contact_taking_an_own_identity_name_is_refused(self):
        """The core of gitlab#173: the namespace collision itself."""
        self._add(_identity("alice", "aa:bb", own=True))
        with self.assertRaises(IdentityExistsError):
            self._add(_identity("alice", "cc:dd", own=False), allow_key_change=True)

    def test_refusal_does_not_depend_on_allow_key_change(self):
        """allow_key_change is about a CHANGED KEY, not about the namespace.

        The TOFU gate was the only thing standing in the way before, and it
        is designed to be passable.
        """
        self._add(_identity("alice", "aa:bb", own=True))
        for kwargs in ({"allow_key_change": True}, {"overwrite": True, "allow_key_change": True}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(IdentityExistsError):
                    self._add(_identity("alice", "cc:dd", own=False), **kwargs)

    def test_refusal_holds_even_for_an_identical_fingerprint(self):
        """A matching fingerprint passes the TOFU check, so if the namespace
        rule were folded into it the collision would slip through."""
        self._add(_identity("alice", "aa:bb", own=True))
        with self.assertRaises(IdentityExistsError):
            self._add(_identity("alice", "aa:bb", own=False))

    def test_no_shadow_directory_is_left_behind(self):
        """Fail closed means nothing on disk, not merely an exception."""
        self._add(_identity("alice", "aa:bb", own=True))
        with self.assertRaises(IdentityExistsError):
            self._add(_identity("alice", "cc:dd", own=False), allow_key_change=True)
        self.assertFalse((Path(self.tmp) / "contacts" / "alice").exists())

    def test_own_identity_taking_a_contact_name_is_refused(self):
        """The mirror direction: a new own identity must not shadow a
        pinned contact either, or the same substitution runs in reverse."""
        self._add(_identity("bob", "aa:bb", own=False))
        with self.assertRaises(IdentityExistsError):
            self._add(_identity("bob", "cc:dd", own=True), allow_key_change=True)

    def test_unrelated_names_are_unaffected(self):
        self._add(_identity("alice", "aa:bb", own=True))
        self._add(_identity("bob", "cc:dd", own=False))
        self.assertIsNotNone(self.store.get_by_name("alice"))
        self.assertIsNotNone(self.store.get_by_name("bob"))

    def test_updating_a_contact_in_place_still_works(self):
        """Same kind, same name is a normal overwrite, not a collision."""
        self._add(_identity("bob", "aa:bb", own=False))
        self._add(_identity("bob", "aa:bb", own=False), overwrite=True)


class TestDeleteLeavesNoResolvableShadow(_StoreTestCase):
    def _plant_shadow(self):
        """Recreate a pre-fix store: both entries exist under one name."""
        own = Path(self.tmp) / "alice"
        contact = Path(self.tmp) / "contacts" / "alice"
        _write_entry(own, "alice", "aa:bb")
        _write_entry(contact, "alice", "cc:dd")
        return own, contact

    def test_delete_removes_a_pre_existing_shadow_too(self):
        """Stores written before the fix can already contain a shadow;
        deleting the own identity must not promote the attacker's keys."""
        own, contact = self._plant_shadow()
        self.assertTrue(self.store.delete_identity("alice"))
        self.assertFalse(own.exists())
        self.assertFalse(
            contact.exists(),
            "deleting the own identity left a resolvable contact shadow " "(gitlab#173)",
        )

    def test_delete_of_a_plain_contact_still_works(self):
        self._add(_identity("bob", "aa:bb", own=False))
        self.assertTrue(self.store.delete_identity("bob"))
        self.assertFalse((Path(self.tmp) / "contacts" / "bob").exists())

    def test_delete_of_a_missing_name_reports_false(self):
        self.assertFalse(self.store.delete_identity("nobody"))


class TestListSurfacesAShadow(_StoreTestCase):
    def test_shadowed_entries_are_reported(self):
        """A store carrying a shadow from before the fix must not present
        two same-named entries with no disambiguation."""
        _write_entry(Path(self.tmp) / "alice", "alice", "aa:bb")
        _write_entry(Path(self.tmp) / "contacts" / "alice", "alice", "cc:dd")

        shadowed = self.store.find_shadowed_names()
        self.assertEqual(shadowed, ["alice"])


class TestReservedContainerName(_StoreTestCase):
    """`contacts` is the container directory: an entry of that name would be
    written INTO it, invisible to the listing but resolvable by name, and
    deleting it would remove every pinned contact in the store."""

    def test_the_container_name_is_refused(self):
        with self.assertRaises(IdentityError):
            self._add(_identity("contacts", "aa:bb", own=True))

    def test_the_container_name_is_refused_case_insensitively(self):
        """The store lives on case-insensitive filesystems too, where
        base_path/'Contacts' and base_path/'contacts' are one node."""
        for name in ("Contacts", "CONTACTS"):
            with self.subTest(name=name):
                with self.assertRaises(IdentityError):
                    self._add(_identity(name, "aa:bb", own=True))

    def test_an_entry_written_into_the_container_is_reported(self):
        """Stores written before the reserved-name rule can contain one.

        Reported by its OWN predicate, not as a name collision: `identity
        delete contacts` is refused (reserved name) and would remove every
        pinned contact in the store if it were not.
        """
        _write_entry(Path(self.tmp) / "contacts", "contacts", "aa:bb")
        self.assertTrue(self.store.has_misplaced_container_entry())
        self.assertNotIn("contacts", self.store.find_shadowed_names())

    def test_a_clean_store_has_no_container_entry(self):
        self._add(_identity("alice", "aa:bb", own=True))
        self.assertFalse(self.store.has_misplaced_container_entry())


class TestCollisionErrorType(_StoreTestCase):
    def test_the_refusal_has_its_own_type(self):
        """Callers must be able to tell a refused collision from 'not found';
        the keyserver path would otherwise report both as a lookup failure."""
        self._add(_identity("alice", "aa:bb", own=True))
        with self.assertRaises(IdentityNamespaceCollisionError):
            self._add(_identity("alice", "cc:dd", own=False), allow_key_change=True)

    def test_it_is_still_an_identity_exists_error(self):
        self.assertTrue(issubclass(IdentityNamespaceCollisionError, IdentityExistsError))


class TestNonDirectoryNodeDoesNotShadow(_StoreTestCase):
    def test_a_stray_file_does_not_hide_a_contact(self):
        """A file (or dangling symlink) at base_path/<name> must not shadow a
        real contact behind it: resolution would fail instead of falling
        through, and the collision report would call the store clean."""
        (Path(self.tmp) / "alice").write_text("not a directory", encoding="utf-8")
        _write_entry(Path(self.tmp) / "contacts" / "alice", "alice", "cc:dd")
        identity = self.store.get_by_name("alice")
        self.assertIsNotNone(identity)
        self.assertEqual(identity.fingerprint, "cc:dd")


class TestDeleteSelectsAKind(_StoreTestCase):
    def _plant_shadow(self):
        _write_entry(Path(self.tmp) / "alice", "alice", "aa:bb")
        _write_entry(Path(self.tmp) / "contacts" / "alice", "alice", "cc:dd")

    def test_describe_name_shows_both_entries(self):
        """The confirmation prompt needs both, and get_by_name hides one."""
        self._plant_shadow()
        entries = self.store.describe_name("alice")
        self.assertEqual([e["kind"] for e in entries], ["own", "contact"])
        self.assertEqual([e["fingerprint"] for e in entries], ["aa:bb", "cc:dd"])

    def test_kind_own_keeps_the_contact(self):
        """The remediation the warning tells users to perform must exist:
        removing both would destroy private keys AND the TOFU pin."""
        self._plant_shadow()
        self.assertEqual(self.store.delete_identity("alice", kind="own"), ["own"])
        self.assertFalse((Path(self.tmp) / "alice").exists())
        self.assertTrue((Path(self.tmp) / "contacts" / "alice").exists())

    def test_kind_contact_keeps_the_own_identity(self):
        self._plant_shadow()
        self.assertEqual(self.store.delete_identity("alice", kind="contact"), ["contact"])
        self.assertTrue((Path(self.tmp) / "alice").exists())
        self.assertFalse((Path(self.tmp) / "contacts" / "alice").exists())

    def test_default_removes_both_and_reports_both(self):
        self._plant_shadow()
        self.assertEqual(self.store.delete_identity("alice"), ["own", "contact"])

    def test_an_invalid_kind_is_refused(self):
        with self.assertRaises(ValueError):
            self.store.delete_identity("alice", kind="everything")


class TestDeleteCliWarnsBeforeRemovingAShadow(_StoreTestCase):
    def test_confirmation_names_both_entries(self):
        """--force skips the prompt, so the NOTE must precede it and be
        printed regardless."""
        import argparse
        import io
        from contextlib import redirect_stderr

        from openssl_encrypt.modules.identity_cli import cmd_delete

        _write_entry(Path(self.tmp) / "alice", "alice", "aa:bb")
        _write_entry(Path(self.tmp) / "contacts" / "alice", "alice", "cc:dd")

        args = argparse.Namespace(
            identity_name="alice", force=True, kind="both", identity_store=Path(self.tmp)
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = cmd_delete(args)
        out = stderr.getvalue()

        self.assertEqual(status, 0)
        self.assertIn("BOTH an own identity and a contact", out)
        self.assertIn("aa:bb", out)
        self.assertIn("cc:dd", out)
        self.assertIn("--kind own", out)


class TestDeleteKindGuard(_StoreTestCase):
    def test_an_invalid_kind_string_is_an_error_not_a_delete(self):
        """Coercing an unrecognized value to the default would fail OPEN to
        the most destructive branch (private keys AND the pinned key)."""
        import argparse
        import io
        from contextlib import redirect_stderr

        from openssl_encrypt.modules.identity_cli import cmd_delete

        _write_entry(Path(self.tmp) / "alice", "alice", "aa:bb")
        args = argparse.Namespace(
            identity_name="alice", force=True, kind="Own", identity_store=Path(self.tmp)
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = cmd_delete(args)
        self.assertEqual(status, 1)
        self.assertIn("--kind must be", stderr.getvalue())
        self.assertTrue((Path(self.tmp) / "alice").exists(), "nothing may be deleted")

    def test_a_surviving_entry_is_named_after_a_partial_delete(self):
        """Removing one side promotes the other -- the event this issue is
        about -- so the new resolution must be stated."""
        import argparse
        import io
        from contextlib import redirect_stderr

        from openssl_encrypt.modules.identity_cli import cmd_delete

        _write_entry(Path(self.tmp) / "alice", "alice", "aa:bb")
        _write_entry(Path(self.tmp) / "contacts" / "alice", "alice", "cc:dd")
        args = argparse.Namespace(
            identity_name="alice", force=True, kind="own", identity_store=Path(self.tmp)
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = cmd_delete(args)
        out = stderr.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("now resolves to the contact entry", out)
        self.assertIn("cc:dd", out)


if __name__ == "__main__":
    unittest.main()
