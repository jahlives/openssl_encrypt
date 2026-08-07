#!/usr/bin/env python3
"""
Tests for `identity list --json` (gitlab#183 / github#100).

The desktop GUI has always run `identity list --include-contacts --json` and
parsed stdout as {"own": [...], "contacts": [...]} — but the flag never
existed, argparse exited 2, and the GUI swallowed the failure into an empty
identity list. Same accepted-but-nonexistent-flag class as gitlab#164/#181:
presence of a call site is not evidence the surface exists.

Contract notes (from the gitlab#172 work): the JSON channel is deliberately
UNSANITIZED — it is machine-readable, consumers render it themselves, and
json.dumps with ensure_ascii escapes control characters at the transport
level anyway. The GUI expects the key names kem_algorithm / sig_algorithm
(not the dataclass's encryption_algorithm / signing_algorithm).
"""

import argparse
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import setup_identity_parser
from openssl_encrypt.modules.identity import Identity


def _parse(*argv):
    parser = argparse.ArgumentParser()
    setup_identity_parser(parser)
    return parser.parse_args(list(argv))


class TestListJsonParser(unittest.TestCase):
    def test_json_flag_is_accepted(self):
        self.assertTrue(_parse("list", "--json").json)

    def test_gui_invocation_parses(self):
        """The exact argv the GUI has emitted since gitlab#137."""
        args = _parse("list", "--include-contacts", "--json")
        self.assertTrue(args.json)
        self.assertTrue(args.include_contacts)

    def test_default_is_human_output(self):
        """The flag uses SUPPRESS so it cannot shadow the global --json with
        a False default, so absence means the attribute is missing — which
        is exactly how cmd_list reads it."""
        self.assertFalse(getattr(_parse("list"), "json", False))

    def test_the_flag_does_not_shadow_the_global_one(self):
        self.assertNotIn("json", vars(_parse("list")))


class TestListJsonOutput(unittest.TestCase):
    @staticmethod
    def _identity(name, email, own):
        identity = mock.Mock(spec=Identity)
        identity.name = name
        identity.email = email
        identity.fingerprint = ":".join(["ab"] * 32)
        identity.encryption_algorithm = "ML-KEM-768"
        identity.signing_algorithm = "ML-DSA-65"
        identity.created_at = "2026-01-01T00:00:00Z"
        identity.is_own_identity = own
        identity.protection = None
        return identity

    def _run(self, identities, json_flag=True, skips=None, shadowed=None):
        from openssl_encrypt.modules.identity_cli import cmd_list

        args = argparse.Namespace(identity_store=None, include_contacts=True, json=json_flag)
        store = mock.Mock()
        store.find_shadowed_names.return_value = shadowed or []
        store.has_misplaced_container_entry.return_value = False

        def _list(include_contacts=True, skipped=None):
            if skipped is not None:
                skipped.extend(skips or [])
            return identities

        store.list_identities.side_effect = _list
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store",
            return_value=store,
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cmd_list(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_emits_the_shape_the_gui_parses(self):
        status, out, _err = self._run(
            [
                self._identity("alice", "alice@example.com", own=True),
                self._identity("bob", None, own=False),
            ]
        )
        self.assertEqual(status, 0)
        data = json.loads(out)
        self.assertEqual(
            data["own"],
            [
                {
                    "name": "alice",
                    "email": "alice@example.com",
                    "fingerprint": ":".join(["ab"] * 32),
                    "kem_algorithm": "ML-KEM-768",
                    "sig_algorithm": "ML-DSA-65",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ],
        )
        self.assertEqual(data["contacts"][0]["name"], "bob")
        self.assertEqual(data["skipped"], [])
        self.assertEqual(data["shadowed"], [])
        self.assertFalse(data["contacts_container_entry"])
        self.assertIsNone(data["contacts"][0]["email"])

    def test_stdout_carries_only_json(self):
        """The GUI feeds all of stdout to jsonDecode; a banner would break it."""
        _status, out, _err = self._run([self._identity("alice", None, own=True)])
        json.loads(out)

    def test_empty_store_yields_empty_lists(self):
        status, out, _err = self._run([])
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(out),
            {
                "own": [],
                "contacts": [],
                "skipped": [],
                "shadowed": [],
                "contacts_container_entry": False,
            },
        )

    def test_json_values_are_not_display_sanitized(self):
        """Machine-readable contract: the transport escapes what needs
        escaping (ensure_ascii), and the consumer renders — a display-escaped
        email here would show literal backslashes in the GUI."""
        status, out, _err = self._run([self._identity("alice", "a\u202eb@example.com", own=True)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out)["own"][0]["email"], "a\u202eb@example.com")

    def test_skipped_entries_are_reported(self):
        """A store entry that fails to load must not simply be absent: a
        consumer treating this listing as complete would silently drop a
        recipient or report an own identity as deleted."""
        status, out, _err = self._run(
            [self._identity("alice", None, own=True)],
            skips=[{"entry": "bob", "reason": "invalid metadata"}],
        )
        self.assertEqual(status, 0)
        data = json.loads(out)
        self.assertEqual(len(data["own"]), 1)
        self.assertEqual(data["skipped"], [{"entry": "bob", "reason": "invalid metadata"}])

    def test_skipped_entries_are_reported_on_the_human_path_too(self):
        _status, _out, err = self._run(
            [self._identity("alice", None, own=True)],
            json_flag=False,
            skips=[{"entry": "bob", "reason": "invalid metadata"}],
        )
        self.assertIn("could not be loaded", err)
        self.assertIn("bob", err)

    def test_stdout_is_pure_ascii(self):
        """ensure_ascii is what keeps a direct terminal run free of decoded
        escape sequences; it must not be silently flipped for prettier
        output."""
        _status, out, _err = self._run([self._identity("alice", "a\u202eb@example.com", own=True)])
        self.assertTrue(out.isascii(), out)

    def test_empty_store_still_reports_on_the_human_path(self):
        status, out, err = self._run([], json_flag=False)
        self.assertEqual(status, 0)
        self.assertEqual(out, "")
        self.assertIn("No identities found.", err)

    def test_shadowed_names_are_reported(self):
        """A name existing as both an own identity and a contact is
        invisible in the listing itself (gitlab#173), so it has to be
        reported separately or the consumer cannot warn about it."""
        status, out, _err = self._run([self._identity("alice", None, own=True)], shadowed=["alice"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out)["shadowed"], ["alice"])

    def test_shadowed_names_are_reported_on_the_human_path_too(self):
        _status, _out, err = self._run(
            [self._identity("alice", None, own=True)], json_flag=False, shadowed=["alice"]
        )
        self.assertIn("BOTH an own identity and a contact", err)
        self.assertIn("alice", err)

    def test_human_output_is_unchanged_without_the_flag(self):
        status, out, err = self._run([self._identity("alice", None, own=True)], json_flag=False)
        self.assertEqual(status, 0)
        self.assertEqual(out, "")
        self.assertIn("alice", err)


if __name__ == "__main__":
    unittest.main()
