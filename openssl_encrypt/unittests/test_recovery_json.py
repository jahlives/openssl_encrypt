#!/usr/bin/env python3
"""
Tests for `--json` machine-readable output on the recovery-slot commands
(gitlab#146 / github#64).

Without it a non-interactive caller (the desktop GUI Recovery Slots screen,
gitlab#145) has to scrape human-readable stderr for the slot list and for the
freshly generated recovery code.

The code is NOT solved by moving it to stdout: stdout is the conventional
target of `> file`, is merged by `2>&1`, and the desktop GUI's stdout gate
(`logStdout`) defaults to on, is absent from its streaming helper, and is
bypassed entirely on a non-zero exit. So the generated code gets its own
0600 file via --recovery-code-out, and the JSON carries only that path.
"""

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_core import encrypt_file, list_recovery_slots
from openssl_encrypt.modules.recovery_slots import (
    add_recovery_cli,
    generate_recovery_code,
    list_recovery_cli,
    recover_cli,
    remove_recovery_cli,
)

PASSWORD = b"primary-json-password"
PLAINTEXT = b"recovery json payload\n" * 5


def _ns(**kw):
    base = dict(
        input=None,
        output=None,
        password=None,
        recovery_code=None,
        recovery_passphrase=False,
        add_code=False,
        add_passphrase=False,
        slot_id=None,
        json=False,
        recovery_code_out=None,
        quiet=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


class RecoveryJsonBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.enc = os.path.join(self.tmp, "file.enc")
        self.out = os.path.join(self.tmp, "out.bin")

    def tearDown(self):
        for root, _, files in os.walk(self.tmp, topdown=False):
            for f in files:
                os.unlink(os.path.join(root, f))
            os.rmdir(root)

    def _encrypt(self, recovery_credentials=None):
        data = encrypt_file(
            input_file=PLAINTEXT,
            output_file=None,
            password=PASSWORD,
            algorithm="aes-gcm",
            quiet=True,
            envelope=True,
            recovery_credentials=recovery_credentials,
        )
        with open(self.enc, "wb") as f:
            f.write(data)

    def _run_json(self, fn, ns):
        """Run a handler with --json and return the parsed stdout document."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn(ns)
        return json.loads(buf.getvalue())


class TestListRecoveryJson(RecoveryJsonBase):
    def test_lists_slots_as_json_on_stdout(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        doc = self._run_json(list_recovery_cli, _ns(input=self.enc, json=True))

        self.assertIn("slots", doc)
        self.assertEqual(len(doc["slots"]), 1)
        self.assertEqual(doc["slots"][0]["type"], "recovery_code")
        self.assertEqual(doc["slots"][0]["id"], list_recovery_slots(self.enc)[0]["id"])

    def test_key_id_is_passed_through_untruncated(self):
        """The human view truncates key_id to 16 chars; JSON must not.

        Asserted as an exact passthrough of whatever list_recovery_slots
        reports — including None for slot types that carry no key_id — so this
        pins the absence of truncation logic without needing a key_id-bearing
        slot to construct.
        """
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        slots = list_recovery_slots(self.enc)
        doc = self._run_json(list_recovery_cli, _ns(input=self.enc, json=True))
        self.assertEqual(doc["slots"][0]["key_id"], slots[0].get("key_id"))

    def test_empty_slot_list_is_still_valid_json(self):
        self._encrypt()
        doc = self._run_json(list_recovery_cli, _ns(input=self.enc, json=True))
        self.assertEqual(doc["slots"], [])

    def test_without_json_nothing_is_written_to_stdout(self):
        """stdout is reserved for piped data; the human view goes to stderr."""
        self._encrypt([{"type": "recovery_code", "code": generate_recovery_code()}])
        buf = io.StringIO()
        with redirect_stdout(buf):
            list_recovery_cli(_ns(input=self.enc))
        self.assertEqual(buf.getvalue(), "")


class TestAddRecoveryJson(RecoveryJsonBase):
    def test_generated_code_goes_to_a_0600_file_never_a_stream(self):
        """The credential must never touch stdout or stderr under --json.

        A recovery code unwraps the file's DEK, so it is password-equivalent.
        stdout is the conventional target of `> file` (created at the caller's
        umask) and is merged into stderr by `2>&1`; stderr reaches terminal
        scrollback and the desktop GUI's persistent debug log. Writing the file
        ourselves is the only way the tool controls the permissions.
        """
        self._encrypt()
        code_path = os.path.join(self.tmp, "code.txt")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_code=True,
                    json=True,
                    recovery_code_out=code_path,
                )
            )

        doc = json.loads(out.getvalue())
        self.assertEqual(doc["slot_type"], "recovery_code")
        self.assertEqual(doc["recovery_code_written_to"], code_path)
        self.assertNotIn("recovery_code", doc)

        self.assertEqual(oct(os.stat(code_path).st_mode & 0o777), "0o600")
        with open(code_path) as f:
            code = f.read().strip()

        # The credential appears on neither stream.
        self.assertNotIn(code, out.getvalue())
        self.assertNotIn(code, err.getvalue())

        # And it actually unlocks the file.
        recover_cli(_ns(input=self.enc, output=self.out, recovery_code=code))
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_add_code_with_json_requires_a_destination(self):
        """Fail closed rather than silently withhold the credential."""
        self._encrypt()
        with self.assertRaises(ValueError):
            add_recovery_cli(
                _ns(input=self.enc, output=self.enc, password=PASSWORD, add_code=True, json=True)
            )

    def test_existing_destination_is_refused(self):
        self._encrypt()
        code_path = os.path.join(self.tmp, "code.txt")
        with open(code_path, "w") as f:
            f.write("pre-existing")

        with self.assertRaises(FileExistsError):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_code=True,
                    json=True,
                    recovery_code_out=code_path,
                )
            )

    def test_destination_may_not_be_the_envelope(self):
        """Otherwise the header write truncates the credential and reports success."""
        self._encrypt()
        distinct_out = os.path.join(self.tmp, "rewritten.enc")
        # Both arms: the destination colliding with --input, and with a
        # --output that differs from --input.
        for in_path, out_path, dest in (
            (self.enc, self.enc, self.enc),
            (self.enc, distinct_out, distinct_out),
        ):
            with self.assertRaises(ValueError):
                add_recovery_cli(
                    _ns(
                        input=in_path,
                        output=out_path,
                        password=PASSWORD,
                        add_code=True,
                        json=True,
                        recovery_code_out=dest,
                    )
                )

    def test_destination_without_add_code_is_refused(self):
        """Silently ignoring it lets a wrapper read back a stale earlier file."""
        self._encrypt()
        with mock.patch("getpass.getpass", return_value="a phrase"):
            with self.assertRaises(ValueError):
                add_recovery_cli(
                    _ns(
                        input=self.enc,
                        output=self.enc,
                        password=PASSWORD,
                        add_passphrase=True,
                        recovery_code_out=os.path.join(self.tmp, "code.txt"),
                    )
                )

    def test_missing_destination_fails_before_prompting(self):
        """The usage error must not sit behind a getpass a GUI cannot answer."""
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with self.assertRaises(ValueError):
                add_recovery_cli(_ns(input=self.enc, output=self.enc, add_code=True, json=True))
            gp.assert_not_called()

    def test_destination_replaces_the_stderr_display_without_json(self):
        """A named private destination must be honoured regardless of --json."""
        self._encrypt()
        code_path = os.path.join(self.tmp, "code.txt")
        err = io.StringIO()
        with redirect_stderr(err):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_code=True,
                    recovery_code_out=code_path,
                )
            )
        with open(code_path) as f:
            code = f.read().strip()
        self.assertNotIn(code, err.getvalue())
        self.assertIn(code_path, err.getvalue())

    def test_json_reports_the_credential_source(self):
        """A planted env passphrase must be distinguishable from a typed one."""
        self._encrypt()
        with mock.patch.dict(
            os.environ,
            {"OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE": "planted phrase"},
        ):
            doc = self._run_json(
                add_recovery_cli,
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_passphrase=True,
                    json=True,
                ),
            )
        self.assertIn("OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE", doc["credential_source"])

    def test_passphrase_slot_reports_no_code(self):
        self._encrypt()
        with mock.patch("getpass.getpass", return_value="a recovery phrase"):
            doc = self._run_json(
                add_recovery_cli,
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_passphrase=True,
                    json=True,
                ),
            )
        self.assertEqual(doc["slot_type"], "passphrase")
        self.assertNotIn("recovery_code", doc)
        self.assertNotIn("recovery_code_written_to", doc)

    def test_without_json_code_still_shown_on_stderr(self):
        """The interactive one-time display must not regress."""
        self._encrypt()
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            add_recovery_cli(_ns(input=self.enc, output=self.enc, password=PASSWORD, add_code=True))
        self.assertEqual(out.getvalue(), "")
        self.assertIn("RECOVERY CODE", err.getvalue())


class TestRemoveAndRecoverJson(RecoveryJsonBase):
    def test_remove_reports_the_removed_slot(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        self._encrypt(
            [{"type": "recovery_code", "code": c1}, {"type": "recovery_code", "code": c2}]
        )
        slot_id = list_recovery_slots(self.enc)[0]["id"]

        doc = self._run_json(
            remove_recovery_cli,
            _ns(
                input=self.enc,
                output=self.enc,
                password=PASSWORD,
                slot_id=slot_id,
                json=True,
            ),
        )
        self.assertEqual(doc["removed_slot_id"], slot_id)
        self.assertEqual(doc["output"], self.enc)
        self.assertEqual(len(list_recovery_slots(self.enc)), 1)

    def test_recover_reports_the_output_path(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        doc = self._run_json(
            recover_cli,
            _ns(input=self.enc, output=self.out, recovery_code=code, json=True),
        )
        self.assertEqual(doc["output"], self.out)


class TestInPlaceRewriteSelection(RecoveryJsonBase):
    """Same-file rewrites must not destroy the ciphertext they manage.

    The truncating path opens the user's ciphertext "wb", so a crash or
    ENOSPC mid-write destroys it. Adding or removing a recovery slot
    naturally targets the same file, which makes this the common case
    (gitlab#148).

    The CLI used to decide this itself, via a _rewrites_in_place() helper
    tested here. It no longer does: _write_envelope_header derives the
    choice immediately before the write, because a value computed in the
    CLI was computed before a multi-second KDF and could go stale, and
    because a caller that forgot it got the destructive path. That helper
    and the five unit tests that pinned its return value are gone --
    the predicates are now tested directly against the decision point in
    test_envelope_atomic_rewrite.py, including the symlink and hardlink
    exclusions. What remains here is the end-to-end property.
    """

    def test_in_place_rewrite_preserves_slot_contents(self):
        """End-to-end: the atomic path must produce the same result."""
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        add_recovery_cli(
            _ns(
                input=self.enc,
                output=self.enc,
                password=PASSWORD,
                add_code=True,
                json=True,
                recovery_code_out=os.path.join(self.tmp, "c.txt"),
            )
        )
        self.assertEqual(len(list_recovery_slots(self.enc)), 2)
        # The original credential still opens the rewritten file.
        recover_cli(_ns(input=self.enc, output=self.out, recovery_code=code))
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)


class TestJsonParserRegistration(unittest.TestCase):
    def test_all_four_subparsers_accept_json(self):
        from openssl_encrypt.modules.crypt_cli_subparser import (
            setup_add_recovery_parser,
            setup_list_recovery_parser,
            setup_recover_parser,
            setup_remove_recovery_parser,
        )

        cases = [
            (setup_list_recovery_parser, ["-i", "in.enc", "--json"]),
            (setup_recover_parser, ["-i", "in.enc", "-o", "out", "--json"]),
            (
                setup_add_recovery_parser,
                ["-i", "in.enc", "-o", "o", "--add-code", "--json", "--recovery-code-out", "c.txt"],
            ),
            (
                setup_remove_recovery_parser,
                ["-i", "in.enc", "-o", "o", "--slot-id", "x", "--json"],
            ),
        ]
        for setup, argv in cases:
            p = argparse.ArgumentParser()
            setup(p)
            self.assertTrue(p.parse_args(argv).json)


if __name__ == "__main__":
    unittest.main()
