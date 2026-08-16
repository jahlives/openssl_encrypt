#!/usr/bin/env python3
"""
`--json` machine-readable output on the recovery-slot commands (gitlab#277).

The gitlab#146 --json work (1.4.x commit dac23fcd) was never ported when the
1.5.x line diverged, yet the capabilities manifest already advertises --json
for list-recovery/add-recovery/remove-recovery/recover — so a GUI trusting
the manifest breaks. This ports the behavior, adapted to the 1.5.x surface
(shamir share slots; no env-passphrase channel).

Credential-delivery rule carried over from 1.4.x: a generated recovery code
is password-equivalent and never travels on stdout (target of `> file`,
merged by `2>&1`) or stderr (terminal scrollback, GUI debug log). Under
--json it must go to a caller-named 0600 file via --recovery-code-out, and
the JSON carries only that path.
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
        recovery_share=None,
        add_code=False,
        add_passphrase=False,
        add_shares=None,
        shares_dir=".",
        slot_id=None,
        json=False,
        recovery_code_out=None,
        password_policy="standard",
        force_password=False,
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
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(self.tmp)

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
        """Run a handler with --json and return the envelope's data payload.

        All 1.5.x JSON endpoints emit through the total-json envelope
        (gitlab#268): {"status": "ok", "data": <payload>} — one document on
        stdout.
        """
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn(ns)
        envelope = json.loads(buf.getvalue())
        self.assertEqual(envelope["status"], "ok")
        return envelope["data"]


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
        """The human view truncates key_id to 16 chars; JSON must not."""
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

        envelope = json.loads(out.getvalue())
        self.assertEqual(envelope["status"], "ok")
        doc = envelope["data"]
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

    def test_passphrase_slot_reports_source_and_no_code(self):
        self._encrypt()
        with mock.patch("getpass.getpass", return_value="A-Rec0very-Phrase-With-Entropy!"):
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
        self.assertIn("interactively", doc["credential_source"])
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


class TestAddSharesJson(RecoveryJsonBase):
    """--add-shares is 1.5.x-only; its JSON must carry paths, never secrets."""

    def test_add_shares_json_reports_paths_and_parameters(self):
        self._encrypt()
        share_dir = os.path.join(self.tmp, "shares")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_shares="2-of-3",
                    shares_dir=share_dir,
                    json=True,
                )
            )

        envelope = json.loads(out.getvalue())
        self.assertEqual(envelope["status"], "ok")
        doc = envelope["data"]
        self.assertEqual(doc["slot_type"], "shamir")
        self.assertEqual(doc["threshold"], 2)
        self.assertEqual(doc["num_shares"], 3)
        self.assertEqual(len(doc["shares"]), 3)
        for p in doc["shares"]:
            self.assertTrue(os.path.isfile(p), p)
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
        # No share content or reconstructed secret in the document or streams.
        for p in doc["shares"]:
            with open(p) as f:
                share_json = json.load(f)
            self.assertNotIn(str(share_json["data"]), out.getvalue())

        # Two of the three shares actually recover the file.
        recover_cli(
            _ns(
                input=self.enc, output=self.out, recovery_share=[doc["shares"][0], doc["shares"][2]]
            )
        )
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_add_shares_without_json_prints_nothing_to_stdout(self):
        self._encrypt()
        share_dir = os.path.join(self.tmp, "shares")
        out = io.StringIO()
        with redirect_stdout(out):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_shares="2-of-3",
                    shares_dir=share_dir,
                )
            )
        self.assertEqual(out.getvalue(), "")


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

    def test_recover_without_json_prints_nothing_to_stdout(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])
        out = io.StringIO()
        with redirect_stdout(out):
            recover_cli(_ns(input=self.enc, output=self.out, recovery_code=code))
        self.assertEqual(out.getvalue(), "")


class TestJsonStreamOutputRefusal(unittest.TestCase):
    """--json cannot share stdout with a payload stream (gitlab#277 review).

    recover writes user plaintext to --output; add-/remove-recovery copy the
    attacker-influenceable envelope payload verbatim. Aimed at a stdout
    device, those bytes would precede (and could forge) the one JSON
    document, so the invocation is refused up front — before any password
    source is consumed.
    """

    def _run(self, argv):
        import subprocess
        import sys as _sys

        return subprocess.run(
            [_sys.executable, "-m", "openssl_encrypt.crypt", *argv],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
        )

    def test_stream_outputs_are_refused_for_the_writing_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = os.path.join(tmp, "probe.enc")
            with open(probe, "w") as f:
                f.write("x")
            cases = [
                ["recover", "-i", probe, "-o", "/dev/stdout", "--recovery-code", "A", "--json"],
                ["add-recovery", "-i", probe, "-o", "-", "--add-passphrase", "--json"],
                ["remove-recovery", "-i", probe, "-o", "/dev/fd/1", "--slot-id", "x", "--json"],
            ]
            for argv in cases:
                r = self._run(argv)
                self.assertEqual(r.returncode, 2, argv)
                envelope = json.loads(r.stdout)
                self.assertEqual(envelope["status"], "error", argv)


class TestUntrustedHeaderBounds(RecoveryJsonBase):
    def test_slot_list_is_capped_with_explicit_marker(self):
        from openssl_encrypt.modules.recovery_slots import MAX_DEK_SLOTS

        creds = [
            {"type": "recovery_code", "code": generate_recovery_code()}
            for _ in range(MAX_DEK_SLOTS + 1)
        ]
        self._encrypt(creds)
        buf = io.StringIO()
        with redirect_stdout(buf):
            list_recovery_cli(_ns(input=self.enc, json=True))
        envelope = json.loads(buf.getvalue())
        self.assertEqual(envelope["status"], "ok")
        self.assertEqual(len(envelope["data"]["slots"]), MAX_DEK_SLOTS)
        self.assertTrue(envelope["data"]["truncated"])

    def test_write_recovery_code_file_rejects_non_base32_value_free(self):
        from openssl_encrypt.modules.recovery_slots import _write_recovery_code_file

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as ctx:
                _write_recovery_code_file(os.path.join(tmp, "c.txt"), "sécret-é")
            self.assertNotIn("é", str(ctx.exception))
            self.assertEqual(os.listdir(tmp), [])


class TestManifestJsonFields(unittest.TestCase):
    def test_recovery_endpoints_declare_their_data_fields(self):
        from openssl_encrypt.modules.capabilities import _JSON_FIELDS as fields

        # metadata_authenticated + truncated joined the declared surface in
        # gitlab#280/#279 (unauthenticated-listing marker, cap marker).
        self.assertEqual(fields["list-recovery"], ["metadata_authenticated", "slots", "truncated"])
        self.assertEqual(fields["recover"], ["output"])
        self.assertEqual(fields["add-recovery"], ["output", "slot_type", "credential_source"])
        self.assertEqual(fields["remove-recovery"], ["output", "removed_slot_id"])


class TestJsonErrorEnvelope(unittest.TestCase):
    """A JSON caller must get its one document even on failure (gitlab#268)."""

    def test_list_recovery_failure_emits_error_envelope_on_stdout(self):
        import subprocess
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(
                [
                    _sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "list-recovery",
                    "-i",
                    os.path.join(tmp, "missing.enc"),
                    "--json",
                ],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=300,
            )
            self.assertNotEqual(r.returncode, 0)
            envelope = json.loads(r.stdout)
            self.assertEqual(envelope["status"], "error")
            self.assertIn("message", envelope["error"])


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
            ns = p.parse_args(argv)
            self.assertTrue(getattr(ns, "json", False))


if __name__ == "__main__":
    unittest.main()
