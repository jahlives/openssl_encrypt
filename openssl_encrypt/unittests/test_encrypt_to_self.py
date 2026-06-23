#!/usr/bin/env python3
"""
Tests for feature #6: encrypt-to-self.

When encrypting *for a recipient*, the sender's own identity is added as an
additional recipient by default so the sender can later decrypt their own
outbound file (avoiding a common data-loss footgun). Opt out with
--no-encrypt-to-self.

Test classes:
- TestResolveRecipientsWithSelf: the pure recipient-resolution helper (no
  liboqs required; uses lightweight stub identities).
- TestEncryptToSelfRoundTrip: end-to-end at the crypto layer — the sender can
  decrypt their own outbound file when encrypt-to-self is on, and cannot when
  it is off (gated on liboqs availability).
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.identity import resolve_recipients_with_self


class _StubIdentity:
    """Minimal duck-typed identity exposing only what the helper touches."""

    def __init__(self, fingerprint, name="stub"):
        self.fingerprint = fingerprint
        self.name = name


class TestResolveRecipientsWithSelf(unittest.TestCase):
    """The pure encrypt-to-self recipient-resolution helper."""

    def setUp(self):
        self.r1 = _StubIdentity("fp-recipient-1", "R1")
        self.r2 = _StubIdentity("fp-recipient-2", "R2")
        self.sender = _StubIdentity("fp-sender", "Sender")

    def test_appends_sender_when_enabled(self):
        out = resolve_recipients_with_self([self.r1, self.r2], self.sender, enabled=True)
        self.assertIn(self.sender, out)
        self.assertEqual(len(out), 3)
        # Order preserved; sender appended last.
        self.assertEqual(out[-1], self.sender)

    def test_disabled_leaves_recipients_unchanged(self):
        out = resolve_recipients_with_self([self.r1, self.r2], self.sender, enabled=False)
        self.assertEqual(out, [self.r1, self.r2])
        self.assertNotIn(self.sender, out)

    def test_no_duplicate_when_sender_already_recipient(self):
        """Sender already explicitly listed (by fingerprint) is not duplicated."""
        sender_dup = _StubIdentity("fp-sender", "Sender-as-recipient")
        out = resolve_recipients_with_self([self.r1, sender_dup], self.sender, enabled=True)
        # No extra slot added; exactly the two originals.
        self.assertEqual(len(out), 2)
        sender_fps = [r.fingerprint for r in out if r.fingerprint == "fp-sender"]
        self.assertEqual(len(sender_fps), 1)

    def test_does_not_mutate_input_list(self):
        recipients = [self.r1]
        out = resolve_recipients_with_self(recipients, self.sender, enabled=True)
        self.assertEqual(len(recipients), 1)  # original untouched
        self.assertEqual(len(out), 2)

    def test_empty_recipients_gets_sender(self):
        out = resolve_recipients_with_self([], self.sender, enabled=True)
        self.assertEqual(out, [self.sender])

    def test_none_sender_is_noop(self):
        out = resolve_recipients_with_self([self.r1], None, enabled=True)
        self.assertEqual(out, [self.r1])


try:
    from openssl_encrypt.modules.crypt_core import (
        decrypt_file_asymmetric,
        encrypt_file_asymmetric,
    )
    from openssl_encrypt.modules.identity import Identity
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestEncryptToSelfRoundTrip(unittest.TestCase):
    """Crypto-level proof that encrypt-to-self lets the sender decrypt."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sender = Identity.generate("Sender", "sender@example.com", "sender_pass")
        self.recipient = Identity.generate("Recipient", "rcpt@example.com", "rcpt_pass")
        self.test_file = os.path.join(self.temp_dir, "msg.txt")
        self.content = "Outbound secret the sender may need to recover later."
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write(self.content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _decrypt_as(self, identity, encrypted_file, tag):
        out = os.path.join(self.temp_dir, f"dec_{tag}.txt")
        decrypt_file_asymmetric(
            input_file=encrypted_file,
            output_file=out,
            recipient=identity,
            sender_public_key=self.sender.signing_public_key,
            quiet=True,
        )
        with open(out, "r", encoding="utf-8") as f:
            return f.read()

    def test_sender_can_decrypt_own_file_when_enabled(self):
        recipients = resolve_recipients_with_self([self.recipient], self.sender, enabled=True)
        enc = os.path.join(self.temp_dir, "to_self.enc")
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=enc,
            recipients=recipients,
            sender=self.sender,
            quiet=True,
        )
        # The intended recipient can read it...
        self.assertEqual(self._decrypt_as(self.recipient, enc, "rcpt"), self.content)
        # ...and so can the sender (the whole point of the feature).
        self.assertEqual(self._decrypt_as(self.sender, enc, "self"), self.content)

    def test_sender_cannot_decrypt_when_disabled(self):
        recipients = resolve_recipients_with_self([self.recipient], self.sender, enabled=False)
        enc = os.path.join(self.temp_dir, "no_self.enc")
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=enc,
            recipients=recipients,
            sender=self.sender,
            quiet=True,
        )
        # Recipient still works.
        self.assertEqual(self._decrypt_as(self.recipient, enc, "rcpt"), self.content)
        # Sender is not a recipient -> decryption must fail.
        with self.assertRaises(Exception):
            self._decrypt_as(self.sender, enc, "self")


if __name__ == "__main__":
    unittest.main()
