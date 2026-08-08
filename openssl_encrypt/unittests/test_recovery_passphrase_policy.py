#!/usr/bin/env python3
"""
A recovery passphrase must meet the same policy as a password (gitlab#149).

`_validated_passphrase` (added under gitlab#144) rejected only blank and
whitespace-only values, so a one-character recovery passphrase was accepted.
A recovery slot is an *additional* wrapping of the same DEK, so a file's
confidentiality is that of its weakest slot -- and Argon2id at t=3/64 MiB
does not rescue a one-character secret. Meanwhile the primary password from
`OPENSSL_ENCRYPT_PASSWORD` *was* policy-checked. The weaker credential on the
same key got the weaker check, which is backwards.

The asymmetry that matters here, and the reason this is not simply "validate
everywhere":

  * ADDING a slot is a choice being made now, so the policy applies.
  * UNLOCKING an existing slot is not. Enforcing there would refuse a
    passphrase the user already has, on a file whose primary password is
    typically already lost -- turning a weak-credential warning into
    permanent data loss. Those tests are the load-bearing ones below.

`--force-password` overrides, as it does for the primary password, because a
recovery passphrase the user cannot change is better used than refused.
"""

import os
import unittest
from unittest import mock

from openssl_encrypt.modules import recovery_slots

PASSWORD = b"Tr0ub4dor&3-Correct-Horse!"
WEAK = "abc"
STRONG = "Tr0ub4dor&3-Correct-Horse-Battery!"


class _Args:
    """Only the attributes the policy path reads."""

    def __init__(self, **kwargs):
        self.quiet = True
        self.force_password = False
        self.password_policy = "standard"
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestAddingASlotEnforcesThePolicy(unittest.TestCase):
    def test_a_weak_passphrase_is_refused(self):
        from openssl_encrypt.modules.crypt_errors import ValidationError

        with self.assertRaises(ValidationError):
            recovery_slots._policy_checked_passphrase(WEAK, "test", _Args())

    def test_a_strong_passphrase_is_accepted_unmodified(self):
        result = recovery_slots._policy_checked_passphrase(STRONG, "test", _Args())
        self.assertEqual(
            result,
            STRONG,
            "the passphrase was modified; a slot wrapped under one string and "
            "looked up under another is permanently unopenable",
        )

    def test_force_password_overrides(self):
        result = recovery_slots._policy_checked_passphrase(WEAK, "test", _Args(force_password=True))
        self.assertEqual(result, WEAK)

    def test_a_blank_passphrase_is_still_refused_even_with_force(self):
        """--force-password is for weak, not for absent.

        A blank-passphrase slot is equivalent to publishing the file: anyone
        can unwrap it, so no override should reach it.
        """
        for blank in ("", "   ", "\t\n"):
            with self.assertRaises(ValueError):
                recovery_slots._policy_checked_passphrase(blank, "test", _Args(force_password=True))

    def test_the_policy_level_is_honoured(self):
        """`--password-policy minimal` should relax it, as it does elsewhere."""
        relaxed = "abcdefghijkl"
        try:
            recovery_slots._policy_checked_passphrase(
                relaxed, "test", _Args(password_policy="minimal")
            )
        except Exception as error:  # noqa: BLE001 - reporting which level refused
            self.fail(f"the minimal policy refused a 12-character passphrase: {error}")

        # The negative arm: without it, this passes even if the policy is
        # skipped entirely.
        with self.assertRaises(Exception):
            recovery_slots._policy_checked_passphrase(
                relaxed, "test", _Args(password_policy="standard")
            )

    def test_policy_none_is_not_a_bypass(self):
        """`--password-policy none` is gone from the choices, and a namespace
        carrying it (main_with_args back-fills that value) must not disable
        the check."""
        with self.assertRaises(Exception):
            recovery_slots._policy_checked_passphrase(WEAK, "test", _Args(password_policy="none"))

    def test_no_args_means_only_the_blank_check(self):
        """WEAK, not STRONG: with STRONG this passes whether or not the policy
        ran, which pins nothing."""
        self.assertEqual(recovery_slots._policy_checked_passphrase(WEAK, "test", None), WEAK)
        with self.assertRaises(ValueError):
            recovery_slots._policy_checked_passphrase("   ", "test", None)


class TestUnlockingAnExistingSlotDoesNotEnforce(unittest.TestCase):
    """The load-bearing tests.

    A slot created before this change -- or with --force-password -- must
    still open. Enforcing the policy at unlock time would refuse a
    passphrase the user already holds, on a file whose primary password is
    usually already gone. That converts "you chose a weak credential" into
    permanent data loss.

    This line has no credential environment channel (gitlab#144 is 1.4.x
    only), so the unlock path prompts; these drive that.
    """

    def test_the_unlock_path_does_not_policy_check(self):
        import inspect

        from openssl_encrypt.modules.recovery_slots import _recover_kwargs_from_args

        source = inspect.getsource(_recover_kwargs_from_args)
        self.assertNotIn(
            "_policy_checked_passphrase",
            source,
            "unlocking policy-checks the passphrase, so an existing weak slot "
            "can no longer be opened",
        )

    def test_a_weak_passphrase_reaches_the_unlock_kwargs_unchanged(self):
        from openssl_encrypt.modules.recovery_slots import _recover_kwargs_from_args

        with mock.patch("getpass.getpass", return_value=WEAK):
            kwargs = _recover_kwargs_from_args(_Args(recovery_passphrase=True))
        self.assertEqual(kwargs.get("recovery_passphrase"), WEAK)


class TestTheAddPathBehaves(unittest.TestCase):
    """Behavioural, not source-text.

    The first version of this asserted `inspect.getsource(...)` contained the
    helper's name twice. That passes if the identifier appears in a comment,
    says nothing about whether the checked value is the one that reaches the
    slot, and would not have caught the three tests in a fourth file that this
    change broke. These drive the real CLI instead.
    """

    def setUp(self):
        import shutil
        import tempfile

        from openssl_encrypt.modules.crypt_core import encrypt_file

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.enc = os.path.join(self.tmp, "p.enc")
        self.out = os.path.join(self.tmp, "p.out")
        # Same shape as the other recovery suites: bytes in, envelope out.
        data = encrypt_file(
            input_file=b"RECOVERY-CANARY",
            output_file=None,
            password=PASSWORD,
            algorithm="aes-gcm",
            quiet=True,
            envelope=True,
        )
        with open(self.enc, "wb") as handle:
            handle.write(data)

    def _args(self, **kwargs):
        import argparse

        base = dict(
            input=self.enc,
            output=self.enc,
            password=PASSWORD.decode(),
            add_passphrase=True,
            add_code=False,
            add_shares=None,
            recovery_code=None,
            recovery_passphrase=False,
            json=False,
            recovery_code_out=None,
            quiet=True,
            force_password=False,
            password_policy="standard",
            allow_high_kdf_cost=False,
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_a_weak_passphrase_creates_no_slot(self):
        from openssl_encrypt.modules.crypt_core import list_recovery_slots
        from openssl_encrypt.modules.recovery_slots import add_recovery_cli

        with mock.patch("getpass.getpass", return_value=WEAK):
            with self.assertRaises(Exception):
                add_recovery_cli(self._args())

        self.assertEqual(
            list_recovery_slots(self.enc), [], "a weak passphrase was wrapped into a slot"
        )

    def test_force_password_creates_a_weak_slot_that_still_opens(self):
        """Closes both halves of the backward-compatibility question.

        A deliberately weak slot must be creatable, and -- because unlocking
        is not policy-checked -- it must still open afterwards.
        """
        from openssl_encrypt.modules.crypt_core import list_recovery_slots
        from openssl_encrypt.modules.recovery_slots import add_recovery_cli, recover_cli

        with mock.patch("getpass.getpass", return_value=WEAK):
            add_recovery_cli(self._args(force_password=True))

        slots = list_recovery_slots(self.enc)
        self.assertEqual([s["type"] for s in slots], ["passphrase"])

        with mock.patch("getpass.getpass", return_value=WEAK):
            recover_cli(self._args(output=self.out, recovery_passphrase=True))
        with open(self.out, "rb") as handle:
            self.assertEqual(handle.read(), b"RECOVERY-CANARY")


if __name__ == "__main__":
    unittest.main()
