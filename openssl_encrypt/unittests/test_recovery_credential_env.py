#!/usr/bin/env python3
"""
Tests for the env-var input path for recovery credentials (gitlab#144 /
github#62).

A non-interactive caller (the desktop GUI) cannot put a recovery code on argv
without leaking it to the process list, and cannot answer a getpass() prompt
that reads /dev/tty. These tests pin the env-var channel that replaces both:
the value is read from the environment and removed immediately, mirroring
OPENSSL_ENCRYPT_REKEY_PASSWORD (crypt_cli.py:6785-6791).
"""

import argparse
import os
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_core import encrypt_file, list_recovery_slots
from openssl_encrypt.modules.recovery_slots import (
    ADD_RECOVERY_PASSPHRASE_ENV,
    RECOVERY_CODE_ENV,
    RECOVERY_PASSPHRASE_ENV,
    add_recovery_cli,
    generate_recovery_code,
    recover_cli,
    remove_recovery_cli,
)

PASSWORD = b"primary-cli-password"
PLAINTEXT = b"recovery env round-trip payload\n" * 6


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
        quiet=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


class RecoveryEnvBase(unittest.TestCase):
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


class TestRecoveryCodeFromEnv(RecoveryEnvBase):
    def test_recover_uses_env_code_and_consumes_it(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: code}):
            recover_cli(_ns(input=self.enc, output=self.out))
            # The credential must not linger in the environment of anything
            # this process spawns later.
            self.assertNotIn(RECOVERY_CODE_ENV, os.environ)

        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_empty_env_value_is_treated_as_unset(self):
        self._encrypt([{"type": "recovery_code", "code": generate_recovery_code()}])
        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: ""}):
            with self.assertRaises(ValueError):
                recover_cli(_ns(input=self.enc, output=self.out))

    def test_explicit_flag_takes_precedence_over_env(self):
        real = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": real}])

        # The env var holds a wrong code; the flag must win, so recovery works.
        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: generate_recovery_code()}):
            recover_cli(_ns(input=self.enc, output=self.out, recovery_code=real))
            # The unused env credential must still be consumed: several call
            # sites run subprocess.run() with no env=, so anything left behind
            # is inherited by a later child.
            self.assertNotIn(RECOVERY_CODE_ENV, os.environ)

        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_flag_on_argv_warns_about_process_list(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch("openssl_encrypt.modules.recovery_slots.eprint") as ep:
            recover_cli(_ns(input=self.enc, output=self.out, recovery_code=code))

        warnings = [c for c in ep.call_args_list if "process list" in str(c)]
        self.assertTrue(warnings, "expected a process-list warning for --recovery-code")

    def test_add_recovery_unlocks_with_env_code(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: code}):
            add_recovery_cli(_ns(input=self.enc, output=self.enc, add_code=True))
            self.assertNotIn(RECOVERY_CODE_ENV, os.environ)

        self.assertEqual(len(list_recovery_slots(self.enc)), 2)

    def test_remove_recovery_unlocks_with_env_code(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        self._encrypt(
            [{"type": "recovery_code", "code": c1}, {"type": "recovery_code", "code": c2}]
        )
        slot_id = list_recovery_slots(self.enc)[0]["id"]

        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: c1}):
            remove_recovery_cli(_ns(input=self.enc, output=self.enc, slot_id=slot_id))
            self.assertNotIn(RECOVERY_CODE_ENV, os.environ)

        self.assertEqual(len(list_recovery_slots(self.enc)), 1)


class TestEnvCannotSelectCredentialPath(RecoveryEnvBase):
    """The env var supplies a value; only an explicit flag selects the path.

    Otherwise anyone able to plant a variable in the user's environment once
    would get a durable extra decryption path into every file subsequently
    passed to add-recovery (security review 2026-07-25, finding 1).
    """

    def test_env_passphrase_alone_does_not_add_a_slot(self):
        self._encrypt()
        with mock.patch.dict(
            os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: "planted backdoor phrase"}
        ):
            with self.assertRaises(ValueError):
                add_recovery_cli(_ns(input=self.enc, output=self.enc, password=PASSWORD))

        self.assertEqual(list_recovery_slots(self.enc), [])

    def test_env_passphrase_alone_does_not_select_recover_path(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])
        with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: "planted phrase"}):
            # No --recovery-passphrase flag and no code: must refuse, not
            # silently try the planted passphrase.
            with self.assertRaises(ValueError):
                recover_cli(_ns(input=self.enc, output=self.out))


class TestBlankEnvCredentials(RecoveryEnvBase):
    """A blank env value must fail fast, never fall through to a tty prompt.

    getpass() with no controlling tty reads stdin, so a GUI subprocess would
    hang indefinitely (security review 2026-07-25, finding 5).
    """

    def test_blank_add_passphrase_env_raises_without_prompting(self):
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: "   "}):
                with self.assertRaises(ValueError):
                    add_recovery_cli(
                        _ns(
                            input=self.enc,
                            output=self.enc,
                            password=PASSWORD,
                            add_passphrase=True,
                        )
                    )
            gp.assert_not_called()

    def test_blank_recover_passphrase_env_raises_without_prompting(self):
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: "   "}):
                with self.assertRaises(ValueError):
                    recover_cli(
                        _ns(input=self.enc, output=self.out, recovery_passphrase=True)
                    )
            gp.assert_not_called()

    def test_truly_empty_add_passphrase_env_raises_without_prompting(self):
        """VAR="" must fail fast, not be treated as "unset" and prompt."""
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: ""}):
                with self.assertRaises(ValueError):
                    add_recovery_cli(
                        _ns(
                            input=self.enc,
                            output=self.enc,
                            password=PASSWORD,
                            add_passphrase=True,
                        )
                    )
            gp.assert_not_called()

    def test_truly_empty_recover_passphrase_env_raises_without_prompting(self):
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: ""}):
                with self.assertRaises(ValueError):
                    recover_cli(
                        _ns(input=self.enc, output=self.out, recovery_passphrase=True)
                    )
            gp.assert_not_called()

    def test_blank_recovery_code_env_does_not_prompt_on_add(self):
        """VAR="" must not degrade into a password prompt on the add path.

        recover_cli fails fast only because it has no password fallback; add and
        remove do, so they need their own coverage (re-review finding 2).
        """
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: ""}):
                with self.assertRaises(ValueError):
                    add_recovery_cli(
                        _ns(input=self.enc, output=self.enc, add_code=True)
                    )
            gp.assert_not_called()

    def test_blank_recovery_code_env_does_not_prompt_on_remove(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        self._encrypt(
            [{"type": "recovery_code", "code": c1}, {"type": "recovery_code", "code": c2}]
        )
        slot_id = list_recovery_slots(self.enc)[0]["id"]
        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: ""}):
                with self.assertRaises(ValueError):
                    remove_recovery_cli(
                        _ns(input=self.enc, output=self.enc, slot_id=slot_id)
                    )
            gp.assert_not_called()

    def test_early_error_still_consumes_every_credential(self):
        """A raise partway through must not strand the other credentials.

        _read_recovery_code raises on a set-but-empty variable; consumption of
        everything else must already have happened (final review, NEW-1).
        """
        self._encrypt()
        with mock.patch.dict(
            os.environ,
            {
                RECOVERY_CODE_ENV: "",
                RECOVERY_PASSPHRASE_ENV: "stranded",
                ADD_RECOVERY_PASSPHRASE_ENV: "stranded",
                "CRYPT_PASSWORD": "stranded",
            },
        ):
            with self.assertRaises(ValueError):
                add_recovery_cli(_ns(input=self.enc, output=self.enc, add_code=True))
            for name in (
                RECOVERY_CODE_ENV,
                RECOVERY_PASSPHRASE_ENV,
                ADD_RECOVERY_PASSPHRASE_ENV,
                "CRYPT_PASSWORD",
            ):
                self.assertNotIn(name, os.environ)

    def test_selector_usage_error_still_consumes_credentials(self):
        self._encrypt()
        with mock.patch.dict(
            os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: "stranded", "CRYPT_PASSWORD": "x"}
        ):
            with self.assertRaises(ValueError):
                add_recovery_cli(_ns(input=self.enc, output=self.enc))
            self.assertNotIn(ADD_RECOVERY_PASSPHRASE_ENV, os.environ)
            self.assertNotIn("CRYPT_PASSWORD", os.environ)

    def test_empty_env_var_is_removed_not_left_behind(self):
        self._encrypt([{"type": "recovery_code", "code": generate_recovery_code()}])
        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: ""}):
            with self.assertRaises(ValueError):
                recover_cli(_ns(input=self.enc, output=self.out))
            self.assertNotIn(RECOVERY_CODE_ENV, os.environ)


class TestPassphraseFromEnv(RecoveryEnvBase):
    def test_add_passphrase_from_env_without_prompting(self):
        self._encrypt()
        phrase = "env supplied recovery phrase"

        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: phrase}):
                add_recovery_cli(
                    _ns(input=self.enc, output=self.enc, password=PASSWORD, add_passphrase=True)
                )
                self.assertNotIn(ADD_RECOVERY_PASSPHRASE_ENV, os.environ)
            gp.assert_not_called()

        self.assertEqual(list_recovery_slots(self.enc)[0]["type"], "passphrase")

    def test_recover_passphrase_from_env_without_prompting(self):
        self._encrypt()
        phrase = "env supplied recovery phrase"

        with mock.patch.dict(os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: phrase}):
            add_recovery_cli(
                _ns(input=self.enc, output=self.enc, password=PASSWORD, add_passphrase=True)
            )

        with mock.patch("getpass.getpass") as gp:
            with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: phrase}):
                recover_cli(
                    _ns(input=self.enc, output=self.out, recovery_passphrase=True)
                )
                self.assertNotIn(RECOVERY_PASSPHRASE_ENV, os.environ)
            gp.assert_not_called()

        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)


class TestInteractivePassphraseValidation(RecoveryEnvBase):
    """An empty interactive passphrase must not create a slot.

    A recovery slot is an additional wrapping of the same DEK, so a slot wrapped
    under "" lets anyone unwrap the file — two Enter presses would otherwise be
    enough to create one (security review 2026-07-25 re-review, finding 1).
    """

    def test_two_empty_prompts_do_not_create_a_slot(self):
        self._encrypt()
        with mock.patch("getpass.getpass", return_value=""):
            with self.assertRaises(ValueError):
                add_recovery_cli(
                    _ns(
                        input=self.enc,
                        output=self.enc,
                        password=PASSWORD,
                        add_passphrase=True,
                    )
                )
        self.assertEqual(list_recovery_slots(self.enc), [])

    def test_whitespace_only_prompt_does_not_create_a_slot(self):
        self._encrypt()
        with mock.patch("getpass.getpass", return_value="   "):
            with self.assertRaises(ValueError):
                add_recovery_cli(
                    _ns(
                        input=self.enc,
                        output=self.enc,
                        password=PASSWORD,
                        add_passphrase=True,
                    )
                )
        self.assertEqual(list_recovery_slots(self.enc), [])

    def test_passphrase_is_not_silently_normalized(self):
        """A slot added with surrounding whitespace must open with it intact.

        Stripping on one channel but not the other would leave the slot
        permanently unopenable through the other one.
        """
        self._encrypt()
        padded = "  pass phrase  "

        with mock.patch("getpass.getpass", return_value=padded):
            add_recovery_cli(
                _ns(input=self.enc, output=self.enc, password=PASSWORD, add_passphrase=True)
            )

        with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: padded}):
            recover_cli(_ns(input=self.enc, output=self.out, recovery_passphrase=True))

        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)


class TestUnusedCredentialsAreConsumed(RecoveryEnvBase):
    """No recovery env var may survive an invocation that did not use it."""

    def test_unused_passphrase_env_consumed_when_code_path_taken(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch.dict(
            os.environ,
            {RECOVERY_CODE_ENV: code, RECOVERY_PASSPHRASE_ENV: "unused phrase"},
        ):
            recover_cli(_ns(input=self.enc, output=self.out))
            self.assertNotIn(RECOVERY_PASSPHRASE_ENV, os.environ)

    def test_unused_add_passphrase_env_consumed_when_add_code_used(self):
        self._encrypt()
        with mock.patch.dict(
            os.environ, {ADD_RECOVERY_PASSPHRASE_ENV: "unused phrase"}
        ):
            add_recovery_cli(
                _ns(input=self.enc, output=self.enc, password=PASSWORD, add_code=True)
            )
            self.assertNotIn(ADD_RECOVERY_PASSPHRASE_ENV, os.environ)

    def test_recover_consumes_credentials_it_never_uses(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch.dict(
            os.environ,
            {
                RECOVERY_CODE_ENV: code,
                ADD_RECOVERY_PASSPHRASE_ENV: "unused",
                "CRYPT_PASSWORD": "unused-primary",
            },
        ):
            recover_cli(_ns(input=self.enc, output=self.out))
            self.assertNotIn(ADD_RECOVERY_PASSPHRASE_ENV, os.environ)
            self.assertNotIn("CRYPT_PASSWORD", os.environ)

    def test_crypt_password_consumed_even_when_code_unlocks(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        with mock.patch.dict(
            os.environ, {RECOVERY_CODE_ENV: code, "CRYPT_PASSWORD": "unused-primary"}
        ):
            add_recovery_cli(_ns(input=self.enc, output=self.enc, add_code=True))
            self.assertNotIn("CRYPT_PASSWORD", os.environ)


class TestSelectorValidatedBeforeCredentials(RecoveryEnvBase):
    def test_missing_selector_fails_before_prompting(self):
        """Usage error must not be preceded by a blocking getpass()."""
        self._encrypt()
        with mock.patch("getpass.getpass") as gp:
            with self.assertRaises(ValueError):
                add_recovery_cli(_ns(input=self.enc, output=self.enc))
            gp.assert_not_called()

    def test_both_selectors_is_an_error(self):
        self._encrypt()
        with self.assertRaises(ValueError):
            add_recovery_cli(
                _ns(
                    input=self.enc,
                    output=self.enc,
                    password=PASSWORD,
                    add_code=True,
                    add_passphrase=True,
                )
            )


class TestConsumedSecretRedaction(unittest.TestCase):
    """Redaction must survive consumption of the variable.

    _value_looks_secret resolves _SECRET_ENV_VARS against the LIVE environment,
    so once _consume_env has deleted the variable that comparison can never
    match. Asserting mere tuple membership manufactured false assurance
    (security review 2026-07-25, finding 2), so assert actual redaction.
    """

    def test_consumed_recovery_code_is_still_redacted(self):
        from openssl_encrypt.modules.recovery_slots import _consume_env
        from openssl_encrypt.modules.security_logger import _value_looks_secret

        code = generate_recovery_code()
        # A grouped-base32 recovery code has no 32-char contiguous run (the
        # groups are '-' separated), so the entropy heuristic does not catch it.
        self.assertFalse(_value_looks_secret(code))

        with mock.patch.dict(os.environ, {RECOVERY_CODE_ENV: code}):
            self.assertEqual(_consume_env(RECOVERY_CODE_ENV), code)

        self.assertNotIn(RECOVERY_CODE_ENV, os.environ)
        self.assertTrue(_value_looks_secret(code))

    def test_consumed_passphrase_is_still_redacted(self):
        from openssl_encrypt.modules.recovery_slots import _consume_env
        from openssl_encrypt.modules.security_logger import _value_looks_secret

        # Short and low-entropy: neither heuristic would flag it.
        phrase = "correct horse battery"
        self.assertFalse(_value_looks_secret(phrase))

        with mock.patch.dict(os.environ, {RECOVERY_PASSPHRASE_ENV: phrase}):
            _consume_env(RECOVERY_PASSPHRASE_ENV)

        self.assertTrue(_value_looks_secret(phrase))

    def test_env_names_registered_for_the_unconsumed_case(self):
        from openssl_encrypt.modules.security_logger import _SECRET_ENV_VARS

        for name in (RECOVERY_CODE_ENV, RECOVERY_PASSPHRASE_ENV, ADD_RECOVERY_PASSPHRASE_ENV):
            self.assertIn(name, _SECRET_ENV_VARS)


if __name__ == "__main__":
    unittest.main()
