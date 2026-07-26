#!/usr/bin/env python3
"""
Tests for the shared credential environment channel (gitlab#154, gitlab#159).

Two credentials had no non-interactive input path at all: the second password
for keyed hidden mode (`_resolve_second_password`) and the signer identity
passphrase (`sign`). Both reached only a `getpass()` prompt, which reads
/dev/tty and cannot be answered by the desktop GUI or any CI caller — so the
GUI hidden-header support and the Sign screen were unbuildable.

The fix generalizes the mechanism gitlab#144 built for recovery slots rather
than adding a third and fourth private copy of it.
"""

import os
import unittest
from unittest import mock

from openssl_encrypt.modules.credential_env import (
    CredentialError,
    consume_all,
    consume_env,
    resolve_credential,
    validated,
)

VAR = "OPENSSL_ENCRYPT_TEST_CREDENTIAL"
OTHER = "OPENSSL_ENCRYPT_TEST_CREDENTIAL_2"


def _restore_fingerprint_registry(test):
    """Snapshot and restore the process-global consumed-secret registry.

    `consume_env` registers every value it reads into a bounded per-name ring
    in security_logger. These tests consume real values, so without this they
    would evict entries that other tests in a full-suite run depend on.
    """
    from openssl_encrypt.modules import security_logger

    # Deep-ish copy: the values are per-name ring OrderedDicts, so a
    # shallow copy would restore the SAME mutated ring and per-name
    # eviction would still leak across tests.
    saved = {
        k: v.copy()
        for k, v in security_logger._consumed_secret_fingerprints.items()
    }

    def restore():
        security_logger._consumed_secret_fingerprints.clear()
        security_logger._consumed_secret_fingerprints.update(saved)

    test.addCleanup(restore)


class EnvTestCase(unittest.TestCase):
    def setUp(self):
        _restore_fingerprint_registry(self)
        for name in (VAR, OTHER):
            os.environ.pop(name, None)
            self.addCleanup(os.environ.pop, name, None)


class TestConsumeEnv(EnvTestCase):
    def test_an_absent_variable_is_none(self):
        self.assertIsNone(consume_env(VAR))

    def test_a_present_variable_is_returned_and_removed(self):
        os.environ[VAR] = "s3cret"
        self.assertEqual(consume_env(VAR), "s3cret")
        self.assertNotIn(VAR, os.environ, "the credential was left in the environment")

    def test_a_blank_variable_is_distinguishable_from_an_absent_one(self):
        """The distinction decides whether to fall through to a prompt.

        Collapsing them would make a GUI subprocess hang on a getpass() it can
        never answer, instead of failing fast.
        """
        os.environ[VAR] = ""
        self.assertEqual(consume_env(VAR), "")
        self.assertIsNone(consume_env(VAR), "a second read must see it gone")

    def test_the_value_is_registered_before_it_is_deleted(self):
        """Between read and delete it matches neither redaction check.

        A concurrent log_event from another thread would write it unredacted,
        so registration must not be deferred until after the delete.
        """
        os.environ[VAR] = "s3cret"
        seen = []

        def record(name, value):
            seen.append((name, value, name in os.environ))

        with mock.patch(
            "openssl_encrypt.modules.credential_env.register_consumed_secret",
            side_effect=record,
        ):
            consume_env(VAR)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], VAR)
        self.assertEqual(seen[0][1], "s3cret")
        self.assertTrue(seen[0][2], "registered after deletion, leaving a window")


class TestConsumeAll(EnvTestCase):
    def test_every_variable_is_consumed(self):
        os.environ[VAR] = "a"
        os.environ[OTHER] = "b"
        result = consume_all(VAR, OTHER)
        self.assertEqual(result, {VAR: "a", OTHER: "b"})
        self.assertNotIn(VAR, os.environ)
        self.assertNotIn(OTHER, os.environ)

    def test_absent_variables_map_to_none(self):
        self.assertEqual(consume_all(VAR), {VAR: None})


class TestValidated(unittest.TestCase):
    def test_a_blank_value_is_refused(self):
        for value in ("", "   ", "\t\n"):
            with self.subTest(value=value):
                with self.assertRaises(CredentialError):
                    validated(value, "$SOME_VAR")

    def test_a_real_value_is_returned_unchanged(self):
        """Not stripped: a credential must open through every channel.

        Normalizing here would mean a passphrase set through the environment
        would not match the same passphrase typed at a prompt.
        """
        self.assertEqual(validated("  spaced  ", "x"), "  spaced  ")

    def test_a_newline_is_refused_on_a_new_channel(self):
        for value in ("pw\n", "pw\r", "a\nb"):
            with self.subTest(value=value):
                with self.assertRaises(CredentialError):
                    validated(value, "$SOME_VAR")

    def test_a_newline_is_allowed_on_a_pre_existing_channel(self):
        """Byte semantics are load-bearing where files already exist.

        `--second-password` predates this rule, so a file encrypted with a
        newline-bearing value must stay decryptable; only the new environment
        channel enforces the restriction.
        """
        self.assertEqual(
            validated("pw\n", "--second-password", reject_newline=False), "pw\n"
        )

    def test_the_error_names_the_channel(self):
        with self.assertRaises(CredentialError) as ctx:
            validated("", "$OPENSSL_ENCRYPT_SOMETHING")
        self.assertIn("OPENSSL_ENCRYPT_SOMETHING", str(ctx.exception))


class TestResolveCredential(EnvTestCase):
    def test_the_environment_supplies_the_value(self):
        os.environ[VAR] = "from-env"
        self.assertEqual(resolve_credential(True, VAR, "prompt: "), "from-env")

    def test_an_explicit_value_wins_over_the_environment(self):
        os.environ[VAR] = "from-env"
        self.assertEqual(
            resolve_credential(True, VAR, "prompt: ", explicit="explicit"),
            "explicit",
        )

    def test_a_superseded_variable_is_still_consumed(self):
        """Otherwise it is inherited by a later child process.

        Several call sites run subprocess.run() with no env=.
        """
        os.environ[VAR] = "from-env"
        resolve_credential(True, VAR, "prompt: ", explicit="explicit")
        self.assertNotIn(VAR, os.environ)

    def test_the_environment_cannot_select_a_path_that_was_not_requested(self):
        """A planted variable must not route a secret into an unasked path.

        This is the property that keeps the environment a value channel rather
        than a control channel.
        """
        os.environ[VAR] = "planted"
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            self.assertIsNone(resolve_credential(False, VAR, "prompt: "))

    def test_a_variable_is_consumed_even_when_not_requested(self):
        os.environ[VAR] = "planted"
        resolve_credential(False, VAR, "prompt: ")
        self.assertNotIn(VAR, os.environ, "a planted value was left for a child")

    def test_a_blank_environment_value_fails_fast_rather_than_prompting(self):
        os.environ[VAR] = ""
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            with self.assertRaises(CredentialError):
                resolve_credential(True, VAR, "prompt: ")

    def test_falls_back_to_the_prompt_when_nothing_is_supplied(self):
        with mock.patch("getpass.getpass", return_value="typed") as prompt:
            self.assertEqual(resolve_credential(True, VAR, "prompt: "), "typed")
        prompt.assert_called_once_with("prompt: ")


class TestSecondPasswordUsesTheChannel(unittest.TestCase):
    """gitlab#154: keyed hidden mode had no non-interactive input path."""

    ENV = "OPENSSL_ENCRYPT_SECOND_PASSWORD"

    def setUp(self):
        _restore_fingerprint_registry(self)
        os.environ.pop(self.ENV, None)
        self.addCleanup(os.environ.pop, self.ENV, None)

    def _args(self, **kw):
        import argparse

        base = dict(
            second_password_fd=None, second_password=None,
            second_password_prompt=False, hidden_header=False,
            legacy_format=False, action="encrypt",
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def _resolve(self, **kw):
        from openssl_encrypt.modules.crypt_cli import _resolve_second_password

        return _resolve_second_password(self._args(**kw))

    def test_the_environment_supplies_it_once_the_feature_is_requested(self):
        os.environ[self.ENV] = "second-pw"
        self.assertEqual(self._resolve(hidden_header=True), b"second-pw")

    def test_a_planted_variable_alone_does_not_enable_keyed_hidden_mode(self):
        """The whole point of the `requested` guard.

        A non-None return here makes _hidden_for_encrypt turn hidden mode on,
        so if a bare variable sufficed, an exported value would silently write
        every file with a keyed hidden header the user never chose and cannot
        reproduce -- readable by whoever planted it, and locking the user out
        of their own metadata.
        """
        os.environ[self.ENV] = "planted"
        self.assertIsNone(self._resolve(), "a bare variable supplied a credential")

    def test_hidden_mode_stays_off_for_a_planted_variable(self):
        """Assert the DECISION, not just the resolver.

        The resolver returning None is only half the property; what matters is
        the mode actually chosen for the file.
        """
        from openssl_encrypt.modules.crypt_cli import (
            _hidden_for_encrypt,
            _resolve_second_password,
        )

        os.environ[self.ENV] = "planted"
        args = self._args()
        second = _resolve_second_password(args)
        self.assertFalse(
            _hidden_for_encrypt(args, second),
            "a planted variable silently switched the file to keyed hidden mode",
        )

    def test_the_variable_is_consumed(self):
        os.environ[self.ENV] = "second-pw"
        self._resolve(hidden_header=True)
        self.assertNotIn(self.ENV, os.environ)

    def test_an_unrequested_variable_is_consumed_too(self):
        """Otherwise it is inherited by a child even when unused."""
        os.environ[self.ENV] = "planted"
        self._resolve()
        self.assertNotIn(self.ENV, os.environ)

    def test_an_explicit_flag_still_wins(self):
        os.environ[self.ENV] = "from-env"
        self.assertEqual(
            self._resolve(second_password="from-flag", hidden_header=True),
            b"from-flag",
        )

    def test_a_superseded_variable_is_still_consumed(self):
        os.environ[self.ENV] = "from-env"
        self._resolve(second_password="from-flag", hidden_header=True)
        self.assertNotIn(self.ENV, os.environ, "left for a child process to inherit")

    def test_a_blank_environment_value_is_refused(self):
        os.environ[self.ENV] = ""
        with self.assertRaises(CredentialError):
            self._resolve(hidden_header=True)

    def test_a_blank_flag_value_is_refused_the_same_way(self):
        """`--second-password ""` used to fall through and yield keyless.

        Same user intent as a blank variable, two different outcomes; the
        erroring one is correct.
        """
        with self.assertRaises(CredentialError):
            self._resolve(second_password="")

    def test_a_value_with_a_trailing_newline_is_refused(self):
        """The fd and prompt channels both stop at the first newline.

        A GUI passing a text field's contents verbatim would otherwise derive
        a different header key from the same passphrase typed at the prompt,
        with no error at any point.
        """
        os.environ[self.ENV] = "second-pw\n"
        with self.assertRaises(CredentialError):
            self._resolve(hidden_header=True)

    def test_nothing_supplied_is_still_none(self):
        """The keyless / non-hidden case must be unaffected."""
        self.assertIsNone(self._resolve())

    def test_an_ignored_variable_is_reported_rather_than_dropped_silently(self):
        """Silence would leave a caller believing the metadata is keyed.

        The help text points callers at this variable, so setting it and
        getting a plain legacy-format file with cleartext metadata -- at exit
        code 0, with no output -- is the worst possible outcome.
        """
        import io
        from contextlib import redirect_stderr

        os.environ[self.ENV] = "planted"
        buf = io.StringIO()
        with redirect_stderr(buf):
            self.assertIsNone(self._resolve())
        message = buf.getvalue()
        self.assertIn("WARNING", message)
        self.assertIn(self.ENV, message)
        self.assertNotIn("planted", message, "the VALUE was echoed")

    def test_a_blank_flag_value_is_allowed_when_decrypting(self):
        """Data preservation beats strictness on the decrypt side.

        A file encrypted on an earlier release with a whitespace-only value
        must stay decryptable; the hard error belongs on encrypt, where
        wrapping under a guessable secret is the actual harm.
        """
        self.assertEqual(self._resolve(second_password="   ", action="decrypt"),
                         b"   ")

    def test_an_empty_fd_is_refused_when_encrypting(self):
        """An empty fd used to yield a silently KEYLESS header.

        hidden_header maps b"" back to "no second password", so a caller who
        asked for keyed mode got keyless -- exactly what --second-password ""
        now errors on.
        """
        r, w = os.pipe()
        os.close(w)
        try:
            with self.assertRaises(CredentialError):
                self._resolve(second_password_fd=r, hidden_header=True)
        finally:
            os.close(r)

    def test_main_with_args_never_touches_sys_before_its_local_import(self):
        """`main_with_args` has a local `import sys` partway down its body.

        That makes `sys` local to the WHOLE function, so any `sys.` use above
        that line raises UnboundLocalError at runtime. The CredentialError
        handler for the second password sits above it and originally used
        `sys.exit` / `file=sys.stderr`, so a rejected credential produced an
        UnboundLocalError instead of the clean exit it was written to give.

        Asserted statically rather than by driving the CLI: an end-to-end
        invocation exits 2 for argparse reasons too, so it cannot distinguish
        the handler working from the handler crashing.
        """
        import ast
        import inspect

        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(inspect.getsource(crypt_cli))
        func = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "main_with_args"
        )
        local_import = min(
            (n.lineno for n in ast.walk(func)
             if isinstance(n, ast.Import)
             for a in n.names if a.name == "sys"),
            default=None,
        )
        if local_import is None:
            self.skipTest("main_with_args no longer imports sys locally")

        early = [
            n.lineno for n in ast.walk(func)
            if isinstance(n, ast.Name) and n.id == "sys" and n.lineno < local_import
        ]
        self.assertEqual(
            early, [],
            f"`sys` used at lines {early}, before the local `import sys` at "
            f"line {local_import} -- these raise UnboundLocalError",
        )

    def test_the_variable_is_registered_for_log_redaction(self):
        from openssl_encrypt.modules.security_logger import _SECRET_ENV_VARS

        self.assertIn(self.ENV, _SECRET_ENV_VARS)


class TestSignerPassphraseUsesTheChannel(unittest.TestCase):
    """gitlab#159: `sign` reached only a getpass() prompt on /dev/tty."""

    ENV = "OPENSSL_ENCRYPT_SIGNER_PASSPHRASE"

    def setUp(self):
        _restore_fingerprint_registry(self)
        os.environ.pop(self.ENV, None)
        self.addCleanup(os.environ.pop, self.ENV, None)

    def test_the_variable_is_registered_for_log_redaction(self):
        from openssl_encrypt.modules.security_logger import _SECRET_ENV_VARS

        self.assertIn(self.ENV, _SECRET_ENV_VARS)

    def _passphrase_for(self, level):
        """Drive sign_file_cli far enough to capture the passphrase it uses.

        Calling resolve_credential directly with a hand-supplied `requested=`
        would prove nothing about the HSM_ONLY mapping in sign_file_cli, which
        is the actual new logic.
        """
        from openssl_encrypt.modules import file_signature

        meta = mock.Mock()
        meta.is_own_identity = True
        meta.protection = None if level is None else mock.Mock(level=level)

        store = mock.Mock()
        store.get_by_name.side_effect = [meta, RuntimeError("stop here")]

        # sign_file_cli imports these inside the function body, so the source
        # modules are the patch targets, not file_signature's namespace.
        args = mock.Mock(input="f.txt", output=None, armor=True, sign_with="signer")
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.resolve_identity_store_path",
            return_value=None,
        ), mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store",
            return_value=store,
        ), mock.patch(
            "getpass.getpass", side_effect=AssertionError("prompted")
        ), self.assertRaises(
            (RuntimeError, SystemExit)
        ):
            file_signature.sign_file_cli(args)
        return store.get_by_name.call_args_list

    def test_an_hsm_only_identity_is_not_given_a_planted_passphrase(self):
        """A planted variable must not introduce a passphrase.

        HSM_ONLY is exactly the case where Identity.load accepts
        passphrase=None, so requesting one would be wrong as well as unsafe.
        """
        from openssl_encrypt.modules.identity_protection import ProtectionLevel

        os.environ[self.ENV] = "planted"
        calls = self._passphrase_for(ProtectionLevel.HSM_ONLY)
        self.assertGreaterEqual(len(calls), 2, "never reached the key load")
        self.assertIsNone(
            calls[1].kwargs.get("passphrase"),
            "an HSM-only identity was handed a planted passphrase",
        )

    def test_a_password_protected_identity_uses_the_environment_value(self):
        from openssl_encrypt.modules.identity_protection import ProtectionLevel

        os.environ[self.ENV] = "signer-pw"
        calls = self._passphrase_for(ProtectionLevel.PASSWORD_ONLY)
        self.assertGreaterEqual(len(calls), 2, "never reached the key load")
        self.assertEqual(calls[1].kwargs.get("passphrase"), "signer-pw")

    def test_encrypt_sign_with_uses_the_same_variable(self):
        """`encrypt --sign-with` signs with the same identity as `sign`.

        It had its own bare getpass, so it was equally undriveable without a
        terminal. Only `sign_file_cli` is covered above, so without this a
        refactor could silently revert the encrypt-side wiring.
        """
        import ast
        import inspect

        from openssl_encrypt.modules import crypt_cli

        source = inspect.getsource(crypt_cli)
        self.assertIn("SIGNER_PASSPHRASE_ENV", source,
                      "the encrypt path no longer references the variable")
        # And that it goes through the shared resolver rather than a bare
        # prompt: a getpass here would reintroduce the /dev/tty dependency.
        tree = ast.parse(source)
        resolver_calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "resolve_credential"
        ]
        self.assertTrue(
            any(
                any(
                    isinstance(kw.value, ast.Name)
                    and kw.value.id == "SIGNER_PASSPHRASE_ENV"
                    for kw in call.keywords
                )
                for call in resolver_calls
            ),
            "encrypt --sign-with does not resolve through the shared channel",
        )

    def test_the_variable_is_consumed_even_for_an_hsm_only_identity(self):
        from openssl_encrypt.modules.identity_protection import ProtectionLevel

        os.environ[self.ENV] = "planted"
        self._passphrase_for(ProtectionLevel.HSM_ONLY)
        self.assertNotIn(self.ENV, os.environ, "left for a child process")


if __name__ == "__main__":
    unittest.main()
