#!/usr/bin/env python3
"""
TDD tests for secret redaction in debug output (--unsafe-show-secrets).

``--debug`` historically printed secret material (key material, KDF
intermediates, the FIDO2 hardware pepper, user plaintext) in cleartext,
guarded only by a prominent warning. The new default redacts every secret to

    <label>: <redacted: N bytes, sha256:XXXXXXXXXXXX>

(N = byte length, fingerprint = first 12 hex chars of the SHA-256 of the raw
value) so the log structure stays identical and it remains possible to see
whether a secret changed between steps without seeing it. Cleartext output
requires the explicit opt-in ``--debug --unsafe-show-secrets``; the flag
without ``--debug`` is an error. All secret output flows through the single
chokepoint ``debug_secret()`` in ``modules/debug_redaction.py``.
"""

import hashlib
import os
import re
import shutil
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

from openssl_encrypt.modules.debug_redaction import (
    debug_secret,
    secret_fingerprint,
    set_show_secrets,
    show_secrets_enabled,
)

REDACTION_RE = re.compile(r"<redacted: (?P<n>\d+) bytes, sha256:(?P<fp>[0-9a-f]{12})>")


def _fp(raw: bytes) -> str:
    """Expected fingerprint: keyed (per-process) truncated HMAC-SHA256."""
    return secret_fingerprint(raw)


class DebugSecretHelperTests(unittest.TestCase):
    """Unit tests for the debug_secret() chokepoint itself."""

    def tearDown(self):
        set_show_secrets(False)

    def test_default_is_redacted(self):
        """Module state defaults to redaction; no opt-in leaks across imports."""
        self.assertFalse(show_secrets_enabled())
        self.assertIn("<redacted:", debug_secret("KEY", b"\x01\x02\x03"))

    def test_redaction_format_exact(self):
        """Redaction format: <label>: <redacted: N bytes, sha256:XXXXXXXXXXXX>."""
        value = b"super-secret-key-material"
        out = debug_secret("ENCRYPT:KEY Final derived key", value)
        self.assertEqual(
            out,
            f"ENCRYPT:KEY Final derived key: "
            f"<redacted: {len(value)} bytes, sha256:{_fp(value)}>",
        )

    def test_redaction_format_regex(self):
        """The rendered value part matches the documented shape."""
        out = debug_secret("LABEL", os.urandom(64))
        m = REDACTION_RE.search(out)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group("n")), 64)

    def test_same_value_same_fingerprint(self):
        """Stable fingerprint: identical secrets compare equal across log lines."""
        value = os.urandom(32)
        out1 = debug_secret("STEP1", value)
        out2 = debug_secret("STEP2", value)
        fp1 = REDACTION_RE.search(out1).group("fp")
        fp2 = REDACTION_RE.search(out2).group("fp")
        self.assertEqual(fp1, fp2)

    def test_different_values_different_fingerprint(self):
        """Different secrets must be visibly different in redacted logs."""
        out1 = debug_secret("STEP", b"A" * 32)
        out2 = debug_secret("STEP", b"B" * 32)
        fp1 = REDACTION_RE.search(out1).group("fp")
        fp2 = REDACTION_RE.search(out2).group("fp")
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_is_keyed_not_plain_sha256(self):
        """The fingerprint must NOT be the unkeyed truncated SHA-256 of the
        value: a plain hash would let anyone holding the log offline-confirm a
        guessed (low-entropy) password. The ephemeral per-process HMAC key
        keeps same-run comparability without creating that oracle."""
        value = b"correct horse battery staple"
        fp = REDACTION_RE.search(debug_secret("PW", value)).group("fp")
        self.assertNotEqual(fp, hashlib.sha256(value).hexdigest()[:12])

    def test_redacted_output_contains_no_raw_value(self):
        """Neither hex nor the raw bytes of the secret appear when redacted."""
        value = os.urandom(32)
        out = debug_secret("KEY", value)
        self.assertNotIn(value.hex(), out)
        self.assertNotIn(value.hex().upper(), out)

    def test_unsafe_mode_shows_hex_cleartext(self):
        """With the override the current cleartext (hex) behavior is preserved."""
        value = os.urandom(32)
        set_show_secrets(True)
        self.assertEqual(debug_secret("KEY", value), f"KEY: {value.hex()}")

    def test_unsafe_mode_str_passthrough(self):
        """A str secret (e.g. the Fernet base64 key) is shown verbatim."""
        fernet_key = "q0PDgHVwjxAcnbpQJTYCTMLerBvHlSSpJx5-Y2xqmz0="
        set_show_secrets(True)
        self.assertEqual(debug_secret("FERNET Key", fernet_key), f"FERNET Key: {fernet_key}")

    def test_str_value_fingerprinted_over_utf8(self):
        """Redacted str secrets: N and fingerprint computed over the UTF-8 bytes."""
        secret = "q0PDgHVwjxAcnbpQJTYCTMLerBvHlSSpJx5-Y2xqmz0="
        out = debug_secret("FERNET Key", secret)
        raw = secret.encode("utf-8")
        self.assertEqual(out, f"FERNET Key: <redacted: {len(raw)} bytes, sha256:{_fp(raw)}>")
        self.assertNotIn(secret, out)

    def test_bytearray_and_memoryview_accepted(self):
        """KDF paths hold secrets in bytearrays; both bytes-likes are accepted."""
        raw = os.urandom(16)
        for value in (bytearray(raw), memoryview(raw)):
            out = debug_secret("KDF", value)
            self.assertIn(f"<redacted: 16 bytes, sha256:{_fp(raw)}>", out)

    def test_empty_label_returns_bare_rendering(self):
        """An empty label yields just the rendered value (for embedding, e.g. argv)."""
        value = b"cli-password"
        out = debug_secret("", value)
        self.assertEqual(out, f"<redacted: {len(value)} bytes, sha256:{_fp(value)}>")
        set_show_secrets(True)
        self.assertEqual(debug_secret("", value), value.hex())


class GenerateKeyRedactionTests(unittest.TestCase):
    """The KDF pipeline must emit secrets only through debug_secret()."""

    PASSWORD = b"redaction-suite-known-password"
    SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ARGON2_CHEAP = {
        "argon2": {
            "enabled": True,
            "time_cost": 1,
            "memory_cost": 512,
            "parallelism": 1,
            "type": "id",
        }
    }

    def tearDown(self):
        set_show_secrets(False)

    def _derive_with_logs(self):
        from openssl_encrypt.modules.crypt_core import generate_key

        with self.assertLogs(level="DEBUG") as cm:
            key, _, _ = generate_key(
                self.PASSWORD,
                self.SALT,
                self.ARGON2_CHEAP,
                quiet=True,
                algorithm="aes-gcm",
                debug=True,
                format_version=13,
            )
        return bytes(key), "\n".join(cm.output)

    def test_redacted_by_default(self):
        """debug=True derivation emits redaction markers and no password hex."""
        key, logs = self._derive_with_logs()
        self.assertIn("<redacted:", logs)
        self.assertNotIn(self.PASSWORD.hex(), logs)
        self.assertNotIn(key.hex(), logs)

    def test_unsafe_mode_shows_cleartext(self):
        """With the override the raw KDF input (the password) appears again."""
        set_show_secrets(True)
        _, logs = self._derive_with_logs()
        self.assertIn(self.PASSWORD.hex(), logs)
        self.assertNotIn("<redacted:", logs)

    def test_redacted_fingerprint_identifies_the_secret(self):
        """The Round-1 KDF input is password||salt; its redacted fingerprint
        must be the fingerprint of exactly those bytes, so a reader can tell
        whether the same secret flows through different steps of one run."""
        _, logs = self._derive_with_logs()
        self.assertIn(f"sha256:{_fp(self.PASSWORD + self.SALT)}", logs)


class ArgvSanitizerTests(unittest.TestCase):
    """Unit tests for sanitize_argv_for_debug().

    Regression: the first sanitizer only covered ``-p``/``--password``;
    values of --second-password, --keystore-password, --manifest-password,
    --rekey-password, --recovery-code, --encryption-data and the
    ``--opt=value`` / attached ``-pVALUE`` forms leaked in cleartext in the
    ``DEBUG: sys.argv = ...`` dump.
    """

    SECRET = "S3cr3t-Argv-Value!"

    def tearDown(self):
        set_show_secrets(False)

    def _sanitize(self, argv):
        from openssl_encrypt.modules.crypt_cli import sanitize_argv_for_debug

        return sanitize_argv_for_debug(argv)

    def test_expected_secret_options_enrolled(self):
        """Pin the option inventory: dropping one must fail this test."""
        from openssl_encrypt.modules.crypt_cli import SECRET_VALUE_CLI_OPTIONS

        expected = {
            "-p",
            "--password",
            "--second-password",
            "--keystore-password",
            "--manifest-password",
            "--rekey-password",
            "--recovery-code",
            "--encryption-data",
        }
        self.assertTrue(
            expected <= set(SECRET_VALUE_CLI_OPTIONS),
            f"missing: {expected - set(SECRET_VALUE_CLI_OPTIONS)}",
        )

    def test_every_secret_option_value_is_redacted(self):
        """`--opt value` form: the value is redacted for EVERY enrolled option."""
        from openssl_encrypt.modules.crypt_cli import SECRET_VALUE_CLI_OPTIONS

        for opt in sorted(SECRET_VALUE_CLI_OPTIONS):
            with self.subTest(option=opt):
                out = self._sanitize(["crypt.py", "encrypt", opt, self.SECRET, "--verbose"])
                joined = " ".join(out)
                self.assertNotIn(self.SECRET, joined)
                self.assertIn("<redacted:", joined)
                # Structure preserved: only the value slot was rewritten.
                self.assertEqual(out[0], "crypt.py")
                self.assertEqual(out[1], "encrypt")
                self.assertEqual(out[2], opt)
                self.assertEqual(out[4], "--verbose")

    def test_eq_form_is_redacted(self):
        """`--opt=value` form keeps the option name, redacts the value."""
        from openssl_encrypt.modules.crypt_cli import SECRET_VALUE_CLI_OPTIONS

        for opt in sorted(o for o in SECRET_VALUE_CLI_OPTIONS if o.startswith("--")):
            with self.subTest(option=opt):
                out = self._sanitize(["crypt.py", f"{opt}={self.SECRET}"])
                self.assertNotIn(self.SECRET, " ".join(out))
                self.assertTrue(out[1].startswith(f"{opt}=<redacted:"))

    def test_attached_short_form_is_redacted(self):
        """`-pVALUE` (argparse attached short option) is redacted too."""
        out = self._sanitize(["crypt.py", f"-p{self.SECRET}"])
        self.assertNotIn(self.SECRET, " ".join(out))
        self.assertTrue(out[1].startswith("-p<redacted:"))

    def test_consecutive_secret_options(self):
        """`--password x --keystore-password y`: both values redacted."""
        out = self._sanitize(
            ["crypt.py", "--password", "first-pw", "--keystore-password", "second-pw"]
        )
        joined = " ".join(out)
        self.assertNotIn("first-pw", joined)
        self.assertNotIn("second-pw", joined)
        self.assertEqual(joined.count("<redacted:"), 2)

    def test_secret_option_as_last_argument(self):
        """A trailing secret option without a value must not crash or mangle."""
        out = self._sanitize(["crypt.py", "encrypt", "--password"])
        self.assertEqual(out, ["crypt.py", "encrypt", "--password"])

    def test_non_secret_arguments_untouched(self):
        """Non-secret options and values pass through byte-identical."""
        argv = ["crypt.py", "--quiet", "encrypt", "--input", "file.txt", "--argon2-rounds", "3"]
        self.assertEqual(self._sanitize(argv), argv)

    def test_unsafe_mode_shows_values_verbatim(self):
        """With --unsafe-show-secrets active the sanitizer passes str values
        through in cleartext (same chokepoint, same opt-in)."""
        set_show_secrets(True)
        out = self._sanitize(["crypt.py", "--keystore-password", self.SECRET])
        self.assertEqual(out[2], self.SECRET)


class UnsafeShowSecretsCLITests(unittest.TestCase):
    """CLI flag wiring: validation, redaction default, cleartext opt-in."""

    PW = "RedactionCliPassword123!"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.dir, "msg.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"debug redaction CLI round-trip content")
        self.out_file = os.path.join(self.dir, "msg.enc")
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        shutil.rmtree(self.dir, ignore_errors=True)
        set_show_secrets(False)

    def _run_encrypt(self, extra_flags):
        """Run `encrypt` in-process; return (exit_code, stderr_text)."""
        from openssl_encrypt.modules.crypt_cli import main as cli_main

        sys.argv = [
            "crypt.py",
            "--quiet",
            "encrypt",
            "--input",
            self.test_file,
            "--output",
            self.out_file,
            "--force-password",
            "--algorithm",
            "fernet",
            "--argon2-rounds",
            "1",
        ] + list(extra_flags)
        stderr = StringIO()
        code = 0
        with mock.patch("getpass.getpass", return_value=self.PW):
            with mock.patch("sys.stderr", stderr):
                try:
                    cli_main()
                except SystemExit as e:
                    code = e.code if e.code is not None else 0
        return code, stderr.getvalue()

    def _run_encrypt_with_logs(self, extra_flags):
        """Like _run_encrypt but also captures DEBUG log records."""
        with self.assertLogs(level="DEBUG") as cm:
            code, stderr_text = self._run_encrypt(extra_flags)
        return code, stderr_text, "\n".join(cm.output)

    def test_unsafe_show_secrets_without_debug_is_an_error(self):
        """--unsafe-show-secrets without --debug must exit with a clear error."""
        code, stderr_text = self._run_encrypt(["--unsafe-show-secrets"])
        self.assertNotEqual(code, 0)
        self.assertIn("--unsafe-show-secrets", stderr_text)
        self.assertIn("--debug", stderr_text)
        # Refused before doing any work: no output file was produced.
        self.assertFalse(os.path.exists(self.out_file))

    def test_debug_redacts_secrets_by_default(self):
        """Plain --debug: redaction markers present, no secret bytes anywhere."""
        code, stderr_text, logs = self._run_encrypt_with_logs(["--debug"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.out_file))
        self.assertIn("<redacted:", logs)
        # The final derived key line keeps its label but not its value.
        self.assertRegex(
            logs,
            r"ENCRYPT:KEY Final derived key for [^:]+: "
            r"<redacted: \d+ bytes, sha256:[0-9a-f]{12}>",
        )
        # No raw secret bytes in any debug output (known-secret scan).
        pw_hex = self.PW.encode("utf-8").hex()
        self.assertNotIn(pw_hex, logs)
        self.assertNotIn(pw_hex, stderr_text)
        self.assertNotRegex(logs, r"ENCRYPT:KEY Final derived key for [^:]+: [0-9a-f]{32,}")
        # The warning tells the user redaction is active.
        self.assertIn("REDACTED", stderr_text)

    def test_debug_with_unsafe_shows_cleartext_and_warns(self):
        """--debug --unsafe-show-secrets: cleartext values + explicit warning."""
        code, stderr_text, logs = self._run_encrypt_with_logs(["--debug", "--unsafe-show-secrets"])
        self.assertEqual(code, 0)
        self.assertNotIn("<redacted:", logs)
        # The final derived key is shown in cleartext hex again.
        self.assertRegex(logs, r"ENCRYPT:KEY Final derived key for [^:]+: [0-9a-f]{32,}")
        # The prominent warning explicitly says secrets are being shown.
        self.assertIn("CLEARTEXT", stderr_text)

    def test_plain_debug_omits_loud_leak_banner(self):
        """Plain --debug no longer leaks secrets, so the loud SENSITIVE-DATA
        banner and the 'do not use on production' notice must NOT fire. Only a
        calm note stating redaction is active (and how to opt into cleartext)
        is shown."""
        code, stderr_text, _ = self._run_encrypt_with_logs(["--debug"])
        self.assertEqual(code, 0)
        # Loud, now-inaccurate framing is gone on the redacted path.
        self.assertNotIn("SENSITIVE DATA LOGGING ACTIVE", stderr_text)
        self.assertNotIn("DO NOT use", stderr_text)
        # A calm note still tells the user redaction is active and how to
        # reveal secrets if they really need to.
        self.assertIn("REDACTED", stderr_text)
        self.assertIn("--unsafe-show-secrets", stderr_text)
        # The one caution that still materially applies in redacted mode is
        # retained: lengths + public values reach stderr and may persist.
        self.assertIn("persist", stderr_text)

    def test_unsafe_debug_keeps_loud_banner(self):
        """--debug --unsafe-show-secrets is the path that actually leaks, so it
        must keep the loud SENSITIVE-DATA banner and the production warning."""
        code, stderr_text, _ = self._run_encrypt_with_logs(["--debug", "--unsafe-show-secrets"])
        self.assertEqual(code, 0)
        self.assertIn("SENSITIVE DATA LOGGING ACTIVE", stderr_text)
        self.assertIn("DO NOT use", stderr_text)
        self.assertIn("CLEARTEXT", stderr_text)

    def test_argv_dump_redacts_cli_password(self):
        """--debug dumps sys.argv; a password passed as an option value must
        be redacted there (regression: only -p/--password were covered, and
        other secret-valued flags leaked in cleartext)."""
        code, stderr_text, logs = self._run_encrypt_with_logs(["--debug", "--password", self.PW])
        self.assertEqual(code, 0)
        self.assertIn("sys.argv", stderr_text)
        self.assertNotIn(self.PW, stderr_text)
        self.assertNotIn(self.PW, logs)
        self.assertIn("<redacted:", stderr_text)

    def test_argv_dump_shows_cli_password_in_unsafe_mode(self):
        """With --unsafe-show-secrets the argv dump shows the password again
        (str secrets are rendered verbatim in cleartext mode)."""
        code, stderr_text, _ = self._run_encrypt_with_logs(
            ["--debug", "--unsafe-show-secrets", "--password", self.PW]
        )
        self.assertEqual(code, 0)
        self.assertIn("sys.argv", stderr_text)
        self.assertIn(self.PW, stderr_text)

    def test_unsafe_flag_is_global_position_independent(self):
        """The flag is accepted before the subcommand too (global-flag set)."""
        from openssl_encrypt.modules.crypt_cli import main as cli_main

        sys.argv = [
            "crypt.py",
            "--unsafe-show-secrets",
            "--quiet",
            "encrypt",
            "--input",
            self.test_file,
            "--output",
            self.out_file,
            "--force-password",
            "--algorithm",
            "fernet",
            "--argon2-rounds",
            "1",
        ]
        stderr = StringIO()
        code = 0
        with mock.patch("getpass.getpass", return_value=self.PW):
            with mock.patch("sys.stderr", stderr):
                try:
                    cli_main()
                except SystemExit as e:
                    code = e.code if e.code is not None else 0
        self.assertNotEqual(code, 0)
        self.assertIn("--unsafe-show-secrets", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
