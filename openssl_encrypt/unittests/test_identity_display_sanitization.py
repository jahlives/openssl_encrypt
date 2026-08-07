#!/usr/bin/env python3
"""
Tests for terminal-escape sanitization of identity display paths (gitlab#172).

`Identity.import_public` validates `name` but took `email` completely raw, and
the CLI printed it straight to the terminal via `eprint` (a bare `print`).
A JSON string may contain `\\u001b`, so an imported bundle carrying

    "email": "x\\u001b[1A\\u001b[2KFingerprint: <trusted fp>\\u001b[1A"

could overwrite or precede the genuine `Fingerprint:` line. Out-of-band
fingerprint comparison is the ONLY authenticity mechanism this design has
(identity.py, check_fingerprint_consistency SECURITY NOTE), so forging that
line attacks the trust model directly. The same class existed on the error
paths: a rejected name or alias was interpolated verbatim into the
IdentityError message, which the CLI echoes.

Note SecureJSONValidator rejects *literal* control characters but not
`\\uXXXX` escape sequences, whose source text is printable -- routing the
document through the validator does not close this.
"""

import argparse
import base64
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.crypt_utils import sanitize_for_display
from openssl_encrypt.modules.identity import (
    Identity,
    IdentityError,
    validate_identity_created_at,
    validate_identity_email,
    validate_identity_fingerprint,
    validate_identity_name,
)

# The attack string from the issue — cursor-up, erase-line, forged line —
# plus a one-byte C1 CSI (\x9b), so an assertion passes only if the WHOLE
# class stays covered, not just ESC.
FORGED = "x\x1b[1A\x1b[2K\x9b2KFingerprint: AA:BB:CC:DD:EE:FF\x1b[1A"

# Output must contain nothing from the terminal-control class. Asserting
# against the class (not just "\x1b") means narrowing the sanitizer back to
# C0-only (dropping DEL/C1) would fail these tests. Newline is exempt: the
# captured stream contains eprint's own structural line breaks — what must
# never appear is a newline smuggled inside a VALUE, and the payloads here
# would surface any other class member if one leaked through.
CONTROL_CLASS = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def assert_no_controls(testcase, output):
    testcase.assertIsNone(CONTROL_CLASS.search(output), repr(output))


class TestSanitizeForDisplay(unittest.TestCase):
    """The helper itself: escape everything < 0x20, 0x7f, and C1."""

    def test_esc_is_escaped(self):
        self.assertEqual(sanitize_for_display("a\x1bb"), "a\\x1bb")

    def test_c0_controls_are_escaped(self):
        self.assertEqual(sanitize_for_display("a\nb"), "a\\nb")
        self.assertEqual(sanitize_for_display("a\rb"), "a\\rb")
        self.assertEqual(sanitize_for_display("a\x00b"), "a\\x00b")
        self.assertEqual(sanitize_for_display("a\tb"), "a\\tb")

    def test_del_is_escaped(self):
        self.assertEqual(sanitize_for_display("a\x7fb"), "a\\x7fb")

    def test_c1_controls_are_escaped(self):
        """C1 CSI (0x9b) is a one-byte escape-sequence introducer on some
        terminals, so the C1 range must be covered, not only ESC."""
        for ch in ("\x80", "\x9b", "\x9f"):
            with self.subTest(ch=hex(ord(ch))):
                result = sanitize_for_display(f"a{ch}b")
                self.assertNotIn(ch, result)
                self.assertTrue(result.startswith("a\\x"), result)

    def test_printable_text_is_unchanged(self):
        for text in ("alice@example.com", "héllo wörld", "名前", "a b.c-d_e"):
            with self.subTest(text=text):
                self.assertEqual(sanitize_for_display(text), text)

    def test_non_string_input_is_coerced(self):
        """Error-path callers pass exception objects, not strings."""
        self.assertEqual(sanitize_for_display(IdentityError("bad\x1bname")), "bad\\x1bname")

    def test_forged_fingerprint_line_is_neutralized(self):
        result = sanitize_for_display(FORGED)
        assert_no_controls(self, result)
        self.assertIn("\\x1b", result)
        self.assertIn("\\x9b", result)

    def test_backslash_is_escaped_for_unambiguity(self):
        """A literal 7-char "a\\x1b[1A" must not render identically to an
        escaped real ESC, or the evidence trail is forgeable."""
        self.assertEqual(sanitize_for_display("a\\x1b"), "a\\\\x1b")
        self.assertNotEqual(sanitize_for_display("a\\x1b[1A"), sanitize_for_display("a\x1b[1A"))

    def test_bidi_overrides_are_escaped(self):
        """VTE/Kitty honour bidi controls, which can visually reverse an
        email within its line (moc.elpmaxe -> example.com spoofing)."""
        for ch in ("\u202e", "\u202a", "\u2066", "\u200f"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertNotIn(ch, sanitize_for_display(f"a{ch}b"))


class TestEmailValidation(unittest.TestCase):
    """import_public must validate email like it validates name."""

    def test_none_is_accepted(self):
        validate_identity_email(None)

    def test_plain_email_is_accepted(self):
        validate_identity_email("alice@example.com")

    def test_non_string_is_rejected(self):
        for value in ({}, [], 42, b"a@b"):
            with self.subTest(value=value):
                with self.assertRaises(IdentityError):
                    validate_identity_email(value)

    def test_overlong_email_is_rejected(self):
        with self.assertRaises(IdentityError):
            validate_identity_email("a" * 315 + "@example.com")

    def test_control_characters_are_rejected(self):
        for ch in ("\x1b", "\n", "\r", "\x00", "\x7f", "\x9b"):
            with self.subTest(ch=hex(ord(ch))):
                with self.assertRaises(IdentityError):
                    validate_identity_email(f"a{ch}b@example.com")

    def test_bidi_and_line_separators_are_rejected(self):
        """Widened for gitlab#183: these pass every terminal-escape check but
        reorder text in any UAX #9 renderer (Flutter), and U+2028/U+2029 are
        mandatory line breaks under UAX #14 — so a GUI consumer of the
        machine-readable channel would render attacker text on its own line."""
        for cp in (0x061C, 0x200E, 0x200F, 0x202A, 0x202E, 0x2028, 0x2029, 0x2066, 0x2069):
            with self.subTest(cp=hex(cp)):
                with self.assertRaises(IdentityError):
                    validate_identity_email(f"a{chr(cp)}b@example.com")
                with self.assertRaises(IdentityError):
                    validate_identity_created_at(f"2026-01-01{chr(cp)}")

    def test_zero_width_joiners_are_still_accepted(self):
        """ZWNJ/ZWJ are load-bearing in Persian and Indic scripts and in
        emoji sequences; the display side neutralizes them instead."""
        validate_identity_email(f"a{chr(0x200C)}b{chr(0x200D)}c@example.com")

    def test_rejection_message_carries_no_raw_control_chars(self):
        try:
            validate_identity_email(FORGED)
        except IdentityError as e:
            self.assertNotIn("\x1b", str(e))
        else:
            self.fail("control-character email was accepted")

    def test_import_public_rejects_crafted_email(self):
        """End-to-end through the actual import path: a document whose email
        carries the forged-fingerprint payload must be refused."""
        data = {
            "name": "mallory",
            "email": FORGED,
            "fingerprint": "aa:bb:cc:dd",
            "created_at": "2026-01-01T00:00:00",
            "encryption_algorithm": "ML-KEM-768",
            "signing_algorithm": "ML-DSA-65",
            "encryption_public_key": base64.b64encode(b"ek").decode(),
            "signing_public_key": base64.b64encode(b"sk").decode(),
        }
        with mock.patch.object(Identity, "check_fingerprint_consistency", return_value=True):
            with self.assertRaises(IdentityError):
                Identity.import_public(data)

    def test_import_public_still_accepts_a_clean_document(self):
        data = {
            "name": "alice",
            "email": "alice@example.com",
            "fingerprint": "aa:bb:cc:dd",
            "created_at": "2026-01-01T00:00:00",
            "encryption_algorithm": "ML-KEM-768",
            "signing_algorithm": "ML-DSA-65",
            "encryption_public_key": base64.b64encode(b"ek").decode(),
            "signing_public_key": base64.b64encode(b"sk").decode(),
        }
        with mock.patch.object(Identity, "check_fingerprint_consistency", return_value=True):
            identity = Identity.import_public(data)
        self.assertEqual(identity.email, "alice@example.com")


class TestErrorMessagesSanitized(unittest.TestCase):
    """A rejected name/alias is echoed by `eprint(f"ERROR: {e}")` -- the
    interpolated value must reach the message escaped, not verbatim."""

    def test_rejected_name_is_escaped_in_the_message(self):
        try:
            validate_identity_name(FORGED)
        except IdentityError as e:
            self.assertNotIn("\x1b", str(e))
            self.assertIn("\\x1b", str(e))
        else:
            self.fail("control-character name was accepted")

    def test_rejected_dotdot_name_stays_informative(self):
        """The '..' branch interpolates too; regex-valid names cannot carry
        control characters, but the message must still name the offender."""
        try:
            validate_identity_name("a..b")
        except IdentityError as e:
            self.assertIn("a..b", str(e))
        else:
            self.fail("'..' name was accepted")


class _CmdTestBase(unittest.TestCase):
    """Shared plumbing for CLI display tests, mirroring
    test_identity_import_data.py."""

    @staticmethod
    def _identity(email):
        identity = mock.Mock(spec=Identity)
        identity.name = "mallory"
        identity.email = email
        identity.fingerprint = "11:22:33"
        identity.encryption_algorithm = "ML-KEM-768"
        identity.signing_algorithm = "ML-DSA-65"
        identity.encryption_public_key = b"ek"
        identity.signing_public_key = b"sk"
        identity.is_own_identity = False
        identity.protection = None
        return identity


class TestImportDisplaySanitized(_CmdTestBase):
    def _run_import(self, identity, stdin_doc):
        from openssl_encrypt.modules.identity_cli import cmd_import

        args = argparse.Namespace(
            data_stdin=True,
            file=None,
            alias=None,
            overwrite=False,
            allow_key_change=False,
            identity_store=None,
        )
        stderr = io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.identity.Identity.import_public",
            return_value=identity,
        ), mock.patch("openssl_encrypt.modules.identity_cli.get_identity_store"), mock.patch(
            "sys.stdin", io.StringIO(stdin_doc)
        ):
            with redirect_stderr(stderr):
                status = cmd_import(args)
        return status, stderr.getvalue()

    def test_import_success_output_carries_no_raw_escapes(self):
        """The primary attack: forged email printed directly above the
        genuine Fingerprint: line on import success."""
        status, output = self._run_import(self._identity(FORGED), json.dumps({"name": "mallory"}))
        self.assertEqual(status, 0)
        assert_no_controls(self, output)

    def test_rejected_alias_is_echoed_escaped(self):
        from openssl_encrypt.modules.identity_cli import cmd_import

        args = argparse.Namespace(
            data_stdin=True,
            file=None,
            alias=FORGED,
            overwrite=False,
            allow_key_change=False,
            identity_store=None,
        )
        stderr = io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.identity.Identity.import_public",
            return_value=self._identity(None),
        ), mock.patch("openssl_encrypt.modules.identity_cli.get_identity_store"), mock.patch(
            "sys.stdin", io.StringIO(json.dumps({"name": "m"}))
        ):
            with redirect_stderr(stderr):
                status = cmd_import(args)
        self.assertNotEqual(status, 0)
        assert_no_controls(self, stderr.getvalue())


class TestListShowDisplaySanitized(_CmdTestBase):
    """Contacts imported before this fix may already sit in the store with a
    crafted email; list/show must not replay the attack from disk."""

    def test_list_output_carries_no_raw_escapes(self):
        from openssl_encrypt.modules.identity_cli import cmd_list

        args = argparse.Namespace(identity_store=None, include_contacts=True)
        store = mock.Mock()
        store.list_identities.return_value = [self._identity(FORGED)]
        store.find_shadowed_names.return_value = []
        stderr = io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store",
            return_value=store,
        ):
            with redirect_stderr(stderr):
                status = cmd_list(args)
        self.assertEqual(status, 0)
        assert_no_controls(self, stderr.getvalue())

    def test_show_output_carries_no_raw_escapes(self):
        from openssl_encrypt.modules.identity_cli import cmd_show

        args = argparse.Namespace(identity_store=None, identity_name="mallory")
        store = mock.Mock()
        store.get_by_name.return_value = self._identity(FORGED)
        stderr = io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store",
            return_value=store,
        ):
            with redirect_stderr(stderr):
                status = cmd_show(args)
        self.assertEqual(status, 0)
        assert_no_controls(self, stderr.getvalue())


class TestFieldValidators(unittest.TestCase):
    """fingerprint and created_at get the same import contract as email."""

    def test_valid_fingerprint_is_accepted(self):
        validate_identity_fingerprint(
            ":".join(["ab"] * 32)  # SHA-256 shape, the format the tool writes
        )

    def test_crafted_fingerprints_are_rejected(self):
        for fp in (FORGED, "AA:BB", "not a fingerprint", "aabb", "aa", "", None, 42):
            with self.subTest(fp=fp):
                with self.assertRaises(IdentityError):
                    validate_identity_fingerprint(fp)

    def test_rejection_message_omits_the_fingerprint(self):
        try:
            validate_identity_fingerprint(FORGED)
        except IdentityError as e:
            assert_no_controls(self, str(e))

    def test_created_at_accepts_iso_timestamp(self):
        validate_identity_created_at("2026-01-01T00:00:00Z")

    def test_created_at_rejects_controls_length_and_type(self):
        for value in (FORGED, "a" * 65, None, 42):
            with self.subTest(value=value):
                with self.assertRaises(IdentityError):
                    validate_identity_created_at(value)

    def test_import_public_validates_before_construction(self):
        """The crafted email must be refused even when the rest of the
        document is unusable -- validation runs before the Identity object
        (and its base64/fingerprint machinery) exists."""
        with self.assertRaises(IdentityError):
            Identity.import_public({"name": "m", "email": FORGED})

    def test_crafted_algorithms_are_rejected_on_import(self):
        """Algorithm identifiers print directly under the Fingerprint: line
        in list/show, so they carry the same format contract."""
        from openssl_encrypt.modules.identity import validate_identity_algorithm

        validate_identity_algorithm("ML-DSA-65")
        validate_identity_algorithm("Dilithium3")
        for algorithm in (FORGED, "a" * 33, "SPHINCS+-SHA2-128f", 42, None):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(IdentityError):
                    validate_identity_algorithm(algorithm)
        with self.assertRaises(IdentityError):
            Identity.import_public(
                {
                    "name": "m",
                    "fingerprint": "aa:bb:cc:dd",
                    "created_at": "2026-01-01T00:00:00",
                    "encryption_algorithm": FORGED,
                }
            )

    def test_generate_rejects_a_crafted_email(self):
        """identity create --email is the PRODUCER side: the value is
        exported verbatim and uploaded in a keyserver bundle, attacking
        other users' trust prompts."""
        with self.assertRaises(IdentityError):
            Identity.generate(name="m", email=FORGED)


class TestKeyChangeWarningSanitized(_CmdTestBase):
    """The TOFU key-change warning is the highest-stakes display block in
    the tool; an unvalidated store on disk controls old_fingerprint."""

    def test_key_change_block_carries_no_raw_escapes(self):
        from openssl_encrypt.modules.identity import IdentityKeyChangedError
        from openssl_encrypt.modules.identity_cli import cmd_import

        args = argparse.Namespace(
            data_stdin=True,
            file=None,
            alias=None,
            overwrite=False,
            allow_key_change=False,
            identity_store=None,
        )
        store = mock.Mock()
        store.add_identity.side_effect = IdentityKeyChangedError("mallory", FORGED, "aa:bb:cc:dd")
        stderr = io.StringIO()
        stdin = io.StringIO(json.dumps({"name": "mallory"}))
        stdin.isatty = lambda: False
        with mock.patch(
            "openssl_encrypt.modules.identity.Identity.import_public",
            return_value=self._identity(None),
        ), mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store",
            return_value=store,
        ), mock.patch(
            "sys.stdin", stdin
        ):
            with redirect_stderr(stderr):
                status = cmd_import(args)
        self.assertNotEqual(status, 0)
        assert_no_controls(self, stderr.getvalue())


class TestKeyserverSurfaces(unittest.TestCase):
    """The keyserver trust prompt renders a fully remote attacker's bundle;
    the self-signature is no defence (it verifies against the key shipped IN
    the bundle)."""

    @staticmethod
    def _bundle(**overrides):
        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        fields = dict(
            name="mallory",
            email="mallory@example.com",
            fingerprint="aa:bb:cc:dd",
            created_at="2026-01-01T00:00:00Z",
            encryption_public_key=b"ek",
            signing_public_key=b"sk",
            encryption_algorithm="ML-KEM-768",
            signing_algorithm="ML-DSA-65",
            self_signature=b"sig",
        )
        fields.update(overrides)
        return PublicKeyBundle(**fields)

    def test_bundle_rejects_crafted_display_fields(self):
        for field in ("email", "created_at"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self._bundle(**{field: FORGED})
        with self.assertRaises(ValueError):
            self._bundle(name="m\x1ballory")
        with self.assertRaises(ValueError):
            self._bundle(fingerprint=FORGED)

    def test_clean_bundle_is_still_accepted(self):
        bundle = self._bundle()
        self.assertEqual(bundle.email, "mallory@example.com")

    def test_trust_prompt_sanitizes_a_cache_era_bundle(self):
        """Bundles cached before __post_init__ validation still reach the
        trust prompt; the display itself must not replay the attack."""
        from openssl_encrypt.modules.key_bundle import PublicKeyBundle
        from openssl_encrypt.modules.key_resolver import default_trust_callback

        with mock.patch.object(PublicKeyBundle, "__post_init__", lambda self: None):
            bundle = self._bundle(email=FORGED, created_at=FORGED)
        stderr = io.StringIO()
        with mock.patch("builtins.input", return_value="n"):
            with redirect_stderr(stderr):
                trusted = default_trust_callback(bundle)
        self.assertFalse(trusted)
        assert_no_controls(self, stderr.getvalue())


class TestLoadValidatesStoredMetadata(unittest.TestCase):
    """A stored identity file is untrusted display input too: a supplied
    --identity-store directory feeds list/show and the TOFU key-change
    warning without any import-time check."""

    def _write_store(self, tmp, **overrides):
        import pathlib

        doc = {
            "name": "alice",
            "email": "alice@example.com",
            "fingerprint": "aa:bb:cc:dd",
            "created_at": "2026-01-01T00:00:00Z",
            "encryption_algorithm": "ML-KEM-768",
            "signing_algorithm": "ML-DSA-65",
        }
        doc.update(overrides)
        d = pathlib.Path(tmp) / "alice"
        d.mkdir()
        (d / "identity.json").write_text(json.dumps(doc), encoding="utf-8")
        (d / "encryption_public.pem").write_bytes(b"ek")
        (d / "signing_public.pem").write_bytes(b"sk")
        return d

    def test_crafted_fields_are_refused_on_load(self):
        import tempfile

        for field in (
            "email",
            "fingerprint",
            "created_at",
            "name",
            "encryption_algorithm",
            "signing_algorithm",
        ):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as tmp:
                    d = self._write_store(tmp, **{field: FORGED})
                    with self.assertRaises(IdentityError):
                        Identity.load(d, load_private_keys=False)

    def test_a_clean_stored_identity_still_loads(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            d = self._write_store(tmp)
            identity = Identity.load(d, load_private_keys=False)
        self.assertEqual(identity.email, "alice@example.com")

    def test_an_oversized_identity_json_is_refused(self):
        """A gigabyte identity.json in a hostile store must not DoS
        `identity list`; the read itself is bounded."""
        import tempfile

        from openssl_encrypt.modules.json_validator import SecureJSONValidator

        with tempfile.TemporaryDirectory() as tmp:
            d = self._write_store(tmp)
            pad = "x" * (SecureJSONValidator.MAX_JSON_SIZE + 1)
            (d / "identity.json").write_text(
                json.dumps({"name": "alice", "pad": pad}), encoding="utf-8"
            )
            with self.assertRaises(IdentityError):
                Identity.load(d, load_private_keys=False)


class TestSignatureSidecarSanitized(unittest.TestCase):
    """verify-signature prints the sidecar's signer_fingerprint before any
    cryptographic check; the sidecar is attacker-supplied."""

    @staticmethod
    def _sidecar(**overrides):
        doc = {
            "signatures": [{"component": "ml-dsa-65", "value": "AAAA"}],
            "algorithm": "ML-DSA-65",
            "signer_fingerprint": "aa:bb:cc:dd",
        }
        doc.update(overrides)
        return json.dumps({k: v for k, v in doc.items() if v is not ...})

    def test_parse_signature_rejects_a_crafted_signer_fingerprint(self):
        from openssl_encrypt.modules.file_signature import FileSignatureError, parse_signature

        with self.assertRaises(FileSignatureError) as ctx:
            parse_signature(self._sidecar(signer_fingerprint=FORGED))
        assert_no_controls(self, str(ctx.exception))

    def test_parse_signature_rejects_a_crafted_component_name(self):
        """`component` is display-only and DELIBERATELY excluded from the
        signed payload, so any tamperer can rewrite it on a VALID signature
        — it would print inside the GOOD-signature block."""
        from openssl_encrypt.modules.file_signature import FileSignatureError, parse_signature

        for component in (FORGED, "UPPER", "a" * 65, 42):
            with self.subTest(component=component):
                sidecar = self._sidecar(signatures=[{"component": component, "value": "AAAA"}])
                with self.assertRaises(FileSignatureError):
                    parse_signature(sidecar)

    def test_parse_signature_rejects_a_crafted_algorithm(self):
        """algorithm feeds PQCSigner pre-verification, whose unsupported-
        algorithm error echoes it verbatim."""
        from openssl_encrypt.modules.file_signature import FileSignatureError, parse_signature

        for algorithm in (FORGED, "a" * 33, 42):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(FileSignatureError):
                    parse_signature(self._sidecar(algorithm=algorithm))

    def test_parse_signature_requires_fingerprint_algorithm_and_list(self):
        """Every sidecar this tool writes carries all three; a missing
        fingerprint would print "Unknown signer (fingerprint None)" and a
        missing algorithm fails on an exception path that skips the intended
        error formatting."""
        from openssl_encrypt.modules.file_signature import FileSignatureError, parse_signature

        for overrides in (
            {"signer_fingerprint": ...},
            {"algorithm": ...},
            {"signatures": 42},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(FileSignatureError):
                    parse_signature(self._sidecar(**overrides))

    def test_parse_signature_accepts_the_written_shapes(self):
        from openssl_encrypt.modules.file_signature import parse_signature

        parsed = parse_signature(self._sidecar())
        self.assertEqual(parsed["algorithm"], "ML-DSA-65")
        self.assertEqual(parsed["signer_fingerprint"], "aa:bb:cc:dd")


if __name__ == "__main__":
    unittest.main()
