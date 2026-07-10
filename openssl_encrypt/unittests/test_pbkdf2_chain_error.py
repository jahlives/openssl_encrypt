#!/usr/bin/env python3
"""
Pointed migration error for removed-PBKDF2-chain files
(docs/PBKDF2_CHAIN_ERROR_PLAN.md).

1.4.x sequential files whose key-derivation chain used pbkdf2_iterations > 0
cannot be derived on 1.5.x (the PBKDF2 chain stage was removed in 1.5.0).
Instead of a generic authentication error indistinguishable from a wrong
password, decrypt must fail BEFORE key derivation with guidance naming the
breaking change and the migration path (decrypt with 1.4.x, re-encrypt).

Scoping is critical: 1.4.x wrote the `pbkdf2` metadata entry for EVERY file
when pbkdf2_iterations > 0, including independent-XOR files that never
consumed it — those decrypt fine and must never trip this check.
"""

import contextlib
import io
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.crypt_errors import DecryptionError

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")
PASSWORD = b"fixture-corpus-password-2026"
PLAINTEXT = b"openssl_encrypt format-version fixture corpus 2026-07-10\n"

# 1.4.x sequential fixtures whose chain used pbkdf2_iterations=1000
PBKDF2_SEQUENTIAL_FIXTURES = ["v9_plain.enc", "v13_sequential.enc"]
# Fixtures that carry the same pbkdf2 metadata entry but never consumed it
INDEPENDENT_FIXTURES_WITH_PBKDF2_ENTRY = ["v11_independent.enc", "v13_independent.enc"]


def _decrypt(name, password=PASSWORD, quiet=True):
    outfile = os.path.join(tempfile.mkdtemp(), name + ".out")
    decrypt_file(os.path.join(FIXTURE_DIR, name), outfile, password, quiet=quiet)
    with open(outfile, "rb") as f:
        return f.read()


class TestPbkdf2ChainError(unittest.TestCase):
    def test_sequential_pbkdf2_files_raise_pointed_error(self):
        for name in PBKDF2_SEQUENTIAL_FIXTURES:
            with self.subTest(fixture=name):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(Exception) as ctx:
                        _decrypt(name, quiet=False)
                # The stderr notice is the user-visible channel (exception
                # messages are sanitized outside debug mode).
                notice = stderr.getvalue()
                self.assertIn("removed in v1.5.0", notice)
                self.assertIn("PBKDF2", notice)
                self.assertIn("openssl-encrypt 1.4", notice)
                # The exception itself must be the pointed DecryptionError
                # (visible in debug/test environments), raised BEFORE key
                # derivation — not a downstream AEAD authentication error.
                self.assertIn("PBKDF2", str(ctx.exception))

    def test_quiet_still_raises_without_notice(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(Exception):
                _decrypt("v9_plain.enc", quiet=True)
        self.assertNotIn("removed in v1.5.0", stderr.getvalue())

    def test_independent_files_with_pbkdf2_entry_still_decrypt(self):
        # The false-positive guard: same pbkdf2 metadata entry, but the
        # independent-XOR path never used it.
        for name in INDEPENDENT_FIXTURES_WITH_PBKDF2_ENTRY:
            with self.subTest(fixture=name):
                self.assertEqual(_decrypt(name), PLAINTEXT)

    def test_pbkdf2_free_sequential_still_roundtrips(self):
        # 1.5.x can still write and read v13-sequential files; only the
        # removed PBKDF2 stage is unreadable.
        tmp = tempfile.mkdtemp()
        infile = os.path.join(tmp, "in.txt")
        outfile = os.path.join(tmp, "seq.enc")
        recovered = os.path.join(tmp, "seq.out")
        with open(infile, "wb") as f:
            f.write(b"pbkdf2-free sequential probe")
        encrypt_file(
            infile,
            outfile,
            PASSWORD,
            {"sha256": 10},
            format_version=13,
            xor_mode="sequential",
            quiet=True,
        )
        decrypt_file(outfile, recovered, PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"pbkdf2-free sequential probe")

    def test_wrong_password_is_not_reported_as_pbkdf2(self):
        # A wrong password on a READABLE file must keep its normal
        # authentication error — the new message must never mask it.
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(Exception) as ctx:
                _decrypt("v13_independent.enc", password=b"wrong-password", quiet=False)
        self.assertNotIn("removed in v1.5.0", stderr.getvalue())
        self.assertNotIn("PBKDF2", str(ctx.exception))


class TestHelperUnit(unittest.TestCase):
    """Direct unit coverage of _check_removed_pbkdf2_chain (also stands in
    for the asymmetric and envelope hooks, which build the same minimal
    metadata dict)."""

    def _meta(self, fv=9, xor_mode=None, pbkdf2=None, flat=None):
        meta = {"format_version": fv}
        if xor_mode is not None:
            meta["xor_mode"] = xor_mode
        kdf_config = {}
        if pbkdf2 is not None:
            kdf_config["pbkdf2"] = pbkdf2
        meta["derivation_config"] = {"kdf_config": kdf_config}
        if flat is not None:
            meta["pbkdf2_iterations"] = flat
        return meta

    def test_sequential_with_rounds_raises(self):
        from openssl_encrypt.modules.crypt_core import _check_removed_pbkdf2_chain

        for meta in (
            self._meta(fv=9, pbkdf2={"rounds": 1000}),
            self._meta(fv=13, xor_mode="sequential", pbkdf2={"iterations": 5}),
            self._meta(fv=3, flat=1000),
        ):
            with self.subTest(meta=meta):
                with self.assertRaises(DecryptionError):
                    _check_removed_pbkdf2_chain(meta, quiet=True)

    def test_independent_routes_never_raise(self):
        from openssl_encrypt.modules.crypt_core import _check_removed_pbkdf2_chain

        for meta in (
            self._meta(fv=13, xor_mode="independent", pbkdf2={"rounds": 1000}),
            self._meta(fv=11, pbkdf2={"rounds": 1000}),
            self._meta(fv=12, pbkdf2={"rounds": 1000}),
            self._meta(fv=14, pbkdf2={"rounds": 1000}),
        ):
            with self.subTest(meta=meta):
                _check_removed_pbkdf2_chain(meta, quiet=True)  # must not raise

    def test_zero_missing_or_malformed_rounds_do_not_raise(self):
        from openssl_encrypt.modules.crypt_core import _check_removed_pbkdf2_chain

        _check_removed_pbkdf2_chain(self._meta(fv=9), quiet=True)
        _check_removed_pbkdf2_chain(self._meta(fv=9, pbkdf2={"rounds": 0}), quiet=True)
        _check_removed_pbkdf2_chain(self._meta(fv=9, pbkdf2={"rounds": "x"}), quiet=True)
        _check_removed_pbkdf2_chain(
            {"format_version": 9, "derivation_config": {"kdf_config": "junk"}}, quiet=True
        )
        _check_removed_pbkdf2_chain("not-a-dict", quiet=True)


if __name__ == "__main__":
    unittest.main()
