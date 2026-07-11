#!/usr/bin/env python3
"""
Type-safe format_version handling in the keystore modules (review LOW-2,
gitlab#111).

The v14 series converted ``format_version in [4..10]`` gates to
``format_version >= 4`` in keystore_wrapper.py / keystore_utils.py. Those
sites read ``format_version`` from raw ``json.loads`` output, so crafted
metadata carrying a non-int value (``"4"``, ``true``, ``[]``) raised an
unhandled TypeError at the comparison. Fail-closed either way (no bypass),
but a crash is a DoS-of-one-operation and an ugly failure mode.

These tests pin the fixed behavior: non-int ``format_version`` values are
rejected with the project's clean ValidationError (or routed to the legacy
branch where a swallowing try/except already governed the site) — never a
TypeError — while every valid int routes exactly as before.
"""

import base64
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.keystore_utils import (
    _coerce_format_version,
    get_pqc_key_for_decryption,
)
from openssl_encrypt.modules.keystore_wrapper import decrypt_file_with_keystore

CRAFTED_VALUES = ["4", "14", True, False, [], {}, 4.0, None]


def _crafted_file(format_version_value) -> str:
    """Write a syntactically valid encrypted-file header with crafted metadata."""
    metadata = {
        "format_version": format_version_value,
        "derivation_config": {"kdf_config": {"dual_encryption": True}},
        "encryption": {"algorithm": "aes-256-gcm"},
    }
    header = base64.b64encode(json.dumps(metadata).encode("utf-8"))
    fd, path = tempfile.mkstemp(suffix=".enc")
    with os.fdopen(fd, "wb") as f:
        f.write(header + b":" + b"\x00" * 64)
    return path


class TestCoerceFormatVersion(unittest.TestCase):
    def test_valid_ints_pass_through(self):
        for fv in (1, 3, 4, 5, 6, 7, 10, 13, 14):
            self.assertEqual(_coerce_format_version({"format_version": fv}, 1), fv)

    def test_absent_uses_default(self):
        self.assertEqual(_coerce_format_version({}, 3), 3)
        self.assertEqual(_coerce_format_version(None, 1), 1)

    def test_non_int_values_rejected(self):
        # None PRESENT is invalid (absent means default) — matches the main
        # decrypt path's semantics in crypt_core.
        for fv in CRAFTED_VALUES:
            with self.subTest(fv=fv):
                with self.assertRaises(ValidationError):
                    _coerce_format_version({"format_version": fv}, 1)

    def test_bool_is_not_an_int_here(self):
        # bool is an int subclass; True >= 4 is valid Python but nonsense
        # metadata, so it must be rejected explicitly.
        with self.assertRaises(ValidationError):
            _coerce_format_version({"format_version": True}, 1)


class TestGetPqcKeyForDecryptionTypeSafety(unittest.TestCase):
    def _args(self):
        return SimpleNamespace(quiet=True, verbose=False, input=None)

    def test_crafted_metadata_raises_clean_error(self):
        for fv in CRAFTED_VALUES:
            with self.subTest(fv=fv):
                with self.assertRaises(ValidationError):
                    get_pqc_key_for_decryption(self._args(), {}, metadata={"format_version": fv})

    def test_valid_metadata_still_routes(self):
        # No keys present anywhere -> graceful (None, None, None), no raise.
        result = get_pqc_key_for_decryption(self._args(), {}, metadata={"format_version": 14})
        self.assertEqual(result, (None, None, None))


class TestDecryptWithKeystoreTypeSafety(unittest.TestCase):
    def test_crafted_file_never_typeerrors(self):
        for fv in ["4", True, [], {}]:
            with self.subTest(fv=fv):
                path = _crafted_file(fv)
                out = path + ".out"
                try:
                    with self.assertRaises(Exception) as ctx:
                        decrypt_file_with_keystore(path, out, password=b"test-password")
                    self.assertNotIsInstance(
                        ctx.exception,
                        TypeError,
                        f"unhandled TypeError leaked for format_version={fv!r}",
                    )
                finally:
                    os.unlink(path)
                    if os.path.exists(out):
                        os.unlink(out)


if __name__ == "__main__":
    unittest.main()
