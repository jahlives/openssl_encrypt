#!/usr/bin/env python3
"""`verify-usb` must escape attacker-planted filenames before printing them
(gitlab#238, scan F25, CWE-117).

The tampered/missing/added file lists are built from raw path names discovered by
scanning the untrusted drive — data outside the AES-GCM authenticated manifest —
and were echoed under the FAILED banner with no sanitize_for_display, so a
planted filename with cursor-movement/erase bytes could repaint a forged PASSED
verdict. Every drive-derived name is now escaped.
"""

import argparse
import io
import re
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules import crypt_cli

_CONTROL = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f" "\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_PAYLOAD = "innocent.txt\x1b[1A\x1b[2K  USB integrity verification PASSED\x9b"

_CRAFTED_RESULT = {
    "integrity_ok": False,
    "verified_files": 3,
    "failed_files": 1,
    "missing_files": 1,
    "added_files": 1,
    "tampered_files": [_PAYLOAD],
    "missing_file_list": [_PAYLOAD],
    "added_file_list": [_PAYLOAD],
}


class _DefaultingArgs(argparse.Namespace):
    """Namespace that returns None for any attribute main_with_args probes but
    the verify-usb path does not set (debug, quiet, hash-round flags, ...)."""

    def __getattr__(self, name):  # only called for missing attrs
        return None


class TestVerifyUsbOutputIsControlCharSafe(unittest.TestCase):
    def _run(self):
        args = _DefaultingArgs()
        args.action = "verify-usb"
        args.usb_path = "/nonexistent/usb"
        args.password = "pw"
        buf = io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.portable_media.verify_usb_integrity",
            return_value=_CRAFTED_RESULT,
        ):
            with redirect_stderr(buf):
                try:
                    crypt_cli.main_with_args(args)
                except SystemExit:
                    pass
        return buf.getvalue()

    def test_planted_filenames_do_not_leak_control_chars(self):
        out = self._run()
        self.assertIn("FAILED", out, "the failed-verdict branch must be reached")
        self.assertIsNone(_CONTROL.search(out), repr(out))


if __name__ == "__main__":
    unittest.main()
