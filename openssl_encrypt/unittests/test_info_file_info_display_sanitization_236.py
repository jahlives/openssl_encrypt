#!/usr/bin/env python3
"""`info` (print_file_info) must escape terminal control characters in every
untrusted metadata field (gitlab#236, scan F4, CWE-117).

A crafted file's metadata fields (pepper_name, hsm_plugin, algorithm, ...) used
to be printed raw, so cursor-movement / erase-line / bidi bytes could repaint
the info output — including forging a Fingerprint line — on the very command
whose job is to judge an untrusted file. Every metadata-derived value must now
be routed through sanitize_for_display.

The metadata must pass schema validation to reach the print path, so the test
starts from a real encrypted file and injects the payload into the free-form
fields the schema accepts (which is exactly where the F4 vector lives).
"""

import base64
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    encrypt_file,
    print_file_info,
)

# The terminal-control class the display sanitizer neutralizes. Newline is
# exempt: print_file_info emits its own structural line breaks; what must never
# appear is any of these RAW bytes smuggled inside a metadata VALUE (an escaped
# rendering like the literal text "\\x1b" is fine).
_CONTROL = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f" "\u200e\u200f\u202a-\u202e\u2066-\u2069]")

# ESC cursor-up + erase-line + a forged line + a C1 CSI + a bidi override.
_PAYLOAD = "x\x1b[1A\x1b[2K\x9bFingerprint: AA:BB:CC‮"


class TestInfoOutputIsControlCharSafe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        src = os.path.join(self.tmp, "plain.txt")
        with open(src, "wb") as f:
            f.write(b"hello\n")
        self.enc = os.path.join(self.tmp, "file.enc")
        encrypt_file(
            src,
            self.enc,
            b"pw",
            {
                "sha512": 10,
                "argon2": {
                    "enabled": True,
                    "time_cost": 1,
                    "memory_cost": 512,
                    "parallelism": 1,
                    "type": "id",
                },
            },
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tamper(self, mutate):
        with open(self.enc, "rb") as f:
            content = f.read()
        colon = content.find(b":")
        meta = json.loads(base64.b64decode(content[:colon]))
        mutate(meta)
        header = base64.b64encode(json.dumps(meta).encode("utf-8"))
        with open(self.enc, "wb") as f:
            f.write(header + b":" + content[colon + 1 :])

    def _info_stderr(self):
        buf = io.StringIO()
        try:
            with redirect_stderr(buf):
                print_file_info(self.enc)
        except Exception:
            pass  # only the printed-so-far output matters
        return buf.getvalue()

    def test_baseline_info_prints_something(self):
        out = self._info_stderr()
        self.assertIn("Algorithm", out)  # sanity: the print path is exercised

    def test_injected_pepper_fields_are_sanitized(self):
        def mutate(meta):
            enc = meta.setdefault("encryption", {})
            enc["pepper_plugin"] = _PAYLOAD
            enc["pepper_name"] = _PAYLOAD

        self._tamper(mutate)
        out = self._info_stderr()
        self.assertIn("Pepper", out, "the injected pepper fields must be reached and printed")
        self.assertIsNone(_CONTROL.search(out), repr(out))

    def test_injected_hsm_plugin_is_sanitized(self):
        self._tamper(lambda m: m.setdefault("encryption", {}).__setitem__("hsm_plugin", _PAYLOAD))
        out = self._info_stderr()
        self.assertIsNone(_CONTROL.search(out), repr(out))

    def test_legacy_format_top_level_fields_are_sanitized(self):
        # gitlab#236 review: for a crafted legacy (v1/v2) file the schema is not
        # applied, so mode/xor_mode/encrypted_at must be sanitized too. A C1 CSI
        # (0x9b) passes the JSON security scan (it only rejects C0) but is a
        # terminal-repaint byte.
        c1 = "sym\x9b[2Kforged‮"

        def mutate(meta):
            meta["format_version"] = 1
            meta["mode"] = c1
            meta["xor_mode"] = c1
            meta["encrypted_at"] = c1

        self._tamper(mutate)
        out = self._info_stderr()
        self.assertIsNone(_CONTROL.search(out), repr(out))


if __name__ == "__main__":
    unittest.main()
