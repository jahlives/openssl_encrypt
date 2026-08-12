#!/usr/bin/env python3
"""Phase 1c of the total-json plan (docs/total-json-output-plan.md, gitlab#268,
github#144): the verifiers are JSON-capable and registered.

verify-integrity and verify-signature keep their pre-existing bare documents
(frozen shapes; both predate the envelope); verify-usb wraps its result dict
in the status/data envelope and reports exceptions as a JSON error document
in JSON mode. Tests adapt per line via the capabilities manifest.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules import crypt_cli


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with mock.patch("sys.argv", ["crypt.py"] + argv):
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ret = crypt_cli.main()
                code = 0 if ret is None else ret
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
    return code, out.getvalue(), err.getvalue()


def _manifest():
    code, out, _ = _run(["capabilities"])
    assert code == 0
    return json.loads(out)


class TestVerifyUsbEnvelope(unittest.TestCase):
    def test_verify_usb_json_error_is_json(self):
        # A directory that is not a portable drive: the failure must arrive
        # as an envelope error document on stdout, not bare stderr text.
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = _run(["verify-usb", "--usb-path", tmp, "--password", "x", "--json"])
        self.assertNotEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["status"], "error")
        self.assertIn("message", doc["error"])

    def test_verify_usb_json_passes_the_fail_closed_guard(self):
        # The monolithic guard must allow verify-usb; the refusal message
        # would otherwise land on stderr before any verification runs.
        with tempfile.TemporaryDirectory() as tmp:
            _, out, err = _run(["verify-usb", "--usb-path", tmp, "--password", "x", "--json"])
        self.assertNotIn("is not supported", err)


class TestVerifyIntegrityDocument(unittest.TestCase):
    def test_bare_document_shape_is_frozen(self):
        code, out, err = _run(["verify-integrity", "--json"])
        # Exit code mirrors the verification verdict; the document must parse
        # either way and carry the pinned top-level keys.
        doc = json.loads(out)
        for key in ("exit_code", "files", "scope", "signature", "trust_warning"):
            self.assertIn(key, doc)
        self.assertNotIn("status", doc)  # deliberately NO envelope (frozen)
        self.assertEqual(code, doc["exit_code"])


class TestVerifySignatureDocument(unittest.TestCase):
    def test_refusal_arrives_as_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "f.txt")
            with open(target, "w") as f:
                f.write("data")
            code, out, err = _run(["verify-signature", "--input", target, "--json"])
        self.assertNotEqual(code, 0)
        doc = json.loads(out)  # refusal document, frozen shape
        self.assertIn("valid", doc)
        self.assertFalse(doc["valid"])


class TestCapabilitiesRegistration(unittest.TestCase):
    def test_phase_1c_endpoints_registered(self):
        manifest = _manifest()
        for endpoint in ("verify-integrity", "verify-signature", "verify-usb"):
            if endpoint not in manifest["commands"]:
                continue  # not on this line
            self.assertIn(endpoint, manifest["json_endpoints"], endpoint)
            self.assertIn(endpoint, manifest["json_fields"], endpoint)
            self.assertTrue(manifest["json_fields"][endpoint])


if __name__ == "__main__":
    unittest.main()
