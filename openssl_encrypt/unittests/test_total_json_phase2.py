#!/usr/bin/env python3
"""Phase 2 of the total-json plan (docs/total-json-output-plan.md, gitlab#268,
github#144): operation result reports.

encrypt/decrypt/rekey/sign/armor/dearmor/shred/create-usb emit the status/data
envelope on completion (human progress stays on stderr; exit codes unchanged);
derive-password --json carries the derived key in the envelope (stdout-only
secret; raw format refused); generate-password keeps its pre-existing bare
document. decrypt --json without an output path is refused - the JSON report
cannot share stdout with the plaintext.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules import crypt_cli


def _run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    patches = [mock.patch("sys.argv", ["crypt.py"] + argv)]
    if env:
        patches.append(mock.patch.dict(os.environ, env))
    with patches[0], patches[1] if env else mock.patch.dict(os.environ, {}):
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ret = crypt_cli.main()
                code = 0 if ret is None else ret
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
    return code, out.getvalue(), err.getvalue()


def _ok_data(test, argv, env=None):
    code, out, err = _run(argv, env)
    test.assertEqual(code, 0, f"{argv} exited {code}; stderr: {err[-500:]}")
    doc = json.loads(out)
    test.assertEqual(doc["status"], "ok")
    return doc["data"]


_FAST = ["--sha512-rounds", "10"]


class TestEncryptDecryptRekey(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = os.path.join(self.tmp, "plain.txt")
        with open(self.src, "w") as f:
            f.write("hello json\n")
        self.enc = os.path.join(self.tmp, "out.enc")
        self.env = {"CRYPT_PASSWORD": "test-password-123"}

    def _encrypt(self):
        return _ok_data(
            self,
            ["encrypt", "-i", self.src, "-o", self.enc, "--force-password"] + _FAST + ["--json"],
            env=self.env,
        )

    def test_encrypt_json_report(self):
        data = self._encrypt()
        self.assertEqual(data["action"], "encrypt")
        self.assertEqual(data["output"], self.enc)
        self.assertTrue(os.path.exists(self.enc))

    def test_decrypt_json_refuses_stream_output_targets(self):
        # Security review 2026-08-13 F1: with a stream target the payload and
        # the envelope would share stdout, letting attacker-influenceable
        # plaintext forge an envelope line for line-oriented consumers.
        self._encrypt()
        for target in ("-", "/dev/stdout"):
            code, out, err = _run(["decrypt", "-i", self.enc, "-o", target, "--json"], env=self.env)
            self.assertEqual(code, 2, target)
            self.assertEqual(json.loads(out)["status"], "error")

    def test_decrypt_json_report_and_refusal_without_output(self):
        self._encrypt()
        code, out, err = _run(["decrypt", "-i", self.enc, "--json"], env=self.env)
        self.assertEqual(code, 2)
        doc = json.loads(out)
        self.assertEqual(doc["status"], "error")

        dec = os.path.join(self.tmp, "roundtrip.txt")
        data = _ok_data(self, ["decrypt", "-i", self.enc, "-o", dec, "--json"], env=self.env)
        self.assertEqual(data["action"], "decrypt")
        self.assertEqual(data["output"], dec)
        with open(dec) as f:
            self.assertEqual(f.read(), "hello json\n")


class TestShredArmor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_shred_json_report(self):
        victim = os.path.join(self.tmp, "victim.txt")
        with open(victim, "w") as f:
            f.write("x")
        data = _ok_data(self, ["shred", "-i", victim, "--json"])
        self.assertEqual(data["action"], "shred")
        self.assertEqual(data["matched"], 1)
        self.assertTrue(data["success"])
        self.assertFalse(os.path.exists(victim))


class TestDeriveAndGeneratePassword(unittest.TestCase):
    def test_derive_password_json_envelope(self):
        data = _ok_data(
            self,
            ["derive-password", "--output-length", "16"] + _FAST + ["--json"],
            env={"OPENSSL_ENCRYPT_PASSWORD": "base-password"},
        )
        self.assertEqual(data["format"], "hex")
        bytes.fromhex(data["derived"])  # must be valid hex

    def test_derive_password_json_refuses_raw(self):
        code, out, err = _run(
            ["derive-password", "--output-length", "16", "--output-format", "raw"]
            + _FAST
            + ["--json"],
            env={"OPENSSL_ENCRYPT_PASSWORD": "base-password"},
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "error")

    def test_generate_password_bare_document_frozen(self):
        code, out, err = _run(["generate-password", "20", "--json"])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)
        self.assertIn("password", doc)
        self.assertNotIn("status", doc)  # frozen pre-envelope shape


class TestCapabilitiesRegistration(unittest.TestCase):
    def test_phase_2_endpoints_registered(self):
        code, out, _ = _run(["capabilities"])
        self.assertEqual(code, 0)
        manifest = json.loads(out)
        for endpoint in (
            "encrypt",
            "decrypt",
            "rekey",
            "sign",
            "armor",
            "dearmor",
            "shred",
            "create-usb",
            "derive-password",
            "generate-password",
        ):
            if endpoint not in manifest["commands"]:
                continue  # not on this line
            self.assertIn(endpoint, manifest["json_endpoints"], endpoint)
            self.assertIn(endpoint, manifest["json_fields"], endpoint)


if __name__ == "__main__":
    unittest.main()
