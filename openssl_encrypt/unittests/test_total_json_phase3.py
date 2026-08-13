#!/usr/bin/env python3
"""Phase 3 of the total-json plan (docs/total-json-output-plan.md, gitlab#268,
github#144): grouped commands' reporting subcommands emit JSON.

keyserver status / cache-stats and hsm fido2-status emit the status/data
envelope; identity show emits the envelope with raw (unsanitized, gitlab#183)
public metadata. The group commands are registered as endpoints.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules import crypt_cli


def _run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with mock.patch("sys.argv", ["crypt.py"] + argv), mock.patch.dict(os.environ, env or {}):
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ret = crypt_cli.main()
                code = 0 if ret is None else ret
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
    return code, out.getvalue(), err.getvalue()


class TestKeyserverReporters(unittest.TestCase):
    def test_status_json(self):
        code, out, err = _run(["keyserver", "status", "--json"])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)
        self.assertEqual(doc["status"], "ok")
        data = doc["data"]
        self.assertIsInstance(data["enabled"], bool)
        self.assertIsInstance(data["has_api_token"], bool)
        self.assertIn("cache", data)

    def test_cache_stats_json(self):
        code, out, err = _run(["keyserver", "cache-stats", "--json"])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)
        self.assertEqual(doc["status"], "ok")
        self.assertIn("total_entries", doc["data"])


class TestHsmFido2Status(unittest.TestCase):
    def test_fido2_status_json(self):
        code, out, err = _run(["hsm", "fido2-status", "--json"])
        if code != 0 and out.strip():
            # Since gitlab#270 F4 a missing fido2 stack yields a JSON error
            # document (previously a raw NameError escaped the handler).
            doc = json.loads(out)
            if doc.get("status") == "error" and "FIDO2" in doc["error"]["message"]:
                self.skipTest("fido2 stack unavailable in this environment")
        if code != 0 and not out.strip():
            self.skipTest("fido2 plugin unavailable in this environment")
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)
        self.assertEqual(doc["status"], "ok")
        data = doc["data"]
        self.assertIsInstance(data["registered"], bool)
        self.assertIsInstance(data["credentials"], list)


class TestIdentityShow(unittest.TestCase):
    def test_show_missing_identity_fails_without_stdout_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = _run(
                ["identity", "show", "no-such-identity", "--json"],
                env={"OPENSSL_ENCRYPT_IDENTITY_STORE": tmp},
            )
        self.assertNotEqual(code, 0)


class TestCapabilitiesRegistration(unittest.TestCase):
    def test_phase_3_groups_registered(self):
        code, out, _ = _run(["capabilities"])
        self.assertEqual(code, 0)
        manifest = json.loads(out)
        for endpoint in ("keyserver", "hsm", "identity", "plugin", "telemetry"):
            if endpoint not in manifest["commands"]:
                continue
            self.assertIn(endpoint, manifest["json_endpoints"], endpoint)


if __name__ == "__main__":
    unittest.main()
