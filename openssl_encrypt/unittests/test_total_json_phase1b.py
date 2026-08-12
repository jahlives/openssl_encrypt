#!/usr/bin/env python3
"""Phase 1b of the total-json plan (docs/total-json-output-plan.md, gitlab#268,
github#144): the file/config reporter commands are JSON-capable.

Contract under test:
  * list-plugins / plugin-info honor the (previously silently ignored)
    monolithic global ``--json`` and emit the status/data envelope.
  * security-info --json emits the recommendations report in the envelope.
  * analyze-config and ``template list`` gain ``--json`` as an alias for their
    pre-existing ``--output-format json`` / ``--format json``; those bare
    document shapes are frozen (their consumers predate the envelope).
  * ``info --json`` (pre-existing bare metadata document) works end to end.
  * All six are registered in capabilities json_endpoints/json_fields.
  * Fail-closed: the monolithic global ``--json`` on a non-JSON action is
    refused, not silently ignored.
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


def _ok_data(test, argv):
    code, out, err = _run(argv)
    test.assertEqual(code, 0, f"{argv} exited {code}; stderr: {err[-500:]}")
    doc = json.loads(out)
    test.assertEqual(doc["status"], "ok")
    return doc["data"]


class TestPluginReporters(unittest.TestCase):
    def test_list_plugins_json(self):
        data = _ok_data(self, ["list-plugins", "--json"])
        self.assertIn("plugins", data)
        self.assertIsInstance(data["plugins"], list)

    def test_plugin_info_json(self):
        listing = _ok_data(self, ["list-plugins", "--json"])["plugins"]
        if not listing:
            self.skipTest("no plugins discovered in this environment")
        plugin_id = listing[0]["id"]
        data = _ok_data(self, ["plugin-info", "--plugin-id", plugin_id, "--json"])
        for key in ("name", "version", "type", "enabled", "capabilities"):
            self.assertIn(key, data)

    def test_plugin_info_json_unknown_id_error_envelope(self):
        code, out, err = _run(["plugin-info", "--plugin-id", "no-such-plugin", "--json"])
        self.assertNotEqual(code, 0)
        doc = json.loads(out)  # JSON mode: the error arrives as JSON on stdout
        self.assertEqual(doc["status"], "error")
        self.assertIn("message", doc["error"])


class TestSecurityInfo(unittest.TestCase):
    def test_security_info_json(self):
        data = _ok_data(self, ["security-info", "--json"])
        self.assertIn("report", data)
        self.assertIn("Argon2id", data["report"])

    def test_security_info_human_stays_on_stderr(self):
        code, out, err = _run(["security-info"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")
        self.assertIn("SECURITY RECOMMENDATIONS", err)


def _manifest_commands():
    code, out, _ = _run(["capabilities"])
    assert code == 0
    return set(json.loads(out)["commands"])


class TestAliases(unittest.TestCase):
    # These commands exist on the 1.4.x line only (the 1.5.x surface
    # reduction removed them); the manifest is the line-accurate source.
    def test_analyze_config_json_alias(self):
        if "analyze-config" not in _manifest_commands():
            self.skipTest("analyze-config not on this line")
        code, out, err = _run(["analyze-config", "--json"])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)  # bare document, frozen shape (no envelope)
        self.assertIn("overall_score", doc)
        self.assertNotIn("status", doc)

    def test_template_list_json_alias(self):
        if "template" not in _manifest_commands():
            self.skipTest("template not on this line")
        code, out, err = _run(["template", "list", "--json"])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)
        self.assertIn("templates", doc)
        self.assertNotIn("status", doc)


class TestInfoRegistered(unittest.TestCase):
    def setUp(self):
        from openssl_encrypt.modules.crypt_core import EncryptionAlgorithm, encrypt_file

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
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
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
        )

    def test_info_json_bare_metadata_document(self):
        code, out, err = _run(["info", "--json", "-i", self.enc])
        self.assertEqual(code, 0, err[-300:])
        doc = json.loads(out)  # bare metadata document, frozen shape
        self.assertIn("format_version", doc)
        self.assertNotIn("status", doc)


class TestCapabilitiesRegistration(unittest.TestCase):
    def test_phase_1b_endpoints_registered(self):
        code, out, err = _run(["capabilities"])
        self.assertEqual(code, 0)
        manifest = json.loads(out)
        for endpoint in (
            "info",
            "analyze-config",
            "template",
            "list-plugins",
            "plugin-info",
            "security-info",
        ):
            if endpoint not in manifest["commands"]:
                continue  # not on this line; the manifest filters it out
            self.assertIn(endpoint, manifest["json_endpoints"], endpoint)
            self.assertIn(endpoint, manifest["json_fields"], endpoint)
            self.assertTrue(manifest["json_fields"][endpoint])


class TestFailClosed(unittest.TestCase):
    def test_monolithic_json_on_non_endpoint_is_refused(self):
        # shred routes via the monolithic parser, which accepts the global
        # --json for every action; without a guard it would be silently
        # ignored. It must refuse instead (and print no stdout document).
        code, out, err = _run(["shred", "--json", os.devnull])
        self.assertNotEqual(code, 0)
        self.assertEqual(out.strip(), "")


if __name__ == "__main__":
    unittest.main()
