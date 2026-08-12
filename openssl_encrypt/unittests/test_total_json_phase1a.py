#!/usr/bin/env python3
"""Phase 1a of the total-json plan (docs/total-json-output-plan.md, gitlab#268,
github#144): the version/catalog reporter commands emit a machine-readable
envelope behind ``--json``.

Contract under test:
  * ``--json`` on version / show-version-file / list-algorithms / check-argon2 /
    check-pqc prints EXACTLY ONE JSON document on stdout with the envelope
    ``{"status": "ok", "data": {...}}``; human output stays off stdout.
  * ``list-available-algorithms`` already prints a bare JSON document (a GUI
    consumer predates the envelope); its shape is frozen as-is.
  * The capabilities manifest registers every Phase 1a endpoint in
    ``json_endpoints`` and pins its data fields in ``json_fields``.
  * Fail-closed: ``--json`` on a not-yet-converted action is refused (exit 2)
    on the legacy monolithic path instead of silently printing human text.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules import crypt_cli

PHASE_1A_ENVELOPE_ENDPOINTS = [
    "version",
    "show-version-file",
    "list-algorithms",
    "check-argon2",
    "check-pqc",
]


def _run(argv):
    """Run the real CLI entry point with argv, capturing streams and exit code."""
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


class TestEnvelopeHelper(unittest.TestCase):
    def test_ok_envelope_shape(self):
        from openssl_encrypt.modules.json_output import emit_json

        out = io.StringIO()
        with redirect_stdout(out):
            emit_json({"a": 1})
        self.assertEqual(json.loads(out.getvalue()), {"status": "ok", "data": {"a": 1}})

    def test_error_envelope_shape(self):
        from openssl_encrypt.modules.json_output import emit_json_error

        out = io.StringIO()
        with redirect_stdout(out):
            emit_json_error("boom")
        self.assertEqual(
            json.loads(out.getvalue()),
            {"status": "error", "error": {"message": "boom"}},
        )


class TestReporterEnvelopes(unittest.TestCase):
    def _ok_data(self, argv):
        code, out, err = _run(argv)
        self.assertEqual(code, 0, f"{argv} exited {code}; stderr: {err[-500:]}")
        doc = json.loads(out)  # stdout must be one valid JSON document
        self.assertEqual(doc["status"], "ok")
        return doc["data"]

    def test_version_json(self):
        data = self._ok_data(["version", "--json"])
        self.assertIn("version", data)
        self.assertIn("git_commit", data)
        self.assertIn("python", data)
        self.assertIn("platform", data)

    def test_show_version_file_json(self):
        data = self._ok_data(["show-version-file", "--json"])
        for key in ("version", "git_commit", "history"):
            self.assertIn(key, data)

    def test_list_algorithms_json(self):
        data = self._ok_data(["list-algorithms", "--json"])
        for key in ("ciphers", "hashes", "kdfs", "kems", "signatures"):
            self.assertIn(key, data)
            self.assertIsInstance(data[key], list)
        self.assertTrue(data["ciphers"], "cipher list must not be empty")

    def test_check_argon2_json(self):
        data = self._ok_data(["check-argon2", "--json"])
        self.assertIsInstance(data["available"], bool)
        self.assertIn("variants", data)
        self.assertIsInstance(data["variants"], list)

    def test_check_pqc_json(self):
        data = self._ok_data(["check-pqc", "--json"])
        self.assertIsInstance(data["available"], bool)
        self.assertIn("algorithms", data)
        self.assertIsInstance(data["algorithms"], list)

    def test_json_mode_keeps_stdout_pure(self):
        for argv in (["version", "--json"], ["check-argon2", "--json"]):
            _, out, _ = _run(argv)
            # json.loads on the WHOLE stream: any stray human line breaks this.
            json.loads(out)

    def test_without_json_stdout_stays_empty(self):
        # The human reports write to stderr (eprint); stdout stays reserved
        # for machine output. Guards against the envelope leaking by default.
        code, out, err = _run(["version"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")
        self.assertNotEqual(err.strip(), "")


class TestListAvailableAlgorithmsRegistered(unittest.TestCase):
    def test_bare_json_document_shape_is_frozen(self):
        code, out, err = _run(["list-available-algorithms"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        for key in ("ciphers", "hashes", "kdfs", "kems", "signatures", "libraries"):
            self.assertIn(key, doc)
        # Deliberately NO envelope: existing consumers (the GUI) predate it.
        self.assertNotIn("status", doc)


class TestCapabilitiesRegistration(unittest.TestCase):
    def test_phase_1a_endpoints_registered(self):
        code, out, err = _run(["capabilities"])
        self.assertEqual(code, 0)
        manifest = json.loads(out)
        for endpoint in PHASE_1A_ENVELOPE_ENDPOINTS + ["list-available-algorithms"]:
            self.assertIn(endpoint, manifest["json_endpoints"], endpoint)
            self.assertIn(endpoint, manifest["json_fields"], endpoint)
            self.assertTrue(manifest["json_fields"][endpoint])


class TestFailClosed(unittest.TestCase):
    def test_json_on_unconverted_action_is_refused(self):
        # config-wizard is excluded from total-json by design (interactive):
        # --json must be rejected, not silently ignored (no half-machine
        # output, nothing on stdout).
        code, out, err = _run(["config-wizard", "--json"])
        self.assertNotEqual(code, 0)
        self.assertEqual(out.strip(), "")


if __name__ == "__main__":
    unittest.main()
