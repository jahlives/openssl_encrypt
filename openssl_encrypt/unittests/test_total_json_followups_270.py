#!/usr/bin/env python3
"""Security-review follow-ups for the total-json surface (gitlab#270,
github#146; review 2026-08-13 F2/F3/F4/F8).

  * F2: decrypt --json without a usable output path is refused BEFORE the
    password sources are consumed - a scripted caller keeps its CRYPT_PASSWORD
    env var (previously it was cleared for an operation that never ran).
  * F3: the fail-closed --json guard keys on the curated JSON-endpoint set,
    not on parser routing - `crypt --json config-wizard` (flag before the
    command forces the monolithic route) is refused, not silently ignored.
  * F4: JSON mode emits exactly one document even on failure paths: shred
    with no match, sign failure, decrypt failure, and the generic fallback.
  * F8: what the endpoints emit stays within the capabilities manifest's
    curated json_fields (envelope endpoints: data keys are a subset; frozen
    bare documents: the pinned keys are guaranteed present).
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
    with mock.patch("sys.argv", ["crypt.py"] + argv), mock.patch.dict(os.environ, env or {}):
        with redirect_stdout(out), redirect_stderr(err):
            try:
                ret = crypt_cli.main()
                code = 0 if ret is None else ret
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        env_after = dict(os.environ)
    return code, out.getvalue(), err.getvalue(), env_after


def _error_doc(test, out):
    doc = json.loads(out)
    test.assertEqual(doc["status"], "error")
    test.assertIn("message", doc["error"])
    return doc


class TestF2EarlyDecryptRefusal(unittest.TestCase):
    def test_refusal_precedes_password_consumption(self):
        code, out, err, env_after = _run(
            ["decrypt", "-i", "/nonexistent.enc", "--json"],
            env={"CRYPT_PASSWORD": "still-here"},
        )
        self.assertEqual(code, 2)
        _error_doc(self, out)
        # The refusal must fire before the env password is read-and-cleared:
        # the caller re-runs with -o and needs the secret intact.
        self.assertEqual(env_after.get("CRYPT_PASSWORD"), "still-here")


class TestF3RoutingProofGuard(unittest.TestCase):
    def test_json_before_excluded_command_is_refused(self):
        # --json BEFORE the command makes the argv scan swallow the command
        # token and fall through to the monolithic parser, which accepts the
        # global --json for every action - the old guard exempted any name
        # that is also subparser-registered, letting such invocations
        # silently ignore the flag. enable-plugin exists on both lines and
        # has no JSON emitter.
        code, out, err, _ = _run(["--json", "enable-plugin"])
        self.assertEqual(code, 2)
        self.assertEqual(out.strip(), "")
        self.assertIn("--json is not supported", err)


class TestF4ErrorEnvelopes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_shred_no_match_emits_error_doc(self):
        code, out, err, _ = _run(["shred", "-i", os.path.join(self.tmp, "no-such-*"), "--json"])
        self.assertNotEqual(code, 0)
        _error_doc(self, out)

    def test_sign_failure_emits_error_doc(self):
        code, out, err, _ = _run(
            [
                "sign",
                "--input",
                os.path.join(self.tmp, "missing.txt"),
                "--sign-with",
                "nobody",
                "--json",
            ]
        )
        self.assertNotEqual(code, 0)
        _error_doc(self, out)

    def test_decrypt_failure_emits_error_doc(self):
        src = os.path.join(self.tmp, "p.txt")
        with open(src, "w") as f:
            f.write("x")
        enc = os.path.join(self.tmp, "p.enc")
        code, out, err, _ = _run(
            [
                "encrypt",
                "-i",
                src,
                "-o",
                enc,
                "--force-password",
                "--sha512-rounds",
                "10",
                "--json",
            ],
            env={"CRYPT_PASSWORD": "right-password-123"},
        )
        self.assertEqual(code, 0, err[-300:])
        dec = os.path.join(self.tmp, "p.out")
        code, out, err, _ = _run(
            ["decrypt", "-i", enc, "-o", dec, "--json"],
            env={"CRYPT_PASSWORD": "wrong-password-456"},
        )
        self.assertNotEqual(code, 0)
        _error_doc(self, out)


class TestF8ManifestEnforcedFields(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        code, out, _, _ = _run(["capabilities"])
        assert code == 0
        cls.manifest = json.loads(out)

    def _data_of(self, argv):
        code, out, err, _ = _run(argv)
        self.assertEqual(code, 0, f"{argv}: {err[-300:]}")
        return json.loads(out)

    def test_envelope_data_keys_stay_within_pinned_fields(self):
        # Envelope endpoints: every emitted data key must be curated in
        # json_fields - the manifest is the enforced allowlist, so a future
        # payload widening (e.g. a secret slipping in) fails this test.
        for endpoint, argv in {
            "version": ["version", "--json"],
            "show-version-file": ["show-version-file", "--json"],
            "list-algorithms": ["list-algorithms", "--json"],
            "check-argon2": ["check-argon2", "--json"],
            "check-pqc": ["check-pqc", "--json"],
            "security-info": ["security-info", "--json"],
            "list-plugins": ["list-plugins", "--json"],
        }.items():
            if endpoint not in self.manifest["commands"]:
                continue
            doc = self._data_of(argv)
            self.assertEqual(doc["status"], "ok", endpoint)
            pinned = set(self.manifest["json_fields"][endpoint])
            self.assertLessEqual(
                set(doc["data"].keys()),
                pinned,
                f"{endpoint} emits keys outside its curated json_fields",
            )

    def test_bare_documents_carry_their_pinned_keys(self):
        # Frozen bare documents: the pinned keys are the guaranteed subset.
        for endpoint, argv in {
            "list-available-algorithms": ["list-available-algorithms"],
        }.items():
            if endpoint not in self.manifest["commands"]:
                continue
            doc = self._data_of(argv)
            pinned = set(self.manifest["json_fields"][endpoint])
            self.assertLessEqual(
                pinned, set(doc.keys()), f"{endpoint} lost a key its json_fields pin guarantees"
            )


if __name__ == "__main__":
    unittest.main()
