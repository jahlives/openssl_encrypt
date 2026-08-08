#!/usr/bin/env python3
"""
`verify-signature --json` must answer on every outcome, and must expose the
authenticated algorithm (gitlab#160).

Two defects in one machine-readable channel:

  * **It went silent on the security-relevant outcome.** A pinned-signer
    mismatch, an unknown pinned identity and an unknown signer each wrote a
    message to stderr and `sys.exit(1)` without emitting any JSON. So a
    consumer that asked for JSON got an empty stdout and a bare exit code
    for exactly the cases that mean "this signature is not from who you
    said" -- and had to guess. The GUI guessed from "did the user pin?",
    which works but is inference, not information.

  * **It exposed the attacker-controlled labels and withheld the
    authenticated one.** `components[].component` is free text from the
    sidecar and is deliberately NOT part of the signed payload -- so a `.sig`
    can carry a valid signature whose labels name algorithms that were never
    used. Meanwhile `algorithm` IS bound into `_signed_payload`, and was
    absent from the JSON entirely. The only algorithm information a consumer
    could display was the part an attacker controls.

Both are about the same property: a JSON consumer should be able to act on
the verdict without inferring anything.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _SignatureTestCase(unittest.TestCase):
    """Builds a real identity, signs a real file, then verifies it."""

    PW = "Tr0ub4dor&3-Correct-Horse!"

    def setUp(self):
        from openssl_encrypt.modules.identity import Identity, IdentityStore

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = self.tmp / "identities"
        self.target = self.tmp / "data.txt"
        self.target.write_text("signed content")

        # Built directly rather than through `identity create`: that command
        # prompts, and the point here is the verify path's JSON.
        store = IdentityStore(base_path=str(self.store))
        for name in ("signer-a", "signer-b"):
            store.add_identity(
                Identity.generate(name, f"{name}@x.test", self.PW), passphrase=self.PW
            )

        # Signed through the library rather than the `sign` command: on this
        # branch the signer passphrase can only come from an interactive
        # prompt (OPENSSL_ENCRYPT_SIGNER_PASSPHRASE is 1.4.x-only) and a
        # subprocess cannot answer /dev/tty. The subject here is the VERIFY
        # path's JSON, so producing the sidecar directly is the honest way to
        # reach it.
        import datetime

        from openssl_encrypt.modules.file_signature import (
            build_signature,
            hash_file,
            serialize_signature,
        )

        signer = store.get_by_name("signer-a", load_private_keys=True, passphrase=self.PW)
        sidecar = build_signature(
            hash_file(str(self.target)),
            signer,
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        # Raw JSON, not armored, so these tests can read and relabel it.
        self.sig.write_bytes(serialize_signature(sidecar, armored=False))

    @property
    def sig(self):
        return self.tmp / "data.txt.sig"

    def _cli(self, *argv):
        env = dict(os.environ)
        # The environment variable, not the global --identity-store flag:
        # that flag does not reach the store resolution for these commands
        # (a separate defect, tracked as gitlab#210).
        env["OPENSSL_ENCRYPT_IDENTITY_STORE"] = str(self.store)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt.crypt",
                *argv,
            ],
            capture_output=True,
            text=True,
            cwd=REPO,
            env=env,
            timeout=180,
        )

    def _verify_json(self, *extra):
        result = self._cli(
            "verify-signature",
            "-i",
            str(self.target),
            "--signature",
            str(self.sig),
            "--json",
            *extra,
        )
        return result


class TestTheJsonChannelAlwaysAnswers(_SignatureTestCase):
    def test_a_good_signature_emits_json(self):
        result = self._verify_json()
        document = json.loads(result.stdout)
        self.assertTrue(document["valid"], document)

    def test_a_pinned_signer_mismatch_emits_json(self):
        """The defect: this printed nothing on stdout and exited 1."""
        result = self._verify_json("--signer", "signer-b")

        self.assertTrue(
            result.stdout.strip(),
            "no JSON was emitted for a pinned-signer mismatch, so a consumer "
            f"gets only an exit code: {result.stderr[-300:]}",
        )
        document = json.loads(result.stdout)
        self.assertFalse(document["valid"])
        self.assertTrue(document.get("reason"), document)

    def test_an_unknown_pinned_identity_emits_json(self):
        result = self._verify_json("--signer", "no-such-identity")
        self.assertTrue(result.stdout.strip(), result.stderr[-300:])
        document = json.loads(result.stdout)
        self.assertFalse(document["valid"])
        self.assertTrue(document.get("reason"), document)

    def test_an_unparseable_signature_emits_json(self):
        """The same silence, one step earlier: a malformed sidecar exited 1
        with nothing on stdout."""
        self.sig.write_text("this is not a signature")
        result = self._verify_json()
        self.assertTrue(result.stdout.strip(), result.stderr[-300:])
        document = json.loads(result.stdout)
        self.assertFalse(document["valid"])
        self.assertTrue(document.get("reason"), document)

    def test_a_missing_signature_file_emits_json(self):
        self.sig.unlink()
        result = self._verify_json()
        self.assertTrue(result.stdout.strip(), result.stderr[-300:])
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_the_exit_code_still_signals_failure(self):
        """Emitting JSON must not turn a refusal into success -- a script
        checking $? has to keep working."""
        for extra in (("--signer", "signer-b"), ("--signer", "no-such-identity")):
            with self.subTest(extra=extra):
                self.assertNotEqual(self._verify_json(*extra).returncode, 0)


class TestTheAuthenticatedAlgorithmIsExposed(_SignatureTestCase):
    def test_the_algorithm_field_is_present(self):
        document = json.loads(self._verify_json().stdout)
        self.assertIn(
            "algorithm",
            document,
            "the authenticated algorithm is absent, so the only algorithm "
            "information a consumer can show is the unauthenticated labels",
        )
        self.assertTrue(document["algorithm"])

    def test_it_matches_the_signed_payload(self):
        """It has to be the value that was signed, not one re-read from the
        sidecar's display fields."""
        document = json.loads(self._verify_json().stdout)
        sidecar = json.loads(self.sig.read_text())
        self.assertEqual(document["algorithm"], sidecar["algorithm"])

    def test_a_relabelled_component_does_not_change_it(self):
        """The point of the distinction: the label is not signed, the
        algorithm is.

        The label is format-validated, so it cannot be arbitrary text -- but
        it can be swapped for a DIFFERENT valid algorithm name, and the
        signature still verifies, because verification uses only the
        entry's `value`. `algorithm` is bound into the signed payload and
        cannot be moved that way.
        """
        sidecar = json.loads(self.sig.read_text())
        # The labels live under "signatures"; `components` in the JSON output
        # is derived from them at verify time.
        self.assertTrue(sidecar.get("signatures"), "the fixture produced no component list")
        real_algorithm = sidecar["algorithm"]
        for entry in sidecar["signatures"]:
            entry["component"] = "ml-dsa-87" if real_algorithm != "ml-dsa-87" else "ml-dsa-44"
        self.sig.write_text(json.dumps(sidecar, indent=2))

        result = self._verify_json()
        document = json.loads(result.stdout)
        self.assertTrue(
            document["valid"],
            "rewriting an unauthenticated label broke verification; if that "
            "is now signed, this test's premise needs revisiting",
        )
        self.assertEqual(document["algorithm"], real_algorithm)


if __name__ == "__main__":
    unittest.main()
