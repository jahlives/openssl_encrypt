#!/usr/bin/env python3
"""info reports decryptability and 1.5.x readiness (gitlab#298, 1.4.x port).

``assess_decrypt_compatibility`` on this line reports two things, computed
from PUBLIC header metadata only: whether THIS installation can decrypt the
file (missing local dependencies), and whether the file uses components that
v1.5.0 removed (``upgrade_blockers`` — "rekey before upgrading"). Hard
constraints (maintainer, 2026-08-23):

- header-only: the assessment takes the metadata dict and nothing else — no
  password may influence it, so ``info`` cannot become a password oracle;
- it never raises: a crafted header degrades, never aborts info;
- legacy kyber names and streaming aes-ocb3 decrypt on fixed 1.5.x and are
  notes, not upgrade blockers.
"""

import base64
import inspect
import json
import os
import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import assess_decrypt_compatibility

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")


def _fixture_metadata(name: str) -> dict:
    """Parse a fixture's metadata header without touching the payload."""
    raw = open(os.path.join(FIXTURE_DIR, name), "rb").read()
    head, _, _ = raw.partition(b":")
    return json.loads(base64.b64decode(head))


class TestAssessmentContract(unittest.TestCase):
    """Signature and no-raise guarantees (the anti-oracle constraints)."""

    def test_signature_takes_metadata_only(self):
        """No password-like parameter exists to influence the assessment."""
        params = list(inspect.signature(assess_decrypt_compatibility).parameters)
        self.assertEqual(params, ["metadata"])

    def test_never_raises_on_garbage(self):
        """Crafted/garbage headers must degrade, not abort info."""
        for garbage in (None, [], "x", {"encryption": "not-a-dict"}, {"derivation_config": 7}):
            with self.subTest(metadata=garbage):
                result = assess_decrypt_compatibility(garbage)
                self.assertIn("decryptable", result)

    def test_clean_v14_file_is_unremarkable(self):
        """A current-format fixture: decryptable, no upgrade blockers."""
        result = assess_decrypt_compatibility(_fixture_metadata("v14_default.enc"))
        self.assertTrue(result["decryptable"])
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["upgrade_blockers"], [])


class TestUpgradeBlockers(unittest.TestCase):
    """Components removed in 1.5.0 surface as upgrade blockers."""

    def _blockers_for(self, meta):
        result = assess_decrypt_compatibility(meta)
        self.assertTrue(result["decryptable"], msg="still decryptable HERE: " + repr(result))
        self.assertTrue(result["upgrade_blockers"], msg=repr(result))
        return json.dumps(result["upgrade_blockers"])

    def test_pbkdf2_sequential_is_upgrade_blocker(self):
        """The sequential pbkdf2 fixture must warn before a 1.5.x upgrade."""
        self.assertIn("pbkdf2", self._blockers_for(_fixture_metadata("v13_sequential.enc")))

    def test_pbkdf2_independent_not_flagged(self):
        """Independent-XOR files never used the pbkdf2 stage — no blocker."""
        result = assess_decrypt_compatibility(_fixture_metadata("v13_independent.enc"))
        self.assertEqual(result["upgrade_blockers"], [], msg=repr(result))

    def test_whirlpool_is_upgrade_blocker(self):
        """Whirlpool rounds warn before a 1.5.x upgrade."""
        meta = _fixture_metadata("v14_default.enc")
        meta["derivation_config"]["hash_config"]["whirlpool"] = {"rounds": 5}
        self.assertIn("whirlpool", self._blockers_for(meta))

    def test_camellia_and_nonstreaming_ocb3_are_upgrade_blockers(self):
        """Removed ciphers warn before a 1.5.x upgrade."""
        for name in ("camellia", "aes-ocb3"):
            with self.subTest(algorithm=name):
                meta = _fixture_metadata("v14_default.enc")
                meta["encryption"]["algorithm"] = name
                self.assertIn(name, self._blockers_for(meta))

    def test_streaming_ocb3_and_kyber_names_are_notes(self):
        """Streaming aes-ocb3 and kyber names decrypt on fixed 1.5.x."""
        meta = _fixture_metadata("v14_streaming.enc")
        meta["encryption"]["algorithm"] = "aes-ocb3"
        result = assess_decrypt_compatibility(meta)
        self.assertEqual(result["upgrade_blockers"], [], msg=repr(result))
        self.assertTrue(result["notes"])

        meta = _fixture_metadata("v14_pqc.enc")
        meta["encryption"]["algorithm"] = "kyber768-hybrid"
        result = assess_decrypt_compatibility(meta)
        self.assertEqual(result["upgrade_blockers"], [], msg=repr(result))
        self.assertTrue(any("ML-KEM" in note for note in result["notes"]), msg=repr(result))


class TestDependencyIssues(unittest.TestCase):
    """Missing local modules surface as decryptability issues HERE."""

    def test_whirlpool_module_missing_flagged(self):
        """Whirlpool rounds + missing module = not decryptable here."""
        meta = _fixture_metadata("v14_default.enc")
        meta["derivation_config"]["hash_config"]["whirlpool"] = {"rounds": 5}
        with mock.patch.object(crypt_core, "WHIRLPOOL_AVAILABLE", False):
            result = assess_decrypt_compatibility(meta)
        self.assertFalse(result["decryptable"])
        self.assertIn("whirlpool", json.dumps(result["issues"]))


class TestInfoJsonCarriesCompatibility(unittest.TestCase):
    """info --json emits the compatibility document."""

    def test_json_document_contains_compatibility(self):
        """The emitted JSON gains a top-level compatibility key."""
        import contextlib
        import io

        from openssl_encrypt.modules.crypt_core import print_file_info

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            print_file_info(os.path.join(FIXTURE_DIR, "v13_sequential.enc"), json_output=True)
        doc = json.loads(stdout.getvalue())
        self.assertIn("compatibility", doc)
        self.assertTrue(doc["compatibility"]["decryptable"])
        self.assertIn("pbkdf2", json.dumps(doc["compatibility"]["upgrade_blockers"]))

    def test_capabilities_manifest_registers_compatibility(self):
        """The capabilities json_fields for info include the new key."""
        from openssl_encrypt.modules.capabilities import _JSON_FIELDS

        self.assertIn("compatibility", _JSON_FIELDS["info"])
