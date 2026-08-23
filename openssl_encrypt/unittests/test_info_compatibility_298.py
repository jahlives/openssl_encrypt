#!/usr/bin/env python3
"""info reports per-file decryptability on the running line (gitlab#298).

``assess_decrypt_compatibility`` computes, from PUBLIC header metadata only,
whether this version can decrypt the file — surfacing the fail-closed
refusals of gitlab#294/#295/#296/#297 at inspection time instead of at a
failed decrypt. Hard constraints (maintainer, 2026-08-23):

- header-only: the assessment takes the metadata dict and nothing else — no
  password may influence it, so ``info`` cannot become a password oracle;
- it never raises: a crafted header degrades to an "unknown" note, never an
  info abort;
- streaming aes-ocb3 files stay decryptable and must NOT be flagged;
- legacy kyber names route since gitlab#296 and must NOT be flagged.
"""

import base64
import inspect
import json
import os
import tempfile
import unittest

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

    def test_clean_v14_file_has_no_blockers(self):
        """A current-format fixture reports decryptable with no issues."""
        result = assess_decrypt_compatibility(_fixture_metadata("v14_default.enc"))
        self.assertTrue(result["decryptable"])
        self.assertEqual(result["issues"], [])


class TestRemovedComponentsFlagged(unittest.TestCase):
    """Each fail-closed refusal surfaces as an inspection-time issue."""

    def _issues_for(self, meta):
        result = assess_decrypt_compatibility(meta)
        self.assertFalse(result["decryptable"])
        return json.dumps(result["issues"])

    def test_pbkdf2_sequential_flagged(self):
        """The pbkdf2-era sequential fixture is flagged as undecryptable."""
        issues = self._issues_for(_fixture_metadata("v13_sequential.enc"))
        self.assertIn("pbkdf2", issues)

    def test_whirlpool_flagged(self):
        """Recorded whirlpool rounds are flagged (gitlab#294)."""
        meta = _fixture_metadata("v14_default.enc")
        meta["derivation_config"]["hash_config"]["whirlpool"] = {"rounds": 5}
        self.assertIn("whirlpool", self._issues_for(meta))

    def test_camellia_flagged(self):
        """A camellia file is flagged with the removal (gitlab#297)."""
        meta = _fixture_metadata("v14_default.enc")
        meta["encryption"]["algorithm"] = "camellia"
        self.assertIn("camellia", self._issues_for(meta))

    def test_non_streaming_aes_ocb3_flagged(self):
        """Non-streaming aes-ocb3 is flagged; the detail names streaming."""
        meta = _fixture_metadata("v14_default.enc")
        meta["encryption"]["algorithm"] = "aes-ocb3"
        issues = self._issues_for(meta)
        self.assertIn("aes-ocb3", issues)
        self.assertIn("streaming", issues)

    def test_pqc_aes_ocb3_data_cipher_flagged(self):
        """A PQC hybrid with aes-ocb3 encryption_data is flagged (gitlab#295)."""
        meta = _fixture_metadata("v14_pqc.enc")
        meta["encryption"]["encryption_data"] = "aes-ocb3"
        self.assertIn("aes-ocb3", self._issues_for(meta))


class TestExemptionsNotFlagged(unittest.TestCase):
    """Decryptable configurations must not be flagged."""

    def test_streaming_aes_ocb3_not_flagged(self):
        """Streaming aes-ocb3 stays decryptable (maintainer decision)."""
        meta = _fixture_metadata("v14_streaming.enc")
        meta["encryption"]["algorithm"] = "aes-ocb3"
        result = assess_decrypt_compatibility(meta)
        self.assertTrue(result["decryptable"], msg=repr(result))

    def test_legacy_kyber_name_not_flagged(self):
        """kyber-named hybrids route since gitlab#296 — a note, not an issue."""
        import importlib.util

        if importlib.util.find_spec("oqs") is None:
            self.skipTest("liboqs-python not installed")
        meta = _fixture_metadata("v14_pqc.enc")
        meta["encryption"]["algorithm"] = "kyber768-hybrid"
        result = assess_decrypt_compatibility(meta)
        self.assertTrue(result["decryptable"], msg=repr(result))

    def test_recorded_noop_hash_rounds_not_flagged(self):
        """Historically recorded no-op hash rounds decrypt fine (gitlab#294)."""
        meta = _fixture_metadata("v14_default.enc")
        meta["derivation_config"]["hash_config"]["sha384"] = {"rounds": 4}
        result = assess_decrypt_compatibility(meta)
        self.assertTrue(result["decryptable"], msg=repr(result))


class TestInfoJsonCarriesCompatibility(unittest.TestCase):
    """info --json emits the compatibility document."""

    def test_json_document_contains_compatibility(self):
        """The emitted JSON gains a top-level compatibility key."""
        import contextlib
        import io

        from openssl_encrypt.modules.crypt_core import print_file_info

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            print_file_info(os.path.join(FIXTURE_DIR, "v14_default.enc"), json_output=True)
        doc = json.loads(stdout.getvalue())
        self.assertIn("compatibility", doc)
        self.assertTrue(doc["compatibility"]["decryptable"])

    def test_capabilities_manifest_registers_compatibility(self):
        """The capabilities json_fields for info include the new key."""
        from openssl_encrypt.modules.capabilities import _JSON_FIELDS

        self.assertIn("compatibility", _JSON_FIELDS["info"])
