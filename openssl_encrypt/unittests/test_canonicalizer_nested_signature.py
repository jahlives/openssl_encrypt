"""Regression test for root-only signature stripping in canonicalization (#86 / PQC-6).

MetadataCanonicalizer built the signed byte string by recursively removing EVERY
key named 'signature' at any depth. The top-level envelope signature must be
excluded (it can't sign itself), but a nested field named 'signature' (e.g. a
per-recipient or per-key signature) would then fall OUTSIDE the signed transcript
and could be altered without invalidating the outer signature.

The fix strips only the top-level 'signature' key; nested 'signature' fields stay
in the canonical bytes. Current metadata has 'signature' only at the top level,
so existing signatures still verify (canonical bytes unchanged for that shape).
"""

import unittest

from openssl_encrypt.modules.asymmetric_core import MetadataCanonicalizer


class TestCanonicalizerNestedSignature(unittest.TestCase):
    def test_top_level_signature_stripped_nested_retained(self):
        metadata = {
            "algorithm": "ml-kem-768",
            "signature": "TOP_LEVEL_ENVELOPE_SIG",
            "recipients": [
                {"id": "r1", "signature": "NESTED_RECIPIENT_SIG_1"},
                {"id": "r2", "signature": "NESTED_RECIPIENT_SIG_2"},
            ],
        }
        canonical = MetadataCanonicalizer.canonicalize(metadata).decode("utf-8")

        # The top-level envelope signature is excluded (it cannot sign itself).
        self.assertNotIn("TOP_LEVEL_ENVELOPE_SIG", canonical)
        # Nested signatures must remain inside the signed transcript.
        self.assertIn("NESTED_RECIPIENT_SIG_1", canonical)
        self.assertIn("NESTED_RECIPIENT_SIG_2", canonical)
        self.assertIn("r1", canonical)

    def test_top_level_only_metadata_is_unchanged(self):
        # Backward-compat: for metadata whose only 'signature' is top-level, the
        # canonical bytes are exactly the fields minus that key.
        metadata = {"b": 2, "a": 1, "signature": "SIG"}
        canonical = MetadataCanonicalizer.canonicalize(metadata).decode("utf-8")
        self.assertEqual(canonical, '{"a":1,"b":2}')


if __name__ == "__main__":
    unittest.main()
