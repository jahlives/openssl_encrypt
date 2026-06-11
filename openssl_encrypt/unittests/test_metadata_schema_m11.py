#!/usr/bin/env python3
"""
Regression tests for M11: validate_metadata must not fail open on unknown
format versions, and must actually load/use every shipped metadata schema.

Two problems:
1. The metadata schema list in _load_schemas had drifted - metadata_v9 and
   metadata_v12 schema files existed on disk but were never registered, so
   those versions silently skipped schema validation.
2. validate_metadata returned the data unvalidated for any version not in a
   hand-maintained if/elif ladder ("fail open"), letting an attacker bypass
   the per-version schema by declaring an unknown version.

Fix: register metadata schemas dynamically, validate against the
version-specific schema when one exists, keep accepting genuine legacy
(missing / v1 / v2) under the generic security limits, and FAIL CLOSED for
unknown / future / non-integer versions.

See SECURITY_REVIEW_FINDINGS.md (M11).
"""

import json
import unittest

from openssl_encrypt.modules.json_validator import (
    JSONValidationError,
    SecureJSONValidator,
    get_json_validator,
    secure_metadata_loads,
)


class TestMetadataSchemaRegistration(unittest.TestCase):
    """Every metadata_v{N}_schema.json on disk must be registered."""

    def test_v9_and_v12_registered(self):
        v = SecureJSONValidator()
        self.assertIn("metadata_v9", v.schemas)
        self.assertIn("metadata_v12", v.schemas)

    def test_all_shipped_metadata_schemas_registered(self):
        import glob
        import os
        import re

        v = SecureJSONValidator()
        schemas_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schemas"
        )
        for path in glob.glob(os.path.join(schemas_dir, "metadata_v*_schema.json")):
            m = re.match(r"metadata_v(\d+)_schema\.json$", os.path.basename(path))
            if m:
                self.assertIn(f"metadata_v{m.group(1)}", v.schemas)


class TestMetadataFailClosed(unittest.TestCase):
    """Unknown / future / non-integer versions must be rejected, not skipped."""

    def test_unknown_high_version_rejected(self):
        with self.assertRaises(JSONValidationError):
            secure_metadata_loads(json.dumps({"format_version": 99}))

    def test_future_version_without_schema_rejected(self):
        # 13 has no schema shipped -> must fail closed, not skip validation
        with self.assertRaises(JSONValidationError):
            secure_metadata_loads(json.dumps({"format_version": 13}))

    def test_string_version_rejected(self):
        with self.assertRaises(JSONValidationError):
            secure_metadata_loads(json.dumps({"format_version": "10"}))

    def test_v9_now_schema_validated(self):
        # Previously v9 skipped schema validation entirely. A v9 doc missing
        # required fields (mode/derivation_config/encryption) must now be
        # rejected.
        with self.assertRaises(JSONValidationError):
            secure_metadata_loads(json.dumps({"format_version": 9}))

    def test_v12_now_schema_validated(self):
        with self.assertRaises(JSONValidationError):
            secure_metadata_loads(json.dumps({"format_version": 12}))


class TestMetadataLegacyStillAccepted(unittest.TestCase):
    """Genuine legacy / missing versions must keep loading (backward compat)."""

    def test_missing_version_accepted(self):
        data = secure_metadata_loads(json.dumps({"some": "legacy-metadata"}))
        self.assertEqual(data.get("some"), "legacy-metadata")

    def test_v1_accepted(self):
        data = secure_metadata_loads(json.dumps({"format_version": 1, "x": 1}))
        self.assertEqual(data.get("format_version"), 1)

    def test_v2_accepted(self):
        data = secure_metadata_loads(json.dumps({"format_version": 2}))
        self.assertEqual(data.get("format_version"), 2)


if __name__ == "__main__":
    unittest.main()
