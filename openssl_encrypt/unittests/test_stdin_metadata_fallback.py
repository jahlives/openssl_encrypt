#!/usr/bin/env python3
"""
`StdinMetadataExtractor._parse_metadata`'s validator-unavailable fallback
must work, and must bound what it reads (gitlab#118).

The issue reported that the `ImportError` fallback feeds
`metadata.get("format_version", 1)` straight into `format_version >= 4`, so
a crafted non-int value raises an unhandled TypeError.

Reproducing it showed something worse: **the fallback never ran at all.**
The names come from an import inside the `try`, and the first handler is
`except (JSONSecurityError, JSONValidationError)`. Evaluating that tuple
needs those names, which are unbound when the import failed, so it raised
`UnboundLocalError` before the `except ImportError` clause was ever
considered:

    format_version='4'   -> ValueError: cannot access local variable 'JSONSecurityError'
    format_version=True  -> ValueError: cannot access local variable 'JSONSecurityError'

Same function-local-import trap that has bitten this file before: a name
imported inside a function is local to the whole function, including the
except clauses evaluated before the import ran.

So this fixes two things: the fallback is now reachable, and it bounds
`format_version` the way the equivalent site in crypt_core.py already does
-- an int (not a bool) within range, rather than whatever the file says.
"""

import base64
import builtins
import json
import unittest


def _blocked_validator():
    """Context manager making `.json_validator` unimportable."""
    from unittest import mock

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if "json_validator" in name:
            raise ImportError("simulated: validator unavailable")
        return real_import(name, *args, **kwargs)

    return mock.patch.object(builtins, "__import__", blocked)


class _ExtractorTestCase(unittest.TestCase):
    def setUp(self):
        from openssl_encrypt.modules.crypt_cli import StdinMetadataExtractor

        self.extractor = StdinMetadataExtractor.__new__(StdinMetadataExtractor)

    def parse(self, document):
        return self.extractor._parse_metadata(base64.b64encode(json.dumps(document).encode()))


class TestTheFallbackIsReachable(_ExtractorTestCase):
    def test_a_valid_document_parses_without_the_validator(self):
        with _blocked_validator():
            result = self.parse({"format_version": 4, "encryption": {"algorithm": "aes-gcm"}})
        self.assertIsNotNone(result, "the fallback raised instead of parsing; it was unreachable")
        self.assertEqual(result["format_version"], 4)
        self.assertEqual(result["algorithm"], "aes-gcm")

    def test_an_older_format_still_reads_the_flat_shape(self):
        with _blocked_validator():
            result = self.parse({"format_version": 3, "algorithm": "fernet"})
        self.assertEqual(result["algorithm"], "fernet")

    def test_malformed_json_is_reported_not_raised(self):
        with _blocked_validator():
            self.assertIsNone(self.extractor._parse_metadata(base64.b64encode(b"{not json")))


class TestTheFallbackBoundsWhatItReads(_ExtractorTestCase):
    """A crafted file must not decide the version field's type."""

    def test_a_non_integer_version_is_refused(self):
        for value in ("4", [], {"a": 1}, None, 4.5):
            with self.subTest(value=value):
                with _blocked_validator():
                    self.assertIsNone(
                        self.parse({"format_version": value}),
                        f"a {type(value).__name__} version was accepted",
                    )

    def test_a_boolean_version_is_refused(self):
        """bool is an int subclass, so a plain isinstance check lets it
        through -- and `True >= 4` silently selects the legacy branch."""
        with _blocked_validator():
            self.assertIsNone(self.parse({"format_version": True}))

    def test_an_out_of_range_version_is_refused(self):
        from openssl_encrypt.modules.crypt_core import LATEST_STABLE_FORMAT_VERSION

        for value in (0, -1, LATEST_STABLE_FORMAT_VERSION + 1, 10**9):
            with self.subTest(value=value):
                with _blocked_validator():
                    self.assertIsNone(self.parse({"format_version": value}))

    def test_every_supported_version_is_accepted(self):
        """The negative arm: the bound must not refuse real files."""
        from openssl_encrypt.modules.crypt_core import LATEST_STABLE_FORMAT_VERSION

        for value in range(1, LATEST_STABLE_FORMAT_VERSION + 1):
            with self.subTest(value=value):
                with _blocked_validator():
                    self.assertIsNotNone(self.parse({"format_version": value}))

    def test_a_missing_version_still_defaults(self):
        with _blocked_validator():
            result = self.parse({"algorithm": "fernet"})
        self.assertEqual(result["format_version"], 1)


class TestTheValidatorPathIsUnchanged(_ExtractorTestCase):
    """The normal path already refuses these; it must keep doing so."""

    def test_a_crafted_version_is_still_refused_with_the_validator(self):
        for value in ("4", [], {"a": 1}):
            with self.subTest(value=value):
                self.assertIsNone(self.parse({"format_version": value}))

    def test_an_incomplete_document_is_still_refused_with_the_validator(self):
        """The validator enforces a schema the fallback cannot -- a v4
        document without `derivation_config` is rejected there and accepted
        by the fallback. That asymmetry is intended: the fallback is a
        degraded path, and this pins that using it does not silently become
        the norm.
        """
        self.assertIsNone(self.parse({"format_version": 4, "encryption": {"algorithm": "aes-gcm"}}))

        with _blocked_validator():
            self.assertIsNotNone(
                self.parse({"format_version": 4, "encryption": {"algorithm": "aes-gcm"}})
            )


if __name__ == "__main__":
    unittest.main()
