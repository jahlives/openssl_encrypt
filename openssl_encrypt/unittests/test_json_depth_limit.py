"""Regression tests for GitLab #94 [IO-5]: JSON depth limit enforced only after parse.

``validate_json_structure`` capped nesting at 20, but only *after*
``json.loads`` had already parsed the full document — so a hostile
deeply-nested document could still drive the CPython parser into a
``RecursionError``, which was uncaught. The depth limit must be enforced
on the raw string before parsing, and ``RecursionError`` must be mapped
to the module's own exception.
"""

import unittest

from openssl_encrypt.modules.json_validator import (
    JSONSecurityError,
    SecureJSONValidator,
)


def _nested(depth: int, open_ch: str = "[", close_ch: str = "]") -> str:
    return open_ch * depth + close_ch * depth


class TestJSONDepthPreParse(unittest.TestCase):
    """Depth cap must reject hostile documents before json.loads runs."""

    def setUp(self) -> None:
        self.validator = SecureJSONValidator()

    def test_depth_within_limit_parses(self) -> None:
        depth = SecureJSONValidator.MAX_NESTING_DEPTH
        data = self.validator.parse_and_validate_json(_nested(depth))
        self.assertIsInstance(data, list)

    def test_depth_over_limit_rejected(self) -> None:
        depth = SecureJSONValidator.MAX_NESTING_DEPTH + 1
        with self.assertRaises(JSONSecurityError):
            self.validator.parse_and_validate_json(_nested(depth))

    def test_hostile_depth_rejected_without_recursion_error(self) -> None:
        """A parser-killing document must raise JSONSecurityError, not RecursionError."""
        hostile = _nested(100_000)
        try:
            self.validator.parse_and_validate_json(hostile)
        except JSONSecurityError:
            pass  # expected
        except RecursionError:  # pragma: no cover - the bug under test
            self.fail("RecursionError leaked through parse_and_validate_json")
        else:
            self.fail("hostile document was accepted")

    def test_hostile_object_depth_rejected(self) -> None:
        """Same guarantee for object nesting, not just arrays."""
        depth = 60_000
        hostile = '{"a":' * depth + "1" + "}" * depth
        with self.assertRaises(JSONSecurityError):
            self.validator.parse_and_validate_json(hostile)

    def test_depth_scan_ignores_brackets_inside_strings(self) -> None:
        """Brackets inside JSON strings are data, not structure."""
        doc = '{"key": "' + "[" * 100 + '"}'
        data = self.validator.parse_and_validate_json(doc)
        self.assertEqual(data["key"], "[" * 100)

    def test_depth_scan_handles_escaped_quotes(self) -> None:
        r"""Escaped quotes (\") must not terminate the in-string state."""
        doc = '{"key": "a\\"' + "[" * 100 + '"}'
        data = self.validator.parse_and_validate_json(doc)
        self.assertIn("[" * 100, data["key"])


if __name__ == "__main__":
    unittest.main()
