"""Regression tests for audit-log value-level scrubbing (#56 / CLI-2).

The audit logger only redacted fields whose NAME contained password/key/etc., so
a secret value stored under a differently-named field (e.g. "note", "detail")
was written verbatim. The fix adds a value-level scrubber that redacts
secret-shaped values (long high-entropy tokens, or values equal to a known
password environment variable) regardless of field name, recursively, while
preserving legitimate audit content such as file paths and short words.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.security_logger import SecurityAuditLogger


class TestAuditLogValueScrub(unittest.TestCase):
    def setUp(self):
        SecurityAuditLogger._instance = None
        self._tmp = tempfile.TemporaryDirectory()
        self.logger = SecurityAuditLogger(log_dir=self._tmp.name, enabled=True)

    def tearDown(self):
        SecurityAuditLogger._instance = None
        self._tmp.cleanup()

    def _log_content(self):
        with open(self.logger.log_file, "r", encoding="utf-8") as f:
            return f.read()

    def test_high_entropy_value_under_benign_field_is_redacted(self):
        token = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # 36-char high-entropy blob
        self.logger.log_event("evt", "info", {"note": token})
        content = self._log_content()
        self.assertNotIn(token, content)
        self.assertIn("***REDACTED***", content)

    def test_password_env_value_under_benign_field_is_redacted(self):
        os.environ["CRYPT_PASSWORD"] = "hunter2short"  # too short to be high-entropy
        try:
            self.logger.log_event("evt", "info", {"info": "hunter2short"})
        finally:
            del os.environ["CRYPT_PASSWORD"]
        self.assertNotIn("hunter2short", self._log_content())

    def test_nested_secret_value_is_redacted(self):
        token = "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"  # 36 chars, benign nested key
        self.logger.log_event("evt", "info", {"meta": {"blob": token}})
        self.assertNotIn(token, self._log_content())

    def test_paths_and_short_values_are_preserved(self):
        self.logger.log_event("evt", "info", {"file_path": "/tmp/test.txt", "operation": "encrypt"})
        content = self._log_content()
        self.assertIn("/tmp/test.txt", content)
        self.assertIn("encrypt", content)


if __name__ == "__main__":
    unittest.main()
