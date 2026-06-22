#!/usr/bin/env python3
"""
Regression tests: thread-local debug-mode must not leak across tests.

``crypt_cli`` enables raw-exception passthrough via ``set_debug_mode(True)`` for
the lifetime of the process (see crypt_cli.py, the ``--debug`` path). Under
pytest-xdist a worker process is reused across many tests, so without a per-test
reset that thread-local state leaks: a later test on the same worker sees
passthrough enabled and ``secure_error_handler`` re-raises the *raw* exception
instead of translating it to a SecureError subclass. That was observed as
intermittent failures of ``TestCryptErrorsFixes`` (keystore error category).

The fix is an autouse fixture in ``conftest.py`` that resets the debug state to a
clean baseline before every test. These tests guard that behaviour; when run in
order (serially) ``test_a`` deliberately leaks the state and the later tests
prove the reset cleared it.
"""

import unittest

from openssl_encrypt.modules.crypt_errors import (
    ErrorCategory,
    KeystoreError,
    is_debug_passthrough_enabled,
    secure_error_handler,
    set_debug_mode,
)


class TestDebugModeIsolation(unittest.TestCase):
    """The autouse reset must neutralise leaked debug-passthrough state."""

    def test_a_leak_debug_passthrough(self) -> None:
        """Simulate a prior CLI ``--debug`` test that leaves passthrough enabled."""
        set_debug_mode(True)
        self.assertTrue(is_debug_passthrough_enabled())

    def test_b_baseline_is_clean_after_leak(self) -> None:
        """Despite test_a, this test must start with passthrough disabled."""
        self.assertFalse(
            is_debug_passthrough_enabled(),
            "debug passthrough leaked from a previous test; autouse reset missing",
        )

    def test_c_handler_wraps_after_leak(self) -> None:
        """The secure handler must wrap raw exceptions, not pass them through."""

        @secure_error_handler(error_category=ErrorCategory.KEYSTORE)
        def boom():
            raise RuntimeError("boom")

        with self.assertRaises(KeystoreError):
            boom()


if __name__ == "__main__":
    unittest.main()
