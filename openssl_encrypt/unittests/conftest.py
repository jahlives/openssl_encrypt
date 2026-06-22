#!/usr/bin/env python3
"""
Shared pytest fixtures for the openssl_encrypt unit-test suite.

Provides per-test isolation for process-global state that would otherwise leak
between tests sharing a pytest-xdist worker process.
"""

import pytest

from openssl_encrypt.modules.crypt_errors import set_debug_mode


@pytest.fixture(autouse=True)
def _reset_debug_mode():
    """Reset thread-local debug passthrough to a clean baseline before each test.

    ``crypt_cli`` calls ``set_debug_mode(True)`` on the ``--debug`` path, enabling
    raw-exception passthrough for the lifetime of the process. xdist reuses a
    worker process across tests, so without this reset that state leaks: a later
    test sees passthrough enabled and ``secure_error_handler`` re-raises raw
    exceptions instead of translating them, producing order-dependent failures
    (e.g. ``TestCryptErrorsFixes``). Forcing passthrough off before each test
    guarantees a deterministic baseline regardless of run order; tests that need
    passthrough enable it themselves within the test body.
    """
    set_debug_mode(False)
    yield
