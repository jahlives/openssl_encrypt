"""Pytest fixtures for PIV hardware integration tests.

These tests run against a real PIV token and are skipped automatically unless
the environment describes one. Configure via environment variables:

    PIV_PKCS11_LIB   path to the PKCS#11 module (e.g. /usr/lib/opensc-pkcs11.so)
    PIV_SLOT_INDEX   PKCS#11 slot index (default 0)
    PIV_SLOT         PIV key slot in hex: 9a (default), 9c, 9d, 9e
    PIV_PIN          PIN for PIN-only keys (test-harness only; never used by the app)
    PIV_BIOMETRIC    set (to anything) for Bio keys; the PIN prompt is skipped
    PIV_TEST_DISCONNECT  set to enable the manual mid-operation disconnect test

This conftest intentionally does NOT import the PKCS#11 mock: integration tests
exercise the real binding and real hardware.
"""

import os

import pytest


def _require_binding():
    try:
        import pkcs11  # noqa: F401
    except ImportError:
        pytest.skip("python-pkcs11 is not installed; skipping PIV hardware tests")


@pytest.fixture
def piv_lib_path():
    lib = os.environ.get("PIV_PKCS11_LIB")
    if not lib:
        pytest.skip("Set PIV_PKCS11_LIB to a PKCS#11 module path to run PIV hardware tests")
    if not os.path.isfile(lib):
        pytest.skip(f"PIV_PKCS11_LIB does not point to a file: {lib}")
    return lib


@pytest.fixture
def piv_pin():
    """Return the PIN as a bytearray, or None for the biometric flow."""
    if os.environ.get("PIV_BIOMETRIC"):
        return None
    pin = os.environ.get("PIV_PIN")
    if pin is None:
        pytest.skip("Set PIV_PIN (or PIV_BIOMETRIC) to run PIV hardware tests")
    return bytearray(pin.encode("utf-8"))


@pytest.fixture
def piv_backend(piv_lib_path):
    _require_binding()
    from openssl_encrypt.modules.piv_backend import PIVBackend

    slot_index = int(os.environ.get("PIV_SLOT_INDEX", "0"))
    piv_slot = int(os.environ.get("PIV_SLOT", "9a"), 16)
    return PIVBackend(piv_lib_path, slot_index=slot_index, piv_slot=piv_slot)
