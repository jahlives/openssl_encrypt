"""PIV hardware integration tests.

Marked ``@pytest.mark.integration`` and skipped automatically when no PIV token
is configured (see conftest.py). They validate the determinism guarantee and
clean error handling against real hardware (YubiKey Bio MPE, Token2 R3.3+, or
any PKCS#11 PIV token).
"""

import os

import pytest

SALT16 = b"piv-hw-test-salt"  # 16 bytes, mirrors the real pepper pipeline


@pytest.mark.integration
class TestPIVHardwareDeterminism:
    def test_two_consecutive_signs_are_deterministic(self, piv_backend, piv_pin):
        pepper1 = piv_backend.get_pepper(SALT16, pin=bytearray(piv_pin) if piv_pin else None)
        pepper2 = piv_backend.get_pepper(SALT16, pin=bytearray(piv_pin) if piv_pin else None)
        assert pepper1 == pepper2
        assert len(pepper1) == 32

    def test_different_input_yields_different_pepper(self, piv_backend, piv_pin):
        a = piv_backend.get_pepper(b"input-alpha--16b", pin=bytearray(piv_pin) if piv_pin else None)
        b = piv_backend.get_pepper(b"input-beta---16b", pin=bytearray(piv_pin) if piv_pin else None)
        assert a != b

    def test_verify_hardware_reports_all_checks_pass(self, piv_backend, piv_pin):
        result = piv_backend.verify_hardware(pin=bytearray(piv_pin) if piv_pin else None)
        assert result["library_file_exists"] is True
        assert result["library_loadable"] is True
        assert result["key_present"] is True
        assert result["key_type_supported"] is True
        assert result["deterministic"] is True
        assert result["pepper_length_ok"] is True
        assert result["session_closed"] is True


@pytest.mark.integration
class TestPIVHardwareErrorHandling:
    @pytest.mark.skipif(
        not os.environ.get("PIV_TEST_DISCONNECT"),
        reason="Manual test: set PIV_TEST_DISCONNECT and pull the token when prompted",
    )
    def test_disconnect_mid_operation_raises_clean_error(self, piv_backend, piv_pin):
        from openssl_encrypt.modules.piv_backend import PIVError

        input("\n>>> Unplug / remove the PIV token now, then press Enter to attempt a signature...")
        with pytest.raises(PIVError) as exc:
            piv_backend.get_pepper(SALT16, pin=bytearray(piv_pin) if piv_pin else None)
        # The error must be one of our descriptive PIV errors, not a raw PKCS#11 crash.
        assert "PIN" not in str(exc.value) or "locked" in str(exc.value).lower()
