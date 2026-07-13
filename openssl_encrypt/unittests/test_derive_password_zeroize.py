#!/usr/bin/env python3
"""
Regression tests for gitlab#123 (security review 2026-07-13, LOW-1).

The derive-password CLI action did not apply the gitlab#113 zeroization
discipline: the HSM pepper was held as plain immutable bytes and never
wiped, and the cleanup wiped only a *copy* of the derived key
(bytearray(key)) while the truncated output slice stayed resident.

Scope (decided 2026-07-13): the handler wipes the pepper buffer and the
wipeable derived-output copies. The immutable bytes returned by
generate_key itself (M10 design, common to all callers) is out of scope.
"""

import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from openssl_encrypt.modules import secure_memory
from openssl_encrypt.modules.crypt_cli import main as cli_main


class _WipeRecorder:
    """Wrap the real secure_memzero, snapshotting buffers it successfully wipes.

    Snapshots are taken at call time but recorded only when the real call
    returns True: secure_memzero refuses immutable input (M10), and a refused
    wipe must not satisfy these tests.
    """

    def __init__(self):
        self.real = secure_memory.secure_memzero
        self.wiped = []

    def __call__(self, data, *args, **kwargs):
        snapshot = bytes(data) if isinstance(data, (bytes, bytearray, memoryview)) else None
        result = self.real(data, *args, **kwargs)
        if result and snapshot is not None:
            self.wiped.append(snapshot)
        return result


class TestDerivePasswordZeroize(unittest.TestCase):
    """The derive-password handler must wipe pepper and derived-key copies."""

    FIXED_SALT = "aa" * 16
    PEPPER = b"\xab" * 20

    def _mock_yubikey_plugin(self, pepper):
        from openssl_encrypt.modules.plugin_system.plugin_base import PluginResult

        fake_plugin = mock.MagicMock()
        fake_plugin.plugin_id = "yubikey_hsm"
        fake_plugin.name = "Yubikey Challenge-Response HSM"
        fake_plugin.get_required_capabilities.return_value = set()
        fake_plugin.initialize.return_value = PluginResult.success_result("initialized")
        fake_plugin.get_hsm_pepper.return_value = PluginResult.success_result(
            "ok",
            data={"hsm_pepper": pepper, "slot": 1},
        )
        return mock.patch(
            "openssl_encrypt.plugins.hsm.yubikey_challenge_response.YubikeyHSMPlugin",
            return_value=fake_plugin,
        )

    def _run(self, extra_args, pepper, recorder=None):
        """Run derive-password --hsm yubikey with a fixed pepper.

        Enables Argon2 with minimal cost so generate_key actually runs a KDF
        (same rationale as TestDerivePasswordHsm in test_derive_password.py).
        """
        import contextlib

        base = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--password",
            "testpassword123!",
            "--salt",
            self.FIXED_SALT,
            "--enable-argon2",
            "--argon2-rounds",
            "1",
            "--argon2-time",
            "1",
            "--argon2-memory",
            "8",
            "--argon2-parallelism",
            "1",
            "--hsm",
            "yubikey",
        ]
        sys.argv = base + extra_args
        stdout_capture, stderr_capture = io.StringIO(), io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        exit_code = None
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            with contextlib.ExitStack() as stack:
                stack.enter_context(self._mock_yubikey_plugin(pepper))
                if recorder is not None:
                    stack.enter_context(
                        mock.patch.object(secure_memory, "secure_memzero", recorder)
                    )
                with mock.patch("sys.exit") as mock_exit:
                    mock_exit.side_effect = SystemExit
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else (mock_exit.call_args[0][0] if mock_exit.called else 0)
                        )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_plugin_pepper_buffer_zeroized_after_run(self):
        """A mutable pepper buffer from the plugin is wiped in place.

        The plugin hands over a bytearray; after the handler finishes, that
        very buffer must be all zeros (identity-based check - wiping a copy
        does not count).
        """
        pepper_ba = bytearray(self.PEPPER)
        rc, stdout, stderr = self._run([], pepper_ba)
        self.assertEqual(rc, 0, f"stderr: {stderr}")
        self.assertRegex(stdout.strip(), r"^[0-9a-f]+$")
        self.assertEqual(
            pepper_ba,
            bytearray(len(self.PEPPER)),
            "HSM pepper buffer was not zeroized in place after derive-password",
        )

    def test_derived_output_buffer_zeroized(self):
        """The truncated derived-output buffer is wiped after printing.

        Uses --output-length 16 so the output slice differs from the full
        key: pre-fix code wiped only a bytearray copy of the full key, never
        a buffer holding the 16-byte output.
        """
        recorder = _WipeRecorder()
        rc, stdout, stderr = self._run(
            ["--output-length", "16"], bytearray(self.PEPPER), recorder=recorder
        )
        self.assertEqual(rc, 0, f"stderr: {stderr}")
        derived = bytes.fromhex(stdout.strip())
        self.assertEqual(len(derived), 16)
        self.assertIn(
            derived,
            recorder.wiped,
            "derived output buffer was never passed to secure_memzero",
        )

    def test_pepper_still_alters_output(self):
        """Wiping must not change derivation: same pepper, same output."""
        rc1, out1, _ = self._run([], bytearray(self.PEPPER))
        rc2, out2, _ = self._run([], bytearray(self.PEPPER))
        rc3, out3, _ = self._run([], bytearray(b"\x11" * 20))
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertEqual(rc3, 0)
        self.assertEqual(out1.strip(), out2.strip())
        self.assertNotEqual(out1.strip(), out3.strip())


if __name__ == "__main__":
    unittest.main()
