#!/usr/bin/env python3
"""Regression tests for gitlab#128 (KDF-cost memory-exhaustion DoS).

A crafted encrypted file or tampered keystore can declare arbitrarily large
memory-hard KDF cost parameters (Argon2 memory_cost, scrypt N, balloon
space_cost) that are consumed during key derivation BEFORE authentication,
OOM-crashing the host on decrypt. The fix adds an escapable peak-memory
ceiling (HARD_MEMORY_CEILING_KB, default 8 GiB) enforced before any KDF runs,
overridable via allow_high_kdf_cost / --allow-high-kdf-cost or an interactive
confirmation. Time/CPU cost stays advisory; only memory is hard-guarded.

Backward-compat invariant: a config at the largest shipped preset (2 GiB) is
below the ceiling and must never be refused.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from openssl_encrypt.modules import decryption_estimator as de
from openssl_encrypt.modules.benchmark_constants import HARD_MEMORY_CEILING_KB
from openssl_encrypt.modules.crypt_errors import ValidationError

# The exact hostile values from the finding.
ARGON2_1TIB_KIB = 1073741824  # 1 TiB expressed in KiB
SCRYPT_N_2POW30 = 2**30
SHIPPED_MAX_MEMORY_KB = 2 * 1024 * 1024  # 2 GiB, template_manager.py paranoid max


class TestCeilingConstant(unittest.TestCase):
    def test_ceiling_above_shipped_max(self):
        """The ceiling must sit strictly above the largest preset the tool
        ships, so no legitimate file is ever refused."""
        self.assertGreater(HARD_MEMORY_CEILING_KB, SHIPPED_MAX_MEMORY_KB)


class TestEnforceMemoryCeiling(unittest.TestCase):
    """Core guard logic: enforce_memory_ceiling(peak_memory_kb, ...)."""

    def test_under_ceiling_passes(self):
        # No raise for a value at the shipped maximum.
        de.enforce_memory_ceiling(
            SHIPPED_MAX_MEMORY_KB, allow_high_kdf_cost=False, interactive=False
        )

    def test_at_ceiling_passes(self):
        de.enforce_memory_ceiling(
            HARD_MEMORY_CEILING_KB, allow_high_kdf_cost=False, interactive=False
        )

    def test_over_ceiling_non_interactive_refused(self):
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(
                HARD_MEMORY_CEILING_KB + 1, allow_high_kdf_cost=False, interactive=False
            )

    def test_over_ceiling_override_flag_allows(self):
        # The escape hatch: explicit override proceeds even far over the ceiling.
        de.enforce_memory_ceiling(ARGON2_1TIB_KIB, allow_high_kdf_cost=True, interactive=False)

    def test_over_ceiling_interactive_yes_allows(self):
        with mock.patch("builtins.input", return_value="y"):
            de.enforce_memory_ceiling(ARGON2_1TIB_KIB, allow_high_kdf_cost=False, interactive=True)

    def test_over_ceiling_interactive_no_refused(self):
        with mock.patch("builtins.input", return_value=""):
            with self.assertRaises(ValidationError):
                de.enforce_memory_ceiling(
                    ARGON2_1TIB_KIB, allow_high_kdf_cost=False, interactive=True
                )

    def test_enforcement_independent_of_quiet_display(self):
        """The guard is not one of the display flags: it must fire on a huge
        value regardless of how the estimate would have been shown."""
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(ARGON2_1TIB_KIB, allow_high_kdf_cost=False, interactive=False)


class TestHostileMetadataEstimated(unittest.TestCase):
    """The real estimator on the finding's crafted metadata must land over the
    ceiling, so the guard rejects it."""

    def _meta(self, kdf_config):
        return {
            "format_version": 14,
            "derivation_config": {"hash_config": {}, "kdf_config": kdf_config},
        }

    def test_argon2_1tib_metadata_over_ceiling(self):
        est = de.estimate_decryption_cost(
            self._meta(
                {
                    "argon2": {
                        "enabled": True,
                        "memory_cost": ARGON2_1TIB_KIB,
                        "time_cost": 3,
                        "rounds": 1,
                    }
                }
            )
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)

    def test_scrypt_huge_n_metadata_over_ceiling(self):
        est = de.estimate_decryption_cost(
            self._meta({"scrypt": {"enabled": True, "n": SCRYPT_N_2POW30, "r": 8, "p": 1}})
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)

    def test_legitimate_2gib_metadata_under_ceiling(self):
        """Compat: a paranoid-but-real 2 GiB Argon2 config is accepted."""
        est = de.estimate_decryption_cost(
            self._meta(
                {
                    "argon2": {
                        "enabled": True,
                        "memory_cost": SHIPPED_MAX_MEMORY_KB,
                        "time_cost": 3,
                        "rounds": 1,
                    }
                }
            )
        )
        self.assertLessEqual(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)


class TestKeystoreCeiling(unittest.TestCase):
    """gitlab#128 F9/F10: the keystore load path bypasses the file estimator and
    must guard the header's KDF cost independently, before derivation."""

    def _write_keystore(self, memory_cost):
        import base64
        import json
        import struct
        import tempfile

        header = {
            "version": "1.0",
            "protection": {
                "method": "argon2id+aes-256-gcm",
                "params": {
                    "argon2_params": {
                        "memory_cost": memory_cost,
                        "time_cost": 3,
                        "parallelism": 4,
                    },
                    "salt": base64.b64encode(b"\x00" * 16).decode(),
                    "kdf_version": 2,
                },
            },
        }
        header_json = json.dumps(header).encode("utf-8")
        blob = struct.pack(">I", len(header_json)) + header_json + b"\x00" * 32
        fd, path = tempfile.mkstemp(suffix=".pqc")
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_keystore_huge_memory_cost_refused(self):
        from openssl_encrypt.modules.pqc_keystore import PQCKeystore

        ks = PQCKeystore(self._write_keystore(ARGON2_1TIB_KIB))
        with self.assertRaises(ValidationError) as ctx:
            ks.load_keystore("whatever")
        self.assertIn("ceiling", str(ctx.exception).lower())

    def test_keystore_normal_cost_passes_guard(self):
        """A normal-cost header must not be rejected by the ceiling guard (it
        will fail later for other reasons, but never at the guard)."""
        from openssl_encrypt.modules.pqc_keystore import PQCKeystore

        ks = PQCKeystore(self._write_keystore(65536))
        try:
            ks.load_keystore("whatever")
        except Exception as exc:  # noqa: BLE001 - only the guard message is asserted against
            self.assertNotIn("ceiling", str(exc).lower())


class TestEstimatorBypassRegressions(unittest.TestCase):
    """gitlab#128 security-review follow-up: metadata shapes that previously
    zeroed the estimated memory and slipped past the ceiling."""

    def _meta(self, kdf_config):
        return {
            "format_version": 14,
            "derivation_config": {"hash_config": {}, "kdf_config": kdf_config},
        }

    def test_scrypt_rounds_zero_still_counts_memory(self):
        """rounds=0 makes estimated time 0, but the executor runs scrypt once
        regardless, so its memory must still be counted."""
        est = de.estimate_decryption_cost(
            self._meta(
                {"scrypt": {"enabled": True, "n": SCRYPT_N_2POW30, "r": 8, "p": 1, "rounds": 0}}
            )
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)

    def test_balloon_rounds_zero_still_counts_memory(self):
        est = de.estimate_decryption_cost(
            self._meta({"balloon": {"enabled": True, "space_cost": 200_000_000, "rounds": 0}})
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)

    def test_nondict_kdf_config_fails_closed(self):
        """A non-dict KDF entry (crafted metadata) must trip the ceiling, not
        silently estimate to zero."""
        est = de.estimate_decryption_cost(self._meta({"argon2": "not-a-dict"}))
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)

    def test_parallel_sum_exceeds_ceiling_while_peak_does_not(self):
        """Concurrent components: each under the ceiling, but their sum over it.
        The parallel path must enforce against total_memory_kb."""
        half = 5 * 1024 * 1024  # 5 GiB each; two of them = 10 GiB
        est = de.estimate_decryption_cost(
            self._meta(
                {
                    "argon2": {"enabled": True, "memory_cost": half, "time_cost": 3, "rounds": 1},
                    "scrypt": {"enabled": True, "n": half * 1024 // 128, "r": 1, "p": 1},
                }
            )
        )
        self.assertLessEqual(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        self.assertGreater(est.total_memory_kb, HARD_MEMORY_CEILING_KB)

    def test_balloon_high_space_cost_stays_under_ceiling(self):
        """Compat: a legitimate custom high space_cost (real memory ~tens of MB)
        must not be refused (was a ~360x over-estimate before)."""
        est = de.estimate_decryption_cost(
            self._meta({"balloon": {"enabled": True, "space_cost": 262144, "time_cost": 20}})
        )
        self.assertLessEqual(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)


class TestRekeyFastPathCeiling(unittest.TestCase):
    """gitlab#128 security-review HIGH-1: the envelope rekey fast-path derives
    the KEK from the file's own KDF config without reaching decrypt_file, so it
    must enforce the ceiling itself."""

    def _write_envelope(self, memory_cost):
        import base64
        import json
        import tempfile

        meta = {
            "format_version": 14,
            "xor_mode": "independent",
            "encryption": {
                "algorithm": "aes-gcm",
                "cascade": False,
                "wrapped_dek": base64.b64encode(b"\x00" * 48).decode(),
            },
            "derivation_config": {
                "salt": base64.b64encode(b"\x00" * 16).decode(),
                "hash_config": {},
                "kdf_config": {
                    "argon2": {
                        "enabled": True,
                        "memory_cost": memory_cost,
                        "time_cost": 3,
                        "rounds": 1,
                    }
                },
            },
        }
        blob = base64.b64encode(json.dumps(meta).encode()) + b":" + b"\x00" * 32
        fd, path = tempfile.mkstemp(suffix=".enc")
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_rekey_fast_path_refuses_huge_kdf_cost(self):
        # Exercise the fast-path helper directly: it parses metadata itself and
        # derives the KEK before decrypt_file is ever reached, so this is where
        # the guard has to live.
        from openssl_encrypt.modules.crypt_core import _rekey_envelope_fast

        path = self._write_envelope(ARGON2_1TIB_KIB)
        with self.assertRaises(ValidationError) as ctx:
            _rekey_envelope_fast(
                input_file=path,
                output_file=path + ".out",
                old_password=b"oldpassword123",
                new_password=b"newpassword123",
                in_place=False,
                quiet=True,
            )
        self.assertIn("ceiling", str(ctx.exception).lower())


class TestRecoverySlotCeiling(unittest.TestCase):
    """gitlab#128 review R1: the recovery-slot password path derives the KEK from
    the file's own KDF config before the slot-set MAC is checked, so it must
    enforce the ceiling itself (reached via add-recovery / remove-recovery)."""

    def _meta(self, memory_cost):
        import base64

        return {
            "format_version": 14,
            "xor_mode": "independent",
            "encryption": {
                "algorithm": "aes-gcm",
                "cascade": False,
                "wrapped_dek": base64.b64encode(b"\x00" * 48).decode(),
            },
            "derivation_config": {
                "salt": base64.b64encode(b"\x00" * 16).decode(),
                "hash_config": {},
                "kdf_config": {
                    "argon2": {
                        "enabled": True,
                        "memory_cost": memory_cost,
                        "time_cost": 3,
                        "rounds": 1,
                    }
                },
            },
        }

    def test_recover_password_path_refuses_huge_kdf_cost(self):
        from openssl_encrypt.modules.crypt_core import _recover_envelope_dek

        with self.assertRaises(ValidationError) as ctx:
            _recover_envelope_dek(self._meta(ARGON2_1TIB_KIB), password=b"pw12345678")
        self.assertIn("ceiling", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
