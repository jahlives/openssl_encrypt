#!/usr/bin/env python3
"""
gitlab#288: ALL legacy-chain KDF stages must fail CLOSED, like the RandomX
stage after gitlab#287.

Historically, Argon2/Balloon/Scrypt/HKDF failures in generate_key's legacy
sequential chain printed "Falling back to PBKDF2" and silently dropped the
stage, and a requested-but-unavailable stage was skipped without ANY
message. Both produce a key weaker than configured plus a key/metadata
mismatch that can strand the file.

Contract (per stage, failure and unavailability):
- raises KeyDerivationError; never returns a stage-dropped key;
- the decrypt-only opt-in hatch (OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF=<stage>)
  reproduces the legacy dropped-stage derivation for files written under
  the old fallback; encryption never gets the hatch.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_errors import KeyDerivationError

PASSWORD = b"fail-closed-288-password"
SALT = b"fail-closed-288s"  # 16 bytes


def _boom(*args, **kwargs):
    raise RuntimeError("simulated stage failure (gitlab#288)")


def _stage_config(stage):
    config = {stage: {"enabled": True, "rounds": 1}}
    if stage == "hkdf":
        # HKDF-only configs are refused upfront (it does not stretch);
        # pair it with hash rounds like any real config would.
        config["sha256"] = 10
    return config


def _decrypt_config(stage):
    config = _stage_config(stage)
    config["_is_from_decryption_metadata"] = True
    return config


def _failure_patch(stage):
    """Patch the stage's inner derivation call to raise."""
    if stage == "argon2":
        return mock.patch.object(crypt_core.argon2.low_level, "hash_secret_raw", _boom)
    if stage == "balloon":
        return mock.patch.object(crypt_core, "balloon_m", _boom)
    if stage == "scrypt":
        return mock.patch.object(crypt_core, "Scrypt", _boom)
    if stage == "hkdf":
        # The repaired stage imports HKDF locally (gitlab#290), so patch the
        # source module attribute the local import resolves at call time.
        return mock.patch("cryptography.hazmat.primitives.kdf.hkdf.HKDF", _boom)
    raise AssertionError(stage)


AVAILABILITY_FLAG = {
    "argon2": "ARGON2_AVAILABLE",
    "balloon": "BALLOON_AVAILABLE",
    "scrypt": "SCRYPT_AVAILABLE",
    "hkdf": "HKDF_AVAILABLE",
}
STAGES = tuple(AVAILABILITY_FLAG)


class TestStageFailureFailsClosed(unittest.TestCase):
    """A raising stage must abort key derivation for every legacy-chain KDF."""

    def setUp(self):
        # Class-level state leaks between generate_key calls (pre-existing
        # quirk); normalize so worksteal ordering cannot flake these tests.
        crypt_core.KeyStretch.key_stretch = False

    def test_failure_raises(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], True):
                    with _failure_patch(stage):
                        with self.assertRaises(KeyDerivationError):
                            crypt_core.generate_key(
                                PASSWORD, SALT, _stage_config(stage), quiet=True
                            )

    def test_failure_never_returns_stage_dropped_key(self):
        """If fail-open were reintroduced, the silently returned key would
        equal the skip-path derivation — compare against exactly that."""
        for stage in STAGES:
            with self.subTest(stage=stage):
                crypt_core.KeyStretch.key_stretch = False
                with mock.patch.object(
                    crypt_core, "_dropped_stage_recovery_allowed", lambda *a: True
                ):
                    with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], True):
                        with _failure_patch(stage):
                            skip_key, _s, _c = crypt_core.generate_key(
                                PASSWORD, SALT, _stage_config(stage), quiet=True
                            )
                crypt_core.KeyStretch.key_stretch = False
                with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], True):
                    with _failure_patch(stage):
                        try:
                            key, _s2, _c2 = crypt_core.generate_key(
                                PASSWORD, SALT, _stage_config(stage), quiet=True
                            )
                        except KeyDerivationError:
                            continue  # failing closed is the contract
                self.assertNotEqual(
                    key,
                    skip_key,
                    msg=f"{stage} failure silently produced the stage-dropped key",
                )


class TestStageUnavailableFailsClosed(unittest.TestCase):
    """A requested-but-unavailable stage must abort, not silently vanish
    (before gitlab#288 there was no message at all)."""

    def setUp(self):
        # Class-level state leaks between generate_key calls (pre-existing
        # quirk); normalize so worksteal ordering cannot flake these tests.
        crypt_core.KeyStretch.key_stretch = False

    def test_unavailable_raises(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], False):
                    with self.assertRaises(KeyDerivationError):
                        crypt_core.generate_key(PASSWORD, SALT, _stage_config(stage), quiet=True)


class TestLegacyRecoveryHatch(unittest.TestCase):
    """OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF=<stage>: decrypt-only, opt-in
    recovery reproducing the legacy dropped-stage derivation.

    Oracle note: exact byte-equality with the PRE-fix fail-open code was
    verified once against commit 0fc3e7bd (pre-gitlab#287, 1.4.x line) for
    the randomx-unavailable and hkdf-failure scenarios — the hatch output
    matched the old code exactly. The permanent baseline below mocks the
    recovery gate itself (same skip path, no env var), pinning that the
    env-var gating does not alter the derivation. A disabled-stage config
    is NOT a valid baseline: legacy metadata records enabled=True, which
    downstream branches read from hash_config independently of the skip."""

    @staticmethod
    def _reset_stretch_flag():
        """KeyStretch.key_stretch is CLASS-level state that leaks between
        generate_key calls (pre-existing quirk); reset it so both
        derivations in a comparison start identically."""
        crypt_core.KeyStretch.key_stretch = False

    def _gate_open_baseline(self, config):
        """Derive via the recovery skip path with the gate itself mocked."""
        self._reset_stretch_flag()
        with mock.patch.object(crypt_core, "_dropped_stage_recovery_allowed", lambda *a: True):
            key, _s, _c = crypt_core.generate_key(PASSWORD, SALT, dict(config), quiet=True)
        return key

    def _derive_with_env(self, config, env):
        self._reset_stretch_flag()
        with mock.patch.dict("os.environ", env):
            key, _s, _c = crypt_core.generate_key(PASSWORD, SALT, dict(config), quiet=True)
        return key

    def test_hatch_reproduces_dropped_key_on_decrypt(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], False):
                    baseline = self._gate_open_baseline(_decrypt_config(stage))
                    key = self._derive_with_env(
                        _decrypt_config(stage), {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": stage}
                    )
                self.assertEqual(
                    key,
                    baseline,
                    msg=f"{stage} env-var hatch must match the recovery skip path",
                )

    def test_hatch_covers_stage_failure_on_decrypt(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], True):
                    with _failure_patch(stage):
                        baseline = self._gate_open_baseline(_decrypt_config(stage))
                        key = self._derive_with_env(
                            _decrypt_config(stage), {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": stage}
                        )
                self.assertEqual(key, baseline)

    def test_hatch_refused_for_encryption(self):
        """Without the decryption marker the env var must change nothing."""
        for stage in STAGES:
            with self.subTest(stage=stage):
                with mock.patch.dict("os.environ", {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": stage}):
                    with mock.patch.object(crypt_core, AVAILABILITY_FLAG[stage], False):
                        with self.assertRaises(KeyDerivationError):
                            crypt_core.generate_key(
                                PASSWORD, SALT, _stage_config(stage), quiet=True
                            )

    def test_hatch_is_per_stage(self):
        """Allowing one stage must not unlock another."""
        with mock.patch.dict("os.environ", {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "balloon"}):
            with mock.patch.object(crypt_core, "ARGON2_AVAILABLE", False):
                with self.assertRaises(KeyDerivationError):
                    crypt_core.generate_key(PASSWORD, SALT, _decrypt_config("argon2"), quiet=True)

    def test_randomx_alias_still_works(self):
        """The gitlab#287 variable stays a working alias for the randomx stage."""
        config = {"randomx": {"enabled": True, "rounds": 1}}
        config["_is_from_decryption_metadata"] = True
        with mock.patch.object(crypt_core, "RANDOMX_AVAILABLE", False):
            baseline = self._gate_open_baseline(config)
            key = self._derive_with_env(config, {"OPENSSL_ENCRYPT_ALLOW_DROPPED_RANDOMX": "1"})
        self.assertEqual(key, baseline)

    def test_general_var_covers_randomx_too(self):
        config = {"randomx": {"enabled": True, "rounds": 1}}
        config["_is_from_decryption_metadata"] = True
        with mock.patch.object(crypt_core, "RANDOMX_AVAILABLE", False):
            baseline = self._gate_open_baseline(config)
            key = self._derive_with_env(config, {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "randomx"})
        self.assertEqual(key, baseline)


# Pre-fix fail-open golden keys (hex), computed ONCE from the last commits
# before the fail-closed fixes: 0fc3e7bd (1.4.x line) and 067d1923 (1.5.x
# line), for PASSWORD/SALT above with the marker-bearing per-stage configs.
# The recovery hatch must keep reproducing these BYTE-EXACTLY, or legacy
# files written under the old fallbacks become undecryptable.
PRE_FIX_GOLDENS = {
    "1.4": {
        "argon2:failure": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "argon2:unavailable": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "balloon:failure": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "balloon:unavailable": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "hkdf:failure": "e06dff076c797f19acb39d0d3bbcb2a44a4ffbdd35eb621a66b9cb18a8ed067a",
        "hkdf:unavailable": "3447335f4232783566786d737335304e4f377979704570502d393031363249615a726e4c474b6a74426e6f3d",
        "randomx:failure": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "randomx:unavailable": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "scrypt:failure": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
        "scrypt:unavailable": "394e4a58394a6f4e476f453473555464495f7a54646f326a724338634943396851445761324365753877343d",
    },
    "1.5": {
        "argon2:failure": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "argon2:unavailable": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "balloon:failure": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "balloon:unavailable": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "hkdf:failure": "4c4a586334553455584139386255537339504533462b4334707465613156597946566c6b6c496b52412f553d",
        "hkdf:unavailable": "4c4a586334553455584139386255537339504533462b4334707465613156597946566c6b6c496b52412f553d",
        "randomx:failure": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "randomx:unavailable": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "scrypt:failure": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
        "scrypt:unavailable": "574b385a335863565961613657305078585a4d4f2b555242416a3744746370777752355a767742344439773d",
    },
}


class TestPreFixGoldenEquality(unittest.TestCase):
    """The hatch must reproduce the pre-fix fail-open derivation byte-exactly
    for every stage and both trigger modes, on whichever line is running."""

    ALL_STAGES = ("argon2", "balloon", "scrypt", "hkdf", "randomx")
    ALL_AVAIL = dict(AVAILABILITY_FLAG, randomx="RANDOMX_AVAILABLE")

    @staticmethod
    def _any_failure_patch(stage):
        if stage == "randomx":
            return mock.patch.object(crypt_core, "randomx_kdf", _boom)
        return _failure_patch(stage)

    def _hatch_key_hex(self, stage, mode):
        crypt_core.KeyStretch.key_stretch = False
        env = {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": stage}
        config = _decrypt_config(stage)
        with mock.patch.dict("os.environ", env):
            if mode == "failure":
                with mock.patch.object(crypt_core, self.ALL_AVAIL[stage], True):
                    with self._any_failure_patch(stage):
                        key, _s, _c = crypt_core.generate_key(PASSWORD, SALT, config, quiet=True)
            else:
                with mock.patch.object(crypt_core, self.ALL_AVAIL[stage], False):
                    key, _s, _c = crypt_core.generate_key(PASSWORD, SALT, config, quiet=True)
        return bytes(key).hex()

    @staticmethod
    def _running_line():
        """Which maintenance line this checkout is: '1.4' or '1.5'.

        Read from setup.py's VERSION constant so the RIGHT golden table is
        enforced with assertEqual — membership in either line's table would
        let a cross-line derivation port slip through (review N3).
        """
        import re
        from pathlib import Path

        setup_py = Path(__file__).resolve().parents[2] / "setup.py"
        match = re.search(r'^VERSION\s*=\s*"(\d+\.\d+)\.', setup_py.read_text(), re.M)
        assert match, "cannot determine maintenance line from setup.py"
        return match.group(1)

    def test_hatch_matches_pre_fix_goldens(self):
        line = self._running_line()
        goldens = PRE_FIX_GOLDENS[line]
        for stage in self.ALL_STAGES:
            for mode in ("failure", "unavailable"):
                with self.subTest(stage=stage, mode=mode):
                    combo = f"{stage}:{mode}"
                    self.assertEqual(
                        self._hatch_key_hex(stage, mode),
                        goldens[combo],
                        msg=f"{combo}: hatch output drifted from this line's "
                        "pre-fix fail-open derivation — legacy files would be "
                        "stranded",
                    )


class TestWritePathDeniesHatch(unittest.TestCase):
    """gitlab#288 review finding 1: a KEK that could be WRITTEN must never be
    derived through the hatch."""

    def test_deny_flag_beats_marker_and_env(self):
        config = _decrypt_config("argon2")
        config["_deny_dropped_stage_recovery"] = True
        with mock.patch.dict("os.environ", {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "argon2"}):
            with mock.patch.object(crypt_core, "ARGON2_AVAILABLE", False):
                with self.assertRaises(KeyDerivationError):
                    crypt_core.generate_key(PASSWORD, SALT, config, quiet=True)

    def test_gate_function_respects_deny_flag(self):
        config = {"_is_from_decryption_metadata": True, "_deny_dropped_stage_recovery": True}
        with mock.patch.dict("os.environ", {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "argon2"}):
            self.assertFalse(crypt_core._dropped_stage_recovery_allowed(config, "argon2"))

    def test_envelope_kek_denies_by_default(self):
        """_derive_envelope_kek must stamp the deny flag unless the caller is
        an explicit unwrap site."""
        import base64 as b64

        derivation_config = {
            "salt": b64.b64encode(SALT).decode("ascii"),
            "kdf_config": {"argon2": {"enabled": True, "rounds": 1}},
        }
        with mock.patch.dict("os.environ", {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "argon2"}):
            with mock.patch.object(crypt_core, "ARGON2_AVAILABLE", False):
                with self.assertRaises(KeyDerivationError):
                    crypt_core._derive_envelope_kek(
                        PASSWORD, derivation_config, "fernet", 9, "sequential"
                    )
                # Positive control: the explicit unwrap opt-in must still
                # honor the hatch (pins that the unwrap side keeps working).
                kek = crypt_core._derive_envelope_kek(
                    PASSWORD,
                    derivation_config,
                    "fernet",
                    9,
                    "sequential",
                    allow_dropped_recovery=True,
                )
                self.assertTrue(kek)

    def test_envelope_kek_default_is_deny(self):
        """The secure default itself is part of the contract (review N5)."""
        import inspect

        default = (
            inspect.signature(crypt_core._derive_envelope_kek)
            .parameters["allow_dropped_recovery"]
            .default
        )
        self.assertIs(default, False)

    def test_marker_alone_is_insufficient(self):
        """The decryption marker without the env var must fail closed."""
        import os

        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in ("OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF", "OPENSSL_ENCRYPT_ALLOW_DROPPED_RANDOMX")
        }
        with mock.patch.dict("os.environ", clean_env, clear=True):
            with mock.patch.object(crypt_core, "ARGON2_AVAILABLE", False):
                with self.assertRaises(KeyDerivationError):
                    crypt_core.generate_key(PASSWORD, SALT, _decrypt_config("argon2"), quiet=True)


if __name__ == "__main__":
    unittest.main()
