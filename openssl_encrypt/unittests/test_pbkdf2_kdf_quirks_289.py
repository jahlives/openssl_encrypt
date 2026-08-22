#!/usr/bin/env python3
"""
gitlab#289: PBKDF2-stage and KeyStretch-state quirks in generate_key.

Empirically confirmed defects (pre-fix goldens computed on the pre-fix code,
1.4.x commit dd7531b6):

1. (1.4.x) The derived key depended on VERBOSITY: the PBKDF2 stage set
   ``KeyStretch.key_stretch = True`` only inside the loud display branch,
   affecting both the 100k fallback and the final key-encoding branch — a
   PBKDF2-bearing legacy config derived one key under ``--quiet`` and
   another with normal output, and files only decrypted at the verbosity
   they were written with (the project's own fixture corpus is
   quiet-written).
2. (both lines) ``KeyStretch.key_stretch`` is class-level state never reset
   by generate_key, leaking between calls in one process.
3. (1.4.x) v4-structured metadata (``derivation_config.kdf_config.
   pbkdf2_iterations=N``) left ``use_pbkdf2`` as bool True, so ``range(True)``
   ran exactly ONE iteration regardless of N — format-locked (every existing
   v4 file was written that way).

Post-fix contract:
- ENCRYPTION is verbosity-independent (always the loud-variant flag): no
  new divergent files can be written.
- DECRYPTION is faithful by default — the variant follows verbosity exactly
  like the pre-fix code, because existing files require it — with a
  both-way override (``OPENSSL_ENCRYPT_LEGACY_QUIET_KDF_FALLBACK=1`` forces
  the quiet-variant, ``=0`` the loud-variant) for cross-verbosity decrypts.
- The flags are reset at generate_key entry (per-call determinism).
- The v4 bool case keeps its historical single-iteration semantics.
"""

import re
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules import crypt_core

PASSWORD = b"probe-289-password"
SALT = b"probe-289-salt16"

# Pre-fix goldens (1.4.x, commit dd7531b6).
GOLDEN_PBKDF2_LOUD = (
    "425031415a336e5730533838466b31366e51386543656f5f67643245586a2d6444334755354b31484c4f593d"
)
GOLDEN_PBKDF2_QUIET = (
    "786675444e5836666a39334b636b3059676a324d72353439733278636537414741713359625175734137453d"
)
GOLDEN_DROP_QUIET = (
    "4b344d466b654f5939424f515a4b5330446743644e713676594a34724c46447552624641316546373443413d"
)
GOLDEN_V4BOOL_LOUD = (
    "446d475362447a615255736755304f4f756d7438515a6d73676c4a4a6a364b41574d32656f535a7a5551303d"
)
GOLDEN_V4BOOL_QUIET = (
    "4b79377a7531373957717145744152502f4e75634d4f7537616371344967304c55344a494839494a546c343d"
)

PBKDF2_CONFIG = {"pbkdf2_iterations": 5}
DROP_CONFIG = {
    "randomx": {"enabled": True, "rounds": 1},
    "pbkdf2_iterations": 5,
    "_is_from_decryption_metadata": True,
}
HATCH_ENV = {"OPENSSL_ENCRYPT_ALLOW_DROPPED_KDF": "randomx"}


def _line():
    setup_py = Path(__file__).resolve().parents[2] / "setup.py"
    match = re.search(r'^VERSION\s*=\s*"(\d+\.\d+)\.', setup_py.read_text(), re.M)
    assert match
    return match.group(1)


def _derive(cfg, quiet, env=None, poison_flag=False):
    """Derive with controlled ambient state (flag poisoned unless None)."""
    if poison_flag is not None:
        crypt_core.KeyStretch.key_stretch = poison_flag
    with mock.patch.dict("os.environ", env or {}):
        with mock.patch.object(crypt_core, "RANDOMX_AVAILABLE", False):
            key, _s, _c = crypt_core.generate_key(PASSWORD, SALT, dict(cfg), quiet=quiet)
    return bytes(key).hex()


def _marked(cfg):
    config = dict(cfg)
    config["_is_from_decryption_metadata"] = True
    return config


class TestPerCallDeterminism(unittest.TestCase):
    """The flags must be reset at generate_key entry on BOTH lines."""

    def test_poisoned_flag_does_not_change_derivation(self):
        clean = _derive(DROP_CONFIG, quiet=True, env=HATCH_ENV, poison_flag=False)
        poisoned = _derive(DROP_CONFIG, quiet=True, env=HATCH_ENV, poison_flag=True)
        self.assertEqual(
            poisoned,
            clean,
            msg="KeyStretch.key_stretch leaked into the derivation from prior state",
        )


@unittest.skipUnless(_line() == "1.4", "PBKDF2 chain stage exists on 1.4.x only")
class TestEncryptionVerbosityIndependent(unittest.TestCase):
    """Encryption (no decryption marker) must derive identically at any
    verbosity — no new verbosity-divergent files can be written."""

    def test_encrypt_quiet_equals_loud_equals_golden(self):
        quiet = _derive(PBKDF2_CONFIG, quiet=True)
        loud = _derive(PBKDF2_CONFIG, quiet=False)
        self.assertEqual(quiet, loud, msg="encrypt-side derivation depends on verbosity")
        self.assertEqual(loud, GOLDEN_PBKDF2_LOUD)

    # (encrypt-side v4-shape configs are now refused — see
    # TestAsymAndCommandSurfaces.test_v4_shape_encrypt_fails_closed)


@unittest.skipUnless(_line() == "1.4", "PBKDF2 chain stage exists on 1.4.x only")
class TestDecryptionFaithfulByDefault(unittest.TestCase):
    """Decryption reproduces the pre-fix verbosity-following derivation by
    default (existing files, incl. the fixture corpus, require it), with a
    both-way env override for cross-verbosity decrypts."""

    def test_default_follows_verbosity_like_pre_fix(self):
        self.assertEqual(_derive(_marked(PBKDF2_CONFIG), quiet=True), GOLDEN_PBKDF2_QUIET)
        self.assertEqual(_derive(_marked(PBKDF2_CONFIG), quiet=False), GOLDEN_PBKDF2_LOUD)

    def test_override_forces_quiet_variant_even_when_loud(self):
        env = {"OPENSSL_ENCRYPT_LEGACY_QUIET_KDF_FALLBACK": "1"}
        self.assertEqual(_derive(_marked(PBKDF2_CONFIG), quiet=False, env=env), GOLDEN_PBKDF2_QUIET)

    def test_override_forces_loud_variant_even_when_quiet(self):
        env = {"OPENSSL_ENCRYPT_LEGACY_QUIET_KDF_FALLBACK": "0"}
        self.assertEqual(_derive(_marked(PBKDF2_CONFIG), quiet=True, env=env), GOLDEN_PBKDF2_LOUD)

    def test_dropped_kdf_quiet_decrypt_matches_pre_fix(self):
        """The gitlab#289 review scenario: dropped randomx + pbkdf2 under
        --quiet took the 100k fallback; faithful default reproduces it."""
        self.assertEqual(_derive(DROP_CONFIG, quiet=True, env=HATCH_ENV), GOLDEN_DROP_QUIET)

    def test_v4_bool_decrypt_faithful(self):
        v4 = _marked({"derivation_config": {"kdf_config": {"pbkdf2_iterations": 5}}})
        self.assertEqual(_derive(v4, quiet=True), GOLDEN_V4BOOL_QUIET)
        self.assertEqual(_derive(v4, quiet=False), GOLDEN_V4BOOL_LOUD)

    def test_override_ignored_for_encryption(self):
        """The env override must never touch an encrypt-side derivation."""
        env = {"OPENSSL_ENCRYPT_LEGACY_QUIET_KDF_FALLBACK": "1"}
        self.assertEqual(_derive(PBKDF2_CONFIG, quiet=True, env=env), GOLDEN_PBKDF2_LOUD)


@unittest.skipUnless(_line() == "1.4", "PBKDF2 chain stage exists on 1.4.x only")
class TestSelfDescribedNewFiles(unittest.TestCase):
    """Post-fix files record their flag variant in metadata
    (kdf_config.kdf_flag_variant), so NEW files round-trip at ANY verbosity
    combination — decryption never guesses the variant for them."""

    def test_encrypt_records_variant(self):
        crypt_core.KeyStretch.key_stretch = False
        _k, _s, config = crypt_core.generate_key(PASSWORD, SALT, dict(PBKDF2_CONFIG), quiet=True)
        self.assertEqual(config.get("kdf_flag_variant"), "loud")

    def test_recorded_variant_beats_verbosity_and_env(self):
        marked = _marked(PBKDF2_CONFIG)
        marked["kdf_flag_variant"] = "loud"
        # quiet decrypt of a self-described file: loud-variant key
        self.assertEqual(_derive(marked, quiet=True), GOLDEN_PBKDF2_LOUD)
        # even with the legacy override set, the file's record wins
        env = {"OPENSSL_ENCRYPT_LEGACY_QUIET_KDF_FALLBACK": "1"}
        self.assertEqual(_derive(marked, quiet=True, env=env), GOLDEN_PBKDF2_LOUD)

    def test_real_file_roundtrips_all_verbosity_combinations(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "s.txt")
            open(src, "w").write("rt-289")
            for enc_quiet in (True, False):
                enc = os.path.join(tmp, f"e{enc_quiet}.enc")
                crypt_core.KeyStretch.key_stretch = False
                crypt_core.encrypt_file(
                    src,
                    enc,
                    b"rt-289-pw",
                    {"pbkdf2_iterations": 5},
                    quiet=enc_quiet,
                    format_version=9,
                )
                for dec_quiet in (True, False):
                    out = os.path.join(tmp, f"o{enc_quiet}{dec_quiet}")
                    crypt_core.KeyStretch.key_stretch = False
                    crypt_core.decrypt_file(enc, out, b"rt-289-pw", quiet=dec_quiet)
                    with self.subTest(enc_quiet=enc_quiet, dec_quiet=dec_quiet):
                        self.assertEqual(open(out).read(), "rt-289")


@unittest.skipUnless(_line() == "1.4", "PBKDF2 chain stage exists on 1.4.x only")
class TestV4BoolIterations(unittest.TestCase):
    """v4-structured pbkdf2_iterations ran exactly one iteration — format-
    locked; the count is honored only by the v3 direct config."""

    def test_v3_direct_config_honors_count(self):
        five = _derive({"pbkdf2_iterations": 5}, quiet=True)
        one = _derive({"pbkdf2_iterations": 1}, quiet=True)
        self.assertNotEqual(five, one)


@unittest.skipUnless(_line() == "1.4", "PBKDF2 chain stage exists on 1.4.x only")
class TestAsymAndCommandSurfaces(unittest.TestCase):
    """Review F1/F2 coverage: the asymmetric path and derive-password."""

    def test_asym_real_file_roundtrips_all_verbosity_combinations(self):
        """Asymmetric files (PBKDF2 on their DEFAULT config) must round-trip
        at any verbosity combination — the asym decrypt path carries the
        decryption marker and the variant record (review F1). A fresh
        identity per combination: decrypt wipes the recipient private key."""
        import os
        import tempfile
        import uuid

        from openssl_encrypt.modules.identity import Identity

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "s.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("asym-289")
            for enc_quiet in (True, False):
                for dec_quiet in (True, False):
                    with self.subTest(enc_quiet=enc_quiet, dec_quiet=dec_quiet):
                        alice = Identity.generate(f"A289-{uuid.uuid4().hex[:8]}", None, None)
                        enc = os.path.join(tmp, f"a{enc_quiet}{dec_quiet}.enc")
                        out = enc + ".out"
                        crypt_core.KeyStretch.key_stretch = False
                        result = crypt_core.encrypt_file_asymmetric(
                            input_file=src,
                            output_file=enc,
                            recipients=[alice],
                            sender=alice,
                            quiet=enc_quiet,
                        )
                        self.assertTrue(result["success"])
                        crypt_core.KeyStretch.key_stretch = False
                        crypt_core.decrypt_file_asymmetric(
                            input_file=enc,
                            output_file=out,
                            recipient=alice,
                            sender_public_key=alice.signing_public_key,
                            quiet=dec_quiet,
                        )
                        with open(out, encoding="utf-8") as f:
                            self.assertEqual(f.read(), "asym-289")

    def test_derive_password_style_output_is_stable(self):
        """derive-password pins the quiet variant explicitly; its output must
        equal the pre-fix derivation byte-exactly (review F2). Golden from
        commit dd7531b6."""
        golden = (
            "6b5458526e30364233594b52695870527278426937"
            "304932426f464a754e674d45797045576e65317747383d"
        )
        crypt_core.KeyStretch.key_stretch = False
        key, _s, _c = crypt_core.generate_key(
            password=b"derive-289-pw",
            salt=b"derive-289-salt!",
            hash_config={"pbkdf2_iterations": 5, "kdf_flag_variant": "quiet"},
            pbkdf2_iterations=0,
            quiet=True,
            algorithm="fernet",
            format_version=9,
        )
        self.assertEqual(bytes(key).hex(), golden)

    def test_v4_shape_encrypt_fails_closed(self):
        """Encrypt-side v4-shape pbkdf2 config is refused instead of silently
        running one iteration (review F4); decrypt keeps the format-locked
        single-iteration semantics."""
        from openssl_encrypt.modules.crypt_errors import ValidationError

        v4 = {"derivation_config": {"kdf_config": {"pbkdf2_iterations": 5}}}
        with self.assertRaises(ValidationError):
            _derive(v4, quiet=True)


if __name__ == "__main__":
    unittest.main()
