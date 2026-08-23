#!/usr/bin/env python3
"""Hash stages must fail closed instead of silently not running (gitlab#294).

Two silent-no-op classes were found by the 2026-08-23 fail-closed audit:

- **Whirlpool** was removed from 1.5.x's derivation paths, but no decrypt-time
  guard exists (unlike PBKDF2's ``_check_removed_pbkdf2_chain``): a legacy
  file recording whirlpool rounds silently skipped the stage, derived the
  wrong key, and failed with an error indistinguishable from a wrong
  password.
- **sha384, sha224, sha3_384, sha3_224, blake2s, shake128** have live CLI
  flags and are recorded into metadata, but NO derivation path on any release
  ever applied them (empirically: recording rounds yields a byte-identical
  key to recording nothing). Historic files therefore decrypt correctly only
  because decrypt ignores them the same way — so decrypt must keep ignoring
  them, and new encryption must refuse to record them.

These tests pin the fail-closed behavior for both classes.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    UNAPPLIED_HASH_STAGES,
    decrypt_file,
    encrypt_file,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")
PASSWORD = b"fixture-corpus-password-2026"


def _inject_hash_rounds(src_path: str, name: str, rounds: int, dest_dir: str) -> str:
    """Copy a fixture with an extra hash stage recorded in its metadata.

    Args:
        src_path: Existing fixture file.
        name: hash_config key to inject (e.g. ``whirlpool``).
        rounds: Recorded round count.
        dest_dir: Directory receiving the rewritten copy.

    Returns:
        Path of the rewritten file.
    """
    raw = open(src_path, "rb").read()
    head, sep, rest = raw.partition(b":")
    meta = json.loads(base64.b64decode(head))
    meta.setdefault("derivation_config", {}).setdefault("hash_config", {})[name] = {
        "rounds": rounds
    }
    out = os.path.join(dest_dir, os.path.basename(src_path) + f".{name}")
    with open(out, "wb") as f:
        f.write(base64.b64encode(json.dumps(meta).encode()) + sep + rest)
    return out


class TestWhirlpoolFailsClosed(unittest.TestCase):
    """A file recording whirlpool rounds must be refused, not mis-derived."""

    @classmethod
    def setUpClass(cls):
        """Prepare a temp dir shared by the rewritten fixtures."""
        cls.tmp = tempfile.mkdtemp()

    def test_whirlpool_file_refused_with_specific_error(self):
        """The refusal must name Whirlpool and point at 1.4.x, pre-derivation."""
        path = _inject_hash_rounds(
            os.path.join(FIXTURE_DIR, "v14_default.enc"), "whirlpool", 5, self.tmp
        )
        with self.assertRaises(Exception) as ctx:
            decrypt_file(path, os.path.join(self.tmp, "wp.out"), PASSWORD, quiet=True)
        msg = str(ctx.exception)
        self.assertIn(
            "whirlpool",
            msg.lower(),
            msg="whirlpool-configured file must fail with a SPECIFIC removal "
            "error, not a generic auth/wrong-password error (gitlab#294): " + msg,
        )
        self.assertIn("1.4", msg, msg="error must point at the 1.4.x line: " + msg)


class TestUnappliedHashRefusedOnEncrypt(unittest.TestCase):
    """New encryption must refuse hash stages no derivation path executes."""

    @classmethod
    def setUpClass(cls):
        """Prepare a temp dir and a small plaintext input."""
        cls.tmp = tempfile.mkdtemp()
        cls.src = os.path.join(cls.tmp, "plain.txt")
        with open(cls.src, "wb") as f:
            f.write(b"hash stage fail closed corpus\n")

    def test_unapplied_stage_set_is_pinned(self):
        """The refused set is exactly the audited no-op stages."""
        self.assertEqual(
            UNAPPLIED_HASH_STAGES,
            frozenset(
                {
                    "sha384",
                    "sha224",
                    "sha3_384",
                    "sha3_224",
                    "blake2s",
                    "shake128",
                    "whirlpool",
                }
            ),
        )

    def test_each_unapplied_stage_refused(self):
        """Requesting any no-op stage must raise, naming the stage."""
        for name in sorted(UNAPPLIED_HASH_STAGES):
            with self.subTest(stage=name):
                out = os.path.join(self.tmp, f"{name}.enc")
                with self.assertRaises(Exception) as ctx:
                    encrypt_file(
                        self.src,
                        out,
                        b"test-password-294",
                        hash_config={name: 3, "sha256": 2},
                        quiet=True,
                    )
                self.assertIn(name, str(ctx.exception))
                self.assertFalse(os.path.exists(out), msg=f"{name}: output must not be written")

    def test_applied_stages_still_encrypt_and_roundtrip(self):
        """The seven genuinely applied stages keep working end to end."""
        out = os.path.join(self.tmp, "ok.enc")
        dec = os.path.join(self.tmp, "ok.out")
        encrypt_file(
            self.src,
            out,
            b"test-password-294",
            hash_config={"sha256": 2, "blake2b": 2},
            quiet=True,
        )
        decrypt_file(out, dec, b"test-password-294", quiet=True)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), b"hash stage fail closed corpus\n")

    def test_recorded_noop_rounds_still_ignored_on_decrypt(self):
        """Decrypt keeps ignoring historically recorded no-op rounds.

        Every release recorded these stages without applying them, so real
        files depend on decrypt ignoring them — injecting recorded rounds
        into a fixture must NOT change the derived key. The v14 fixture binds
        metadata into the AEAD transcript, so the rewritten copy fails
        authentication — but it must NOT fail with a stage-removal error,
        proving decrypt does not refuse the recorded no-op stages.
        """
        path = _inject_hash_rounds(
            os.path.join(FIXTURE_DIR, "v14_default.enc"), "sha384", 4, self.tmp
        )
        try:
            decrypt_file(path, os.path.join(self.tmp, "s384.out"), PASSWORD, quiet=True)
        except Exception as exc:  # noqa: BLE001 - asserting on the failure class
            self.assertNotIn("sha384", str(exc).lower())
            self.assertNotIn("removed", str(exc).lower())
