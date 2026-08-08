#!/usr/bin/env python3
"""
`verify-usb` must not take its KDF cost from the drive it is checking
(gitlab#200).

`verify_usb_integrity` is the command you run *because you do not trust the
drive*. With no `--sha*-rounds` flags the CLI passes `hash_config=None`, and
`_read_hash_config_from_integrity` then reads `config/hash_config.json` --
plaintext, unauthenticated, and sitting on the drive under examination --
and feeds it straight to `multi_hash_password` before any integrity check
has run.

Measured before the fix, the attacker set the work factor linearly:

    {"sha512": 1}         0.02 s
    {"sha512": 100000}    0.27 s
    {"sha512": 1000000}   2.48 s

so `{"sha512": 10**12}` is roughly 29 days, and an Argon2/scrypt block with
a large `memory_cost`/`N` exhausts memory instead. `json.load` was also
uncapped, so a multi-GB file OOMs before parsing finishes -- the sibling
`.integrity` read is capped at 128 MiB, so this file was simply missed.

The bound is deliberately an allowlist rather than a ceiling per key: this
file is unauthenticated, so there is no legitimate reason to honour a shape
the writer never produces. `create-usb` writes the flat hash-round keys and
`pbkdf2_iterations`, plus the `type` that `multi_hash_password` mutates in
-- nothing else, so nothing else is accepted.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator


class _DriveTestCase(unittest.TestCase):
    def setUp(self):
        import shutil

        self.creator = USBDriveCreator()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.config_dir = self.root / self.creator.CONFIG_DIR
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def _plant(self, contents):
        """Write an attacker-controlled hash_config.json onto the drive."""
        path = self.config_dir / "hash_config.json"
        if isinstance(contents, (dict, list)):
            path.write_text(json.dumps(contents))
        else:
            path.write_text(contents)
        return path

    def _read_back(self):
        return self.creator._read_hash_config_from_integrity(self.root, "pw")


class TestACraftedDriveCannotSetTheWorkFactor(_DriveTestCase):
    def test_an_absurd_round_count_is_refused(self):
        self._plant({"sha512": 10**12})
        self.assertIsNone(
            self._read_back(),
            "the drive's own file set the KDF work factor; a crafted drive "
            "can make verify-usb run for days",
        )

    def test_a_memory_hard_block_is_refused(self):
        """The OOM arm. Nothing the writer produces contains these."""
        for payload in (
            {
                "derivation_config": {
                    "kdf_config": {"argon2": {"enabled": True, "memory_cost": 2**32}}
                }
            },
            {"scrypt": {"n": 2**30, "r": 8, "p": 1}},
            {"balloon": {"space_cost": 2**30}},
        ):
            with self.subTest(payload=payload):
                self._plant(payload)
                self.assertIsNone(self._read_back())

    def test_a_huge_file_is_not_read_into_memory(self):
        """Uncapped json.load OOMs before parsing finishes.

        Written as a real oversized file rather than a mocked read, because
        the cap has to be on the read itself -- a check after `json.load`
        has already returned is too late.
        """
        path = self.config_dir / "hash_config.json"
        with open(path, "w") as handle:
            handle.write('{"sha512": 1, "padding": "')
            for _ in range(64):
                handle.write("A" * 65536)
            handle.write('"}')
        self.assertGreater(os.path.getsize(path), 4 * 1024 * 1024)
        self.assertIsNone(self._read_back())

    def test_non_integer_and_negative_values_are_refused(self):
        for value in (-1, 0.5, True, "1000", None, [1], {"a": 1}):
            with self.subTest(value=value):
                self._plant({"sha512": value})
                self.assertIsNone(self._read_back())

    def test_an_unknown_key_is_refused(self):
        """Allowlist, not denylist: the writer produces a known shape."""
        self._plant({"sha512": 1000, "__proto__": 1})
        self.assertIsNone(self._read_back())

    def test_a_non_dict_document_is_refused(self):
        for payload in ("[1, 2, 3]", '"a string"', "12345", "not json at all"):
            with self.subTest(payload=payload):
                self._plant(payload)
                self.assertIsNone(self._read_back())


class TestALegitimateDriveStillVerifies(unittest.TestCase):
    """The load-bearing half.

    A bound that refuses real drives converts a denial-of-service into a
    permanent inability to verify -- worse than the bug. These are the
    shapes `create-usb` actually writes: the flat round keys, the PBKDF2
    iteration count, and the `type` key `multi_hash_password` mutates in.
    """

    def setUp(self):
        import shutil

        self.creator = USBDriveCreator()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.config_dir = self.root / self.creator.CONFIG_DIR
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def _round_trip(self, config):
        self.creator._store_hash_config_metadata(self.config_dir, dict(config))
        return self.creator._read_hash_config_from_integrity(self.root, "pw")

    def test_the_shape_the_writer_produces_survives(self):
        config = {"sha512": 10000, "sha256": 5000, "pbkdf2_iterations": 100000, "type": "id"}
        self.assertEqual(self._round_trip(config), config)

    def test_every_round_key_the_cli_can_set_is_accepted(self):
        """Pinned against the CLI's own list, so a new flag that the
        validator does not know about is caught here rather than by a user
        whose drive stopped verifying."""
        config = {
            key: 100
            for key in (
                "sha512",
                "sha384",
                "sha256",
                "sha224",
                "sha3_512",
                "sha3_384",
                "sha3_256",
                "sha3_224",
                "blake2b",
                "blake3",
                "shake256",
                "shake128",
                "whirlpool",
                "pbkdf2_iterations",
            )
        }
        self.assertEqual(self._round_trip(config), config)

    def test_a_missing_file_is_still_just_a_missing_file(self):
        """No file means "fall back", not "refuse"."""
        self.assertIsNone(self.creator._read_hash_config_from_integrity(self.root, "pw"))


if __name__ == "__main__":
    unittest.main()
