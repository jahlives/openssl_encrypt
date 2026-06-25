#!/usr/bin/env python3
"""
Golden-fixture tests: committed recovery-slot files must keep decrypting with
their fixed recovery credentials forever. These pin the on-disk recovery-slot
format so later changes cannot silently break old files.

The fixtures were produced by openssl_encrypt itself with FIXED credentials
(committed below) and are immutable.
"""

import base64
import json
import unittest
from pathlib import Path

from openssl_encrypt.modules.crypt_core import decrypt_file
from openssl_encrypt.modules.secret_sharing import Share

_DIR = Path(__file__).parent / "testfiles" / "recovery_slots"
PASSWORD = b"1234"
CODE = "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHHIIIIIJJJJJKK"
PASSPHRASE = b"golden fixture recovery passphrase"
PLAINTEXT = (_DIR / "plaintext.bin").read_bytes()


def _meta(path):
    return json.loads(base64.b64decode(path.read_bytes().split(b":", 1)[0]))


class TestRecoverySlotGoldenFixtures(unittest.TestCase):
    def test_fixtures_have_slot_set(self):
        for name, typ in (
            ("recovery_code.enc", "recovery_code"),
            ("passphrase.enc", "passphrase"),
            ("shamir.enc", "shamir"),
        ):
            enc = _meta(_DIR / name)["encryption"]
            self.assertIn("dek_slots", enc, name)
            self.assertIn("dek_slots_mac", enc, name)
            self.assertEqual(enc["dek_slots"][0]["type"], typ, name)

    def test_recovery_code_fixture(self):
        self.assertEqual(
            decrypt_file(
                input_file=str(_DIR / "recovery_code.enc"),
                output_file=None,
                recovery_code=CODE,
                quiet=True,
            ),
            PLAINTEXT,
        )

    def test_passphrase_fixture(self):
        self.assertEqual(
            decrypt_file(
                input_file=str(_DIR / "passphrase.enc"),
                output_file=None,
                recovery_passphrase=PASSPHRASE,
                quiet=True,
            ),
            PLAINTEXT,
        )

    def test_shamir_fixture(self):
        shares = [
            Share.from_file(str(_DIR / "shamir_share_1.json")),
            Share.from_file(str(_DIR / "shamir_share_3.json")),
        ]
        self.assertEqual(
            decrypt_file(
                input_file=str(_DIR / "shamir.enc"),
                output_file=None,
                recovery_shares=shares,
                quiet=True,
            ),
            PLAINTEXT,
        )

    def test_primary_password_still_works(self):
        for name in ("recovery_code.enc", "passphrase.enc", "shamir.enc"):
            self.assertEqual(
                decrypt_file(
                    input_file=str(_DIR / name), output_file=None, password=PASSWORD, quiet=True
                ),
                PLAINTEXT,
                name,
            )


if __name__ == "__main__":
    unittest.main()
