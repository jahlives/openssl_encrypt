#!/usr/bin/env python3
"""Golden-fixture tests: committed recovery-slot files must keep decrypting
with their fixed recovery credentials, pinning the on-disk format. Generated
with a portable SHA-256-only KDF. The shamir fixtures are 1.5.x-produced
(shamir slots cannot be created on this line): share-based decrypt is
1.5.x-only, but this line must list their K-of-N and decrypt them with the
primary password — asserted against the real producer output so the
gitlab#278 listing cannot silently no-op on real files (gitlab#281)."""

import base64
import json
import unittest
from pathlib import Path

from openssl_encrypt.modules.crypt_core import decrypt_file

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

    def test_shamir_fixture_lists_k_of_n(self):
        """The listing works against REAL 1.5.x producer output, not a shape
        the tests invented (gitlab#281): build_shamir_slot nests the values
        under params.shamir, verified cross-branch."""
        from openssl_encrypt.modules.crypt_core import list_recovery_slots

        shamir = [s for s in list_recovery_slots(str(_DIR / "shamir.enc")) if s["type"] == "shamir"]
        self.assertEqual(len(shamir), 1)
        self.assertEqual(shamir[0]["threshold"], 2)
        self.assertEqual(shamir[0]["num_shares"], 3)

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
