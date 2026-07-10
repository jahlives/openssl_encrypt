#!/usr/bin/env python3
"""
Format-version fixture corpus (v14 implementation plan Phase 5).

Pre-encrypted fixtures under testfiles/format_versions/ pin the DECRYPT
behavior of every supported write topology as of the v14 rollout
(2026-07-10). A failure here means a change broke reading of existing
files — which is never acceptable. DO NOT regenerate these fixtures to
make a failing test pass; fix the regression instead.

Fixture inventory (all encrypt "plaintext.bin" with the same password):
- v9_plain.enc            sequential chain (the pre-v14 default)
- v11_independent.enc     independent-XOR, pre-domain-separation
- v13_independent.enc     independent-XOR + per-component salts
- v13_sequential.enc      sequential-XOR opt-in (stays writable)
- v14_default.enc         v14 independent-XOR (TLV seed)
- v12_streaming.enc       chunked streaming (legacy streaming version)
- v14_streaming.enc       chunked streaming at v14
- v13_pqc_hkdf.enc        PQC with the v12+ HKDF KEM key (Phase 0)
- v13_pqc_legacy_kdf.enc  PQC with the pre-1.4.8 bare-SHA256 KEM key —
                          pins the Phase 0 decrypt fallback
- v14_pqc.enc             PQC with the v14 transcript-bound KEM key
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")
PASSWORD = b"fixture-corpus-password-2026"
PLAINTEXT = b"openssl_encrypt format-version fixture corpus 2026-07-10\n"

PLAIN_FIXTURES = [
    "v11_independent.enc",
    "v13_independent.enc",
    "v14_default.enc",
    "v12_streaming.enc",
    "v14_streaming.enc",
]

# 1.5.x removed the deprecated PBKDF2 chain entirely (documented 1.5.0
# BREAKING change: "decrypt such files with v1.4.x first"). These fixtures
# were written by 1.4.x with pbkdf2_iterations in the SEQUENTIAL derivation
# (the independent path never used PBKDF2, so those fixtures stay readable).
# They must fail CLEANLY here — a silent wrong-plaintext would be a bug.
EXPECTED_UNREADABLE_ON_15X = [
    "v9_plain.enc",
    "v13_sequential.enc",
]

PQC_FIXTURES = [
    "v13_pqc_hkdf.enc",
    "v13_pqc_legacy_kdf.enc",
    "v14_pqc.enc",
]


class TestFixtureCorpus(unittest.TestCase):
    def _decrypt(self, name):
        outfile = os.path.join(tempfile.mkdtemp(), name + ".out")
        decrypt_file(os.path.join(FIXTURE_DIR, name), outfile, PASSWORD, quiet=True)
        with open(outfile, "rb") as f:
            return f.read()

    def test_all_fixtures_present(self):
        for name in PLAIN_FIXTURES + EXPECTED_UNREADABLE_ON_15X + PQC_FIXTURES:
            self.assertTrue(
                os.path.isfile(os.path.join(FIXTURE_DIR, name)), f"missing fixture {name}"
            )

    def test_plain_fixtures_decrypt(self):
        for name in PLAIN_FIXTURES:
            with self.subTest(fixture=name):
                self.assertEqual(self._decrypt(name), PLAINTEXT)

    def test_pbkdf2_sequential_fixtures_fail_cleanly(self):
        # Documented 1.5.0 breaking change (PBKDF2 chain removed): 1.4.x
        # sequential files that used pbkdf2_iterations cannot be derived on
        # this line and must fail with an error, never wrong plaintext.
        for name in EXPECTED_UNREADABLE_ON_15X:
            with self.subTest(fixture=name):
                with self.assertRaises(Exception):
                    self._decrypt(name)


class TestPqcFixtureCorpus(unittest.TestCase):
    def setUp(self):
        from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE

        if not LIBOQS_AVAILABLE:
            self.skipTest("liboqs not available")

    def _decrypt(self, name):
        outfile = os.path.join(tempfile.mkdtemp(), name + ".out")
        decrypt_file(os.path.join(FIXTURE_DIR, name), outfile, PASSWORD, quiet=True)
        with open(outfile, "rb") as f:
            return f.read()

    def test_pqc_fixtures_decrypt(self):
        # Includes the legacy-KDF fixture: its embedded private key is
        # unlocked by the password and the KEM key needs the Phase 0
        # bare-SHA256 fallback — the full pre-1.4.8 read path.
        for name in PQC_FIXTURES:
            with self.subTest(fixture=name):
                self.assertEqual(self._decrypt(name), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
