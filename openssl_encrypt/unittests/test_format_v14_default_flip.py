#!/usr/bin/env python3
"""
format_version 14 default flip (M2 Option A) + M1 full-length independent
scrypt goldens (v14 implementation plan Phase 4).

Default writes (no explicit format_version) now emit format_version 14 with
the independent-XOR topology; explicit sequential XOR stays pinned at v13;
explicit format_version values are honored unchanged (API back-compat).
Streaming defaults to v14 for independent mode and keeps v12 for sequential
requests (the v14-sequential refusal is file-size independent).

M1: the independent-XOR scrypt component derives the full key length
(dklen=key_length) — pinned here for the wide-key algorithms so the 256-bit
sequential truncation (crypt_core sequential scrypt length=32, deliberately
unchanged for legacy) can never leak into v14 writes. The sequential legacy
vector guards that the < 14 scrypt stage stays byte-identical.

Golden values MUST match on feature/v1.4.x and v1.5.x. DO NOT CHANGE.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    LATEST_STABLE_FORMAT_VERSION,
    decrypt_file,
    encrypt_file,
    generate_key,
    generate_key_independent_xor,
)

TEST_PASSWORD = b"v14-default-flip-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}
SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

SCRYPT_CONFIG = {
    "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1, "rounds": 1},
}

# Pinned after implementation; MUST be identical on both maintenance lines.
GOLDEN_M1_AES_SIV_HEX = "242ec4f368c20ea6963ff384f4dbee6de6d1f182a195b039ac730e6815f64d850120925e45f0b7df12c84e0e6649dff1c80e02b536c878b392a04800eff919a3"
GOLDEN_M1_THREEFISH_512_HEX = "24e3dd91f8857af274debcd9799e51cf667f99444e0ea7d17751f83fac6e52e135049523081bd97d5592c22168b436bbd38be64cd18d6a6da0bec9ba28115ba0"
GOLDEN_M1_THREEFISH_1024_HEX = "7e90569fd8bbb30774f9692be272fa9eccd86da80c180d3476fe0d9b3be66b181010c74f9f8f28efb70c2db493dd4df65722eb87b41e7047d4f4e0273c44ed715cf9fee25ede13d73f2b11f3be5386a8acc12773efd65cd87a2b91d9e23535ef5787d25af07efee2ebf21e7feb059294c5a20c7667c1c4884e562e939b95880b"
# Legacy guard: sequential scrypt at v13 (256-bit intermediate, unchanged).
GOLDEN_SEQ_SCRYPT_V13_HEX = "6c052d1a3ccfb221ced983074198aba4e065e1eb021de4b104421485efae446ddb75c646f285c8c17bfc4d05ec04df4c3bf6ddd6b2846e9341c373a67220d46e"


def _read_metadata(path):
    with open(path, "rb") as f:
        return json.loads(base64.b64decode(f.read().split(b":", 1)[0]))


class TestDefaultFlip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.infile = os.path.join(self.tmp, "in.txt")
        with open(self.infile, "wb") as f:
            f.write(b"default flip probe")

    def _encrypt(self, name, **kw):
        outfile = os.path.join(self.tmp, name)
        encrypt_file(self.infile, outfile, TEST_PASSWORD, BASIC_HASH_CONFIG, quiet=True, **kw)
        return outfile

    def test_default_write_is_v14_independent(self):
        outfile = self._encrypt("default.enc")
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], LATEST_STABLE_FORMAT_VERSION)
        self.assertEqual(metadata["format_version"], 14)
        self.assertEqual(metadata.get("xor_mode"), "independent")
        recovered = outfile + ".out"
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"default flip probe")

    def test_sequential_default_stays_v13(self):
        outfile = self._encrypt("seq.enc", xor_mode="sequential")
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], 13)
        self.assertEqual(metadata.get("xor_mode"), "sequential")
        recovered = outfile + ".out"
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"default flip probe")

    def test_explicit_versions_are_honored(self):
        for fv in (9, 11, 13):
            outfile = self._encrypt(f"explicit{fv}.enc", format_version=fv)
            self.assertEqual(_read_metadata(outfile)["format_version"], fv, f"fv={fv}")


class TestStreamingDefault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.infile = os.path.join(self.tmp, "big.bin")
        with open(self.infile, "wb") as f:
            f.write(os.urandom(12 * 1024 * 1024))  # above the 10 MB threshold

    def _roundtrip(self, outfile):
        recovered = outfile + ".out"
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            recovered_data = f.read()
        with open(self.infile, "rb") as f:
            self.assertEqual(recovered_data, f.read())

    def test_streaming_default_is_v14(self):
        outfile = os.path.join(self.tmp, "stream14.enc")
        encrypt_file(
            self.infile, outfile, TEST_PASSWORD, BASIC_HASH_CONFIG, algorithm="aes-gcm", quiet=True
        )
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], 14)
        self.assertTrue(metadata.get("streaming", {}).get("enabled"))
        self._roundtrip(outfile)

    def test_streaming_sequential_is_refused(self):
        # Pre-existing data-loss bug (verified 2026-07-10): sequential XOR +
        # streaming silently produced files the decrypt router could not
        # authenticate (v11/v12 streaming always routes independent). The
        # combination is now refused cleanly.
        outfile = os.path.join(self.tmp, "streamseq.enc")
        from openssl_encrypt.modules.crypt_errors import ValidationError

        with self.assertRaises((ValueError, ValidationError)):
            encrypt_file(
                self.infile,
                outfile,
                TEST_PASSWORD,
                BASIC_HASH_CONFIG,
                algorithm="aes-gcm",
                xor_mode="sequential",
                quiet=True,
            )

    def test_sequential_with_no_streaming_works_for_large_files(self):
        # The documented escape hatch for sequential XOR on large inputs.
        outfile = os.path.join(self.tmp, "seq_nostream.enc")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            algorithm="aes-gcm",
            xor_mode="sequential",
            no_streaming=True,
            quiet=True,
        )
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], 13)
        self.assertEqual(metadata.get("xor_mode"), "sequential")
        self._roundtrip(outfile)

    def test_streaming_explicit_v12_stays_v12(self):
        outfile = os.path.join(self.tmp, "explicit12.enc")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            algorithm="aes-gcm",
            format_version=12,
            quiet=True,
        )
        self.assertEqual(_read_metadata(outfile)["format_version"], 12)
        self._roundtrip(outfile)


class TestM1FullLengthScrypt(unittest.TestCase):
    """M1: independent scrypt-final derives the full key length at v14."""

    def _derive(self, algorithm, fv=14):
        key, _, _ = generate_key_independent_xor(
            TEST_PASSWORD,
            SALT,
            SCRYPT_CONFIG,
            quiet=True,
            algorithm=algorithm,
            format_version=fv,
        )
        return bytes(key)

    def test_aes_siv_full_length(self):
        key = self._derive("aes-siv")
        self.assertEqual(len(key), 64)
        self.assertEqual(key.hex(), GOLDEN_M1_AES_SIV_HEX)

    def test_threefish_512_full_length(self):
        key = self._derive("threefish-512")
        self.assertEqual(len(key), 64)
        self.assertEqual(key.hex(), GOLDEN_M1_THREEFISH_512_HEX)

    def test_threefish_1024_full_length(self):
        key = self._derive("threefish-1024")
        self.assertEqual(len(key), 128)
        self.assertEqual(key.hex(), GOLDEN_M1_THREEFISH_1024_HEX)

    def test_xor_normalization_info_string_pinned(self):
        # Both copies of the XOR-component normalization (crypt_core's
        # normalize_to_key_length_secure and parallel_kdf's _normalize_bytes)
        # must keep the pinned HKDF info=b"v10_xor_normalize" expansion —
        # a drift in either silently changes derived keys. DO NOT CHANGE.
        golden = (
            "823fc6f8936d4046bdf80fb0a80b957f4faf8f40389688ed1019d2b9391a9841"
            "92c75b14e7709081994208220712b442ccc983828e3df7623599dfd9f3b3f803"
        )
        from openssl_encrypt.modules.crypt_core import normalize_to_key_length_secure
        from openssl_encrypt.modules.parallel_kdf import _normalize_bytes
        from openssl_encrypt.modules.secure_memory import SecureBytes

        self.assertEqual(
            bytes(normalize_to_key_length_secure(SecureBytes(b"\x00" * 32), 64)).hex(), golden
        )
        self.assertEqual(bytes(_normalize_bytes(b"\x00" * 32, 64)).hex(), golden)

    def test_sequential_scrypt_v13_legacy_vector(self):
        # Guards the sequential scrypt length=32 site: an accidental "fix"
        # of the 256-bit intermediate would change every existing sequential
        # scrypt file. The site must stay byte-identical for < 14 (and no
        # v14 write can reach it).
        key, _, _ = generate_key(
            TEST_PASSWORD,
            SALT,
            SCRYPT_CONFIG,
            quiet=True,
            algorithm="aes-siv",
            format_version=13,
        )
        self.assertEqual(bytes(key).hex(), GOLDEN_SEQ_SCRYPT_V13_HEX)


if __name__ == "__main__":
    unittest.main()
