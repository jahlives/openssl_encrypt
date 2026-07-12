"""Scaffolding tests for format_version 14 (v14 implementation plan, Phase 1).

v14 semantics at this phase: metadata/schema registration, xor_mode stamping,
and the fail-closed topology guard (v14 is independent-XOR only; sequential
XOR stays pinned at v13 per the M2 decision of 2026-07-10). Key-derivation
changes (#100/#83/M1) arrive in later phases and are NOT pinned here.
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
)
from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.json_validator import JSONValidationError, SecureJSONValidator

TEST_PASSWORD = b"v14-scaffolding-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}


def _read_metadata(path):
    with open(path, "rb") as f:
        return json.loads(base64.b64decode(f.read().split(b":", 1)[0]))


class TestV14Constants(unittest.TestCase):
    def test_latest_stable_format_version(self):
        self.assertEqual(LATEST_STABLE_FORMAT_VERSION, 14)


class TestV14SchemaRegistration(unittest.TestCase):
    def setUp(self):
        self.validator = SecureJSONValidator()
        self.tmp = tempfile.mkdtemp()
        self.infile = os.path.join(self.tmp, "in.txt")
        with open(self.infile, "wb") as f:
            f.write(b"v14 schema probe")

    def _v13_metadata_as_v14(self):
        outfile = os.path.join(self.tmp, "v13.enc")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            format_version=13,
            quiet=True,
        )
        metadata = _read_metadata(outfile)
        metadata["format_version"] = 14
        return metadata

    def test_v14_schema_is_registered(self):
        self.assertIn("metadata_v14", self.validator.schemas)

    def test_v14_metadata_validates(self):
        metadata = self._v13_metadata_as_v14()
        metadata["xor_mode"] = "independent"
        validated = self.validator.validate_metadata(json.dumps(metadata))
        self.assertEqual(validated["format_version"], 14)

    def test_v14_schema_rejects_sequential_xor_mode(self):
        # v14 carries xor_mode="independent" only (M2 decision); a sequential
        # v14 blob must fail schema validation, not silently pass.
        metadata = self._v13_metadata_as_v14()
        metadata["xor_mode"] = "sequential"
        with self.assertRaises(JSONValidationError):
            self.validator.validate_metadata(json.dumps(metadata))

    def test_v14_schema_requires_xor_mode(self):
        # A v14 blob without xor_mode must not validate: decrypt would
        # otherwise have to guess the topology for hand-crafted blobs.
        metadata = self._v13_metadata_as_v14()
        metadata.pop("xor_mode", None)
        with self.assertRaises(JSONValidationError):
            self.validator.validate_metadata(json.dumps(metadata))

    def test_unknown_future_version_fails_closed(self):
        metadata = self._v13_metadata_as_v14()
        metadata["format_version"] = 99
        with self.assertRaises(JSONValidationError):
            self.validator.validate_metadata(json.dumps(metadata))


class TestV14WritePath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.infile = os.path.join(self.tmp, "in.txt")
        with open(self.infile, "wb") as f:
            f.write(b"v14 write-path probe")

    def test_v14_roundtrip_stamps_independent(self):
        outfile = os.path.join(self.tmp, "v14.enc")
        recovered = os.path.join(self.tmp, "v14.out")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            format_version=14,
            quiet=True,
        )
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], 14)
        self.assertEqual(metadata.get("xor_mode"), "independent")
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"v14 write-path probe")

    def test_v14_refuses_sequential_xor_mode(self):
        # Fail closed: no code path may emit a v14 sequential(-XOR) file —
        # otherwise the M1/seed gates dropped for the sequential path would
        # be silently missing (implementation plan section 3).
        outfile = os.path.join(self.tmp, "v14seq.enc")
        with self.assertRaises((ValueError, ValidationError)):
            encrypt_file(
                self.infile,
                outfile,
                TEST_PASSWORD,
                BASIC_HASH_CONFIG,
                format_version=14,
                xor_mode="sequential",
                quiet=True,
            )

    def test_v14_sequential_refused_even_for_streaming_size(self):
        # The refusal must fire BEFORE the streaming force-to-12 rewrites
        # format_version, or the invariant would be file-size dependent.
        bigfile = os.path.join(self.tmp, "big.bin")
        with open(bigfile, "wb") as f:
            f.write(os.urandom(12 * 1024 * 1024))  # above the 10 MB streaming threshold
        outfile = os.path.join(self.tmp, "v14seq_big.enc")
        with self.assertRaises((ValueError, ValidationError)):
            encrypt_file(
                bigfile,
                outfile,
                TEST_PASSWORD,
                BASIC_HASH_CONFIG,
                format_version=14,
                xor_mode="sequential",
                quiet=True,
            )

    def test_v13_sequential_still_writable(self):
        # The M2 decision keeps --use-xor-composition as a v13-pinned opt-in:
        # v13 sequential writes must keep working unchanged.
        outfile = os.path.join(self.tmp, "v13seq.enc")
        recovered = os.path.join(self.tmp, "v13seq.out")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            format_version=13,
            xor_mode="sequential",
            quiet=True,
        )
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], 13)
        self.assertEqual(metadata.get("xor_mode"), "sequential")
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"v14 write-path probe")


class TestEmbeddedPqcKeySaltGate(unittest.TestCase):
    """Regression tests for the pqc_key_salt version gate.

    The decrypt-side salt lookup was gated on format_version in [4..10], so
    v11-v13 files with an embedded password-encrypted PQC private key always
    failed with "Missing PQC key salt" (pre-existing bug, found while wiring
    v14). The gate is now >= 4, matching every v4+ metadata writer, which
    stores the salt under metadata["encryption"]["pqc_key_salt"].
    """

    def setUp(self):
        from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE

        if not LIBOQS_AVAILABLE:
            self.skipTest("liboqs not available")
        from openssl_encrypt.modules.pqc import PQCipher

        self.keypair = PQCipher("ML-KEM-768", quiet=True).generate_keypair()
        self.tmp = tempfile.mkdtemp()
        self.infile = os.path.join(self.tmp, "in.txt")
        with open(self.infile, "wb") as f:
            f.write(b"embedded pqc key probe")

    def _roundtrip(self, format_version):
        outfile = os.path.join(self.tmp, f"v{format_version}.enc")
        recovered = os.path.join(self.tmp, f"v{format_version}.out")
        encrypt_file(
            self.infile,
            outfile,
            TEST_PASSWORD,
            BASIC_HASH_CONFIG,
            algorithm="ml-kem-768-hybrid",
            format_version=format_version,
            pqc_keypair=self.keypair,
            pqc_store_private_key=True,
            quiet=True,
        )
        metadata = _read_metadata(outfile)
        self.assertEqual(metadata["format_version"], format_version)
        self.assertIn("pqc_key_salt", metadata["encryption"])
        decrypt_file(outfile, recovered, TEST_PASSWORD, quiet=True)
        with open(recovered, "rb") as f:
            self.assertEqual(f.read(), b"embedded pqc key probe")

    def test_v13_embedded_encrypted_pqc_key_roundtrip(self):
        self._roundtrip(13)

    def test_v14_embedded_encrypted_pqc_key_roundtrip(self):
        self._roundtrip(14)


if __name__ == "__main__":
    unittest.main()
