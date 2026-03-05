#!/usr/bin/env python3
"""
Unit tests for Shamir's Secret Sharing module.

Tests GF(256) arithmetic, split/combine operations,
share serialization, and input validation.
"""

import itertools
import json
import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.crypt_errors import SecretSharingError
from openssl_encrypt.modules.secret_sharing import (
    GF256,
    SHARE_FILE_HEADER,
    Share,
    ShareMetadata,
    combine_shares,
    split_secret,
)


class TestGF256(unittest.TestCase):
    """Test GF(256) arithmetic operations."""

    def test_mul_identity(self):
        """Multiplying by 1 returns the same element."""
        for a in range(256):
            self.assertEqual(GF256.mul(a, 1), a)

    def test_mul_zero(self):
        """Multiplying by 0 returns 0."""
        for a in range(256):
            self.assertEqual(GF256.mul(a, 0), 0)
            self.assertEqual(GF256.mul(0, a), 0)

    def test_mul_commutativity(self):
        """Multiplication is commutative."""
        for a in range(1, 50):
            for b in range(1, 50):
                self.assertEqual(GF256.mul(a, b), GF256.mul(b, a))

    def test_inv_correctness(self):
        """a * inv(a) == 1 for all nonzero a."""
        for a in range(1, 256):
            inv_a = GF256.inv(a)
            self.assertEqual(GF256.mul(a, inv_a), 1, f"Failed for a={a}")

    def test_inv_zero_raises(self):
        """Inverting zero raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            GF256.inv(0)

    def test_evaluate_polynomial_constant(self):
        """Constant polynomial returns the constant for any x."""
        for secret in [0, 1, 42, 255]:
            self.assertEqual(GF256.evaluate_polynomial([secret], 5), secret)

    def test_evaluate_polynomial_at_zero_is_secret(self):
        """Lagrange interpolation at x=0 recovers the constant term."""
        coeffs = [42, 100, 200]
        points = [(x, GF256.evaluate_polynomial(coeffs, x)) for x in range(1, 4)]
        result = GF256.lagrange_interpolate(points)
        self.assertEqual(result, 42)


class TestSplitCombine(unittest.TestCase):
    """Test split and combine operations."""

    def test_2_of_3(self):
        """2-of-3 split and combine recovers the secret."""
        secret = b"hello world"
        shares = split_secret(secret, threshold=2, num_shares=3)
        self.assertEqual(len(shares), 3)

        # Any 2 shares should work
        for combo in itertools.combinations(shares, 2):
            recovered = combine_shares(list(combo))
            self.assertEqual(recovered, secret)

    def test_3_of_5(self):
        """3-of-5 split and combine recovers the secret."""
        secret = b"secret_password_123!"
        shares = split_secret(secret, threshold=3, num_shares=5)

        for combo in itertools.combinations(shares, 3):
            recovered = combine_shares(list(combo))
            self.assertEqual(recovered, secret)

    def test_5_of_10(self):
        """5-of-10 split and combine recovers the secret."""
        secret = os.urandom(32)
        shares = split_secret(secret, threshold=5, num_shares=10)

        # Test just a few combinations (all would be too many)
        for combo in list(itertools.combinations(shares, 5))[:10]:
            recovered = combine_shares(list(combo))
            self.assertEqual(recovered, secret)

    def test_k_minus_1_shares_insufficient(self):
        """k-1 shares raises SecretSharingError for insufficient count."""
        secret = b"A" * 16
        shares = split_secret(secret, threshold=3, num_shares=5)

        # With only 2 shares (k-1), combine should raise
        with self.assertRaises(SecretSharingError):
            combine_shares(shares[:2])

    def test_all_shares_combine(self):
        """Using all n shares also recovers the secret."""
        secret = b"full_set"
        shares = split_secret(secret, threshold=2, num_shares=5)
        recovered = combine_shares(shares)
        self.assertEqual(recovered, secret)

    def test_single_byte_secret(self):
        """Single byte secret splits and combines correctly."""
        secret = b"\x42"
        shares = split_secret(secret, threshold=2, num_shares=3)
        recovered = combine_shares(shares[:2])
        self.assertEqual(recovered, secret)

    def test_binary_secret(self):
        """Binary (non-text) secret splits and combines correctly."""
        secret = bytes(range(256))
        shares = split_secret(secret, threshold=3, num_shares=5)
        recovered = combine_shares(shares[:3])
        self.assertEqual(recovered, secret)

    def test_key_id_consistency(self):
        """All shares from one split have the same key_id."""
        shares = split_secret(b"test", threshold=2, num_shares=5)
        key_ids = {s.metadata.key_id for s in shares}
        self.assertEqual(len(key_ids), 1)

    def test_custom_key_id(self):
        """Custom key_id is preserved in all shares."""
        custom_id = "custom-test-id-123"
        shares = split_secret(b"test", threshold=2, num_shares=3, key_id=custom_id)
        for s in shares:
            self.assertEqual(s.metadata.key_id, custom_id)

    def test_share_indices_are_sequential(self):
        """Share indices are 1-based and sequential."""
        shares = split_secret(b"test", threshold=2, num_shares=5)
        indices = [s.metadata.share_index for s in shares]
        self.assertEqual(indices, [1, 2, 3, 4, 5])


class TestShareSerialization(unittest.TestCase):
    """Test Share JSON and file serialization."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_json_roundtrip(self):
        """Share survives JSON serialization/deserialization."""
        shares = split_secret(b"roundtrip_test", threshold=2, num_shares=3)
        for original in shares:
            json_str = original.to_json()
            restored = Share.from_json(json_str)
            self.assertEqual(restored.data, original.data)
            self.assertEqual(restored.metadata.threshold, original.metadata.threshold)
            self.assertEqual(restored.metadata.share_index, original.metadata.share_index)
            self.assertEqual(restored.metadata.key_id, original.metadata.key_id)

    def test_file_roundtrip(self):
        """Share survives file write/read."""
        shares = split_secret(b"file_test", threshold=2, num_shares=3)
        for share in shares:
            filepath = os.path.join(self.temp_dir, f"share_{share.metadata.share_index}.json")
            share.to_file(filepath)
            restored = Share.from_file(filepath)
            self.assertEqual(restored.data, share.data)
            self.assertEqual(restored.metadata.key_id, share.metadata.key_id)

    def test_json_has_header(self):
        """Serialized JSON includes the file header."""
        shares = split_secret(b"test", threshold=2, num_shares=3)
        json_str = shares[0].to_json()
        obj = json.loads(json_str)
        self.assertEqual(obj["header"], SHARE_FILE_HEADER)

    def test_metadata_preserved(self):
        """All metadata fields are preserved in serialization."""
        shares = split_secret(b"metadata_test", threshold=3, num_shares=5)
        share = shares[2]  # Index 3
        restored = Share.from_json(share.to_json())
        self.assertEqual(restored.metadata.threshold, 3)
        self.assertEqual(restored.metadata.total_shares, 5)
        self.assertEqual(restored.metadata.share_index, 3)
        self.assertEqual(restored.metadata.algorithm, "shamir-gf256")
        self.assertTrue(restored.metadata.created_at)  # Non-empty

    def test_from_json_invalid_header(self):
        """Invalid header in JSON raises SecretSharingError."""
        bad_json = json.dumps({"header": "wrong", "metadata": {}, "data": []})
        with self.assertRaises(SecretSharingError):
            Share.from_json(bad_json)

    def test_from_json_invalid_json(self):
        """Invalid JSON string raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            Share.from_json("not valid json{{{")

    def test_from_file_nonexistent(self):
        """Reading nonexistent file raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            Share.from_file("/nonexistent/path/share.json")

    def test_combine_from_files(self):
        """Full roundtrip: split, write files, read files, combine."""
        secret = b"full_roundtrip_secret"
        shares = split_secret(secret, threshold=2, num_shares=3)

        # Write all shares to files
        filepaths = []
        for share in shares:
            fp = os.path.join(self.temp_dir, f"s{share.metadata.share_index}.json")
            share.to_file(fp)
            filepaths.append(fp)

        # Read back and combine just 2 shares
        loaded = [Share.from_file(fp) for fp in filepaths[:2]]
        recovered = combine_shares(loaded)
        self.assertEqual(recovered, secret)


class TestValidation(unittest.TestCase):
    """Test input validation for split/combine."""

    def test_threshold_less_than_2(self):
        """Threshold < 2 raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            split_secret(b"test", threshold=1, num_shares=3)

    def test_shares_less_than_threshold(self):
        """num_shares < threshold raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            split_secret(b"test", threshold=5, num_shares=3)

    def test_shares_exceed_255(self):
        """num_shares > 255 raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            split_secret(b"test", threshold=2, num_shares=256)

    def test_empty_secret(self):
        """Empty secret raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            split_secret(b"", threshold=2, num_shares=3)

    def test_mismatched_key_ids(self):
        """Shares with different key_ids fail to combine."""
        shares1 = split_secret(b"secret1", threshold=2, num_shares=3, key_id="id-1")
        shares2 = split_secret(b"secret2", threshold=2, num_shares=3, key_id="id-2")
        mixed = [shares1[0], shares2[1]]
        with self.assertRaises(SecretSharingError):
            combine_shares(mixed)

    def test_insufficient_shares(self):
        """Fewer than threshold shares raises SecretSharingError."""
        shares = split_secret(b"test", threshold=3, num_shares=5)
        with self.assertRaises(SecretSharingError):
            combine_shares(shares[:2])  # Only 2, need 3

    def test_no_shares(self):
        """Empty shares list raises SecretSharingError."""
        with self.assertRaises(SecretSharingError):
            combine_shares([])

    def test_duplicate_indices(self):
        """Duplicate share indices raises SecretSharingError."""
        shares = split_secret(b"test", threshold=2, num_shares=3)
        duplicate = [shares[0], shares[0]]  # Same share twice
        with self.assertRaises(SecretSharingError):
            combine_shares(duplicate)

    def test_threshold_equals_shares(self):
        """threshold == num_shares works (all shares required)."""
        secret = b"all_required"
        shares = split_secret(secret, threshold=3, num_shares=3)
        recovered = combine_shares(shares)
        self.assertEqual(recovered, secret)


if __name__ == "__main__":
    unittest.main()
