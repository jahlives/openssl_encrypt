"""
Tests for the CLI reconstruction feature of the ``info`` action.

When ``openssl_encrypt info <file>`` runs, the existing metadata
display is now followed by a reconstructed
``openssl_encrypt encrypt`` command line that would produce equivalent
encryption settings on a fresh file. Each test below exercises one
slice of the reconstructor.
"""

import unittest


class TestReconstructorScaffolding(unittest.TestCase):
    """The reconstructor helper is importable and produces sensible output."""

    def test_helper_importable(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        self.assertTrue(callable(_reconstruct_cli_from_metadata))

    def test_minimal_metadata_emits_encrypt_command(self):
        """Empty-ish metadata still produces a syntactically-valid command."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        result = _reconstruct_cli_from_metadata({})
        self.assertIsInstance(result, str)
        # Must start with the program + action so it's copy-paste-runnable.
        self.assertTrue(result.lstrip().startswith("openssl_encrypt encrypt"))


class TestReconstructCipher(unittest.TestCase):
    """Reconstruct --algorithm / --cascade from metadata['encryption']."""

    def test_symmetric_aes_gcm(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {"encryption": {"algorithm": "aes-gcm"}}
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--algorithm aes-gcm", out)
        self.assertNotIn("--cascade", out)

    def test_symmetric_chacha20(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {"encryption": {"algorithm": "chacha20-poly1305"}}
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--algorithm chacha20-poly1305", out)

    def test_cascade_two_layer(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {
            "encryption": {
                "cascade": True,
                "cipher_chain": ["aes-256-gcm", "chacha20-poly1305"],
            }
        }
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--cascade", out)
        self.assertIn("--algorithm aes-256-gcm,chacha20-poly1305", out)

    def test_cascade_three_layer(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {
            "encryption": {
                "cascade": True,
                "cipher_chain": [
                    "aes-256-gcm",
                    "chacha20-poly1305",
                    "threefish-512",
                ],
            }
        }
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn(
            "--algorithm aes-256-gcm,chacha20-poly1305,threefish-512", out
        )

    def test_missing_encryption_section_skipped(self):
        """No 'encryption' key in metadata → no algorithm/cascade in output."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata({})
        self.assertNotIn("--algorithm", out)
        self.assertNotIn("--cascade", out)


class TestReconstructPrimaryKdfs(unittest.TestCase):
    """Reconstruct --argon2-* / --scrypt-* / --balloon-* from kdf_config."""

    def _meta_with_kdf(self, kdf_name, kdf_params):
        return {"derivation_config": {"kdf_config": {kdf_name: kdf_params}}}

    def test_argon2_enabled(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf(
            "argon2",
            {
                "enabled": True,
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32,
                "type": 2,  # 2 == "id"
                "rounds": 10,
            },
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-argon2", out)
        self.assertIn("--argon2-rounds 10", out)
        self.assertIn("--argon2-time 3", out)
        self.assertIn("--argon2-memory 65536", out)
        self.assertIn("--argon2-parallelism 4", out)
        self.assertIn("--argon2-hash-len 32", out)
        self.assertIn("--argon2-type id", out)

    def test_argon2_type_int_mapping(self):
        """Metadata stores type as int; reconstruct must map back to string."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        # type=1 -> "i", type=0 -> "d"
        out_i = _reconstruct_cli_from_metadata(
            self._meta_with_kdf("argon2", {"enabled": True, "type": 1, "rounds": 1})
        )
        self.assertIn("--argon2-type i", out_i)

        out_d = _reconstruct_cli_from_metadata(
            self._meta_with_kdf("argon2", {"enabled": True, "type": 0, "rounds": 1})
        )
        self.assertIn("--argon2-type d", out_d)

    def test_argon2_disabled_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf(
            "argon2", {"enabled": False, "time_cost": 3}
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertNotIn("--enable-argon2", out)
        self.assertNotIn("--argon2", out)

    def test_scrypt_enabled(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf(
            "scrypt",
            {"enabled": True, "n": 1024, "r": 8, "p": 1, "rounds": 3},
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-scrypt", out)
        self.assertIn("--scrypt-rounds 3", out)
        self.assertIn("--scrypt-n 1024", out)
        self.assertIn("--scrypt-r 8", out)
        self.assertIn("--scrypt-p 1", out)

    def test_scrypt_disabled_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf("scrypt", {"enabled": False, "n": 1024})
        out = _reconstruct_cli_from_metadata(meta)
        self.assertNotIn("--enable-scrypt", out)

    def test_balloon_enabled(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf(
            "balloon",
            {
                "enabled": True,
                "time_cost": 3,
                "space_cost": 65536,
                "parallelism": 4,
                "rounds": 2,
            },
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-balloon", out)
        self.assertIn("--balloon-rounds 2", out)
        self.assertIn("--balloon-time-cost 3", out)
        self.assertIn("--balloon-space-cost 65536", out)
        self.assertIn("--balloon-parallelism 4", out)

    def test_balloon_disabled_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta_with_kdf("balloon", {"enabled": False, "rounds": 1})
        out = _reconstruct_cli_from_metadata(meta)
        self.assertNotIn("--enable-balloon", out)

    def test_all_three_kdfs_together(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = {
            "derivation_config": {
                "kdf_config": {
                    "argon2": {"enabled": True, "rounds": 5, "type": 2},
                    "scrypt": {"enabled": True, "rounds": 1, "n": 1024, "r": 8, "p": 1},
                    "balloon": {"enabled": True, "rounds": 2, "time_cost": 3},
                }
            }
        }
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-argon2", out)
        self.assertIn("--enable-scrypt", out)
        self.assertIn("--enable-balloon", out)


class TestReconstructSecondaryKdfs(unittest.TestCase):
    """Reconstruct --hkdf-* and --randomx-* from kdf_config."""

    def _meta(self, kdf_name, kdf_params):
        return {"derivation_config": {"kdf_config": {kdf_name: kdf_params}}}

    def test_hkdf_enabled(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta(
            "hkdf",
            {
                "enabled": True,
                "rounds": 5,
                "algorithm": "sha256",
                "info": "openssl_encrypt_hkdf",
            },
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-hkdf", out)
        self.assertIn("--hkdf-rounds 5", out)
        self.assertIn("--hkdf-algorithm sha256", out)
        self.assertIn("--hkdf-info openssl_encrypt_hkdf", out)

    def test_hkdf_disabled_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta("hkdf", {"enabled": False, "rounds": 1})
        )
        self.assertNotIn("--enable-hkdf", out)

    def test_randomx_enabled(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        meta = self._meta(
            "randomx",
            {
                "enabled": True,
                "rounds": 10,
                "mode": "light",
                "height": 1,
                "hash_len": 32,
            },
        )
        out = _reconstruct_cli_from_metadata(meta)
        self.assertIn("--enable-randomx", out)
        self.assertIn("--randomx-rounds 10", out)
        self.assertIn("--randomx-mode light", out)
        self.assertIn("--randomx-height 1", out)
        self.assertIn("--randomx-hash-len 32", out)

    def test_randomx_fast_mode(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta("randomx", {"enabled": True, "rounds": 5, "mode": "fast"})
        )
        self.assertIn("--randomx-mode fast", out)

    def test_randomx_disabled_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta("randomx", {"enabled": False, "rounds": 1})
        )
        self.assertNotIn("--enable-randomx", out)


class TestReconstructHashRounds(unittest.TestCase):
    """Reconstruct --shaXXX-rounds N from hash_config (rounds > 0 only)."""

    def _meta(self, hash_config):
        return {"derivation_config": {"hash_config": hash_config}}

    def test_sha512_nonzero_rounds(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta({"sha512": {"rounds": 100000}})
        )
        self.assertIn("--sha512-rounds 100000", out)

    def test_sha512_zero_rounds_skipped(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta({"sha512": {"rounds": 0}})
        )
        self.assertNotIn("--sha512-rounds", out)

    def test_sha256_scalar_form(self):
        """Older metadata stores rounds as a scalar, not a dict."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(self._meta({"sha256": 10000}))
        self.assertIn("--sha256-rounds 10000", out)

    def test_sha3_512_underscore_to_hyphen(self):
        """Metadata key 'sha3_512' must become flag prefix 'sha3-512'."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta({"sha3_512": {"rounds": 5}})
        )
        self.assertIn("--sha3-512-rounds 5", out)
        self.assertNotIn("--sha3_512-rounds", out)

    def test_blake2b_blake3(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta(
                {
                    "blake2b": {"rounds": 20000},
                    "blake3": {"rounds": 10000},
                }
            )
        )
        self.assertIn("--blake2b-rounds 20000", out)
        self.assertIn("--blake3-rounds 10000", out)

    def test_shake256_shake128(self):
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta(
                {
                    "shake256": {"rounds": 15000},
                    "shake128": {"rounds": 7500},
                }
            )
        )
        self.assertIn("--shake256-rounds 15000", out)
        self.assertIn("--shake128-rounds 7500", out)

    def test_unknown_hash_algorithm_skipped(self):
        """Hash names not in the supported set are silently skipped."""
        from openssl_encrypt.modules.crypt_core import _reconstruct_cli_from_metadata

        out = _reconstruct_cli_from_metadata(
            self._meta({"some-future-hash": {"rounds": 100}})
        )
        # Should not appear in output (no flag for it).
        self.assertNotIn("--some-future-hash-rounds", out)
        self.assertNotIn("some-future-hash", out)


if __name__ == "__main__":
    unittest.main()
