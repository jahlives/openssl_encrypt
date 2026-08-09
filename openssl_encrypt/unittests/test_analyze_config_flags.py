#!/usr/bin/env python3
"""Tests that `analyze-config` scores the flags the user actually passes
(gitlab#168 / gitlab#166 part 2).

`run_config_analyzer` fed `vars(args)` straight into the analyzer, but the
analyzer reads a different set of key names than the analyze-config parser
produces: `pbkdf2_iterations` vs the parser's `pbkdf2_rounds`, `argon2_memory`
vs `argon2_memory_cost`, `enable_scrypt`/`enable_balloon`/`enable_hkdf` (which
the parser never defines at all), and `algorithm` vs `encryption_data_algorithm`.
So `--pbkdf2-rounds 600000 --scrypt-n 1048576` scored PBKDF2 and scrypt as
ABSENT, and `--encryption-data-algorithm` was ignored in favour of the literal
`aes-gcm`. These tests drive the REAL parser through `run_config_analyzer`
(never a hand-built dict), so they see exactly what a CLI user gets.

Also covers the aliasing note in gitlab#168: `config = vars(args)` aliased the
live `Namespace.__dict__` and then mutated it, and could hand the analyzer a
secret-valued attribute the entry parser had set. The fix passes an explicit,
translated, whitelisted copy, so the parsed namespace is left untouched.
"""

import argparse
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout


def _analyze(*argv):
    """Parse `argv` with the real analyze-config parser and run the analyzer."""
    from openssl_encrypt.modules.crypt_cli import run_config_analyzer
    from openssl_encrypt.modules.crypt_cli_subparser import setup_analyze_config_parser

    parser = argparse.ArgumentParser()
    setup_analyze_config_parser(parser)
    args = parser.parse_args(list(argv) + ["--output-format", "json"])
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return run_config_analyzer(args)


class TestConfiguredKdfsAreScored(unittest.TestCase):
    def test_pbkdf2_rounds_flag_registers_the_kdf(self):
        analysis = _analyze("--pbkdf2-rounds", "600000")
        self.assertIn("PBKDF2", analysis.configuration_summary["active_kdfs"])

    def test_scrypt_n_flag_registers_the_kdf(self):
        analysis = _analyze("--scrypt-n", "1048576")
        self.assertIn("Scrypt", analysis.configuration_summary["active_kdfs"])

    def test_argon2_flags_register_the_kdf(self):
        analysis = _analyze("--enable-argon2", "--argon2-memory-cost", "131072")
        self.assertIn("Argon2", analysis.configuration_summary["active_kdfs"])

    def test_balloon_flag_registers_the_kdf(self):
        analysis = _analyze("--balloon-space-cost", "1024", "--balloon-time-cost", "20")
        self.assertIn("Balloon", analysis.configuration_summary["active_kdfs"])

    def test_hkdf_flag_registers_the_kdf(self):
        analysis = _analyze("--hkdf-rounds", "8")
        self.assertIn("HKDF", analysis.configuration_summary["active_kdfs"])

    def test_no_kdf_flags_means_no_active_kdfs(self):
        analysis = _analyze()
        self.assertEqual(analysis.configuration_summary["active_kdfs"], [])


class TestConfiguredCipherIsReflected(unittest.TestCase):
    def test_encryption_algorithm_flag_is_reflected(self):
        analysis = _analyze("--encryption-data-algorithm", "xchacha20-poly1305")
        self.assertEqual(analysis.configuration_summary["algorithm"], "xchacha20-poly1305")

    def test_default_algorithm_is_still_aes_gcm(self):
        analysis = _analyze()
        self.assertEqual(analysis.configuration_summary["algorithm"], "aes-gcm")


class TestAFlagMovesTheScore(unittest.TestCase):
    """The whole point of gitlab#168: a passed flag must change the report."""

    def test_strong_kdfs_score_higher_than_none(self):
        bare = _analyze()
        strong = _analyze(
            "--pbkdf2-rounds",
            "1000000",
            "--enable-argon2",
            "--argon2-memory-cost",
            "1048576",
            "--scrypt-n",
            "1048576",
        )
        self.assertGreater(
            strong.configuration_summary["overall_score"],
            bare.configuration_summary["overall_score"],
        )


class TestNamespaceIsNotMutatedOrLeaked(unittest.TestCase):
    def test_the_parsed_namespace_is_not_mutated(self):
        # config = vars(args) aliased the live Namespace and then added
        # `compliance_requirements` to it (gitlab#168).
        from openssl_encrypt.modules.crypt_cli import run_config_analyzer
        from openssl_encrypt.modules.crypt_cli_subparser import setup_analyze_config_parser

        parser = argparse.ArgumentParser()
        setup_analyze_config_parser(parser)
        args = parser.parse_args(
            ["--compliance-frameworks", "fips_140_2", "--output-format", "json"]
        )
        before = dict(vars(args))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            run_config_analyzer(args)
        self.assertEqual(
            dict(vars(args)),
            before,
            "run_config_analyzer must not mutate the parsed namespace",
        )

    def test_a_secret_attribute_never_reaches_the_analyzer(self):
        # The whitelist must exclude anything the analyzer has no business
        # seeing, so a secret the entry namespace happened to carry cannot be
        # handed on (gitlab#168 "Related").
        from openssl_encrypt.modules.crypt_cli import _build_analysis_config

        ns = argparse.Namespace(
            pbkdf2_rounds=600000,
            password="super-secret-password",
            keystore_password="another-secret",
        )
        config = _build_analysis_config(ns)
        self.assertNotIn("password", config)
        self.assertNotIn("keystore_password", config)
        self.assertEqual(config.get("pbkdf2_iterations"), 600000)


if __name__ == "__main__":
    unittest.main()
