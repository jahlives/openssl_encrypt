#!/usr/bin/env python3
"""The --quick template must not use deprecated/removed building blocks (gitlab#271).

Maintainer decision (2026-08-23): --quick uses aes-gcm-siv (matching
--standard's family and the 1.5.x line) and a memory-hard KDF — Argon2id with
the "low" preset (time_cost 2, 32 MB, parallelism 2, 1 round) — instead of
the deprecated PBKDF2-plus-hash-rounds stack. Existing quick-written files
decrypt unchanged (algorithm and KDF config are read from file metadata).
"""

import json
import os
import unittest

from openssl_encrypt.modules.crypt_cli import SecurityTemplate, get_template_config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestQuickTemplateModernized(unittest.TestCase):
    """In-code QUICK template: memory-hard, no deprecated KDF."""

    def setUp(self):
        """Load the in-code quick template once per test."""
        self.config = get_template_config(SecurityTemplate.QUICK)["hash_config"]

    def test_argon2_enabled_with_low_preset(self):
        """Argon2id 'low' preset drives the quick KDF cost."""
        argon2 = self.config["argon2"]
        self.assertTrue(argon2["enabled"])
        self.assertEqual(argon2["time_cost"], 2)
        self.assertEqual(argon2["memory_cost"], 32768)
        self.assertEqual(argon2["parallelism"], 2)
        self.assertEqual(argon2["rounds"], 1)

    def test_no_pbkdf2_work_factor(self):
        """The deprecated PBKDF2 stage carries no rounds in quick."""
        self.assertFalse(self.config.get("pbkdf2_iterations", 0))


class TestQuickJsonTemplate(unittest.TestCase):
    """templates/quick.json must match the in-code template's decisions."""

    def setUp(self):
        """Load the shipped JSON template."""
        path = os.path.join(REPO_ROOT, "openssl_encrypt", "templates", "quick.json")
        self.config = json.load(open(path))["hash_config"]

    def test_argon2_enabled_with_low_preset(self):
        """The JSON template enables the same Argon2id low preset."""
        argon2 = self.config["argon2"]
        self.assertTrue(argon2["enabled"])
        self.assertEqual(argon2["memory_cost"], 32768)
        self.assertEqual(argon2["parallelism"], 2)

    def test_no_deprecated_stages(self):
        """No PBKDF2 work factor; no removed whirlpool stage."""
        self.assertFalse(self.config.get("pbkdf2_iterations", 0))
        wp = self.config.get("whirlpool", 0)
        self.assertFalse(wp.get("rounds", 0) if isinstance(wp, dict) else wp)


class TestQuickCipherAssignment(unittest.TestCase):
    """--quick assigns aes-gcm-siv, never a deprecated cipher."""

    def test_quick_block_assigns_gcm_siv(self):
        """The CLI's quick branch pins the modern AEAD by source text."""
        import openssl_encrypt.modules.crypt_cli as cli_mod

        source = open(cli_mod.__file__, encoding="utf-8").read()
        quick_idx = source.index("elif args.quick:")
        assignment = source[quick_idx : source.index("elif args.standard:", quick_idx)]
        self.assertIn('"aes-gcm-siv"', assignment)
        self.assertNotIn('"aes-ocb3"', assignment)
