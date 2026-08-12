#!/usr/bin/env python3
"""
`crypt capabilities --json` emits a machine-readable manifest of what THIS CLI
build supports, so a single (future, separate-repo) GUI can gate its UI on the
CLI it is paired with instead of hardcoding a version->feature matrix
(docs/gui-split-unified-plan.md, P1-P3).

Design contract:
  * ``commands`` and ``flags`` are INTROSPECTED from the live argparse parser --
    they cannot drift from what the CLI actually accepts.
  * ``features`` is a curated overlay of rules, each referencing a real command
    or flag, so a feature boolean is COMPUTED (true/false) from the introspected
    surface rather than hand-asserted (removing a command flips its feature off
    automatically -- e.g. steganography on a line that dropped it).
  * ``command_flags`` / ``json_endpoints`` / ``json_fields`` are curated maps
    that a drift test pins against the introspected commands/flags.
  * The manifest carries only public names -- never a secret value -- and is
    independent of the process environment.
"""

import argparse
import json
import os
import unittest
from unittest import mock

from openssl_encrypt.modules import capabilities as cap


def _synthetic_parser(include_stego=True):
    p = argparse.ArgumentParser()
    p.add_argument(
        "action",
        choices=[
            "encrypt",
            "decrypt",
            "add-recovery",
            "list-recovery",
            "identity",
            "hsm",
            "check-pqc",
            "rekey",
            "shred",
            "generate-password",
            "sign",
            "verify-signature",
            "plugin",
            "create-usb",
            "keyserver",
            "telemetry",
            "armor",
            "verify-integrity",
            "capabilities",
        ],
    )
    p.add_argument("--envelope", action="store_true")
    p.add_argument("--pqc-keyfile")
    p.add_argument("--json", action="store_true")
    p.add_argument("-i", "--input")
    if include_stego:
        p.add_argument("--stego-password")
    return p


class TestIntrospection(unittest.TestCase):
    def setUp(self):
        self.parser = _synthetic_parser()

    def test_commands_are_the_action_choices(self):
        cmds = cap.introspect_commands(self.parser)
        self.assertIn("encrypt", cmds)
        self.assertIn("decrypt", cmds)
        self.assertIn("capabilities", cmds)
        # exactly the choices, nothing invented
        self.assertEqual(set(cmds), set(self.parser._actions[1].choices))

    def test_flags_include_declared_options(self):
        flags = cap.introspect_flags(self.parser)
        self.assertIn("--envelope", flags)
        self.assertIn("--json", flags)
        self.assertIn("--input", flags)
        self.assertIn("--stego-password", flags)
        # positional 'action' is not a flag
        self.assertNotIn("action", flags)

    def test_suppressed_flags_are_excluded(self):
        # The manifest must match the --help surface: flags hidden with
        # help=argparse.SUPPRESS (deprecated/legacy toggles) are not advertised.
        p = argparse.ArgumentParser()
        p.add_argument("action", choices=["encrypt"])
        p.add_argument("--visible")
        p.add_argument("--hidden-legacy", help=argparse.SUPPRESS)
        flags = cap.introspect_flags(p)
        self.assertIn("--visible", flags)
        self.assertNotIn("--hidden-legacy", flags)

    def test_suppressed_flags_in_subparsers_are_excluded(self):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="cmd")
        c = sub.add_parser("encrypt")
        c.add_argument("--shown")
        c.add_argument("--secret-toggle", help=argparse.SUPPRESS)
        flags = cap.introspect_flags(p)
        self.assertIn("--shown", flags)
        self.assertNotIn("--secret-toggle", flags)


class TestFeatureDerivation(unittest.TestCase):
    def test_command_backed_features_true_when_command_present(self):
        m = cap.build_capabilities_manifest(_synthetic_parser())
        f = m["features"]
        self.assertTrue(f["recovery_slots"])  # add-recovery present
        self.assertTrue(f["rekey"])
        self.assertTrue(f["portable_usb"])  # create-usb present

    def test_flag_backed_features_track_flags(self):
        f = cap.build_capabilities_manifest(_synthetic_parser())["features"]
        self.assertTrue(f["envelope"])  # --envelope present
        self.assertTrue(f["steganography"])  # --stego-password present

    def test_removing_a_correlate_flips_the_feature_off(self):
        # A line that dropped steganography (no --stego* flag) reports it false,
        # with no manifest edit -- the whole point of computed features.
        f = cap.build_capabilities_manifest(_synthetic_parser(include_stego=False))["features"]
        self.assertFalse(f["steganography"])
        self.assertTrue(f["envelope"])  # unrelated feature unaffected

    def test_every_feature_value_is_a_bool(self):
        f = cap.build_capabilities_manifest(_synthetic_parser())["features"]
        self.assertTrue(all(isinstance(v, bool) for v in f.values()))
        self.assertEqual(set(f), set(cap._FEATURE_RULES))


class TestManifestShape(unittest.TestCase):
    def setUp(self):
        self.m = cap.build_capabilities_manifest(_synthetic_parser())

    def test_has_required_top_level_keys(self):
        for key in (
            "schema_version",
            "cli_version",
            "line",
            "commands",
            "flags",
            "features",
            "command_flags",
            "json_endpoints",
            "json_fields",
        ):
            self.assertIn(key, self.m)

    def test_schema_version_matches_constant(self):
        self.assertEqual(self.m["schema_version"], cap.CAPABILITIES_SCHEMA_VERSION)
        self.assertIsInstance(cap.CAPABILITIES_SCHEMA_VERSION, int)

    def test_line_is_derived_from_version(self):
        # "1.4.9" -> "1.4.x"; unknown -> "unknown"
        self.assertRegex(self.m["line"], r"^\d+\.\d+\.x$|^unknown$")

    def test_is_json_serializable(self):
        s = cap.manifest_json(_synthetic_parser())
        self.assertEqual(json.loads(s)["schema_version"], cap.CAPABILITIES_SCHEMA_VERSION)

    def test_deterministic(self):
        a = cap.build_capabilities_manifest(_synthetic_parser())
        b = cap.build_capabilities_manifest(_synthetic_parser())
        self.assertEqual(a, b)


class TestNoSecretLeak(unittest.TestCase):
    def test_manifest_is_independent_of_environment_secrets(self):
        base = cap.build_capabilities_manifest(_synthetic_parser())
        with mock.patch.dict(
            os.environ,
            {"CRYPT_PASSWORD": "s3cret", "OPENSSL_ENCRYPT_RECOVERY_CODE": "AAAA-BBBB"},
        ):
            withsecret = cap.build_capabilities_manifest(_synthetic_parser())
        self.assertEqual(base, withsecret)

    def test_no_field_carries_a_secret_value(self):
        blob = cap.manifest_json(_synthetic_parser())
        # public flag NAMES like "--stego-password" are fine; no secret VALUES.
        self.assertNotIn("s3cret", blob)
        self.assertNotIn("CRYPT_PASSWORD=", blob)


class TestCuratedOverlayInternallyConsistent(unittest.TestCase):
    """Curated maps must reference names the manifest actually derives from the
    introspected surface (guards typos without needing the real CLI)."""

    def setUp(self):
        self.m = cap.build_capabilities_manifest(_synthetic_parser())

    def test_json_fields_keys_are_json_endpoints(self):
        for endpoint in self.m["json_fields"]:
            self.assertIn(endpoint, self.m["json_endpoints"])

    def test_feature_rules_reference_known_kinds(self):
        for feat, rule in cap._FEATURE_RULES.items():
            self.assertIn(rule[0], ("command", "flag", "flag_prefix"))


class TestSubparserRecursion(unittest.TestCase):
    def test_flags_are_collected_from_nested_subparsers(self):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="cmd")
        enc = sub.add_parser("encrypt")
        enc.add_argument("--nested-only")
        flags = cap.introspect_flags(p)
        self.assertIn("--nested-only", flags)


class TestRealCliManifest(unittest.TestCase):
    """Drift guard against the REAL CLI surface (subprocess), branch-agnostic."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        import sys

        out = subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.cli", "capabilities"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        cls.manifest = json.loads(out.stdout)

    def test_valid_manifest_with_core_commands(self):
        m = self.manifest
        self.assertEqual(m["schema_version"], cap.CAPABILITIES_SCHEMA_VERSION)
        for c in ("encrypt", "decrypt", "add-recovery", "identity", "capabilities"):
            self.assertIn(c, m["commands"])

    def test_features_are_self_consistent_with_emitted_surface(self):
        # Each computed feature must equal its rule evaluated on the emitted
        # commands/flags -- this catches a mis-derivation on either line.
        m = self.manifest
        cmds, flags = set(m["commands"]), set(m["flags"])
        for feat, (kind, ref) in cap._FEATURE_RULES.items():
            if kind == "command":
                expected = ref in cmds
            elif kind == "flag":
                expected = ref in flags
            else:
                expected = any(f.startswith(ref) for f in flags)
            self.assertEqual(m["features"][feat], expected, f"feature {feat} mis-derived")

    def test_curated_maps_are_subsets_of_reality(self):
        m = self.manifest
        cmds, flags = set(m["commands"]), set(m["flags"])
        for cmd, cflags in m["command_flags"].items():
            self.assertIn(cmd, cmds)
            for f in cflags:
                self.assertIn(f, flags)
        for e in m["json_endpoints"]:
            self.assertIn(e, cmds)
        for e in m["json_fields"]:
            self.assertIn(e, m["json_endpoints"])

    def test_curated_names_actually_matched_reality(self):
        # Typo guard: a curated flag that survived the intent-INTERSECT-reality
        # filter proves the name is spelled like the real CLI's.
        m = self.manifest
        self.assertIn("--envelope", m["command_flags"].get("encrypt", []))
        self.assertIn("--add-code", m["command_flags"].get("add-recovery", []))
        self.assertIn("capabilities", m["json_endpoints"])

    def test_suppress_invariant_pinned(self):
        # The flags set is the union of the --help-visible surface, never a
        # superset: flags SUPPRESS in every parser stay out, flags documented in
        # the monolithic parser stay in even if a subparser re-declares them
        # SUPPRESS. Guards a future refactor from re-opening the disclosure delta
        # or silently dropping a documented capability (review Finding 1).
        flags = set(self.manifest["flags"])
        for hidden_everywhere in ("--pbkdf2", "--scrypt-cost", "--sha512", "--blake2b"):
            self.assertNotIn(hidden_everywhere, flags)
        self.assertIn("--disable-common-password-check", flags)  # documented in monolithic


class TestGuiFacingContractIsStable(unittest.TestCase):
    """The manifest is a contract the separately-released desktop GUI gates on
    (docs/gui-split-unified-plan.md, P15). Dropping or renaming a top-level field
    or a feature name breaks the GUI's gating silently against a paired CLI, so
    both vocabularies are pinned here. Changing either is a DELIBERATE act: update
    the GUI's capability map (lib/capabilities.dart) and the GUI-side contract
    tests in the same change, and bump CAPABILITIES_SCHEMA_VERSION if the shape
    changes. This is the CLI-repo half of P15's drift guard.
    """

    def test_top_level_field_vocabulary_is_pinned(self):
        m = cap.build_capabilities_manifest(_synthetic_parser())
        self.assertEqual(
            set(m),
            {
                "schema_version",
                "cli_version",
                "line",
                "commands",
                "flags",
                "features",
                "command_flags",
                "json_endpoints",
                "json_fields",
            },
        )

    def test_feature_name_vocabulary_is_pinned(self):
        self.assertEqual(
            set(cap._FEATURE_RULES),
            {
                "armor",
                "decryption",
                "encryption",
                "envelope",
                "hsm",
                "identity",
                "integrity_verify",
                "keyserver",
                "password_generator",
                "plugins",
                "portable_usb",
                "pqc",
                "pqc_keyfile",
                "recovery_slots",
                "rekey",
                "shred",
                "signature_verify",
                "signing",
                "steganography",
                "telemetry",
            },
        )


if __name__ == "__main__":
    unittest.main()
