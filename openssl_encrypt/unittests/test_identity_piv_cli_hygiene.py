#!/usr/bin/env python3
"""Identity/PIV CLI hygiene (gitlab#163 / gitlab#218 findings 1 & 2).

1. `identity create` declared `--hsm-piv-slot`/`--hsm-pkcs11-lib`/`--hsm-biometric`
   (via `_add_piv_hsm_arguments`) but its `--hsm` choices exclude `piv` and
   `cmd_create` never reads them — dead surface a caller could pass and have
   silently ignored.
2. `--no-touch`'s help claimed to "Disable HSM touch / button-press
   requirement", but `require_touch` only suppresses the interactive
   "touch your device" prompt; the device's touch policy is hardware-side.
3. `--hsm-piv-slot` accepted slot `9c`, which PIV_BACKEND.md documents as
   unsupported (signing on 9c fails `CKR_USER_NOT_LOGGED_IN` because the backend
   does a whole-session login, not per-signature re-authentication).
"""

import argparse
import unittest

from openssl_encrypt.modules.crypt_cli_subparser import _piv_slot_arg, build_subparser


def _identity_create_parser():
    parser = build_subparser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and "identity" in action.choices:
            identity = action.choices["identity"]
            for sub in identity._actions:
                if isinstance(sub, argparse._SubParsersAction) and "create" in sub.choices:
                    return sub.choices["create"]
    raise AssertionError("identity create parser not found")


class TestCreateHasNoDeadPivArgs(unittest.TestCase):
    def setUp(self):
        self.parser = _identity_create_parser()

    def _rejects(self, *extra):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--name", "alice", *extra])

    def test_hsm_piv_slot_is_rejected_on_create(self):
        self._rejects("--hsm-piv-slot", "9a")

    def test_hsm_pkcs11_lib_is_rejected_on_create(self):
        self._rejects("--hsm-pkcs11-lib", "/x.so")

    def test_hsm_biometric_is_rejected_on_create(self):
        self._rejects("--hsm-biometric")

    def test_real_create_flags_still_accepted(self):
        # Guard against over-removal: --hsm, --hsm-slot, --no-touch stay.
        ns = self.parser.parse_args(
            ["--name", "alice", "--hsm", "onlykey", "--hsm-slot", "3", "--no-touch"]
        )
        self.assertEqual(ns.hsm, "onlykey")
        self.assertEqual(ns.hsm_slot, 3)
        self.assertTrue(ns.no_touch)


class TestNoTouchHelpIsHonest(unittest.TestCase):
    def test_help_does_not_claim_to_disable_the_requirement(self):
        parser = _identity_create_parser()
        help_text = next(a.help for a in parser._actions if "--no-touch" in a.option_strings)
        # It suppresses the PROMPT; it does not change the device's touch policy.
        self.assertNotIn("Disable HSM touch", help_text)
        self.assertIn("prompt", help_text.lower())


class TestPivSlot9cRejected(unittest.TestCase):
    def test_9c_is_rejected_with_guidance(self):
        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            _piv_slot_arg("9c")
        self.assertIn("9c", str(ctx.exception))

    def test_supported_slots_still_parse(self):
        self.assertEqual(_piv_slot_arg("9a"), 0x9A)
        self.assertEqual(_piv_slot_arg("9d"), 0x9D)
        self.assertEqual(_piv_slot_arg("9e"), 0x9E)


if __name__ == "__main__":
    unittest.main()
