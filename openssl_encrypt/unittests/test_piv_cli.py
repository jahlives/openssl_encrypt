"""Unit tests for the PIV CLI argument wiring.

Verifies the --hsm-pkcs11-lib / --hsm-piv-slot / --hsm-biometric arguments and
the PIV slot parser, independent of the large per-command subparsers.
"""

import argparse
import unittest

from openssl_encrypt.modules.crypt_cli_subparser import (
    _add_piv_hsm_arguments,
    _piv_slot_arg,
)


class TestPivSlotArg(unittest.TestCase):
    def test_parses_hex_without_prefix(self):
        self.assertEqual(_piv_slot_arg("9a"), 0x9A)
        self.assertEqual(_piv_slot_arg("9d"), 0x9D)
        self.assertEqual(_piv_slot_arg("9e"), 0x9E)

    def test_slot_9c_is_rejected(self):
        # 9c signing fails at runtime (CKR_USER_NOT_LOGGED_IN); rejected up
        # front now (gitlab#163).
        with self.assertRaises(argparse.ArgumentTypeError):
            _piv_slot_arg("9c")

    def test_parses_hex_with_prefix(self):
        self.assertEqual(_piv_slot_arg("0x9a"), 0x9A)

    def test_rejects_unsupported_slot(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _piv_slot_arg("99")

    def test_rejects_garbage(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _piv_slot_arg("zz")


class TestPivArgumentGroup(unittest.TestCase):
    def _parser(self):
        parser = argparse.ArgumentParser()
        group = parser.add_argument_group("HSM Options")
        _add_piv_hsm_arguments(group)
        return parser

    def test_defaults(self):
        args = self._parser().parse_args([])
        self.assertIsNone(args.hsm_pkcs11_lib)
        self.assertEqual(args.hsm_piv_slot, 0x9A)
        self.assertFalse(args.hsm_biometric)

    def test_all_flags_parsed(self):
        args = self._parser().parse_args(
            [
                "--hsm-pkcs11-lib",
                "/usr/lib/opensc-pkcs11.so",
                "--hsm-piv-slot",
                "9d",
                "--hsm-biometric",
            ]
        )
        self.assertEqual(args.hsm_pkcs11_lib, "/usr/lib/opensc-pkcs11.so")
        self.assertEqual(args.hsm_piv_slot, 0x9D)
        self.assertTrue(args.hsm_biometric)

    def test_invalid_piv_slot_rejected_by_parser(self):
        with self.assertRaises(SystemExit):
            self._parser().parse_args(["--hsm-piv-slot", "99"])


if __name__ == "__main__":
    unittest.main()
