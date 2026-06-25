#!/usr/bin/env python3
"""
CLI tests for the recovery-slot subcommands (list-recovery, recover,
add-recovery, remove-recovery). Handlers are driven directly via argparse
Namespaces (prompts mocked); a smoke test confirms the subparsers register.
"""

import argparse
import os
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_core import encrypt_file, list_recovery_slots
from openssl_encrypt.modules.recovery_slots import (
    add_recovery_cli,
    generate_recovery_code,
    list_recovery_cli,
    recover_cli,
    remove_recovery_cli,
)

PASSWORD = b"primary-cli-password"
PLAINTEXT = b"recovery cli round-trip payload\n" * 6


def _ns(**kw):
    base = dict(
        input=None,
        output=None,
        password=None,
        recovery_code=None,
        recovery_passphrase=False,
        recovery_share=None,
        add_code=False,
        add_passphrase=False,
        add_shares=None,
        shares_dir=".",
        slot_id=None,
        quiet=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


class RecoveryCliBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.enc = os.path.join(self.tmp, "file.enc")
        self.out = os.path.join(self.tmp, "out.bin")

    def tearDown(self):
        for root, _, files in os.walk(self.tmp, topdown=False):
            for f in files:
                os.unlink(os.path.join(root, f))
            os.rmdir(root)

    def _encrypt(self, recovery_credentials=None):
        data = encrypt_file(
            input_file=PLAINTEXT,
            output_file=None,
            password=PASSWORD,
            algorithm="aes-gcm",
            quiet=True,
            envelope=True,
            recovery_credentials=recovery_credentials,
        )
        with open(self.enc, "wb") as f:
            f.write(data)


class TestListRecoverCli(RecoveryCliBase):
    def test_list_and_recover_with_code(self):
        code = generate_recovery_code()
        self._encrypt([{"type": "recovery_code", "code": code}])

        slots = list_recovery_slots(self.enc)
        self.assertEqual(slots[0]["type"], "recovery_code")
        list_recovery_cli(_ns(input=self.enc))  # should not raise

        recover_cli(_ns(input=self.enc, output=self.out, recovery_code=code))
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_recover_requires_a_credential(self):
        self._encrypt([{"type": "recovery_code", "code": generate_recovery_code()}])
        with self.assertRaises(ValueError):
            recover_cli(_ns(input=self.enc, output=self.out))


class TestAddRemoveCli(RecoveryCliBase):
    def test_add_passphrase_then_recover(self):
        self._encrypt()  # plain envelope, no recovery yet
        with mock.patch("getpass.getpass", return_value="my recovery phrase"):
            add_recovery_cli(_ns(input=self.enc, output=self.enc, password=PASSWORD, add_passphrase=True))
        # recover with that passphrase
        with mock.patch("getpass.getpass", return_value="my recovery phrase"):
            recover_cli(_ns(input=self.enc, output=self.out, recovery_passphrase=True))
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_add_shares_then_recover(self):
        self._encrypt()
        add_recovery_cli(
            _ns(
                input=self.enc,
                output=self.enc,
                password=PASSWORD,
                add_shares="2-of-3",
                shares_dir=self.tmp,
            )
        )
        shares = sorted(
            os.path.join(self.tmp, f) for f in os.listdir(self.tmp) if f.startswith("recovery_share_")
        )
        self.assertEqual(len(shares), 3)
        recover_cli(_ns(input=self.enc, output=self.out, recovery_share=shares[:2]))
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_remove_recovery(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        self._encrypt(
            [{"type": "recovery_code", "code": c1}, {"type": "recovery_code", "code": c2}]
        )
        slot_id = list_recovery_slots(self.enc)[0]["id"]
        remove_recovery_cli(
            _ns(input=self.enc, output=self.enc, password=PASSWORD, slot_id=slot_id)
        )
        self.assertEqual(len(list_recovery_slots(self.enc)), 1)


class TestParserRegistration(unittest.TestCase):
    def test_subcommands_parse(self):
        from openssl_encrypt.modules.crypt_cli_subparser import (
            setup_add_recovery_parser,
            setup_recover_parser,
        )

        p = argparse.ArgumentParser()
        setup_recover_parser(p)
        ns = p.parse_args(["-i", "in.enc", "-o", "out.bin", "--recovery-code", "ABC-DEF"])
        self.assertEqual(ns.recovery_code, "ABC-DEF")

        p2 = argparse.ArgumentParser()
        setup_add_recovery_parser(p2)
        ns2 = p2.parse_args(["-i", "in.enc", "-o", "out.enc", "--add-shares", "2-of-3"])
        self.assertEqual(ns2.add_shares, "2-of-3")


if __name__ == "__main__":
    unittest.main()
