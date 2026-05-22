"""
CLI integration tests for OnlyKey support.

Verifies:
1. The argparse layer accepts --hsm onlykey and --hsm-slot N for the full
   OnlyKey slot range (1..12), not the YubiKey-only 1..2 range.
2. The dispatch block in crypt_cli.py has a branch for the "onlykey"
   plugin name and the user-facing error / help text mentions it.

These tests are source-level / parser-level only — they do not invoke
the full encrypt pipeline.
"""

import os
import re
import unittest


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CRYPT_CLI = os.path.join(REPO_ROOT, "openssl_encrypt", "modules", "crypt_cli.py")
SUBPARSER = os.path.join(
    REPO_ROOT, "openssl_encrypt", "modules", "crypt_cli_subparser.py"
)


class TestHsmDispatchHasOnlykeyBranch(unittest.TestCase):
    """The --hsm dispatch code must recognise "onlykey" as a plugin name."""

    def test_dispatch_block_mentions_onlykey(self):
        src = _read(CRYPT_CLI)
        # The existing pattern is `elif args.hsm.lower() == "fido2":`
        # — we want a matching branch for onlykey.
        self.assertRegex(
            src,
            r'elif\s+args\.hsm\.lower\(\)\s*==\s*["\']onlykey["\']',
            msg="crypt_cli.py needs an 'elif args.hsm.lower() == \"onlykey\"' "
            "dispatch branch alongside the existing yubikey / fido2 branches.",
        )

    def test_dispatch_imports_onlykey_plugin(self):
        src = _read(CRYPT_CLI)
        self.assertIn(
            "from ..plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin",
            src,
            msg="crypt_cli.py dispatch must import OnlykeyHSMPlugin.",
        )

    def test_unknown_hsm_error_message_lists_onlykey(self):
        """The 'Unknown HSM plugin' error message must mention onlykey."""
        src = _read(CRYPT_CLI)
        m = re.search(r"Unknown HSM plugin.*?Supported:.*?onlykey", src)
        self.assertIsNotNone(
            m,
            msg="The 'Unknown HSM plugin' error message must list 'onlykey' "
            "as a supported value.",
        )


class TestHsmFlagHelpTextMentionsOnlykey(unittest.TestCase):
    """Help text for the encrypt-side --hsm flag must list onlykey."""

    def test_main_parser_help_mentions_onlykey(self):
        src = _read(CRYPT_CLI)
        # Capture the --hsm add_argument block (multi-line help text uses
        # adjacent string literals). Terminate at the next add_argument call
        # to be robust to embedded parens in the help text.
        m = re.search(
            r'plugin_group\.add_argument\(\s*["\']--hsm["\'].*?(?=plugin_group\.add_argument)',
            src,
            re.DOTALL,
        )
        self.assertIsNotNone(m, "Could not find --hsm definition in crypt_cli.py")
        block = m.group(0)
        self.assertIn("onlykey", block.lower())

    def test_subparser_help_mentions_onlykey(self):
        """All four subparser argument groups also need updated help text."""
        src = _read(SUBPARSER)
        # Each encrypt-side block starts with `hsm_group.add_argument(\n"--hsm",`
        # — not `--hsm-slot`, which appears in the same group.
        blocks = re.findall(
            r"hsm_group\.add_argument\(\s*[\"']--hsm[\"'],.*?(?=hsm_group\.|\Z)",
            src,
            re.DOTALL,
        )
        # NOTE: the identity-side --hsm flag (create_parser.add_argument)
        # is intentionally NOT in this count — that's covered by the
        # identity-protection commits, not the encrypt-side CLI.
        self.assertGreaterEqual(
            len(blocks),
            3,
            msg=f"Expected ≥3 encrypt-side --hsm blocks in subparser, "
            f"found {len(blocks)}",
        )
        for i, block in enumerate(blocks):
            self.assertIn(
                "onlykey",
                block.lower(),
                msg=f"--hsm help block {i} does not mention onlykey: {block[:200]}",
            )


class TestHsmSlotChoicesRemoved(unittest.TestCase):
    """
    Per the approved plan (Q6 option a), argparse must NOT restrict the
    encrypt-side --hsm-slot to choices=[1,2]. Each plugin validates its
    own slot range at runtime — YubiKey rejects 3..12; OnlyKey rejects 13+.

    The identity-side --hsm-slot (create_parser) is touched in the
    identity-protection commits, not here.
    """

    def test_subparser_encrypt_hsm_slot_has_no_choices(self):
        src = _read(SUBPARSER)
        # Match only hsm_group.add_argument("--hsm-slot", ...) blocks
        # (the encrypt-side ones). The identity-side block uses
        # create_parser.add_argument instead.
        slot_blocks = re.findall(
            r"hsm_group\.add_argument\(\s*[\"']--hsm-slot[\"'],.*?(?=hsm_group\.|\n\s*integrity_group|\n\s*streaming_group|\n\s*pepper_group|\Z)",
            src,
            re.DOTALL,
        )
        self.assertGreater(
            len(slot_blocks),
            0,
            "Could not find encrypt-side --hsm-slot blocks in subparser",
        )
        for block in slot_blocks:
            self.assertNotIn(
                "choices=[1, 2]",
                block,
                msg=f"--hsm-slot block still has choices=[1, 2]: {block[:200]}",
            )

    def test_main_cli_hsm_slot_has_no_choices(self):
        src = _read(CRYPT_CLI)
        m = re.search(
            r"plugin_group\.add_argument\(\s*[\"']--hsm-slot[\"'].*?\)",
            src,
            re.DOTALL,
        )
        self.assertIsNotNone(m, "Could not find --hsm-slot in crypt_cli.py")
        self.assertNotIn("choices=[1, 2]", m.group(0))


if __name__ == "__main__":
    unittest.main()
