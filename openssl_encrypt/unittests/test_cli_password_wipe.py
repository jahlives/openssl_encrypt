"""Regression tests for GitLab #89 [CLI-6]: no-op in-memory 'secure clear' of passwords.

Rebinding a name to a fresh zero-filled str/bytes object
(``pwd = "\\x00" * len(pwd)``) does not overwrite the original immutable
object; it only makes the code *look* like it wipes the password. Prompt
buffers must instead be routed through mutable ``bytearray`` objects and
wiped in place with ``secure_memzero`` (where wiping is possible at all;
the transient ``str`` returned by ``getpass`` is an inherent Python
limitation, see #81).
"""

import re
import unittest
from pathlib import Path

CLI_SOURCE = Path(__file__).resolve().parent.parent / "modules" / "crypt_cli.py"


class TestNoFakePasswordWipe(unittest.TestCase):
    """Ensure the misleading rebinding pseudo-wipe never returns to the CLI."""

    def test_no_rebinding_pseudo_wipe_in_cli(self) -> None:
        """crypt_cli.py must not 'wipe' passwords by rebinding to zero-filled objects."""
        source = CLI_SOURCE.read_text(encoding="utf-8")
        pattern = re.compile(r'=\s*b?"\\x00"\s*\*\s*len\(')

        offenders = [
            f"line {lineno}: {line.strip()}"
            for lineno, line in enumerate(source.splitlines(), start=1)
            if pattern.search(line)
        ]

        self.assertEqual(
            offenders,
            [],
            "Found no-op pseudo-wipe(s) in crypt_cli.py (rebinding does not "
            "overwrite immutable objects; use bytearray + secure_memzero):\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
