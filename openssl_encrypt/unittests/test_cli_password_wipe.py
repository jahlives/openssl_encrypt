"""Regression tests for GitLab #89 [CLI-6]: no-op in-memory 'secure clear'.

Rebinding a name to a fresh zero-filled str/bytes object
(``pwd = "\\x00" * len(pwd)``) does not overwrite the original immutable
object; it only makes the code *look* like it wipes the secret. Sensitive
buffers must instead be routed through mutable ``bytearray`` objects and
wiped in place with ``secure_memzero`` (where wiping is possible at all;
the transient ``str`` returned by ``getpass`` is an inherent Python
limitation, see #81).

The pseudo-wipe originally lived in ``crypt_cli.py`` (#89) but the same
bug-class later turned up in ``keystore_utils.py`` too, so this test scans
every module rather than a single file.
"""

import re
import unittest
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

# Match an *assignment* that rebinds a name to a zero-filled str/bytes,
# e.g. ``x = "\x00" * len(x)`` or ``x = b"\x00" * len(x)``.
# The negative lookbehind excludes comparisons (``==``, ``!=``, ``<=``,
# ``>=``) such as the legitimate all-zero pepper checks in crypt_core.py.
PSEUDO_WIPE = re.compile(r'(?<![=!<>])=\s*b?"\\x00"\s*\*\s*len\(')


class TestNoFakePasswordWipe(unittest.TestCase):
    """Ensure the misleading rebinding pseudo-wipe never returns to any module."""

    def test_no_rebinding_pseudo_wipe_in_modules(self) -> None:
        """No module may 'wipe' a secret by rebinding to a zero-filled object."""
        offenders = []
        for module in sorted(MODULES_DIR.rglob("*.py")):
            for lineno, line in enumerate(module.read_text(encoding="utf-8").splitlines(), start=1):
                if PSEUDO_WIPE.search(line):
                    rel = module.relative_to(MODULES_DIR.parent)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")

        self.assertEqual(
            offenders,
            [],
            "Found no-op pseudo-wipe(s) — rebinding does not overwrite "
            "immutable objects; use bytearray + secure_memzero:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
