#!/usr/bin/env python3
"""
`generate-password` must not repeat the claim gitlab#152 removed, and the
destination check must catch hard links (gitlab#182).

**The screen-clearing claim.** gitlab#152 removed it from the
`encrypt --random` path because it is false: `\\033[2J` repaints the visible
screen and removes nothing from scrollback, a pipe, a `script(1)`
transcript or a CI log. Claiming otherwise is worse than saying nothing,
because the user stops taking their own precautions.

The same untrue message survived in `display_password_with_timeout`, which
`generate-password` still calls -- so the claim was removed from one command
and left on the other. `user-guide.md` even says "The tool does not claim to
erase it" directly below `generate-password` examples where it did.

**The destination collision check** used `realpath`, which resolves symlinks
but not hard links, so a destination hardlinked to `--output` was still
truncated by the ciphertext write moments later -- destroying the password
and reporting success. `os.path.samefile` closes that for a destination that
already exists.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock


class TestNoFalseErasureClaim(unittest.TestCase):
    def _shown(self, **kwargs):
        from openssl_encrypt.modules import crypt_utils

        lines = []
        with mock.patch.object(
            crypt_utils, "eprint", lambda *a, **k: lines.append(" ".join(map(str, a)))
        ):
            with mock.patch.object(crypt_utils.sys.stderr, "write", lambda *_a: None):
                with mock.patch.object(crypt_utils.sys.stdin, "isatty", return_value=True):
                    crypt_utils.display_password_with_timeout("S3cret-Password", **kwargs)
        return "\n".join(lines)

    def test_it_does_not_claim_to_have_cleared_the_screen(self):
        self.assertNotIn(
            "cleared from screen",
            self._shown(),
            "the claim gitlab#152 removed from `encrypt --random` is still "
            "made by `generate-password`",
        )

    def test_it_still_shows_the_password(self):
        """The negative arm: removing the claim must not remove the delivery."""
        self.assertIn("S3cret-Password", self._shown())

    def test_it_still_warns_that_this_is_the_only_showing(self):
        shown = self._shown().lower()
        self.assertTrue(
            "only time" in shown or "save this password" in shown,
            f"the urgency of recording the password was lost: {shown[:200]}",
        )

    def test_the_source_no_longer_carries_the_sentence(self):
        """Belt and braces: the message could return through another branch."""
        import inspect

        from openssl_encrypt.modules import crypt_utils

        self.assertNotIn(
            "Password has been cleared from screen",
            inspect.getsource(crypt_utils),
        )


class TestTheDestinationCheckCatchesHardLinks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        from openssl_encrypt.modules.crypt_cli import _check_random_password_destination

        self.check = _check_random_password_destination

    def _path(self, name, contents=b"x"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(contents)
        return path

    def test_the_same_path_is_still_refused(self):
        output = self._path("out.enc")
        with self.assertRaises(ValueError):
            self.check(output, None, output)

    def test_a_symlinked_destination_is_still_refused(self):
        output = self._path("out.enc")
        link = os.path.join(self.tmp, "link.txt")
        os.symlink(output, link)
        with self.assertRaises(ValueError):
            self.check(link, None, output)

    def test_a_hardlinked_destination_is_refused(self):
        """realpath resolves symlinks but not hard links, so this was
        accepted -- and then truncated by the ciphertext write."""
        output = self._path("out.enc")
        hardlink = os.path.join(self.tmp, "hard.txt")
        os.link(output, hardlink)
        with self.assertRaises(ValueError):
            self.check(hardlink, None, output)

    def test_a_hardlink_to_the_input_is_refused_too(self):
        source = self._path("in.txt")
        hardlink = os.path.join(self.tmp, "hard-in.txt")
        os.link(source, hardlink)
        with self.assertRaises(ValueError):
            self.check(hardlink, source, None)

    def test_a_genuinely_separate_destination_is_accepted(self):
        """The load-bearing negative arm: refusing everything would break
        the feature rather than fix it."""
        output = self._path("out.enc")
        self.check(os.path.join(self.tmp, "password.txt"), None, output)

    def test_a_nonexistent_destination_is_still_accepted(self):
        """The normal case -- the destination is created by this run, so it
        does not exist yet and samefile cannot be asked about it."""
        self.check(os.path.join(self.tmp, "new.txt"), None, os.path.join(self.tmp, "out.enc"))

    def test_an_empty_path_is_still_refused(self):
        with self.assertRaises(ValueError):
            self.check("   ", None, None)


if __name__ == "__main__":
    unittest.main()
