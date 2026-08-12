#!/usr/bin/env python3
"""
`-o` equal to `-i` must not destroy the file on the slow paths (gitlab#195).

gitlab#148 fixed this for the envelope header writer: a same-file rewrite
goes through a temp file and `os.replace`, or -- where a rename cannot be
used -- through a backup that is restored on failure. The slow paths were
left out and are the residual that issue records.

`rekey_file` decides atomicity from the flag alone (`in_place = output_file
is None`), so `rekey -i f -o f` passes a non-None output, takes the
non-atomic branch, and hands its own input path to `encrypt_file` as the
write target. `decrypt_file` has the same shape. Both then open that path
`"wb"`, truncating the user's only copy before the replacement exists.

The password recovers the plaintext in the envelope case, so the blast
radius is smaller than gitlab#148's, but the failure is the same: a crash,
a full disk or an exception between the truncate and the final write leaves
a shortened, unreadable file where the original was.

These tests use the shared predicates rather than re-deriving "same file",
so a future divergence between the two is visible here.
"""

import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core as cc
from openssl_encrypt.modules.crypt_core import (
    _rewrites_same_file,
    _write_destroys_input,
    decrypt_file,
    encrypt_file,
)

PASSWORD = b"Tr0ub4dor&3-Correct-Horse!"
PLAINTEXT = b"CANARY-PLAINTEXT-THAT-MUST-SURVIVE"


def _fail_part_way_through_write():
    """Half the bytes, then ENOSPC, on the atomic path's own handle.

    Patched at `os.fdopen` rather than `builtins.open`: the fixed path writes
    through a mkstemp descriptor, so a builtins.open injector never fires and
    the test would pass while proving nothing -- the first version of this
    file did exactly that, and asserted the ciphertext was unchanged after a
    SUCCESSFUL same-file decrypt, which is not the contract.
    """
    real_fdopen = os.fdopen

    def fdopen(fd, mode, *args, **kwargs):
        handle = real_fdopen(fd, mode, *args, **kwargs)
        if "w" in str(mode):
            original_write = handle.write

            def partial_write(data):
                original_write(data[: max(1, len(data) // 2)])
                raise OSError(28, "No space left on device")

            handle.write = partial_write
        return handle

    return mock.patch("os.fdopen", side_effect=fdopen)


class _SameFileTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _plain(self, name="secret.txt"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(PLAINTEXT)
        return path

    def _encrypted(self, name="secret.enc"):
        source = self._plain("source.txt")
        target = os.path.join(self.tmp, name)
        encrypt_file(source, target, PASSWORD, quiet=True)
        return target

    def _contents(self, path):
        with open(path, "rb") as handle:
            return handle.read()


class TestThePredicatesAreShared(_SameFileTestCase):
    """The fix must reuse gitlab#148's predicates, not a third copy.

    Three definitions of "the same file" in one module is how the recovery
    slot path and the rekey path came to disagree in the first place.
    """

    def test_same_path_is_recognised_as_destroying_the_input(self):
        path = self._plain()
        self.assertTrue(_write_destroys_input(path, path))

    def test_two_spellings_of_one_file_are_recognised(self):
        path = self._plain()
        spelled = os.path.join(self.tmp, ".", "secret.txt")
        self.assertTrue(_write_destroys_input(path, spelled))

    def test_a_distinct_destination_is_not(self):
        path = self._plain()
        self.assertFalse(_write_destroys_input(path, os.path.join(self.tmp, "other.txt")))

    def test_a_regular_same_file_can_be_replaced_atomically(self):
        path = self._plain()
        self.assertTrue(_rewrites_same_file(path, path))


class TestDecryptToTheInputPath(_SameFileTestCase):
    def test_a_failure_mid_write_leaves_the_ciphertext_intact(self):
        """The regression gitlab#195 asks for, on the decrypt path."""
        encrypted = self._encrypted()
        before = self._contents(encrypted)

        with _fail_part_way_through_write():
            with self.assertRaises(Exception):
                decrypt_file(encrypted, encrypted, PASSWORD, quiet=True)

        self.assertEqual(
            self._contents(encrypted),
            before,
            "the ciphertext was truncated; a failed same-file decrypt destroyed it",
        )

    def test_a_successful_same_file_decrypt_still_works(self):
        encrypted = self._encrypted()
        decrypt_file(encrypted, encrypted, PASSWORD, quiet=True)
        self.assertEqual(self._contents(encrypted), PLAINTEXT)

    def test_the_mode_is_not_widened(self):
        """0644 in, not 0600: with a 0600 input the assertion held before the
        fix too, so it could not fail. A .enc that arrived by scp or git
        checkout is commonly 0644, and the atomic path inherits the ORIGINAL
        file's mode -- this pins the inherit-then-clamp interaction, and
        fails if the clamp is ever dropped.
        """
        encrypted = self._encrypted()
        os.chmod(encrypted, 0o644)
        decrypt_file(encrypted, encrypted, PASSWORD, quiet=True)
        self.assertEqual(
            stat.S_IMODE(os.stat(encrypted).st_mode) & 0o077,
            0,
            "a same-file rewrite made the plaintext readable by others",
        )


class TestRekeyToTheInputPath(_SameFileTestCase):
    def test_a_failure_mid_write_leaves_the_ciphertext_intact(self):
        """`rekey -i f -o f` is the shape users actually type.

        Injected at `crypt_core.safe_open_file`, which is what encrypt_file
        writes the re-encrypted bytes through -- the os.fdopen injector used
        for the decrypt path never reaches it, and a test that cannot fail
        proves nothing.
        """
        from openssl_encrypt.modules.crypt_core import rekey_file

        encrypted = self._encrypted()
        before = self._contents(encrypted)

        import contextlib

        real_safe_open = cc.safe_open_file

        @contextlib.contextmanager
        def failing_safe_open(path, mode, *args, **kwargs):
            with real_safe_open(path, mode, *args, **kwargs) as handle:
                if "w" in str(mode):
                    original_write = handle.write

                    def partial_write(data):
                        original_write(data[: max(1, len(data) // 2)])
                        raise OSError(28, "No space left on device")

                    handle.write = partial_write
                yield handle

        with mock.patch.object(cc, "safe_open_file", failing_safe_open):
            with self.assertRaises(Exception):
                rekey_file(
                    encrypted, encrypted, PASSWORD, b"An0ther-Str0ng-Passphrase!", quiet=True
                )

        self.assertEqual(
            self._contents(encrypted),
            before,
            "the ciphertext was truncated; a failed same-file rekey destroyed it",
        )

    def test_a_successful_same_file_rekey_still_opens_with_the_new_password(self):
        from openssl_encrypt.modules.crypt_core import rekey_file

        encrypted = self._encrypted()
        new_password = b"An0ther-Str0ng-Passphrase!"
        rekey_file(encrypted, encrypted, PASSWORD, new_password, quiet=True)

        recovered = os.path.join(self.tmp, "back.txt")
        decrypt_file(encrypted, recovered, new_password, quiet=True)
        self.assertEqual(self._contents(recovered), PLAINTEXT)


class TestEncryptToTheInputPath(_SameFileTestCase):
    """`encrypt -i f -o f` is the plaintext-side shape of the same defect.

    A successful run was always fine -- verified at 3 MB and at 13.5 MB, over
    the streaming threshold -- so this is about the failure path only, and the
    fix protects it without refusing a command that works.
    """

    def test_a_failure_mid_write_leaves_the_plaintext_intact(self):
        plain = self._plain("victim.txt")
        before = self._contents(plain)

        with _fail_part_way_through_write():
            with self.assertRaises(Exception):
                encrypt_file(plain, plain, PASSWORD, quiet=True)

        self.assertEqual(
            self._contents(plain),
            before,
            "a failed same-file encrypt destroyed the plaintext",
        )

    def test_a_successful_same_file_encrypt_round_trips(self):
        plain = self._plain("roundtrip.txt")
        encrypt_file(plain, plain, PASSWORD, quiet=True)
        recovered = os.path.join(self.tmp, "back.txt")
        decrypt_file(plain, recovered, PASSWORD, quiet=True)
        self.assertEqual(self._contents(recovered), PLAINTEXT)


class TestRekeyKeepsEveryNameRotated(_SameFileTestCase):
    """A rotation reported as complete must not leave a copy on the old key.

    Deriving only "is this the same file" and then calling os.replace broke
    the link: the other name kept the OLD password while the tool printed
    "Rekey completed successfully" (caught in review).
    """

    def test_a_hardlinked_rekey_rotates_both_names(self):
        from openssl_encrypt.modules.crypt_core import rekey_file

        first = self._encrypted("a.enc")
        second = os.path.join(self.tmp, "b.enc")
        os.link(first, second)
        inode = os.stat(first).st_ino
        new_password = b"An0ther-Str0ng-Passphrase!"

        rekey_file(first, second, PASSWORD, new_password, quiet=True)

        self.assertEqual(os.stat(first).st_ino, inode, "the hard link was broken")
        self.assertEqual(os.stat(second).st_ino, inode, "the hard link was broken")

        for name in (first, second):
            recovered = os.path.join(self.tmp, os.path.basename(name) + ".out")
            decrypt_file(name, recovered, new_password, quiet=True)
            self.assertEqual(self._contents(recovered), PLAINTEXT)

            with self.assertRaises(Exception, msg=f"{name} still opens with the old password"):
                decrypt_file(name, recovered + ".old", PASSWORD, quiet=True)


if __name__ == "__main__":
    unittest.main()
