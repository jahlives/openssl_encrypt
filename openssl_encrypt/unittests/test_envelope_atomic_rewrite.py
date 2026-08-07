#!/usr/bin/env python3
"""
The envelope writer must never destroy a file it fails to rewrite (gitlab#148).

`_write_envelope_header` writes metadata||payload over an existing envelope.
It has three paths, and which one runs is derived from the filesystem, not
from anything a caller passes:

  * atomic -- mkstemp in the same directory, write, fsync, `os.replace`,
    mode preserved. Used whenever the target can be replaced that way.
  * write-through -- for a symlink or a multiply-linked inode, where
    `os.replace` would install a NEW inode and break the other name. The
    original is copied to an fsynced `.slotbak_` backup first and restored
    if the write fails.
  * plain -- a genuinely distinct destination, where nothing of the user's
    is at risk.

There is deliberately no test that a caller cannot force the destructive
path: the `in_place` parameter that used to allow exactly that is gone, so
the channel no longer exists to test. What is tested instead is the property
that actually matters -- a failure MID-WRITE leaves the original ciphertext
byte-for-byte intact -- on every path that touches the user's own file.
Choosing the right path only implies that; it does not demonstrate it.
"""

import io
import os
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.crypt_core import _write_envelope_header
from openssl_encrypt.modules.crypt_errors import RekeyError, ValidationError

# The exclusions this module is about are POSIX file semantics: a second hard
# link, a symlink, a FIFO. Windows either lacks the calls or needs privileges
# for them, so the classes that depend on them are skipped there rather than
# failing for an unrelated reason.
_POSIX_LINKS = unittest.skipIf(sys.platform == "win32", "needs POSIX link semantics")

ORIGINAL = b"eyJvcmlnaW5hbCI6IHRydWV9:ORIGINAL-CIPHERTEXT-PAYLOAD"


class _EnvelopeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "secret.enc")
        with open(self.path, "wb") as handle:
            handle.write(ORIGINAL)
        os.chmod(self.path, 0o640)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _contents(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def _backups(self):
        return [n for n in os.listdir(self.tmp) if n.startswith(".slotbak_")]

    def _leftovers(self, *expected):
        return [n for n in os.listdir(self.tmp) if n not in expected]


def _fail_part_way_through_write():
    """Write half the bytes, then raise ENOSPC -- a real disk-full shape.

    Patching os.fdopen to raise instead would fail BEFORE any byte is
    written, which proves something much weaker than "a failure mid-write
    leaves the original intact".

    NOTE for anyone adding a test here: the patch is process-wide and
    intercepts the atomic path's temp-file handle. It does NOT touch the
    write-through path, which writes through builtins.open -- that one has
    its own injector below.
    """
    real_fdopen = os.fdopen

    def fdopen(fd, mode, *args, **kwargs):
        handle = real_fdopen(fd, mode, *args, **kwargs)
        original_write = handle.write

        def partial_write(data):
            original_write(data[: len(data) // 2])
            raise OSError(28, "No space left on device")

        handle.write = partial_write
        return handle

    return mock.patch("os.fdopen", side_effect=fdopen)


def _fail_the_first_truncating_write():
    """Fail the FIRST write-mode builtins.open only.

    One-shot on purpose: the restore reopens the same destination, and a
    mock that failed every write would sabotage the recovery the test
    exists to observe. A failure during the restore too is a separate
    scenario, covered by TestFailedRestoreKeepsTheOnlyCopy.

    NOTE: this patches builtins.open process-wide. It deliberately does not
    fire on the "rb" source read, and the backup handle comes from
    os.fdopen, so neither is affected.
    """
    real_open = open
    state = {"fired": False}

    def failing_open(path, mode="r", *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        if "w" in mode and not state["fired"]:
            state["fired"] = True
            original_write = handle.write

            def partial_write(data):
                original_write(data[: len(data) // 2])
                raise OSError(28, "No space left on device")

            handle.write = partial_write
        return handle

    return mock.patch("builtins.open", side_effect=failing_open)


class TestMidWriteFailurePreservesCiphertext(_EnvelopeTestCase):
    """The regression gitlab#148 asks for, on the atomic path."""

    def test_the_original_is_left_intact(self):
        inode = os.stat(self.path).st_ino
        with _fail_part_way_through_write():
            with self.assertRaises(OSError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, self.path)
        self.assertEqual(self._contents(), ORIGINAL)
        self.assertEqual(os.stat(self.path).st_ino, inode, "the original inode was replaced")

    def test_a_failure_leaves_no_temporary_file_behind(self):
        with _fail_part_way_through_write():
            with self.assertRaises(OSError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, self.path)
        self.assertEqual(self._leftovers("secret.enc"), [])

    def test_a_failure_before_any_write_also_preserves_it(self):
        """A failure before the file object exists is handled too.

        This does NOT prove the descriptor was closed -- that would need a
        spy on mkstemp -- so the docstring does not claim it. What it pins
        is that the early-failure path still leaves the original intact and
        no temp file behind.
        """
        with mock.patch("os.fdopen", side_effect=OSError(24, "Too many open files")):
            with self.assertRaises(OSError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, self.path)
        self.assertEqual(self._contents(), ORIGINAL)
        self.assertEqual(self._leftovers("secret.enc"), [])

    def test_a_successful_rewrite_replaces_the_content_and_keeps_the_mode(self):
        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, self.path)
        self.assertIn(b"NEW-PAYLOAD", self._contents())
        self.assertEqual(
            stat.S_IMODE(os.stat(self.path).st_mode),
            0o640,
            "the original mode must be preserved, not mkstemp's 0600",
        )

    def test_output_none_means_rewrite_in_place(self):
        """The sibling rekey API's documented convention.

        It used to reach open(None, "wb") and raise TypeError.
        """
        inode = os.stat(self.path).st_ino
        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, None)
        self.assertIn(b"NEW-PAYLOAD", self._contents())
        self.assertNotEqual(
            os.stat(self.path).st_ino, inode, "output=None did not take the atomic path"
        )
        self.assertEqual(self._leftovers("secret.enc"), [])


@_POSIX_LINKS
class TestExcludedTargetsTakeTheWriteThroughPath(_EnvelopeTestCase):
    """A symlink or a second hard link cannot use os.replace.

    It installs a NEW inode, so the rename would replace the link itself,
    or give one name the new envelope and leave the other on the old one --
    for remove-recovery a silent revocation failure reported as success.
    These have to be written THROUGH the shared inode.
    """

    def test_a_multiply_linked_file_keeps_every_name_consistent(self):
        other = os.path.join(self.tmp, "hardlink.enc")
        os.link(self.path, other)
        inode = os.stat(self.path).st_ino

        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, other)

        self.assertEqual(os.stat(self.path).st_ino, inode, "the link was broken")
        self.assertEqual(os.stat(other).st_ino, inode, "the link was broken")
        self.assertIn(b"NEW-PAYLOAD", self._contents())
        with open(other, "rb") as handle:
            self.assertIn(b"NEW-PAYLOAD", handle.read(), "the other name kept the old envelope")
        self.assertEqual(
            self._backups(), [], "the pre-change copy was left beside the rewritten file"
        )

    def test_a_symlinked_destination_is_written_through(self):
        link = os.path.join(self.tmp, "link.enc")
        os.symlink(self.path, link)
        inode = os.stat(self.path).st_ino

        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", link, link)

        self.assertTrue(os.path.islink(link), "the link was replaced by a regular file")
        self.assertEqual(
            os.stat(self.path).st_ino, inode, "the real file was replaced, not written through"
        )
        self.assertIn(b"NEW-PAYLOAD", self._contents())
        self.assertEqual(self._backups(), [])

    def test_an_input_symlink_with_a_real_output_is_written_through(self):
        """The discriminating shape for the input-side symlink exclusion.

        Without it, samestat follows the link, the atomic path is chosen,
        and os.replace swaps the LINK for a regular file while the real
        envelope keeps its old header.
        """
        link = os.path.join(self.tmp, "link.enc")
        os.symlink(self.path, link)
        inode = os.stat(self.path).st_ino

        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", link, self.path)

        self.assertTrue(os.path.islink(link), "the symlink was replaced")
        self.assertEqual(
            os.stat(self.path).st_ino, inode, "the real file was replaced, not written through"
        )
        self.assertIn(b"NEW-PAYLOAD", self._contents())


@_POSIX_LINKS
class TestWriteThroughIsStillCrashSafe(_EnvelopeTestCase):
    """Excluded from the atomic path must not mean unprotected.

    Writing through the shared inode is the only way to keep every name
    consistent, but truncating the user's only ciphertext is the very
    failure gitlab#148 is about, so the original is backed up first and
    restored if the write fails.
    """

    def test_a_multiply_linked_rewrite_is_restored_after_a_failure(self):
        other = os.path.join(self.tmp, "hardlink.enc")
        os.link(self.path, other)

        inode = os.stat(self.path).st_ino
        with _fail_the_first_truncating_write():
            with self.assertRaises(OSError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, other)

        self.assertEqual(self._contents(), ORIGINAL, "the ciphertext was destroyed, not restored")
        # A restore implemented as os.replace(backup, target) would satisfy
        # the content check above while breaking the link -- which is the one
        # thing this whole path exists to preserve.
        self.assertEqual(os.stat(self.path).st_ino, inode, "the restore broke the hard link")
        self.assertEqual(os.stat(self.path).st_nlink, 2, "the restore broke the hard link")
        self.assertEqual(self._leftovers("secret.enc", "hardlink.enc"), [])

    def test_a_symlinked_rewrite_is_restored_after_a_failure(self):
        link = os.path.join(self.tmp, "link.enc")
        os.symlink(self.path, link)

        with _fail_the_first_truncating_write():
            with self.assertRaises(OSError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", link, link)

        self.assertEqual(self._contents(), ORIGINAL)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self._backups(), [])


@_POSIX_LINKS
class TestAnUnopenableTargetIsNotReportedAsDestroyed(_EnvelopeTestCase):
    """A failure to OPEN the target truncated nothing.

    The write-through handler assumes the file has been truncated, so
    running it for an open failure -- EACCES on a read-only file in a
    writable directory, EPERM on an immutable one, EROFS -- would tell the
    user their ciphertext was destroyed and orphan a full copy of it, over a
    routine permission error.
    """

    def test_the_restore_is_not_attempted_when_nothing_was_truncated(self):
        """The discriminating assertion is that the restore never runs.

        Checking only the file contents would not discriminate: an
        unnecessary restore rewrites the same bytes and looks like success.
        The damage shows only when the restore ALSO fails -- then the user
        is told their intact file was destroyed -- so what has to be pinned
        is that the handler is not entered at all.
        """
        other = os.path.join(self.tmp, "hardlink.enc")
        os.link(self.path, other)
        captured = io.StringIO()
        real_open = open

        def failing_open(path, mode="r", *args, **kwargs):
            if "w" in mode:
                raise PermissionError(13, "Permission denied")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("openssl_encrypt.modules.crypt_core._restore_from_backup") as restore:
            with mock.patch("builtins.open", side_effect=failing_open):
                with redirect_stderr(captured):
                    with self.assertRaises(PermissionError):
                        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, other)

        restore.assert_not_called()
        self.assertEqual(self._contents(), ORIGINAL, "the untouched file was modified")
        self.assertEqual(self._backups(), [], "a copy of the envelope was orphaned")
        self.assertNotIn(
            "CRITICAL", captured.getvalue(), "a permission error was reported as destroyed data"
        )


@_POSIX_LINKS
class TestFailedRestoreKeepsTheOnlyCopy(_EnvelopeTestCase):
    """If the restore fails too, the backup is the last copy of the file.

    Deleting it would destroy it, so it is kept -- and the user has to be
    told where it is, because it is dot-prefixed and invisible to a plain
    ls. That message must NOT travel in the exception: RekeyError is a
    SecureError, which replaces the message it is given with a generic
    string unless DEBUG=1 is set. Asserting on str(exc) passes under pytest
    (which sets PYTEST_CURRENT_TEST) and proves nothing about production.
    """

    def _run_with_a_failing_restore(self):
        other = os.path.join(self.tmp, "hardlink.enc")
        os.link(self.path, other)
        captured = io.StringIO()

        with _fail_the_first_truncating_write():
            with mock.patch(
                "openssl_encrypt.modules.crypt_core._restore_from_backup",
                side_effect=OSError(28, "No space left on device"),
            ):
                with redirect_stderr(captured):
                    with self.assertRaises(RekeyError) as caught:
                        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, other)
        return captured.getvalue(), caught.exception

    def test_the_backup_is_kept_and_its_location_is_printed(self):
        stderr, _ = self._run_with_a_failing_restore()

        backups = self._backups()
        self.assertEqual(len(backups), 1, "the last copy of the original was deleted")
        with open(os.path.join(self.tmp, backups[0]), "rb") as handle:
            self.assertEqual(handle.read(), ORIGINAL, "the backup is not the original")
        self.assertIn(backups[0], stderr, "the user is not told where the only copy is")

    def test_the_kept_backup_is_not_readable_by_others(self):
        self._run_with_a_failing_restore()
        backup = os.path.join(self.tmp, self._backups()[0])
        self.assertEqual(
            stat.S_IMODE(os.stat(backup).st_mode),
            0o600,
            "a copy of the pre-change envelope was left readable by others",
        )

    def test_the_message_does_not_depend_on_running_under_pytest(self):
        """The bug this pins: the guidance used to live in the exception.

        SecureError keeps the detail only when PYTEST_CURRENT_TEST or
        DEBUG=1 is set, so the message reached test runs and nobody else.
        """
        environment = dict(os.environ)
        environment.pop("PYTEST_CURRENT_TEST", None)
        environment.pop("DEBUG", None)
        with mock.patch.dict(os.environ, environment, clear=True):
            stderr, _ = self._run_with_a_failing_restore()
        self.assertIn(self._backups()[0], stderr, "the message is gated on the test environment")

    def test_both_failures_are_reported(self):
        stderr, _ = self._run_with_a_failing_restore()
        self.assertIn("write failed", stderr.lower())
        self.assertIn("restore failed", stderr.lower())

    def test_the_underlying_failure_is_chained_not_swallowed(self):
        """`raise ... from restore_error` is deliberate.

        Without asserting it, a regression that let the raw OSError
        propagate instead of the RekeyError would still satisfy the tests
        above.
        """
        _, exception = self._run_with_a_failing_restore()
        self.assertIsInstance(exception.__cause__, OSError)


@unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are POSIX-only")
class TestNonRegularSameFileRewriteIsRefused(_EnvelopeTestCase):
    """No backup can be taken of a FIFO or a device node -- reading it back
    would block, and it cannot be restored by copying bytes into it -- so no
    recoverable write is possible and the writer refuses rather than
    truncating.
    """

    def test_a_fifo_named_as_both_input_and_output_is_refused(self):
        fifo = os.path.join(self.tmp, "pipe.enc")
        os.mkfifo(fifo)

        # If the refusal regresses, control reaches open(fifo, "wb"), which
        # blocks forever waiting for a reader. Without this alarm the
        # regression signal would be a hung CI job rather than a red test.
        def _blocked(signum, frame):
            raise AssertionError("the writer blocked on the FIFO instead of refusing")

        previous = signal.signal(signal.SIGALRM, _blocked)
        signal.alarm(5)
        try:
            with self.assertRaises(ValidationError):
                _write_envelope_header({"new": True}, b"NEW-PAYLOAD", fifo, fifo)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

        self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode), "the FIFO was replaced")
        self.assertEqual(self._backups(), [])


class TestDistinctDestinationUnaffected(_EnvelopeTestCase):
    def test_a_different_output_file_is_written_normally(self):
        other = os.path.join(self.tmp, "out.enc")
        _write_envelope_header({"new": True}, b"NEW-PAYLOAD", self.path, other)
        with open(other, "rb") as handle:
            self.assertIn(b"NEW-PAYLOAD", handle.read())
        self.assertEqual(self._contents(), ORIGINAL, "the input must not be touched")
        self.assertEqual(self._backups(), [], "a backup was taken for a file not at risk")
        self.assertEqual(
            stat.S_IMODE(os.stat(other).st_mode),
            0o600,
            "a newly created envelope must not be readable by others",
        )


if __name__ == "__main__":
    unittest.main()
