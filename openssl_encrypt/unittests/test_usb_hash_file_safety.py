#!/usr/bin/env python3
"""
Hashing a file on an untrusted drive must not hang or leave the drive
(gitlab#202).

`_sha256_file` claimed in its own docstring that its byte bound stopped "a
FIFO / symlink to an unbounded stream ... from exhausting memory or looping
forever". It did not: the bound applies to `f.read()`, but `open(path,
"rb")` on a FIFO blocks inside `open()` itself, before a single byte is
read. Measured before the fix:

    hashed within 5s: False | exists(): True | is_file(): False

The added-file and autorun scans guard with `is_file()`, but the main
manifest loop guards with `exists()` -- True for a FIFO -- so replacing any
manifest-listed file with a FIFO hung `verify-usb` indefinitely, on the
exact path whose job is to report tampering.

A non-regular or symlinked entry is now *tampered*, not something to hash.
That is the correct verdict anyway: a real drive's manifest lists regular
files, so anything else at that path is a substitution.
"""

import os
import shutil
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator

TIMEOUT_SECONDS = 5


class _HashTestCase(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _call_with_timeout(self, path):
        """Run _sha256_file on another thread so a hang is a failure, not a
        hung test run. Returns (finished, result_or_exception)."""
        box = {}

        def run():
            try:
                box["result"] = self.creator._sha256_file(path)
            except BaseException as error:  # noqa: BLE001 - reported to the caller
                box["error"] = error

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=TIMEOUT_SECONDS)
        return not thread.is_alive(), box


class TestANonRegularFileIsRefusedNotHashed(_HashTestCase):
    def test_a_fifo_does_not_hang(self):
        fifo = self.tmp / "planted"
        os.mkfifo(fifo)

        finished, box = self._call_with_timeout(fifo)

        self.assertTrue(
            finished,
            f"_sha256_file blocked for over {TIMEOUT_SECONDS}s on a FIFO; a "
            "planted named pipe hangs verify-usb forever",
        )
        self.assertIn("error", box, "a FIFO was hashed as if it were a regular file")

    def test_a_directory_is_refused(self):
        target = self.tmp / "adir"
        target.mkdir()
        finished, box = self._call_with_timeout(target)
        self.assertTrue(finished)
        self.assertIn("error", box)

    def test_a_symlink_is_not_followed(self):
        """A manifest-listed name replaced by a symlink must not cause a file
        outside the drive to be read."""
        outside = self.tmp / "outside.txt"
        outside.write_bytes(b"content from outside the drive")
        link = self.tmp / "listed-name"
        os.symlink(outside, link)

        finished, box = self._call_with_timeout(link)

        self.assertTrue(finished)
        self.assertIn("error", box, "the symlink was followed and its target hashed")

    def test_a_symlink_to_a_regular_file_is_refused_even_inside_the_drive(self):
        """No exception for links that happen to resolve within the tree:
        the manifest lists regular files, so a link at that path is a
        substitution regardless of where it points."""
        real = self.tmp / "real.txt"
        real.write_bytes(b"data")
        link = self.tmp / "link.txt"
        os.symlink(real, link)

        finished, box = self._call_with_timeout(link)
        self.assertTrue(finished)
        self.assertIn("error", box)


class TestARegularFileStillHashesCorrectly(_HashTestCase):
    """The load-bearing half: refusing everything would 'fix' this by
    breaking verification entirely."""

    def test_the_digest_is_unchanged(self):
        import hashlib

        payload = b"the quick brown fox" * 1000
        path = self.tmp / "regular.bin"
        path.write_bytes(payload)

        finished, box = self._call_with_timeout(path)

        self.assertTrue(finished)
        self.assertNotIn("error", box, box.get("error"))
        self.assertEqual(box["result"], hashlib.sha256(payload).hexdigest())

    def test_an_empty_file_hashes(self):
        import hashlib

        path = self.tmp / "empty.bin"
        path.write_bytes(b"")
        finished, box = self._call_with_timeout(path)
        self.assertTrue(finished)
        self.assertEqual(box["result"], hashlib.sha256(b"").hexdigest())

    def test_a_file_larger_than_a_chunk_hashes(self):
        """The streaming loop, not just the single-read case."""
        import hashlib

        payload = os.urandom(3 * 1024 * 1024)
        path = self.tmp / "big.bin"
        path.write_bytes(payload)
        finished, box = self._call_with_timeout(path)
        self.assertTrue(finished)
        self.assertEqual(box["result"], hashlib.sha256(payload).hexdigest())


class TestTheVerifierReportsTamperingRatherThanHanging(unittest.TestCase):
    """A refused file has to become a verdict, not a hang or a traceback.

    `verify-usb`'s whole job is to answer "was this drive tampered with", so
    a manifest-listed file replaced by a FIFO must come back as tampering.
    Driven through the real `_create_integrity_file` /
    `_verify_integrity_file` pair, the same way the gitlab#132 suite does.
    """

    def setUp(self):
        self.creator = USBDriveCreator()
        self.key = os.urandom(32)
        self.usb_root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.usb_root, ignore_errors=True)
        self.portable_root = self.usb_root / self.creator.PORTABLE_DIR
        self.portable_root.mkdir(parents=True)
        (self.portable_root / "app.py").write_text("print('hi')\n")
        (self.portable_root / "readme.txt").write_text("hello\n")

    def _verify_with_timeout(self):
        box = {}
        done = threading.Event()

        def run():
            try:
                box["result"] = self.creator._verify_integrity_file(
                    self.portable_root, self.key, usb_root=self.usb_root
                )
            except BaseException as error:  # noqa: BLE001 - reported to the caller
                box["error"] = error
            finally:
                done.set()

        threading.Thread(target=run, daemon=True).start()
        return done.wait(timeout=TIMEOUT_SECONDS), box

    def test_a_listed_file_replaced_by_a_fifo_is_tampering(self):
        self.creator._create_integrity_file(self.portable_root, self.key, usb_root=self.usb_root)

        target = self.portable_root / "app.py"
        target.unlink()
        os.mkfifo(target)

        finished, box = self._verify_with_timeout()

        self.assertTrue(
            finished,
            f"verification blocked for over {TIMEOUT_SECONDS}s; a planted FIFO "
            "hangs verify-usb forever",
        )
        self.assertNotIn("error", box, box.get("error"))
        self.assertFalse(
            box["result"]["integrity_ok"],
            "a manifest-listed file replaced by a FIFO verified as intact",
        )

    def test_an_untouched_drive_still_verifies(self):
        """Without this, refusing everything would 'pass' the test above."""
        self.creator._create_integrity_file(self.portable_root, self.key, usb_root=self.usb_root)

        finished, box = self._verify_with_timeout()

        self.assertTrue(finished)
        self.assertNotIn("error", box, box.get("error"))
        self.assertTrue(
            box["result"]["integrity_ok"],
            "an untouched drive was reported as tampered",
        )


if __name__ == "__main__":
    unittest.main()
