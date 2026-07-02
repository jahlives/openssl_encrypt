"""Regression tests for create_secure_file hardening (#58 / IO-1).

create_secure_file() opened the target with O_CREAT|O_WRONLY|O_TRUNC and no
O_NOFOLLOW, and the mode argument is ignored by open() when the file already
exists. Consequences in a shared/temp directory:

* symlink attack -- a planted symlink at the target path redirected the
  truncate+write through to an arbitrary file; and
* permission bypass -- an attacker who pre-created the target (e.g. world
  readable) had those permissions preserved while the tool wrote secrets into it.

The fix adds O_NOFOLLOW, refuses non-regular / foreign-owned targets, and
fchmod()s the descriptor so the intended 0600 mode is enforced even for a
pre-existing file.
"""

import os
import stat
import sys
import tempfile
import unittest

from openssl_encrypt.modules.file_permissions import PermissionLevel, create_secure_file


@unittest.skipIf(sys.platform == "win32", "POSIX permission semantics")
class TestCreateSecureFileHardening(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_symlinked_target_is_rejected_and_not_written_through(self):
        target = os.path.join(self.dir, "victim")
        with open(target, "w") as f:
            f.write("important-untouched")
        link = os.path.join(self.dir, "link")
        os.symlink(target, link)

        with self.assertRaises(OSError):
            fd = create_secure_file(link, PermissionLevel.OWNER_ONLY)
            os.close(fd)  # pragma: no cover - only reached if the bug is present

        # The symlink target must be intact (not truncated through the link).
        with open(target) as f:
            self.assertEqual(f.read(), "important-untouched")

    def test_preexisting_loose_permissions_are_tightened(self):
        path = os.path.join(self.dir, "preexisting")
        with open(path, "w") as f:
            f.write("old")
        os.chmod(path, 0o666)

        fd = create_secure_file(path, PermissionLevel.OWNER_ONLY)
        try:
            mode = stat.S_IMODE(os.fstat(fd).st_mode)
        finally:
            os.close(fd)
        self.assertEqual(mode, 0o600, "mode must be enforced even when the file pre-exists")

    def test_normal_creation_still_works_and_is_owner_only(self):
        path = os.path.join(self.dir, "fresh")
        fd = create_secure_file(path, PermissionLevel.OWNER_ONLY)
        try:
            os.write(fd, b"secret-bytes")
        finally:
            os.close(fd)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"secret-bytes")


if __name__ == "__main__":
    unittest.main()
