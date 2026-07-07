"""Regression tests for GitLab #74 [IO-4]: os.umask() process-global race.

create_secure_file() and create_secure_directory() used to set the
process-global os.umask() for the duration of the create call and restore it
in a finally block. os.umask is process-wide, so during that window any OTHER
thread creating a file/dir raced against the temporarily-changed mask.

The hardened versions must not touch the global umask at all: the file is
created with os.open(mode=...) and pinned with fchmod; each missing directory
component is created with mkdir(mode=...) and pinned with chmod. This test
guards that os.umask is never called and that the resulting permissions are
correct (final dir and every component we create are owner-only), while a
pre-existing component is left untouched.
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules.file_permissions import (
    PermissionLevel,
    create_secure_directory,
    create_secure_file,
)


@unittest.skipIf(sys.platform == "win32", "POSIX umask semantics only")
class TestUmaskFreeCreation(unittest.TestCase):
    def test_create_secure_file_does_not_touch_global_umask(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "secret.bin"
            with mock.patch("openssl_encrypt.modules.file_permissions.os.umask") as um:
                fd = create_secure_file(path, PermissionLevel.OWNER_ONLY)
                os.close(fd)
            um.assert_not_called()
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_create_secure_directory_does_not_touch_global_umask(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "a" / "b" / "c"
            with mock.patch("openssl_encrypt.modules.file_permissions.os.umask") as um:
                create_secure_directory(target, PermissionLevel.OWNER_FULL)
            um.assert_not_called()
            # The final directory and every parent we created are owner-only.
            for comp in (Path(d) / "a", Path(d) / "a" / "b", target):
                self.assertEqual(stat.S_IMODE(os.stat(comp).st_mode), 0o700, comp)

    def test_pre_existing_component_left_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            existing = Path(d) / "a"
            existing.mkdir(mode=0o755)
            target = existing / "b" / "c"
            create_secure_directory(target, PermissionLevel.OWNER_FULL)
            # Pre-existing parent keeps its perms; newly created ones are 0o700.
            self.assertEqual(stat.S_IMODE(os.stat(existing).st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(os.stat(existing / "b").st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_existing_final_directory_mode_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "exists"
            target.mkdir(mode=0o755)
            create_secure_directory(target, PermissionLevel.OWNER_FULL)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)

    def test_concurrent_create_of_component_is_tolerated(self):
        """A component created by another process between the exists() probe and
        our mkdir must be skipped (FileExistsError), not raised (#74)."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "a" / "b"
            real_mkdir = Path.mkdir
            calls = {"n": 0}

            def racing_mkdir(self, *args, **kwargs):
                calls["n"] += 1
                if calls["n"] == 1:
                    real_mkdir(self, *args, **kwargs)  # actually create it
                    raise FileExistsError(f"raced: {self}")
                return real_mkdir(self, *args, **kwargs)

            with mock.patch.object(Path, "mkdir", racing_mkdir):
                create_secure_directory(target, PermissionLevel.OWNER_FULL)

            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
