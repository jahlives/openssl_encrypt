#!/usr/bin/env python3
"""
Unit tests for the cross-platform file_permissions helper module.

Tests cover:
- set_permissions + check_permissions round-trips for each PermissionLevel
- create_secure_directory and create_secure_file
- Nonexistent path errors
- Idempotency
- POSIX-only: stat returns expected octal modes, umask atomicity
- Windows-only: DACL has expected ACEs, no inherited ACEs, pywin32 fallback
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openssl_encrypt.modules.file_permissions import (
    PermissionLevel,
    check_permissions,
    copy_permissions,
    create_secure_directory,
    create_secure_file,
    get_posix_mode,
    set_permissions,
)


class TestSetAndCheckPermissions(unittest.TestCase):
    """Test set_permissions + check_permissions round-trips."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.tmpdir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")
        self.test_dir = os.path.join(self.tmpdir, "test_dir")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_owner_only_file(self):
        """OWNER_ONLY: set + check round-trip on file."""
        set_permissions(self.test_file, PermissionLevel.OWNER_ONLY)
        self.assertTrue(check_permissions(self.test_file, PermissionLevel.OWNER_ONLY))

    def test_owner_full_directory(self):
        """OWNER_FULL: set + check round-trip on directory."""
        set_permissions(self.test_dir, PermissionLevel.OWNER_FULL)
        self.assertTrue(check_permissions(self.test_dir, PermissionLevel.OWNER_FULL))

    def test_owner_write_public_read(self):
        """OWNER_WRITE_PUBLIC_READ: set + check round-trip on file."""
        set_permissions(self.test_file, PermissionLevel.OWNER_WRITE_PUBLIC_READ)
        self.assertTrue(check_permissions(self.test_file, PermissionLevel.OWNER_WRITE_PUBLIC_READ))

    def test_check_returns_false_for_wrong_level(self):
        """check_permissions returns False when level doesn't match."""
        set_permissions(self.test_file, PermissionLevel.OWNER_ONLY)
        self.assertFalse(check_permissions(self.test_file, PermissionLevel.OWNER_WRITE_PUBLIC_READ))

    def test_nonexistent_path_raises(self):
        """set_permissions raises FileNotFoundError for nonexistent path."""
        with self.assertRaises(FileNotFoundError):
            set_permissions("/nonexistent/path/file.txt", PermissionLevel.OWNER_ONLY)

    def test_check_nonexistent_returns_false(self):
        """check_permissions returns False for nonexistent path."""
        self.assertFalse(check_permissions("/nonexistent/path", PermissionLevel.OWNER_ONLY))

    def test_idempotent_set(self):
        """Setting the same permission level twice is a no-op."""
        set_permissions(self.test_file, PermissionLevel.OWNER_ONLY)
        set_permissions(self.test_file, PermissionLevel.OWNER_ONLY)
        self.assertTrue(check_permissions(self.test_file, PermissionLevel.OWNER_ONLY))

    def test_path_object_accepted(self):
        """Path objects work as well as strings."""
        set_permissions(Path(self.test_file), PermissionLevel.OWNER_ONLY)
        self.assertTrue(check_permissions(Path(self.test_file), PermissionLevel.OWNER_ONLY))


class TestGetPosixMode(unittest.TestCase):
    """Test get_posix_mode returns expected values."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.tmpdir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_owner_only_mode(self):
        """get_posix_mode returns 0o600 after setting OWNER_ONLY."""
        set_permissions(self.test_file, PermissionLevel.OWNER_ONLY)
        self.assertEqual(get_posix_mode(self.test_file), 0o600)

    def test_owner_full_mode(self):
        """get_posix_mode returns 0o700 after setting OWNER_FULL."""
        test_dir = os.path.join(self.tmpdir, "subdir")
        os.makedirs(test_dir)
        set_permissions(test_dir, PermissionLevel.OWNER_FULL)
        self.assertEqual(get_posix_mode(test_dir), 0o700)

    def test_public_read_mode(self):
        """get_posix_mode returns 0o644 after setting OWNER_WRITE_PUBLIC_READ."""
        set_permissions(self.test_file, PermissionLevel.OWNER_WRITE_PUBLIC_READ)
        self.assertEqual(get_posix_mode(self.test_file), 0o644)


class TestCreateSecureDirectory(unittest.TestCase):
    """Test create_secure_directory."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_creates_directory(self):
        """Directory is created."""
        target = Path(self.tmpdir) / "secure_dir"
        result = create_secure_directory(target)
        self.assertTrue(result.exists())
        self.assertTrue(result.is_dir())

    def test_owner_full_by_default(self):
        """Default permission is OWNER_FULL (0o700)."""
        target = Path(self.tmpdir) / "secure_dir"
        create_secure_directory(target)
        self.assertTrue(check_permissions(target, PermissionLevel.OWNER_FULL))

    def test_nested_directory_creation(self):
        """Creates parent directories as needed."""
        target = Path(self.tmpdir) / "a" / "b" / "c"
        result = create_secure_directory(target)
        self.assertTrue(result.exists())

    def test_existing_directory_ok(self):
        """Calling on existing directory doesn't raise."""
        target = Path(self.tmpdir) / "existing"
        target.mkdir()
        result = create_secure_directory(target)
        self.assertEqual(result, target)
        self.assertTrue(check_permissions(target, PermissionLevel.OWNER_FULL))

    def test_returns_path_object(self):
        """Returns a Path object."""
        target = Path(self.tmpdir) / "secure_dir"
        result = create_secure_directory(target)
        self.assertIsInstance(result, Path)

    def test_custom_level(self):
        """Custom permission level is applied."""
        target = Path(self.tmpdir) / "custom_dir"
        create_secure_directory(target, level=PermissionLevel.OWNER_ONLY)
        self.assertTrue(check_permissions(target, PermissionLevel.OWNER_ONLY))


class TestCreateSecureFile(unittest.TestCase):
    """Test create_secure_file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_creates_file_with_fd(self):
        """Returns a valid file descriptor."""
        target = os.path.join(self.tmpdir, "secure_file.txt")
        fd = create_secure_file(target)
        try:
            os.write(fd, b"test data")
        finally:
            os.close(fd)
        self.assertTrue(os.path.exists(target))

    def test_owner_only_by_default(self):
        """Default permission is OWNER_ONLY (0o600)."""
        target = os.path.join(self.tmpdir, "secure_file.txt")
        fd = create_secure_file(target)
        os.close(fd)
        self.assertTrue(check_permissions(target, PermissionLevel.OWNER_ONLY))

    def test_file_content_writable(self):
        """Can write data through the returned fd."""
        target = os.path.join(self.tmpdir, "writable.txt")
        fd = create_secure_file(target)
        os.write(fd, b"hello world")
        os.close(fd)
        with open(target, "rb") as f:
            self.assertEqual(f.read(), b"hello world")


class TestCopyPermissions(unittest.TestCase):
    """Test copy_permissions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = os.path.join(self.tmpdir, "source.txt")
        self.target = os.path.join(self.tmpdir, "target.txt")
        for f in (self.source, self.target):
            with open(f, "w") as fh:
                fh.write("test")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_copy_owner_only(self):
        """Copies OWNER_ONLY permissions."""
        set_permissions(self.source, PermissionLevel.OWNER_ONLY)
        copy_permissions(self.source, self.target)
        self.assertTrue(check_permissions(self.target, PermissionLevel.OWNER_ONLY))

    def test_copy_public_read(self):
        """Copies OWNER_WRITE_PUBLIC_READ permissions."""
        set_permissions(self.source, PermissionLevel.OWNER_WRITE_PUBLIC_READ)
        copy_permissions(self.source, self.target)
        self.assertTrue(check_permissions(self.target, PermissionLevel.OWNER_WRITE_PUBLIC_READ))

    def test_source_not_found(self):
        """Raises FileNotFoundError if source doesn't exist."""
        with self.assertRaises(FileNotFoundError):
            copy_permissions("/nonexistent", self.target)

    def test_target_not_found(self):
        """Raises FileNotFoundError if target doesn't exist."""
        with self.assertRaises(FileNotFoundError):
            copy_permissions(self.source, "/nonexistent")


@unittest.skipIf(sys.platform == "win32", "POSIX-only tests")
class TestPosixSpecific(unittest.TestCase):
    """POSIX-specific permission tests."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_stat_returns_0600(self):
        """stat returns 0o600 for OWNER_ONLY."""
        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")
        set_permissions(f, PermissionLevel.OWNER_ONLY)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)

    def test_stat_returns_0700(self):
        """stat returns 0o700 for OWNER_FULL."""
        d = os.path.join(self.tmpdir, "dir")
        os.makedirs(d)
        set_permissions(d, PermissionLevel.OWNER_FULL)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)

    def test_stat_returns_0644(self):
        """stat returns 0o644 for OWNER_WRITE_PUBLIC_READ."""
        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")
        set_permissions(f, PermissionLevel.OWNER_WRITE_PUBLIC_READ)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o644)

    def test_umask_restored_after_secure_directory(self):
        """umask is restored after create_secure_directory."""
        original = os.umask(0o022)
        os.umask(original)

        create_secure_directory(Path(self.tmpdir) / "test_umask_dir")

        current = os.umask(0o022)
        os.umask(current)
        self.assertEqual(current, original)

    def test_umask_restored_after_secure_file(self):
        """umask is restored after create_secure_file."""
        original = os.umask(0o022)
        os.umask(original)

        fd = create_secure_file(os.path.join(self.tmpdir, "test_umask_file"))
        os.close(fd)

        current = os.umask(0o022)
        os.umask(current)
        self.assertEqual(current, original)


@unittest.skipUnless(sys.platform == "win32", "Windows-only tests")
class TestWindowsSpecific(unittest.TestCase):
    """Windows-specific DACL tests."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _skip_if_no_pywin32(self):
        from openssl_encrypt.modules.file_permissions import _HAS_WIN32

        if not _HAS_WIN32:
            self.skipTest("pywin32 not available")

    def test_dacl_owner_only_aces(self):
        """OWNER_ONLY DACL has exactly owner + SYSTEM ACEs."""
        self._skip_if_no_pywin32()
        import ntsecuritycon as con
        import win32security

        from openssl_encrypt.modules.file_permissions import _get_system_sid, _get_windows_owner_sid

        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")

        set_permissions(f, PermissionLevel.OWNER_ONLY)

        sd = win32security.GetFileSecurity(f, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        owner_sid = _get_windows_owner_sid()
        system_sid = _get_system_sid()

        ace_sids = set()
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_sids.add(str(ace[2]))

        expected_sids = {str(owner_sid), str(system_sid)}
        self.assertEqual(ace_sids, expected_sids, "Should have exactly owner + SYSTEM")

    def test_dacl_owner_full_aces(self):
        """OWNER_FULL DACL gives owner FILE_ALL_ACCESS."""
        self._skip_if_no_pywin32()
        import ntsecuritycon as con
        import win32security

        from openssl_encrypt.modules.file_permissions import _get_windows_owner_sid

        d = os.path.join(self.tmpdir, "testdir")
        os.makedirs(d)

        set_permissions(d, PermissionLevel.OWNER_FULL)

        sd = win32security.GetFileSecurity(d, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        owner_sid = _get_windows_owner_sid()
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if str(ace[2]) == str(owner_sid):
                self.assertEqual(ace[1], con.FILE_ALL_ACCESS)

    def test_dacl_public_read_has_everyone(self):
        """OWNER_WRITE_PUBLIC_READ includes Everyone with read."""
        self._skip_if_no_pywin32()
        import ntsecuritycon as con
        import win32security

        from openssl_encrypt.modules.file_permissions import _get_everyone_sid

        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")

        set_permissions(f, PermissionLevel.OWNER_WRITE_PUBLIC_READ)

        sd = win32security.GetFileSecurity(f, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        everyone_sid = _get_everyone_sid()
        found_everyone = False
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if str(ace[2]) == str(everyone_sid):
                found_everyone = True
                self.assertEqual(ace[1], con.FILE_GENERIC_READ)

        self.assertTrue(found_everyone, "Everyone ACE should be present")

    def test_no_inherited_aces(self):
        """DACL should have no inherited ACEs (PROTECTED_DACL)."""
        self._skip_if_no_pywin32()
        import win32security

        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")

        set_permissions(f, PermissionLevel.OWNER_ONLY)

        sd = win32security.GetFileSecurity(f, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            # ace[0] is (ace_type, ace_flags)
            ace_flags = ace[0][1]
            # INHERITED_ACE = 0x10
            self.assertFalse(ace_flags & 0x10, "No ACEs should be inherited")

    def test_synthetic_posix_mode(self):
        """get_posix_mode returns synthetic modes on Windows."""
        self._skip_if_no_pywin32()

        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")

        set_permissions(f, PermissionLevel.OWNER_ONLY)
        self.assertEqual(get_posix_mode(f), 0o600)

        set_permissions(f, PermissionLevel.OWNER_WRITE_PUBLIC_READ)
        self.assertEqual(get_posix_mode(f), 0o644)

    def test_fallback_without_pywin32(self):
        """When pywin32 is not available, falls back to os.chmod."""
        f = os.path.join(self.tmpdir, "test.txt")
        with open(f, "w") as fh:
            fh.write("x")

        with patch("openssl_encrypt.modules.file_permissions._HAS_WIN32", False):
            # Should not raise even without pywin32
            set_permissions(f, PermissionLevel.OWNER_ONLY)
            # check_permissions falls back to stat mode
            # On Windows without pywin32 this is unreliable, but should not error
            check_permissions(f, PermissionLevel.OWNER_ONLY)


if __name__ == "__main__":
    unittest.main()
