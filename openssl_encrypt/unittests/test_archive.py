#!/usr/bin/env python3
"""
Unit tests for directory archiving — tar creation, extraction security,
and encrypt/decrypt roundtrip for directories.
"""

import os
import shutil
import stat
import tarfile
import tempfile
import unittest

from openssl_encrypt.modules.archive import (
    DirectoryArchiver,
    secure_tar_extract,
    validate_directory_input,
)
from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    print_file_info,
)
from openssl_encrypt.modules.crypt_errors import ValidationError


class TestDirectoryArchiver(unittest.TestCase):
    """Test DirectoryArchiver tar creation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_dir = os.path.join(self.temp_dir, "testdir")
        os.makedirs(self.test_dir)

        # Create test structure
        with open(os.path.join(self.test_dir, "file.txt"), "w") as f:
            f.write("hello")
        os.makedirs(os.path.join(self.test_dir, "sub"))
        with open(os.path.join(self.test_dir, "sub", "nested.txt"), "w") as f:
            f.write("world")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_tar_to_file(self):
        """Creates a valid tar file."""
        archiver = DirectoryArchiver()
        tar_path = archiver.create_tar_to_file(self.test_dir)
        self.assertTrue(os.path.isfile(tar_path))
        self.assertGreater(os.path.getsize(tar_path), 0)

        # Verify it's a valid tar
        with tarfile.open(tar_path, "r") as t:
            names = t.getnames()
            self.assertTrue(any("file.txt" in n for n in names))
            self.assertTrue(any("nested.txt" in n for n in names))
        os.unlink(tar_path)

    def test_tar_preserves_directory_structure(self):
        """Tar preserves nested directory structure."""
        archiver = DirectoryArchiver()
        tar_path = archiver.create_tar_to_file(self.test_dir)
        with tarfile.open(tar_path, "r") as t:
            names = t.getnames()
            self.assertTrue(any("sub" in n for n in names))
        os.unlink(tar_path)

    def test_tar_uses_basename_as_root(self):
        """Tar uses directory basename as archive root."""
        archiver = DirectoryArchiver()
        tar_path = archiver.create_tar_to_file(self.test_dir)
        with tarfile.open(tar_path, "r") as t:
            names = t.getnames()
            # Root should be "testdir", not the full path
            self.assertTrue(names[0].startswith("testdir"))
        os.unlink(tar_path)

    def test_empty_directory(self):
        """Empty directory can be archived."""
        empty_dir = os.path.join(self.temp_dir, "empty")
        os.makedirs(empty_dir)
        archiver = DirectoryArchiver()
        tar_path = archiver.create_tar_to_file(empty_dir)
        self.assertTrue(os.path.isfile(tar_path))
        os.unlink(tar_path)

    def test_symlinks_skipped_by_default(self):
        """Symlinks are skipped when follow_symlinks=False."""
        link_path = os.path.join(self.test_dir, "link.txt")
        try:
            os.symlink(os.path.join(self.test_dir, "file.txt"), link_path)
        except OSError:
            self.skipTest("Cannot create symlinks")

        archiver = DirectoryArchiver(follow_symlinks=False)
        tar_path = archiver.create_tar_to_file(self.test_dir)
        with tarfile.open(tar_path, "r") as t:
            names = t.getnames()
            self.assertFalse(any("link.txt" in n for n in names))
        os.unlink(tar_path)


class TestGetManifest(unittest.TestCase):
    """Test get_manifest()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_dir = os.path.join(self.temp_dir, "testdir")
        os.makedirs(self.test_dir)
        with open(os.path.join(self.test_dir, "a.txt"), "w") as f:
            f.write("aaaa")
        with open(os.path.join(self.test_dir, "b.txt"), "w") as f:
            f.write("bbbb")
        os.makedirs(os.path.join(self.test_dir, "sub"))
        with open(os.path.join(self.test_dir, "sub", "c.txt"), "w") as f:
            f.write("cccc")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_count(self):
        """Manifest reports correct file count."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)
        self.assertEqual(manifest["total_files"], 3)

    def test_dir_count(self):
        """Manifest reports correct directory count."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)
        self.assertEqual(manifest["total_dirs"], 1)

    def test_total_size(self):
        """Manifest reports reasonable total size."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)
        self.assertEqual(manifest["total_size_bytes"], 12)  # 3 * 4 bytes

    def test_root_name(self):
        """Manifest root_name is directory basename."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)
        self.assertEqual(manifest["root_name"], "testdir")

    def test_no_symlinks(self):
        """Manifest reports no symlinks when there are none."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)
        self.assertFalse(manifest["contains_symlinks"])


class TestTarExtraction(unittest.TestCase):
    """Test secure_tar_extract security checks."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.temp_dir, "output")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_tar_bytes(self, members):
        """Helper to create tar bytes with specified members.

        Args:
            members: list of (name, content_bytes) tuples.
        """
        import io

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, content in members:
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                t.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    def test_normal_extraction(self):
        """Normal tar extracts correctly."""
        data = self._create_tar_bytes([("file.txt", b"hello")])
        secure_tar_extract(data, self.output_dir)
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "file.txt")))
        with open(os.path.join(self.output_dir, "file.txt"), "rb") as f:
            self.assertEqual(f.read(), b"hello")

    def test_nested_extraction(self):
        """Nested files extract correctly."""
        data = self._create_tar_bytes(
            [
                ("dir/file.txt", b"content"),
            ]
        )
        secure_tar_extract(data, self.output_dir)
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "dir", "file.txt")))

    def test_path_traversal_rejected(self):
        """Path traversal (../) is rejected."""
        data = self._create_tar_bytes([("../escape.txt", b"evil")])
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)

    def test_absolute_path_rejected(self):
        """Absolute paths are rejected."""
        data = self._create_tar_bytes([("/etc/passwd", b"evil")])
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)

    def _create_tar_with_link(self, link_name, link_target, linktype, extra=None):
        """Helper to build tar bytes containing a symlink or hardlink member.

        Args:
            link_name: Archive name of the link member.
            link_target: linkname the link points at (the escape vector).
            linktype: tarfile.SYMTYPE or tarfile.LNKTYPE.
            extra: optional list of (name, content_bytes) regular members added
                after the link (used to write *through* a hardlink).
        """
        import io

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            info = tarfile.TarInfo(name=link_name)
            info.type = linktype
            info.linkname = link_target
            info.size = 0
            t.addfile(info)
            for name, content in extra or []:
                reg = tarfile.TarInfo(name=name)
                reg.size = len(content)
                t.addfile(reg, io.BytesIO(content))
        return buf.getvalue()

    def test_hardlink_escape_rejected(self):
        """Hardlink whose target escapes the output dir is rejected."""
        data = self._create_tar_with_link("foo", "../../etc/passwd", tarfile.LNKTYPE)
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)

    def test_hardlink_absolute_target_rejected(self):
        """Hardlink with an absolute target is rejected."""
        data = self._create_tar_with_link("foo", "/etc/passwd", tarfile.LNKTYPE)
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)

    def test_hardlink_write_through_does_not_escape(self):
        """A hardlink+regular-file pair cannot overwrite a file outside output_dir."""
        # Sentinel outside the extraction directory that must NOT be modified.
        outside = os.path.join(self.temp_dir, "victim.txt")
        with open(outside, "wb") as f:
            f.write(b"ORIGINAL")
        data = self._create_tar_with_link(
            "foo",
            "../victim.txt",
            tarfile.LNKTYPE,
            extra=[("foo", b"PWNED")],
        )
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)
        with open(outside, "rb") as f:
            self.assertEqual(f.read(), b"ORIGINAL")

    def test_symlink_escape_via_addfile_rejected(self):
        """Symlink escaping the output dir is rejected (parity with hardlink)."""
        data = self._create_tar_with_link("foo", "../../etc/passwd", tarfile.SYMTYPE)
        with self.assertRaises(ValidationError):
            secure_tar_extract(data, self.output_dir)

    def test_roundtrip(self):
        """Archive → extract roundtrip preserves content."""
        # Create test dir
        src_dir = os.path.join(self.temp_dir, "src")
        os.makedirs(os.path.join(src_dir, "sub"))
        with open(os.path.join(src_dir, "a.txt"), "w") as f:
            f.write("alpha")
        with open(os.path.join(src_dir, "sub", "b.txt"), "w") as f:
            f.write("beta")

        # Archive
        archiver = DirectoryArchiver()
        tar_path = archiver.create_tar_to_file(src_dir)

        # Extract
        secure_tar_extract(tar_path, self.output_dir)

        # Verify
        with open(os.path.join(self.output_dir, "src", "a.txt")) as f:
            self.assertEqual(f.read(), "alpha")
        with open(os.path.join(self.output_dir, "src", "sub", "b.txt")) as f:
            self.assertEqual(f.read(), "beta")
        os.unlink(tar_path)


class TestValidateDirectoryInput(unittest.TestCase):
    """Test validate_directory_input()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_directory(self):
        """Valid directory passes validation."""
        validate_directory_input(self.temp_dir)  # Should not raise

    def test_nonexistent_path(self):
        """Nonexistent path raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_directory_input("/nonexistent/path/12345")

    def test_file_not_directory(self):
        """File path (not a directory) raises ValidationError."""
        filepath = os.path.join(self.temp_dir, "file.txt")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("x")
        with self.assertRaises(ValidationError):
            validate_directory_input(filepath)

    def test_empty_path(self):
        """Empty path raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_directory_input("")


class TestDirectoryEncryptDecrypt(unittest.TestCase):
    """Test full encrypt/decrypt roundtrip for directories."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_for_archive!"

        # Create test directory structure
        self.test_dir = os.path.join(self.temp_dir, "mydir")
        os.makedirs(os.path.join(self.test_dir, "sub"))
        with open(os.path.join(self.test_dir, "file.txt"), "w") as f:
            f.write("hello from file.txt")
        with open(os.path.join(self.test_dir, "sub", "nested.txt"), "w") as f:
            f.write("hello from nested.txt")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_directory_encrypt_decrypt_roundtrip(self):
        """Directory encrypt and decrypt preserves all files."""
        enc_file = os.path.join(self.temp_dir, "mydir.enc")
        encrypt_file(
            input_file=self.test_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )
        self.assertTrue(os.path.isfile(enc_file))

        # Decrypt to output directory
        output_dir = os.path.join(self.temp_dir, "restored")
        decrypt_file(
            input_file=enc_file,
            output_file=output_dir,
            password=self.password,
            quiet=True,
        )

        # Verify content
        restored_file = os.path.join(output_dir, "mydir", "file.txt")
        self.assertTrue(os.path.isfile(restored_file))
        with open(restored_file) as f:
            self.assertEqual(f.read(), "hello from file.txt")

        restored_nested = os.path.join(output_dir, "mydir", "sub", "nested.txt")
        self.assertTrue(os.path.isfile(restored_nested))
        with open(restored_nested) as f:
            self.assertEqual(f.read(), "hello from nested.txt")

    def test_directory_encrypt_with_fernet(self):
        """Directory encrypt works with Fernet algorithm."""
        enc_file = os.path.join(self.temp_dir, "fernet_dir.enc")
        encrypt_file(
            input_file=self.test_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.FERNET,
            quiet=True,
        )
        self.assertTrue(os.path.isfile(enc_file))

        output_dir = os.path.join(self.temp_dir, "fernet_restored")
        decrypt_file(
            input_file=enc_file,
            output_file=output_dir,
            password=self.password,
            quiet=True,
        )

        self.assertTrue(os.path.isfile(os.path.join(output_dir, "mydir", "file.txt")))

    def test_directory_encrypt_with_chacha20(self):
        """Directory encrypt works with ChaCha20-Poly1305."""
        enc_file = os.path.join(self.temp_dir, "chacha_dir.enc")
        encrypt_file(
            input_file=self.test_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.CHACHA20_POLY1305,
            quiet=True,
        )
        self.assertTrue(os.path.isfile(enc_file))

        output_dir = os.path.join(self.temp_dir, "chacha_restored")
        decrypt_file(
            input_file=enc_file,
            output_file=output_dir,
            password=self.password,
            quiet=True,
        )

        self.assertTrue(os.path.isfile(os.path.join(output_dir, "mydir", "file.txt")))

    def test_metadata_contains_archive_info(self):
        """Encrypted directory metadata contains archive field."""
        import base64
        import json

        enc_file = os.path.join(self.temp_dir, "meta_check.enc")
        encrypt_file(
            input_file=self.test_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        with open(enc_file, "rb") as f:
            content = f.read()
        metadata_b64 = content.split(b":")[0]
        metadata = json.loads(base64.b64decode(metadata_b64))

        self.assertIn("archive", metadata)
        self.assertEqual(metadata["archive"]["type"], "tar")
        self.assertEqual(metadata["archive"]["original_path"], "mydir")
        self.assertIn("manifest", metadata["archive"])
        self.assertEqual(metadata["archive"]["manifest"]["total_files"], 2)

    def test_empty_directory_roundtrip(self):
        """Empty directory encrypt/decrypt roundtrip."""
        empty_dir = os.path.join(self.temp_dir, "empty")
        os.makedirs(empty_dir)

        enc_file = os.path.join(self.temp_dir, "empty.enc")
        encrypt_file(
            input_file=empty_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        output_dir = os.path.join(self.temp_dir, "empty_out")
        decrypt_file(
            input_file=enc_file,
            output_file=output_dir,
            password=self.password,
            quiet=True,
        )

        self.assertTrue(os.path.isdir(os.path.join(output_dir, "empty")))

    def test_special_chars_in_filenames(self):
        """Files with special characters in names survive roundtrip."""
        special_dir = os.path.join(self.temp_dir, "special")
        os.makedirs(special_dir)
        with open(os.path.join(special_dir, "file with spaces.txt"), "w") as f:
            f.write("spaces")
        with open(os.path.join(special_dir, "file-with-dashes.txt"), "w") as f:
            f.write("dashes")

        enc_file = os.path.join(self.temp_dir, "special.enc")
        encrypt_file(
            input_file=special_dir,
            output_file=enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        output_dir = os.path.join(self.temp_dir, "special_out")
        decrypt_file(
            input_file=enc_file,
            output_file=output_dir,
            password=self.password,
            quiet=True,
        )

        with open(os.path.join(output_dir, "special", "file with spaces.txt")) as f:
            self.assertEqual(f.read(), "spaces")


class TestManifestFileList(unittest.TestCase):
    """Test that manifest includes detailed file list."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_dir = os.path.join(self.temp_dir, "mydir")
        os.makedirs(os.path.join(self.test_dir, "sub"))
        with open(os.path.join(self.test_dir, "file.txt"), "w") as f:
            f.write("hello from file.txt")
        with open(os.path.join(self.test_dir, "sub", "nested.txt"), "w") as f:
            f.write("hello from nested.txt")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_includes_file_list(self):
        """Manifest contains a files list with paths and sizes."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)

        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]), 2)

        paths = [e["path"] for e in manifest["files"]]
        self.assertIn("file.txt", paths)
        self.assertIn(os.path.join("sub", "nested.txt"), paths)

        for entry in manifest["files"]:
            self.assertIn("path", entry)
            self.assertIn("size", entry)
            self.assertIsInstance(entry["size"], int)
            self.assertGreater(entry["size"], 0)

    def test_manifest_file_list_has_mtime(self):
        """File entries include modification time."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)

        for entry in manifest["files"]:
            self.assertIn("mtime", entry)
            # ISO format string
            self.assertIsInstance(entry["mtime"], str)
            self.assertIn("T", entry["mtime"])

    def test_manifest_file_list_sorted(self):
        """File list is sorted by path."""
        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(self.test_dir)

        paths = [e["path"] for e in manifest["files"]]
        self.assertEqual(paths, sorted(paths))

    def test_manifest_file_list_empty_dir(self):
        """Empty directory produces empty file list."""
        empty_dir = os.path.join(self.temp_dir, "empty")
        os.makedirs(empty_dir)

        archiver = DirectoryArchiver()
        manifest = archiver.get_manifest(empty_dir)

        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]), 0)


class TestInfoArchiveDisplay(unittest.TestCase):
    """Test that info action displays archive metadata."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_for_archive!"

        self.test_dir = os.path.join(self.temp_dir, "mydir")
        os.makedirs(os.path.join(self.test_dir, "sub"))
        with open(os.path.join(self.test_dir, "file.txt"), "w") as f:
            f.write("hello from file.txt")
        with open(os.path.join(self.test_dir, "sub", "nested.txt"), "w") as f:
            f.write("hello from nested.txt")

        # Encrypt the directory
        self.enc_file = os.path.join(self.temp_dir, "mydir.enc")
        encrypt_file(
            input_file=self.test_dir,
            output_file=self.enc_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_info_shows_archive_section(self):
        """print_file_info shows archive metadata for encrypted directories."""
        import io
        import sys

        old_stderr = sys.stderr
        stderr_capture = io.StringIO()
        sys.stderr = stderr_capture

        try:
            print_file_info(self.enc_file)
        finally:
            sys.stderr = old_stderr

        output = stderr_capture.getvalue()
        self.assertIn("Archive:", output)
        self.assertIn("Original Path:", output)
        self.assertIn("mydir", output)
        self.assertIn("Files:", output)
        self.assertIn("2", output)  # 2 files
        self.assertIn("Directories:", output)

    def test_info_list_shows_files(self):
        """print_file_info with list_files=True shows individual files."""
        import io
        import sys

        old_stderr = sys.stderr
        stderr_capture = io.StringIO()
        sys.stderr = stderr_capture

        try:
            print_file_info(self.enc_file, list_files=True)
        finally:
            sys.stderr = old_stderr

        output = stderr_capture.getvalue()
        self.assertIn("Archive Contents:", output)
        self.assertIn("file.txt", output)
        self.assertIn("nested.txt", output)

    def test_info_non_archive_no_archive_section(self):
        """print_file_info for a regular file does not show archive section."""
        import io
        import sys

        # Encrypt a regular file
        regular_file = os.path.join(self.temp_dir, "regular.txt")
        with open(regular_file, "w") as f:
            f.write("just a regular file")

        enc_regular = os.path.join(self.temp_dir, "regular.enc")
        encrypt_file(
            input_file=regular_file,
            output_file=enc_regular,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        old_stderr = sys.stderr
        stderr_capture = io.StringIO()
        sys.stderr = stderr_capture

        try:
            print_file_info(enc_regular)
        finally:
            sys.stderr = old_stderr

        output = stderr_capture.getvalue()
        self.assertNotIn("Archive:", output)
        self.assertNotIn("Archive Contents:", output)

    def test_metadata_file_list_in_archive(self):
        """Encrypted archive metadata includes file list."""
        import base64
        import json

        with open(self.enc_file, "rb") as f:
            content = f.read()
        metadata_b64 = content.split(b":")[0]
        metadata = json.loads(base64.b64decode(metadata_b64))

        archive = metadata.get("archive", {})
        manifest = archive.get("manifest", {})
        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]), 2)

        paths = [e["path"] for e in manifest["files"]]
        self.assertIn("file.txt", paths)


if __name__ == "__main__":
    unittest.main()
