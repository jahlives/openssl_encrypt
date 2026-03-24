#!/usr/bin/env python3
"""
Directory archiving module for encrypted directory support.

Provides tar-based directory archiving for encrypt/decrypt operations,
with security-hardened extraction to prevent path traversal attacks.
"""

import os
import stat
import sys
import tarfile
import tempfile
from typing import Dict, Optional

from .crypt_errors import ValidationError

# Import secure file deletion
try:
    from .crypt_utils import secure_shred_file as _secure_shred_file

    _SECURE_SHRED_AVAILABLE = True
except ImportError:
    _SECURE_SHRED_AVAILABLE = False


def secure_cleanup_temp_file(filepath: str) -> None:
    """Securely delete a temporary file by shredding before unlinking.

    Args:
        filepath: Path to the temporary file.
    """
    if not filepath or not os.path.exists(filepath):
        return
    try:
        if _SECURE_SHRED_AVAILABLE:
            _secure_shred_file(filepath, passes=1, quiet=True)
        else:
            # Fallback: overwrite with random data then delete
            size = os.path.getsize(filepath)
            with open(filepath, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            os.unlink(filepath)
    except OSError:
        # Last resort: just delete
        try:
            os.unlink(filepath)
        except OSError:
            pass


class DirectoryArchiver:
    """Creates tar archives from directories for encryption.

    Attributes:
        preserve_permissions: Whether to preserve file permissions in tar.
        follow_symlinks: Whether to follow symlinks when archiving.
    """

    def __init__(
        self,
        preserve_permissions: bool = True,
        follow_symlinks: bool = False,
    ):
        self.preserve_permissions = preserve_permissions
        self.follow_symlinks = follow_symlinks

    def create_tar_to_file(self, dir_path: str) -> str:
        """Create a tar archive of the directory to a temporary file.

        Args:
            dir_path: Path to the directory to archive.

        Returns:
            Path to the temporary tar file.

        Raises:
            ValidationError: If the directory is invalid.
        """
        validate_directory_input(dir_path)

        # Create temp file for the tar
        fd, temp_tar_path = tempfile.mkstemp(suffix=".tar", prefix="ossl_enc_")
        os.close(fd)

        try:
            # Use the directory basename as the archive root
            root_name = os.path.basename(os.path.normpath(dir_path))

            with tarfile.open(temp_tar_path, "w") as tar:
                tar.add(
                    dir_path,
                    arcname=root_name,
                    recursive=True,
                    filter=self._tar_filter if not self.follow_symlinks else None,
                )

        except Exception as e:
            # Securely clean up temp file on error
            secure_cleanup_temp_file(temp_tar_path)
            raise ValidationError(f"Failed to create archive: {e}")

        return temp_tar_path

    def _tar_filter(self, tarinfo: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
        """Filter for tar.add() to handle symlinks and permissions.

        Args:
            tarinfo: The TarInfo object being added.

        Returns:
            The TarInfo object (possibly modified) or None to skip.
        """
        # Skip symlinks if not following them
        if tarinfo.issym() or tarinfo.islnk():
            if not self.follow_symlinks:
                return None

        # Optionally strip permissions
        if not self.preserve_permissions:
            tarinfo.mode = 0o644 if tarinfo.isfile() else 0o755

        return tarinfo

    def get_manifest(self, dir_path: str) -> Dict:
        """Get a manifest of the directory contents.

        Args:
            dir_path: Path to the directory.

        Returns:
            Dictionary with directory statistics and file list.
        """
        validate_directory_input(dir_path)

        total_files = 0
        total_dirs = 0
        total_size = 0
        contains_symlinks = False
        file_list = []

        norm_dir = os.path.normpath(dir_path)

        for root, dirs, files in os.walk(dir_path, followlinks=self.follow_symlinks):
            total_dirs += len(dirs)
            for f in files:
                filepath = os.path.join(root, f)
                if os.path.islink(filepath):
                    contains_symlinks = True
                    if not self.follow_symlinks:
                        continue
                try:
                    file_size = os.path.getsize(filepath)
                    file_mtime = os.path.getmtime(filepath)
                    total_size += file_size
                except OSError:
                    file_size = 0
                    file_mtime = 0
                total_files += 1

                # Store relative path from the archived directory
                rel_path = os.path.relpath(filepath, norm_dir)
                entry = {
                    "path": rel_path,
                    "size": file_size,
                }
                if file_mtime:
                    from datetime import datetime, timezone

                    entry["mtime"] = datetime.fromtimestamp(
                        file_mtime, tz=timezone.utc
                    ).isoformat()
                file_list.append(entry)

            # Check dirs for symlinks too
            for d in dirs:
                dirpath = os.path.join(root, d)
                if os.path.islink(dirpath):
                    contains_symlinks = True

        root_name = os.path.basename(os.path.normpath(dir_path))

        # Sort file list by path for consistent output
        file_list.sort(key=lambda e: e["path"])

        return {
            "total_files": total_files,
            "total_dirs": total_dirs,
            "total_size_bytes": total_size,
            "contains_symlinks": contains_symlinks,
            "root_name": root_name,
            "files": file_list,
        }


def secure_tar_extract(tar_data_or_path, output_dir: str) -> None:
    """Security-hardened tar extraction.

    Validates all members before extraction to prevent:
    - Path traversal (.. components)
    - Absolute paths
    - Symlinks pointing outside output_dir

    Args:
        tar_data_or_path: Either bytes (tar data) or str (path to tar file).
        output_dir: Directory to extract into.

    Raises:
        ValidationError: If any security check fails.
    """
    import io

    if isinstance(tar_data_or_path, (bytes, bytearray)):
        tar_fileobj = io.BytesIO(tar_data_or_path)
        tar = tarfile.open(fileobj=tar_fileobj, mode="r")
    elif isinstance(tar_data_or_path, str):
        tar = tarfile.open(tar_data_or_path, mode="r")
    else:
        raise ValidationError("tar_data_or_path must be bytes or a file path")

    try:
        # Validate ALL members before extracting ANY
        abs_output = os.path.realpath(output_dir)

        for member in tar.getmembers():
            # Reject absolute paths
            if os.path.isabs(member.name):
                raise ValidationError(
                    f"Absolute path in archive: {member.name}"
                )

            # Reject path traversal
            # Normalize and check for .. components
            normalized = os.path.normpath(member.name)
            if normalized.startswith("..") or "/../" in "/" + normalized + "/":
                raise ValidationError(
                    f"Path traversal in archive: {member.name}"
                )

            # Check resolved path is within output_dir
            target_path = os.path.realpath(os.path.join(output_dir, member.name))
            if not target_path.startswith(abs_output + os.sep) and target_path != abs_output:
                raise ValidationError(
                    f"Path escapes output directory: {member.name}"
                )

            # Reject symlinks pointing outside output_dir
            if member.issym():
                link_target = os.path.normpath(
                    os.path.join(os.path.dirname(member.name), member.linkname)
                )
                if link_target.startswith("..") or os.path.isabs(member.linkname):
                    raise ValidationError(
                        f"Symlink escapes output directory: {member.name} -> {member.linkname}"
                    )

        # All checks passed — extract
        os.makedirs(output_dir, exist_ok=True)
        if sys.version_info >= (3, 12):
            tar.extractall(path=output_dir, filter="data")
        else:
            # Python < 3.12 lacks the filter parameter;
            # security is already enforced by the manual validation above
            tar.extractall(path=output_dir)
    finally:
        tar.close()


def validate_directory_input(path: str) -> None:
    """Validate that a path is a readable directory.

    Args:
        path: Path to validate.

    Raises:
        ValidationError: If path is not a valid readable directory.
    """
    if not path:
        raise ValidationError("Directory path cannot be empty")

    if not os.path.exists(path):
        raise ValidationError(f"Directory does not exist: {path}")

    if not os.path.isdir(path):
        raise ValidationError(f"Path is not a directory: {path}")

    if not os.access(path, os.R_OK):
        raise ValidationError(f"Directory is not readable: {path}")
