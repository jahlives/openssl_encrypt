"""
Cross-platform file permission management.

Abstracts POSIX chmod/umask and Windows NTFS DACLs behind a unified API.
On POSIX, delegates to os.chmod/os.umask. On Windows, uses pywin32 to set
proper NTFS DACLs with inheritance disabled.

This module is intentionally self-contained — no imports from other
openssl_encrypt modules — so it can be cleanly backported.

Dependencies:
    - stdlib only on POSIX
    - pywin32 (win32security, ntsecuritycon, pywintypes) on Windows
      Falls back to os.chmod() if pywin32 is unavailable (degraded security).
"""

import logging
import os
import stat
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Windows-specific imports (conditional)
_HAS_WIN32 = False
if sys.platform == "win32":
    try:
        import ntsecuritycon as con
        import pywintypes
        import win32api
        import win32security

        _HAS_WIN32 = True
    except ImportError:
        logger.warning(
            "pywin32 not installed — falling back to os.chmod() for permissions. "
            "File security is degraded on Windows without pywin32."
        )


class PermissionLevel(Enum):
    """Permission levels for files and directories."""

    OWNER_ONLY = "owner_only"  # 0o600 / owner RW only
    OWNER_FULL = "owner_full"  # 0o700 / owner RWX only
    OWNER_WRITE_PUBLIC_READ = "owner_write_public_read"  # 0o644 / owner RW, everyone read


# POSIX mode mapping
_POSIX_MODES = {
    PermissionLevel.OWNER_ONLY: 0o600,
    PermissionLevel.OWNER_FULL: 0o700,
    PermissionLevel.OWNER_WRITE_PUBLIC_READ: 0o644,
}


def _get_windows_owner_sid():
    """Get the SID of the current user (file owner)."""
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_QUERY,
    )
    return win32security.GetTokenInformation(token, win32security.TokenUser)[0]


def _get_system_sid():
    """Get the SYSTEM account SID."""
    return win32security.ConvertStringSidToSid("S-1-5-18")


def _get_everyone_sid():
    """Get the Everyone group SID."""
    return win32security.ConvertStringSidToSid("S-1-1-0")


def _build_dacl(level: PermissionLevel) -> "win32security.ACL":
    """
    Build a Windows DACL matching the given permission level.

    Args:
        level: The permission level to apply.

    Returns:
        A win32security ACL object with the appropriate ACEs.
    """
    dacl = win32security.ACL()
    owner_sid = _get_windows_owner_sid()
    system_sid = _get_system_sid()

    if level == PermissionLevel.OWNER_ONLY:
        # Owner: read + write
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
            owner_sid,
        )
    elif level == PermissionLevel.OWNER_FULL:
        # Owner: full control
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_ALL_ACCESS,
            owner_sid,
        )
    elif level == PermissionLevel.OWNER_WRITE_PUBLIC_READ:
        # Owner: full control
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_ALL_ACCESS,
            owner_sid,
        )
        # Everyone: read
        everyone_sid = _get_everyone_sid()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_GENERIC_READ,
            everyone_sid,
        )

    # SYSTEM always gets full access (standard Windows practice)
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        con.FILE_ALL_ACCESS,
        system_sid,
    )

    return dacl


def _apply_dacl(path: str, dacl: "win32security.ACL") -> None:
    """
    Apply a DACL to a file/directory, disabling inheritance.

    Args:
        path: File or directory path.
        dacl: The DACL to apply.
    """
    # PROTECTED_DACL_SECURITY_INFORMATION disables inheritance from parent
    security_info = (
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION
    )
    sd = win32security.GetFileSecurity(str(path), win32security.OWNER_SECURITY_INFORMATION)
    sd.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(path), security_info, sd)


def _dacl_matches_level(path: str, level: PermissionLevel) -> bool:
    """
    Check if the current DACL on a path matches the expected permission level.

    Args:
        path: File or directory path.
        level: The expected permission level.

    Returns:
        True if the DACL matches the expected level.
    """
    try:
        sd = win32security.GetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return False

        owner_sid = _get_windows_owner_sid()
        system_sid = _get_system_sid()
        everyone_sid = _get_everyone_sid()

        # Collect ACEs
        ace_count = dacl.GetAceCount()
        aces = []
        for i in range(ace_count):
            ace = dacl.GetAce(i)
            # ace is (ace_type_and_flags, access_mask, sid)
            aces.append(ace)

        # Build expected ACE set based on level
        if level == PermissionLevel.OWNER_ONLY:
            expected_sids = {str(owner_sid), str(system_sid)}
            # Check: exactly owner + SYSTEM, no others
            actual_sids = {str(ace[2]) for ace in aces}
            if actual_sids != expected_sids:
                return False
            # Check owner has read+write (not full)
            for ace in aces:
                if str(ace[2]) == str(owner_sid):
                    mask = ace[1]
                    # Should have read+write but NOT execute/full
                    expected = con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE
                    if mask != expected:
                        return False

        elif level == PermissionLevel.OWNER_FULL:
            expected_sids = {str(owner_sid), str(system_sid)}
            actual_sids = {str(ace[2]) for ace in aces}
            if actual_sids != expected_sids:
                return False
            # Owner should have FILE_ALL_ACCESS
            for ace in aces:
                if str(ace[2]) == str(owner_sid):
                    if ace[1] != con.FILE_ALL_ACCESS:
                        return False

        elif level == PermissionLevel.OWNER_WRITE_PUBLIC_READ:
            expected_sids = {str(owner_sid), str(system_sid), str(everyone_sid)}
            actual_sids = {str(ace[2]) for ace in aces}
            if actual_sids != expected_sids:
                return False
            # Owner: full, Everyone: read
            for ace in aces:
                if str(ace[2]) == str(everyone_sid):
                    if ace[1] != con.FILE_GENERIC_READ:
                        return False
                elif str(ace[2]) == str(owner_sid):
                    if ace[1] != con.FILE_ALL_ACCESS:
                        return False

        return True

    except Exception as e:
        logger.debug(f"DACL check failed for {path}: {e}")
        return False


def _derive_posix_mode_from_dacl(path: str) -> int:
    """
    Derive a synthetic POSIX mode from Windows DACL analysis.

    This allows get_file_permissions() callers to get a meaningful
    mode value on Windows. Maps known DACL patterns to POSIX equivalents.

    Args:
        path: File or directory path.

    Returns:
        Synthetic POSIX mode (e.g. 0o600, 0o700, 0o644).
    """
    for level in PermissionLevel:
        if _dacl_matches_level(path, level):
            return _POSIX_MODES[level]

    # If no known pattern matches, return permissive as a conservative signal
    return 0o777


def set_permissions(path, level: PermissionLevel) -> None:
    """
    Set file/directory permissions to the specified level.

    On POSIX: uses os.chmod().
    On Windows with pywin32: sets NTFS DACLs with inheritance disabled.
    On Windows without pywin32: falls back to os.chmod() (degraded).

    Args:
        path: File or directory path (str or Path).
        level: The desired permission level.

    Raises:
        FileNotFoundError: If the path does not exist.
        OSError: If permissions cannot be set.
    """
    path_str = str(path)

    if not os.path.exists(path_str):
        raise FileNotFoundError(f"Path does not exist: {path_str}")

    if sys.platform == "win32" and _HAS_WIN32:
        dacl = _build_dacl(level)
        _apply_dacl(path_str, dacl)
    else:
        os.chmod(path_str, _POSIX_MODES[level])


def check_permissions(path, level: PermissionLevel) -> bool:
    """
    Check if a file/directory has the expected permission level.

    On POSIX: checks stat mode bits.
    On Windows with pywin32: checks DACL ACEs.
    On Windows without pywin32: checks stat mode bits (unreliable).

    Args:
        path: File or directory path (str or Path).
        level: The expected permission level.

    Returns:
        True if permissions match the expected level.
    """
    path_str = str(path)

    if not os.path.exists(path_str):
        return False

    if sys.platform == "win32" and _HAS_WIN32:
        return _dacl_matches_level(path_str, level)
    else:
        current_mode = stat.S_IMODE(os.stat(path_str).st_mode)
        return current_mode == _POSIX_MODES[level]


def get_posix_mode(path) -> int:
    """
    Get the POSIX permission mode for a file/directory.

    On POSIX: returns actual stat mode bits.
    On Windows with pywin32: derives synthetic POSIX mode from DACL.
    On Windows without pywin32: returns stat mode bits (unreliable).

    Args:
        path: File or directory path (str or Path).

    Returns:
        POSIX permission mode (e.g. 0o600, 0o700).
    """
    path_str = str(path)

    if sys.platform == "win32" and _HAS_WIN32:
        return _derive_posix_mode_from_dacl(path_str)
    else:
        return stat.S_IMODE(os.stat(path_str).st_mode)


def create_secure_directory(path, level: PermissionLevel = PermissionLevel.OWNER_FULL) -> Path:
    """
    Create a directory with secure permissions set atomically.

    On POSIX: creates each missing component with mkdir(mode=...) + chmod,
    without touching the process-global umask (#74).
    On Windows: creates directory then applies DACL.

    Args:
        path: Directory path to create (str or Path).
        level: Permission level (default: OWNER_FULL / 0o700).

    Returns:
        Path object for the created directory.

    Raises:
        OSError: If directory creation or permission setting fails.
    """
    path = Path(path)

    if sys.platform == "win32":
        path.mkdir(parents=True, exist_ok=True)
        if _HAS_WIN32:
            dacl = _build_dacl(level)
            _apply_dacl(str(path), dacl)
    else:
        posix_mode = _POSIX_MODES[level]
        # Create each missing path component explicitly at the target mode
        # instead of setting the process-global os.umask (which is process-wide
        # and races other threads creating files concurrently, #74). mkdir's
        # mode argument is still masked by any ambient umask, so chmod each
        # component we create to pin the exact mode. Pre-existing components are
        # left untouched (matching mkdir -p / exist_ok=True semantics).
        missing = []
        probe = path
        while not probe.exists():
            missing.append(probe)
            parent = probe.parent
            if parent == probe:  # reached the filesystem root
                break
            probe = parent
        for component in reversed(missing):
            try:
                component.mkdir(mode=posix_mode)
            except FileExistsError:
                # Created concurrently by another process; leave it as-is.
                continue
            os.chmod(component, posix_mode)

        # Defense in depth: enforce the intended mode on the final directory
        # even if it already existed.
        current = stat.S_IMODE(os.stat(path).st_mode)
        if current != posix_mode:
            os.chmod(path, posix_mode)

    return path


def create_secure_file(
    path, level: PermissionLevel = PermissionLevel.OWNER_ONLY, exclusive: bool = False
) -> int:
    """
    Open/create a file with secure permissions, returning a file descriptor.

    On POSIX: uses os.open(mode=...) + fchmod, without touching the
    process-global umask (#74).
    On Windows: creates file then applies DACL.

    Args:
        path: File path to create (str or Path).
        level: Permission level (default: OWNER_ONLY / 0o600).
        exclusive: Fail with FileExistsError if the path already exists (O_EXCL)
            instead of truncating it. Use for a destination that must never
            silently clobber, e.g. a written-out credential.

    Returns:
        File descriptor (int) for the opened file.

    Raises:
        FileExistsError: If exclusive is set and the path exists.
        OSError: If file creation or permission setting fails.
    """
    path_str = str(path)
    posix_mode = _POSIX_MODES[level]
    create_flag = os.O_EXCL if exclusive else os.O_TRUNC

    if sys.platform == "win32":
        fd = os.open(path_str, os.O_CREAT | os.O_WRONLY | create_flag, posix_mode)
        if _HAS_WIN32:
            try:
                dacl = _build_dacl(level)
                _apply_dacl(path_str, dacl)
            except Exception:
                os.close(fd)
                raise
    else:
        # O_NOFOLLOW rejects a symlink at the final path component, so a planted
        # symlink cannot redirect the truncate+write to an arbitrary file (#58).
        flags = os.O_CREAT | os.O_WRONLY | create_flag | getattr(os, "O_NOFOLLOW", 0)
        # Do not touch the process-global os.umask (it is process-wide and races
        # other threads creating files, #74). os.open()'s mode is masked by any
        # ambient umask, but the file can never be created MORE permissive than
        # posix_mode (umask only clears bits) and the unconditional fchmod below
        # pins the exact mode.
        fd = os.open(path_str, flags, posix_mode)

        # open()'s mode argument is ignored when the file already exists, so an
        # attacker-pre-created (e.g. world-readable) or foreign-owned target would
        # otherwise keep its permissions/owner while we write secrets into it.
        # Reject non-regular / foreign-owned targets and enforce the mode (#58).
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"Refusing to open non-regular secure file: {path_str}")
            if st.st_uid != os.geteuid():
                raise OSError(f"Refusing to open secure file owned by another user: {path_str}")
            os.fchmod(fd, posix_mode)
        except Exception:
            os.close(fd)
            raise

    return fd


def copy_permissions(source, target) -> None:
    """
    Copy permissions from source file/directory to target.

    On POSIX: copies stat mode bits via os.chmod().
    On Windows with pywin32: copies the DACL from source to target.
    On Windows without pywin32: copies stat mode bits (degraded).

    Args:
        source: Source file/directory path.
        target: Target file/directory path.

    Raises:
        FileNotFoundError: If source does not exist.
        OSError: If permissions cannot be copied.
    """
    source_str = str(source)
    target_str = str(target)

    if not os.path.exists(source_str):
        raise FileNotFoundError(f"Source path does not exist: {source_str}")
    if not os.path.exists(target_str):
        raise FileNotFoundError(f"Target path does not exist: {target_str}")

    if sys.platform == "win32" and _HAS_WIN32:
        # Copy the DACL from source to target
        sd = win32security.GetFileSecurity(source_str, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()

        security_info = (
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        )
        target_sd = win32security.GetFileSecurity(
            target_str, win32security.OWNER_SECURITY_INFORMATION
        )
        target_sd.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(target_str, security_info, target_sd)
    else:
        mode = stat.S_IMODE(os.stat(source_str).st_mode)
        os.chmod(target_str, mode)
