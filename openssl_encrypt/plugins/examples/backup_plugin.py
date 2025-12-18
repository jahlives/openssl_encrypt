#!/usr/bin/env python3
"""
Backup and Restore Plugin

This plugin demonstrates how to safely create backups of files before encryption
and manage file restoration. It shows secure file handling within the plugin
system's security constraints.

Features:
- Creates timestamped backups before encryption
- Manages backup directory structure
- Provides restore capabilities
- Safe cleanup of temporary files
- Respects file permissions and metadata

Security Notes:
- Only works with unencrypted source files (pre-processing)
- Creates backups in secure locations with proper permissions
- Never accesses encrypted content
- Follows secure file handling practices
"""

import os
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from ...modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PostProcessorPlugin,
    PreProcessorPlugin,
    UtilityPlugin,
)


class FileBackupPlugin(PreProcessorPlugin):
    """
    Pre-processor plugin that creates secure backups before encryption.
    Demonstrates safe file handling and backup management.
    """

    def __init__(self):
        super().__init__("file_backup", "File Backup Plugin", "1.0.0")
        self.backup_base_dir = None

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Creates timestamped backups of files before encryption"

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize plugin with configuration."""
        try:
            # Set up backup directory
            backup_dir = config.get("backup_directory")
            if backup_dir:
                self.backup_base_dir = Path(backup_dir)
            else:
                # Use default backup location
                home_dir = Path.home()
                self.backup_base_dir = home_dir / ".openssl_encrypt_backups"

            # Create backup directory if it doesn't exist
            self.backup_base_dir.mkdir(parents=True, exist_ok=True)

            # Set secure permissions
            os.chmod(self.backup_base_dir, 0o700)  # Only owner can access

            return PluginResult.success_result(
                f"Backup plugin initialized with directory: {self.backup_base_dir}"
            )

        except Exception as e:
            return PluginResult.error_result(f"Backup plugin initialization failed: {str(e)}")

    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """Create backup of file before encryption."""
        try:
            if not os.path.exists(file_path):
                return PluginResult.error_result(f"Source file not found: {file_path}")

            # Initialize backup directory if not done
            if not self.backup_base_dir:
                self.backup_base_dir = Path.home() / ".openssl_encrypt_backups"
                self.backup_base_dir.mkdir(parents=True, exist_ok=True)
                os.chmod(self.backup_base_dir, 0o700)

            # Generate backup path with timestamp
            source_path = Path(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{source_path.stem}_{timestamp}{source_path.suffix}"

            # Create dated subdirectory
            date_dir = self.backup_base_dir / datetime.now().strftime("%Y-%m-%d")
            date_dir.mkdir(exist_ok=True)
            os.chmod(date_dir, 0o700)

            backup_path = date_dir / backup_name

            # Copy file with metadata preservation
            shutil.copy2(file_path, backup_path)

            # Ensure backup has secure permissions
            source_stat = os.stat(file_path)
            os.chmod(backup_path, source_stat.st_mode)

            # Add backup information to context
            context.add_metadata("backup_created", True)
            context.add_metadata("backup_path", str(backup_path))
            context.add_metadata("backup_timestamp", timestamp)
            context.add_metadata("original_file_path", file_path)

            file_size = os.path.getsize(file_path)
            backup_size = os.path.getsize(backup_path)

            self.logger.info(f"Created backup: {backup_name} ({backup_size} bytes)")

            return PluginResult.success_result(
                f"Created backup of {source_path.name}",
                {
                    "backup_path": str(backup_path),
                    "backup_size": backup_size,
                    "original_size": file_size,
                    "timestamp": timestamp,
                },
            )

        except PermissionError as e:
            return PluginResult.error_result(f"Permission denied creating backup: {str(e)}")
        except Exception as e:
            return PluginResult.error_result(f"Backup creation failed: {str(e)}")


class BackupVerificationPlugin(PostProcessorPlugin):
    """
    Post-processor that verifies backup integrity after encryption.
    Ensures backup process completed successfully.
    """

    def __init__(self):
        super().__init__("backup_verifier", "Backup Verification Plugin", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Verifies backup integrity after encryption completion"

    def process_encrypted_file(
        self, encrypted_file_path: str, context: PluginSecurityContext
    ) -> PluginResult:
        """Verify backup was created successfully."""
        try:
            # Check if backup was created during pre-processing
            backup_created = context.metadata.get("backup_created", False)
            if not backup_created:
                return PluginResult.success_result("No backup was requested for verification")

            backup_path = context.metadata.get("backup_path")
            if not backup_path:
                return PluginResult.error_result("Backup path not found in context")

            # Verify backup exists and is readable
            if not os.path.exists(backup_path):
                return PluginResult.error_result(f"Backup file missing: {backup_path}")

            # Get file sizes for verification
            backup_size = os.path.getsize(backup_path)
            original_size = context.metadata.get("original_file_size", 0)

            if original_size > 0 and backup_size != original_size:
                return PluginResult.error_result(
                    f"Backup size mismatch: expected {original_size}, got {backup_size}"
                )

            # Verify backup is accessible
            try:
                with open(backup_path, "rb") as f:
                    # Just try to read first few bytes to verify accessibility
                    f.read(100)
            except Exception as e:
                return PluginResult.error_result(f"Backup not readable: {str(e)}")

            self.logger.info(f"Backup verification successful: {os.path.basename(backup_path)}")

            return PluginResult.success_result(
                f"Backup verified: {os.path.basename(backup_path)}",
                {
                    "backup_verified": True,
                    "backup_size": backup_size,
                    "verification_timestamp": time.time(),
                },
            )

        except Exception as e:
            return PluginResult.error_result(f"Backup verification failed: {str(e)}")


class BackupUtilityPlugin(UtilityPlugin):
    """
    Utility plugin providing backup management functions.
    Demonstrates utility plugin capabilities for backup operations.
    """

    def __init__(self):
        super().__init__("backup_utils", "Backup Utility Plugin", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Provides utility functions for backup management and restoration"

    def get_utility_functions(self) -> Dict[str, callable]:
        """Return available utility functions."""
        return {
            "list_backups": self.list_backups,
            "restore_backup": self.restore_backup,
            "cleanup_old_backups": self.cleanup_old_backups,
            "get_backup_info": self.get_backup_info,
        }

    def list_backups(self, backup_dir: Optional[str] = None) -> Dict[str, Any]:
        """List available backups."""
        try:
            if not backup_dir:
                backup_dir = Path.home() / ".openssl_encrypt_backups"
            else:
                backup_dir = Path(backup_dir)

            if not backup_dir.exists():
                return {"backups": [], "total_count": 0}

            backups = []
            total_size = 0

            # Walk through backup directory structure
            for date_dir in backup_dir.iterdir():
                if date_dir.is_dir():
                    for backup_file in date_dir.iterdir():
                        if backup_file.is_file():
                            stat = backup_file.stat()
                            backups.append(
                                {
                                    "name": backup_file.name,
                                    "path": str(backup_file),
                                    "date": date_dir.name,
                                    "size": stat.st_size,
                                    "created": stat.st_ctime,
                                    "modified": stat.st_mtime,
                                }
                            )
                            total_size += stat.st_size

            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x["created"], reverse=True)

            return {
                "backups": backups,
                "total_count": len(backups),
                "total_size": total_size,
                "backup_directory": str(backup_dir),
            }

        except Exception as e:
            return {"error": f"Failed to list backups: {str(e)}"}

    def restore_backup(self, backup_path: str, restore_path: str) -> Dict[str, Any]:
        """Restore a backup to specified location."""
        try:
            if not os.path.exists(backup_path):
                return {"success": False, "error": f"Backup not found: {backup_path}"}

            # Check if restore path already exists
            if os.path.exists(restore_path):
                return {"success": False, "error": f"Restore target already exists: {restore_path}"}

            # Copy backup to restore location
            shutil.copy2(backup_path, restore_path)

            # Verify restoration
            backup_size = os.path.getsize(backup_path)
            restored_size = os.path.getsize(restore_path)

            if backup_size != restored_size:
                os.remove(restore_path)  # Clean up partial restore
                return {
                    "success": False,
                    "error": f"Size mismatch during restore: {backup_size} != {restored_size}",
                }

            return {
                "success": True,
                "backup_path": backup_path,
                "restore_path": restore_path,
                "size": restored_size,
                "restore_timestamp": time.time(),
            }

        except Exception as e:
            return {"success": False, "error": f"Restore failed: {str(e)}"}

    def cleanup_old_backups(
        self, backup_dir: Optional[str] = None, days_to_keep: int = 30
    ) -> Dict[str, Any]:
        """Clean up old backups beyond specified days."""
        try:
            if not backup_dir:
                backup_dir = Path.home() / ".openssl_encrypt_backups"
            else:
                backup_dir = Path(backup_dir)

            if not backup_dir.exists():
                return {"cleaned": 0, "size_freed": 0, "error": "Backup directory not found"}

            cutoff_time = time.time() - (days_to_keep * 24 * 3600)
            cleaned_count = 0
            size_freed = 0

            for date_dir in backup_dir.iterdir():
                if date_dir.is_dir():
                    # Check if entire date directory is old
                    try:
                        dir_date = datetime.strptime(date_dir.name, "%Y-%m-%d")
                        if dir_date.timestamp() < cutoff_time:
                            # Remove entire date directory
                            for backup_file in date_dir.iterdir():
                                if backup_file.is_file():
                                    size_freed += backup_file.stat().st_size
                                    cleaned_count += 1
                            shutil.rmtree(date_dir)
                        else:
                            # Check individual files in recent directories
                            for backup_file in date_dir.iterdir():
                                if backup_file.is_file():
                                    if backup_file.stat().st_ctime < cutoff_time:
                                        size_freed += backup_file.stat().st_size
                                        backup_file.unlink()
                                        cleaned_count += 1
                    except ValueError:
                        # Skip directories that don't match date format
                        continue

            return {
                "cleaned": cleaned_count,
                "size_freed": size_freed,
                "days_kept": days_to_keep,
                "cleanup_timestamp": time.time(),
            }

        except Exception as e:
            return {"error": f"Cleanup failed: {str(e)}"}

    def get_backup_info(self, backup_path: str) -> Dict[str, Any]:
        """Get detailed information about a specific backup."""
        try:
            if not os.path.exists(backup_path):
                return {"error": f"Backup not found: {backup_path}"}

            backup_file = Path(backup_path)
            stat = backup_file.stat()

            # Try to extract timestamp from filename
            timestamp_match = None
            name_parts = backup_file.stem.split("_")
            if len(name_parts) >= 2:
                potential_timestamp = name_parts[-1]
                try:
                    timestamp_match = datetime.strptime(potential_timestamp, "%Y%m%d_%H%M%S")
                except ValueError:
                    pass

            info = {
                "name": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
                "permissions": oct(stat.st_mode)[-3:],
                "is_readable": os.access(backup_path, os.R_OK),
            }

            if timestamp_match:
                info["backup_timestamp"] = timestamp_match.isoformat()

            # Try to determine original filename
            name_without_timestamp = (
                "_".join(name_parts[:-1]) if len(name_parts) > 1 else backup_file.stem
            )
            info["original_name"] = name_without_timestamp + backup_file.suffix

            return info

        except Exception as e:
            return {"error": f"Failed to get backup info: {str(e)}"}
