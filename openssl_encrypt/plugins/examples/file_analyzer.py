#!/usr/bin/env python3
"""
File Metadata Analyzer Plugin

This plugin demonstrates how to safely analyze file metadata before and after
encryption without accessing sensitive content. It shows best practices for
plugin development within the OpenSSL Encrypt security model.

Features:
- Analyzes file sizes, types, and timestamps
- Calculates file type distributions
- Tracks encryption overhead
- Generates safe metadata reports
- No access to file contents or sensitive data

Security Notes:
- Only accesses file metadata, never file contents
- Works with encrypted files safely
- Logs only non-sensitive information
- Follows zero-trust plugin architecture
"""

import hashlib
import json
import logging
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Dict

from ...modules.plugin_system import (
    AnalyzerPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PostProcessorPlugin,
    PreProcessorPlugin,
)

logger = logging.getLogger(__name__)


class FileMetadataAnalyzer(AnalyzerPlugin):
    """
    Analyzer plugin that examines file metadata without accessing content.
    Demonstrates safe file analysis within plugin security constraints.
    """

    def __init__(self):
        super().__init__("file_analyzer", "File Metadata Analyzer", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Analyzes file metadata (size, type, timestamps) without accessing sensitive content"

    def analyze_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """Analyze file metadata safely."""
        try:
            if not os.path.exists(file_path):
                return PluginResult.error_result(f"File not found: {file_path}")

            # Gather safe metadata
            stat = os.stat(file_path)
            analysis = {
                "file_name": os.path.basename(file_path),
                "file_size": stat.st_size,
                "created_time": stat.st_ctime,
                "modified_time": stat.st_mtime,
                "accessed_time": stat.st_atime,
                "file_extension": Path(file_path).suffix.lower(),
                "is_executable": os.access(file_path, os.X_OK),
                "permissions": oct(stat.st_mode)[-3:],
            }

            # Detect MIME type safely (doesn't read content for most types)
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                analysis["mime_type"] = mime_type
                analysis["file_category"] = self._categorize_mime_type(mime_type)

            # Calculate file age
            age_seconds = time.time() - stat.st_mtime
            analysis["age_days"] = age_seconds / (24 * 3600)

            # Determine if this looks like an encrypted file
            analysis["appears_encrypted"] = self._appears_encrypted(file_path)

            logger.info(
                f"Analyzed file metadata: {analysis['file_name']} "
                f"({analysis['file_size']} bytes, {analysis.get('file_category', 'unknown')})"
            )

            return PluginResult.success_result(
                f"Analyzed metadata for {analysis['file_name']}", {"analysis": analysis}
            )

        except PermissionError:
            return PluginResult.error_result(f"Permission denied accessing: {file_path}")
        except Exception as e:
            return PluginResult.error_result(f"Analysis error: {str(e)}")

    def _categorize_mime_type(self, mime_type: str) -> str:
        """Categorize MIME type into broad categories."""
        if mime_type.startswith("text/"):
            return "text"
        elif mime_type.startswith("image/"):
            return "image"
        elif mime_type.startswith("video/"):
            return "video"
        elif mime_type.startswith("audio/"):
            return "audio"
        elif mime_type.startswith("application/"):
            if "pdf" in mime_type:
                return "document"
            elif any(office in mime_type for office in ["word", "excel", "powerpoint", "office"]):
                return "document"
            elif "zip" in mime_type or "archive" in mime_type:
                return "archive"
            else:
                return "application"
        else:
            return "other"

    def _appears_encrypted(self, file_path: str) -> bool:
        """Check if file appears to be encrypted based on safe indicators."""
        try:
            # Check file extension
            encrypted_extensions = {".enc", ".gpg", ".aes", ".encrypted", ".crypt"}
            if Path(file_path).suffix.lower() in encrypted_extensions:
                return True

            # Check if it's one of our encrypted files by looking for base64 structure
            # This is safe as we're only checking structure, not content
            with open(file_path, "rb") as f:
                header = f.read(100)  # Read just enough to check structure

            # Our encrypted files have base64 metadata followed by ':'
            try:
                header_str = header.decode("utf-8", errors="ignore")
                if ":" in header_str and header_str.split(":")[0].replace("\n", "").replace(
                    "\r", ""
                ):
                    # Try to decode the first part as base64
                    import base64

                    first_part = header_str.split(":")[0].strip()
                    base64.b64decode(first_part + "==")  # Add padding just in case
                    return True
            except (UnicodeDecodeError, ValueError):
                pass

            return False

        except Exception:
            return False


class FilePreProcessor(PreProcessorPlugin):
    """
    Pre-processor that logs file information before encryption.
    Demonstrates safe pre-processing without accessing sensitive content.
    """

    def __init__(self):
        super().__init__("file_pre_analyzer", "File Pre-Processor", "1.0.0")

    def get_required_capabilities(self):
        return {
            PluginCapability.READ_FILES,
            PluginCapability.WRITE_LOGS,
            PluginCapability.MODIFY_METADATA,
        }

    def get_description(self):
        return "Logs safe file information before encryption and adds metadata"

    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """Process file before encryption."""
        try:
            if not os.path.exists(file_path):
                return PluginResult.error_result(f"File not found: {file_path}")

            # Use the analyzer to get file info
            analyzer = FileMetadataAnalyzer()
            analysis_result = analyzer.analyze_file(file_path, context)

            if not analysis_result.success:
                return analysis_result

            analysis = analysis_result.data.get("analysis", {})

            # Add useful metadata to context for other plugins or post-processing
            context.add_metadata("original_file_size", analysis.get("file_size", 0))
            context.add_metadata("original_file_type", analysis.get("file_category", "unknown"))
            context.add_metadata("original_file_extension", analysis.get("file_extension", ""))
            context.add_metadata("pre_encryption_timestamp", time.time())

            # Log the pre-encryption state
            logger.info(
                f"Pre-encryption analysis: {analysis.get('file_name')} "
                f"({analysis.get('file_size')} bytes, "
                f"{analysis.get('file_category', 'unknown')} type)"
            )

            return PluginResult.success_result(
                f"Pre-processed {analysis.get('file_name')}", {"original_analysis": analysis}
            )

        except Exception as e:
            return PluginResult.error_result(f"Pre-processing error: {str(e)}")


class EncryptionOverheadAnalyzer(PostProcessorPlugin):
    """
    Post-processor that analyzes encryption overhead and file changes.
    Demonstrates how to safely analyze encryption results.
    """

    def __init__(self):
        super().__init__("encryption_overhead", "Encryption Overhead Analyzer", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Analyzes encryption overhead and file size changes after encryption"

    def process_encrypted_file(
        self, encrypted_file_path: str, context: PluginSecurityContext
    ) -> PluginResult:
        """Analyze encrypted file and calculate overhead."""
        try:
            if not os.path.exists(encrypted_file_path):
                return PluginResult.error_result(f"Encrypted file not found: {encrypted_file_path}")

            encrypted_size = os.path.getsize(encrypted_file_path)
            original_size = context.metadata.get("original_file_size", 0)

            analysis = {
                "encrypted_file_name": os.path.basename(encrypted_file_path),
                "encrypted_size": encrypted_size,
                "original_size": original_size,
            }

            if original_size > 0:
                overhead = encrypted_size - original_size
                overhead_percentage = (overhead / original_size) * 100
                size_ratio = encrypted_size / original_size

                analysis.update(
                    {
                        "overhead_bytes": overhead,
                        "overhead_percentage": overhead_percentage,
                        "size_ratio": size_ratio,
                        "efficiency_rating": self._calculate_efficiency_rating(overhead_percentage),
                    }
                )

                logger.info(
                    f"Encryption overhead analysis: {analysis['encrypted_file_name']} "
                    f"- Original: {original_size} bytes, Encrypted: {encrypted_size} bytes "
                    f"({overhead_percentage:.1f}% overhead)"
                )

            # Add algorithm and timestamp info if available
            algorithm = context.metadata.get("algorithm", "unknown")
            operation = context.metadata.get("operation", "unknown")

            analysis.update(
                {"algorithm": algorithm, "operation": operation, "analysis_timestamp": time.time()}
            )

            # Check if this looks like our encrypted format
            analysis["openssl_encrypt_format"] = self._verify_format(encrypted_file_path)

            return PluginResult.success_result(
                f"Analyzed encryption overhead for {analysis['encrypted_file_name']}",
                {"overhead_analysis": analysis},
            )

        except Exception as e:
            return PluginResult.error_result(f"Overhead analysis error: {str(e)}")

    def _calculate_efficiency_rating(self, overhead_percentage: float) -> str:
        """Calculate efficiency rating based on overhead."""
        if overhead_percentage < 5:
            return "excellent"
        elif overhead_percentage < 15:
            return "good"
        elif overhead_percentage < 30:
            return "fair"
        else:
            return "high_overhead"

    def _verify_format(self, encrypted_file_path: str) -> bool:
        """Verify this is our encrypted format by checking structure."""
        try:
            with open(encrypted_file_path, "rb") as f:
                header = f.read(200)

            # Check for our format structure (metadata:data)
            header_str = header.decode("utf-8", errors="ignore")
            if ":" in header_str:
                parts = header_str.split(":", 1)
                if len(parts) == 2:
                    # Try to decode metadata part as base64
                    import base64

                    try:
                        metadata_bytes = base64.b64decode(parts[0] + "==")
                        metadata = json.loads(metadata_bytes.decode("utf-8"))
                        # Check for our format version
                        return metadata.get("format_version") in [4, 5]
                    except (ValueError, json.JSONDecodeError):
                        pass

            return False

        except Exception:
            return False
