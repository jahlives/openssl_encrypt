#!/usr/bin/env python3
"""
Integrity verification module for encrypted files.

Performs structural checks on encrypted files without requiring a password.
Validates file format, metadata schema, base64 encoding, and streaming
structure (for format v12).
"""

import base64
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .crypt_errors import ValidationError
from .crypt_utils import eprint


@dataclass
class VerificationResult:
    """Result of a single verification check."""

    check_name: str
    passed: bool
    message: str
    details: Optional[str] = None


class FileVerifier:
    """Performs structural verification checks on encrypted files.

    Checks file readability, base64 metadata encoding, JSON validity,
    metadata schema compliance, format version, and streaming structure.
    """

    # Required top-level metadata fields
    REQUIRED_METADATA_FIELDS = {"format_version", "encryption"}

    # Required fields within the encryption sub-object
    REQUIRED_ENCRYPTION_FIELDS = {"algorithm"}

    # Supported format version range
    MIN_FORMAT_VERSION = 3
    # Keep in sync with crypt_core.LATEST_STABLE_FORMAT_VERSION (imported
    # lazily below would create a cycle; the fixture corpus + verify tests
    # pin this value).
    MAX_FORMAT_VERSION = 14

    # Streaming constants
    STREAMING_MAGIC = b"OESC"
    STREAMING_PAYLOAD_VERSION = 1

    def __init__(self, input_file: str):
        """Initialize verifier with the file to check.

        Args:
            input_file: Path to the encrypted file.
        """
        self.input_file = input_file
        self.results: List[VerificationResult] = []
        self._file_content: Optional[bytes] = None
        self._metadata_b64: Optional[bytes] = None
        self._metadata_json: Optional[str] = None
        self._metadata: Optional[dict] = None
        self._encrypted_data: Optional[bytes] = None

    def _add_result(
        self,
        check_name: str,
        passed: bool,
        message: str,
        details: Optional[str] = None,
    ) -> bool:
        """Record a check result and return its pass/fail status."""
        self.results.append(
            VerificationResult(
                check_name=check_name,
                passed=passed,
                message=message,
                details=details,
            )
        )
        return passed

    def _check_file_readable(self) -> bool:
        """Check that the file exists and is readable."""
        if not os.path.exists(self.input_file):
            return self._add_result(
                "file_readable",
                False,
                "File does not exist",
                details=f"Path: {self.input_file}",
            )

        if not os.path.isfile(self.input_file):
            return self._add_result(
                "file_readable",
                False,
                "Path is not a regular file",
                details=f"Path: {self.input_file}",
            )

        if not os.access(self.input_file, os.R_OK):
            return self._add_result(
                "file_readable",
                False,
                "File is not readable",
                details=f"Path: {self.input_file}",
            )

        file_size = os.path.getsize(self.input_file)
        if file_size == 0:
            return self._add_result(
                "file_readable",
                False,
                "File is empty",
                details=f"Size: {file_size} bytes",
            )

        try:
            with open(self.input_file, "rb") as f:
                self._file_content = f.read()
            # Transparently peel a hidden ("whitened") file to legacy-equivalent
            # bytes so the structural checks below work unchanged (keyless).
            from .hidden_header import to_legacy_bytes

            self._file_content = to_legacy_bytes(self._file_content)
        except OSError as e:
            return self._add_result(
                "file_readable",
                False,
                "Failed to read file",
                details=str(e),
            )

        return self._add_result(
            "file_readable",
            True,
            "File is readable",
            details=f"Size: {file_size} bytes",
        )

    def _check_base64_metadata(self) -> bool:
        """Check that file contains colon-separated base64 metadata."""
        if self._file_content is None:
            return self._add_result(
                "base64_metadata",
                False,
                "No file content available",
            )

        if b":" not in self._file_content:
            return self._add_result(
                "base64_metadata",
                False,
                "File does not contain metadata separator ':'",
                details="Expected format: base64(metadata):encrypted_data",
            )

        parts = self._file_content.split(b":", 1)
        self._metadata_b64 = parts[0]
        self._encrypted_data = parts[1]

        try:
            decoded = base64.b64decode(self._metadata_b64)
            self._metadata_json = decoded.decode("utf-8")
        except Exception as e:
            return self._add_result(
                "base64_metadata",
                False,
                "Failed to decode base64 metadata",
                details=str(e),
            )

        return self._add_result(
            "base64_metadata",
            True,
            "Base64 metadata decoded successfully",
            details=f"Metadata size: {len(self._metadata_b64)} bytes (encoded)",
        )

    def _check_metadata_json(self) -> bool:
        """Check that decoded metadata is valid JSON."""
        if self._metadata_json is None:
            return self._add_result(
                "metadata_json",
                False,
                "No decoded metadata available",
            )

        try:
            self._metadata = json.loads(self._metadata_json)
        except json.JSONDecodeError as e:
            return self._add_result(
                "metadata_json",
                False,
                "Metadata is not valid JSON",
                details=str(e),
            )

        if not isinstance(self._metadata, dict):
            return self._add_result(
                "metadata_json",
                False,
                "Metadata JSON is not a dictionary",
                details=f"Type: {type(self._metadata).__name__}",
            )

        return self._add_result(
            "metadata_json",
            True,
            "Metadata is valid JSON",
            details=f"Keys: {sorted(self._metadata.keys())}",
        )

    def _check_metadata_schema(self) -> bool:
        """Check that metadata contains required fields."""
        if self._metadata is None:
            return self._add_result(
                "metadata_schema",
                False,
                "No parsed metadata available",
            )

        format_version = self._metadata.get("format_version")

        # Older formats (< 4) use different schema
        if format_version is not None and isinstance(format_version, int) and format_version < 4:
            # Minimal check for old formats
            if "format_version" not in self._metadata:
                return self._add_result(
                    "metadata_schema",
                    False,
                    "Missing required field: format_version",
                )
            return self._add_result(
                "metadata_schema",
                True,
                "Metadata schema valid (legacy format)",
                details=f"format_version: {format_version}",
            )

        # Check required fields for modern formats
        missing_fields = self.REQUIRED_METADATA_FIELDS - set(self._metadata.keys())
        if missing_fields:
            return self._add_result(
                "metadata_schema",
                False,
                f"Missing required metadata fields: {sorted(missing_fields)}",
            )

        # Check encryption sub-object
        encryption = self._metadata.get("encryption", {})
        if not isinstance(encryption, dict):
            return self._add_result(
                "metadata_schema",
                False,
                "encryption field is not a dictionary",
            )

        missing_enc_fields = self.REQUIRED_ENCRYPTION_FIELDS - set(encryption.keys())
        if missing_enc_fields:
            return self._add_result(
                "metadata_schema",
                False,
                f"Missing required encryption fields: {sorted(missing_enc_fields)}",
            )

        return self._add_result(
            "metadata_schema",
            True,
            "Metadata schema is valid",
            details=f"Algorithm: {encryption.get('algorithm', 'unknown')}",
        )

    def _check_format_version(self) -> bool:
        """Check that format version is in supported range."""
        if self._metadata is None:
            return self._add_result(
                "format_version",
                False,
                "No parsed metadata available",
            )

        version = self._metadata.get("format_version")
        if version is None:
            return self._add_result(
                "format_version",
                False,
                "No format_version in metadata",
            )

        if not isinstance(version, int):
            return self._add_result(
                "format_version",
                False,
                f"format_version is not an integer: {type(version).__name__}",
            )

        if version < self.MIN_FORMAT_VERSION or version > self.MAX_FORMAT_VERSION:
            return self._add_result(
                "format_version",
                False,
                f"Unsupported format version: {version}",
                details=f"Supported range: {self.MIN_FORMAT_VERSION}-{self.MAX_FORMAT_VERSION}",
            )

        return self._add_result(
            "format_version",
            True,
            f"Format version {version} is supported",
        )

    def _check_streaming_structure(self) -> bool:
        """Check streaming structure for format v12 files."""
        if self._metadata is None or self._encrypted_data is None:
            return self._add_result(
                "streaming_structure",
                False,
                "No metadata or encrypted data available",
            )

        version = self._metadata.get("format_version")
        is_streaming_meta = bool(self._metadata.get("streaming", {}).get("enabled", False))
        if version not in (12, 14) or (version == 14 and not is_streaming_meta):
            # Not a streaming file — skip this check (v12 is always
            # streaming; v14 streams only when the streaming block is set)
            return self._add_result(
                "streaming_structure",
                True,
                "Not a streaming format — skipped",
            )

        data = self._encrypted_data

        # Check OESC magic
        if len(data) < 4 or data[:4] != self.STREAMING_MAGIC:
            return self._add_result(
                "streaming_structure",
                False,
                "Missing OESC magic bytes",
                details=f"First 4 bytes: {data[:4].hex() if len(data) >= 4 else 'too short'}",
            )

        # Check payload version
        if len(data) < 8:
            return self._add_result(
                "streaming_structure",
                False,
                "File too short for payload version",
            )

        payload_version = struct.unpack("<I", data[4:8])[0]
        if payload_version != self.STREAMING_PAYLOAD_VERSION:
            return self._add_result(
                "streaming_structure",
                False,
                f"Unsupported payload version: {payload_version}",
                details=f"Expected: {self.STREAMING_PAYLOAD_VERSION}",
            )

        # Parse chunks to validate structure
        offset = 8
        chunk_count = 0
        issues = []

        while offset < len(data) - 36:  # Leave room for trailer (u32le + 32B HMAC)
            # Each chunk: [chunk_index: u32le] [ciphertext_len: u32le] [ciphertext]
            if offset + 8 > len(data):
                issues.append(f"Truncated chunk header at offset {offset}")
                break

            chunk_index = struct.unpack("<I", data[offset : offset + 4])[0]
            ciphertext_len = struct.unpack("<I", data[offset + 4 : offset + 8])[0]

            if chunk_index != chunk_count:
                issues.append(
                    f"Non-sequential chunk index: expected {chunk_count}, got {chunk_index}"
                )

            # Sanity check on chunk size (max 16 MB)
            max_chunk_size = 16 * 1024 * 1024
            if ciphertext_len > max_chunk_size:
                issues.append(
                    f"Chunk {chunk_index} size {ciphertext_len} exceeds maximum {max_chunk_size}"
                )
                break

            if offset + 8 + ciphertext_len > len(data):
                issues.append(
                    f"Truncated chunk {chunk_index}: need {ciphertext_len} bytes, "
                    f"only {len(data) - offset - 8} available"
                )
                break

            offset += 8 + ciphertext_len
            chunk_count += 1

        # Check trailer
        if offset + 36 <= len(data):
            trailer_chunk_count = struct.unpack("<I", data[offset : offset + 4])[0]
            if trailer_chunk_count != chunk_count:
                issues.append(
                    f"Trailer chunk count mismatch: header says {chunk_count}, "
                    f"trailer says {trailer_chunk_count}"
                )
            # HMAC commitment is next 32 bytes — we can't verify without the key
            offset += 36
        elif chunk_count > 0:
            issues.append("Missing or truncated trailer")

        if issues:
            return self._add_result(
                "streaming_structure",
                False,
                "Streaming structure issues detected",
                details="; ".join(issues),
            )

        return self._add_result(
            "streaming_structure",
            True,
            f"Streaming structure valid ({chunk_count} chunks)",
        )

    def _check_encrypted_data_present(self) -> bool:
        """Check that encrypted data payload is non-empty."""
        if self._encrypted_data is None:
            return self._add_result(
                "encrypted_data",
                False,
                "No encrypted data available",
            )

        if len(self._encrypted_data) == 0:
            return self._add_result(
                "encrypted_data",
                False,
                "Encrypted data payload is empty",
            )

        return self._add_result(
            "encrypted_data",
            True,
            "Encrypted data payload present",
            details=f"Size: {len(self._encrypted_data)} bytes",
        )

    def run_all_checks(self) -> Tuple[bool, List[VerificationResult]]:
        """Run all verification checks in order.

        Returns:
            Tuple of (all_passed, results_list).
        """
        self.results = []

        # Run checks in order — each depends on the previous
        if not self._check_file_readable():
            return False, self.results

        if not self._check_base64_metadata():
            return False, self.results

        if not self._check_metadata_json():
            return False, self.results

        # These checks can all run
        self._check_metadata_schema()
        self._check_format_version()
        self._check_encrypted_data_present()
        self._check_streaming_structure()

        all_passed = all(r.passed for r in self.results)
        return all_passed, self.results


def verify_file_integrity(
    input_file: str,
    json_output: bool = False,
    verbose: bool = False,
) -> Tuple[bool, List[VerificationResult]]:
    """Verify the structural integrity of an encrypted file.

    Performs checks without requiring a password:
    - File readability
    - Base64 metadata encoding
    - JSON metadata validity
    - Required metadata fields
    - Format version range
    - Streaming structure (v12)

    Args:
        input_file: Path to the encrypted file.
        json_output: If True, print results as JSON.
        verbose: If True, include detailed information.

    Returns:
        Tuple of (all_passed, results_list).
    """
    verifier = FileVerifier(input_file)
    all_passed, results = verifier.run_all_checks()

    if json_output:
        output = {
            "file": input_file,
            "valid": all_passed,
            "checks": [],
        }
        for r in results:
            check_entry = {
                "check": r.check_name,
                "passed": r.passed,
                "message": r.message,
            }
            if verbose and r.details:
                check_entry["details"] = r.details
            output["checks"].append(check_entry)
        print(json.dumps(output, indent=2))
    else:
        status = "PASS" if all_passed else "FAIL"
        eprint(f"Verification: {status}")
        eprint(f"File: {input_file}")
        eprint()
        for r in results:
            icon = "[+]" if r.passed else "[-]"
            eprint(f"  {icon} {r.check_name}: {r.message}")
            if verbose and r.details:
                eprint(f"      {r.details}")

    return all_passed, results
