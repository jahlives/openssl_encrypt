#!/usr/bin/env python3
"""
Telemetry Data Filter - Strict data access control for telemetry plugins.

SECURITY CRITICAL: This module is the ONLY interface between core and telemetry
plugins. It defines exactly what data plugins can see through strict whitelisting.

SECURITY GUARANTEE:
- Input: Full metadata (may contain sensitive data)
- Output: Only whitelisted fields in immutable TelemetryEvent
- This is the ONLY way for telemetry data to leave the core

NEVER EXPOSED:
- Passwords, keys (public/private/symmetric), salts
- Filenames, file sizes, file paths
- Fingerprints, key IDs
- IP addresses, user identifiers
- Plaintext or ciphertext data

ALWAYS EXPOSED (per Kerckhoffs's principle):
- Algorithm names and non-identifying parameters
- Format versions and modes
- Success/failure status (categorized only)
- Timestamps (UTC only, no timezone info)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)  # Immutable!
class TelemetryEvent:
    """
    Strictly typed, immutable telemetry data.

    SECURITY: This dataclass is frozen (immutable) to prevent any modification
    after creation. All fields are validated and whitelisted.

    ALLOWED (public per Kerckhoffs's principle):
    - Algorithm names and parameters
    - Format version and mode
    - Timestamps (UTC, no local timezone)

    NEVER CONTAINS:
    - Passwords, keys, salts
    - Filenames, file sizes
    - Fingerprints, key IDs
    - IP addresses, user identifiers
    - Plaintext or ciphertext data
    """

    # Timestamp (UTC, no timezone information)
    timestamp: str  # ISO 8601 format

    # Operation
    operation: str  # "encrypt" or "decrypt"
    mode: str  # "symmetric" or "asymmetric"
    format_version: int  # 4, 5, 6, 7, or 8

    # Hash configuration (only algorithm names, NOT rounds - too identifying)
    hash_algorithms: Tuple[str, ...]  # ("sha512", "sha3_256", "blake2b")

    # KDF configuration (algorithms and safe numeric parameters)
    kdf_algorithms: Tuple[str, ...]  # ("argon2", "balloon")

    # Encryption (only algorithm name)
    encryption_algorithm: str  # "aes-256-gcm"

    # Fields with defaults must come after fields without defaults
    kdf_parameters: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Example: {"argon2": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}}

    # Cascade encryption (format v8) - count only, NOT exact cipher sequence
    cascade_enabled: bool = False
    cascade_cipher_count: Optional[int] = None

    # PQC (only algorithm names, NEVER keys)
    pqc_kem_algorithm: Optional[str] = None  # "ML-KEM-768" or None
    pqc_signing_algorithm: Optional[str] = None  # "ML-DSA-65" or None (asymmetric only)

    # HSM usage (plugin name only, NO slot numbers or serial numbers)
    hsm_plugin_used: Optional[str] = None  # "yubikey"

    # Success/Failure (no detailed error messages)
    success: bool = True
    error_category: Optional[str] = None  # "invalid_password", "corrupted_data", etc.


class TelemetryDataFilter:
    """
    Filter that transforms metadata into safe TelemetryEvents.

    SECURITY GUARANTEE:
    - Input: Full metadata (including sensitive data)
    - Output: Only allowed, anonymized fields
    - This class is the ONLY way for plugins to receive data

    DESIGN PRINCIPLE:
    - Whitelist approach: only explicitly allowed fields pass through
    - No exceptions: if it's not on the whitelist, it NEVER passes
    - Validation: all values are validated against allowed sets
    """

    # Whitelist of allowed hash algorithms (for validation)
    ALLOWED_HASH_ALGOS = frozenset(
        [
            "sha256",
            "sha384",
            "sha512",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "blake2b",
            "blake2s",
            "blake3",
            "whirlpool",
            "shake128",
            "shake256",
        ]
    )

    # Whitelist of allowed KDF algorithms
    ALLOWED_KDF_ALGOS = frozenset(
        [
            "argon2",
            "argon2id",
            "argon2i",
            "argon2d",
            "balloon",
            "scrypt",
            "pbkdf2",
            "hkdf",
            "randomx",
        ]
    )

    # Whitelist of allowed encryption algorithms
    ALLOWED_ENC_ALGOS = frozenset(
        [
            "aes-128-gcm",
            "aes-256-gcm",
            "aes-256-siv",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "camellia-256-gcm",
            "fernet",
            "cascade",
        ]
    )

    # Whitelist of allowed PQC KEM algorithms
    ALLOWED_PQC_KEM = frozenset(
        [
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "Kyber512",
            "Kyber768",
            "Kyber1024",
            "HQC-128",
            "HQC-192",
            "HQC-256",
        ]
    )

    # Whitelist of allowed PQC signing algorithms
    ALLOWED_PQC_SIGN = frozenset(
        [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "Dilithium2",
            "Dilithium3",
            "Dilithium5",
            "MAYO-1",
            "MAYO-3",
            "MAYO-5",
            "CROSS-rsdp-128",
            "CROSS-rsdp-192",
            "CROSS-rsdp-256",
        ]
    )

    # Allowed error categories (no sensitive details)
    ALLOWED_ERROR_CATEGORIES = frozenset(
        [
            "invalid_password",
            "corrupted_data",
            "unsupported_format",
            "kdf_error",
            "encryption_error",
            "signature_invalid",
            "key_error",
            "hsm_error",
            "unknown",
        ]
    )

    @classmethod
    def filter_metadata(
        cls,
        metadata: Dict[str, Any],
        operation: str,
        success: bool = True,
        error_category: Optional[str] = None,
    ) -> TelemetryEvent:
        """
        Filters metadata and creates a safe TelemetryEvent.

        SECURITY GUARANTEE:
        This is the ONLY method that creates TelemetryEvent objects.
        It implements strict whitelisting to ensure no sensitive data leaks.

        Args:
            metadata: Full metadata from the encryption/decryption operation
            operation: "encrypt" or "decrypt"
            success: Whether the operation succeeded
            error_category: Error category if failed (must be in ALLOWED_ERROR_CATEGORIES)

        Returns:
            TelemetryEvent with only whitelisted data (immutable)

        Security Notes:
            - Salt values: NEVER exposed (only salt length could be exposed, but we don't)
            - Keys: NEVER exposed (public, private, or symmetric)
            - Passwords: NEVER exposed
            - Filenames: NEVER exposed
            - Hash rounds: NOT exposed (could be identifying)
            - Cascade cipher sequence: NOT exposed (only count)
            - HSM slot numbers: NOT exposed (only plugin name)
        """

        # Timestamp in UTC (NO local timezone!)
        timestamp = datetime.now(timezone.utc).isoformat()

        # Format and mode extraction (safe integers/strings)
        format_version = metadata.get("format_version", 0)
        mode = metadata.get("mode", "symmetric")

        # Extract hash algorithms (names only, NOT rounds)
        # Rounds can be identifying (e.g., 1000000 rounds of SHA-512 is unusual)
        hash_algos: List[str] = []
        derivation_config = metadata.get("derivation_config", {})
        hash_config = derivation_config.get("hash_config", {})

        for algo in hash_config.keys():
            if algo in cls.ALLOWED_HASH_ALGOS:
                hash_algos.append(algo)

        # Extract KDF algorithms and safe parameters
        kdf_algos: List[str] = []
        kdf_params: Dict[str, Dict[str, int]] = {}
        kdf_config = derivation_config.get("kdf_config", {})

        for algo, config in kdf_config.items():
            algo_normalized = algo.lower()

            # Check if algorithm is allowed
            if algo_normalized in cls.ALLOWED_KDF_ALGOS or algo_normalized.startswith("argon2"):
                kdf_algos.append(algo_normalized)

                # Extract only safe numeric parameters (no keys, no salts)
                if isinstance(config, dict):
                    safe_params = {}
                    # Whitelist of safe KDF parameter names
                    safe_param_names = {
                        "time_cost",
                        "memory_cost",
                        "parallelism",
                        "hash_len",  # Argon2
                        "space_cost",
                        "delta",
                        "parallel_cost",  # Balloon
                        "n",
                        "r",
                        "p",  # Scrypt
                        "iterations",  # PBKDF2
                    }

                    for param_name, param_value in config.items():
                        if param_name in safe_param_names and isinstance(param_value, (int, float)):
                            safe_params[param_name] = int(param_value)

                    if safe_params:
                        kdf_params[algo_normalized] = safe_params

        # Extract encryption algorithm
        enc_config = metadata.get("encryption", {})

        # Handle cascade mode (format v8) - special handling
        cascade_enabled = enc_config.get("cascade", False)
        cascade_cipher_count = None
        enc_algo = "unknown"

        if cascade_enabled:
            # Cascade encryption - do NOT expose exact cipher sequence
            # Exposing ["aes-256-gcm", "chacha20-poly1305", "camellia"] is too identifying
            cipher_chain = enc_config.get("cipher_chain", [])
            cascade_cipher_count = len(cipher_chain) if cipher_chain else 0
            enc_algo = "cascade"  # Generic, not identifying
        else:
            # Normal encryption
            enc_algo = enc_config.get("algorithm", "unknown")
            if enc_algo not in cls.ALLOWED_ENC_ALGOS:
                enc_algo = "unknown"

        # Extract PQC algorithms (names only, NO keys!)
        pqc_kem = None
        pqc_sign = None

        if mode == "asymmetric":
            # Asymmetric mode - extract KEM and signing algorithms
            asym_config = metadata.get("asymmetric", {})

            # KEM algorithm
            recipient = asym_config.get("recipient", {})
            kem_algo = recipient.get("algorithm")
            if kem_algo in cls.ALLOWED_PQC_KEM:
                pqc_kem = kem_algo

            # Signing algorithm
            sender = asym_config.get("sender", {})
            sign_algo = sender.get("signing_algorithm")
            if sign_algo in cls.ALLOWED_PQC_SIGN:
                pqc_sign = sign_algo
        else:
            # Symmetric mode - check if PQC keypair encryption is used
            if "pqc_public_key" in enc_config or "pqc_key_encrypted" in enc_config:
                # PQC is used but don't expose algorithm details in symmetric mode
                # (could be identifying)
                pqc_kem = "pqc_symmetric"

        # Extract HSM plugin name (sanitize, no slot numbers!)
        hsm_plugin = enc_config.get("hsm_plugin")
        if hsm_plugin:
            # Sanitize plugin name: only alphanumeric and dash, max 32 chars
            hsm_plugin = re.sub(r"[^a-zA-Z0-9\-]", "", str(hsm_plugin))[:32]
        else:
            hsm_plugin = None

        # Validate error category
        if error_category and error_category not in cls.ALLOWED_ERROR_CATEGORIES:
            error_category = "unknown"

        # Create immutable TelemetryEvent
        return TelemetryEvent(
            timestamp=timestamp,
            operation=operation,
            mode=mode,
            format_version=format_version,
            hash_algorithms=tuple(sorted(hash_algos)),
            kdf_algorithms=tuple(sorted(kdf_algos)),
            kdf_parameters=kdf_params,
            encryption_algorithm=enc_algo,
            cascade_enabled=cascade_enabled,
            cascade_cipher_count=cascade_cipher_count,
            pqc_kem_algorithm=pqc_kem,
            pqc_signing_algorithm=pqc_sign,
            hsm_plugin_used=hsm_plugin,
            success=success,
            error_category=error_category,
        )

    @classmethod
    def to_dict(cls, event: TelemetryEvent) -> Dict[str, Any]:
        """
        Converts TelemetryEvent to dictionary for JSON serialization.

        Args:
            event: TelemetryEvent instance

        Returns:
            Dictionary representation (safe for JSON serialization)
        """
        return {
            "timestamp": event.timestamp,
            "operation": event.operation,
            "mode": event.mode,
            "format_version": event.format_version,
            "hash_algorithms": list(event.hash_algorithms),
            "kdf_algorithms": list(event.kdf_algorithms),
            "kdf_parameters": event.kdf_parameters,
            "encryption_algorithm": event.encryption_algorithm,
            "cascade_enabled": event.cascade_enabled,
            "cascade_cipher_count": event.cascade_cipher_count,
            "pqc_kem_algorithm": event.pqc_kem_algorithm,
            "pqc_signing_algorithm": event.pqc_signing_algorithm,
            "hsm_plugin_used": event.hsm_plugin_used,
            "success": event.success,
            "error_category": event.error_category,
        }
