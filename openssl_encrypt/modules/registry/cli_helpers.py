#!/usr/bin/env python3
"""
CLI Helper Utilities for Registry Integration.

Provides helper functions to integrate the algorithm registries with
the existing CLI and config wizard infrastructure.

All code in English as per project requirements.
"""

from typing import Dict, List, Tuple

from .cipher_registry import CipherRegistry
from .hash_registry import HashRegistry
from .kdf_registry import KDFRegistry
from .kem_registry import KEMRegistry
from .signature_registry import SignatureRegistry


def get_available_ciphers() -> List[str]:
    """
    Get list of available cipher algorithm names.

    Returns:
        List of cipher names from the registry
    """
    registry = CipherRegistry.default()
    return registry.list_names(include_aliases=False)


def get_available_hashes() -> List[str]:
    """
    Get list of available hash algorithm names.

    Returns:
        List of hash names from the registry
    """
    registry = HashRegistry.default()
    return registry.list_names(include_aliases=False)


def get_available_kdfs() -> List[str]:
    """
    Get list of available KDF algorithm names.

    Returns:
        List of KDF names from the registry
    """
    registry = KDFRegistry.default()
    return registry.list_names(include_aliases=False)


def get_available_kems() -> List[str]:
    """
    Get list of available KEM algorithm names.

    Returns:
        List of KEM names from the registry
    """
    registry = KEMRegistry.default()
    return registry.list_names(include_aliases=False)


def get_available_signatures() -> List[str]:
    """
    Get list of available signature algorithm names.

    Returns:
        List of signature names from the registry
    """
    registry = SignatureRegistry.default()
    return registry.list_names(include_aliases=False)


def get_cipher_info_dict() -> Dict[str, Dict[str, any]]:
    """
    Get cipher information as dictionary for CLI display.

    Returns:
        Dictionary mapping cipher name to info dict with fields:
        - display_name: Human-readable name
        - description: Algorithm description
        - security_level: Security level classification
        - key_size: Key size in bytes
        - available: Whether algorithm is available on this system
    """
    registry = CipherRegistry.default()
    result = {}

    for name, (info, is_available) in registry.list_all().items():
        result[name] = {
            "display_name": info.display_name,
            "description": info.description,
            "security_level": info.security_level.name,
            "key_size": info.key_size,
            "nonce_size": info.nonce_size,
            "tag_size": info.tag_size,
            "available": is_available,
        }

    return result


def get_kdf_info_dict() -> Dict[str, Dict[str, any]]:
    """
    Get KDF information as dictionary for CLI display.

    Returns:
        Dictionary mapping KDF name to info dict
    """
    registry = KDFRegistry.default()
    result = {}

    for name, (info, is_available) in registry.list_all().items():
        result[name] = {
            "display_name": info.display_name,
            "description": info.description,
            "security_level": info.security_level.name,
            "available": is_available,
        }

    return result


def format_algorithm_help(category: str) -> str:
    """
    Format algorithm help text for CLI display.

    Args:
        category: Algorithm category ("cipher", "hash", "kdf", "kem", "signature")

    Returns:
        Formatted help text string
    """
    if category == "cipher":
        registry = CipherRegistry.default()
        title = "Available Ciphers"
    elif category == "hash":
        registry = HashRegistry.default()
        title = "Available Hash Functions"
    elif category == "kdf":
        registry = KDFRegistry.default()
        title = "Available Key Derivation Functions"
    elif category == "kem":
        registry = KEMRegistry.default()
        title = "Available KEMs (Post-Quantum)"
    elif category == "signature":
        registry = SignatureRegistry.default()
        title = "Available Signatures (Post-Quantum)"
    else:
        return f"Unknown category: {category}"

    lines = [f"\n{title}:", "=" * (len(title) + 1), ""]

    for name, (info, is_available) in registry.list_all().items():
        status = "✓" if is_available else "✗"
        security = info.security_level.name.lower()

        # Format line
        line = f"  {status} {name:25s} - {info.description}"

        # Add security level indicator
        if info.security_level.name == "LEGACY":
            line += " [LEGACY]"
        elif info.security_level.name == "PARANOID":
            line += " [PARANOID]"

        # Add unavailability note
        if not is_available:
            line += " (requires additional package)"

        lines.append(line)

    return "\n".join(lines)


def get_recommended_cipher() -> str:
    """
    Get recommended cipher algorithm name.

    Returns:
        Name of recommended cipher (aes-256-gcm)
    """
    return "aes-256-gcm"


def get_recommended_hash() -> str:
    """
    Get recommended hash algorithm name.

    Returns:
        Name of recommended hash (sha256)
    """
    return "sha256"


def get_recommended_kdf() -> str:
    """
    Get recommended KDF algorithm name.

    Returns:
        Name of recommended KDF (argon2id)
    """
    return "argon2id"


def get_recommended_kem() -> str:
    """
    Get recommended KEM algorithm name.

    Returns:
        Name of recommended KEM (ml-kem-768)
    """
    return "ml-kem-768"


def get_recommended_signature() -> str:
    """
    Get recommended signature algorithm name.

    Returns:
        Name of recommended signature (ml-dsa-65)
    """
    return "ml-dsa-65"


def validate_algorithm_name(name: str, category: str) -> Tuple[bool, str]:
    """
    Validate that an algorithm name exists and is available.

    Args:
        name: Algorithm name to validate
        category: Category ("cipher", "hash", "kdf", "kem", "signature")

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if algorithm exists and is available
        - error_message: Empty string if valid, error description if invalid
    """
    if category == "cipher":
        registry = CipherRegistry.default()
    elif category == "hash":
        registry = HashRegistry.default()
    elif category == "kdf":
        registry = KDFRegistry.default()
    elif category == "kem":
        registry = KEMRegistry.default()
    elif category == "signature":
        registry = SignatureRegistry.default()
    else:
        return False, f"Unknown category: {category}"

    # Check if algorithm exists
    if not registry.exists(name):
        available = registry.list_names()
        return False, f"Algorithm '{name}' not found. Available: {', '.join(available)}"

    # Check if algorithm is available on this system
    if not registry.is_available(name):
        return False, f"Algorithm '{name}' is not available (requires additional package)"

    return True, ""


def get_cipher_aliases(canonical_name: str) -> List[str]:
    """
    Get all aliases for a cipher algorithm.

    Args:
        canonical_name: Canonical algorithm name

    Returns:
        List of aliases (including canonical name)
    """
    registry = CipherRegistry.default()
    try:
        info = registry.get_info(canonical_name)
        return [canonical_name] + list(info.aliases)
    except Exception:
        return [canonical_name]
