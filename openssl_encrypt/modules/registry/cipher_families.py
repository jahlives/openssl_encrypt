#!/usr/bin/env python3
"""
Cipher Family Definitions for Diversity Validation.

This module defines cryptographic cipher families and their relationships
to support cascade encryption diversity validation.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set


class DesignType(Enum):
    """Fundamental cipher design paradigm."""

    SPN = auto()  # Substitution-Permutation Network (AES, Serpent)
    FEISTEL = auto()  # Feistel Network (Twofish, Camellia)
    ARX = auto()  # Add-Rotate-XOR (ChaCha, Threefish, Salsa)
    STREAM = auto()  # Stream cipher (Fernet uses AES-CBC internally)
    OTHER = auto()  # Other designs


@dataclass
class CipherFamily:
    """Definition of a cipher family with its cryptographic properties."""

    name: str
    design_type: DesignType
    primitive: str
    members: Set[str] = field(default_factory=set)
    related_families: Set[str] = field(default_factory=set)
    designer: Optional[str] = None
    notes: Optional[str] = None

    def __post_init__(self):
        """Normalize member names to lowercase."""
        self.members = {m.lower() for m in self.members}
        self.related_families = {f.lower() for f in self.related_families}


# Cipher family definitions
CIPHER_FAMILIES: Dict[str, CipherFamily] = {
    "aes": CipherFamily(
        name="aes",
        design_type=DesignType.SPN,
        primitive="Rijndael",
        members={
            "aes-256-gcm",
            "aes-128-gcm",
            "aes-gcm",
            "aes-gcm-siv",
            "aes-siv",
            "aes-ocb3",
        },
        related_families={"camellia"},
        designer="Daemen & Rijmen",
        notes="NIST standard, hardware acceleration widely available",
    ),
    "chacha": CipherFamily(
        name="chacha",
        design_type=DesignType.ARX,
        primitive="ChaCha",
        members={"chacha20-poly1305", "xchacha20-poly1305"},
        related_families={"salsa"},
        designer="Daniel J. Bernstein",
        notes="Designed for software performance without hardware acceleration",
    ),
    "threefish": CipherFamily(
        name="threefish",
        design_type=DesignType.ARX,
        primitive="Threefish",
        members={"threefish-512", "threefish-1024"},
        related_families=set(),
        designer="Schneier et al.",
        notes="Part of Skein hash function, designed for post-quantum security",
    ),
    "fernet": CipherFamily(
        name="fernet",
        design_type=DesignType.SPN,  # Uses AES-128-CBC internally
        primitive="Fernet (AES-CBC + HMAC)",
        members={"fernet"},
        related_families={"aes"},
        designer="Fernet Spec Authors",
        notes="High-level encryption format, uses AES-128-CBC with HMAC-SHA256",
    ),
}


def normalize_cipher_name(cipher_name: str) -> str:
    """
    Normalize a cipher name to lowercase for lookups.

    Args:
        cipher_name: The cipher name to normalize

    Returns:
        Normalized cipher name
    """
    return cipher_name.lower().strip()


def get_cipher_family(cipher_name: str) -> Optional[CipherFamily]:
    """
    Get the family object for a cipher.

    Args:
        cipher_name: Name of the cipher (e.g., "aes-256-gcm", "chacha20-poly1305")

    Returns:
        CipherFamily object if found, None otherwise
    """
    normalized = normalize_cipher_name(cipher_name)

    for family in CIPHER_FAMILIES.values():
        if normalized in family.members:
            return family

    return None


def get_family_name(cipher_name: str) -> Optional[str]:
    """
    Get the family name for a cipher.

    Args:
        cipher_name: Name of the cipher

    Returns:
        Family name (str) if found, None otherwise
    """
    family = get_cipher_family(cipher_name)
    return family.name if family else None


def are_related_families(family1: str, family2: str) -> bool:
    """
    Check if two families are cryptographically related.

    Related families share design principles or have common ancestry.

    Args:
        family1: Name of first family
        family2: Name of second family

    Returns:
        True if families are related, False otherwise
    """
    family1 = family1.lower()
    family2 = family2.lower()

    if family1 == family2:
        return False  # Same family, not "related"

    family1_obj = CIPHER_FAMILIES.get(family1)
    family2_obj = CIPHER_FAMILIES.get(family2)

    if not family1_obj or not family2_obj:
        return False

    # Check if family1 lists family2 as related, or vice versa
    return family2 in family1_obj.related_families or family1 in family2_obj.related_families


def get_design_type(cipher_name: str) -> Optional[DesignType]:
    """
    Get the design type for a cipher.

    Args:
        cipher_name: Name of the cipher

    Returns:
        DesignType if found, None otherwise
    """
    family = get_cipher_family(cipher_name)
    return family.design_type if family else None


def list_all_families() -> List[str]:
    """
    Get a list of all defined cipher families.

    Returns:
        List of family names
    """
    return list(CIPHER_FAMILIES.keys())


def list_family_members(family_name: str) -> List[str]:
    """
    Get all cipher names in a family.

    Args:
        family_name: Name of the family

    Returns:
        List of cipher names in the family
    """
    family = CIPHER_FAMILIES.get(family_name.lower())
    return sorted(family.members) if family else []
