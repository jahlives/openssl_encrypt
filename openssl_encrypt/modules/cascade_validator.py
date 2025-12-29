#!/usr/bin/env python3
"""
Cascade Diversity Validator.

This module validates cipher chains in cascade encryption to ensure
cryptographic diversity and warn about potentially weak combinations.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional

from .registry.cipher_families import are_related_families, get_design_type, get_family_name


class DiversityWarningLevel(Enum):
    """Severity level for diversity warnings."""

    INFO = auto()  # Informational message, not a problem
    WARNING = auto()  # Potential issue, but not critical
    ERROR = auto()  # Serious problem that should prevent encryption


@dataclass
class DiversityWarning:
    """A diversity validation warning or error."""

    level: DiversityWarningLevel
    message: str
    ciphers_involved: List[str]
    suggestion: Optional[str] = None


class CascadeDiversityValidator:
    """
    Validates cipher chains for cryptographic diversity.

    This validator checks cascade configurations for common pitfalls:
    - Multiple ciphers from the same family (e.g., AES-GCM + AES-SIV)
    - Related cipher families (e.g., ChaCha20 + Salsa20)
    - Lack of design diversity (e.g., all ARX or all SPN ciphers)
    """

    def __init__(self, strict: bool = False):
        """
        Initialize the validator.

        Args:
            strict: If True, treat warnings as errors
        """
        self.strict = strict

    def validate(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """
        Validate a cipher chain for diversity.

        Args:
            cipher_names: List of cipher names in the cascade chain

        Returns:
            List of diversity warnings/errors found
        """
        warnings = []

        # Check for same family ciphers
        warnings.extend(self._check_same_family(cipher_names))

        # Check for related families
        warnings.extend(self._check_related_families(cipher_names))

        # Check for design diversity
        warnings.extend(self._check_design_diversity(cipher_names))

        # Upgrade warnings to errors in strict mode
        if self.strict:
            warnings = [
                DiversityWarning(
                    level=DiversityWarningLevel.ERROR
                    if w.level == DiversityWarningLevel.WARNING
                    else w.level,
                    message=w.message,
                    ciphers_involved=w.ciphers_involved,
                    suggestion=w.suggestion,
                )
                for w in warnings
            ]

        return warnings

    def _check_same_family(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """
        Check if multiple ciphers are from the same family.

        Using multiple ciphers from the same family (e.g., AES-GCM + AES-SIV)
        reduces diversity benefits since they share the same underlying primitive.

        Args:
            cipher_names: List of cipher names

        Returns:
            List of warnings for same-family ciphers
        """
        warnings = []
        family_to_ciphers = {}

        # Group ciphers by family
        for cipher in cipher_names:
            family = get_family_name(cipher)
            if family:
                if family not in family_to_ciphers:
                    family_to_ciphers[family] = []
                family_to_ciphers[family].append(cipher)

        # Check for families with multiple ciphers
        for family, ciphers in family_to_ciphers.items():
            if len(ciphers) > 1:
                warnings.append(
                    DiversityWarning(
                        level=DiversityWarningLevel.WARNING,
                        message=(
                            f"Multiple ciphers from the same '{family}' family: {', '.join(ciphers)}. "
                            "This reduces cryptographic diversity since they share the same underlying primitive."
                        ),
                        ciphers_involved=ciphers,
                        suggestion=(
                            "Consider using ciphers from different families. "
                            "For example, combine AES with ChaCha20 or Threefish for better diversity."
                        ),
                    )
                )

        return warnings

    def _check_related_families(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """
        Check if ciphers are from related families.

        Related families (e.g., ChaCha20 and Salsa20, or AES and Camellia)
        share design principles and may have correlated weaknesses.

        Args:
            cipher_names: List of cipher names

        Returns:
            List of informational messages about related families
        """
        warnings = []
        families = [get_family_name(c) for c in cipher_names if get_family_name(c)]

        # Check all pairs
        for i, family1 in enumerate(families):
            for family2 in families[i + 1 :]:
                if are_related_families(family1, family2):
                    # Find which ciphers belong to these families
                    ciphers1 = [c for c in cipher_names if get_family_name(c) == family1]
                    ciphers2 = [c for c in cipher_names if get_family_name(c) == family2]

                    warnings.append(
                        DiversityWarning(
                            level=DiversityWarningLevel.INFO,
                            message=(
                                f"Ciphers from related families detected: '{family1}' and '{family2}'. "
                                "These families share design principles and may have correlated properties."
                            ),
                            ciphers_involved=ciphers1 + ciphers2,
                            suggestion=(
                                "This is not necessarily a problem, but be aware that "
                                "related families may not provide completely independent security."
                            ),
                        )
                    )

        return warnings

    def _check_design_diversity(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """
        Check if cascade has design-level diversity.

        Best practice is to combine ciphers with different design paradigms
        (e.g., SPN + ARX) to maximize the effort required to break all layers.

        Args:
            cipher_names: List of cipher names

        Returns:
            List of informational messages about design diversity
        """
        warnings = []
        design_types = [get_design_type(c) for c in cipher_names if get_design_type(c)]

        if not design_types:
            return warnings

        # Count design types
        design_counts = {}
        for design in design_types:
            design_counts[design] = design_counts.get(design, 0) + 1

        # Check if all ciphers use the same design
        if len(design_counts) == 1:
            design = list(design_counts.keys())[0]
            design_name = design.name

            warnings.append(
                DiversityWarning(
                    level=DiversityWarningLevel.INFO,
                    message=(
                        f"All ciphers use the same design paradigm ({design_name}). "
                        "Mixing different design types (e.g., SPN + ARX) can provide "
                        "better theoretical security against algorithmic breakthroughs."
                    ),
                    ciphers_involved=cipher_names,
                    suggestion=(
                        "Consider adding a cipher with a different design. "
                        "For example: combine AES (SPN) with ChaCha20 or Threefish (ARX)."
                    ),
                )
            )
        else:
            # Good diversity - multiple design types
            design_names = ", ".join(d.name for d in design_counts.keys())
            warnings.append(
                DiversityWarning(
                    level=DiversityWarningLevel.INFO,
                    message=(
                        f"Good design diversity: using {len(design_counts)} different paradigms ({design_names}). "
                        "This provides strong theoretical protection against algorithmic attacks."
                    ),
                    ciphers_involved=cipher_names,
                    suggestion=None,
                )
            )

        return warnings


def validate_cascade_diversity(
    cipher_names: List[str], strict: bool = False
) -> List[DiversityWarning]:
    """
    Convenience function to validate cascade cipher diversity.

    Args:
        cipher_names: List of cipher names in the cascade
        strict: If True, treat warnings as errors

    Returns:
        List of diversity warnings/errors
    """
    validator = CascadeDiversityValidator(strict=strict)
    return validator.validate(cipher_names)
