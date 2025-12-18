#!/usr/bin/env python3
"""
Security Scoring System for OpenSSL Encrypt

This module provides a comprehensive security scoring system that evaluates
encryption configurations without revealing sensitive implementation details.
The scoring system helps users understand the security strength of their
chosen configuration while maintaining operational security.

Security Design:
- No information leakage about specific vulnerabilities
- Generic strength ratings without revealing attack vectors
- Time estimates based on current computational capabilities
- Educational guidance without compromising security posture
"""

import hashlib
import math
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SecurityLevel(Enum):
    """Security level classifications."""

    MINIMAL = 1  # Basic protection, fast operations
    LOW = 2  # Below recommended minimum
    MODERATE = 3  # Adequate for most use cases
    GOOD = 4  # Recommended for important data
    HIGH = 5  # Strong protection for sensitive data
    VERY_HIGH = 6  # Excellent security posture
    MAXIMUM = 7  # Highest available security
    OVERKILL = 8  # Beyond practical requirements
    THEORETICAL = 9  # Academic/research level
    EXTREME = 10  # Maximum possible configuration


class SecurityScorer:
    """
    Security configuration scoring engine.

    Evaluates encryption configurations across multiple dimensions:
    - Hash algorithm strength and iteration counts
    - Key derivation function selection and parameters
    - Encryption algorithm security level
    - Post-quantum readiness
    - Overall configuration coherence
    """

    # Hash algorithm strength ratings (relative security levels)
    HASH_STRENGTH = {
        "sha256": 4.0,
        "sha512": 4.5,
        "sha3_256": 4.2,
        "sha3_512": 4.7,
        "sha224": 3.5,
        "sha384": 4.3,
        "blake2b": 4.6,
        "blake3": 4.8,
        "shake256": 4.4,
        "shake128": 4.0,
        "whirlpool": 3.0,  # Legacy
    }

    # KDF strength multipliers
    KDF_STRENGTH = {
        "argon2": 5.0,  # Modern, memory-hard
        "scrypt": 4.0,  # Memory-hard
        "pbkdf2": 2.0,  # Legacy, CPU-only
        "balloon": 4.5,  # Memory-hard with proven security
        "hkdf": 3.5,  # Fast, suitable for key stretching
    }

    # Encryption algorithm security ratings
    CIPHER_STRENGTH = {
        "aes-gcm": 4.5,
        "aes-gcm-siv": 4.7,
        "aes-siv": 4.4,
        "aes-ocb3": 4.3,
        "chacha20-poly1305": 4.6,
        "xchacha20-poly1305": 4.8,
        "fernet": 3.5,  # Simplified, but solid
    }

    # Post-quantum algorithm bonuses
    PQC_BONUS = {
        "ml-kem": 2.0,  # NIST standard
        "kyber": 1.8,  # Pre-standard Kyber
        "hqc": 1.5,  # Alternative approach
    }

    def __init__(self):
        """Initialize the security scorer."""
        pass

    def score_configuration(
        self,
        hash_config: Dict[str, Any],
        kdf_config: Dict[str, Any],
        cipher_info: Dict[str, Any],
        pqc_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Score a complete encryption configuration.

        Args:
            hash_config: Hash algorithm configuration
            kdf_config: KDF configuration
            cipher_info: Encryption cipher information
            pqc_info: Post-quantum configuration (optional)

        Returns:
            Dictionary containing comprehensive security analysis
        """
        scores = {}

        # Score individual components
        hash_score = self._score_hash_config(hash_config)
        kdf_score = self._score_kdf_config(kdf_config)
        cipher_score = self._score_cipher_config(cipher_info)
        pqc_score = self._score_pqc_config(pqc_info) if pqc_info else 0

        # Calculate component scores
        scores["hash_analysis"] = hash_score
        scores["kdf_analysis"] = kdf_score
        scores["cipher_analysis"] = cipher_score
        scores["pqc_analysis"] = {"score": pqc_score, "enabled": bool(pqc_info)}

        # Calculate overall score
        base_score = (
            hash_score["score"] * 0.25 + kdf_score["score"] * 0.35 + cipher_score["score"] * 0.30
        )

        # Add post-quantum bonus
        if pqc_score > 0:
            base_score += min(pqc_score * 0.10, 1.5)  # Cap PQC bonus

        # Ensure score stays within bounds
        overall_score = max(1.0, min(10.0, base_score))

        scores["overall"] = {
            "score": round(overall_score, 1),
            "level": self._score_to_level(overall_score),
            "description": self._get_security_description(overall_score),
        }

        # Add computational estimates
        scores["estimates"] = self._calculate_security_estimates(
            hash_score, kdf_score, cipher_score
        )

        # Add improvement suggestions (generic)
        scores["suggestions"] = self._generate_suggestions(scores)

        return scores

    def _score_hash_config(self, hash_config: Dict[str, Any]) -> Dict[str, Any]:
        """Score hash algorithm configuration."""
        score = 0.0
        active_hashes = []
        total_rounds = 0

        for hash_name, config in hash_config.items():
            if isinstance(config, dict) and config.get("rounds", 0) > 0:
                base_strength = self.HASH_STRENGTH.get(hash_name, 2.0)
                rounds = config["rounds"]

                # Score based on rounds (logarithmic scaling)
                if rounds > 0:
                    round_score = min(math.log10(rounds) / 6.0, 1.0)  # Cap at 1M rounds = 1.0
                    hash_score = base_strength * (0.5 + 0.5 * round_score)
                    score = max(score, hash_score)
                    active_hashes.append(hash_name)
                    total_rounds += rounds

        # Multiple hash bonus (but diminishing returns)
        if len(active_hashes) > 1:
            score *= 1 + 0.1 * (len(active_hashes) - 1)

        return {
            "score": min(score, 10.0),
            "algorithms": active_hashes,
            "total_rounds": total_rounds,
            "description": self._describe_hash_strength(score),
        }

    def _score_kdf_config(self, kdf_config: Dict[str, Any]) -> Dict[str, Any]:
        """Score KDF configuration."""
        score = 0.0
        active_kdfs = []

        for kdf_name, config in kdf_config.items():
            if isinstance(config, dict) and config.get("enabled", False):
                base_strength = self.KDF_STRENGTH.get(kdf_name, 2.0)
                kdf_score = base_strength

                # Adjust score based on parameters
                if kdf_name == "argon2":
                    # Score based on memory cost (more memory = higher score)
                    memory_cost = config.get("memory_cost", 65536)
                    memory_score = min(math.log2(memory_cost) / 20.0, 1.2)
                    kdf_score *= memory_score

                elif kdf_name == "scrypt":
                    # Score based on N parameter
                    n_param = config.get("n", 16384)
                    n_score = min(math.log2(n_param) / 18.0, 1.2)
                    kdf_score *= n_score

                elif kdf_name == "pbkdf2":
                    # PBKDF2 rounds matter more due to simpler algorithm
                    rounds = config.get("rounds", 100000)
                    round_score = min(math.log10(rounds) / 6.0, 1.0)
                    kdf_score *= 0.5 + 0.5 * round_score

                score = max(score, kdf_score)
                active_kdfs.append(kdf_name)

        # Multiple KDF bonus
        if len(active_kdfs) > 1:
            score *= 1 + 0.15 * (len(active_kdfs) - 1)

        return {
            "score": min(score, 10.0),
            "algorithms": active_kdfs,
            "description": self._describe_kdf_strength(score),
        }

    def _score_cipher_config(self, cipher_info: Dict[str, Any]) -> Dict[str, Any]:
        """Score encryption cipher configuration."""
        algorithm = cipher_info.get("algorithm", "unknown")
        base_score = self.CIPHER_STRENGTH.get(algorithm, 2.0)

        # Check for additional security features
        authenticated = (
            "gcm" in algorithm
            or "siv" in algorithm
            or "ocb" in algorithm
            or "poly1305" in algorithm
        )
        if authenticated:
            base_score *= 1.1

        return {
            "score": min(base_score, 10.0),
            "algorithm": algorithm,
            "authenticated": authenticated,
            "description": self._describe_cipher_strength(base_score),
        }

    def _score_pqc_config(self, pqc_info: Dict[str, Any]) -> float:
        """Score post-quantum configuration."""
        if not pqc_info or not pqc_info.get("enabled", False):
            return 0.0

        pqc_algorithm = pqc_info.get("algorithm", "")

        # Determine PQC family
        for family, bonus in self.PQC_BONUS.items():
            if family in pqc_algorithm.lower():
                # Higher security levels get better scores
                if "768" in pqc_algorithm or "192" in pqc_algorithm:
                    return bonus * 1.2
                elif "1024" in pqc_algorithm or "256" in pqc_algorithm:
                    return bonus * 1.5
                else:
                    return bonus

        return 1.0  # Unknown PQC algorithm gets basic bonus

    def _score_to_level(self, score: float) -> SecurityLevel:
        """Convert numeric score to security level."""
        if score <= 2.0:
            return SecurityLevel.MINIMAL
        elif score <= 3.0:
            return SecurityLevel.LOW
        elif score <= 4.0:
            return SecurityLevel.MODERATE
        elif score <= 5.0:
            return SecurityLevel.GOOD
        elif score <= 6.0:
            return SecurityLevel.HIGH
        elif score <= 7.0:
            return SecurityLevel.VERY_HIGH
        elif score <= 8.0:
            return SecurityLevel.MAXIMUM
        elif score <= 9.0:
            return SecurityLevel.OVERKILL
        elif score <= 9.5:
            return SecurityLevel.THEORETICAL
        else:
            return SecurityLevel.EXTREME

    def _get_security_description(self, score: float) -> str:
        """Get human-readable security description."""
        level = self._score_to_level(score)

        descriptions = {
            SecurityLevel.MINIMAL: "Basic protection suitable for low-value data",
            SecurityLevel.LOW: "Below recommended security level for most use cases",
            SecurityLevel.MODERATE: "Adequate security for everyday use",
            SecurityLevel.GOOD: "Recommended security level for important data",
            SecurityLevel.HIGH: "Strong protection for sensitive information",
            SecurityLevel.VERY_HIGH: "Excellent security posture for critical data",
            SecurityLevel.MAXIMUM: "Highest practical security level",
            SecurityLevel.OVERKILL: "Exceeds practical requirements for most scenarios",
            SecurityLevel.THEORETICAL: "Academic-grade security configuration",
            SecurityLevel.EXTREME: "Maximum possible security settings",
        }

        return descriptions.get(level, "Unknown security level")

    def _describe_hash_strength(self, score: float) -> str:
        """Describe hash configuration strength."""
        if score <= 2.0:
            return "Minimal hash security"
        elif score <= 4.0:
            return "Moderate hash strength"
        elif score <= 6.0:
            return "Strong hash configuration"
        else:
            return "Excellent hash security"

    def _describe_kdf_strength(self, score: float) -> str:
        """Describe KDF configuration strength."""
        if score <= 2.0:
            return "Basic key derivation"
        elif score <= 4.0:
            return "Adequate KDF configuration"
        elif score <= 6.0:
            return "Strong key derivation"
        else:
            return "Excellent KDF security"

    def _describe_cipher_strength(self, score: float) -> str:
        """Describe cipher strength."""
        if score <= 3.0:
            return "Basic encryption"
        elif score <= 4.5:
            return "Strong encryption"
        else:
            return "Excellent encryption algorithm"

    def _calculate_security_estimates(
        self, hash_score: Dict[str, Any], kdf_score: Dict[str, Any], cipher_score: Dict[str, Any]
    ) -> Dict[str, str]:
        """Calculate security time estimates (generic, educational only)."""
        # These are very rough educational estimates
        # Not meant to be precise security assessments

        total_operations = hash_score.get("total_rounds", 100000)
        kdf_complexity = len(kdf_score.get("algorithms", [])) * 100000

        # Rough estimate of total computational work
        work_factor = total_operations + kdf_complexity

        if work_factor < 100000:
            time_estimate = "Minutes to hours (basic protection)"
        elif work_factor < 1000000:
            time_estimate = "Days to weeks (moderate protection)"
        elif work_factor < 10000000:
            time_estimate = "Months to years (good protection)"
        else:
            time_estimate = "Many years to decades (strong protection)"

        return {
            "brute_force_time": time_estimate,
            "note": "Estimates are educational only and based on current technology",
            "disclaimer": "Actual security depends on many factors beyond configuration",
        }

    def _generate_suggestions(self, scores: Dict[str, Any]) -> List[str]:
        """Generate generic improvement suggestions."""
        suggestions = []
        overall_score = scores["overall"]["score"]

        if overall_score < 4.0:
            suggestions.append("Consider using stronger algorithm configurations")

        if not scores["pqc_analysis"]["enabled"]:
            suggestions.append("Consider post-quantum algorithms for future-proofing")

        if scores["hash_analysis"]["score"] < 4.0:
            suggestions.append("Hash configuration could be strengthened")

        if scores["kdf_analysis"]["score"] < 4.0:
            suggestions.append("Key derivation settings could be enhanced")

        if overall_score > 8.0:
            suggestions.append("Configuration may be stronger than necessary for most use cases")

        if not suggestions:
            suggestions.append("Configuration provides good security balance")

        return suggestions


def analyze_security_config(
    hash_config: Dict[str, Any],
    kdf_config: Dict[str, Any],
    cipher_info: Dict[str, Any],
    pqc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience function to analyze security configuration.

    Args:
        hash_config: Hash algorithm configuration
        kdf_config: KDF configuration
        cipher_info: Cipher configuration
        pqc_info: Post-quantum configuration (optional)

    Returns:
        Security analysis results
    """
    scorer = SecurityScorer()
    return scorer.score_configuration(hash_config, kdf_config, cipher_info, pqc_info)
