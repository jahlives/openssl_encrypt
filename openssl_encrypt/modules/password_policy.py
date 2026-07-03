#!/usr/bin/env python3
"""
Password Policy Module

This module provides password policy validation and enforcement mechanisms
to ensure that passwords meet security requirements.
"""

import base64
import hashlib
import importlib.resources
import math
import os
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .crypt_utils import eprint

# Import from local modules
try:
    from .crypt_core import string_entropy
    from .crypt_errors import ValidationError
except ImportError:
    # For standalone testing
    from openssl_encrypt.modules.crypt_core import string_entropy
    from openssl_encrypt.modules.crypt_errors import ValidationError

# Optional pattern-aware strength backend. When zxcvbn is installed it provides
# dictionary/sequence/keyboard/date detection; otherwise a built-in heuristic
# fallback is used. Keep this probe intact -- do NOT strip the unused import,
# it is a capability check for an optional dependency.
try:
    from zxcvbn import zxcvbn as _zxcvbn

    _HAVE_ZXCVBN = True
except ImportError:  # pragma: no cover - exercised via the heuristic fallback tests
    _zxcvbn = None
    _HAVE_ZXCVBN = False


class PasswordPolicy:
    """
    Password policy enforcement and validation.

    This class provides methods to validate passwords against defined policies,
    including length, complexity, common password detection, and entropy requirements.
    """

    # Minimum secure entropy values (in bits)
    ENTROPY_VERY_WEAK = 35.0  # Below this is very weak
    ENTROPY_WEAK = 60.0  # Below this is weak
    ENTROPY_MODERATE = 80.0  # Below this is moderate
    ENTROPY_STRONG = 100.0  # Below this is strong, above is very strong

    # Default patterns for character class checks
    PATTERN_LOWERCASE = re.compile(r"[a-z]")
    PATTERN_UPPERCASE = re.compile(r"[A-Z]")
    PATTERN_DIGITS = re.compile(r"[0-9]")
    PATTERN_SPECIAL = re.compile(r"[^a-zA-Z0-9]")

    # Policy levels
    LEVEL_MINIMAL = "minimal"  # Just minimum length
    LEVEL_BASIC = "basic"  # Length + basic complexity
    LEVEL_STANDARD = "standard"  # Length + full complexity + entropy
    LEVEL_PARANOID = "paranoid"  # Length + full complexity + entropy + common password check

    def __init__(
        self,
        policy_level: str = "standard",
        min_length: int = 12,
        require_lowercase: bool = True,
        require_uppercase: bool = True,
        require_digits: bool = True,
        require_special: bool = True,
        min_entropy: float = ENTROPY_MODERATE,
        check_common_passwords: bool = True,
        common_passwords_path: Optional[str] = None,
        strict_strength: bool = False,
    ):
        """
        Initialize the password policy with specified requirements.

        Args:
            policy_level: Predefined policy level (minimal, basic, standard, paranoid)
            min_length: Minimum password length requirement
            require_lowercase: Whether to require lowercase letters
            require_uppercase: Whether to require uppercase letters
            require_digits: Whether to require digits
            require_special: Whether to require special characters
            min_entropy: Minimum entropy value required (in bits)
            check_common_passwords: Whether to check against common password lists
            common_passwords_path: Path to custom common password list
            strict_strength: Gate on the pattern-aware strength estimate instead
                of the raw search-space entropy. Enabled automatically for the
                ``paranoid`` level; can be forced on for any level.
        """
        # Apply predefined policy level if specified
        if policy_level:
            self._apply_policy_level(policy_level)
        else:
            # Use provided parameters
            self.min_length = min_length
            self.require_lowercase = require_lowercase
            self.require_uppercase = require_uppercase
            self.require_digits = require_digits
            self.require_special = require_special
            self.min_entropy = min_entropy
            self.check_common_passwords = check_common_passwords

        # strict_strength may already be set by the policy level (paranoid). An
        # explicit True from the caller can only tighten, never loosen it.
        self.strict_strength = getattr(self, "strict_strength", False) or strict_strength

        # Initialize common password checking if enabled
        self.common_password_checker = None
        if self.check_common_passwords:
            self.common_password_checker = CommonPasswordChecker(common_passwords_path)

    def _apply_policy_level(self, level: str):
        """
        Apply a predefined policy level.

        Args:
            level: The policy level to apply (minimal, basic, standard, paranoid)
        """
        level = level.lower()
        # Default: advisory strength only. The paranoid level opts into gating
        # on the pattern-aware estimate below.
        self.strict_strength = False
        if level == self.LEVEL_MINIMAL:
            self.min_length = 8
            self.require_lowercase = False
            self.require_uppercase = False
            self.require_digits = False
            self.require_special = False
            self.min_entropy = 0
            self.check_common_passwords = False

        elif level == self.LEVEL_BASIC:
            self.min_length = 10
            self.require_lowercase = True
            self.require_uppercase = True
            self.require_digits = True
            self.require_special = False
            self.min_entropy = self.ENTROPY_WEAK
            self.check_common_passwords = False

        elif level == self.LEVEL_STANDARD:
            self.min_length = 12
            self.require_lowercase = True
            self.require_uppercase = True
            self.require_digits = True
            self.require_special = True
            self.min_entropy = self.ENTROPY_MODERATE
            self.check_common_passwords = True

        elif level == self.LEVEL_PARANOID:
            self.min_length = 16
            self.require_lowercase = True
            self.require_uppercase = True
            self.require_digits = True
            self.require_special = True
            self.min_entropy = self.ENTROPY_STRONG
            self.check_common_passwords = True
            self.strict_strength = True

        else:
            # Default to standard if unknown level
            self._apply_policy_level(self.LEVEL_STANDARD)

    def validate_password(self, password: str, quiet: bool = False) -> Tuple[bool, List[str]]:
        """
        Validate a password against the policy.

        Args:
            password: The password to validate
            quiet: Whether to suppress validation warnings

        Returns:
            Tuple containing validation result (bool) and list of validation messages
        """
        msgs = []
        valid = True

        # Always validate: check length
        if len(password) < self.min_length:
            msgs.append(f"Password is too short (minimum {self.min_length} characters required)")
            valid = False

        # Check character classes requirements
        if self.require_lowercase and not self.PATTERN_LOWERCASE.search(password):
            msgs.append("Password must contain at least one lowercase letter")
            valid = False

        if self.require_uppercase and not self.PATTERN_UPPERCASE.search(password):
            msgs.append("Password must contain at least one uppercase letter")
            valid = False

        if self.require_digits and not self.PATTERN_DIGITS.search(password):
            msgs.append("Password must contain at least one digit")
            valid = False

        if self.require_special and not self.PATTERN_SPECIAL.search(password):
            msgs.append("Password must contain at least one special character")
            valid = False

        # Check entropy if a minimum is specified
        if self.min_entropy > 0:
            est = estimate_strength(password)
            # The displayed strength/label is always pattern-aware. The hard gate
            # uses the pattern-aware estimate only under strict_strength; otherwise
            # it stays on the raw search-space measure for backward compatibility.
            gate_bits = est.bits if self.strict_strength else est.raw_bits

            if not quiet:
                msgs.append(f"Password strength: {est.category} (entropy: {est.bits:.1f} bits)")
                for warning in est.warnings:
                    msgs.append(f"Password weakness: {warning}")

            if gate_bits < self.min_entropy:
                msgs.append(
                    f"Password entropy is too low (minimum {self.min_entropy} bits required)"
                )
                valid = False

        # Check against common passwords list
        if self.check_common_passwords and self.common_password_checker:
            if self.common_password_checker.is_common_password(password):
                msgs.append("Password is too common (found in common password lists)")
                valid = False

        return valid, msgs

    def validate_password_or_raise(self, password: str, quiet: bool = False) -> None:
        """
        Validate a password against the policy and raise a ValidationError if invalid.

        Args:
            password: The password to validate
            quiet: Whether to suppress validation warnings

        Raises:
            ValidationError: If the password does not meet policy requirements
        """
        valid, msgs = self.validate_password(password, quiet)

        # Informational messages (strength label + advisory weakness warnings)
        # are printed even when the password is accepted, and are never part of
        # the raised error.
        informational = ("Password strength:", "Password weakness:")

        if not quiet and msgs:
            for msg in msgs:
                if msg.startswith(informational):
                    eprint(msg)

        # Raise exception if validation failed
        if not valid:
            error_msgs = [msg for msg in msgs if not msg.startswith(informational)]
            raise ValidationError("\n".join(error_msgs))

    def generate_feedback(self, password: str) -> str:
        """
        Generate detailed feedback for a password.

        Args:
            password: The password to analyze

        Returns:
            A string containing detailed feedback about the password strength
        """
        valid, msgs = self.validate_password(password, quiet=False)

        est = estimate_strength(password)

        # Create more detailed feedback
        if not valid:
            feedback = "Password does not meet requirements:\n"
            feedback += "\n".join(
                f"- {msg}" for msg in msgs if not msg.startswith("Password strength:")
            )
            feedback += f"\n\nPassword strength: {est.category} ({est.bits:.1f} bits)"
        else:
            # Password is valid, but provide additional feedback
            feedback = "Password meets basic requirements, but consider:\n"

            if len(password) < 16:
                feedback += "- Using a longer password (16+ characters) for better security\n"

            if len(set(password)) < len(password) * 0.7:
                feedback += "- Using more unique characters (avoid repetition)\n"

            for warning in est.warnings:
                feedback += f"- {warning}\n"

            if est.bits < self.ENTROPY_STRONG:
                feedback += f"- Adding more complexity to increase entropy ({est.bits:.1f} bits)\n"
            else:
                feedback += "Your password is strong! ✓\n"

        return feedback


class CommonPasswordChecker:
    """
    Checker for common/compromised passwords.

    This class provides efficient checking against known common password lists
    to prevent the use of easily guessable passwords.
    """

    # Default paths to check for common password lists
    DEFAULT_PATHS = [
        # Package resource path (modern importlib.resources approach)
        str(importlib.resources.files("openssl_encrypt").joinpath("data/common_passwords.txt")),
        # Local module directory
        os.path.join(os.path.dirname(__file__), "../data/common_passwords.txt"),
        # Local project directory
        os.path.join(os.path.dirname(__file__), "../../data/common_passwords.txt"),
        # System paths
        "/usr/share/dict/words",
        "/usr/share/common-passwords/common-passwords.txt",
    ]

    # Include common passwords directly embedded as a string
    # This ensures baseline protection even if no external files are available
    EMBEDDED_PASSWORDS = """
    password
    123456
    12345678
    qwerty
    abc123
    monkey
    1234567
    letmein
    trustno1
    dragon
    baseball
    111111
    iloveyou
    master
    sunshine
    ashley
    bailey
    passw0rd
    shadow
    123123
    654321
    superman
    qazwsx
    michael
    football
    welcome
    jesus
    ninja
    mustang
    password1
    admin
    abc123456
    default
    welcome123
    test123
    123qwe
    123abc
    """

    def __init__(self, custom_path: Optional[str] = None):
        """
        Initialize the common password checker.

        A custom list AUGMENTS the embedded baseline list rather than
        replacing it: a small custom list must never weaken the baseline
        protection. Without a custom path, the default system/package
        paths are tried, with the embedded list as fallback.

        Args:
            custom_path: Path to a custom common password list (checked in
                addition to the embedded baseline list)
        """
        self.password_hashes = set()
        self.loaded_at_least_one = False

        # Try to load passwords from custom path if provided
        if custom_path and os.path.exists(custom_path):
            self._load_password_list(custom_path)
            # #97: custom + embedded is intentional. The old code reached
            # the embedded list only through a forgotten loaded_at_least_one
            # flag; load it explicitly so the semantics are by design, not
            # by accident.
            self._load_embedded_passwords()
            self.loaded_at_least_one = True
        else:
            # Try all default paths
            for path in self.DEFAULT_PATHS:
                if os.path.exists(path):
                    self._load_password_list(path)
                    self.loaded_at_least_one = True

            # If no external files were loaded, use the embedded list
            if not self.loaded_at_least_one:
                self._load_embedded_passwords()
                self.loaded_at_least_one = True

    def _load_password_list(self, path: str) -> None:
        """
        Load common passwords from a file.

        Args:
            path: Path to the password file
        """
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    if password and len(password) >= 6:  # Only store reasonably sized passwords
                        # Store SHA-256 hash of the password to save memory
                        self.password_hashes.add(hashlib.sha256(password.encode("utf-8")).digest())
        except Exception as e:
            # Don't raise exception if loading fails - just continue with what we have
            eprint(f"Warning: Could not load common password list from {path}: {e}")

    def _load_embedded_passwords(self) -> None:
        """Load the embedded password list."""
        try:
            # Process each password from the embedded list
            for password in self.EMBEDDED_PASSWORDS.splitlines():
                password = password.strip()
                if password and len(password) >= 6:
                    self.password_hashes.add(hashlib.sha256(password.encode("utf-8")).digest())
        except Exception as e:
            # If loading fails, just continue with an empty set
            eprint(f"Warning: Could not load embedded common password list: {e}")

    def is_common_password(self, password: str) -> bool:
        """
        Check if a password is in the list of common passwords.

        Args:
            password: The password to check

        Returns:
            True if the password is common, False otherwise
        """
        if not self.loaded_at_least_one:
            # If no password list was loaded, we can't check
            return False

        # Check if the password hash is in our set
        password_hash = hashlib.sha256(password.encode("utf-8")).digest()
        return password_hash in self.password_hashes


# ---------------------------------------------------------------------------
# Pattern-aware strength estimation
# ---------------------------------------------------------------------------


@dataclass
class StrengthResult:
    """Result of a pattern-aware password strength estimate.

    Attributes:
        bits: Pattern-aware entropy estimate in bits. Never exceeds ``raw_bits``.
        raw_bits: The raw search-space entropy (``string_entropy``).
        category: Human-readable bucket for ``bits`` (see ``strength_category``).
        warnings: Human-readable descriptions of detected weaknesses (may be empty).
        source: Which backend produced the estimate ("zxcvbn" or "heuristic").
    """

    bits: float
    raw_bits: float
    category: str
    warnings: List[str] = field(default_factory=list)
    source: str = "heuristic"


def strength_category(bits: float) -> str:
    """Map an entropy value (in bits) to a strength label.

    Single source of truth for the VERY WEAK / WEAK / MODERATE / STRONG /
    VERY STRONG buckets used throughout the module.
    """
    if bits < PasswordPolicy.ENTROPY_VERY_WEAK:
        return "VERY WEAK"
    if bits < PasswordPolicy.ENTROPY_WEAK:
        return "WEAK"
    if bits < PasswordPolicy.ENTROPY_MODERATE:
        return "MODERATE"
    if bits < PasswordPolicy.ENTROPY_STRONG:
        return "STRONG"
    return "VERY STRONG"


# Common leet-speak substitutions, applied before the common-password lookup so
# that "P@ssw0rd" is recognised as "password".
_LEET_MAP = str.maketrans({"@": "a", "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s"})

# Rows used for keyboard-walk detection (lower-cased, US QWERTY).
_KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

# Named zxcvbn match types that indicate structure (i.e. not raw brute force).
_ZXCVBN_STRUCTURED = frozenset({"dictionary", "spatial", "repeat", "sequence", "regex", "date"})

# Lazily-instantiated shared checker for the heuristic fallback.
_common_checker: Optional["CommonPasswordChecker"] = None


def _get_common_checker() -> "CommonPasswordChecker":
    global _common_checker
    if _common_checker is None:
        _common_checker = CommonPasswordChecker()
    return _common_checker


def _leet_normalize(password: str) -> str:
    return password.translate(_LEET_MAP).lower()


def _adjacent(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` are neighbours in a sequence or on the keyboard."""
    if a.isalnum() and b.isalnum() and abs(ord(a) - ord(b)) == 1:
        return True
    for row in _KEYBOARD_ROWS:
        ia, ib = row.find(a), row.find(b)
        if ia != -1 and ib != -1 and abs(ia - ib) == 1:
            return True
    return False


def _longest_pattern_run(password: str) -> int:
    """Length of the longest ascending/descending sequence or keyboard walk."""
    lowered = password.lower()
    best = current = 1
    for i in range(1, len(lowered)):
        if _adjacent(lowered[i - 1], lowered[i]):
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def _heuristic_estimate(password: str, raw_bits: float) -> StrengthResult:
    """Search-space entropy minus penalties for detected patterns."""
    bits = raw_bits
    warnings: List[str] = []
    unique = max(len(set(password)), 1)
    per_char = raw_bits / unique  # == log2(pool_size)

    # Common password (directly or after undoing leet substitutions).
    checker = _get_common_checker()
    normalized = _leet_normalize(password)
    if checker.is_common_password(password) or checker.is_common_password(normalized):
        bits = min(bits, PasswordPolicy.ENTROPY_VERY_WEAK - 1.0)
        warnings.append("resembles a common password")

    # Sequences / keyboard walks: collapse the run to a single effective char.
    run = _longest_pattern_run(password)
    if run >= 4:
        bits = min(bits, max(raw_bits - (run - 1) * per_char, 0.0))
        warnings.append("contains a sequence or keyboard pattern")

    # Runs of a repeated character (e.g. "aaaa").
    if re.search(r"(.)\1{2,}", password):
        bits = min(bits, max(bits - per_char, 0.0))
        warnings.append("contains repeated characters")

    # Dates / years.
    if re.search(r"(?:19|20)\d\d", password):
        bits = min(bits, max(bits - per_char, 0.0))
        warnings.append("contains a date or year")

    return StrengthResult(
        bits=max(bits, 0.0),
        raw_bits=raw_bits,
        category=strength_category(max(bits, 0.0)),
        warnings=warnings,
        source="heuristic",
    )


def _zxcvbn_estimate(password: str, raw_bits: float) -> StrengthResult:
    """Pattern-aware estimate backed by zxcvbn.

    zxcvbn's guess count is accurate when it identifies structure but saturates
    well below the true search space for structureless passwords, so it is only
    allowed to lower the estimate when a *named* (non-bruteforce) pattern is
    found. Otherwise the raw search-space entropy is trusted.
    """
    result = _zxcvbn(password)
    guess_bits = math.log2(max(result.get("guesses", 1), 1))
    sequence = result.get("sequence", []) or []
    structured = sorted(
        {s.get("pattern") for s in sequence if s.get("pattern") in _ZXCVBN_STRUCTURED}
    )

    bits = min(raw_bits, guess_bits) if structured else raw_bits

    warnings: List[str] = []
    feedback = result.get("feedback") or {}
    if feedback.get("warning"):
        warnings.append(feedback["warning"])
    warnings.extend(feedback.get("suggestions") or [])
    if structured and not warnings:
        warnings.append("contains predictable pattern(s): " + ", ".join(structured))

    return StrengthResult(
        bits=bits,
        raw_bits=raw_bits,
        category=strength_category(bits),
        warnings=warnings,
        source="zxcvbn",
    )


def estimate_strength(password: str) -> StrengthResult:
    """Estimate password strength accounting for predictable patterns.

    Uses zxcvbn when available, otherwise a built-in heuristic. The returned
    ``bits`` never exceeds the raw ``string_entropy`` search-space measure and is
    pulled down when dictionary words, sequences, keyboard walks, repeats or
    dates are detected.
    """
    password = str(password)
    raw_bits = string_entropy(password)
    if not password:
        return StrengthResult(0.0, 0.0, strength_category(0.0), [], "heuristic")
    if _HAVE_ZXCVBN:
        return _zxcvbn_estimate(password, raw_bits)
    return _heuristic_estimate(password, raw_bits)


def get_pattern_strength(password: str) -> StrengthResult:
    """Public wrapper returning the full pattern-aware ``StrengthResult``."""
    return estimate_strength(password)


def build_strength_report(
    password: str,
    policy_level: str = "standard",
    strict_strength: bool = False,
) -> Dict:
    """Build a structured strength/policy report for a password.

    Pure function (no I/O, does not print or log the password). Combines the
    pattern-aware estimate with a policy evaluation so callers (e.g. the
    ``check-password`` CLI command) can render human or JSON output.

    Args:
        password: The password to analyse.
        policy_level: Policy level to evaluate against, or "none" to skip the
            policy check and only report strength.
        strict_strength: Gate the policy on the pattern-aware estimate instead of
            the raw search-space entropy (see :class:`PasswordPolicy`).

    Returns:
        A JSON-serialisable dict with the estimate, the resolved policy result
        and any failure messages.
    """
    est = estimate_strength(password)

    valid = True
    failures: List[str] = []
    if policy_level and policy_level.lower() != "none":
        policy = PasswordPolicy(policy_level=policy_level, strict_strength=strict_strength)
        # quiet=True keeps only requirement failures (no informational label).
        valid, failures = policy.validate_password(password, quiet=True)
        strict_strength = policy.strict_strength

    return {
        "length": len(password),
        "raw_bits": round(est.raw_bits, 1),
        "bits": round(est.bits, 1),
        "category": est.category,
        "warnings": list(est.warnings),
        "source": est.source,
        "policy_level": policy_level,
        "strict_strength": strict_strength,
        "valid": valid,
        "failures": failures,
    }


def format_strength_report(report: Dict) -> str:
    """Render a human-readable (stderr-friendly) view of a strength report."""
    lines = [
        f"Password strength: {report['category']} "
        f"({report['bits']:.1f} bits pattern-aware, {report['raw_bits']:.1f} bits raw)",
        f"Estimator backend: {report['source']}",
    ]
    for warning in report["warnings"]:
        lines.append(f"Weakness: {warning}")

    level = report.get("policy_level")
    if level and str(level).lower() != "none":
        status = "PASS" if report["valid"] else "FAIL"
        strict = " (strict)" if report.get("strict_strength") else ""
        lines.append(f"Policy '{level}'{strict}: {status}")
        for failure in report["failures"]:
            lines.append(f"  - {failure}")

    return "\n".join(lines)


# Direct API functions for easy use
def validate_password(
    password: str, policy_level: str = "standard", quiet: bool = False
) -> Tuple[bool, List[str]]:
    """
    Validate a password against the specified policy level.

    Args:
        password: The password to validate
        policy_level: Policy level to use (minimal, basic, standard, paranoid)
        quiet: Whether to suppress validation warnings

    Returns:
        Tuple containing validation result (bool) and list of validation messages
    """
    policy = PasswordPolicy(policy_level=policy_level)
    return policy.validate_password(password, quiet)


def validate_password_or_raise(
    password: str, policy_level: str = "standard", quiet: bool = False
) -> None:
    """
    Validate a password against the specified policy level and raise exception if invalid.

    Args:
        password: The password to validate
        policy_level: Policy level to use (minimal, basic, standard, paranoid)
        quiet: Whether to suppress validation warnings

    Raises:
        ValidationError: If the password does not meet policy requirements
    """
    policy = PasswordPolicy(policy_level=policy_level)
    policy.validate_password_or_raise(password, quiet)


def get_password_strength(password: str) -> Tuple[float, str]:
    """
    Get the strength of a password.

    Args:
        password: The password to analyze

    Returns:
        Tuple containing entropy value (float) and strength category (str)
    """
    entropy = string_entropy(password)
    return entropy, strength_category(entropy)


if __name__ == "__main__":
    # Simple testing code
    import argparse

    parser = argparse.ArgumentParser(description="Password Policy Module - Test Tool")
    parser.add_argument("--password", "-p", help="Password to test")
    parser.add_argument(
        "--level",
        "-l",
        choices=["minimal", "basic", "standard", "paranoid"],
        default="standard",
        help="Policy level to test against",
    )
    args = parser.parse_args()

    if not args.password:
        args.password = input("Enter password to test: ")

    policy = PasswordPolicy(policy_level=args.level)
    valid, msgs = policy.validate_password(args.password)

    eprint(f"\nTesting against '{args.level}' policy level:")
    for msg in msgs:
        eprint(f"- {msg}")

    if valid:
        eprint("\nResult: Password MEETS requirements ✓")
    else:
        eprint("\nResult: Password DOES NOT MEET requirements ✗")

    eprint("\nDetailed feedback:")
    eprint(policy.generate_feedback(args.password))
