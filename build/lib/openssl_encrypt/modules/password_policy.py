#!/usr/bin/env python3
"""
Password Policy Module

This module provides password policy validation and enforcement mechanisms
to ensure that passwords meet security requirements.
"""

import re
import os
import math
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import zlib
import base64
import hashlib
import importlib.resources

# Import from local modules
try:
    from .crypt_errors import ValidationError
    from .crypt_core import string_entropy
except ImportError:
    # For standalone testing
    from openssl_encrypt.modules.crypt_errors import ValidationError
    from openssl_encrypt.modules.crypt_core import string_entropy


class PasswordPolicy:
    """
    Password policy enforcement and validation.
    
    This class provides methods to validate passwords against defined policies,
    including length, complexity, common password detection, and entropy requirements.
    """
    
    # Minimum secure entropy values (in bits)
    ENTROPY_VERY_WEAK = 35.0    # Below this is very weak
    ENTROPY_WEAK = 60.0         # Below this is weak
    ENTROPY_MODERATE = 80.0     # Below this is moderate
    ENTROPY_STRONG = 100.0      # Below this is strong, above is very strong
    
    # Default patterns for character class checks
    PATTERN_LOWERCASE = re.compile(r'[a-z]')
    PATTERN_UPPERCASE = re.compile(r'[A-Z]')
    PATTERN_DIGITS = re.compile(r'[0-9]')
    PATTERN_SPECIAL = re.compile(r'[^a-zA-Z0-9]')
    
    # Policy levels
    LEVEL_MINIMAL = "minimal"      # Just minimum length
    LEVEL_BASIC = "basic"          # Length + basic complexity
    LEVEL_STANDARD = "standard"    # Length + full complexity + entropy
    LEVEL_PARANOID = "paranoid"    # Length + full complexity + entropy + common password check
    
    def __init__(self, 
                 policy_level: str = "standard",
                 min_length: int = 12,
                 require_lowercase: bool = True,
                 require_uppercase: bool = True,
                 require_digits: bool = True,
                 require_special: bool = True,
                 min_entropy: float = ENTROPY_MODERATE,
                 check_common_passwords: bool = True,
                 common_passwords_path: Optional[str] = None):
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
            entropy = string_entropy(password)
            # Add message about entropy regardless of validity for informational purposes
            if entropy < self.ENTROPY_VERY_WEAK:
                strength = "VERY WEAK"
            elif entropy < self.ENTROPY_WEAK:
                strength = "WEAK"
            elif entropy < self.ENTROPY_MODERATE:
                strength = "MODERATE"
            elif entropy < self.ENTROPY_STRONG:
                strength = "STRONG"
            else:
                strength = "VERY STRONG"
                
            if not quiet:
                msgs.append(f"Password strength: {strength} (entropy: {entropy:.1f} bits)")
            
            if entropy < self.min_entropy:
                msgs.append(f"Password entropy is too low (minimum {self.min_entropy} bits required)")
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
        
        # Print information messages even if password is valid
        if not quiet and msgs:
            for msg in msgs:
                # Only print informational messages like entropy strength
                if "Password strength:" in msg:
                    print(msg)
        
        # Raise exception if validation failed
        if not valid:
            # Only include error messages (not informational ones)
            error_msgs = [msg for msg in msgs if "Password strength:" not in msg]
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
        
        entropy = string_entropy(password)
        
        # Create more detailed feedback 
        if not valid:
            feedback = "Password does not meet requirements:\n"
            feedback += "\n".join([f"- {msg}" for msg in msgs if "Password strength:" not in msg])
            feedback += f"\n\nPassword strength: {entropy:.1f} bits"
        else:
            # Password is valid, but provide additional feedback
            feedback = "Password meets basic requirements, but consider:\n"
            
            if len(password) < 16:
                feedback += "- Using a longer password (16+ characters) for better security\n"
                
            if len(set(password)) < len(password) * 0.7:
                feedback += "- Using more unique characters (avoid repetition)\n"
                
            if re.search(r'(.)\1\1', password):
                feedback += "- Avoiding repeated character sequences\n"
                
            if entropy < self.ENTROPY_STRONG:
                feedback += f"- Adding more complexity to increase entropy ({entropy:.1f} bits)\n"
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
        str(importlib.resources.files('openssl_encrypt').joinpath('data/common_passwords.txt')),
        # Local module directory
        os.path.join(os.path.dirname(__file__), '../data/common_passwords.txt'),
        # Local project directory
        os.path.join(os.path.dirname(__file__), '../../data/common_passwords.txt'),
        # System paths
        '/usr/share/dict/words',
        '/usr/share/common-passwords/common-passwords.txt',
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
        
        Args:
            custom_path: Path to a custom common password list
        """
        self.password_hashes = set()
        self.loaded_at_least_one = False
        
        # Try to load passwords from custom path if provided
        if custom_path and os.path.exists(custom_path):
            self._load_password_list(custom_path)
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
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password and len(password) >= 6:  # Only store reasonably sized passwords
                        # Store SHA-256 hash of the password to save memory
                        self.password_hashes.add(hashlib.sha256(password.encode('utf-8')).digest())
        except Exception as e:
            # Don't raise exception if loading fails - just continue with what we have
            print(f"Warning: Could not load common password list from {path}: {e}")
    
    def _load_embedded_passwords(self) -> None:
        """Load the embedded password list."""
        try:
            # Process each password from the embedded list
            for password in self.EMBEDDED_PASSWORDS.splitlines():
                password = password.strip()
                if password and len(password) >= 6:
                    self.password_hashes.add(hashlib.sha256(password.encode('utf-8')).digest())
        except Exception as e:
            # If loading fails, just continue with an empty set
            print(f"Warning: Could not load embedded common password list: {e}")
    
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
        password_hash = hashlib.sha256(password.encode('utf-8')).digest()
        return password_hash in self.password_hashes


# Direct API functions for easy use
def validate_password(password: str, policy_level: str = "standard",
                     quiet: bool = False) -> Tuple[bool, List[str]]:
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


def validate_password_or_raise(password: str, policy_level: str = "standard",
                              quiet: bool = False) -> None:
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
    
    if entropy < PasswordPolicy.ENTROPY_VERY_WEAK:
        strength = "VERY WEAK"
    elif entropy < PasswordPolicy.ENTROPY_WEAK:
        strength = "WEAK"
    elif entropy < PasswordPolicy.ENTROPY_MODERATE:
        strength = "MODERATE"
    elif entropy < PasswordPolicy.ENTROPY_STRONG:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"
        
    return entropy, strength


if __name__ == "__main__":
    # Simple testing code
    import argparse
    
    parser = argparse.ArgumentParser(description="Password Policy Module - Test Tool")
    parser.add_argument("--password", "-p", help="Password to test")
    parser.add_argument("--level", "-l", choices=["minimal", "basic", "standard", "paranoid"],
                        default="standard", help="Policy level to test against")
    args = parser.parse_args()
    
    if not args.password:
        args.password = input("Enter password to test: ")
    
    policy = PasswordPolicy(policy_level=args.level)
    valid, msgs = policy.validate_password(args.password)
    
    print(f"\nTesting against '{args.level}' policy level:")
    for msg in msgs:
        print(f"- {msg}")
    
    if valid:
        print("\nResult: Password MEETS requirements ✓")
    else:
        print("\nResult: Password DOES NOT MEET requirements ✗")
        
    print("\nDetailed feedback:")
    print(policy.generate_feedback(args.password))