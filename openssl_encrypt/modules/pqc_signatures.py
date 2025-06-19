#!/usr/bin/env python3
"""
Post-Quantum Cryptography Signature Module

This module provides base classes and interfaces for post-quantum signature schemes,
including MAYO (multivariate-based) and CROSS (code-based) algorithms.
"""

import hashlib
import secrets
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Union

from .secure_memory import SecureBytes, secure_memzero


class PQSignature(ABC):
    """
    Base class for post-quantum signature schemes.
    
    This abstract class defines the common interface that all post-quantum
    signature implementations must follow.
    """
    
    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a public/private key pair for the signature algorithm.
        
        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement generate_keypair")
    
    @abstractmethod
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using the private key.
        
        Args:
            message (bytes): The message to sign
            private_key (bytes): The private signing key
            
        Returns:
            bytes: The signature
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
            ValueError: If private key is invalid or signing fails
        """
        raise NotImplementedError("Subclasses must implement sign")
    
    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature against a message using the public key.
        
        Args:
            message (bytes): The original message
            signature (bytes): The signature to verify
            public_key (bytes): The public verification key
            
        Returns:
            bool: True if signature is valid, False otherwise
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement verify")
    
    @abstractmethod
    def get_algorithm_name(self) -> str:
        """
        Get the algorithm identifier string.
        
        Returns:
            str: The algorithm name (e.g., "MAYO-1", "CROSS-128")
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement get_algorithm_name")
    
    @abstractmethod
    def get_public_key_size(self) -> int:
        """
        Get the size of public keys for this algorithm.
        
        Returns:
            int: Public key size in bytes
        """
        raise NotImplementedError("Subclasses must implement get_public_key_size")
    
    @abstractmethod
    def get_private_key_size(self) -> int:
        """
        Get the size of private keys for this algorithm.
        
        Returns:
            int: Private key size in bytes
        """
        raise NotImplementedError("Subclasses must implement get_private_key_size")
    
    @abstractmethod
    def get_signature_size(self) -> int:
        """
        Get the size of signatures for this algorithm.
        
        Returns:
            int: Signature size in bytes
        """
        raise NotImplementedError("Subclasses must implement get_signature_size")
    
    def get_security_level(self) -> int:
        """
        Get the NIST security level for this algorithm.
        
        Returns:
            int: NIST security level (1, 3, or 5)
        """
        # Default implementation - subclasses should override
        return 1
    
    def validate_key_sizes(self, public_key: bytes, private_key: bytes) -> bool:
        """
        Validate that key sizes match algorithm specifications.
        
        Args:
            public_key (bytes): The public key to validate
            private_key (bytes): The private key to validate
            
        Returns:
            bool: True if key sizes are correct
        """
        return (len(public_key) == self.get_public_key_size() and 
                len(private_key) == self.get_private_key_size())
    
    def validate_signature_size(self, signature: bytes) -> bool:
        """
        Validate that signature size matches algorithm specifications.
        
        Args:
            signature (bytes): The signature to validate
            
        Returns:
            bool: True if signature size is correct
        """
        return len(signature) == self.get_signature_size()


class PQSignatureError(Exception):
    """Base exception class for post-quantum signature operations."""
    pass


class KeyGenerationError(PQSignatureError):
    """Exception raised when key generation fails."""
    pass


class SigningError(PQSignatureError):
    """Exception raised when signing operation fails."""
    pass


class VerificationError(PQSignatureError):
    """Exception raised when signature verification fails."""
    pass


class InvalidKeyError(PQSignatureError):
    """Exception raised when provided keys are invalid."""
    pass


class InvalidSignatureError(PQSignatureError):
    """Exception raised when provided signature is invalid."""
    pass


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length (int): Number of bytes to generate
        
    Returns:
        bytes: Secure random bytes
    """
    return secrets.token_bytes(length)


def hash_message(message: bytes, algorithm: str = "sha256") -> bytes:
    """
    Hash a message using the specified algorithm.
    
    Args:
        message (bytes): The message to hash
        algorithm (str): Hash algorithm to use (default: sha256)
        
    Returns:
        bytes: The hash digest
    """
    if algorithm == "sha256":
        return hashlib.sha256(message).digest()
    elif algorithm == "sha512":
        return hashlib.sha512(message).digest()
    elif algorithm == "sha3_256":
        return hashlib.sha3_256(message).digest()
    elif algorithm == "sha3_512":
        return hashlib.sha3_512(message).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
    Args:
        a (bytes): First byte sequence
        b (bytes): Second byte sequence
        
    Returns:
        bool: True if sequences are equal
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0