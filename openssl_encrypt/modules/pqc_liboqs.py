#!/usr/bin/env python3
"""
Post-Quantum Cryptography Integration with liboqs

This module provides integration with the Open Quantum Safe (OQS) liboqs library
through its Python bindings, enabling support for additional post-quantum
algorithms beyond our current ML-KEM (Kyber) implementation.

Dependencies:
- liboqs-python (pip install liboqs)
"""

import os
import sys
import hashlib
import secrets
import logging
from enum import Enum
from typing import Tuple, Optional, Dict, List, Any, Union, cast

# Configure logger
logger = logging.getLogger(__name__)

# Try to import liboqs, with graceful fallback
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    oqs = None  # type: ignore

# Environment variable to control initialization messages
LIBOQS_QUIET = os.environ.get('LIBOQS_QUIET', '').lower() in ('1', 'true', 'yes', 'on')


class PQAlgorithm(Enum):
    """
    Enumeration of supported post-quantum algorithms.
    Includes both our native implementations and liboqs-supported algorithms.
    """
    # Key Encapsulation Mechanisms (KEMs)
    # ML-KEM (formerly Kyber) - FIPS 203
    ML_KEM_512 = "ML-KEM-512"     # Level 1 (AES-128 equivalent)
    ML_KEM_768 = "ML-KEM-768"     # Level 3 (AES-192 equivalent)
    ML_KEM_1024 = "ML-KEM-1024"   # Level 5 (AES-256 equivalent)
    
    # Legacy Kyber names (kept for backward compatibility)
    KYBER_512 = "Kyber512"
    KYBER_768 = "Kyber768" 
    KYBER_1024 = "Kyber1024"
    
    # HQC - NIST selection March 2025, standard forthcoming
    HQC_128 = "HQC-128"   # Level 1
    HQC_192 = "HQC-192"   # Level 3
    HQC_256 = "HQC-256"   # Level 5
    
    # Digital Signature Algorithms (DSAs)
    # ML-DSA (formerly Dilithium) - FIPS 204
    ML_DSA_44 = "ML-DSA-44"     # Level 1
    ML_DSA_65 = "ML-DSA-65"     # Level 3 
    ML_DSA_87 = "ML-DSA-87"     # Level 5
    
    # SLH-DSA (formerly SPHINCS+) - FIPS 205
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128F"   # Level 1
    SLH_DSA_SHA2_192F = "SLH-DSA-SHA2-192F"   # Level 3
    SLH_DSA_SHA2_256F = "SLH-DSA-SHA2-256F"   # Level 5
    
    # FN-DSA (formerly Falcon) - FIPS 206 (forthcoming)
    FN_DSA_512 = "FN-DSA-512"     # Level 1
    FN_DSA_1024 = "FN-DSA-1024"   # Level 5 (no middle level defined)


# Mapping from our enum values to liboqs algorithm names
LIBOQS_ALGORITHM_MAPPING: Dict[str, str] = {
    # KEMs
    "ML-KEM-512": "ML_KEM_512",
    "ML-KEM-768": "ML_KEM_768",
    "ML-KEM-1024": "ML_KEM_1024",
    "Kyber512": "Kyber512",  # Legacy names still supported in liboqs
    "Kyber768": "Kyber768",
    "Kyber1024": "Kyber1024",
    "HQC-128": "HQC-128",
    "HQC-192": "HQC-192",
    "HQC-256": "HQC-256",
    
    # Signatures
    "ML-DSA-44": "ML_DSA_44",
    "ML-DSA-65": "ML_DSA_65",
    "ML-DSA-87": "ML_DSA_87",
    "SLH-DSA-SHA2-128F": "SLH-DSA-SHA2-128F",
    "SLH-DSA-SHA2-192F": "SLH-DSA-SHA2-192F",
    "SLH-DSA-SHA2-256F": "SLH-DSA-SHA2-256F",
    "FN-DSA-512": "Falcon-512",
    "FN-DSA-1024": "Falcon-1024"
}


def check_liboqs_support(quiet: bool = False) -> Tuple[bool, Optional[str], List[str]]:
    """
    Check if liboqs is available and which algorithms are supported.
    
    Args:
        quiet: Whether to suppress output messages
        
    Returns:
        tuple: (is_available, version, supported_algorithms)
    """
    # Respect both parameter and environment variable
    should_be_quiet = quiet or LIBOQS_QUIET
    
    if not LIBOQS_AVAILABLE:
        if not should_be_quiet:
            logger.warning("liboqs-python is not available. Install with: pip install liboqs")
        return False, None, []
    
    try:
        # Get liboqs version
        version = oqs.get_version() if hasattr(oqs, 'get_version') else "unknown"
        
        # Get supported algorithms
        supported_algorithms = []
        
        # Check KEM algorithms
        if hasattr(oqs, 'get_enabled_kem_mechanisms'):
            supported_algorithms.extend(oqs.get_enabled_kem_mechanisms())
        
        # Check signature algorithms
        if hasattr(oqs, 'get_enabled_sig_mechanisms'):
            supported_algorithms.extend(oqs.get_enabled_sig_mechanisms())
        
        # Log available algorithms if not quiet
        if not should_be_quiet:
            logger.info(f"liboqs version {version} available with {len(supported_algorithms)} algorithms")
            logger.info(f"Supported algorithms: {', '.join(supported_algorithms)}")
        
        return True, version, supported_algorithms
    except Exception as e:
        if not should_be_quiet:
            logger.error(f"Error checking liboqs support: {e}")
        return False, None, []


class PQEncapsulator:
    """
    Wrapper class for post-quantum key encapsulation mechanisms (KEMs)
    using liboqs.
    """
    def __init__(self, algorithm: Union[PQAlgorithm, str], quiet: bool = False):
        """
        Initialize a post-quantum KEM wrapper.
        
        Args:
            algorithm: The post-quantum algorithm to use
            quiet: Whether to suppress output messages
            
        Raises:
            ImportError: If liboqs is not available
            ValueError: If the algorithm is not supported
        """
        # Check if liboqs is available
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for additional post-quantum algorithms. "
                             "Install with: pip install liboqs")
        
        # Convert algorithm to string if it's an enum
        if isinstance(algorithm, PQAlgorithm):
            algorithm_str = algorithm.value
        else:
            algorithm_str = algorithm
        
        # Map our algorithm name to liboqs algorithm name
        if algorithm_str in LIBOQS_ALGORITHM_MAPPING:
            liboqs_algorithm = LIBOQS_ALGORITHM_MAPPING[algorithm_str]
        else:
            # Try to use the algorithm name directly
            liboqs_algorithm = algorithm_str
        
        # Check if the algorithm is supported by liboqs
        supported_algorithms = check_liboqs_support(quiet=True)[2]
        if liboqs_algorithm not in supported_algorithms:
            raise ValueError(f"Algorithm '{liboqs_algorithm}' is not supported by liboqs. "
                            f"Supported algorithms: {', '.join(supported_algorithms)}")
        
        self.algorithm = algorithm_str
        self.liboqs_algorithm = liboqs_algorithm
        self.quiet = quiet
        
        # Initialize KEM
        self.kem = oqs.KeyEncapsulation(liboqs_algorithm)
        
        if not quiet:
            logger.info(f"Initialized {algorithm_str} encapsulator using liboqs")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a key pair for the KEM.
        
        Returns:
            tuple: (public_key, secret_key)
        """
        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()
        return public_key, secret_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the public key.
        
        Args:
            public_key: The public key to use for encapsulation
            
        Returns:
            tuple: (ciphertext, shared_secret)
        """
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Decapsulate a shared secret using the secret key.
        
        Args:
            ciphertext: The ciphertext to decapsulate
            secret_key: The secret key to use (if not provided during initialization)
            
        Returns:
            bytes: The shared secret
        """
        if secret_key is not None:
            # Set the secret key if provided
            self.kem.import_secret_key(secret_key)
        
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret
    
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        if hasattr(self, 'kem') and self.kem is not None:
            self.kem.free()


class PQSigner:
    """
    Wrapper class for post-quantum digital signature algorithms (DSAs)
    using liboqs.
    """
    def __init__(self, algorithm: Union[PQAlgorithm, str], quiet: bool = False):
        """
        Initialize a post-quantum DSA wrapper.
        
        Args:
            algorithm: The post-quantum algorithm to use
            quiet: Whether to suppress output messages
            
        Raises:
            ImportError: If liboqs is not available
            ValueError: If the algorithm is not supported
        """
        # Check if liboqs is available
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for additional post-quantum algorithms. "
                             "Install with: pip install liboqs")
        
        # Convert algorithm to string if it's an enum
        if isinstance(algorithm, PQAlgorithm):
            algorithm_str = algorithm.value
        else:
            algorithm_str = algorithm
        
        # Map our algorithm name to liboqs algorithm name
        if algorithm_str in LIBOQS_ALGORITHM_MAPPING:
            liboqs_algorithm = LIBOQS_ALGORITHM_MAPPING[algorithm_str]
        else:
            # Try to use the algorithm name directly
            liboqs_algorithm = algorithm_str
        
        # Check if the algorithm is supported by liboqs
        supported_algorithms = check_liboqs_support(quiet=True)[2]
        if liboqs_algorithm not in supported_algorithms:
            raise ValueError(f"Algorithm '{liboqs_algorithm}' is not supported by liboqs. "
                            f"Supported algorithms: {', '.join(supported_algorithms)}")
        
        self.algorithm = algorithm_str
        self.liboqs_algorithm = liboqs_algorithm
        self.quiet = quiet
        
        # Initialize Signature
        self.sig = oqs.Signature(liboqs_algorithm)
        
        if not quiet:
            logger.info(f"Initialized {algorithm_str} signer using liboqs")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a key pair for the DSA.
        
        Returns:
            tuple: (public_key, secret_key)
        """
        public_key = self.sig.generate_keypair()
        secret_key = self.sig.export_secret_key()
        return public_key, secret_key
    
    def sign(self, message: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Sign a message using the secret key.
        
        Args:
            message: The message to sign
            secret_key: The secret key to use (if not provided during initialization)
            
        Returns:
            bytes: The signature
        """
        if secret_key is not None:
            # Set the secret key if provided
            self.sig.import_secret_key(secret_key)
        
        signature = self.sig.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using the public key.
        
        Args:
            message: The message that was signed
            signature: The signature to verify
            public_key: The public key to use for verification
            
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        return self.sig.verify(message, signature, public_key)
    
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        if hasattr(self, 'sig') and self.sig is not None:
            self.sig.free()


# Simple usage example
def example_usage():
    """Example usage of the PQ algorithm wrappers."""
    # Check if liboqs is available
    available, version, algorithms = check_liboqs_support()
    if not available:
        print("liboqs is not available. Install with: pip install liboqs")
        return
    
    print(f"liboqs version {version} available")
    print(f"Supported algorithms: {', '.join(algorithms[:5])}... (and {len(algorithms)-5} more)")
    
    # Example with KEM
    try:
        # Try with ML-KEM-512 first
        algorithm = "ML-KEM-512" if "ML_KEM_512" in algorithms else "Kyber512"
        print(f"\nTesting KEM with {algorithm}:")
        
        kem = PQEncapsulator(algorithm)
        
        # Generate a key pair
        public_key, secret_key = kem.generate_keypair()
        print(f"  Generated key pair: public key size={len(public_key)} bytes, "
              f"secret key size={len(secret_key)} bytes")
        
        # Encapsulate a shared secret
        ciphertext, shared_secret = kem.encapsulate(public_key)
        print(f"  Encapsulated shared secret: ciphertext size={len(ciphertext)} bytes, "
              f"shared secret size={len(shared_secret)} bytes")
        
        # Decapsulate the shared secret
        decapsulated_secret = kem.decapsulate(ciphertext, secret_key)
        print(f"  Decapsulated shared secret: size={len(decapsulated_secret)} bytes")
        
        # Verify that the shared secrets match
        if shared_secret == decapsulated_secret:
            print("  Success: Shared secrets match!")
        else:
            print("  Error: Shared secrets do not match!")
    except Exception as e:
        print(f"  Error testing KEM: {e}")
    
    # Example with DSA
    try:
        # Try with ML-DSA-44 first
        algorithm = "ML-DSA-44" if "ML_DSA_44" in algorithms else "Dilithium2"
        print(f"\nTesting DSA with {algorithm}:")
        
        dsa = PQSigner(algorithm)
        
        # Generate a key pair
        public_key, secret_key = dsa.generate_keypair()
        print(f"  Generated key pair: public key size={len(public_key)} bytes, "
              f"secret key size={len(secret_key)} bytes")
        
        # Sign a message
        message = b"Hello, post-quantum world!"
        signature = dsa.sign(message, secret_key)
        print(f"  Signed message: signature size={len(signature)} bytes")
        
        # Verify the signature
        is_valid = dsa.verify(message, signature, public_key)
        print(f"  Signature verification: {'Valid' if is_valid else 'Invalid'}")
        
        # Try verifying with a modified message
        modified_message = b"Hello, post-quantum world!!"
        is_valid = dsa.verify(modified_message, signature, public_key)
        print(f"  Modified message verification: {'Valid' if is_valid else 'Invalid'} (should be Invalid)")
    except Exception as e:
        print(f"  Error testing DSA: {e}")


if __name__ == "__main__":
    example_usage()