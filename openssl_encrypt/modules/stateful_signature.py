#!/usr/bin/env python3
"""
Stateful Production Signature Implementation

This module provides a better approach to liboqs integration by maintaining
stateful signature instances that keep the private key state internally.
"""

import logging
from typing import Tuple, Optional

from .pqc_signatures import (
    PQSignature,
    KeyGenerationError,
    SigningError,
    VerificationError,
    InvalidKeyError,
)
from .signature_detection import (
    get_algorithm_info,
    check_liboqs_availability,
)

logger = logging.getLogger(__name__)


class StatefulProductionSignature(PQSignature):
    """
    Stateful production signature that maintains liboqs instance state.
    
    This approach works better with liboqs API by keeping the signature
    instance alive and maintaining the private key state internally.
    """
    
    def __init__(self, algorithm: str):
        """Initialize stateful signature instance."""
        self.algorithm = algorithm
        self.algorithm_info = get_algorithm_info(algorithm)
        
        if not self.algorithm_info or not self.algorithm_info.available:
            raise ValueError(f"Algorithm {algorithm} not available")
        
        if self.algorithm_info.implementation != "liboqs-production":
            raise ValueError(f"Algorithm {algorithm} not available in production mode")
        
        import oqs
        self.oqs = oqs
        self.liboqs_name = self.algorithm_info.liboqs_name
        
        # Signature instance state
        self._signature_instance = None
        self._public_key = None
        self._private_key = None
        self._has_keypair = False
    
    def get_algorithm_name(self) -> str:
        return self.algorithm
    
    def get_public_key_size(self) -> int:
        if self.algorithm_info.key_sizes:
            return self.algorithm_info.key_sizes.get("public_key_size", 0)
        return 0
    
    def get_private_key_size(self) -> int:
        if self.algorithm_info.key_sizes:
            return self.algorithm_info.key_sizes.get("private_key_size", 0)
        return 0
    
    def get_signature_size(self) -> int:
        if self.algorithm_info.key_sizes:
            return self.algorithm_info.key_sizes.get("signature_size", 0)
        return 0
    
    def get_security_level(self) -> int:
        if "1" in self.algorithm or "128" in self.algorithm:
            return 1
        elif "3" in self.algorithm or "192" in self.algorithm:
            return 3
        elif "5" in self.algorithm or "256" in self.algorithm:
            return 5
        return 1
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate keypair and maintain state internally."""
        try:
            # Create fresh signature instance
            self._signature_instance = self.oqs.Signature(self.liboqs_name)
            
            # Generate keypair
            self._public_key = self._signature_instance.generate_keypair()
            self._private_key = self._signature_instance.export_secret_key()
            self._has_keypair = True
            
            logger.debug(f"Generated {self.algorithm} keypair with stateful instance")
            
            return self._public_key, self._private_key
            
        except Exception as e:
            self._cleanup()
            raise KeyGenerationError(f"Keypair generation failed for {self.algorithm}: {e}")
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message (must use private key from this instance)."""
        if not self._has_keypair:
            raise SigningError("No keypair available - call generate_keypair() first")
        
        # Verify this is the correct private key
        if private_key != self._private_key:
            raise InvalidKeyError(
                "Private key doesn't match this instance. "
                "Use the private key returned by generate_keypair() from this instance."
            )
        
        try:
            signature = self._signature_instance.sign(message)
            logger.debug(f"Signed with {self.algorithm}: signature={len(signature)}B")
            return signature
            
        except Exception as e:
            raise SigningError(f"Signing failed for {self.algorithm}: {e}")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature (can use any public key)."""
        try:
            # Create temporary instance for verification
            temp_sig = self.oqs.Signature(self.liboqs_name)
            result = temp_sig.verify(message, signature, public_key)
            
            logger.debug(f"Verified with {self.algorithm}: valid={result}")
            return bool(result)
            
        except Exception as e:
            logger.debug(f"Verification failed for {self.algorithm}: {e}")
            return False
    
    def _cleanup(self):
        """Clean up internal state."""
        self._signature_instance = None
        self._public_key = None
        self._private_key = None
        self._has_keypair = False
    
    def __del__(self):
        """Cleanup on destruction."""
        self._cleanup()


class SignatureInstanceManager:
    """
    Manager for signature instances that provides a more traditional API.
    
    This class creates and manages stateful signature instances to provide
    a more familiar sign/verify interface while working with liboqs limitations.
    """
    
    def __init__(self):
        self._instances = {}
    
    def create_signature(self, algorithm: str) -> StatefulProductionSignature:
        """Create a new signature instance."""
        return StatefulProductionSignature(algorithm)
    
    def sign_with_keypair(self, algorithm: str, message: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Generate keypair and sign message in one operation.
        
        Returns:
            Tuple[bytes, bytes, bytes]: (signature, public_key, private_key)
        """
        sig = self.create_signature(algorithm)
        public_key, private_key = sig.generate_keypair()
        signature = sig.sign(message, private_key)
        return signature, public_key, private_key
    
    def verify_signature(self, algorithm: str, message: bytes, signature: bytes, 
                        public_key: bytes) -> bool:
        """Verify a signature (stateless operation)."""
        sig = self.create_signature(algorithm)
        return sig.verify(message, signature, public_key)


def create_signature_for_signing(algorithm: str) -> StatefulProductionSignature:
    """
    Create a signature instance specifically for signing operations.
    
    This is the recommended way to create signature instances when you
    plan to generate keys and sign with them.
    """
    return StatefulProductionSignature(algorithm)


def verify_standalone_signature(algorithm: str, message: bytes, signature: bytes, 
                               public_key: bytes) -> bool:
    """
    Verify a signature without maintaining state.
    
    This is a convenience function for one-off verification operations.
    """
    manager = SignatureInstanceManager()
    return manager.verify_signature(algorithm, message, signature, public_key)


if __name__ == "__main__":
    # Demo the stateful signature system
    print("Stateful Production Signature Demo")
    print("=" * 40)
    
    try:
        # Test MAYO-1
        algorithm = "MAYO-1"
        print(f"Testing {algorithm}...")
        
        # Create signature instance
        sig = create_signature_for_signing(algorithm)
        print(f"Created signature instance for {algorithm}")
        
        # Generate keypair
        public_key, private_key = sig.generate_keypair()
        print(f"Generated keypair: pub={len(public_key)}B, priv={len(private_key)}B")
        
        # Sign message
        message = b"Hello from stateful signature!"
        signature = sig.sign(message, private_key)
        print(f"Signed message: signature={len(signature)}B")
        
        # Verify signature
        is_valid = sig.verify(message, signature, public_key)
        print(f"Signature valid: {is_valid}")
        
        # Test standalone verification
        is_valid_standalone = verify_standalone_signature(algorithm, message, signature, public_key)
        print(f"Standalone verification: {is_valid_standalone}")
        
        # Test manager approach
        manager = SignatureInstanceManager()
        signature2, public_key2, private_key2 = manager.sign_with_keypair(algorithm, message)
        print(f"Manager signing: signature={len(signature2)}B")
        
        is_valid2 = manager.verify_signature(algorithm, message, signature2, public_key2)
        print(f"Manager verification: {is_valid2}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()