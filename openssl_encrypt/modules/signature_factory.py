#!/usr/bin/env python3
"""
Signature Factory Module

This module provides a factory pattern for creating post-quantum signature
instances with automatic fallback between production (liboqs) and demo
implementations.
"""

import logging
from typing import Dict, List, Optional, Union

from .pqc_signatures import PQSignature
from .signature_detection import (
    get_algorithm_info,
    detect_all_signature_algorithms,
    check_liboqs_availability,
    get_production_algorithms,
    get_demo_algorithms,
)

logger = logging.getLogger(__name__)


class SignatureCreationError(Exception):
    """Exception raised when signature instance creation fails."""
    pass


class NoImplementationAvailableError(SignatureCreationError):
    """Exception raised when no implementation is available for an algorithm."""
    pass


class SignatureFactory:
    """
    Factory for creating signature instances with fallback support.
    
    This factory automatically selects the best available implementation:
    1. Production implementation (liboqs) if available
    2. Demo implementation as fallback
    3. Raises exception if no implementation exists
    """
    
    @staticmethod
    def create_signature(algorithm: str, prefer_production: bool = True) -> PQSignature:
        """
        Create signature instance with automatic implementation selection.
        
        Args:
            algorithm (str): Algorithm name (e.g., "MAYO-1", "CROSS-128")
            prefer_production (bool): Whether to prefer production over demo implementations
            
        Returns:
            PQSignature: Signature instance using the best available implementation
            
        Raises:
            NoImplementationAvailableError: If no implementation is available
            SignatureCreationError: If instance creation fails
        """
        algorithm_info = get_algorithm_info(algorithm)
        
        if not algorithm_info:
            raise NoImplementationAvailableError(f"Algorithm {algorithm} not recognized")
        
        if not algorithm_info.available:
            raise NoImplementationAvailableError(f"Algorithm {algorithm} not available")
        
        try:
            # Try production implementation first if preferred and available
            if prefer_production and algorithm_info.implementation == "liboqs-production":
                logger.debug(f"Creating production signature instance for {algorithm}")
                return SignatureFactory._create_production_signature(algorithm)
            
            # Try demo implementation
            elif algorithm_info.implementation == "demo-fallback":
                logger.debug(f"Creating demo signature instance for {algorithm}")
                return SignatureFactory._create_demo_signature(algorithm)
            
            # If production not preferred, try demo first
            elif not prefer_production and algorithm_info.implementation == "demo-fallback":
                logger.debug(f"Creating demo signature instance for {algorithm}")
                return SignatureFactory._create_demo_signature(algorithm)
            
            # Fall back to production if demo not available
            elif algorithm_info.implementation == "liboqs-production":
                logger.debug(f"Falling back to production signature instance for {algorithm}")
                return SignatureFactory._create_production_signature(algorithm)
            
            else:
                raise NoImplementationAvailableError(
                    f"No suitable implementation available for {algorithm} "
                    f"(detected: {algorithm_info.implementation})"
                )
                
        except Exception as e:
            if isinstance(e, (NoImplementationAvailableError, SignatureCreationError)):
                raise
            raise SignatureCreationError(f"Failed to create signature instance for {algorithm}: {e}")
    
    @staticmethod
    def _create_production_signature(algorithm: str) -> PQSignature:
        """Create production signature instance using liboqs."""
        try:
            from .stateful_signature import StatefulProductionSignature
            return StatefulProductionSignature(algorithm)
        except ImportError as e:
            raise SignatureCreationError(f"Production signature module not available: {e}")
        except Exception as e:
            raise SignatureCreationError(f"Failed to create production signature for {algorithm}: {e}")
    
    @staticmethod
    def _create_demo_signature(algorithm: str) -> PQSignature:
        """Create demo signature instance."""
        try:
            # Extract algorithm type and level
            if algorithm.startswith("MAYO-"):
                level_str = algorithm.split("-")[1]
                level = int(level_str)
                from .mayo_signature import MAYOSignature
                return MAYOSignature(level)
            
            elif algorithm.startswith("CROSS-"):
                # CROSS demo implementation not yet available
                raise NoImplementationAvailableError(f"Demo implementation for {algorithm} not yet available")
            
            else:
                raise NoImplementationAvailableError(f"Unknown algorithm type: {algorithm}")
                
        except ValueError as e:
            raise SignatureCreationError(f"Invalid algorithm specification {algorithm}: {e}")
        except ImportError as e:
            raise SignatureCreationError(f"Demo signature module not available: {e}")
        except Exception as e:
            raise SignatureCreationError(f"Failed to create demo signature for {algorithm}: {e}")
    
    @staticmethod
    def create_production_signature(algorithm: str) -> PQSignature:
        """
        Create production signature instance (liboqs only).
        
        Args:
            algorithm (str): Algorithm name
            
        Returns:
            PQSignature: Production signature instance
            
        Raises:
            NoImplementationAvailableError: If production implementation not available
        """
        algorithm_info = get_algorithm_info(algorithm)
        
        if not algorithm_info or not algorithm_info.available:
            raise NoImplementationAvailableError(f"Algorithm {algorithm} not available")
        
        if algorithm_info.implementation != "liboqs-production":
            raise NoImplementationAvailableError(
                f"Production implementation not available for {algorithm} "
                f"(available: {algorithm_info.implementation})"
            )
        
        return SignatureFactory._create_production_signature(algorithm)
    
    @staticmethod
    def create_demo_signature(algorithm: str) -> PQSignature:
        """
        Create demo signature instance (demo only).
        
        Args:
            algorithm (str): Algorithm name
            
        Returns:
            PQSignature: Demo signature instance
            
        Raises:
            NoImplementationAvailableError: If demo implementation not available
        """
        algorithm_info = get_algorithm_info(algorithm)
        
        if not algorithm_info:
            raise NoImplementationAvailableError(f"Algorithm {algorithm} not recognized")
        
        if algorithm_info.implementation not in ["demo-fallback", "liboqs-production"]:
            raise NoImplementationAvailableError(f"No demo available for {algorithm}")
        
        return SignatureFactory._create_demo_signature(algorithm)
    
    @staticmethod
    def list_available_algorithms() -> Dict[str, str]:
        """
        List all available algorithms and their implementation types.
        
        Returns:
            Dict[str, str]: Mapping of algorithm name to implementation type
        """
        algorithms = {}
        all_algorithms = detect_all_signature_algorithms(quiet=True)
        
        for name, info in all_algorithms.items():
            if info.available:
                if info.implementation == "liboqs-production":
                    algorithms[name] = "production (liboqs)"
                elif info.implementation == "demo-fallback":
                    algorithms[name] = "demo (educational)"
                else:
                    algorithms[name] = info.implementation
        
        return algorithms
    
    @staticmethod
    def list_production_algorithms() -> List[str]:
        """
        List algorithms available in production mode.
        
        Returns:
            List[str]: Algorithm names with production implementations
        """
        production_algos = get_production_algorithms()
        return [algo.algorithm for algo in production_algos]
    
    @staticmethod
    def list_demo_algorithms() -> List[str]:
        """
        List algorithms available in demo mode.
        
        Returns:
            List[str]: Algorithm names with demo implementations
        """
        demo_algos = get_demo_algorithms()
        return [algo.algorithm for algo in demo_algos]
    
    @staticmethod
    def is_production_available(algorithm: str) -> bool:
        """
        Check if production implementation is available for an algorithm.
        
        Args:
            algorithm (str): Algorithm name
            
        Returns:
            bool: True if production implementation available
        """
        try:
            algorithm_info = get_algorithm_info(algorithm)
            return (algorithm_info is not None and 
                    algorithm_info.available and 
                    algorithm_info.implementation == "liboqs-production")
        except Exception:
            return False
    
    @staticmethod
    def is_demo_available(algorithm: str) -> bool:
        """
        Check if demo implementation is available for an algorithm.
        
        Args:
            algorithm (str): Algorithm name
            
        Returns:
            bool: True if demo implementation available
        """
        try:
            algorithm_info = get_algorithm_info(algorithm)
            if not algorithm_info:
                return False
            
            # Demo implementations are available for MAYO
            if algorithm.startswith("MAYO-"):
                return True
            
            # CROSS demo not implemented yet
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_implementation_info(algorithm: str) -> Optional[Dict]:
        """
        Get detailed implementation information for an algorithm.
        
        Args:
            algorithm (str): Algorithm name
            
        Returns:
            Optional[Dict]: Implementation details or None if not available
        """
        algorithm_info = get_algorithm_info(algorithm)
        if not algorithm_info:
            return None
        
        return {
            "algorithm": algorithm_info.algorithm,
            "available": algorithm_info.available,
            "implementation": algorithm_info.implementation,
            "liboqs_name": algorithm_info.liboqs_name,
            "key_sizes": algorithm_info.key_sizes,
            "production_available": SignatureFactory.is_production_available(algorithm),
            "demo_available": SignatureFactory.is_demo_available(algorithm),
        }


# Convenience functions
def create_signature(algorithm: str, prefer_production: bool = True) -> PQSignature:
    """
    Convenience function to create signature instance.
    
    Args:
        algorithm (str): Algorithm name
        prefer_production (bool): Whether to prefer production implementations
        
    Returns:
        PQSignature: Signature instance
    """
    return SignatureFactory.create_signature(algorithm, prefer_production)


def create_best_signature(algorithms: List[str]) -> PQSignature:
    """
    Create signature instance using the best available algorithm from a list.
    
    Args:
        algorithms (List[str]): Preferred algorithms in order of preference
        
    Returns:
        PQSignature: Signature instance for first available algorithm
        
    Raises:
        NoImplementationAvailableError: If no algorithms are available
    """
    for algorithm in algorithms:
        try:
            return SignatureFactory.create_signature(algorithm)
        except NoImplementationAvailableError:
            continue
    
    raise NoImplementationAvailableError(f"None of the algorithms are available: {algorithms}")


if __name__ == "__main__":
    # Demo the signature factory system
    print("Signature Factory Demo")
    print("=" * 30)
    
    # List available algorithms
    available = SignatureFactory.list_available_algorithms()
    print(f"Available algorithms:")
    for name, impl in available.items():
        print(f"  {name}: {impl}")
    
    print(f"\nProduction algorithms: {SignatureFactory.list_production_algorithms()}")
    print(f"Demo algorithms: {SignatureFactory.list_demo_algorithms()}")
    
    # Test creating signatures
    test_algorithms = ["MAYO-1", "MAYO-3", "CROSS-128"]
    
    for algorithm in test_algorithms:
        try:
            print(f"\nTesting {algorithm}:")
            
            # Get implementation info
            info = SignatureFactory.get_implementation_info(algorithm)
            if info:
                print(f"  Implementation: {info['implementation']}")
                print(f"  Production available: {info['production_available']}")
                print(f"  Demo available: {info['demo_available']}")
                
                # Try to create instance
                sig = SignatureFactory.create_signature(algorithm)
                print(f"  Created: {sig.get_algorithm_name()}")
                print(f"  Security level: {sig.get_security_level()}")
                print(f"  Key sizes: pub={sig.get_public_key_size()}B, priv={sig.get_private_key_size()}B")
                
                # Test basic operations
                public_key, private_key = sig.generate_keypair()
                message = b"Hello from signature factory!"
                signature = sig.sign(message, private_key)
                is_valid = sig.verify(message, signature, public_key)
                print(f"  Test signature: {len(signature)}B, valid={is_valid}")
            else:
                print(f"  Not available")
                
        except Exception as e:
            print(f"  Error: {e}")