#!/usr/bin/env python3
"""
Post-Quantum Signature Algorithm Detection Module

This module provides runtime detection and compatibility mapping for 
post-quantum signature algorithms available through liboqs and our
demonstration implementations.
"""

import logging
from typing import Dict, List, Optional, Tuple

# Configure logger
logger = logging.getLogger(__name__)

# Algorithm variant mappings for different liboqs versions
MAYO_ALGORITHM_VARIANTS = {
    "MAYO-1": ["MAYO-1", "mayo1", "MAYO_1"],
    "MAYO-2": ["MAYO-2", "mayo2", "MAYO_2"], 
    "MAYO-3": ["MAYO-3", "mayo3", "MAYO_3"],
    "MAYO-5": ["MAYO-5", "mayo5", "MAYO_5"],
}

CROSS_ALGORITHM_VARIANTS = {
    "CROSS-128": [
        "cross-rsdp-128-balanced", 
        "cross-rsdp-128-fast", 
        "cross-rsdp-128-small",
        "CROSS-128",
        "cross128"
    ],
    "CROSS-192": [
        "cross-rsdp-192-balanced",
        "cross-rsdp-192-fast", 
        "cross-rsdp-192-small",
        "CROSS-192",
        "cross192"
    ],
    "CROSS-256": [
        "cross-rsdp-256-balanced",
        "cross-rsdp-256-fast",
        "cross-rsdp-256-small", 
        "CROSS-256",
        "cross256"
    ],
    # CROSS-G variants (different parameter sets)
    "CROSS-128-G": [
        "cross-rsdpg-128-balanced",
        "cross-rsdpg-128-fast",
        "cross-rsdpg-128-small"
    ],
    "CROSS-192-G": [
        "cross-rsdpg-192-balanced",
        "cross-rsdpg-192-fast", 
        "cross-rsdpg-192-small"
    ],
    "CROSS-256-G": [
        "cross-rsdpg-256-balanced",
        "cross-rsdpg-256-fast",
        "cross-rsdpg-256-small"
    ],
}

# Performance preference for CROSS variants
CROSS_VARIANT_PREFERENCE = {
    "balanced": 0,  # Best balance of size/speed
    "small": 1,     # Smaller signatures
    "fast": 2,      # Faster operations
}


class SignatureAlgorithmInfo:
    """Information about a signature algorithm's availability and implementation."""
    
    def __init__(self, algorithm: str, available: bool, implementation: str, 
                 liboqs_name: Optional[str] = None, key_sizes: Optional[Dict] = None):
        self.algorithm = algorithm
        self.available = available
        self.implementation = implementation  # "liboqs-production", "demo-fallback", "unavailable"
        self.liboqs_name = liboqs_name
        self.key_sizes = key_sizes or {}
    
    def __repr__(self):
        status = "✓" if self.available else "✗"
        return f"{self.algorithm}: {self.implementation} {status}"


def check_liboqs_availability() -> bool:
    """Check if liboqs-python is available."""
    try:
        import oqs
        return True
    except ImportError:
        return False


def get_liboqs_signature_algorithms() -> List[str]:
    """Get list of signature algorithms available in liboqs."""
    try:
        import oqs
        if hasattr(oqs, 'get_enabled_sig_mechanisms'):
            return list(oqs.get_enabled_sig_mechanisms())
        else:
            logger.warning("liboqs does not have get_enabled_sig_mechanisms method")
            return []
    except ImportError:
        logger.debug("liboqs not available")
        return []
    except Exception as e:
        logger.error(f"Error getting liboqs signature algorithms: {e}")
        return []


def detect_mayo_algorithms() -> Dict[str, SignatureAlgorithmInfo]:
    """Detect available MAYO algorithm variants."""
    results = {}
    
    if not check_liboqs_availability():
        # Return demo implementations only
        for standard_name in MAYO_ALGORITHM_VARIANTS.keys():
            results[standard_name] = SignatureAlgorithmInfo(
                algorithm=standard_name,
                available=True,
                implementation="demo-fallback"
            )
        return results
    
    available_sigs = get_liboqs_signature_algorithms()
    
    for standard_name, variants in MAYO_ALGORITHM_VARIANTS.items():
        found_variant = None
        
        # Try to find a matching variant in liboqs
        for variant in variants:
            if variant in available_sigs:
                found_variant = variant
                break
        
        if found_variant:
            # Test the algorithm to get key sizes
            key_sizes = _get_algorithm_key_sizes(found_variant)
            results[standard_name] = SignatureAlgorithmInfo(
                algorithm=standard_name,
                available=True,
                implementation="liboqs-production",
                liboqs_name=found_variant,
                key_sizes=key_sizes
            )
        else:
            # Fall back to demo implementation
            results[standard_name] = SignatureAlgorithmInfo(
                algorithm=standard_name,
                available=True,
                implementation="demo-fallback"
            )
    
    return results


def detect_cross_algorithms() -> Dict[str, SignatureAlgorithmInfo]:
    """Detect available CROSS algorithm variants."""
    results = {}
    
    if not check_liboqs_availability():
        # No demo implementation for CROSS yet
        for standard_name in CROSS_ALGORITHM_VARIANTS.keys():
            if not standard_name.endswith("-G"):  # Only basic variants for now
                results[standard_name] = SignatureAlgorithmInfo(
                    algorithm=standard_name,
                    available=False,
                    implementation="unavailable"
                )
        return results
    
    available_sigs = get_liboqs_signature_algorithms()
    
    for standard_name, variants in CROSS_ALGORITHM_VARIANTS.items():
        # Skip G variants for basic detection
        if standard_name.endswith("-G"):
            continue
            
        # Find best available variant (prefer balanced)
        found_variant = None
        for preference in ["balanced", "small", "fast"]:
            for variant in variants:
                if preference in variant and variant in available_sigs:
                    found_variant = variant
                    break
            if found_variant:
                break
        
        # If no preferred variant, take any available
        if not found_variant:
            for variant in variants:
                if variant in available_sigs:
                    found_variant = variant
                    break
        
        if found_variant:
            # Test the algorithm to get key sizes
            key_sizes = _get_algorithm_key_sizes(found_variant)
            results[standard_name] = SignatureAlgorithmInfo(
                algorithm=standard_name,
                available=True,
                implementation="liboqs-production",
                liboqs_name=found_variant,
                key_sizes=key_sizes
            )
        else:
            results[standard_name] = SignatureAlgorithmInfo(
                algorithm=standard_name,
                available=False,
                implementation="unavailable"
            )
    
    return results


def _get_algorithm_key_sizes(liboqs_name: str) -> Dict:
    """Get key and signature sizes for a liboqs algorithm."""
    try:
        import oqs
        sig = oqs.Signature(liboqs_name)
        
        # Generate temporary keypair to get sizes
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        
        # Generate temporary signature to get size
        test_message = b"test message for size measurement"
        signature = sig.sign(test_message)
        
        return {
            "public_key_size": len(public_key),
            "private_key_size": len(private_key),
            "signature_size": len(signature)
        }
    except Exception as e:
        logger.warning(f"Could not get key sizes for {liboqs_name}: {e}")
        return {}


def detect_all_signature_algorithms(quiet: bool = False) -> Dict[str, SignatureAlgorithmInfo]:
    """Detect all available signature algorithms."""
    results = {}
    
    # Detect MAYO algorithms
    mayo_results = detect_mayo_algorithms()
    results.update(mayo_results)
    
    # Detect CROSS algorithms  
    cross_results = detect_cross_algorithms()
    results.update(cross_results)
    
    if not quiet:
        logger.info(f"Detected {len(results)} signature algorithms")
        for name, info in results.items():
            logger.info(f"  {info}")
    
    return results


def get_algorithm_info(algorithm: str) -> Optional[SignatureAlgorithmInfo]:
    """Get information about a specific algorithm."""
    all_algorithms = detect_all_signature_algorithms(quiet=True)
    return all_algorithms.get(algorithm)


def list_available_algorithms(implementation_filter: Optional[str] = None) -> List[SignatureAlgorithmInfo]:
    """List available algorithms, optionally filtered by implementation type."""
    all_algorithms = detect_all_signature_algorithms(quiet=True)
    
    if implementation_filter:
        return [info for info in all_algorithms.values() 
                if implementation_filter in info.implementation]
    else:
        return [info for info in all_algorithms.values() if info.available]


def get_production_algorithms() -> List[SignatureAlgorithmInfo]:
    """Get only production-ready algorithms (liboqs-based)."""
    return list_available_algorithms("liboqs-production")


def get_demo_algorithms() -> List[SignatureAlgorithmInfo]:
    """Get only demonstration/educational algorithms."""
    return list_available_algorithms("demo-fallback")


def check_algorithm_compatibility(algorithm1: str, algorithm2: str) -> bool:
    """Check if two algorithms can interoperate (same underlying implementation)."""
    info1 = get_algorithm_info(algorithm1)
    info2 = get_algorithm_info(algorithm2)
    
    if not info1 or not info2:
        return False
    
    # Same implementation type and both available
    return (info1.implementation == info2.implementation and 
            info1.available and info2.available)


# Convenience functions for quick checks
def is_mayo_available(level: int) -> bool:
    """Check if MAYO at given security level is available."""
    algorithm = f"MAYO-{level}"
    info = get_algorithm_info(algorithm)
    return info is not None and info.available


def is_cross_available(level: int) -> bool:
    """Check if CROSS at given security level is available."""
    algorithm = f"CROSS-{level}"
    info = get_algorithm_info(algorithm)
    return info is not None and info.available


def get_best_available_algorithm(prefer_production: bool = True) -> Optional[str]:
    """Get the best available signature algorithm."""
    if prefer_production:
        production_algos = get_production_algorithms()
        if production_algos:
            # Prefer MAYO-1 for best balance of security and performance
            for algo in production_algos:
                if algo.algorithm == "MAYO-1":
                    return algo.algorithm
            # Return first available production algorithm
            return production_algos[0].algorithm
    
    # Fall back to demo algorithms
    demo_algos = get_demo_algorithms()
    if demo_algos:
        # Prefer MAYO-1 demo
        for algo in demo_algos:
            if algo.algorithm == "MAYO-1":
                return algo.algorithm
        return demo_algos[0].algorithm
    
    return None


if __name__ == "__main__":
    # Demo the detection system
    import sys
    
    print("Post-Quantum Signature Algorithm Detection")
    print("=" * 50)
    
    liboqs_available = check_liboqs_availability()
    print(f"LibOQS available: {liboqs_available}")
    
    if liboqs_available:
        available_sigs = get_liboqs_signature_algorithms()
        print(f"LibOQS signature algorithms: {len(available_sigs)}")
    
    print("\nDetected Algorithms:")
    print("-" * 30)
    
    all_algorithms = detect_all_signature_algorithms(quiet=True)
    for name, info in all_algorithms.items():
        status = "✓" if info.available else "✗"
        impl = info.implementation.replace("-", " ").title()
        
        size_info = ""
        if info.key_sizes:
            pub_size = info.key_sizes.get("public_key_size", "?")
            sig_size = info.key_sizes.get("signature_size", "?")
            size_info = f" (pub:{pub_size}B, sig:{sig_size}B)"
        
        print(f"{status} {name:12} - {impl:20} {size_info}")
    
    print(f"\nBest available algorithm: {get_best_available_algorithm()}")