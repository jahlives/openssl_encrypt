#!/usr/bin/env python3
"""
Cryptography CLI Helper Module

This module provides helper functions for the CLI interface,
particularly for handling extended post-quantum algorithm options.
"""

import logging
from typing import Optional, Dict, Any, Union

# Configure logger
logger = logging.getLogger(__name__)

try:
    from .pqc_adapter import get_default_encryption_data, HYBRID_ALGORITHM_MAP
except ImportError:
    # Fallback if adapter is not available
    def get_default_encryption_data(algorithm: str) -> str:
        """Fallback implementation if adapter is not available"""
        return "aes-gcm"
    
    HYBRID_ALGORITHM_MAP = {}


def enhance_cli_args(args: Any) -> Any:
    """
    Enhance CLI arguments with better defaults for extended algorithms
    
    This function modifies the args object in-place to provide better defaults
    for the extended algorithms, while still respecting user choices.
    
    Args:
        args: The parsed command-line arguments
        
    Returns:
        The modified args object
    """
    # If no encryption_data is specified, set a default based on algorithm
    if hasattr(args, 'algorithm') and hasattr(args, 'encryption_data'):
        if args.algorithm and not args.encryption_data:
            # Only set default if user didn't specify a value
            args.encryption_data = get_default_encryption_data(args.algorithm)
            logger.debug(f"Using default encryption_data '{args.encryption_data}' for algorithm '{args.algorithm}'")
    
    return args


def add_extended_algorithm_help(parser: Any) -> None:
    """
    Add extended algorithm help text to the parser
    
    Args:
        parser: The argparse parser
    """
    # Get the existing help text for the algorithm argument
    if not hasattr(parser, '_actions'):
        return
    
    for action in parser._actions:
        if action.dest == 'algorithm':
            # Add information about the extended algorithms
            original_help = action.help
            extended_help = original_help + "\n\nExtended algorithms:\n"
            
            # Add info about ML-KEM with ChaCha20
            extended_help += "  ML-KEM with ChaCha20 (post-quantum):\n"
            extended_help += "    ml-kem-512-chacha20, ml-kem-768-chacha20, ml-kem-1024-chacha20\n"
            
            # Update the help text
            action.help = extended_help
            break