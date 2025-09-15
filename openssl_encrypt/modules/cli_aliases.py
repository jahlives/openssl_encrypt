#!/usr/bin/env python3
"""
CLI Syntax Aliases for OpenSSL Encrypt

This module provides simplified CLI aliases that map user-friendly options
to the full set of cryptographic parameters. This enables users to choose
security levels without needing to understand the underlying cryptographic
details while maintaining backward compatibility with existing CLI parameters.

Design Philosophy:
- Aliases map to full parameter sets for consistency
- All aliases produce identical metadata to their full parameter equivalents
- Progressive complexity: simple aliases for beginners, detailed control for experts
- Clear naming that indicates security/performance trade-offs
"""

import argparse
from typing import Dict, List, Tuple, Any, Optional


class CLIAliasConfig:
    """Configuration class for CLI aliases with security levels and performance characteristics."""
    
    # Security level aliases - progressive security/performance trade-offs
    SECURITY_ALIASES = {
        'fast': {
            'description': 'Fast encryption with adequate security for everyday use',
            'template': 'quick',
            'algorithm': 'aes-gcm',
            'security_level': 'moderate',
            'performance': 'high'
        },
        'secure': {
            'description': 'Balanced security and performance for important files',
            'template': 'standard', 
            'algorithm': 'aes-gcm',
            'security_level': 'good',
            'performance': 'moderate'
        },
        'max-security': {
            'description': 'Maximum security for highly sensitive data',
            'template': 'paranoid',
            'algorithm': 'xchacha20-poly1305',
            'security_level': 'very_high',
            'performance': 'low'
        }
    }
    
    # Algorithm family aliases - easier algorithm selection
    ALGORITHM_ALIASES = {
        'aes': 'aes-gcm',
        'chacha': 'chacha20-poly1305',
        'xchacha': 'xchacha20-poly1305',
        'fernet': 'fernet'
    }
    
    # Post-quantum aliases - simplified PQC selection
    PQC_ALIASES = {
        'pq-standard': 'ml-kem-768-hybrid',
        'pq-high': 'ml-kem-1024-hybrid', 
        'pq-alternative': 'hqc-192-hybrid'
    }
    
    # Use case aliases - context-aware configurations
    USE_CASE_ALIASES = {
        'personal': {
            'description': 'Personal files and documents',
            'template': 'standard',
            'algorithm': 'aes-gcm'
        },
        'business': {
            'description': 'Business documents and sensitive data',
            'template': 'standard',
            'algorithm': 'xchacha20-poly1305'
        },
        'archival': {
            'description': 'Long-term storage with future-proofing',
            'template': 'paranoid',
            'algorithm': 'xchacha20-poly1305',
            'pqc': 'ml-kem-1024-hybrid'
        },
        'compliance': {
            'description': 'Regulatory compliance requirements',
            'template': 'paranoid',
            'algorithm': 'aes-gcm',
            'require_keystore': True
        }
    }


class CLIAliasProcessor:
    """Processes CLI aliases and converts them to full parameter sets."""
    
    def __init__(self):
        self.config = CLIAliasConfig()
    
    def add_alias_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add alias arguments to the argument parser."""
        
        # Security level aliases group
        security_group = parser.add_argument_group(
            'Security Level Aliases (simplified security selection)'
        )
        
        security_alias_group = security_group.add_mutually_exclusive_group()
        
        # Add security level aliases
        for alias, config in self.config.SECURITY_ALIASES.items():
            security_alias_group.add_argument(
                f'--{alias}',
                action='store_true',
                help=f"{config['description']} (security: {config['security_level']}, performance: {config['performance']})"
            )
        
        # Algorithm family aliases group  
        algorithm_group = parser.add_argument_group(
            'Algorithm Aliases (simplified algorithm selection)'
        )
        
        algorithm_group.add_argument(
            '--crypto-family',
            choices=list(self.config.ALGORITHM_ALIASES.keys()),
            help='Choose encryption algorithm family: ' + ', '.join([
                f'{alias}={full}' for alias, full in self.config.ALGORITHM_ALIASES.items()
            ])
        )
        
        # Post-quantum aliases
        pqc_group = parser.add_argument_group(
            'Post-Quantum Aliases (simplified post-quantum selection)'
        )
        
        pqc_group.add_argument(
            '--quantum-safe',
            choices=list(self.config.PQC_ALIASES.keys()),
            help='Enable post-quantum encryption: ' + ', '.join([
                f'{alias}={full}' for alias, full in self.config.PQC_ALIASES.items()
            ])
        )
        
        # Use case aliases group
        usecase_group = parser.add_argument_group(
            'Use Case Aliases (context-aware configurations)'
        )
        
        usecase_alias_group = usecase_group.add_mutually_exclusive_group()
        
        for alias, config in self.config.USE_CASE_ALIASES.items():
            usecase_alias_group.add_argument(
                f'--for-{alias}',
                action='store_true',
                help=config['description']
            )
    
    def process_aliases(self, args: argparse.Namespace) -> Dict[str, Any]:
        """
        Process alias arguments and return equivalent full parameters.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Dictionary of parameter overrides to apply
        """
        overrides = {}
        
        # Process security level aliases
        for alias in self.config.SECURITY_ALIASES:
            if getattr(args, alias.replace('-', '_'), False):
                config = self.config.SECURITY_ALIASES[alias]
                if 'template' in config:
                    overrides['template'] = config['template']
                if 'algorithm' in config:
                    overrides['algorithm'] = config['algorithm']
                if 'pqc' in config:
                    overrides['pqc_algorithm'] = config['pqc']
                break
        
        # Process algorithm family aliases
        if hasattr(args, 'crypto_family') and args.crypto_family:
            overrides['algorithm'] = self.config.ALGORITHM_ALIASES[args.crypto_family]
        
        # Process post-quantum aliases
        if hasattr(args, 'quantum_safe') and args.quantum_safe:
            overrides['pqc_algorithm'] = self.config.PQC_ALIASES[args.quantum_safe]
        
        # Process use case aliases
        for alias in self.config.USE_CASE_ALIASES:
            attr_name = f'for_{alias}'
            if getattr(args, attr_name, False):
                config = self.config.USE_CASE_ALIASES[alias]
                if 'template' in config:
                    overrides['template'] = config['template']
                if 'algorithm' in config:
                    overrides['algorithm'] = config['algorithm']
                if 'pqc' in config:
                    overrides['pqc_algorithm'] = config['pqc']
                if 'require_keystore' in config:
                    overrides['require_keystore'] = config['require_keystore']
                break
        
        return overrides
    
    def get_alias_help_text(self) -> str:
        """Generate comprehensive help text for all aliases."""
        
        help_lines = [
            "CLI ALIASES - Simplified Security Configuration",
            "=" * 50,
            "",
            "SECURITY LEVEL ALIASES:",
            "These provide balanced security/performance configurations:",
            ""
        ]
        
        for alias, config in self.config.SECURITY_ALIASES.items():
            help_lines.append(f"  --{alias:<15} {config['description']}")
            help_lines.append(f"  {' ' * 15} Security: {config['security_level']}, Performance: {config['performance']}")
            help_lines.append("")
        
        help_lines.extend([
            "ALGORITHM FAMILY ALIASES:",
            "Simplified algorithm selection:",
            ""
        ])
        
        for alias, full in self.config.ALGORITHM_ALIASES.items():
            help_lines.append(f"  --crypto-family {alias:<10} → {full}")
        
        help_lines.extend([
            "",
            "POST-QUANTUM ALIASES:",
            "Future-proof encryption options:",
            ""
        ])
        
        for alias, full in self.config.PQC_ALIASES.items():
            help_lines.append(f"  --quantum-safe {alias:<12} → {full}")
        
        help_lines.extend([
            "",
            "USE CASE ALIASES:",
            "Context-aware configurations for different scenarios:",
            ""
        ])
        
        for alias, config in self.config.USE_CASE_ALIASES.items():
            help_lines.append(f"  --for-{alias:<12} {config['description']}")
        
        help_lines.extend([
            "",
            "EXAMPLES:",
            "  crypt_cli encrypt --input file.txt --fast",
            "  crypt_cli encrypt --input file.txt --secure --crypto-family xchacha",  
            "  crypt_cli encrypt --input file.txt --for-archival --quantum-safe pq-high",
            "  crypt_cli encrypt --input file.txt --max-security --for-compliance",
            ""
        ])
        
        return "\n".join(help_lines)
    
    def validate_alias_combinations(self, args: argparse.Namespace) -> List[str]:
        """
        Validate that alias combinations make sense and don't conflict.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check for conflicting security levels
        active_security_aliases = [
            alias for alias in self.config.SECURITY_ALIASES
            if getattr(args, alias.replace('-', '_'), False)
        ]
        
        if len(active_security_aliases) > 1:
            errors.append(f"Conflicting security aliases: {', '.join(active_security_aliases)}")
        
        # Check for conflicting use cases
        active_usecase_aliases = [
            alias for alias in self.config.USE_CASE_ALIASES
            if getattr(args, f'for_{alias}', False)
        ]
        
        if len(active_usecase_aliases) > 1:
            errors.append(f"Conflicting use case aliases: {', '.join(active_usecase_aliases)}")
        
        # Validate post-quantum + algorithm combinations
        if (hasattr(args, 'quantum_safe') and args.quantum_safe and
            hasattr(args, 'crypto_family') and args.crypto_family == 'fernet'):
            errors.append("Post-quantum encryption is not compatible with Fernet algorithm")
        
        return errors


def create_alias_processor() -> CLIAliasProcessor:
    """Factory function to create a CLI alias processor."""
    return CLIAliasProcessor()


def apply_alias_overrides(args: argparse.Namespace, overrides: Dict[str, Any]) -> argparse.Namespace:
    """
    Apply alias overrides to parsed arguments.
    
    Args:
        args: Original parsed arguments
        overrides: Dictionary of parameter overrides
        
    Returns:
        Modified argument namespace with overrides applied
    """
    # Create a copy of args to avoid modifying the original
    modified_args = argparse.Namespace(**vars(args))
    
    # Apply overrides, but only if the original argument wasn't explicitly set
    for key, value in overrides.items():
        # Don't override explicit user settings
        if not hasattr(modified_args, key) or getattr(modified_args, key) is None:
            setattr(modified_args, key, value)
    
    return modified_args


# Convenience functions for integration
def add_cli_aliases(parser: argparse.ArgumentParser) -> CLIAliasProcessor:
    """Add CLI alias support to an argument parser."""
    processor = create_alias_processor()
    processor.add_alias_arguments(parser)
    return processor


def process_cli_aliases(args: argparse.Namespace, processor: CLIAliasProcessor) -> Tuple[argparse.Namespace, List[str]]:
    """Process CLI aliases and return modified args plus any validation errors."""
    errors = processor.validate_alias_combinations(args)
    if errors:
        return args, errors
    
    overrides = processor.process_aliases(args)
    modified_args = apply_alias_overrides(args, overrides)
    return modified_args, []