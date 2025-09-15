#!/usr/bin/env python3
"""
Configuration Wizard for OpenSSL Encrypt

This module provides an interactive wizard system that guides users through
security configuration setup with intelligent recommendations based on their
use case and security requirements.

Security Design:
- Progressive disclosure of complexity based on user expertise level
- Context-aware recommendations without revealing vulnerabilities
- Educational guidance with security level explanations
- Integration with existing security scoring system
"""

import sys
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .security_scorer import SecurityLevel, SecurityScorer


class UserExpertise(Enum):
    """User expertise levels for configuration guidance."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class UseCase(Enum):
    """Common use cases for encryption configuration."""

    PERSONAL_FILES = "personal"
    BUSINESS_DOCUMENTS = "business"
    SENSITIVE_DATA = "sensitive"
    ARCHIVAL_STORAGE = "archival"
    HIGH_SECURITY = "high_security"
    COMPLIANCE = "compliance"


class ConfigurationWizard:
    """
    Interactive configuration wizard for security settings.

    Provides guided setup with progressive complexity disclosure and
    intelligent recommendations based on user expertise and use case.
    """

    def __init__(self):
        """Initialize the configuration wizard."""
        self.scorer = SecurityScorer()
        self.config = {}
        self.user_expertise = None
        self.use_case = None

    def run_wizard(self, quiet: bool = False) -> Dict[str, Any]:
        """
        Run the interactive configuration wizard.

        Args:
            quiet: If True, suppress interactive prompts and use defaults

        Returns:
            Complete configuration dictionary
        """
        if not quiet:
            self._show_welcome()
            self._gather_user_info()
        else:
            # Use sensible defaults for quiet mode
            self.user_expertise = UserExpertise.INTERMEDIATE
            self.use_case = UseCase.PERSONAL_FILES

        # Generate initial configuration based on user profile
        self.config = self._generate_base_config()

        if not quiet:
            # Interactive refinement
            self._configure_hash_algorithms()
            self._configure_kdf_settings()
            self._configure_encryption()
            self._configure_post_quantum()

            # Final review and scoring
            self._show_configuration_summary()

        return self.config

    def _show_welcome(self):
        """Display wizard welcome message."""
        print("\n" + "=" * 60)
        print("    OpenSSL Encrypt - Configuration Wizard")
        print("=" * 60)
        print("\nThis wizard will help you configure secure encryption settings")
        print("based on your expertise level and intended use case.\n")
        print("The wizard provides:")
        print("• Guided security configuration setup")
        print("• Intelligent recommendations for your use case")
        print("• Educational explanations of security options")
        print("• Real-time security scoring feedback")
        print("\nPress Ctrl+C at any time to exit.\n")

    def _gather_user_info(self):
        """Gather user expertise and use case information."""
        # Determine user expertise level
        print("STEP 1: Expertise Level")
        print("-" * 25)
        print("Please select your cryptography expertise level:")
        print("1. Beginner     - New to encryption, want simple secure defaults")
        print("2. Intermediate - Some experience, want balanced security/performance")
        print("3. Advanced     - Good understanding, want to customize settings")
        print("4. Expert       - Deep knowledge, want full control")

        while True:
            try:
                choice = input("\nEnter your choice (1-4): ").strip()
                if choice == "1":
                    self.user_expertise = UserExpertise.BEGINNER
                    break
                elif choice == "2":
                    self.user_expertise = UserExpertise.INTERMEDIATE
                    break
                elif choice == "3":
                    self.user_expertise = UserExpertise.ADVANCED
                    break
                elif choice == "4":
                    self.user_expertise = UserExpertise.EXPERT
                    break
                else:
                    print("Please enter a number between 1 and 4.")
            except (EOFError, KeyboardInterrupt):
                print("\nWizard cancelled.")
                sys.exit(0)

        # Determine use case
        print(f"\nSTEP 2: Use Case ({self.user_expertise.value.title()} Mode)")
        print("-" * 40)
        print("What will you primarily use encryption for?")
        print("1. Personal files      - Photos, documents, backups")
        print("2. Business documents  - Corporate files, communications")
        print("3. Sensitive data      - Financial, medical, legal records")
        print("4. Archival storage    - Long-term data preservation")
        print("5. High security       - Classified or highly sensitive material")
        print("6. Compliance          - Regulatory requirements (HIPAA, GDPR, etc.)")

        while True:
            try:
                choice = input("\nEnter your choice (1-6): ").strip()
                if choice == "1":
                    self.use_case = UseCase.PERSONAL_FILES
                    break
                elif choice == "2":
                    self.use_case = UseCase.BUSINESS_DOCUMENTS
                    break
                elif choice == "3":
                    self.use_case = UseCase.SENSITIVE_DATA
                    break
                elif choice == "4":
                    self.use_case = UseCase.ARCHIVAL_STORAGE
                    break
                elif choice == "5":
                    self.use_case = UseCase.HIGH_SECURITY
                    break
                elif choice == "6":
                    self.use_case = UseCase.COMPLIANCE
                    break
                else:
                    print("Please enter a number between 1 and 6.")
            except (EOFError, KeyboardInterrupt):
                print("\nWizard cancelled.")
                sys.exit(0)

    def _generate_base_config(self) -> Dict[str, Any]:
        """Generate base configuration based on user profile."""
        config = {"hash_algorithms": {}, "kdf_settings": {}, "encryption": {}, "post_quantum": {}}

        # Base configuration matrix based on use case
        if self.use_case in [UseCase.PERSONAL_FILES, UseCase.BUSINESS_DOCUMENTS]:
            # Balanced security/performance
            config["hash_algorithms"]["sha256"] = {"rounds": 1000000}
            config["kdf_settings"]["argon2"] = {
                "enabled": True,
                "memory_cost": 65536,  # 64MB
                "time_cost": 3,
                "parallelism": 4,
            }
            config["encryption"]["algorithm"] = "aes-gcm"

        elif self.use_case in [UseCase.SENSITIVE_DATA, UseCase.COMPLIANCE]:
            # Higher security
            config["hash_algorithms"]["sha256"] = {"rounds": 2000000}
            config["hash_algorithms"]["blake2b"] = {"rounds": 1000000}
            config["kdf_settings"]["argon2"] = {
                "enabled": True,
                "memory_cost": 131072,  # 128MB
                "time_cost": 4,
                "parallelism": 4,
            }
            config["kdf_settings"]["scrypt"] = {"enabled": True, "n": 32768, "r": 8, "p": 1}
            config["encryption"]["algorithm"] = "xchacha20-poly1305"

        elif self.use_case == UseCase.ARCHIVAL_STORAGE:
            # Future-proofing emphasis
            config["hash_algorithms"]["sha3_512"] = {"rounds": 1500000}
            config["hash_algorithms"]["blake3"] = {"rounds": 1000000}
            config["kdf_settings"]["argon2"] = {
                "enabled": True,
                "memory_cost": 262144,  # 256MB
                "time_cost": 5,
                "parallelism": 8,
            }
            config["encryption"]["algorithm"] = "aes-gcm-siv"
            config["post_quantum"]["enabled"] = True
            config["post_quantum"]["algorithm"] = "ml-kem-768"

        elif self.use_case == UseCase.HIGH_SECURITY:
            # Maximum security
            config["hash_algorithms"]["sha256"] = {"rounds": 5000000}
            config["hash_algorithms"]["sha3_512"] = {"rounds": 2000000}
            config["hash_algorithms"]["blake3"] = {"rounds": 1500000}
            config["kdf_settings"]["argon2"] = {
                "enabled": True,
                "memory_cost": 524288,  # 512MB
                "time_cost": 8,
                "parallelism": 8,
            }
            config["kdf_settings"]["scrypt"] = {"enabled": True, "n": 65536, "r": 8, "p": 1}
            config["encryption"]["algorithm"] = "xchacha20-poly1305"
            config["post_quantum"]["enabled"] = True
            config["post_quantum"]["algorithm"] = "ml-kem-1024"

        return config

    def _configure_hash_algorithms(self):
        """Interactive hash algorithm configuration."""
        if self.user_expertise == UserExpertise.BEGINNER:
            # Skip for beginners - use defaults
            return

        print(f"\nSTEP 3: Hash Algorithm Configuration")
        print("-" * 40)
        print("Current hash configuration:")

        for alg, settings in self.config["hash_algorithms"].items():
            print(f"• {alg.upper()}: {settings['rounds']:,} rounds")

        if self.user_expertise in [UserExpertise.INTERMEDIATE, UserExpertise.ADVANCED]:
            print("\nWould you like to:")
            print("1. Keep current settings (recommended)")
            print("2. Add more hash algorithms for extra security")
            print("3. Adjust iteration counts")

            try:
                choice = input("\nEnter your choice (1-3): ").strip()
                if choice == "2":
                    self._add_hash_algorithms()
                elif choice == "3":
                    self._adjust_hash_rounds()
            except (EOFError, KeyboardInterrupt):
                print("\nUsing current settings.")

    def _add_hash_algorithms(self):
        """Add additional hash algorithms."""
        available_hashes = {
            "blake3": "Ultra-fast modern hash with parallel processing",
            "sha3_256": "NIST-standardized SHA-3 family hash",
            "sha3_512": "SHA-3 with 512-bit output for maximum security",
            "blake2b": "High-performance cryptographic hash",
        }

        current_hashes = set(self.config["hash_algorithms"].keys())
        available = {k: v for k, v in available_hashes.items() if k not in current_hashes}

        if not available:
            print("All recommended hash algorithms are already configured.")
            return

        print("\nAvailable hash algorithms to add:")
        for i, (alg, desc) in enumerate(available.items(), 1):
            print(f"{i}. {alg.upper()}: {desc}")

        try:
            choices = input(
                f"\nEnter numbers to add (1-{len(available)}, space-separated): "
            ).strip()
            if choices:
                alg_list = list(available.keys())
                for choice in choices.split():
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(alg_list):
                            alg = alg_list[idx]
                            self.config["hash_algorithms"][alg] = {"rounds": 1000000}
                            print(f"Added {alg.upper()} with 1,000,000 rounds")
                    except ValueError:
                        print(f"Skipping invalid choice: {choice}")
        except (EOFError, KeyboardInterrupt):
            print("\nNo changes made.")

    def _adjust_hash_rounds(self):
        """Adjust hash algorithm round counts."""
        print("\nCurrent hash settings:")
        hash_list = list(self.config["hash_algorithms"].items())

        for i, (alg, settings) in enumerate(hash_list, 1):
            print(f"{i}. {alg.upper()}: {settings['rounds']:,} rounds")

        try:
            choice = input(f"\nSelect algorithm to adjust (1-{len(hash_list)}): ").strip()
            idx = int(choice) - 1

            if 0 <= idx < len(hash_list):
                alg, settings = hash_list[idx]
                print(f"\nCurrent {alg.upper()} rounds: {settings['rounds']:,}")
                print("Recommendations:")
                print("• 500,000 - Faster, suitable for frequent use")
                print("• 1,000,000 - Balanced security/performance")
                print("• 2,000,000 - Higher security, slower")
                print("• 5,000,000 - Maximum security, much slower")

                new_rounds = input(f"Enter new round count for {alg.upper()}: ").strip()
                if new_rounds.isdigit():
                    rounds = int(new_rounds)
                    if 100000 <= rounds <= 10000000:
                        self.config["hash_algorithms"][alg]["rounds"] = rounds
                        print(f"Updated {alg.upper()} to {rounds:,} rounds")
                    else:
                        print("Round count should be between 100,000 and 10,000,000")
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nNo changes made.")

    def _configure_kdf_settings(self):
        """Interactive KDF configuration."""
        if self.user_expertise == UserExpertise.BEGINNER:
            return

        print(f"\nSTEP 4: Key Derivation Function (KDF) Configuration")
        print("-" * 55)
        print("Current KDF configuration:")

        for kdf, settings in self.config["kdf_settings"].items():
            if settings.get("enabled"):
                if kdf == "argon2":
                    print(
                        f"• Argon2: {settings['memory_cost']//1024}MB memory, {settings['time_cost']} iterations"
                    )
                elif kdf == "scrypt":
                    print(f"• Scrypt: N={settings['n']}, r={settings['r']}, p={settings['p']}")

        if self.user_expertise in [UserExpertise.ADVANCED, UserExpertise.EXPERT]:
            print("\nWould you like to adjust KDF settings? (y/N): ", end="")
            try:
                response = input().strip().lower()
                if response in ["y", "yes"]:
                    self._adjust_kdf_settings()
            except (EOFError, KeyboardInterrupt):
                print("\nUsing current settings.")

    def _adjust_kdf_settings(self):
        """Adjust KDF parameters."""
        print("\nKDF adjustment options:")
        print("1. Adjust Argon2 memory usage")
        print("2. Add secondary KDF (Scrypt)")
        print("3. Fine-tune Argon2 parameters")

        try:
            choice = input("Enter your choice (1-3): ").strip()

            if choice == "1":
                current_mb = self.config["kdf_settings"]["argon2"]["memory_cost"] // 1024
                print(f"\nCurrent Argon2 memory: {current_mb}MB")
                print("Memory recommendations:")
                print("• 32MB  - Low memory systems")
                print("• 64MB  - Balanced (default)")
                print("• 128MB - Higher security")
                print("• 256MB - Strong security")
                print("• 512MB - Maximum practical security")

                new_mb = input("Enter memory in MB: ").strip()
                if new_mb.isdigit():
                    mb = int(new_mb)
                    if 16 <= mb <= 2048:
                        self.config["kdf_settings"]["argon2"]["memory_cost"] = mb * 1024
                        print(f"Updated Argon2 memory to {mb}MB")

            elif choice == "2" and "scrypt" not in self.config["kdf_settings"]:
                print("\nAdding Scrypt as secondary KDF for enhanced security...")
                self.config["kdf_settings"]["scrypt"] = {
                    "enabled": True,
                    "n": 16384,
                    "r": 8,
                    "p": 1,
                }
                print("Added Scrypt KDF with secure defaults")

        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nNo changes made.")

    def _configure_encryption(self):
        """Interactive encryption algorithm configuration."""
        if self.user_expertise in [UserExpertise.BEGINNER, UserExpertise.INTERMEDIATE]:
            return

        print(f"\nSTEP 5: Encryption Algorithm")
        print("-" * 30)
        current_alg = self.config["encryption"]["algorithm"]
        print(f"Current algorithm: {current_alg.upper()}")

        algorithms = {
            "aes-gcm": "AES-GCM - Industry standard, widely trusted",
            "aes-gcm-siv": "AES-GCM-SIV - Nonce-misuse resistant",
            "xchacha20-poly1305": "XChaCha20-Poly1305 - Modern, extended nonce",
            "chacha20-poly1305": "ChaCha20-Poly1305 - Fast, modern alternative to AES",
        }

        print("\nAvailable encryption algorithms:")
        alg_list = list(algorithms.items())
        for i, (alg, desc) in enumerate(alg_list, 1):
            marker = " (current)" if alg == current_alg else ""
            print(f"{i}. {desc}{marker}")

        try:
            choice = input(
                f"\nSelect algorithm (1-{len(alg_list)}, or Enter to keep current): "
            ).strip()
            if choice and choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(alg_list):
                    new_alg = alg_list[idx][0]
                    self.config["encryption"]["algorithm"] = new_alg
                    print(f"Updated to {new_alg.upper()}")
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nUsing current algorithm.")

    def _configure_post_quantum(self):
        """Interactive post-quantum configuration."""
        if self.user_expertise == UserExpertise.BEGINNER:
            return

        print(f"\nSTEP 6: Post-Quantum Cryptography")
        print("-" * 35)

        pqc_enabled = self.config["post_quantum"].get("enabled", False)

        if not pqc_enabled:
            print("Post-quantum cryptography: DISABLED")
            print("\nPost-quantum algorithms protect against future quantum computers.")
            print("Recommended for:")
            print("• Long-term data storage (>10 years)")
            print("• Highly sensitive information")
            print("• Compliance with quantum-safe requirements")

            try:
                enable = input("\nEnable post-quantum protection? (y/N): ").strip().lower()
                if enable in ["y", "yes"]:
                    self.config["post_quantum"]["enabled"] = True
                    self.config["post_quantum"]["algorithm"] = "ml-kem-768"
                    print("Enabled ML-KEM-768 (NIST standard)")
            except (EOFError, KeyboardInterrupt):
                print("\nPost-quantum remains disabled.")
        else:
            current_alg = self.config["post_quantum"]["algorithm"]
            print(f"Post-quantum cryptography: ENABLED ({current_alg.upper()})")

            if self.user_expertise in [UserExpertise.ADVANCED, UserExpertise.EXPERT]:
                algorithms = {
                    "ml-kem-512": "ML-KEM-512 - NIST standard, Level 1 security",
                    "ml-kem-768": "ML-KEM-768 - NIST standard, Level 3 security (recommended)",
                    "ml-kem-1024": "ML-KEM-1024 - NIST standard, Level 5 security",
                    "hqc-256": "HQC-256 - Alternative approach, code-based",
                }

                print("\nAvailable post-quantum algorithms:")
                alg_list = list(algorithms.items())
                for i, (alg, desc) in enumerate(alg_list, 1):
                    marker = " (current)" if alg == current_alg else ""
                    print(f"{i}. {desc}{marker}")

                try:
                    choice = input(
                        f"\nSelect algorithm (1-{len(alg_list)}, or Enter to keep current): "
                    ).strip()
                    if choice and choice.isdigit():
                        idx = int(choice) - 1
                        if 0 <= idx < len(alg_list):
                            new_alg = alg_list[idx][0]
                            self.config["post_quantum"]["algorithm"] = new_alg
                            print(f"Updated to {new_alg.upper()}")
                except (ValueError, EOFError, KeyboardInterrupt):
                    print("\nUsing current algorithm.")

    def _show_configuration_summary(self):
        """Display final configuration summary with security score."""
        print(f"\n{'='*60}")
        print("    CONFIGURATION SUMMARY")
        print(f"{'='*60}")

        # Convert config to scoring format
        hash_config = self.config["hash_algorithms"]
        kdf_config = {}

        for kdf, settings in self.config["kdf_settings"].items():
            if settings.get("enabled"):
                kdf_config[kdf] = settings

        cipher_info = {"algorithm": self.config["encryption"]["algorithm"]}
        pqc_info = (
            self.config["post_quantum"] if self.config["post_quantum"].get("enabled") else None
        )

        # Calculate security score
        analysis = self.scorer.score_configuration(hash_config, kdf_config, cipher_info, pqc_info)

        print(f"\nSECURITY SCORE: {analysis['overall']['score']}/10")
        print(f"Security Level: {analysis['overall']['level'].name}")
        print(f"Assessment: {analysis['overall']['description']}")

        print(f"\nCONFIGURATION DETAILS:")
        print(f"─────────────────────")

        # Hash algorithms
        print("Hash Algorithms:")
        for alg, settings in self.config["hash_algorithms"].items():
            print(f"  • {alg.upper()}: {settings['rounds']:,} rounds")

        # KDF settings
        print("Key Derivation Functions:")
        for kdf, settings in self.config["kdf_settings"].items():
            if settings.get("enabled"):
                if kdf == "argon2":
                    print(
                        f"  • Argon2: {settings['memory_cost']//1024}MB memory, {settings['time_cost']} iterations, {settings['parallelism']} threads"
                    )
                elif kdf == "scrypt":
                    print(f"  • Scrypt: N={settings['n']}, r={settings['r']}, p={settings['p']}")

        # Encryption
        print(f"Encryption Algorithm:")
        print(f"  • {self.config['encryption']['algorithm'].upper()}")

        # Post-quantum
        if self.config["post_quantum"].get("enabled"):
            print(f"Post-Quantum Cryptography:")
            print(f"  • {self.config['post_quantum']['algorithm'].upper()}")
        else:
            print("Post-Quantum Cryptography: Disabled")

        # Show recommendations
        if analysis["suggestions"]:
            print(f"\nRECOMMENDATIONS:")
            print(f"─────────────────")
            for i, suggestion in enumerate(analysis["suggestions"], 1):
                print(f"{i}. {suggestion}")

        print(f"\n{'='*60}")
        print("Configuration wizard completed!")
        print("Use these settings with the encrypt command for optimal security.")
        print(f"{'='*60}\n")


def run_configuration_wizard(quiet: bool = False) -> Dict[str, Any]:
    """
    Run the interactive configuration wizard.

    Args:
        quiet: If True, run in quiet mode with defaults

    Returns:
        Complete configuration dictionary
    """
    wizard = ConfigurationWizard()
    return wizard.run_wizard(quiet=quiet)


def generate_cli_arguments(config: Dict[str, Any]) -> List[str]:
    """
    Generate CLI arguments from wizard configuration.

    Args:
        config: Configuration dictionary from wizard

    Returns:
        List of CLI argument strings
    """
    args = []

    # Hash algorithms
    for alg, settings in config.get("hash_algorithms", {}).items():
        args.append(f"--{alg.replace('_', '-')}-rounds")
        args.append(str(settings["rounds"]))

    # KDF settings
    kdf_settings = config.get("kdf_settings", {})

    if "argon2" in kdf_settings and kdf_settings["argon2"].get("enabled"):
        argon2 = kdf_settings["argon2"]
        args.extend(
            [
                "--argon2-memory-cost",
                str(argon2["memory_cost"]),
                "--argon2-time-cost",
                str(argon2["time_cost"]),
                "--argon2-parallelism",
                str(argon2["parallelism"]),
            ]
        )

    if "scrypt" in kdf_settings and kdf_settings["scrypt"].get("enabled"):
        scrypt = kdf_settings["scrypt"]
        args.extend(
            [
                "--scrypt-n",
                str(scrypt["n"]),
                "--scrypt-r",
                str(scrypt["r"]),
                "--scrypt-p",
                str(scrypt["p"]),
            ]
        )

    # Encryption algorithm
    if "encryption" in config and "algorithm" in config["encryption"]:
        args.extend(["--encryption-data-algorithm", config["encryption"]["algorithm"]])

    # Post-quantum
    pqc = config.get("post_quantum", {})
    if pqc.get("enabled") and "algorithm" in pqc:
        args.extend(["--pqc-algorithm", pqc["algorithm"]])

    return args
