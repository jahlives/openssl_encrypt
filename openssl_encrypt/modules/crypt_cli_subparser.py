#!/usr/bin/env python3
"""
Subparser implementation for crypt_cli to provide command-specific help.

This module patches the main function to use subparsers for 1.0.0 branch.
Filters out 1.1.0-only algorithms (MAYO and CROSS) that are not available in 1.0.0.
"""

import argparse

from .crypt_cli_helper import add_extended_algorithm_help
from .crypt_core import EncryptionAlgorithm

# Cascade presets for multi-layer encryption
CASCADE_PRESETS = {
    "standard": ["aes-256-gcm", "chacha20-poly1305"],
    "paranoia": ["aes-256-gcm", "chacha20-poly1305", "threefish-512"],
}

# Import registry helper functions
try:
    from .registry import (  # noqa: F401
        format_algorithm_help,
        get_available_ciphers,
        get_available_hashes,
        get_available_kdfs,
        get_available_kems,
        get_available_signatures,
    )

    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False


def get_available_algorithms_1_0():
    """Get only algorithms available in 1.0.0 (excludes MAYO and CROSS)."""
    # 1.1.0-only algorithms that should be excluded from 1.0.0
    excluded_algorithms = {
        "mayo-1-hybrid",
        "mayo-3-hybrid",
        "mayo-5-hybrid",
        "cross-128-hybrid",
        "cross-192-hybrid",
        "cross-256-hybrid",
    }

    available = []
    for algo in EncryptionAlgorithm:
        if algo.value not in excluded_algorithms:
            available.append(algo.value)

    return available


def setup_encrypt_parser(subparser):
    """Set up arguments specific to the encrypt command."""
    # Get only algorithms available in 1.0.0
    all_algorithms = get_available_algorithms_1_0()

    # Build help text with deprecated warnings (only for 1.0.0 algorithms)
    algorithm_help_text = "Encryption algorithm to use:\n"
    if REGISTRY_AVAILABLE:
        algorithm_help_text += (
            "(Use 'list-algorithms' command to see available ciphers, KDFs, and hashes)\n\n"
        )
    for algo in sorted(all_algorithms):
        if algo == EncryptionAlgorithm.FERNET.value:
            description = "default, AES-128-CBC with authentication"
        elif algo == EncryptionAlgorithm.AES_GCM.value:
            description = "AES-256 in GCM mode, high security, widely trusted"
        elif algo == EncryptionAlgorithm.AES_GCM_SIV.value:
            description = "AES-256 in GCM-SIV mode, resistant to nonce reuse"
        elif algo == EncryptionAlgorithm.AES_OCB3.value:
            description = "AES-256 in OCB3 mode, faster than GCM (DEPRECATED)"
        elif algo == EncryptionAlgorithm.AES_SIV.value:
            description = "AES in SIV mode, synthetic IV"
        elif algo == EncryptionAlgorithm.CHACHA20_POLY1305.value:
            description = "modern AEAD cipher with 12-byte nonce"
        elif algo == EncryptionAlgorithm.XCHACHA20_POLY1305.value:
            description = "ChaCha20-Poly1305 with 24-byte nonce, safer for high-volume encryption"
        elif algo == EncryptionAlgorithm.CAMELLIA.value:
            description = "Camellia in CBC mode (DEPRECATED)"
        elif algo == EncryptionAlgorithm.ML_KEM_512_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 1 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_768_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 3 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_1024_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 5 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.KYBER512_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 1 (DEPRECATED - use ml-kem-512-hybrid)"
        elif algo == EncryptionAlgorithm.KYBER768_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 3 (DEPRECATED - use ml-kem-768-hybrid)"
        elif algo == EncryptionAlgorithm.KYBER1024_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 5 (DEPRECATED - use ml-kem-1024-hybrid)"
        elif algo == "ml-kem-512-chacha20":
            description = "ML-KEM-512 with ChaCha20-Poly1305 (post-quantum)"
        elif algo == "ml-kem-768-chacha20":
            description = "ML-KEM-768 with ChaCha20-Poly1305 (post-quantum)"
        elif algo == "ml-kem-1024-chacha20":
            description = "ML-KEM-1024 with ChaCha20-Poly1305 (post-quantum)"
        elif algo == "hqc-128-hybrid":
            description = "HQC-128 hybrid mode (post-quantum)"
        elif algo == "hqc-192-hybrid":
            description = "HQC-192 hybrid mode (post-quantum)"
        elif algo == "hqc-256-hybrid":
            description = "HQC-256 hybrid mode (post-quantum)"
        elif algo == EncryptionAlgorithm.THREEFISH_512.value:
            description = "Threefish-512 with Poly1305 (256-bit PQ security, high security)"
        elif algo == EncryptionAlgorithm.THREEFISH_1024.value:
            description = "Threefish-1024 with Poly1305 (512-bit PQ security, paranoid)"
        else:
            description = "encryption algorithm"
        algorithm_help_text += f"  {algo}: {description}\n"

    subparser.add_argument(
        "--algorithm",
        type=str,
        # Note: choices validation removed to allow comma-separated algorithms for cascade mode
        # Validation is performed in CLI logic for both cascade and non-cascade modes
        default=EncryptionAlgorithm.FERNET.value,
        help=algorithm_help_text,
    )

    # Add extended algorithm help
    add_extended_algorithm_help(subparser)

    # Template selection group
    template_group = subparser.add_mutually_exclusive_group()
    template_group.add_argument(
        "--quick", action="store_true", help="Use quick but secure configuration"
    )
    template_group.add_argument(
        "--standard",
        action="store_true",
        help="Use standard security configuration (default)",
    )
    template_group.add_argument(
        "--paranoid", action="store_true", help="Use maximum security configuration"
    )

    # Add template argument
    subparser.add_argument(
        "-t",
        "--template",
        help="Specify a template name (built-in or from ./template directory)",
    )

    # Password options
    subparser.add_argument(
        "--password",
        "-p",
        help="Password (will prompt if not provided, or use CRYPT_PASSWORD environment variable)",
    )
    subparser.add_argument(
        "--random",
        type=int,
        metavar="LENGTH",
        help="Generate a random password of specified length for encryption",
    )
    subparser.add_argument(
        "--force-password",
        action="store_true",
        help="Force acceptance of weak passwords (use with caution)",
    )

    # I/O options
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file to encrypt",
    )
    subparser.add_argument("--output", "-o", help="Output file (optional)")
    subparser.add_argument(
        "--overwrite",
        "-f",
        action="store_true",
        help="Overwrite the input file with the output",
    )
    subparser.add_argument(
        "--shred",
        "-s",
        action="store_true",
        help="Securely delete the original file after encryption",
    )
    subparser.add_argument(
        "--shred-passes",
        type=int,
        default=3,
        help="Number of passes for secure deletion (default: 3)",
    )

    # Cascade encryption options
    cascade_group = subparser.add_argument_group("Cascade encryption (multi-layer)")
    cascade_group.description = (
        "Cascade encryption applies multiple cipher layers sequentially for defense-in-depth. "
        "Use presets or specify custom cipher chains with comma-separated algorithms."
    )

    cascade_group.add_argument(
        "--cascade",
        nargs="?",
        const=True,
        default=None,
        metavar="PRESET",
        help=(
            "Enable cascade encryption. Use with --algorithm for custom chain "
            "(e.g., --cascade --algorithm aes-256-gcm,chacha20-poly1305), "
            "or specify preset: 'standard' (AES+ChaCha), 'paranoia' (AES+ChaCha+Threefish)"
        ),
    )

    cascade_group.add_argument(
        "--cascade-hash",
        type=str,
        default="sha256",
        choices=[
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "blake2b",
            "blake2s",
        ],
        help="Hash function for HKDF key derivation in cascade mode (default: sha256)",
    )

    cascade_group.add_argument(
        "--no-diversity-check",
        action="store_true",
        help="Disable cipher diversity validation warnings",
    )

    cascade_group.add_argument(
        "--strict-diversity",
        action="store_true",
        help="Treat cipher diversity warnings as errors (abort on weak combinations)",
    )

    # Advanced encryption options
    hash_group = subparser.add_argument_group("Hash options")

    # Add note about available algorithms if registry is available
    if REGISTRY_AVAILABLE:
        hash_group.description = "Hash algorithm configuration. Use 'list-algorithms --category=hashes' to see all available hash functions."

    # Add global KDF rounds parameter
    hash_group.add_argument(
        "--kdf-rounds",
        type=int,
        default=0,
        help="Default number of rounds for all KDFs when enabled without specific rounds (overrides the default of 10)",
    )

    # SHA family arguments - updated to match the main CLI
    hash_group.add_argument(
        "--sha512-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha384-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-384 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-224 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-512-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-384-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-384 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-224 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake2b-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE2b iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake3-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE3 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--shake256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--shake128-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-128 iterations (default: 1,000,000 if flag provided without value)",
    )

    # Scrypt options for encryption
    scrypt_group = subparser.add_argument_group("Scrypt options")
    scrypt_group.add_argument(
        "--enable-scrypt", action="store_true", help="Use Scrypt password hashing"
    )
    scrypt_group.add_argument(
        "--scrypt-rounds",
        type=int,
        default=0,
        help="Use scrypt rounds for iterating (default when enabled: 10)",
    )
    scrypt_group.add_argument("--scrypt-n", type=int, help="Scrypt N parameter (CPU/memory cost)")
    scrypt_group.add_argument(
        "--scrypt-r", type=int, default=8, help="Scrypt r parameter (block size)"
    )
    scrypt_group.add_argument(
        "--scrypt-p", type=int, default=1, help="Scrypt p parameter (parallelization factor)"
    )

    # Argon2 options for encryption
    argon2_description = "Configure Argon2 memory-hard function parameters"
    if REGISTRY_AVAILABLE:
        argon2_description += (
            ". Use 'list-algorithms --category=kdfs' to see all available KDF algorithms."
        )
    argon2_group = subparser.add_argument_group("Argon2 Options", argon2_description)
    argon2_group.add_argument(
        "--enable-argon2",
        action="store_true",
        default=False,
        help="Use Argon2 password hashing (requires argon2-cffi package)",
    )
    argon2_group.add_argument(
        "--argon2-rounds",
        type=int,
        default=0,
        help="Argon2 time cost parameter / rounds (default when enabled: 10)",
    )
    argon2_group.add_argument(
        "--argon2-time",
        type=int,
        default=3,
        help="Argon2 time cost parameter (default: 3)",
    )
    argon2_group.add_argument(
        "--argon2-memory",
        type=int,
        default=65536,
        help="Argon2 memory cost in KB (default: 65536 - 64MB)",
    )
    argon2_group.add_argument(
        "--argon2-parallelism",
        type=int,
        default=4,
        help="Argon2 parallelism factor (default: 4)",
    )
    argon2_group.add_argument(
        "--argon2-hash-len",
        type=int,
        default=32,
        help="Argon2 hash length in bytes (default: 32)",
    )
    argon2_group.add_argument(
        "--argon2-type",
        choices=["id", "i", "d"],
        default="id",
        help="Argon2 variant to use: id (recommended), i, or d",
    )
    argon2_group.add_argument(
        "--argon2-preset",
        choices=["low", "medium", "high", "paranoid"],
        help="Use predefined Argon2 parameters (overrides other Argon2 settings)",
    )

    # RandomX options for encryption
    randomx_group = subparser.add_argument_group("RandomX options")
    randomx_group.add_argument(
        "--enable-randomx",
        action="store_true",
        help="Enable RandomX key derivation (disabled by default, requires pyrx package)",
        default=False,
    )
    randomx_group.add_argument(
        "--randomx-rounds",
        type=int,
        default=0,
        help="Number of RandomX rounds (default when enabled: 10)",
    )
    randomx_group.add_argument(
        "--randomx-mode",
        choices=["light", "fast"],
        default="light",
        help="RandomX mode: light (256MB RAM) or fast (2GB RAM, default: light)",
    )
    randomx_group.add_argument(
        "--randomx-height",
        type=int,
        default=1,
        help="RandomX block height parameter (default: 1)",
    )
    randomx_group.add_argument(
        "--randomx-hash-len",
        type=int,
        default=32,
        help="RandomX output hash length in bytes (default: 32)",
    )

    # PBKDF2 options
    pbkdf2_group = subparser.add_argument_group("PBKDF2 options")
    pbkdf2_group.add_argument(
        "--pbkdf2-iterations",
        type=int,
        default=0,
        help="Number of PBKDF2 iterations (default: 100000)",
    )

    # Balloon Hashing options
    balloon_group = subparser.add_argument_group("Balloon Hashing options")
    balloon_group.add_argument(
        "--enable-balloon",
        action="store_true",
        help="Enable Balloon Hashing KDF",
    )
    balloon_group.add_argument(
        "--balloon-time-cost",
        type=int,
        default=3,
        help="Time cost parameter for Balloon hashing - controls computational complexity. Higher values increase security but also processing time.",
    )
    balloon_group.add_argument(
        "--balloon-space-cost",
        type=int,
        default=65536,
        help="Space cost parameter for Balloon hashing in bytes - controls memory usage. Higher values increase security but require more memory.",
    )
    balloon_group.add_argument(
        "--balloon-parallelism",
        type=int,
        default=4,
        help="Parallelism parameter for Balloon hashing - controls number of parallel threads. Higher values can improve performance on multi-core systems.",
    )
    balloon_group.add_argument(
        "--balloon-rounds",
        type=int,
        default=0,
        help="Number of rounds for Balloon hashing (default when enabled: 10). More rounds increase security but also processing time.",
    )
    balloon_group.add_argument(
        "--balloon-hash-len",
        type=int,
        default=32,
        help="Length of the final hash output in bytes for Balloon hashing.",
    )
    balloon_group.add_argument(
        "--use-balloon",
        action="store_true",
        help=argparse.SUPPRESS,  # Hidden legacy option
    )

    # HKDF options
    hkdf_group = subparser.add_argument_group(
        "HKDF Options", "Configure HMAC-based Key Derivation Function"
    )
    hkdf_group.add_argument(
        "--enable-hkdf",
        action="store_true",
        help="Enable HKDF key derivation",
        default=False,
    )
    hkdf_group.add_argument(
        "--hkdf-rounds",
        type=int,
        default=1,
        help="Number of HKDF chained rounds (default: 1)",
    )
    hkdf_group.add_argument(
        "--hkdf-algorithm",
        choices=["sha224", "sha256", "sha384", "sha512"],
        default="sha256",
        help="Hash algorithm for HKDF (default: sha256)",
    )
    hkdf_group.add_argument(
        "--hkdf-info",
        type=str,
        default="openssl_encrypt_hkdf",
        help="HKDF info string for context (default: openssl_encrypt_hkdf)",
    )

    # PQC options for encryption
    pqc_group = subparser.add_argument_group("Post-Quantum Cryptography options")
    pqc_group.add_argument("--pqc-keyfile", help="Path to save/load the PQC key file")
    pqc_group.add_argument(
        "--pqc-store-key",
        action="store_true",
        help="Store the PQC private key in the encrypted file",
    )

    # Asymmetric encryption options
    asymmetric_group = subparser.add_argument_group(
        "Asymmetric Encryption (Post-Quantum Identity-Based)"
    )
    asymmetric_group.add_argument(
        "--for-identity",
        dest="for_identity",
        action="append",
        metavar="IDENTITY",
        help="Encrypt for recipient identity (can be specified multiple times for multiple recipients). "
        "Switches to asymmetric mode with post-quantum ML-KEM-768 key encapsulation.",
    )
    asymmetric_group.add_argument(
        "--sign-with",
        dest="sign_with",
        metavar="IDENTITY",
        help="Sign with sender identity (required for asymmetric mode). "
        "Uses post-quantum ML-DSA-65 digital signatures.",
    )
    asymmetric_group.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (overrides global --identity-store)",
    )
    asymmetric_group.add_argument(
        "--use-keyserver",
        action="store_true",
        help="Enable keyserver lookup for recipient keys (opt-in). "
        "Fetches public keys from configured keyserver if not found locally.",
    )

    # Keystore options
    keystore_group = subparser.add_argument_group("Keystore options")
    keystore_group.add_argument(
        "--keystore-path",
        help="Path to the keystore file for PQC keys",
    )
    keystore_group.add_argument(
        "--keystore-password",
        help="Password for the keystore (will prompt if not provided)",
    )
    keystore_group.add_argument(
        "--dual-encrypt-key",
        help="PQC key identifier for dual encryption",
    )
    keystore_group.add_argument(
        "--encryption-data",
        help="Additional data to be encrypted alongside the file",
    )

    # Steganography options
    stego_group = subparser.add_argument_group("Steganography options")
    stego_group.add_argument(
        "--stego-hide",
        metavar="COVER_MEDIA",
        help="Hide encrypted data in cover media instead of writing to file (supports PNG, BMP, JPEG, TIFF, WAV, FLAC, MP3, MP4 formats)",
    )
    stego_group.add_argument(
        "--stego-method",
        choices=[
            "lsb",
            "adaptive",
            "f5",
            "outguess",
            "basic",
            "uniform",
            "distortion_comp",
            "multi_level",
        ],
        default="lsb",
        help="Steganographic method to use (default: lsb). For JPEG: f5, outguess, or basic. For images (TIFF/PNG/BMP): lsb or adaptive. For audio (WAV/FLAC/MP3): lsb. For video (MP4): uniform, adaptive, distortion_comp, or multi_level (DCT-based)",
    )
    stego_group.add_argument(
        "--stego-bits-per-channel",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="LSB bits per color channel for images or per sample for audio (default: 1)",
    )
    stego_group.add_argument(
        "--stego-password",
        help="Password for steganographic security (separate from encryption password)",
    )
    stego_group.add_argument(
        "--stego-randomize-pixels",
        action="store_true",
        help="Randomize pixel selection order (requires --stego-password)",
    )
    stego_group.add_argument(
        "--stego-decoy-data", action="store_true", help="Fill unused capacity with decoy data"
    )
    stego_group.add_argument(
        "--jpeg-quality",
        type=int,
        choices=range(70, 101),
        metavar="70-100",
        default=85,
        help="JPEG quality factor for steganography (default: 85)",
    )

    # Video-specific steganography options
    video_stego_group = subparser.add_argument_group("Video steganography options (MP4)")
    video_stego_group.add_argument(
        "--video-quantization-step",
        type=float,
        default=8.0,
        help="DCT quantization step for video steganography (default: 8.0, lower = higher quality but less capacity)",
    )
    video_stego_group.add_argument(
        "--video-adaptation-factor",
        type=float,
        default=1.2,
        help="Adaptation factor for adaptive QIM algorithm (default: 1.2)",
    )
    video_stego_group.add_argument(
        "--video-compensation-factor",
        type=float,
        default=0.5,
        help="Compensation factor for distortion-compensated QIM algorithm (default: 0.5)",
    )
    video_stego_group.add_argument(
        "--video-bits-per-coefficient",
        type=int,
        choices=[1, 2, 3, 4],
        default=2,
        help="Bits per DCT coefficient for multi-level QIM algorithm (default: 2)",
    )
    video_stego_group.add_argument(
        "--video-temporal-spread",
        action="store_true",
        default=True,
        help="Spread data across multiple frames for redundancy (default: enabled)",
    )
    video_stego_group.add_argument(
        "--video-quality-preservation",
        type=int,
        choices=range(1, 11),
        metavar="1-10",
        default=8,
        help="Video quality preservation level (1=max capacity, 10=max quality, default: 8)",
    )

    # HSM plugin arguments for hardware-bound key derivation
    hsm_group = subparser.add_argument_group("HSM Options", "Hardware Security Module integration")
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (Yubikey Challenge-Response). "
        "The HSM adds a hardware-specific pepper to the key derivation, requiring the device "
        "for both encryption and decryption.",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        choices=[1, 2],
        metavar="SLOT",
        help="Manually specify Yubikey slot (1 or 2) for Challenge-Response. "
        "If not specified, the plugin will auto-detect the configured slot.",
    )

    # Remote Pepper plugin arguments for remote pepper storage
    pepper_group = subparser.add_argument_group("Remote Pepper Options", "Remote pepper server integration")
    pepper_group.add_argument(
        "--pepper",
        action="store_true",
        help="Enable remote pepper storage. Auto-generates a unique pepper for this file, "
        "encrypts it with the file password, and stores it on the remote pepper server. "
        "Requires pepper plugin configuration at ~/.openssl_encrypt/plugins/pepper/config.json",
    )
    pepper_group.add_argument(
        "--pepper-name",
        metavar="NAME",
        help="Use an existing named pepper from the remote server instead of auto-generating. "
        "The pepper will be retrieved and decrypted with the file password.",
    )

    # Integrity verification options
    integrity_group = subparser.add_argument_group("Integrity verification options")
    integrity_group.add_argument(
        "--integrity",
        action="store_true",
        help="Store metadata hash on remote integrity server for tamper detection. "
        "Requires integrity plugin configuration at ~/.openssl_encrypt/plugins/integrity/config.json",
    )


def setup_decrypt_parser(subparser):
    """Set up arguments specific to the decrypt command."""
    # Password options
    subparser.add_argument(
        "--password",
        "-p",
        help="Password (will prompt if not provided, or use CRYPT_PASSWORD environment variable)",
    )
    subparser.add_argument(
        "--force-password",
        action="store_true",
        help="Force acceptance of weak passwords (use with caution)",
    )

    # I/O options
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file to decrypt",
    )
    subparser.add_argument("--output", "-o", help="Output file (optional)")
    subparser.add_argument(
        "--overwrite",
        "-f",
        action="store_true",
        help="Overwrite the input file with the output",
    )
    subparser.add_argument(
        "--shred",
        "-s",
        action="store_true",
        help="Securely delete the original file after decryption",
    )
    subparser.add_argument(
        "--shred-passes",
        type=int,
        default=3,
        help="Number of passes for secure deletion (default: 3)",
    )

    # Display options
    subparser.add_argument(
        "--no-estimate",
        action="store_true",
        help="Suppress decryption time/memory estimation display (useful when you trust the file)",
    )

    # PQC options for decryption
    pqc_group = subparser.add_argument_group("Post-Quantum Cryptography options")
    pqc_group.add_argument("--pqc-keyfile", help="Path to load the PQC key file for decryption")
    pqc_group.add_argument(
        "--pqc-allow-mixed-operations",
        action="store_true",
        help="Allow files encrypted with classic algorithms to be decrypted using PQC settings",
    )

    # Asymmetric decryption options
    asymmetric_group = subparser.add_argument_group(
        "Asymmetric Decryption (Post-Quantum Identity-Based)"
    )
    asymmetric_group.add_argument(
        "--with-key",
        dest="key_identity",
        metavar="IDENTITY",
        help="Decrypt using this identity's private key (for asymmetric mode)",
    )
    asymmetric_group.add_argument(
        "--verify-from",
        dest="verify_from",
        metavar="IDENTITY",
        help="Verify signature from this sender identity. "
        "If not specified, will attempt to verify using sender info from metadata.",
    )
    asymmetric_group.add_argument(
        "--no-verify",
        dest="skip_verification",
        action="store_true",
        help="Skip signature verification (DANGEROUS! Only use if you trust the source)",
    )
    asymmetric_group.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (overrides global --identity-store)",
    )

    # Steganography options
    stego_group = subparser.add_argument_group("Steganography options")
    stego_group.add_argument(
        "--stego-extract",
        action="store_true",
        help="Extract encrypted data from steganographic media (input must be stego image, audio, or video file)",
    )
    stego_group.add_argument(
        "--stego-method",
        choices=[
            "lsb",
            "adaptive",
            "f5",
            "outguess",
            "basic",
            "uniform",
            "distortion_comp",
            "multi_level",
        ],
        default="lsb",
        help="Steganographic method used for hiding (default: lsb). For JPEG: f5, outguess, or basic. For TIFF/PNG/BMP/WEBP: lsb or adaptive. For video (MP4): uniform, adaptive, distortion_comp, or multi_level (DCT-based)",
    )
    stego_group.add_argument(
        "--stego-bits-per-channel",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="LSB bits per color channel used (default: 1) - ignored for JPEG methods",
    )
    stego_group.add_argument(
        "--stego-password",
        help="Password for steganographic security (separate from encryption password)",
    )
    stego_group.add_argument(
        "--jpeg-quality",
        type=int,
        choices=range(70, 101),
        metavar="70-100",
        default=85,
        help="JPEG quality factor used for steganography (default: 85)",
    )

    # Video-specific steganography options (for extraction)
    video_stego_group = subparser.add_argument_group("Video steganography options (MP4)")
    video_stego_group.add_argument(
        "--video-quantization-step",
        type=float,
        default=8.0,
        help="DCT quantization step used for video steganography (default: 8.0)",
    )
    video_stego_group.add_argument(
        "--video-adaptation-factor",
        type=float,
        default=1.2,
        help="Adaptation factor used for adaptive QIM algorithm (default: 1.2)",
    )
    video_stego_group.add_argument(
        "--video-compensation-factor",
        type=float,
        default=0.5,
        help="Compensation factor used for distortion-compensated QIM algorithm (default: 0.5)",
    )
    video_stego_group.add_argument(
        "--video-bits-per-coefficient",
        type=int,
        choices=[1, 2, 3, 4],
        default=2,
        help="Bits per DCT coefficient used for multi-level QIM algorithm (default: 2)",
    )
    video_stego_group.add_argument(
        "--video-temporal-spread",
        action="store_true",
        default=True,
        help="Data was spread across multiple frames during hiding (default: enabled)",
    )
    video_stego_group.add_argument(
        "--video-quality-preservation",
        type=int,
        choices=range(1, 11),
        metavar="1-10",
        default=8,
        help="Video quality preservation level used during hiding (default: 8)",
    )

    # HSM plugin arguments for hardware-bound key derivation
    hsm_group = subparser.add_argument_group("HSM Options", "Hardware Security Module integration")
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (Yubikey Challenge-Response). "
        "Required if the file was encrypted with an HSM plugin.",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        choices=[1, 2],
        metavar="SLOT",
        help="Manually specify Yubikey slot (1 or 2) for Challenge-Response. "
        "If not specified, the slot will be read from file metadata or auto-detected.",
    )

    # Integrity verification options
    integrity_group = subparser.add_argument_group("Integrity verification options")
    integrity_group.add_argument(
        "--verify-integrity",
        action="store_true",
        help="Verify metadata integrity with remote server before decryption. "
        "Protects against DoS attacks from tampered metadata with expensive hash/KDF parameters. "
        "Requires integrity plugin configuration at ~/.openssl_encrypt/plugins/integrity/config.json",
    )


def setup_shred_parser(subparser):
    """Set up arguments specific to the shred command."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file or directory to shred (supports glob patterns)",
    )
    subparser.add_argument(
        "--shred-passes",
        type=int,
        default=3,
        help="Number of passes for secure deletion (default: 3)",
    )
    subparser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Process directories recursively when shredding",
    )


def setup_generate_password_parser(subparser):
    """Set up arguments specific to the generate-password command."""
    subparser.add_argument(
        "length",
        type=int,
        nargs="?",
        default=32,
        help="Password length (default: 32)",
    )
    subparser.add_argument(
        "--use-lowercase",
        action="store_true",
        help="Include lowercase letters",
    )
    subparser.add_argument(
        "--use-uppercase",
        action="store_true",
        help="Include uppercase letters",
    )
    subparser.add_argument(
        "--use-digits",
        action="store_true",
        help="Include digits",
    )
    subparser.add_argument(
        "--use-special",
        action="store_true",
        help="Include special characters",
    )


def setup_simple_parser(subparser):
    """Set up arguments for simple commands (security-info, check-argon2, check-pqc, version)."""
    # These commands don't need any special arguments
    pass


def setup_analyze_security_parser(subparser):
    """Set up arguments for analyze-security command."""
    # Add only security-related arguments (no file I/O required)

    # Hash options
    hash_group = subparser.add_argument_group("Hash options")

    # SHA family arguments
    hash_group.add_argument(
        "--sha256-rounds",
        type=int,
        nargs="?",
        const=1000000,
        default=0,
        help="Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha512-rounds",
        type=int,
        nargs="?",
        const=1000000,
        default=0,
        help="Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake2b-rounds",
        type=int,
        nargs="?",
        const=1000000,
        default=0,
        help="Number of BLAKE2b iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake3-rounds",
        type=int,
        nargs="?",
        const=1000000,
        default=0,
        help="Number of BLAKE3 iterations (default: 1,000,000 if flag provided without value)",
    )

    # KDF options
    kdf_group = subparser.add_argument_group("Key Derivation Function options")

    # Argon2 options
    kdf_group.add_argument(
        "--enable-argon2",
        action="store_true",
        default=False,
        help="Enable Argon2 password hashing (requires argon2-cffi package)",
    )
    kdf_group.add_argument(
        "--argon2-rounds",
        type=int,
        default=0,
        help="Argon2 rounds/iterations (default when enabled: 10)",
    )
    kdf_group.add_argument(
        "--argon2-memory-cost",
        type=int,
        default=0,
        help="Argon2 memory cost in KB (default: 1048576 = 1GB)",
    )
    kdf_group.add_argument(
        "--argon2-time-cost",
        type=int,
        default=0,
        help="Argon2 time cost (iterations, default: 3)",
    )
    kdf_group.add_argument(
        "--argon2-parallelism",
        type=int,
        default=0,
        help="Argon2 parallelism (default: 4)",
    )

    # Scrypt options
    kdf_group.add_argument(
        "--scrypt-n",
        type=int,
        default=0,
        help="Scrypt N parameter (default: 16384)",
    )
    kdf_group.add_argument(
        "--scrypt-r",
        type=int,
        default=8,
        help="Scrypt r parameter (default: 8)",
    )
    kdf_group.add_argument(
        "--scrypt-p",
        type=int,
        default=1,
        help="Scrypt p parameter (default: 1)",
    )

    # PBKDF2 options
    kdf_group.add_argument(
        "--pbkdf2-rounds",
        type=int,
        default=0,
        help="PBKDF2 rounds (default: 100000)",
    )

    # Balloon options
    kdf_group.add_argument(
        "--balloon-space-cost",
        type=int,
        default=0,
        help="Balloon space cost (default: 16)",
    )
    kdf_group.add_argument(
        "--balloon-time-cost",
        type=int,
        default=0,
        help="Balloon time cost (default: 20)",
    )

    # HKDF options
    kdf_group.add_argument(
        "--hkdf-rounds",
        type=int,
        default=0,
        help="HKDF rounds (default: 1)",
    )
    kdf_group.add_argument(
        "--hkdf-hash-algorithm",
        choices=["sha256", "sha512", "sha224", "sha384"],
        default="sha256",
        help="Hash algorithm for HKDF (default: sha256)",
    )

    # Encryption algorithm options
    algo_group = subparser.add_argument_group("Encryption algorithm options")
    algo_group.add_argument(
        "--encryption-data-algorithm",
        choices=[
            "aes-gcm",
            "aes-gcm-siv",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "aes-siv",
            "aes-ocb3",
            "fernet",
        ],
        default="aes-gcm",
        help="Data encryption algorithm (default: aes-gcm)",
    )

    # Post-quantum options
    pqc_group = subparser.add_argument_group("Post-quantum cryptography options")
    pqc_group.add_argument(
        "--pqc-algorithm",
        choices=[
            "none",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
            "kyber-512",
            "kyber-768",
            "kyber-1024",
            "hqc-128",
            "hqc-192",
            "hqc-256",
        ],
        default="none",
        help="Post-quantum encryption algorithm (default: none)",
    )


def setup_analyze_config_parser(subparser):
    """Set up arguments specific to the analyze-config command"""
    # Add basic options but also add encryption/security options for analysis
    setup_analyze_security_parser(subparser)

    # Add analyze-config specific options
    subparser.add_argument(
        "--use-case",
        choices=["personal", "business", "compliance", "archival"],
        help="Specify use case for context-aware analysis:\n"
        "  personal   - Personal files and documents\n"
        "  business   - Business documents and sensitive data\n"
        "  compliance - Regulatory compliance requirements\n"
        "  archival   - Long-term storage with future-proofing",
    )

    subparser.add_argument(
        "--compliance-frameworks",
        nargs="*",
        choices=["fips_140_2", "common_criteria", "nist_guidelines"],
        help="Check compliance with specific frameworks:\n"
        "  fips_140_2      - FIPS 140-2 requirements\n"
        "  common_criteria - Common Criteria standards\n"
        "  nist_guidelines - NIST cryptographic guidelines",
    )

    subparser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="Output format for analysis results (default: text)",
    )


def setup_template_parser(subparser):
    """Set up arguments specific to the template command"""
    # Create subparsers for template operations
    template_subparsers = subparser.add_subparsers(
        dest="template_action", help="Template management operations", metavar="operation"
    )

    # List templates
    list_parser = template_subparsers.add_parser("list", help="List available templates")
    list_parser.add_argument(
        "--use-case",
        choices=["personal", "business", "compliance", "archival"],
        help="Filter templates by use case",
    )
    list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # Create template
    create_parser = template_subparsers.add_parser(
        "create", help="Create new template from wizard configuration"
    )
    create_parser.add_argument("name", help="Template name")
    create_parser.add_argument("--description", default="", help="Template description")
    create_parser.add_argument(
        "--use-cases",
        nargs="*",
        choices=["personal", "business", "compliance", "archival"],
        help="Use cases this template is suitable for",
    )
    create_parser.add_argument(
        "--format", choices=["json", "yaml"], default="json", help="Template format (default: json)"
    )
    create_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing template"
    )

    # Analyze template
    analyze_parser = template_subparsers.add_parser(
        "analyze", help="Analyze template security and compatibility"
    )
    analyze_parser.add_argument("template", help="Template name or file path")
    analyze_parser.add_argument(
        "--use-case",
        choices=["personal", "business", "compliance", "archival"],
        help="Analyze for specific use case",
    )
    analyze_parser.add_argument(
        "--compliance-frameworks",
        nargs="*",
        choices=["fips_140_2", "common_criteria", "nist_guidelines"],
        help="Check compliance with frameworks",
    )

    # Compare templates
    compare_parser = template_subparsers.add_parser("compare", help="Compare two templates")
    compare_parser.add_argument("template1", help="First template name or file path")
    compare_parser.add_argument("template2", help="Second template name or file path")
    compare_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # Recommend templates
    recommend_parser = template_subparsers.add_parser(
        "recommend", help="Get template recommendations for use case"
    )
    recommend_parser.add_argument(
        "use_case",
        choices=["personal", "business", "compliance", "archival"],
        help="Use case to recommend templates for",
    )
    recommend_parser.add_argument(
        "--max-results", type=int, default=3, help="Maximum number of recommendations (default: 3)"
    )

    # Delete template
    delete_parser = template_subparsers.add_parser("delete", help="Delete a template")
    delete_parser.add_argument("template", help="Template name or file path to delete")
    delete_parser.add_argument(
        "--force", action="store_true", help="Force deletion without confirmation"
    )


def setup_smart_recommendations_parser(subparser):
    """Set up arguments specific to the smart-recommendations command."""
    # Create subparsers for smart recommendations operations
    recs_subparsers = subparser.add_subparsers(
        dest="recommendations_action", help="Smart recommendations operations", metavar="operation"
    )

    # Get recommendations
    get_parser = recs_subparsers.add_parser("get", help="Get personalized recommendations")
    get_parser.add_argument(
        "--user-id",
        default="default",
        help="User ID for personalized recommendations (default: default)",
    )
    get_parser.add_argument(
        "--user-type",
        choices=["personal", "business", "developer", "compliance"],
        help="Type of user for context-aware recommendations",
    )
    get_parser.add_argument(
        "--experience-level",
        choices=["beginner", "intermediate", "advanced", "expert"],
        help="Experience level for appropriate recommendations",
    )
    get_parser.add_argument(
        "--use-cases",
        nargs="*",
        choices=["personal", "business", "compliance", "archival"],
        help="Primary use cases for targeted recommendations",
    )
    get_parser.add_argument(
        "--data-sensitivity",
        choices=["low", "medium", "high", "top_secret"],
        help="Data sensitivity level",
    )
    get_parser.add_argument(
        "--performance-priority",
        choices=["speed", "security", "balanced"],
        help="Performance priority for optimization recommendations",
    )
    get_parser.add_argument(
        "--compliance-requirements",
        nargs="*",
        choices=["fips_140_2", "common_criteria", "nist_guidelines"],
        help="Compliance frameworks to consider",
    )
    get_parser.add_argument(
        "--analyze-current",
        action="store_true",
        help="Analyze current configuration and provide improvement recommendations",
    )

    # Profile management
    profile_parser = recs_subparsers.add_parser(
        "profile", help="Manage user profiles for personalized recommendations"
    )
    profile_parser.add_argument(
        "--user-id", default="default", help="User ID for profile operations (default: default)"
    )
    profile_group = profile_parser.add_mutually_exclusive_group(required=True)
    profile_group.add_argument(
        "--create", action="store_true", help="Create new user profile interactively"
    )
    profile_group.add_argument("--show", action="store_true", help="Show existing user profile")

    # Feedback system
    feedback_parser = recs_subparsers.add_parser(
        "feedback", help="Provide feedback on recommendations for learning"
    )
    feedback_parser.add_argument(
        "recommendation_id", help="ID of the recommendation to provide feedback on"
    )
    feedback_parser.add_argument(
        "accepted", type=bool, help="Whether the recommendation was accepted (True/False)"
    )
    feedback_parser.add_argument(
        "--user-id", default="default", help="User ID for feedback (default: default)"
    )
    feedback_parser.add_argument("--comment", help="Optional comment about the recommendation")

    # Quick recommendations
    quick_parser = recs_subparsers.add_parser(
        "quick", help="Get quick recommendations for immediate use"
    )
    quick_parser.add_argument(
        "use_case",
        choices=["personal", "business", "compliance", "archival"],
        help="Use case for quick recommendations",
    )
    quick_parser.add_argument(
        "--experience-level",
        choices=["beginner", "intermediate", "advanced", "expert"],
        default="intermediate",
        help="Experience level (default: intermediate)",
    )


def setup_identity_parser(subparser):
    """Set up arguments for the identity command."""
    # Global identity store option
    subparser.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (default: ~/.openssl_encrypt/identities/)",
    )

    # Create subparsers for identity subcommands
    identity_subparsers = subparser.add_subparsers(
        dest="identity_action", help="Identity management operations", metavar="operation"
    )

    # Create identity
    create_parser = identity_subparsers.add_parser("create", help="Create new identity")
    create_parser.add_argument("--name", required=True, help="Identity name")
    create_parser.add_argument("--email", help="Email address (optional)")
    create_parser.add_argument(
        "--kem-algorithm",
        choices=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        default="ML-KEM-768",
        help="KEM algorithm (default: ML-KEM-768)",
    )
    create_parser.add_argument(
        "--sig-algorithm",
        choices=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        default="ML-DSA-65",
        help="Signature algorithm (default: ML-DSA-65)",
    )
    create_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing identity"
    )
    create_parser.add_argument(
        "--hsm",
        choices=["none", "yubikey", "yubikey-only"],
        default="none",
        help="HSM protection for private keys: "
        "'none' (default, password only), "
        "'yubikey' (password + Yubikey required), "
        "'yubikey-only' (Yubikey only, no password)",
    )
    create_parser.add_argument(
        "--hsm-slot",
        type=int,
        choices=[1, 2],
        help="Yubikey slot (1 or 2, default: auto-detect)",
    )
    create_parser.add_argument(
        "--no-touch",
        action="store_true",
        help="Disable Yubikey touch requirement (less secure)",
    )

    # List identities
    list_parser = identity_subparsers.add_parser("list", help="List all identities")
    list_parser.add_argument(
        "--include-contacts",
        action="store_true",
        default=True,
        help="Include contacts (default: True)",
    )

    # Show identity details
    show_parser = identity_subparsers.add_parser("show", help="Show identity details")
    show_parser.add_argument("identity_name", help="Identity name to show")

    # Export public identity
    export_parser = identity_subparsers.add_parser("export", help="Export public identity")
    export_parser.add_argument("identity_name", help="Identity name to export")
    export_parser.add_argument("--output", "-o", help="Output file (default: <name>_public.json)")
    export_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing file")

    # Import public identity
    import_parser = identity_subparsers.add_parser("import", help="Import public identity")
    import_parser.add_argument("--file", required=True, help="JSON file to import")
    import_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing identity"
    )

    # Delete identity
    delete_parser = identity_subparsers.add_parser("delete", help="Delete identity")
    delete_parser.add_argument("identity_name", help="Identity name to delete")
    delete_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Change password
    change_password_parser = identity_subparsers.add_parser(
        "change-password", help="Change identity passphrase"
    )
    change_password_parser.add_argument("identity_name", help="Identity name")


def setup_test_parser(subparser):
    """Set up arguments for the test command."""
    # Create subparsers for test subcommands
    test_subparsers = subparser.add_subparsers(
        dest="test_action", help="Test suite to run", metavar="test_type"
    )

    # Fuzz testing
    fuzz_parser = test_subparsers.add_parser("fuzz", help="Run fuzzing tests")
    fuzz_parser.add_argument("--iterations", type=int, default=5, help="Number of test iterations")
    fuzz_parser.add_argument("--algorithm", help="Test specific algorithm")
    fuzz_parser.add_argument("--seed", type=int, help="Random seed for reproducible tests")

    # Side-channel testing
    sidechannel_parser = test_subparsers.add_parser(
        "side-channel", help="Run side-channel resistance tests"
    )
    sidechannel_parser.add_argument("--algorithm", help="Test specific algorithm")
    sidechannel_parser.add_argument(
        "--timing-threshold",
        type=float,
        default=20.0,
        help="Timing difference threshold percentage (default: 20.0)",
    )

    # Known-Answer Tests
    kat_parser = test_subparsers.add_parser("kat", help="Run Known-Answer Tests")
    kat_parser.add_argument(
        "--test-category",
        choices=["hash", "hmac", "kdf", "encryption", "all"],
        default="all",
        help="Category of tests to run",
    )

    # Benchmark testing
    benchmark_parser = test_subparsers.add_parser("benchmark", help="Run performance benchmarks")
    benchmark_parser.add_argument("--algorithms", nargs="+", help="Algorithms to benchmark")
    benchmark_parser.add_argument(
        "--file-sizes", nargs="+", type=int, help="File sizes to test (in bytes)"
    )
    benchmark_parser.add_argument(
        "--iterations", type=int, default=3, help="Number of benchmark iterations"
    )
    benchmark_parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save results as baseline for regression detection",
    )

    # Memory testing
    memory_parser = test_subparsers.add_parser("memory", help="Run memory safety tests")
    memory_parser.add_argument(
        "--test-iterations", type=int, default=10, help="Number of memory test iterations"
    )
    memory_parser.add_argument(
        "--leak-threshold", type=float, default=1.0, help="Memory leak threshold in MB"
    )

    # Run all tests
    all_parser = test_subparsers.add_parser("all", help="Run all test suites")
    all_parser.add_argument("--parallel", action="store_true", help="Run test suites in parallel")
    all_parser.add_argument("--max-workers", type=int, default=3, help="Maximum parallel workers")

    # Common test arguments
    for parser in [
        fuzz_parser,
        sidechannel_parser,
        kat_parser,
        benchmark_parser,
        memory_parser,
        all_parser,
    ]:
        parser.add_argument(
            "--output-dir", help="Directory for test reports (default: test_reports)"
        )
        parser.add_argument(
            "--output-format",
            nargs="+",
            choices=["json", "html", "text"],
            default=["json", "html"],
            help="Output format(s) for test reports",
        )
        parser.add_argument("--quiet", action="store_true", help="Suppress test progress output")


def setup_list_algorithms_parser(subparser):
    """Set up arguments for list-algorithms command (registry-based)."""
    subparser.add_argument(
        "--category",
        choices=["ciphers", "hashes", "kdfs", "kems", "signatures", "all"],
        default="all",
        help="Algorithm category to list (default: all)",
    )
    subparser.add_argument(
        "--format",
        choices=["simple", "detailed"],
        default="detailed",
        help="Output format (default: detailed)",
    )


def setup_hsm_parser(subparser):
    """Set up arguments for the hsm (Hardware Security Module) command."""
    hsm_subparsers = subparser.add_subparsers(
        dest="hsm_action",
        help="HSM management action",
        required=True,
    )

    # FIDO2 registration subcommand
    fido2_register_parser = hsm_subparsers.add_parser(
        "fido2-register",
        help="Register new FIDO2 credential for hardware-bound encryption"
    )
    fido2_register_parser.add_argument(
        "--description",
        "-d",
        help="Human-readable description for the security key (e.g., 'YubiKey 5 NFC')",
    )
    fido2_register_parser.add_argument(
        "--backup",
        action="store_true",
        help="Register as backup credential (primary must already exist)",
    )
    fido2_register_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )

    # FIDO2 status subcommand
    fido2_status_parser = hsm_subparsers.add_parser(
        "fido2-status",
        help="Show FIDO2 registration status and list registered credentials"
    )
    fido2_status_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )

    # FIDO2 test subcommand
    fido2_test_parser = hsm_subparsers.add_parser(
        "fido2-test",
        help="Test FIDO2 pepper derivation with a random salt"
    )
    fido2_test_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )

    # FIDO2 list devices subcommand
    hsm_subparsers.add_parser(
        "fido2-list",
        help="List connected FIDO2 devices and their capabilities"
    )

    # FIDO2 unregister subcommand
    fido2_unregister_parser = hsm_subparsers.add_parser(
        "fido2-unregister",
        help="Remove FIDO2 credential registration"
    )
    fido2_unregister_parser.add_argument(
        "--credential-id",
        "-c",
        help="Specific credential ID to remove (e.g., 'primary', 'backup-1')",
    )
    fido2_unregister_parser.add_argument(
        "--all",
        dest="remove_all",
        action="store_true",
        help="Remove all registered credentials",
    )
    fido2_unregister_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )
    fido2_unregister_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )


def setup_keyserver_parser(subparser):
    """Set up arguments for the keyserver command."""
    keyserver_subparsers = subparser.add_subparsers(
        dest="keyserver_action",
        help="Keyserver management action",
        required=True,
    )

    # Enable subcommand
    keyserver_subparsers.add_parser("enable", help="Enable keyserver plugin (opt-in)")

    # Disable subcommand
    keyserver_subparsers.add_parser("disable", help="Disable keyserver plugin")

    # Status subcommand
    keyserver_subparsers.add_parser("status", help="Show keyserver status and configuration")

    # Register subcommand (no auth required)
    register_parser = keyserver_subparsers.add_parser(
        "register", help="Register with keyserver and obtain API token"
    )
    register_parser.add_argument(
        "--server",
        help="Specific keyserver URL to register with (default: first configured server)",
    )

    # Search subcommand (public, no auth)
    search_parser = keyserver_subparsers.add_parser(
        "search", help="Search for public key on keyserver"
    )
    search_parser.add_argument("identifier", help="Fingerprint, name, or email to search for")
    search_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Import subcommand (public, no auth)
    import_parser = keyserver_subparsers.add_parser(
        "import", help="Import public key from keyserver to local store"
    )
    import_parser.add_argument("identifier", help="Fingerprint, name, or email to import")
    import_parser.add_argument(
        "--no-trust-prompt", action="store_true", help="Skip trust confirmation (dangerous)"
    )

    # Upload subcommand (requires API token)
    upload_parser = keyserver_subparsers.add_parser(
        "upload", help="Upload public key to keyserver (requires API token)"
    )
    upload_parser.add_argument("identity_name", help="Name of identity to upload")

    # Revoke subcommand (requires API token)
    revoke_parser = keyserver_subparsers.add_parser(
        "revoke", help="Revoke key on keyserver (requires API token)"
    )
    revoke_parser.add_argument("fingerprint", help="Fingerprint of key to revoke")

    # Token management subcommands
    set_token_parser = keyserver_subparsers.add_parser(
        "set-token", help="Set API token for uploads (stored securely)"
    )
    set_token_parser.add_argument("token", help="API token (Bearer token)")

    keyserver_subparsers.add_parser("show-token", help="Show current API token (masked)")

    keyserver_subparsers.add_parser("clear-token", help="Delete API token")

    # Cache management
    cache_clear_parser = keyserver_subparsers.add_parser(
        "cache-clear", help="Clear local keyserver cache"
    )
    cache_clear_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    keyserver_subparsers.add_parser("cache-stats", help="Show cache statistics")


def setup_telemetry_parser(subparser):
    """Set up arguments for the telemetry command."""
    telemetry_subparsers = subparser.add_subparsers(
        dest="telemetry_action",
        help="Telemetry management action",
        required=True,
    )

    # Status subcommand
    telemetry_subparsers.add_parser("status", help="Show telemetry status and statistics")

    # Show pending events subcommand
    show_pending_parser = telemetry_subparsers.add_parser(
        "show-pending", help="Show pending telemetry events (transparency)"
    )
    show_pending_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    show_pending_parser.add_argument(
        "--limit", type=int, default=100, help="Maximum number of events to show (default: 100)"
    )

    # Flush subcommand
    telemetry_subparsers.add_parser("flush", help="Upload all pending events immediately")

    # Clear subcommand
    clear_parser = telemetry_subparsers.add_parser(
        "clear", help="Delete all pending events without uploading"
    )
    clear_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    # Opt-out subcommand
    opt_out_parser = telemetry_subparsers.add_parser(
        "opt-out", help="Completely disable telemetry and delete all data"
    )
    opt_out_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")


def create_subparser_main():
    """
    Create a main function that uses subparsers instead of the monolithic approach.

    This is a replacement for the main() function in crypt_cli.py for 1.0.0 compatibility.
    """
    # Set up main argument parser with subcommands
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files with password protection\n\nEnvironment Variables:\n  CRYPT_PASSWORD    Password for encryption/decryption (alternative to -p)",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Global options
    parser.add_argument("--progress", action="store_true", help="Show progress bar")
    parser.add_argument("--verbose", action="store_true", help="Show hash/kdf details")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed debug information (WARNING: logs passwords and sensitive data - test files only!)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except decrypted content and exit code",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Automatic yes to prompts (for install-dependencies command)",
    )
    parser.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (default: ~/.openssl_encrypt/identities/). "
        "Can also be set via OPENSSL_ENCRYPT_IDENTITY_STORE environment variable.",
    )

    # Create subparsers for each command
    subparsers = parser.add_subparsers(
        dest="action",
        help="Available commands",
        metavar="command",
    )

    # Set up subparsers for each command
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt files with password protection",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_encrypt_parser(encrypt_parser)

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt previously encrypted files",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_decrypt_parser(decrypt_parser)

    shred_parser = subparsers.add_parser(
        "shred",
        help="Securely delete files",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_shred_parser(shred_parser)

    generate_password_parser = subparsers.add_parser(
        "generate-password",
        help="Generate cryptographically secure passwords",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_generate_password_parser(generate_password_parser)

    security_info_parser = subparsers.add_parser(
        "security-info",
        help="Display security information and algorithms",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(security_info_parser)

    analyze_security_parser = subparsers.add_parser(
        "analyze-security",
        help="Analyze current security configuration and display security score",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_analyze_security_parser(analyze_security_parser)

    config_wizard_parser = subparsers.add_parser(
        "config-wizard",
        help="Interactive configuration wizard for security settings",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(config_wizard_parser)

    analyze_config_parser = subparsers.add_parser(
        "analyze-config",
        help="Analyze configuration for security, performance, and compatibility",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_analyze_config_parser(analyze_config_parser)

    template_parser = subparsers.add_parser(
        "template",
        help="Template management operations",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_template_parser(template_parser)

    smart_recommendations_parser = subparsers.add_parser(
        "smart-recommendations",
        help="AI-powered security recommendations",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_smart_recommendations_parser(smart_recommendations_parser)

    test_parser = subparsers.add_parser(
        "test",
        help="Run security test suites (fuzz, side-channel, KAT, benchmark, memory)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_test_parser(test_parser)

    identity_parser = subparsers.add_parser(
        "identity",
        help="Manage post-quantum identities for asymmetric encryption",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_identity_parser(identity_parser)

    check_argon2_parser = subparsers.add_parser(
        "check-argon2",
        help="Verify Argon2 implementation",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(check_argon2_parser)

    check_pqc_parser = subparsers.add_parser(
        "check-pqc",
        help="Check post-quantum cryptography support",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(check_pqc_parser)

    version_parser = subparsers.add_parser(
        "version",
        help="Show version information",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(version_parser)

    show_version_file_parser = subparsers.add_parser(
        "show-version-file",
        help="Show detailed version file information",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(show_version_file_parser)

    # Registry-based algorithm listing command
    if REGISTRY_AVAILABLE:
        list_algorithms_parser = subparsers.add_parser(
            "list-algorithms",
            help="List available cryptographic algorithms (ciphers, hashes, KDFs, KEMs, signatures)",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        setup_list_algorithms_parser(list_algorithms_parser)

    # Algorithm availability information (JSON output for GUI)
    if REGISTRY_AVAILABLE:
        subparsers.add_parser(
            "list-available-algorithms",
            help="List all algorithms with availability status and library requirements (JSON output)",
            formatter_class=argparse.RawTextHelpFormatter,
        )

    # Install optional dependencies (liboqs, liboqs-python, threefish)
    subparsers.add_parser(
        "install-dependencies",
        help="Install optional crypto libraries (liboqs, liboqs-python, threefish) after base package install",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Telemetry management command
    telemetry_parser = subparsers.add_parser(
        "telemetry",
        help="Manage telemetry settings and view pending events",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_telemetry_parser(telemetry_parser)

    # Keyserver management command
    keyserver_parser = subparsers.add_parser(
        "keyserver",
        help="Manage keyserver settings and fetch/upload public keys",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_keyserver_parser(keyserver_parser)

    # HSM (Hardware Security Module) management command
    hsm_parser = subparsers.add_parser(
        "hsm",
        help="Manage HSM (Hardware Security Module) plugins and FIDO2 credentials",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_hsm_parser(hsm_parser)

    # Note: Steganography is now integrated into encrypt/decrypt commands
    # rather than separate commands

    # Parse arguments
    args = parser.parse_args()

    # Handle the case where no command is provided
    if args.action is None:
        parser.print_help()
        return 1

    return parser, args
