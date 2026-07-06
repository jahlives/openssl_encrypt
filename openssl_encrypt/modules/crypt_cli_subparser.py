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


def _piv_slot_arg(value):
    """Parse a PIV slot given as hex (9a/0x9a) or as an int. Returns an int."""
    try:
        parsed = int(value, 16) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"invalid PIV slot: {value!r} (use 9a, 9c, 9d, or 9e)")
    if parsed not in (0x9A, 0x9C, 0x9D, 0x9E):
        raise argparse.ArgumentTypeError(
            f"unsupported PIV slot {value!r}; choose one of 9a, 9c, 9d, 9e"
        )
    return parsed


def _add_piv_hsm_arguments(group):
    """Add PIV/PKCS#11 backend arguments to an existing HSM argument group.

    These apply only when ``--hsm piv`` is selected. For PIV, ``--hsm-slot`` is
    reused as the PKCS#11 slot index. The PIN is never a CLI argument -- it is
    prompted interactively with getpass, or supplied by a Bio key's fingerprint.
    """
    group.add_argument(
        "--hsm-pkcs11-lib",
        metavar="PATH",
        help="Path to the PKCS#11 module for '--hsm piv' (e.g. /usr/lib/opensc-pkcs11.so "
        "or the YubiKey ykcs11 module). Required for the PIV backend.",
    )
    group.add_argument(
        "--hsm-piv-slot",
        type=_piv_slot_arg,
        metavar="SLOT",
        default=0x9A,
        help="PIV key slot to sign with: 9a (Authentication, default), 9c (Digital "
        "Signature), 9d (Key Management), or 9e (Card Authentication).",
    )
    group.add_argument(
        "--hsm-biometric",
        action="store_true",
        help="For '--hsm piv' with a biometric (Bio) key: skip the PIN prompt and "
        "authenticate by fingerprint touch instead.",
    )


def _add_keyring_arguments(subparser):
    """Add keyring integration arguments to a subparser.

    The keyring package is an optional dependency. If not installed,
    these flags print a clear error message and exit.
    """
    keyring_group = subparser.add_argument_group(
        "Keyring options", "OS keyring integration (requires 'keyring' package)"
    )
    keyring_group.add_argument(
        "--keyring-store",
        metavar="LABEL",
        help="Store the password in the OS keyring under LABEL after successful operation",
    )
    keyring_group.add_argument(
        "--keyring-load",
        metavar="LABEL",
        help="Load password from the OS keyring by LABEL instead of prompting",
    )
    keyring_group.add_argument(
        "--keyring-remove",
        metavar="LABEL",
        help="Remove a stored password from the OS keyring and exit",
    )


def _add_hash_kdf_arguments(subparser):
    """Add hash algorithm and KDF argument groups to a subparser.

    Shared by encrypt, decrypt, rekey, and derive-password parsers to avoid
    duplicating ~280 lines of argument definitions.
    """
    # Hash options
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

    # SHA family arguments
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

    # Scrypt options
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
        "--scrypt-p",
        type=int,
        default=1,
        help="Scrypt p parameter (parallelization factor)",
    )

    # Argon2 options
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

    # RandomX options
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


def _add_hidden_header_args(subparser):
    """Add the hidden ("whitened") file-format options shared by encrypt/decrypt.

    The hidden format makes the output indistinguishable from random by
    whitening the identifiable metadata header. Keyless mode is
    anti-fingerprinting only; supplying a second password enables keyed mode,
    which gives real metadata confidentiality.
    """
    group = subparser.add_argument_group("hidden format options")
    group.add_argument(
        "--hidden-header",
        action="store_true",
        help="Produce/expect the hidden (whitened) format that looks like random "
        "bytes. Keyless unless a second password is given.",
    )
    group.add_argument(
        "--legacy-format",
        action="store_true",
        help="Force the legacy base64 metadata format (disable hidden-header "
        "handling, including auto-detection on decrypt).",
    )
    group.add_argument(
        "--second-password",
        metavar="PW",
        help="Second password enabling keyed hidden mode (real metadata "
        "confidentiality). DEPRECATED: visible in process list; prefer "
        "--second-password-fd or --second-password-prompt.",
    )
    group.add_argument(
        "--second-password-fd",
        type=int,
        metavar="FD",
        help="Read the second password from file descriptor FD.",
    )
    group.add_argument(
        "--second-password-prompt",
        action="store_true",
        help="Prompt interactively for the second password (keyed hidden mode).",
    )
    group.add_argument(
        "--no-second-password-prompt",
        action="store_true",
        help="Decrypt only: never prompt for a second password, even at an "
        "interactive terminal (stay silent on keyed/unreadable files).",
    )


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
        elif algo == EncryptionAlgorithm.AES_SIV.value:
            description = "AES in SIV mode, synthetic IV"
        elif algo == EncryptionAlgorithm.CHACHA20_POLY1305.value:
            description = "modern AEAD cipher with 12-byte nonce"
        elif algo == EncryptionAlgorithm.XCHACHA20_POLY1305.value:
            description = "ChaCha20-Poly1305 with 24-byte nonce, safer for high-volume encryption"
        elif algo == EncryptionAlgorithm.ML_KEM_512_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 1 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_768_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 3 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_1024_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 5 (NIST FIPS 203)"
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
        help="Password (DEPRECATED: visible in process list. "
        "Use --password-file or OPENSSL_ENCRYPT_PASSWORD env var instead)",
    )
    subparser.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from FILE (use '-' for stdin). "
        "Recommended over --password to avoid process list exposure",
    )
    subparser.add_argument(
        "--password-fd",
        type=int,
        metavar="FD",
        help="Read password from file descriptor FD",
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

    _add_hidden_header_args(subparser)

    # I/O options
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file to encrypt",
    )
    subparser.add_argument("--output", "-o", help="Output file (optional)")
    subparser.add_argument(
        "--armor",
        "-a",
        action="store_true",
        help="Write ASCII-armored (PEM-style Base64) output that is safe to "
        "paste into email, chat or YAML. decrypt auto-detects armored input.",
    )
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

    # Add shared hash/KDF arguments
    _add_hash_kdf_arguments(subparser)

    # Add keyring arguments
    _add_keyring_arguments(subparser)

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
    # Feature #6: encrypt-to-self. Enabled by default so the sender can always
    # recover their own outbound files; --no-encrypt-to-self opts out.
    asymmetric_group.add_argument(
        "--encrypt-to-self",
        dest="encrypt_to_self",
        action="store_true",
        default=True,
        help="Also encrypt to the sender's own identity (--sign-with) so the "
        "sender can later decrypt their own outbound file. Enabled by default.",
    )
    asymmetric_group.add_argument(
        "--no-encrypt-to-self",
        dest="encrypt_to_self",
        action="store_false",
        help="Do not add the sender as a recipient (disable encrypt-to-self).",
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

    # HSM plugin arguments for hardware-bound key derivation
    hsm_group = subparser.add_argument_group("HSM Options", "Hardware Security Module integration")
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (Yubikey Challenge-Response, slots 1..2), "
        "'onlykey' (OnlyKey Challenge-Response, slots 1..12), "
        "'piv' (PIV/PKCS#11 token, see --hsm-pkcs11-lib/--hsm-piv-slot). "
        "The HSM adds a hardware-specific pepper to the key derivation, requiring the device "
        "for both encryption and decryption.",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        metavar="SLOT",
        help="Manually specify the Challenge-Response slot. Valid range is plugin-specific: "
        "YubiKey 1..2, OnlyKey 1..12. "
        "If not specified, the plugin will auto-detect the configured slot.",
    )
    _add_piv_hsm_arguments(hsm_group)

    # Remote Pepper plugin arguments for remote pepper storage
    pepper_group = subparser.add_argument_group(
        "Remote Pepper Options", "Remote pepper server integration"
    )
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

    # Format version options
    format_group = subparser.add_argument_group("Format version options")
    format_group.add_argument(
        "--use-xor-composition",
        action="store_true",
        default=False,
        help="Enable XOR composition key derivation (format v10). "
        "When enabled, intermediate KDF outputs are XOR'd together for enhanced security. "
        "Compatible with 1.3 branch v8 format. "
        "Files encrypted with this flag require openssl_encrypt 1.3.5+ or 1.4+ to decrypt.",
    )
    format_group.add_argument(
        "--independent-xor",
        action="store_true",
        default=False,
        help="Enable independent XOR key derivation (format v11). "
        "Each algorithm processes the original password+salt independently (no chaining). "
        "Provides strongest-component security guarantee (robust XOR-combiner). "
        "Trade-off: Attackers can parallelize, but key is as strong as strongest algorithm. "
        "Mutually exclusive with --use-xor-composition. "
        "Files require openssl_encrypt 1.4.x+ to decrypt.",
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
        help="Password (DEPRECATED: visible in process list. "
        "Use --password-file or OPENSSL_ENCRYPT_PASSWORD env var instead)",
    )
    subparser.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from FILE (use '-' for stdin). "
        "Recommended over --password to avoid process list exposure",
    )
    subparser.add_argument(
        "--password-fd",
        type=int,
        metavar="FD",
        help="Read password from file descriptor FD",
    )
    subparser.add_argument(
        "--force-password",
        action="store_true",
        help="Force acceptance of weak passwords (use with caution)",
    )

    _add_hidden_header_args(subparser)

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

    # Foreign-format interop (feature #5): read-only decryption of files made
    # by other ecosystems. Opt-in and explicit.
    foreign_group = subparser.add_argument_group("Foreign formats (interop, read-only)")
    foreign_group.add_argument(
        "--from",
        dest="from_format",
        choices=["age", "pgp"],
        help="Decrypt a foreign-format file instead of an openssl-encrypt file: "
        "'age' (age/rage) or 'pgp' (passphrase-based OpenPGP, i.e. gpg -c). The "
        "passphrase (age -p / scrypt, or gpg -c) comes from the usual "
        "--password / prompt.",
    )
    foreign_group.add_argument(
        "--age-identity",
        dest="age_identity",
        metavar="FILE",
        action="append",
        help="age secret-key file (keys.txt with AGE-SECRET-KEY-1… lines) for "
        "X25519 recipients; may be given multiple times.",
    )
    foreign_group.add_argument(
        "--pgp-key",
        dest="pgp_key",
        metavar="FILE",
        action="append",
        help="OpenPGP secret-key file (armored or binary) for public-key "
        "messages (--from pgp); the key passphrase comes from --password/prompt. "
        "Without this, --from pgp expects a passphrase-based (gpg -c) message.",
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

    # HSM plugin arguments for hardware-bound key derivation
    hsm_group = subparser.add_argument_group("HSM Options", "Hardware Security Module integration")
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (slots 1..2), 'onlykey' (slots 1..12), 'piv' (PIV/PKCS#11). "
        "Required if the file was encrypted with an HSM plugin.",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        metavar="SLOT",
        help="Manually specify the Challenge-Response slot. Valid range is plugin-specific: "
        "YubiKey 1..2, OnlyKey 1..12. "
        "If not specified, the slot will be read from file metadata or auto-detected.",
    )
    _add_piv_hsm_arguments(hsm_group)

    # Integrity verification options
    integrity_group = subparser.add_argument_group("Integrity verification options")
    integrity_group.add_argument(
        "--verify-integrity",
        action="store_true",
        help="Verify metadata integrity with remote server before decryption. "
        "Protects against DoS attacks from tampered metadata with expensive hash/KDF parameters. "
        "Requires integrity plugin configuration at ~/.openssl_encrypt/plugins/integrity/config.json",
    )

    # Add keyring arguments
    _add_keyring_arguments(subparser)


def setup_rekey_parser(subparser):
    """Set up arguments specific to the rekey command."""
    # Get only algorithms available in 1.0.0
    all_algorithms = get_available_algorithms_1_0()

    # Old password options (for decryption)
    subparser.add_argument(
        "--password",
        "-p",
        help="Old password for decryption (DEPRECATED: visible in process list. "
        "Use --password-file or OPENSSL_ENCRYPT_PASSWORD env var instead)",
    )
    subparser.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read old password from FILE (use '-' for stdin). "
        "Recommended over --password to avoid process list exposure",
    )
    subparser.add_argument(
        "--password-fd",
        type=int,
        metavar="FD",
        help="Read old password from file descriptor FD",
    )

    # New password options (for re-encryption)
    rekey_group = subparser.add_argument_group("Rekey Password Options")
    rekey_group.add_argument(
        "--rekey-password",
        help="New password for re-encryption (DEPRECATED: visible in process list. "
        "Use --rekey-password-file or OPENSSL_ENCRYPT_REKEY_PASSWORD env var instead)",
    )
    rekey_group.add_argument(
        "--rekey-password-file",
        metavar="FILE",
        help="Read new password from FILE (use '-' for stdin). "
        "Recommended over --rekey-password to avoid process list exposure",
    )
    rekey_group.add_argument(
        "--rekey-password-fd",
        type=int,
        metavar="FD",
        help="Read new password from file descriptor FD",
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
        help="Input encrypted file to rekey",
    )
    subparser.add_argument(
        "--output",
        "-o",
        help="Output file (optional, default: rekey in-place)",
    )

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

    # Algorithm options (for re-encryption)
    subparser.add_argument(
        "--algorithm",
        type=str,
        default=None,
        help="New encryption algorithm (default: inherit from file). "
        "Choices: " + ", ".join(sorted(all_algorithms)),
    )

    # Add extended algorithm help
    add_extended_algorithm_help(subparser)

    # Cascade encryption options
    cascade_group = subparser.add_argument_group("Cascade encryption (multi-layer)")
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

    # Hash options
    hash_group = subparser.add_argument_group("Hash options")
    if REGISTRY_AVAILABLE:
        hash_group.description = "Hash algorithm configuration for re-encryption."

    hash_group.add_argument(
        "--kdf-rounds",
        type=int,
        default=0,
        help="Default number of rounds for all KDFs when enabled without specific rounds",
    )
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
        help="Number of SHA-384 iterations",
    )
    hash_group.add_argument(
        "--sha256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-256 iterations",
    )
    hash_group.add_argument(
        "--sha224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-224 iterations",
    )
    hash_group.add_argument(
        "--sha3-256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-256 iterations",
    )
    hash_group.add_argument(
        "--sha3-512-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-512 iterations",
    )
    hash_group.add_argument(
        "--sha3-384-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-384 iterations",
    )
    hash_group.add_argument(
        "--sha3-224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-224 iterations",
    )
    hash_group.add_argument(
        "--blake2b-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE2b iterations",
    )
    hash_group.add_argument(
        "--blake3-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE3 iterations",
    )
    hash_group.add_argument(
        "--shake256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-256 iterations",
    )
    hash_group.add_argument(
        "--shake128-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-128 iterations",
    )

    # Scrypt options
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

    # Argon2 options
    argon2_group = subparser.add_argument_group("Argon2 Options")
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

    # RandomX options
    randomx_group = subparser.add_argument_group("RandomX options")
    randomx_group.add_argument(
        "--enable-randomx",
        action="store_true",
        help="Enable RandomX key derivation (requires pyrx package)",
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
        help="Time cost parameter for Balloon hashing (default: 3)",
    )
    balloon_group.add_argument(
        "--balloon-space-cost",
        type=int,
        default=65536,
        help="Space cost parameter for Balloon hashing in bytes (default: 65536)",
    )
    balloon_group.add_argument(
        "--balloon-parallelism",
        type=int,
        default=4,
        help="Parallelism parameter for Balloon hashing (default: 4)",
    )
    balloon_group.add_argument(
        "--balloon-rounds",
        type=int,
        default=0,
        help="Number of rounds for Balloon hashing (default when enabled: 10)",
    )
    balloon_group.add_argument(
        "--balloon-hash-len",
        type=int,
        default=32,
        help="Length of the final hash output in bytes for Balloon hashing",
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

    # Display options
    subparser.add_argument(
        "--no-estimate",
        action="store_true",
        help="Suppress decryption time/memory estimation display",
    )

    # HSM plugin arguments
    hsm_group = subparser.add_argument_group("HSM Options", "Hardware Security Module integration")
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (slots 1..2), 'onlykey' (slots 1..12), 'piv' (PIV/PKCS#11). "
        "Required if the file was encrypted with an HSM plugin.",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        metavar="SLOT",
        help="Manually specify the Challenge-Response slot. " "YubiKey 1..2, OnlyKey 1..12.",
    )
    _add_piv_hsm_arguments(hsm_group)

    # Remote Pepper options
    pepper_group = subparser.add_argument_group(
        "Remote Pepper Options", "Remote pepper server integration"
    )
    pepper_group.add_argument(
        "--pepper",
        action="store_true",
        help="Enable remote pepper storage for re-encrypted file.",
    )
    pepper_group.add_argument(
        "--pepper-name",
        metavar="NAME",
        help="Use an existing named pepper from the remote server.",
    )

    # Format version options
    format_group = subparser.add_argument_group("Format version options")
    format_group.add_argument(
        "--use-xor-composition",
        action="store_true",
        default=False,
        help="Enable XOR composition key derivation (format v10).",
    )
    format_group.add_argument(
        "--independent-xor",
        action="store_true",
        default=False,
        help="Enable independent XOR key derivation (format v11). "
        "Provides strongest-component security guarantee (robust XOR-combiner).",
    )

    # Integrity options
    integrity_group = subparser.add_argument_group("Integrity options")
    integrity_group.add_argument(
        "--verify-integrity",
        action="store_true",
        help="Verify metadata integrity before decryption.",
    )
    integrity_group.add_argument(
        "--integrity",
        action="store_true",
        help="Store metadata hash on remote integrity server for re-encrypted file.",
    )

    # Password policy options
    policy_group = subparser.add_argument_group("Password Policy")
    policy_group.add_argument(
        "--password-policy",
        default="standard",
        choices=["none", "basic", "standard", "strict"],
        help="Password policy level for new password (default: standard)",
    )
    policy_group.add_argument(
        "--min-password-length",
        type=int,
        help="Minimum password length override",
    )
    policy_group.add_argument(
        "--min-password-entropy",
        type=float,
        help="Minimum password entropy override",
    )
    policy_group.add_argument(
        "--strict-strength",
        action="store_true",
        help="Gate on the pattern-aware strength estimate instead of raw entropy",
    )
    policy_group.add_argument(
        "--disable-common-password-check",
        action="store_true",
        help="Disable common password list check",
    )

    # Add keyring arguments
    _add_keyring_arguments(subparser)


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


def setup_check_password_parser(subparser):
    """Set up arguments specific to the check-password command.

    Read-only strength/policy report for a password supplied via ``-p``, the
    CRYPT_PASSWORD environment variable, piped on stdin, or an interactive
    prompt. Never writes, encrypts, or echoes the password.
    """
    subparser.add_argument(
        "--password",
        "-p",
        help="Password to check (DEPRECATED: visible in the process list and "
        "shell history. Prefer stdin, an interactive prompt, or CRYPT_PASSWORD)",
    )
    subparser.add_argument(
        "--password-policy",
        default="standard",
        choices=["none", "minimal", "basic", "standard", "paranoid"],
        help="Policy level to evaluate against (default: standard; 'none' reports strength only)",
    )
    subparser.add_argument(
        "--strict-strength",
        action="store_true",
        help="Gate the policy on the pattern-aware estimate instead of raw entropy",
    )
    subparser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON on stdout (human report otherwise goes to stderr)",
    )


def setup_generate_password_parser(subparser):
    """Set up arguments specific to the generate-password command."""
    subparser.add_argument(
        "length",
        type=int,
        nargs="?",
        default=32,
        help="Password length (default: 32, character-based mode only)",
    )
    subparser.add_argument(
        "--use-lowercase",
        action="store_true",
        help="Include lowercase letters (character-based mode)",
    )
    subparser.add_argument(
        "--use-uppercase",
        action="store_true",
        help="Include uppercase letters (character-based mode)",
    )
    subparser.add_argument(
        "--use-digits",
        action="store_true",
        help="Include digits (character-based mode)",
    )
    subparser.add_argument(
        "--use-special",
        action="store_true",
        help="Include special characters (character-based mode)",
    )

    # Diceware mode (mutually exclusive with character-based flags;
    # mutex is enforced at runtime in the handler, not by argparse, so
    # we can produce a more actionable error message than argparse's).
    dice_group = subparser.add_argument_group(
        "Diceware mode",
        "Generate a passphrase by drawing words from a wordlist "
        "(mutually exclusive with character-based generation).",
    )
    dice_group.add_argument(
        "--dice",
        action="store_true",
        help="Generate a Diceware-style passphrase instead of a " "character-based password",
    )
    dice_group.add_argument(
        "--dice-count",
        type=int,
        default=10,
        metavar="N",
        help="Number of words in the passphrase (default: 10, ~129 bits with "
        "the bundled EFF Large Wordlist)",
    )
    dice_group.add_argument(
        "--dice-sep",
        type=str,
        default="",
        metavar="SEP",
        help='Separator between words (default: "" for maximum compatibility '
        "with password fields that strip whitespace)",
    )
    dice_group.add_argument(
        "--dice-list",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to a custom wordlist (default: bundled EFF Large Wordlist). "
        "Accepts both EFF format ('<dice>\\t<word>') and plain "
        "one-word-per-line.",
    )
    dice_group.add_argument(
        "--force-wordlist",
        action="store_true",
        help="Override the 1024-word minimum for custom wordlists "
        "(small lists are otherwise rejected because they yield "
        "less than 10 bits of entropy per word)",
    )


def setup_derive_password_parser(subparser):
    """Set up arguments specific to the derive-password command.

    This command derives a key from a password using configured hash/KDF
    algorithms and prints only the derived key to stdout. It does NOT
    register -i, -o, -a, or --cascade so argparse rejects them.
    """
    # Password options
    subparser.add_argument(
        "--password",
        "-p",
        help="Password (DEPRECATED: visible in process list. "
        "Use --password-file or OPENSSL_ENCRYPT_PASSWORD env var instead)",
    )
    subparser.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from FILE (use '-' for stdin). "
        "Recommended over --password to avoid process list exposure",
    )
    subparser.add_argument(
        "--password-fd",
        type=int,
        metavar="FD",
        help="Read password from file descriptor FD",
    )
    subparser.add_argument(
        "--force-password",
        action="store_true",
        help="Force acceptance of weak passwords (use with caution)",
    )
    subparser.add_argument(
        "--confirm",
        action="store_true",
        help="Prompt for the password twice and verify they match. Recommended "
        "for derive-password since a typo would silently produce a wrong "
        "but valid-looking derived value with no way to detect the mistake "
        "until you try to reuse the output elsewhere.",
    )

    # HSM options — mirror the encrypt-side --hsm/--hsm-slot flags so a
    # hardware token can contribute a pepper to the derivation.
    hsm_group = subparser.add_argument_group(
        "HSM Options",
        "Mix a hardware-derived pepper into the KDF cascade. Reproducing "
        "the output then requires the same password, the same salt, AND "
        "the same secret loaded on the hardware token.",
    )
    hsm_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound "
        "key derivation. Supported: 'yubikey' (slots 1..2), 'onlykey' "
        "(slots 1..12), 'piv' (PIV/PKCS#11).",
    )
    hsm_group.add_argument(
        "--hsm-slot",
        type=int,
        metavar="SLOT",
        help="Manually specify the Challenge-Response slot (YubiKey 1..2, "
        "OnlyKey 1..12). If omitted, the plugin auto-detects the configured "
        "slot.",
    )
    _add_piv_hsm_arguments(hsm_group)

    # Salt options
    salt_group = subparser.add_argument_group("Salt options")
    salt_group.add_argument(
        "--salt",
        type=str,
        default=None,
        metavar="HEX",
        help="Hex-encoded salt for key derivation (for reproducibility). "
        "If not provided, a random salt is generated and printed to stderr.",
    )
    salt_group.add_argument(
        "--salt-length",
        type=int,
        default=16,
        metavar="BYTES",
        help="Length of random salt in bytes (default: 16). Only used when --salt is not provided.",
    )
    salt_group.add_argument(
        "--show-salt",
        action="store_true",
        help="Print the salt (hex) to stderr",
    )

    # Output format options
    output_group = subparser.add_argument_group("Output options")
    output_group.add_argument(
        "--output-format",
        choices=["hex", "base64", "raw"],
        default="hex",
        help="Output format for derived key (default: hex)",
    )
    output_group.add_argument(
        "--output-length",
        type=int,
        default=32,
        metavar="BYTES",
        help="Desired key length in bytes (default: 32)",
    )

    # Password policy options
    subparser.add_argument(
        "--password-policy",
        choices=["none", "basic", "standard", "strict"],
        default="none",
        help="Password policy level (default: none for derive-password)",
    )
    subparser.add_argument(
        "--min-password-length",
        type=int,
        default=None,
        help=argparse.SUPPRESS,
    )
    subparser.add_argument(
        "--min-password-entropy",
        type=float,
        default=None,
        help=argparse.SUPPRESS,
    )
    subparser.add_argument(
        "--strict-strength",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    subparser.add_argument(
        "--disable-common-password-check",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    subparser.add_argument(
        "--custom-password-list",
        default=None,
        help=argparse.SUPPRESS,
    )

    # Shared hash/KDF arguments
    _add_hash_kdf_arguments(subparser)

    # Add keyring arguments
    _add_keyring_arguments(subparser)


def setup_armor_parser(subparser):
    """Set up arguments for the armor / dearmor transport-codec commands.

    Shared by both subcommands: ``armor`` wraps an existing encrypted file in
    a paste-safe PEM/Base64 envelope; ``dearmor`` recovers the raw binary form.
    Neither needs a password — armor is a pure, reversible transport transform.
    """
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input file (encrypted file to armor / armored file to dearmor)",
    )
    subparser.add_argument(
        "--output",
        "-o",
        help="Output file. Default: <input>.asc when armoring, or the input "
        "with a trailing .asc stripped (else <input>.bin) when dearmoring. "
        "Use '-' or /dev/stdout to write to stdout.",
    )
    subparser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite the output file if it already exists",
    )


def setup_verify_parser(subparser):
    """Set up arguments for the verify command."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input encrypted file to verify",
    )
    subparser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    subparser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed check information",
    )


def setup_sign_parser(subparser):
    """Set up arguments for the sign command (detached file signature)."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="File to sign",
    )
    subparser.add_argument(
        "--output",
        "-o",
        help="Detached signature file (default: <input>.sig)",
    )
    subparser.add_argument(
        "--sign-with",
        dest="sign_with",
        metavar="IDENTITY",
        required=True,
        help="Signer identity (an own identity holding a private signing key)",
    )
    subparser.add_argument(
        "--no-armor",
        dest="armor",
        action="store_false",
        default=True,
        help="Write the signature as raw JSON instead of ASCII armor (default: armored)",
    )
    subparser.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (overrides global --identity-store)",
    )


def setup_verify_signature_parser(subparser):
    """Set up arguments for the verify-signature command."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="File whose detached signature to verify",
    )
    subparser.add_argument(
        "--signature",
        "-s",
        help="Detached signature file (default: <input>.sig)",
    )
    subparser.add_argument(
        "--signer",
        dest="signer",
        metavar="IDENTITY",
        help="Pin the expected signer identity by name (optional; otherwise the "
        "signer is resolved from the signature's fingerprint in your identity store)",
    )
    subparser.add_argument(
        "--identity-store",
        dest="identity_store",
        metavar="PATH",
        help="Path to identity store directory (overrides global --identity-store)",
    )
    subparser.add_argument(
        "--json",
        action="store_true",
        help="Output the verification result as JSON",
    )


def setup_split_secret_parser(subparser):
    """Set up arguments for the split-secret command."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input encrypted file whose key to split",
    )
    subparser.add_argument(
        "--shares",
        "-n",
        type=int,
        required=True,
        help="Total number of shares to create",
    )
    subparser.add_argument(
        "--threshold",
        "-k",
        type=int,
        required=True,
        help="Minimum shares needed to reconstruct the key",
    )
    subparser.add_argument(
        "--output-dir",
        "-d",
        default=".",
        help="Directory for share files (default: current directory)",
    )
    subparser.add_argument(
        "-p",
        "--password",
        help="Password for the encrypted file",
    )
    subparser.add_argument(
        "--force-password",
        action="store_true",
        help="Accept the password without strength check",
    )
    subparser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output",
    )


def setup_combine_secrets_parser(subparser):
    """Set up arguments for the combine-secrets command."""
    subparser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input encrypted file to decrypt",
    )
    subparser.add_argument(
        "--shares",
        nargs="+",
        required=True,
        help="Paths to share files",
    )
    subparser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Output file for decrypted data",
    )
    subparser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output",
    )


def setup_list_recovery_parser(subparser):
    """Set up arguments for the list-recovery command."""
    subparser.add_argument("--input", "-i", required=True, help="Encrypted file to inspect")


def setup_recover_parser(subparser):
    """Set up arguments for the recover command (decrypt via a recovery credential)."""
    subparser.add_argument("--input", "-i", required=True, help="Encrypted file to recover")
    subparser.add_argument("--output", "-o", required=True, help="Output (decrypted) file")
    subparser.add_argument("--recovery-code", help="Recovery code to unlock the file")
    subparser.add_argument(
        "--recovery-passphrase",
        action="store_true",
        help="Prompt for a recovery passphrase to unlock the file",
    )
    subparser.add_argument(
        "--recovery-share",
        nargs="+",
        metavar="SHARE",
        help="Shamir share file(s) to reconstruct the recovery secret",
    )
    subparser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")


def setup_add_recovery_parser(subparser):
    """Set up arguments for the add-recovery command."""
    subparser.add_argument("--input", "-i", required=True, help="Existing envelope file")
    subparser.add_argument("--output", "-o", required=True, help="Output file with the new slot")
    # Unlock the existing file (to recover the DEK):
    subparser.add_argument("-p", "--password", help="Password to unlock the file")
    subparser.add_argument(
        "--recovery-code", help="Existing recovery code to unlock the file (instead of --password)"
    )
    # New recovery credential to add (exactly one):
    subparser.add_argument(
        "--add-code", action="store_true", help="Add a freshly generated recovery code"
    )
    subparser.add_argument(
        "--add-passphrase", action="store_true", help="Add a recovery passphrase (prompted)"
    )
    subparser.add_argument(
        "--add-shares", metavar="K-of-N", help="Add a Shamir recovery secret split K-of-N"
    )
    subparser.add_argument(
        "--shares-dir", default=".", help="Directory for generated Shamir share files"
    )
    subparser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")


def setup_remove_recovery_parser(subparser):
    """Set up arguments for the remove-recovery command."""
    subparser.add_argument("--input", "-i", required=True, help="Existing envelope file")
    subparser.add_argument("--output", "-o", required=True, help="Output file without the slot")
    subparser.add_argument("--slot-id", required=True, help="Id of the recovery slot to remove")
    subparser.add_argument("-p", "--password", help="Password to unlock the file")
    subparser.add_argument(
        "--recovery-code", help="Recovery code to unlock the file (instead of --password)"
    )
    subparser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")


def setup_simple_parser(subparser):
    """Set up arguments for simple commands (security-info, check-argon2, check-pqc, version)."""
    # These commands don't need any special arguments
    pass


def setup_plugin_parser(subparser):
    """Set up arguments for the 'plugin' management command (#66)."""

    def _add_store_arg(p):
        p.add_argument(
            "--trusted-keys-dir",
            dest="trusted_keys_dir",
            metavar="PATH",
            help="Trust-anchor store directory "
            "(default: ~/.openssl_encrypt/trusted_plugin_keys/)",
        )

    plugin_subparsers = subparser.add_subparsers(
        dest="plugin_action",
        help="Plugin management operations",
        metavar="operation",
    )

    sign_p = plugin_subparsers.add_parser(
        "sign", help="Sign a plugin file, writing a detached <plugin>.py.asc"
    )
    sign_p.add_argument(
        "--plugin-file", dest="plugin_file", required=True, help="Plugin .py file to sign"
    )
    sign_p.add_argument(
        "--signing-key",
        dest="signing_key",
        required=True,
        help="Signing key fingerprint/id (uses your default keyring; a "
        "hardware token or gpg-agent handles the private key)",
    )
    sign_p.add_argument(
        "--gpg-home",
        dest="gpg_home",
        help="Override GNUPGHOME for signing (advanced/testing)",
    )

    trust_p = plugin_subparsers.add_parser(
        "trust-key", help="Enroll an author's public key as a trusted signing anchor"
    )
    trust_p.add_argument(
        "--trust-key-file",
        dest="trust_key_file",
        required=True,
        help="Path to an ASCII-armored public key file",
    )
    trust_p.add_argument(
        "--trust-fingerprint",
        dest="trust_fingerprint",
        required=True,
        help="Fingerprint confirmed OUT OF BAND; enrollment fails on mismatch",
    )
    _add_store_arg(trust_p)

    list_keys_p = plugin_subparsers.add_parser("list-keys", help="List enrolled trust anchors")
    _add_store_arg(list_keys_p)


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
        dest="identity_action",
        help="Identity management operations",
        metavar="operation",
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
        choices=["none", "yubikey", "yubikey-only", "onlykey", "onlykey-only"],
        default="none",
        help="HSM protection for private keys: "
        "'none' (default, password only), "
        "'yubikey' (password + Yubikey required, slots 1..2), "
        "'yubikey-only' (Yubikey only, no password), "
        "'onlykey' (password + OnlyKey required, slots 1..12), "
        "'onlykey-only' (OnlyKey only, no password)",
    )
    create_parser.add_argument(
        "--hsm-slot",
        type=int,
        help="HSM slot for Challenge-Response. "
        "YubiKey 1..2, OnlyKey 1..12. Default: auto-detect.",
    )
    _add_piv_hsm_arguments(create_parser)
    create_parser.add_argument(
        "--no-touch",
        action="store_true",
        help="Disable HSM touch / button-press requirement (less secure)",
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
    import_parser.add_argument(
        "--allow-key-change",
        action="store_true",
        help="Accept a CHANGED key for an already-pinned identity (TOFU "
        "key-substitution). Required, in addition to --overwrite, to replace a "
        "contact's keys with different ones - only use after verifying the new "
        "fingerprint out of band.",
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
        help="Register new FIDO2 credential for hardware-bound encryption",
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
        help="Show FIDO2 registration status and list registered credentials",
    )
    fido2_status_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )

    # FIDO2 test subcommand
    fido2_test_parser = hsm_subparsers.add_parser(
        "fido2-test", help="Test FIDO2 pepper derivation with a random salt"
    )
    fido2_test_parser.add_argument(
        "--rp-id",
        help="Custom Relying Party ID (default: openssl-encrypt.local)",
    )

    # FIDO2 list devices subcommand
    hsm_subparsers.add_parser(
        "fido2-list", help="List connected FIDO2 devices and their capabilities"
    )

    # OnlyKey list devices subcommand
    hsm_subparsers.add_parser(
        "onlykey-list",
        help="List connected OnlyKey devices (USB VID 0x1d50:0x60fc)",
    )

    # OnlyKey test subcommand
    onlykey_test_parser = hsm_subparsers.add_parser(
        "onlykey-test",
        help="Test OnlyKey Challenge-Response pepper derivation with a random salt",
    )
    onlykey_test_parser.add_argument(
        "--hsm-slot",
        type=int,
        metavar="N",
        help="OnlyKey Challenge-Response slot to test (1..12); default: auto-detect",
    )

    # FIDO2 unregister subcommand
    fido2_unregister_parser = hsm_subparsers.add_parser(
        "fido2-unregister", help="Remove FIDO2 credential registration"
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
    register_parser.add_argument(
        "--email",
        help="Register with email confirmation (sends verification link)",
    )

    # Login subcommand (exchange client_id for JWT tokens)
    login_parser = keyserver_subparsers.add_parser(
        "login", help="Login with client ID to obtain API tokens"
    )
    login_parser.add_argument("client_id", help="Client ID from registration email")
    login_parser.add_argument(
        "--server",
        help="Specific keyserver URL to login to (default: first configured server)",
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
        "--no-trust-prompt",
        action="store_true",
        help="Skip trust confirmation (dangerous)",
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
        "--limit",
        type=int,
        default=100,
        help="Maximum number of events to show (default: 100)",
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
    parser.add_argument(
        "--parallel-kdf",
        action="store_true",
        help="Use parallel processing for key derivation (v11 only, requires --independent-xor). "
        "Speeds up encryption by running hash algorithms and KDFs concurrently. "
        "Requires multiprocessing support.",
    )
    parser.add_argument(
        "--kdf-workers",
        type=int,
        default=None,
        metavar="N",
        help="Number of parallel workers for KDF (default: auto-detect, max: CPU count). "
        "Only used with --parallel-kdf.",
    )
    parser.add_argument("--verbose", action="store_true", help="Show hash/kdf details")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed debug information. Secret values (passwords, key material, "
        "KDF intermediates, hardware peppers) are redacted to length + SHA-256 "
        "fingerprint by default; combine with --unsafe-show-secrets to log them "
        "in cleartext (test files only!)",
    )
    parser.add_argument(
        "--unsafe-show-secrets",
        action="store_true",
        help="UNSAFE: show secret values in cleartext in --debug output instead of "
        "redacting them. Only valid together with --debug.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except decrypted content and exit code",
    )
    parser.add_argument(
        "--yes",
        "-y",
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
    parser.add_argument(
        "--keyring-remove",
        metavar="LABEL",
        help="Remove a stored password from the OS keyring and exit",
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

    rekey_parser = subparsers.add_parser(
        "rekey",
        help="Re-encrypt a file with a new password",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_rekey_parser(rekey_parser)

    armor_parser = subparsers.add_parser(
        "armor",
        help="ASCII-armor an existing encrypted file (paste-safe Base64 envelope)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_armor_parser(armor_parser)

    dearmor_parser = subparsers.add_parser(
        "dearmor",
        help="Recover the raw binary form of an ASCII-armored file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_armor_parser(dearmor_parser)

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

    derive_password_parser = subparsers.add_parser(
        "derive-password",
        help="Derive a key from a password using configured hash/KDF algorithms",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_derive_password_parser(derive_password_parser)

    security_info_parser = subparsers.add_parser(
        "security-info",
        help="Display security information and algorithms",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_simple_parser(security_info_parser)

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

    check_password_parser = subparsers.add_parser(
        "check-password",
        help="Report the strength of a password (read-only; no encryption)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_check_password_parser(check_password_parser)

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

    # Verify command — structural integrity check without password
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify encrypted file integrity without decryption",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_verify_parser(verify_parser)

    # Split-secret command — Shamir's Secret Sharing
    split_secret_parser = subparsers.add_parser(
        "split-secret",
        help="Split encryption key into Shamir's Secret Sharing shares",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_split_secret_parser(split_secret_parser)

    # Combine-secrets command — reconstruct key and decrypt
    combine_secrets_parser = subparsers.add_parser(
        "combine-secrets",
        help="Combine shares to reconstruct key and decrypt file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_combine_secrets_parser(combine_secrets_parser)

    # Recovery-slot management (envelope DEK recovery credentials)
    list_recovery_parser = subparsers.add_parser(
        "list-recovery",
        help="List the recovery slots on an envelope file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_list_recovery_parser(list_recovery_parser)

    recover_parser = subparsers.add_parser(
        "recover",
        help="Decrypt a file using a recovery credential (code/passphrase/shares)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_recover_parser(recover_parser)

    add_recovery_parser = subparsers.add_parser(
        "add-recovery",
        help="Add a recovery slot (code/passphrase/Shamir) to an envelope file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_add_recovery_parser(add_recovery_parser)

    remove_recovery_parser = subparsers.add_parser(
        "remove-recovery",
        help="Remove a recovery slot (by id) from an envelope file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_remove_recovery_parser(remove_recovery_parser)

    # Plugin management (signing / trust-key enrollment) — #66
    plugin_parser = subparsers.add_parser(
        "plugin",
        help="Manage plugin signatures and trusted signing keys",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_plugin_parser(plugin_parser)

    verify_integrity_parser = subparsers.add_parser(
        "verify-integrity",
        help="Verify the signed source-integrity manifest (see docs/SOURCE_INTEGRITY.md)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    verify_integrity_parser.add_argument(
        "--manifest", metavar="PATH", help="Path to manifest.json (default: bundled)"
    )
    verify_integrity_parser.add_argument(
        "--signature", metavar="PATH", help="Path to manifest.json.asc (default: bundled)"
    )
    verify_integrity_parser.add_argument(
        "--pubkey", metavar="PATH", help="Path to the signing public key (default: bundled)"
    )
    verify_integrity_parser.add_argument(
        "--json", action="store_true", help="Emit a JSON report (trust warning retained)"
    )
    verify_integrity_parser.add_argument(
        "--quiet", action="store_true", help="Shorten the trust warning to one line"
    )
    vi_scope = verify_integrity_parser.add_mutually_exclusive_group()
    vi_scope.add_argument(
        "--installed",
        dest="vi_installed",
        action="store_true",
        default=None,
        help="Force installed-package scope (Python source only); default: auto-detect",
    )
    vi_scope.add_argument(
        "--source",
        dest="vi_installed",
        action="store_false",
        help="Force source-checkout scope (full manifest); default: auto-detect",
    )

    # Sign command — detached post-quantum file signature (feature #1)
    sign_parser = subparsers.add_parser(
        "sign",
        help="Create a detached post-quantum signature for a file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_sign_parser(sign_parser)

    # Verify-signature command — verify a detached signature
    verify_signature_parser = subparsers.add_parser(
        "verify-signature",
        help="Verify a detached signature for a file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    setup_verify_signature_parser(verify_signature_parser)

    # Parse arguments
    args = parser.parse_args()

    # Handle the case where no command is provided
    if args.action is None:
        parser.print_help()
        return 1

    return parser, args
