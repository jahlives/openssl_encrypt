#!/usr/bin/env python3
"""
Signature Verification Service (adapted from existing keyserver)

SECURITY CRITICAL:
- All uploaded bundles MUST be verified before storage
- Uses liboqs for post-quantum signature verification
- Double-checks fingerprint calculation
"""

import base64
import hashlib
import json
import logging
from typing import Dict

logger = logging.getLogger(__name__)

# Try to import liboqs
try:
    import oqs

    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning("liboqs-python not available. Signature verification will fail.")


class VerificationError(Exception):
    """Raised when signature verification fails"""

    pass


class FingerprintMismatchError(VerificationError):
    """Raised when fingerprint doesn't match calculated value"""

    pass


def verify_bundle_signature(bundle_data: Dict) -> bool:
    """
    Verify self-signature of public key bundle.

    SECURITY: This is the CRITICAL verification step. All bundles from
    clients MUST pass this check before being stored.

    Verification steps:
    1. Verify self-signature with signing public key (liboqs)
    2. Recalculate fingerprint from public keys
    3. Compare calculated fingerprint with stored fingerprint

    Args:
        bundle_data: Dictionary with bundle data

    Returns:
        True if signature valid and fingerprint matches

    Raises:
        VerificationError: If signature verification fails
        FingerprintMismatchError: If fingerprint doesn't match
        ValueError: If required fields missing or invalid
    """
    if not LIBOQS_AVAILABLE:
        raise VerificationError("liboqs not available - cannot verify signatures")

    # Extract required fields
    try:
        name = bundle_data["name"]
        email = bundle_data.get("email")
        fingerprint = bundle_data["fingerprint"]
        created_at = bundle_data["created_at"]
        encryption_public_key = bundle_data["encryption_public_key"]
        signing_public_key = bundle_data["signing_public_key"]
        encryption_algorithm = bundle_data["encryption_algorithm"]
        signing_algorithm = bundle_data["signing_algorithm"]
        self_signature = bundle_data["self_signature"]
    except KeyError as e:
        raise ValueError(f"Missing required field: {e}")

    # Step 1: Verify self-signature
    logger.debug(f"Verifying signature for bundle '{name}'")

    # Map ML-DSA to Dilithium (liboqs naming)
    algo_map = {
        "ML-DSA-44": "Dilithium2",
        "ML-DSA-65": "Dilithium3",
        "ML-DSA-87": "Dilithium5",
    }

    if signing_algorithm not in algo_map:
        raise ValueError(f"Unsupported signing algorithm: {signing_algorithm}")

    liboqs_algo = algo_map[signing_algorithm]

    try:
        # Create verifier
        verifier = oqs.Signature(liboqs_algo)

        # Reconstruct message (same as client-side)
        message_data = {
            "name": name,
            "email": email,
            "fingerprint": fingerprint,
            "created_at": created_at,
            "encryption_public_key": encryption_public_key,
            "signing_public_key": signing_public_key,
            "encryption_algorithm": encryption_algorithm,
            "signing_algorithm": signing_algorithm,
        }

        # Serialize deterministically (same as client)
        message = json.dumps(message_data, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

        # Decode signature and public key from base64
        signature_bytes = base64.b64decode(self_signature)
        public_key_bytes = base64.b64decode(signing_public_key)

        # Verify signature
        is_valid = verifier.verify(message, signature_bytes, public_key_bytes)

        if not is_valid:
            raise VerificationError("Signature verification failed")

        logger.debug(f"Signature verified for '{name}'")

    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        raise VerificationError(f"Signature verification failed: {e}")

    # Step 2: Verify fingerprint
    logger.debug(f"Verifying fingerprint for bundle '{name}'")

    try:
        # Decode public keys
        enc_pub_key = base64.b64decode(encryption_public_key)
        sig_pub_key = base64.b64decode(signing_public_key)

        # Calculate fingerprint (same as client-side)
        combined_keys = enc_pub_key + sig_pub_key
        calculated_fingerprint = calculate_fingerprint(combined_keys)

        if calculated_fingerprint != fingerprint:
            raise FingerprintMismatchError(
                f"Fingerprint mismatch: stored={fingerprint}, calculated={calculated_fingerprint}"
            )

        logger.debug(f"Fingerprint verified for '{name}'")

    except FingerprintMismatchError:
        raise
    except Exception as e:
        logger.error(f"Fingerprint verification error: {e}")
        raise VerificationError(f"Fingerprint verification failed: {e}")

    logger.info(f"Bundle verification successful for '{name}' (fp: {fingerprint[:20]}...)")
    return True


def calculate_fingerprint(key_data: bytes) -> str:
    """
    Calculate SHA-256 fingerprint with colons.

    Args:
        key_data: Combined public keys (encryption + signing)

    Returns:
        Fingerprint string with colons (e.g., "3a:4b:5c:...")
    """
    # SHA-256 hash
    digest = hashlib.sha256(key_data).digest()

    # Convert to hex with colons
    fingerprint = ":".join(f"{b:02x}" for b in digest)

    return fingerprint


def verify_revocation_signature(
    fingerprint: str, signature_hex: str, signing_public_key_b64: str, signing_algorithm: str
) -> bool:
    """
    Verify revocation signature.

    Args:
        fingerprint: Fingerprint of key being revoked
        signature_hex: Hex-encoded revocation signature
        signing_public_key_b64: Base64-encoded signing public key
        signing_algorithm: Signing algorithm (ML-DSA-44/65/87)

    Returns:
        True if revocation signature is valid

    Raises:
        VerificationError: If verification fails
    """
    if not LIBOQS_AVAILABLE:
        raise VerificationError("liboqs not available - cannot verify signatures")

    # Map ML-DSA to Dilithium
    algo_map = {
        "ML-DSA-44": "Dilithium2",
        "ML-DSA-65": "Dilithium3",
        "ML-DSA-87": "Dilithium5",
    }

    if signing_algorithm not in algo_map:
        raise ValueError(f"Unsupported signing algorithm: {signing_algorithm}")

    liboqs_algo = algo_map[signing_algorithm]

    try:
        # Create verifier
        verifier = oqs.Signature(liboqs_algo)

        # Message is the fingerprint
        message = fingerprint.encode("utf-8")

        # Decode signature and public key
        signature_bytes = bytes.fromhex(signature_hex)
        public_key_bytes = base64.b64decode(signing_public_key_b64)

        # Verify
        is_valid = verifier.verify(message, signature_bytes, public_key_bytes)

        if not is_valid:
            raise VerificationError("Revocation signature verification failed")

        logger.info(f"Revocation signature verified for fingerprint {fingerprint[:20]}...")
        return True

    except Exception as e:
        logger.error(f"Revocation signature verification error: {e}")
        raise VerificationError(f"Revocation verification failed: {e}")
