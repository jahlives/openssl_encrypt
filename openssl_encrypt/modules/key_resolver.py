#!/usr/bin/env python3
"""
Key Resolver - Unified key resolution with local-first priority.

This module provides a unified interface for resolving identities from
multiple sources: local keyring, keyserver cache, and remote keyserver.

SECURITY GUARANTEES:
- Local keyring ALWAYS checked first (Priority 1)
- Keyserver only queried if local lookup fails (Priority 2)
- All keyserver bundles verified before use
- User ALWAYS prompted to trust keyserver keys
- Keys imported to local store after trust confirmation

Resolution order:
1. Local IdentityStore (own identities + contacts)
2. Keyserver (if enabled + user confirms trust)
"""

import logging
from typing import TYPE_CHECKING, Callable, Optional

from .identity import Identity, IdentityStore
from .key_bundle import InvalidFingerprintError, InvalidSignatureError

if TYPE_CHECKING:
    from ..plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from .key_bundle import PublicKeyBundle

logger = logging.getLogger(__name__)


class KeyNotFoundError(Exception):
    """Raised when key not found in any source"""

    pass


class TrustDeclinedError(Exception):
    """Raised when user declines to trust keyserver key"""

    pass


class KeyResolver:
    """
    Unified key resolution with local-first priority.

    This resolver checks multiple sources in order:
    1. Local IdentityStore (fast, trusted)
    2. Keyserver remote (slow, requires trust confirmation)

    SECURITY:
    - Local keyring always checked first
    - Keyserver only queried if explicitly enabled
    - All keyserver bundles cryptographically verified
    - User must explicitly confirm trust for new keys
    - Keys imported to local store after trust confirmation

    Example:
        # Create resolver
        store = IdentityStore()
        keyserver = KeyserverPlugin()
        resolver = KeyResolver(store, keyserver, trust_callback=prompt_user_trust)

        # Resolve identity
        try:
            identity = resolver.resolve("alice@example.com", load_private_keys=False)
            # Use identity for encryption
        except KeyNotFoundError:
            print("Key not found")
        except TrustDeclinedError:
            print("User declined to trust key")
    """

    def __init__(
        self,
        identity_store: IdentityStore,
        keyserver_plugin: Optional["KeyserverPlugin"] = None,
        trust_callback: Optional[Callable[["PublicKeyBundle"], bool]] = None,
    ):
        """
        Initialize key resolver.

        Args:
            identity_store: IdentityStore for local key lookups
            keyserver_plugin: Optional KeyserverPlugin for remote lookups
            trust_callback: Optional callback to confirm trust (takes bundle, returns bool)
        """
        self.identity_store = identity_store
        self.keyserver_plugin = keyserver_plugin
        self.trust_callback = trust_callback or default_trust_callback

        logger.debug(
            f"Initialized KeyResolver (keyserver={'enabled' if keyserver_plugin else 'disabled'})"
        )

    def resolve(self, identifier: str, load_private_keys: bool = False) -> Identity:
        """
        Resolve identifier to Identity.

        Resolution order:
        1. Local IdentityStore (own identities + contacts)
        2. Keyserver (if enabled + user confirms trust)

        Args:
            identifier: Fingerprint, name, or email to search for
            load_private_keys: Whether to load private keys (local only)

        Returns:
            Identity instance

        Raises:
            KeyNotFoundError: If key not found in any source
            TrustDeclinedError: If user declined to trust keyserver key
            InvalidSignatureError: If keyserver bundle signature invalid
            InvalidFingerprintError: If keyserver bundle fingerprint invalid

        Note:
            - Keyserver keys are imported to local store after trust confirmation
            - Private keys can only be loaded from local store
        """
        logger.debug(f"Resolving identifier: '{identifier}'")

        # Priority 1: Local identities (fast)
        logger.debug("Checking local identity store...")
        local_identity = self.identity_store.get_by_name(
            identifier, passphrase=None, load_private_keys=load_private_keys
        )

        if local_identity:
            logger.info(f"Found '{identifier}' in local store")
            return local_identity

        # Priority 2: Keyserver (slow, requires trust)
        if self.keyserver_plugin:
            logger.debug("Checking keyserver...")

            try:
                bundle = self.keyserver_plugin.fetch_key(identifier)

                if bundle:
                    logger.info(f"Found '{identifier}' on keyserver: '{bundle.name}'")

                    # CRITICAL: Verify signature (double-check, plugin should have verified)
                    try:
                        if not bundle.verify_signature():
                            raise InvalidSignatureError(
                                f"Bundle signature verification failed for '{identifier}'"
                            )
                    except (InvalidSignatureError, InvalidFingerprintError) as e:
                        logger.error(f"Bundle verification failed: {e}")
                        raise

                    # Prompt user for trust
                    logger.debug(f"Prompting user to trust '{bundle.name}'")
                    if not self.trust_callback(bundle):
                        logger.info(f"User declined to trust '{bundle.name}'")
                        raise TrustDeclinedError(f"User declined to trust '{identifier}'")

                    # Import to local store (as contact)
                    identity = bundle.to_identity()
                    self.identity_store.add_identity(identity, passphrase=None, overwrite=False)
                    logger.info(
                        f"Imported '{bundle.name}' to local store from keyserver (fp: {bundle.fingerprint[:20]}...)"
                    )

                    return identity

            except (TrustDeclinedError, InvalidSignatureError, InvalidFingerprintError):
                # Re-raise these specific exceptions
                raise
            except Exception as e:
                logger.warning(f"Keyserver lookup failed: {e}")
                # Continue to KeyNotFoundError

        # Not found in any source
        logger.warning(f"Key not found for '{identifier}'")
        raise KeyNotFoundError(f"Key not found for identifier: '{identifier}'")


def default_trust_callback(bundle: "PublicKeyBundle") -> bool:
    """
    Default trust callback that prompts user interactively.

    This displays the bundle information and asks the user to confirm trust.

    Args:
        bundle: PublicKeyBundle to verify

    Returns:
        True if user trusts the key, False otherwise

    Note:
        - Displays fingerprint, algorithms, and creation date
        - User must explicitly type 'y' or 'yes' to trust
        - Default is to NOT trust (safe default)
    """
    # Import here to avoid circular import
    from .key_bundle import PublicKeyBundle

    if not isinstance(bundle, PublicKeyBundle):
        logger.error("Invalid bundle type in trust callback")
        return False

    print("\n" + "=" * 60)
    print("KEYSERVER KEY VERIFICATION")
    print("=" * 60)
    print(f"Identity:    {bundle.name}")
    print(f"Email:       {bundle.email or 'N/A'}")
    print(f"Fingerprint: {bundle.fingerprint}")
    print(f"Algorithms:  {bundle.encryption_algorithm} / {bundle.signing_algorithm}")
    print(f"Created:     {bundle.created_at}")
    print("=" * 60)
    print()
    print("IMPORTANT: Verify the fingerprint through a trusted channel")
    print("(e.g., in-person, phone call, secure messaging)")
    print()

    try:
        response = input("Trust and import this key? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\nAborted")
        return False


def silent_trust_callback(bundle: "PublicKeyBundle") -> bool:
    """
    Silent trust callback that automatically trusts all keys.

    WARNING: This should ONLY be used for testing. In production,
    always use interactive trust confirmation.

    Args:
        bundle: PublicKeyBundle

    Returns:
        Always True
    """
    logger.warning("Using silent trust callback - automatically trusting all keys (TESTING ONLY)")
    return True


if __name__ == "__main__":
    # Simple test
    print("KeyResolver module loaded successfully")
