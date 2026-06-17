#!/usr/bin/env python3
"""
Source-code integrity protection for openssl_encrypt.

This package maintains a PGP-signed manifest of SHA-512 hashes for the project's
core cryptographic/security source files, so that tampering with those files can
be detected.

IMPORTANT TRUST NOTE
--------------------
The verification code in this package lives in the same distribution it checks.
If an attacker can modify the protected source files, they can also modify this
verifier, the manifest, and the bundled public key. A passing result from the
built-in verifier is therefore a convenience *tripwire*, not cryptographic proof.
The only reliable verification is performed manually with a trusted ``gpg`` binary
and a signing-key fingerprint obtained out-of-band (see docs/SOURCE_INTEGRITY.md).
"""
