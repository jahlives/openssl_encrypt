#!/usr/bin/env python3
"""
Central redaction chokepoint for secret values in debug output.

Every place that emits secret material (key material, KDF intermediates,
hardware peppers, passwords, user plaintext) on a debug path MUST format it
through :func:`debug_secret`. Direct ``print``/``logger.debug`` of a secret
value is a security finding.

By default secrets are redacted to::

    <label>: <redacted: N bytes, sha256:XXXXXXXXXXXX>

where ``N`` is the byte length and the fingerprint is the first 12 hex chars
of an HMAC-SHA256 of the raw value under an ephemeral per-process random
key. This keeps the log structure identical to the cleartext form and lets
two log lines from the same run be compared for whether the same secret
flows through them - without revealing the secret itself.

The fingerprint key is generated at import, never logged and never stored:
a plain (unkeyed) truncated SHA-256 would turn every redacted password into
an offline dictionary-confirmation oracle for anyone holding the log. The
cost is that fingerprints are NOT comparable across process runs - which is
exactly the property that makes them safe to share.

Cleartext output is an explicit opt-in: the CLI enables it only when BOTH
``--debug`` and ``--unsafe-show-secrets`` are given, via
:func:`set_show_secrets`. The default (redacting) state must never be
flipped implicitly.
"""

import hashlib
import hmac
import os
from typing import Union

# Number of hex characters of the HMAC-SHA256 digest used as the fingerprint.
_FINGERPRINT_HEX_CHARS = 12

# Ephemeral per-process fingerprint key. Never logged, never persisted. Keys
# the fingerprint so a shared debug log cannot be used to offline-confirm a
# guessed (low-entropy) secret, while same-run comparability is preserved.
_FINGERPRINT_KEY = os.urandom(32)

# Process-wide opt-in, set once at CLI startup (--debug --unsafe-show-secrets).
# Defaults to redaction so library users and the GUI are safe by default.
_show_secrets = False


def secret_fingerprint(raw: bytes) -> str:
    """
    Fingerprint a secret for redacted debug output.

    Args:
        raw: The raw secret bytes.

    Returns:
        First 12 hex chars of HMAC-SHA256 over the value, keyed with the
        ephemeral per-process key (stable within a run, useless offline).
    """
    return hmac.new(_FINGERPRINT_KEY, raw, hashlib.sha256).hexdigest()[:_FINGERPRINT_HEX_CHARS]


def set_show_secrets(enabled: bool) -> None:
    """
    Enable or disable cleartext secrets in debug output.

    Only the CLI startup path (after validating that --unsafe-show-secrets
    was combined with --debug) and tests may call this.

    Args:
        enabled: True to render secrets in cleartext, False to redact.
    """
    global _show_secrets
    _show_secrets = bool(enabled)


def show_secrets_enabled() -> bool:
    """
    Return whether cleartext secret output is currently enabled.

    Returns:
        True if --unsafe-show-secrets is active, False otherwise.
    """
    return _show_secrets


def debug_secret(label: str, value: Union[bytes, bytearray, memoryview, str]) -> str:
    """
    Format a secret value for debug output (the single redaction chokepoint).

    Args:
        label: Log label to prefix the rendered value with. An empty label
            returns just the rendered value, for embedding into a larger
            debug string (e.g. a sanitized argv dump).
        value: The secret. Bytes-likes are rendered as hex in cleartext
            mode; a str (e.g. a base64-encoded key) is rendered verbatim.
            Length and fingerprint are always computed over the raw bytes
            (UTF-8 for str).

    Returns:
        ``"<label>: <value-or-redaction>"`` - redacted by default, cleartext
        only when :func:`set_show_secrets` enabled it.
    """
    if isinstance(value, str):
        # surrogateescape, not strict: this is the redaction chokepoint, reached
        # from sanitize_argv_for_debug with unsanitized argv, and os.environ /
        # argv decode with surrogateescape. A strict encode would raise
        # UnicodeEncodeError, whose message embeds a byte of the value and its
        # offset -- printed verbatim by the generic CLI handler, outside this
        # chokepoint (gitlab#147). A lone HIGH surrogate is outside
        # surrogateescape's round-trip range and still raises, so it is caught
        # and rendered without the bytes rather than allowed to leak.
        try:
            raw = value.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            raw = None
        cleartext = value
    else:
        raw = bytes(value)
        cleartext = raw.hex()

    if _show_secrets:
        rendered = cleartext
    elif raw is None:
        rendered = "<redacted: unencodable str>"
    else:
        rendered = f"<redacted: {len(raw)} bytes, sha256:{secret_fingerprint(raw)}>"

    return f"{label}: {rendered}" if label else rendered
