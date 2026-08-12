"""CLI dispatch for ``plugin integrity`` management (gitlab#194).

Wires the remote file-integrity service to the CLI, matching the argv the
desktop GUI already emits: ``test`` / ``stats`` / ``verify``. All state is
server-side; the client holds only the mTLS cert/key paths.

The verify contract is deliberately FOUR-outcome, because "the file's hash was
tampered" and "the server has never heard of this file" and "the server is
unreachable" are very different answers that must not collapse into one alarm
(the removed GUI batch path made exactly that mistake — reporting a hash
mismatch for a file the service could not reach). Distinct exit codes plus an
``outcome`` field in the JSON let a caller tell them apart:

  0  match       — integrity confirmed
  1  mismatch    — the stored hash differs (a real integrity violation)
  3  not_found   — the file was never registered (NOT an alarm)
  4  unreachable — network / mTLS error reaching the service (NOT an alarm)
  2  usage error

Mismatch vs not_found follows the plugin's own signal: a genuine violation
carries a ``warning`` field in the response (integrity_plugin.verify); its
absence means not-registered.
"""

import json
from pathlib import Path

from ..crypt_utils import eprint, sanitize_for_display

_EXIT_MATCH = 0
_EXIT_MISMATCH = 1
_EXIT_USAGE = 2
_EXIT_NOT_FOUND = 3
_EXIT_UNREACHABLE = 4


def _enabled_config_or_none():
    """Load the persisted, enabled integrity config, or None with a message.

    IntegrityPlugin.__init__ raises when the config is disabled, so the enabled
    check happens here rather than at construction.
    """
    from ...plugins.integrity.config import IntegrityConfig

    try:
        config = IntegrityConfig.from_file()
    except Exception as e:
        eprint(f"❌ Could not load integrity configuration: {sanitize_for_display(str(e))}")
        return None
    if not config.enabled:
        eprint(
            "❌ Remote integrity verification is not enabled. Configure the "
            "integrity server in settings before using these commands."
        )
        return None
    return config


def cmd_test(args) -> int:
    """Validate connectivity/mTLS to an integrity server from ad-hoc settings."""
    from ...plugins.integrity.config import IntegrityConfig
    from ...plugins.integrity.integrity_plugin import IntegrityPlugin

    url = getattr(args, "url", None)
    if not url:
        eprint("❌ --url is required for 'plugin integrity test'")
        return _EXIT_USAGE

    def _path(name):
        value = getattr(args, name, None)
        return Path(value) if value else None

    try:
        config = IntegrityConfig(
            enabled=True,
            server_url=url,
            client_cert=_path("client_cert"),
            client_key=_path("client_key"),
            ca_cert=_path("ca_cert"),
        )
        with IntegrityPlugin(config) as plugin:
            plugin.get_profile()
    except Exception as e:
        eprint(f"❌ Connection test failed: {sanitize_for_display(str(e))}")
        return 1
    eprint("✅ Connection successful.")
    return 0


def cmd_stats(args) -> int:
    """Print verification statistics as JSON."""
    from ...plugins.integrity.integrity_plugin import IntegrityPlugin

    config = _enabled_config_or_none()
    if config is None:
        return 1
    try:
        with IntegrityPlugin(config) as plugin:
            stats = plugin.get_stats()
    except Exception as e:
        eprint(f"❌ Could not fetch integrity statistics: {sanitize_for_display(str(e))}")
        return 1
    print(json.dumps(stats, ensure_ascii=True))
    return 0


def cmd_verify(args) -> int:
    """Verify one file's stored hash; four-outcome contract (see module doc)."""
    from ...plugins.integrity.integrity_plugin import IntegrityPlugin

    file_id = getattr(args, "file_id", None)
    metadata_hash = getattr(args, "metadata_hash", None)
    if not file_id:
        eprint("❌ --file-id is required for 'plugin integrity verify'")
        return _EXIT_USAGE
    if not metadata_hash:
        eprint("❌ --metadata-hash is required for 'plugin integrity verify'")
        return _EXIT_USAGE
    # Validate the hash shape here so a malformed value is a usage error, not a
    # mislabelled "unreachable" (the plugin would raise on it mid-request).
    if len(metadata_hash) != 64 or any(c not in "0123456789abcdefABCDEF" for c in metadata_hash):
        eprint("❌ --metadata-hash must be 64 hex characters (SHA-256).")
        return _EXIT_USAGE

    config = _enabled_config_or_none()
    if config is None:
        # A disabled/unconfigured service is unreachable-ish — never an alarm.
        _emit(file_id, "unreachable", match=False)
        return _EXIT_UNREACHABLE

    try:
        with IntegrityPlugin(config) as plugin:
            match, response = plugin.verify(file_id, metadata_hash)
    except Exception as e:
        # A network/mTLS/validation error is NOT a tamper alarm.
        eprint(f"⚠️  Integrity service unreachable: {sanitize_for_display(str(e))}")
        _emit(file_id, "unreachable", match=False)
        return _EXIT_UNREACHABLE

    if match:
        _emit(file_id, "match", match=True, details=response)
        eprint("✅ Integrity confirmed.")
        return _EXIT_MATCH

    # match is False: distinguish a real violation from a file the service
    # never registered. This keys on the plugin's own signal — a genuine
    # violation carries a `warning` field (integrity_plugin.verify logs it on
    # exactly that condition). DEPENDENCY (gitlab#194): this trusts the server
    # to set `warning` on every real mismatch; that response shape is not
    # verifiable from the client here, so the not-found message stays cautious
    # rather than reassuring, and a caller that expected the file to be
    # registered is told to check out of band.
    if response.get("warning"):
        _emit(file_id, "mismatch", match=False, details=response)
        eprint(
            "🚨 INTEGRITY VIOLATION: the stored hash does NOT match. The "
            "file's metadata may have been tampered with."
        )
        return _EXIT_MISMATCH

    _emit(file_id, "not_found", match=False, details=response)
    eprint(
        "ℹ️  No match and no violation warning from the service. This "
        "usually means the file was never registered — but if you expected "
        "it to be registered, verify its status out of band before trusting "
        "the file. This is not a confirmed tamper alarm."
    )
    return _EXIT_NOT_FOUND


def _emit(file_id, outcome, match, details=None):
    document = {"file_id": file_id, "outcome": outcome, "match": match}
    if details is not None:
        document["details"] = details
    print(json.dumps(document, ensure_ascii=True))


def main(args) -> int:
    """Dispatch a ``plugin integrity`` sub-action; return an exit code."""
    action = getattr(args, "integrity_action", None)
    if action == "test":
        return cmd_test(args)
    if action == "stats":
        return cmd_stats(args)
    if action == "verify":
        return cmd_verify(args)
    eprint("❌ Unknown or missing integrity action. Use one of: test, stats, verify")
    return _EXIT_USAGE
