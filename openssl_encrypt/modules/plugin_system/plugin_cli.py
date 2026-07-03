"""CLI dispatch for the ``plugin`` management command (#66).

Sub-actions:
  * ``sign``       — sign a plugin file with the operator's key
  * ``trust-key``  — enroll an author's public key as a trust anchor
  * ``list-keys``  — list enrolled trust anchors

Mirrors identity_cli.main(args): a single main(args) dispatching on
``args.plugin_action`` and returning an exit code.
"""

from pathlib import Path

from ..crypt_utils import eprint
from .plugin_signing_cli import (
    default_trusted_keys_dir,
    enroll_trust_key,
    list_trust_keys,
    sign_plugin,
)


def _resolve_store(args) -> str:
    return getattr(args, "trusted_keys_dir", None) or default_trusted_keys_dir()


def cmd_sign(args) -> int:
    plugin_file = getattr(args, "plugin_file", None)
    signing_key = getattr(args, "signing_key", None)
    if not plugin_file:
        eprint("❌ --plugin-file is required for 'plugin sign'")
        return 2
    if not signing_key:
        eprint("❌ --signing-key is required for 'plugin sign'")
        return 2
    home = getattr(args, "gpg_home", None)
    try:
        sig_path = sign_plugin(plugin_file, signing_key, home=Path(home) if home else None)
    except FileNotFoundError as e:
        eprint(f"❌ {e}")
        return 1
    except Exception as e:  # gpg failures, unavailable, etc.
        eprint(f"❌ Signing failed: {e}")
        return 1
    eprint(f"✅ Wrote signature: {sig_path}")
    return 0


def cmd_trust_key(args) -> int:
    key_file = getattr(args, "trust_key_file", None)
    fingerprint = getattr(args, "trust_fingerprint", None)
    if not key_file:
        eprint("❌ --trust-key-file is required for 'plugin trust-key'")
        return 2
    if not fingerprint:
        eprint(
            "❌ --trust-fingerprint is required: confirm the key fingerprint "
            "out of band before enrolling it"
        )
        return 2
    store = _resolve_store(args)
    try:
        anchor = enroll_trust_key(key_file, trusted_keys_dir=store, confirm_fingerprint=fingerprint)
    except ValueError as e:
        eprint(f"❌ {e}")
        return 1
    except FileNotFoundError as e:
        eprint(f"❌ {e}")
        return 1
    except Exception as e:
        eprint(f"❌ Enrollment failed: {e}")
        return 1
    eprint(f"✅ Enrolled trust anchor {anchor.fingerprint} ({anchor.label}) in {store}")
    return 0


def cmd_list_keys(args) -> int:
    from .plugin_signature import project_trust_anchor

    store = _resolve_store(args)
    try:
        enrolled = list_trust_keys(trusted_keys_dir=store)
    except Exception as e:
        eprint(f"❌ Could not list trust anchors: {e}")
        return 1

    project = project_trust_anchor()
    if project is not None:
        eprint("Built-in trust anchor (project source-integrity key):")
        eprint(f"  {project.fingerprint}  ({project.label})")
    if enrolled:
        eprint(f"Enrolled trust anchors in {store}:")
        for a in enrolled:
            eprint(f"  {a.fingerprint}  ({a.label})")
    elif project is None:
        eprint(f"No plugin-signing trust anchors (none enrolled in {store})")
    else:
        eprint(f"No additional anchors enrolled in {store}")
    return 0


def main(args) -> int:
    """Dispatch a ``plugin`` management sub-action; return an exit code."""
    action = getattr(args, "plugin_action", None)
    if action == "sign":
        return cmd_sign(args)
    if action == "trust-key":
        return cmd_trust_key(args)
    if action == "list-keys":
        return cmd_list_keys(args)
    eprint("❌ Unknown or missing plugin action. Use one of: sign, trust-key, list-keys")
    return 2
