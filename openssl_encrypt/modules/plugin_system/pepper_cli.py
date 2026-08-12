"""CLI dispatch for ``plugin pepper`` management (gitlab#193).

Wires the pepper plugin's server-side operations to the CLI, matching the argv
the desktop GUI already emits: ``list`` / ``test`` / ``setup-totp`` /
``verify-totp`` / ``configure-deadman``. All pepper state (peppers, the TOTP
secret, the dead-man's-switch timers) lives server-side; the client holds only
the mTLS cert/key paths.

Mirrors plugin_cli.main(args): a single main(args) dispatching on
``args.pepper_action`` and returning an exit code (0 ok, 1 runtime failure,
2 usage error). Handlers never call sys.exit — the top-level wrapper does.

Secret discipline: the TOTP shared secret (from ``setup-totp``) and the
one-time backup codes (from ``verify-totp``) are the only secret payloads.
They are printed to STDOUT only (never stderr, which the GUI persists to its
debug log) and registered with the audit-log redactor so a later log line
cannot echo them.
"""

import json
from pathlib import Path

from ..crypt_utils import eprint, sanitize_for_display
from ..security_logger import register_consumed_secret


def _load_enabled_plugin():
    """Build a PepperPlugin from the persisted, enabled config, or None.

    Prints a clear error and returns None when remote pepper is not configured,
    so every management action fails closed with the same message rather than a
    raw exception.
    """
    from ...plugins.pepper.config import PepperConfig
    from ...plugins.pepper.pepper_plugin import PepperPlugin

    try:
        config = PepperConfig.from_file()
    except Exception as e:
        eprint(f"❌ Could not load pepper configuration: {sanitize_for_display(str(e))}")
        return None
    if not config.enabled:
        eprint(
            "❌ Remote pepper is not enabled. Configure the pepper server in "
            "settings before using these commands."
        )
        return None
    return PepperPlugin(config)


def cmd_test(args) -> int:
    """Validate connectivity/mTLS to a pepper server given ad-hoc settings.

    Unlike the other actions this builds the config directly from the CLI flags
    (the point is to test settings BEFORE they are persisted), forcing
    enabled=True for the probe.
    """
    from ...plugins.pepper.config import PepperConfig
    from ...plugins.pepper.pepper_plugin import PepperPlugin

    url = getattr(args, "url", None)
    if not url:
        eprint("❌ --url is required for 'plugin pepper test'")
        return 2

    def _path(name):
        value = getattr(args, name, None)
        return Path(value) if value else None

    try:
        config = PepperConfig(
            enabled=True,
            server_url=url,
            client_cert=_path("client_cert"),
            client_key=_path("client_key"),
            ca_cert=_path("ca_cert"),
        )
        plugin = PepperPlugin(config)
        # A lightweight authenticated round-trip: exercises mTLS + reachability.
        plugin.get_profile()
    except Exception as e:
        eprint(f"❌ Connection test failed: {sanitize_for_display(str(e))}")
        return 1
    eprint("✅ Connection successful.")
    return 0


def cmd_list(args) -> int:
    """Print stored peppers as JSON: {"peppers": [...]}."""
    plugin = _load_enabled_plugin()
    if plugin is None:
        return 1
    try:
        peppers = plugin.list_peppers()
    except Exception as e:
        eprint(f"❌ Could not list peppers: {sanitize_for_display(str(e))}")
        return 1
    print(json.dumps({"peppers": peppers}, ensure_ascii=True))
    return 0


def cmd_setup_totp(args) -> int:
    """Begin TOTP enrolment; print {secret, qr_code, qr_svg, uri} as JSON.

    The shared secret is the payload — emitted on stdout only and registered
    with the redactor. `qr_code` mirrors the plugin's `qr_svg` value so the GUI
    (which reads `qr_code`) works; `qr_svg` is kept for precise consumers.
    """
    plugin = _load_enabled_plugin()
    if plugin is None:
        return 1
    try:
        result = plugin.setup_totp()
    except Exception as e:
        eprint(f"❌ TOTP setup failed: {sanitize_for_display(str(e))}")
        return 1

    secret = result.get("secret")
    if secret:
        register_consumed_secret("pepper_totp_secret", secret)
    qr = result.get("qr_svg")
    document = {
        "secret": secret,
        "qr_code": qr,  # GUI reads this key
        "qr_svg": qr,
        "uri": result.get("uri"),
    }
    print(json.dumps(document, ensure_ascii=True))
    eprint(
        "Scan the QR/secret in an authenticator app, then run "
        "'plugin pepper verify-totp --code <code>' to finish enrolment."
    )
    return 0


def cmd_verify_totp(args) -> int:
    """Confirm TOTP enrolment with a code; deliver the one-time backup codes.

    On success the server returns 10 single-use backup codes. They are shown
    ONCE, so they are printed on stdout as JSON {"verified": true,
    "backup_codes": [...]} and each is registered with the redactor. Exit 0
    means verified (the GUI reads only the exit code).
    """
    code = getattr(args, "code", None)
    if not code:
        eprint("❌ --code is required for 'plugin pepper verify-totp'")
        return 2
    plugin = _load_enabled_plugin()
    if plugin is None:
        return 1
    try:
        result = plugin.verify_totp(code)
    except Exception as e:
        eprint(f"❌ TOTP verification failed: {sanitize_for_display(str(e))}")
        return 1

    backup_codes = result.get("backup_codes") or []
    # Register each code under a DISTINCT name: the redactor keeps only a few
    # values per name (FIFO), so registering all 10 under one name would leave
    # most unprotected. The primary protection is still that these go to stdout
    # only and are never logged; this is defense-in-depth for any future log.
    for i, bc in enumerate(backup_codes):
        register_consumed_secret(f"pepper_backup_code_{i}", str(bc))
    print(json.dumps({"verified": True, "backup_codes": backup_codes}, ensure_ascii=True))
    if backup_codes:
        eprint("SAVE the backup codes above — they are shown once and each " "works only once.")
    return 0


def cmd_configure_deadman(args) -> int:
    """Enable/disable the dead-man's switch.

    --interval / --grace-period are integer DAYS (matching the GUI), converted
    to the duration strings the server expects. The switch AUTOMATICALLY WIPES
    ALL peppers if no check-in happens within interval + grace, so enabling it
    is a real commitment — but configuring it is not itself destructive.
    """
    enable = getattr(args, "enable", False)
    disable = getattr(args, "disable", False)
    if enable == disable:
        eprint("❌ Choose exactly one of --enable or --disable.")
        return 2

    plugin = _load_enabled_plugin()
    if plugin is None:
        return 1

    try:
        if disable:
            plugin.disable_deadman()
            eprint("✅ Dead-man's switch disabled.")
            return 0
        interval_days = getattr(args, "interval", None)
        grace_days = getattr(args, "grace_period", None)
        if interval_days is None or grace_days is None:
            eprint("❌ --enable requires --interval and --grace-period (in days).")
            return 2
        # Fail closed on non-positive values: this arms an AUTO-WIPE switch, so
        # a 0/negative interval could set an already-past deadline and trigger
        # an immediate wipe. Whole-day granularity also satisfies the server's
        # documented 1-hour minimum.
        if interval_days < 1 or grace_days < 1:
            eprint("❌ --interval and --grace-period must be at least 1 day.")
            return 2
        plugin.configure_deadman(
            interval=f"{interval_days}d",
            grace_period=f"{grace_days}d",
            enabled=True,
        )
    except Exception as e:
        eprint(f"❌ Could not configure the dead-man's switch: " f"{sanitize_for_display(str(e))}")
        return 1
    eprint(
        f"✅ Dead-man's switch enabled: check in at least every "
        f"{interval_days} day(s) (grace {grace_days} day(s)) or ALL peppers "
        f"are wiped."
    )
    return 0


def main(args) -> int:
    """Dispatch a ``plugin pepper`` sub-action; return an exit code."""
    action = getattr(args, "pepper_action", None)
    if action == "test":
        return cmd_test(args)
    if action == "list":
        return cmd_list(args)
    if action == "setup-totp":
        return cmd_setup_totp(args)
    if action == "verify-totp":
        return cmd_verify_totp(args)
    if action == "configure-deadman":
        return cmd_configure_deadman(args)
    eprint(
        "❌ Unknown or missing pepper action. Use one of: list, test, "
        "setup-totp, verify-totp, configure-deadman"
    )
    return 2
