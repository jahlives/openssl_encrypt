#!/usr/bin/env python3
"""Machine-readable capability manifest for the CLI (``crypt capabilities``).

A single, separately-released desktop GUI needs to know what the CLI build it is
talking to actually supports, so it can show/hide screens and options without a
hardcoded version->feature matrix (docs/gui-split-unified-plan.md, P1-P3).

Design (so the manifest cannot lie):
  * ``commands`` and ``flags`` are INTROSPECTED from the live argparse parser --
    they are exactly what the CLI accepts.
  * ``features`` is COMPUTED from a curated rule set, each rule referencing a real
    command or flag. A feature flips off automatically when its correlate is
    absent (e.g. steganography on a line that dropped ``--stego*``); nothing is
    hand-asserted true.
  * ``command_flags`` / ``json_endpoints`` / ``json_fields`` are curated maps that
    express INTENT but are emitted as intent-INTERSECT-reality: any command or
    flag not present in the introspected surface is dropped, so the manifest is a
    subset of what the CLI really has by construction and stays correct across the
    1.4.x / 1.5.x lines.

The manifest contains only public names (never a secret value) and does not read
the process environment.
"""

import re
from typing import Dict, List

CAPABILITIES_SCHEMA_VERSION = 1

# feature name -> (kind, correlate). kind is one of:
#   "command"     -> True iff correlate is a registered command
#   "flag"        -> True iff correlate is a registered option string
#   "flag_prefix" -> True iff any registered option string starts with correlate
_FEATURE_RULES = {
    "encryption": ("command", "encrypt"),
    "decryption": ("command", "decrypt"),
    "envelope": ("flag", "--envelope"),
    "recovery_slots": ("command", "add-recovery"),
    "identity": ("command", "identity"),
    "pqc": ("command", "check-pqc"),
    "pqc_keyfile": ("flag", "--pqc-keyfile"),
    "hsm": ("command", "hsm"),
    "steganography": ("flag_prefix", "--stego"),
    "rekey": ("command", "rekey"),
    "shred": ("command", "shred"),
    "password_generator": ("command", "generate-password"),
    "signing": ("command", "sign"),
    "signature_verify": ("command", "verify-signature"),
    "plugins": ("command", "plugin"),
    "portable_usb": ("command", "create-usb"),
    "keyserver": ("command", "keyserver"),
    "telemetry": ("command", "telemetry"),
    "armor": ("command", "armor"),
    "integrity_verify": ("command", "verify-integrity"),
}

# Curated per-command flag intent (subset relevant to GUI gating). Emitted
# intersected with the introspected flags, so a flag absent on a given line is
# dropped rather than advertised.
_COMMAND_FLAGS = {
    "encrypt": [
        "--input",
        "--output",
        "--algorithm",
        "--envelope",
        "--pqc-keyfile",
        "--recovery-code",
        "--stego-password",
        "--armor",
        "--hsm",
    ],
    "decrypt": [
        "--input",
        "--output",
        "--with-key",
        "--recovery-code",
        "--stego-password",
    ],
    "add-recovery": ["--add-code", "--add-passphrase", "--password", "--json"],
    "remove-recovery": ["--slot-id", "--password", "--json"],
    "list-recovery": ["--json"],
    "recover": ["--recovery-code", "--json"],
    "identity": ["--json"],
    "analyze-security": ["--output-format", "--json"],
    "telemetry": ["--json"],
}

# Commands that emit a machine-readable JSON document on stdout.
_JSON_ENDPOINTS = [
    "capabilities",
    "analyze-security",
    "smart-recommendations",
    "telemetry",
    "identity",
    "list-recovery",
    "recover",
    "add-recovery",
    "remove-recovery",
    "check-password",
    # total-json Phase 1a (gitlab#268): version/catalog reporters. All emit
    # the {"status","data"} envelope EXCEPT list-available-algorithms, whose
    # bare document predates the envelope and is frozen for its GUI consumer.
    "version",
    "show-version-file",
    "list-algorithms",
    "list-available-algorithms",
    "check-argon2",
    "check-pqc",
    # total-json Phase 1b (gitlab#268): file/config reporters. info,
    # analyze-config and template (list) emit pre-existing BARE documents
    # (frozen shapes; --json aliases --output-format/--format json where those
    # exist); list-plugins, plugin-info and security-info use the envelope.
    "info",
    "analyze-config",
    "template",
    "list-plugins",
    "plugin-info",
    "security-info",
    # total-json Phase 1c (gitlab#268): verifiers. verify-integrity and
    # verify-signature keep their pre-existing bare documents (frozen);
    # verify-usb emits the envelope around its result dict.
    "verify-integrity",
    "verify-signature",
    "verify-usb",
    # total-json Phase 2 (gitlab#268): operation result reports (envelope),
    # except generate-password whose pre-existing bare document is frozen.
    "encrypt",
    "decrypt",
    "rekey",
    "sign",
    "armor",
    "dearmor",
    "shred",
    "create-usb",
    "derive-password",
    "generate-password",
    # total-json Phase 3 (gitlab#268): grouped commands whose reporting
    # subcommands emit JSON (keyserver: status/cache-stats/search/show-pending;
    # hsm: fido2-status; identity: list/show/export already partially JSON).
    "keyserver",
    "hsm",
    "plugin",
]

# Per-endpoint output field intent. Seeded; grows as endpoints are pinned.
# "capabilities" is self-describing: its fields are this manifest's own keys.
_MANIFEST_KEYS = [
    "schema_version",
    "cli_version",
    "line",
    "commands",
    "flags",
    "features",
    "command_flags",
    "json_endpoints",
    "json_fields",
]
_JSON_FIELDS = {
    "capabilities": _MANIFEST_KEYS,
    "check-password": ["category", "entropy", "raw_entropy", "warnings", "passed"],
    # Envelope endpoints list their "data" fields.
    "version": ["version", "git_commit", "python", "platform"],
    "show-version-file": ["version", "git_commit", "author", "license", "copyright", "history"],
    "list-algorithms": ["ciphers", "hashes", "kdfs", "kems", "signatures"],
    "list-available-algorithms": [
        "ciphers",
        "hashes",
        "kdfs",
        "kems",
        "signatures",
        "libraries",
    ],
    "check-argon2": ["available", "version", "variants", "functional"],
    "check-pqc": ["available", "liboqs_version", "algorithms"],
    # Bare-document endpoints list their guaranteed top-level keys.
    "info": ["format_version"],
    "analyze-config": [
        "overall_score",
        "security_level",
        "analysis_timestamp",
        "configuration_summary",
        "performance_assessment",
        "compatibility_matrix",
        "compliance_status",
        "future_proofing",
        "recommendations",
    ],
    "template": ["templates"],
    "list-plugins": ["plugins"],
    "plugin-info": ["name", "version", "type", "description", "enabled", "capabilities"],
    "security-info": ["report"],
    "verify-integrity": ["exit_code", "files", "scope", "signature", "trust_warning"],
    "verify-signature": [
        "valid",
        "file_match",
        "signature_valid",
        "signer",
        "signer_fingerprint",
    ],
    "verify-usb": ["integrity_ok", "verified_files"],
    "encrypt": ["action", "input", "output", "algorithm"],
    "decrypt": ["action", "input", "output"],
    "rekey": ["action", "input"],
    "sign": ["input", "signature"],
    "armor": ["action", "input", "output"],
    "dearmor": ["action", "input", "output"],
    "shred": ["action", "pattern", "matched", "success"],
    "create-usb": ["success", "usb_path"],
    "derive-password": ["derived", "format"],
    "generate-password": ["password"],
    "keyserver": ["enabled", "servers", "has_api_token", "cache"],
    "hsm": ["registered", "count", "rp_id", "credentials"],
    # plugin's JSON lives in its pepper/integrity subcommand groups
    # (gitlab#193/#194); the fields name those groups.
    "plugin": ["pepper", "integrity"],
}


def _cli_version() -> str:
    """Best-effort CLI version string, or 'unknown'."""
    try:
        from openssl_encrypt.version import __version__

        if isinstance(__version__, str) and __version__ and __version__ != "unknown":
            return __version__
    except Exception:
        pass
    try:
        from importlib.metadata import version

        return version("openssl-encrypt")
    except Exception:
        return "unknown"


def _line_from_version(version: str) -> str:
    """Map a version like '1.4.9' to the maintenance line '1.4.x'."""
    m = re.match(r"^(\d+)\.(\d+)\.", version or "")
    return f"{m.group(1)}.{m.group(2)}.x" if m else "unknown"


def introspect_commands(parser) -> List[str]:
    """Return the CLI's command names from the live argparse parser.

    The commands are the ``choices`` of the positional ``action`` argument (or,
    defensively, the first positional that declares choices).
    """
    for action in parser._actions:
        if getattr(action, "dest", None) == "action" and action.choices:
            return sorted(action.choices)
    for action in parser._actions:
        if not action.option_strings and action.choices:
            return sorted(action.choices)
    return []


def introspect_flags(parser) -> List[str]:
    """Return every option string (``--flag`` / ``-f``) the parser accepts,
    recursing into any registered subparsers.

    The CLI splits flags across a monolithic parser and a per-command subparser
    (crypt_cli_subparser); a command's own flags (e.g. ``--stego-password``,
    ``--add-code``) live on its subparser. Descending into ``_SubParsersAction``
    choices collects those too, so the manifest reflects the full flag surface.
    """
    import argparse

    flags = set()
    seen = set()

    def _walk(p):
        if id(p) in seen:
            return
        seen.add(id(p))
        for action in p._actions:
            # Match the --help surface: do not advertise flags the CLI hides
            # with help=argparse.SUPPRESS (deprecated/legacy/internal toggles).
            if getattr(action, "help", None) is not argparse.SUPPRESS:
                for opt in action.option_strings:
                    flags.add(opt)
            # Still recurse into subparsers so their (individually checked)
            # flags are collected.
            if isinstance(action, argparse._SubParsersAction):
                for sub in action.choices.values():
                    _walk(sub)

    _walk(parser)
    return sorted(flags)


def _compute_features(commands: List[str], flags: List[str]) -> Dict[str, bool]:
    cmd_set = set(commands)
    flag_set = set(flags)
    out = {}
    for feature, (kind, ref) in _FEATURE_RULES.items():
        if kind == "command":
            out[feature] = ref in cmd_set
        elif kind == "flag":
            out[feature] = ref in flag_set
        elif kind == "flag_prefix":
            out[feature] = any(f.startswith(ref) for f in flag_set)
        else:  # pragma: no cover - guarded by tests
            out[feature] = False
    return out


def build_capabilities_manifest(parser, commands=None, extra_parsers=None) -> Dict:
    """Build the capability manifest dict from the live CLI parser(s).

    Args:
        parser: The fully-constructed monolithic argparse parser used by the CLI.
        commands: The authoritative command-name list. The real CLI passes its
            ``KNOWN_COMMANDS`` here, because the monolithic parser's ``action``
            ``choices`` is only a partial legacy subset (gitlab#176/#179). When
            ``None`` (unit tests with a synthetic parser) the commands are
            introspected from the parser's positional ``choices``.
        extra_parsers: Additional parsers whose flags to union in (the CLI passes
            its per-command subparser, which declares command-specific flags the
            monolithic parser does not).

    Returns:
        A JSON-serializable dict describing this CLI build's capabilities. Only
        public names appear; no secret value and no environment state is read.
    """
    commands = sorted(commands) if commands is not None else introspect_commands(parser)
    flag_set = set(introspect_flags(parser))
    for extra in extra_parsers or ():
        flag_set.update(introspect_flags(extra))
    flags = sorted(flag_set)
    cmd_set = set(commands)

    # Emit curated maps as intent-intersect-reality (drop anything the live CLI
    # does not actually expose).
    command_flags = {
        cmd: [f for f in wanted if f in flag_set]
        for cmd, wanted in _COMMAND_FLAGS.items()
        if cmd in cmd_set
    }
    json_endpoints = [e for e in _JSON_ENDPOINTS if e in cmd_set]
    json_fields = {e: fields for e, fields in _JSON_FIELDS.items() if e in json_endpoints}

    version = _cli_version()
    return {
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "cli_version": version,
        "line": _line_from_version(version),
        "commands": commands,
        "flags": flags,
        "features": _compute_features(commands, flags),
        "command_flags": command_flags,
        "json_endpoints": json_endpoints,
        "json_fields": json_fields,
    }


def manifest_json(parser, commands=None, extra_parsers=None) -> str:
    """Return the capability manifest as a deterministic JSON string."""
    import json

    return json.dumps(
        build_capabilities_manifest(parser, commands=commands, extra_parsers=extra_parsers),
        sort_keys=True,
        indent=2,
    )
