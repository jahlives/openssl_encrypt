#!/usr/bin/env python3
"""Key-derivation configuration for the D-Bus service (gitlab#228, security F1).

Kept dbus-free and separate from ``dbus_service`` so this security-critical
logic is unit-testable without the D-Bus stack, and so it cannot silently
regress into the collapse it fixes.

Background: the D-Bus ``EncryptFile`` handler used to hand-build a ``hash_config``
with flat key names (``argon2_time_cost``, ``sha512_iterations``, ``enable_hkdf``,
...) that ``crypt_core`` never reads. crypt_core wants **flat** hash-round ints
(``hash_config['sha256'] = 10000``) and **nested** KDF dicts
(``hash_config['argon2'] = {'enabled': True, ...}``). So no KDF and no hash
rounds were ever enabled, and because the dict was non-empty it also defeated
``encrypt_file``'s ``hash_config is None`` STANDARD-template default -- every
D-Bus-encrypted file was keyed by a single unstretched SHA-256 (CWE-916).

This module builds the config in the structure crypt_core consumes, starting
from the STANDARD template (which always enables Argon2id), and exposes a
fail-closed check the handler uses to refuse any request that would derive a
key without stretching.
"""

from typing import Any, Dict

# Flat hash-round algorithms crypt_core.get_hash_rounds understands.
_HASH_ALGOS = (
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake3",
    "shake256",
    "whirlpool",
)
# Work-factor KDFs (memory-hard or iterated). HKDF is deliberately excluded:
# it is a fast extract-and-expand, not a password-stretching work factor.
_STRETCHING_KDFS = ("argon2", "scrypt", "balloon", "randomx")
# All nested KDF dicts crypt_core consumes (including hkdf, which is a valid
# component but does not by itself count as stretching).
_KDFS = ("argon2", "scrypt", "balloon", "hkdf", "randomx")

# D-Bus option name -> flat hash-round key crypt_core reads.
_ROUND_OPTIONS = {
    "sha256_rounds": "sha256",
    "sha512_rounds": "sha512",
    "sha3_256_rounds": "sha3_256",
    "sha3_512_rounds": "sha3_512",
    "blake2b_rounds": "blake2b",
    "blake3_rounds": "blake3",
    "shake256_rounds": "shake256",
}
_ARGON2_MODE_MAP = {"argon2i": "i", "argon2d": "d", "argon2id": "id"}

# Upper bounds on client-supplied cost parameters (gitlab#228 review, Medium).
# Before the F1 fix these option keys were dead (crypt_core never read them);
# the fix makes them live, so an unbounded value (e.g. 16 GiB Argon2 memory, a
# billion hash rounds) would be a resource-exhaustion DoS -- and on the system
# bus the root daemon is reachable by any polkit-authorized admin. The
# encryptor has no cost ceiling of its own (crypt_core.py: "the encrypt path
# has no ceiling check of its own"), so the D-Bus boundary caps them. Ceilings
# sit above the PARANOID template (argon2 128 MiB / t=4 / p=8, hash rounds up
# to 800k) so every legitimate request passes; values above the cap are clamped
# down, not rejected, so the operation still succeeds with strong parameters.
_ARGON2_MAX_MEMORY_KIB = 1024 * 1024  # 1 GiB
_ARGON2_MAX_TIME_COST = 32
_ARGON2_MAX_PARALLELISM = 16
_HASH_MAX_ROUNDS = 5_000_000
_BALLOON_MAX_ROUNDS = 5_000
# A hash component counts as stretching only above this round floor, so the
# fail-closed gate is not satisfied by a token single-round hash (review Low).
_HASH_ROUND_FLOOR = 1_000


def _clamp_int(value: Any, lo: int, hi: int) -> Any:
    """Coerce to int and clamp into [lo, hi]; None on unparseable input."""
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return None


def build_encrypt_hash_config(parsed_options: Dict[str, Any]) -> Dict[str, Any]:
    """Build a hash_config crypt_core actually consumes, from D-Bus options.

    Starts from the STANDARD security template (Argon2id t=3/m=64MiB/p=4 +
    RandomX + SHA3-512/BLAKE3 rounds) so the baseline is always stretched, then
    applies the caller's overrides mapped to the keys crypt_core reads. The
    result never collapses to an unstretched key for the shipped option set.

    Args:
        parsed_options: options already unwrapped from D-Bus variants.

    Returns:
        A hash_config dict (flat hash-round ints + nested KDF dicts) suitable
        for ``encrypt_file(..., hash_config=...)``.
    """
    from .crypt_cli import SecurityTemplate, get_template_config

    template = get_template_config(SecurityTemplate.STANDARD)["hash_config"]

    hash_config: Dict[str, Any] = {}
    for algo in _HASH_ALGOS:
        if isinstance(template.get(algo), int):
            hash_config[algo] = template[algo]
    for kdf in _KDFS:
        if isinstance(template.get(kdf), dict):
            hash_config[kdf] = dict(template[kdf])
    hash_config["pbkdf2_iterations"] = 0

    # --- caller overrides, mapped to the correct keys and cost-bounded ---
    # Overrides may only RAISE cost: each lower bound is the STANDARD-template
    # baseline already copied above (falling back to a hardware floor when the
    # template does not set that key). This prevents a client from downgrading
    # the key below STANDARD -- e.g. argon2 memory_cost=8/time_cost=1 or
    # sha3_512_rounds=0 -- which would re-introduce the #228 CWE-916 collapse
    # by weak-but-nonzero parameters instead of dead keys (review Medium).
    for opt, algo in _ROUND_OPTIONS.items():
        if opt in parsed_options:
            baseline = hash_config.get(algo, 0)
            floor = baseline if isinstance(baseline, int) and baseline > 0 else 0
            v = _clamp_int(parsed_options[opt], floor, _HASH_MAX_ROUNDS)
            if v is not None:
                hash_config[algo] = v

    argon2 = hash_config.setdefault("argon2", {"enabled": True})
    for opt, key, hard_lo, hi in (
        ("argon2_time_cost", "time_cost", 1, _ARGON2_MAX_TIME_COST),
        ("argon2_memory_cost", "memory_cost", 8, _ARGON2_MAX_MEMORY_KIB),
        ("argon2_parallelism", "parallelism", 1, _ARGON2_MAX_PARALLELISM),
    ):
        if opt in parsed_options:
            baseline = argon2.get(key)
            lo = max(hard_lo, baseline) if isinstance(baseline, int) else hard_lo
            v = _clamp_int(parsed_options[opt], lo, hi)
            if v is not None:
                argon2[key] = v
                argon2["enabled"] = True
    if "argon2_mode" in parsed_options:
        argon2["enabled"] = True
        argon2["type"] = _ARGON2_MODE_MAP.get(str(parsed_options["argon2_mode"]).lower(), "id")

    if parsed_options.get("enable_hkdf"):
        hash_config.setdefault("hkdf", {})["enabled"] = True

    if "balloon_rounds" in parsed_options:
        rounds = _clamp_int(parsed_options["balloon_rounds"], 0, _BALLOON_MAX_ROUNDS)
        if rounds and rounds > 0:
            balloon = hash_config.setdefault("balloon", {"enabled": True})
            balloon["enabled"] = True
            balloon["rounds"] = rounds

    return hash_config


def config_provides_key_stretching(hash_config: Dict[str, Any]) -> bool:
    """Fail-closed gate: True iff the config would stretch the password.

    Requires at least one hash algorithm with rounds > 0 OR one enabled
    memory-hard/iterated KDF (Argon2/scrypt/balloon/RandomX). HKDF alone does
    NOT qualify. The D-Bus handler refuses to encrypt when this is False, so an
    unstretched single-hash key can never be produced regardless of what
    options a client sends.
    """
    if not isinstance(hash_config, dict):
        return False
    kdf_section = hash_config
    if isinstance(hash_config.get("derivation_config"), dict):
        kdf_section = hash_config["derivation_config"].get("kdf_config", hash_config)

    for algo in _HASH_ALGOS:
        v = hash_config.get(algo)
        if isinstance(v, int) and v >= _HASH_ROUND_FLOOR:
            return True
    for kdf in _STRETCHING_KDFS:
        cfg = kdf_section.get(kdf)
        if isinstance(cfg, dict) and cfg.get("enabled"):
            return True
    return False
