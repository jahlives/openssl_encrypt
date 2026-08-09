#!/usr/bin/env python3
"""
AST lint test to prevent stdout leaks.

Scans all non-test modules for print() calls without file=sys.stderr,
ensuring that only whitelisted data-output locations use stdout.
All code in English as per project requirements.
"""

import ast
import os
import re
import sys
from unittest import mock

import pytest

module_under_test = sys.modules[__name__]

# Whitelisted print() calls that MUST remain on stdout (data output).
# Format: (path_suffix, call_text, occurrences, description)
#
# An entry authorizes ONE CALL SHAPE, a stated number of times -- not a
# region. The call's own source text (ast.get_source_segment) must EQUAL the
# entry's, with whitespace and black's magic trailing comma normalized away
# on both sides so reformatting cannot break an anchor. Equality rather than
# containment: a prefix would leave everything after it unconstrained, so
# adding a credential to an authorized payload would still match. The count
# stops a second copy of an authorized shape from inheriting the first's
# authorization.
#
# This replaced line-number anchors with a +/-50 line tolerance (gitlab#150),
# which authorized any stdout print() within 50 lines of an anchor. With
# several anchors in one file the windows merged and covered whole handler
# regions -- in recovery_slots.py they spanned the code that prints a
# generated recovery code, so turning that eprint into a print would not have
# tripped the lint that exists to guard exactly that. Line drift also forced a
# manual re-anchor on almost every commit touching a whitelisted file.
STDOUT_WHITELIST = [
    # crypt_cli.py — JSON data outputs
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"error": f"Registry system not available: {e}"}))',
        1,
        "JSON error response",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(result, indent=2))",
        1,
        "JSON algorithm result",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(result_dict, indent=2, ensure_ascii=False))",
        1,
        "JSON smart-recommendations",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(bundle.to_dict(), indent=2))",
        1,
        "JSON keyserver bundle",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(events, indent=2))",
        1,
        "JSON telemetry events",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(_report, indent=2))",
        1,
        "check-password JSON report",
    ),
    # crypt_cli.py — analyze-security / smart-recommendations / telemetry status
    # machine-readable output (gitlab#162). The human report stays on stderr; the
    # JSON documents carry only algorithm/config metadata, scores and advice text
    # (telemetry status exposes has_api_key as a boolean, not the key) — no
    # credential or key material. Security-reviewed 2026-08-09.
    (
        "modules/crypt_cli.py",
        "print(json.dumps(result, indent=2, ensure_ascii=False, default=str))",
        1,
        "analyze-security JSON analysis",
    ),
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"error": str(e)}))',
        1,
        "analyze-security JSON error response",
    ),
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"recommendations": [_recommendation_to_dict(r) for r in '
        "recommendations]}, indent=2, ensure_ascii=False, default=str))",
        1,
        "smart-recommendations get JSON output",
    ),
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"use_case": use_case, "experience_level": experience_level, '
        '"recommendations": quick_recs}, indent=2, ensure_ascii=False))',
        1,
        "smart-recommendations quick JSON output",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(status, indent=2))",
        1,
        "telemetry status JSON output",
    ),
    # crypt_cli.py — template list --format json (gitlab#167). Machine-readable
    # output for a non-interactive caller; the human report stays on stderr.
    # Carries template metadata only: no credential, no key material.
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"templates": _template_list_payload(templates)}, indent=2))',
        1,
        "template list JSON output",
    ),
    # crypt_cli.py — template compare --format json (gitlab#167). Same as list:
    # the payload is bounded template metadata + derived verdicts; the raw
    # self-asserted security score is deliberately NOT published (gitlab#169).
    (
        "modules/crypt_cli.py",
        "print(json.dumps(_template_compare_payload(comparison), indent=2))",
        1,
        "template compare JSON output",
    ),
    # crypt_cli.py — decrypted plaintext outputs. One shape, four call sites
    # (asymmetric and asymmetric-path-2, each with a quiet variant): the calls
    # are textually identical, so one entry authorizes exactly that shape.
    (
        "modules/crypt_cli.py",
        'print(plaintext.decode("utf-8", errors="replace"))',
        4,
        "asymmetric decrypted plaintext (2 paths x quiet/non-quiet)",
    ),
    (
        "modules/crypt_cli.py",
        "print(decrypted.decode().rstrip())",
        1,
        "symmetric decrypted text",
    ),
    # crypt_cli.py — derive-password output to stdout
    (
        "modules/crypt_cli.py",
        "print(derived.hex())",
        1,
        "derive-password hex output",
    ),
    (
        "modules/crypt_cli.py",
        'print(_b64.b64encode(derived).decode("ascii"))',
        1,
        "derive-password base64 output",
    ),
    # file_signature.py — verify-signature --json result (machine-readable)
    (
        "modules/file_signature.py",
        "print(result_json)",
        1,
        "verify-signature JSON result",
    ),
    # The same channel for the refusal outcomes (gitlab#160). A --json
    # consumer used to get an empty stdout and a bare exit code for exactly
    # the cases meaning "not from who you said"; the verdict is data, so it
    # belongs on stdout with the rest. Two sites: before the sidecar parses,
    # and after.
    (
        "modules/file_signature.py",
        "print(refusal_json)",
        2,
        "verify-signature JSON refusal verdict",
    ),
    # crypt_cli.py — generate-password --json result (gitlab#187). The
    # password IS the payload here; the human display path is skipped in
    # this mode, so it never also reaches stderr. Two call sites, one
    # shape: character mode and diceware mode.
    (
        "modules/crypt_cli.py",
        "print(password_json)",
        2,
        "generate-password JSON result",
    ),
    # identity_cli.py — identity list --json result (machine-readable, gitlab#183)
    (
        "modules/identity_cli.py",
        "print(listing_json)",
        1,
        "identity list JSON result",
    ),
    # recovery_slots.py — recovery commands' --json results (gitlab#146).
    # Machine-readable output for non-interactive callers. None of these
    # carries a credential: a generated recovery code is written to its own
    # 0600 file via --recovery-code-out, and only that path appears in the
    # JSON. These four entries are exactly why the tolerance mattered — under
    # the old anchors their windows merged over the credential-printing code.
    (
        "modules/recovery_slots.py",
        'print(json.dumps({"slots": [{"id": _capped(s.get("id")), '
        '"type": _capped(s.get("type")), "key_id": _capped(s.get("key_id"))} '
        "for s in slots]}, indent=2))",
        1,
        "list-recovery JSON slot list",
    ),
    (
        "modules/recovery_slots.py",
        'print(json.dumps({"output": args.output}, indent=2))',
        1,
        "recover JSON result",
    ),
    (
        "modules/recovery_slots.py",
        "print(json.dumps(doc, indent=2))",
        1,
        "add-recovery JSON result",
    ),
    (
        "modules/recovery_slots.py",
        'print(json.dumps({"output": args.output, "removed_slot_id": args.slot_id}, indent=2))',
        1,
        "remove-recovery JSON result",
    ),
    # crypt_core.py — JSON data output
    (
        "modules/crypt_core.py",
        "print(json.dumps(metadata, indent=2, ensure_ascii=False))",
        1,
        "print_file_info JSON output",
    ),
    # crypt_core.py — protected DO NOT CHANGE block
    (
        "modules/crypt_core.py",
        'print("Successfully decrypted post-quantum private key from metadata")',
        1,
        "PQC key decryption status (protected)",
    ),
    (
        "modules/crypt_core.py",
        'print("Failed to decrypt post-quantum private key - wrong password")',
        1,
        "PQC key decryption failure (protected)",
    ),
    (
        "modules/crypt_core.py",
        'print(f"Error decrypting private key: {str(e)}")',
        1,
        "PQC key decryption error (protected)",
    ),
    # crypt_utils.py — eprint() helper's own print() call
    (
        "modules/crypt_utils.py",
        "print(*args, **kwargs)",
        1,
        "eprint() helper implementation",
    ),
    # verify_cli.py — verify-integrity --json data output (warning/report use stderr)
    (
        "integrity/verify_cli.py",
        "print(json.dumps(payload, indent=2, sort_keys=True))",
        1,
        "verify-integrity JSON report",
    ),
    # pepper_cli.py — plugin pepper machine-readable output (gitlab#193). The
    # GUI consumes stdout as JSON, and the two secret payloads (the TOTP shared
    # secret from setup-totp, the one-time backup codes from verify-totp) are
    # deliberately delivered HERE on stdout only, never on stderr (which the
    # GUI persists to its debug log); each is also registered with the redactor.
    (
        "modules/plugin_system/pepper_cli.py",
        'print(json.dumps({"peppers": peppers}, ensure_ascii=True))',
        1,
        "pepper list JSON result",
    ),
    (
        "modules/plugin_system/pepper_cli.py",
        "print(json.dumps(document, ensure_ascii=True))",
        1,
        "pepper setup-totp JSON result (secret payload, stdout-only)",
    ),
    (
        "modules/plugin_system/pepper_cli.py",
        'print(json.dumps({"verified": True, "backup_codes": backup_codes}, ensure_ascii=True))',
        1,
        "pepper verify-totp JSON result (backup codes, stdout-only)",
    ),
    # integrity_cli.py — plugin integrity machine-readable output (gitlab#194).
    # No credential: stats are counters, and verify emits an outcome document
    # the GUI reads. On stdout so a non-interactive caller can parse it.
    (
        "modules/plugin_system/integrity_cli.py",
        "print(json.dumps(stats, ensure_ascii=True))",
        1,
        "integrity stats JSON result",
    ),
    (
        "modules/plugin_system/integrity_cli.py",
        "print(json.dumps(document, ensure_ascii=True))",
        1,
        "integrity verify outcome JSON result",
    ),
]


def _normalize(text: str) -> str:
    """Reformat-insensitive form of a call's source text.

    Whitespace is removed, and so is a comma directly before a closing
    bracket: black adds that magic trailing comma when it explodes a call
    across lines, and an anchor must survive its own file being reformatted.

    Two consequences worth knowing, neither security-relevant since
    identifiers and structure are preserved: whitespace inside a string
    literal is normalized too (``print("a b")`` and ``print("ab")`` are one
    shape), and ``ast.get_source_segment`` includes comments, so adding an
    inline comment inside a whitelisted multi-line call changes its text and
    breaks the anchor. That fails closed -- the call is reported -- but the
    fix is to update the entry, not to delete it.
    """
    return re.sub(r",(?=[)\]}])", "", "".join(text.split()))


def _path_matches(filepath: str, suffix: str) -> bool:
    """Path-component-aware suffix match.

    Anchored on a separator so a future `gui_modules/crypt_cli.py` or a
    vendored copy cannot inherit the real module's authorizations.
    """
    normalized = filepath.replace(os.sep, "/")
    suffix = suffix.replace(os.sep, "/")
    return normalized == suffix or normalized.endswith("/" + suffix)


def _is_whitelisted(filepath: str, node: ast.Call, source: str) -> bool:
    """Check whether THIS call is whitelisted.

    Matches the call's own source text rather than its position, so an entry
    authorizes one call shape instead of every print() in its neighbourhood,
    and moving code around does not silently widen or invalidate an anchor.
    """
    return _matching_entry(filepath, node, source) is not None


def _has_stderr_kwarg(node: ast.Call) -> bool:
    """Check if a print/eprint call has file=sys.stderr."""
    for kw in node.keywords:
        if kw.arg == "file":
            # Check for sys.stderr
            if isinstance(kw.value, ast.Attribute):
                if (
                    isinstance(kw.value.value, ast.Name)
                    and kw.value.value.id == "sys"
                    and kw.value.attr == "stderr"
                ):
                    return True
    return False


def _iter_stdout_calls(filepath: str):
    """Yield (node, segment) for every stdout print() call in a file.

    Single source of truth for "what counts as a stdout print and what is
    its normalized text", so the violation test and the whitelist-accuracy
    test cannot drift apart.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "print"):
            continue
        if _has_stderr_kwarg(node):
            continue
        yield node, source


def _matching_entry(filepath: str, node: ast.Call, source: str):
    """The whitelist entry authorizing this call, or None."""
    try:
        raw_segment = ast.get_source_segment(source, node)
    except (IndexError, ValueError):
        # get_source_segment indexes into the source it is handed; if that
        # does not correspond to the node it raises rather than returning
        # None. Either way the call is unreadable.
        raw_segment = None
    segment = _normalize(raw_segment or "")
    if not segment:
        # An empty segment must never match, so an unreadable call is
        # reported rather than authorized -- the one way this could fail open.
        return None
    for entry in STDOUT_WHITELIST:
        suffix, call_text, _count, _desc = entry
        if _path_matches(filepath, suffix) and _normalize(call_text) == segment:
            return entry
    return None


def _find_stdout_prints(filepath: str) -> list:
    """Find stdout print() calls in a file that no whitelist entry authorizes."""
    violations = []
    for node, source in _iter_stdout_calls(filepath):
        if _matching_entry(filepath, node, source) is None:
            violations.append((node.lineno, ast.get_source_segment(source, node) or "print(...)"))
    return violations


def _get_source_files() -> list:
    """Get all non-test Python source files in the package."""
    source_files = []
    package_root = os.path.join(os.path.dirname(__file__), "..")

    for root, dirs, files in os.walk(package_root):
        # Skip test directories and cache
        basename = os.path.basename(root)
        if basename in ("unittests", "__pycache__", ".git"):
            continue

        for f in files:
            if not f.endswith(".py"):
                continue
            # Skip test files and generated files
            if f.startswith("test_") or f == "version.py":
                continue

            source_files.append(os.path.join(root, f))

    return source_files


class TestNoStdoutLeaks:
    """Ensure no accidental print-to-stdout in production code."""

    def test_no_unwhitelisted_stdout_prints(self):
        """All print() calls in non-test code must use stderr or be whitelisted."""
        all_violations = []

        for filepath in _get_source_files():
            violations = _find_stdout_prints(filepath)
            for lineno, code in violations:
                rel_path = os.path.relpath(filepath)
                all_violations.append(f"  {rel_path}:{lineno}: {code[:80]}")

        if all_violations:
            msg = (
                f"Found {len(all_violations)} print() call(s) writing to stdout "
                f"that are not whitelisted:\n"
                + "\n".join(all_violations)
                + "\n\nEither convert to eprint() or add to STDOUT_WHITELIST "
                "in test_no_stdout_leaks.py if this is intentional data output."
            )
            pytest.fail(msg)

    def test_no_sys_stdout_write(self):
        """No sys.stdout.write() calls except for binary pipe output."""
        violations = []

        for filepath in _get_source_files():
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()

            try:
                tree = ast.parse(source, filename=filepath)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func = node.func
                # Match sys.stdout.write (not sys.stdout.buffer.write)
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "write"
                    and isinstance(func.value, ast.Attribute)
                    and func.value.attr == "stdout"
                    and isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "sys"
                ):
                    rel_path = os.path.relpath(filepath)
                    violations.append(f"  {rel_path}:{node.lineno}")

        if violations:
            msg = (
                f"Found {len(violations)} sys.stdout.write() call(s):\n"
                + "\n".join(violations)
                + "\n\nConvert to sys.stderr.write() for non-data output."
            )
            pytest.fail(msg)

    def test_whitelist_entries_are_call_anchored(self):
        """Every entry must name a print() call, not a neighbourhood.

        Anchored at the start, not merely containing `print(`: an empty or
        incidental pattern would authorize by coincidence -- and an empty one
        would match every call, the single way this matcher can fail open.
        """
        for suffix, call_text, count, desc in STDOUT_WHITELIST:
            assert _normalize(call_text).startswith("print("), (
                f"Whitelist entry for {suffix} ({desc}) does not start with a "
                f"print( call: {call_text!r}. Anchor entries to the call itself."
            )
            assert count >= 1, f"{suffix} ({desc}): occurrence count must be >= 1"

    def test_whitelist_matches_exactly_the_expected_calls(self):
        """Each entry must match a real call, the stated number of times.

        Covers both directions: a dead entry is an authorization with no
        justification left in the code, and an extra occurrence means a
        second call silently inherited the first's authorization -- the one
        dimension where shape matching is looser than a position anchor.

        Shares _iter_stdout_calls/_matching_entry with the violation test, so
        the two cannot drift apart.
        """
        counts = {(s, c): 0 for s, c, _n, _d in STDOUT_WHITELIST}

        for filepath in _get_source_files():
            for node, source in _iter_stdout_calls(filepath):
                entry = _matching_entry(filepath, node, source)
                if entry is not None:
                    counts[(entry[0], entry[1])] += 1

        problems = []
        for suffix, call_text, expected, desc in STDOUT_WHITELIST:
            actual = counts[(suffix, call_text)]
            if actual != expected:
                problems.append(f"  {suffix} ({desc}): expected {expected} call(s), found {actual}")

        assert not problems, (
            "Whitelist no longer describes the code:\n"
            + "\n".join(problems)
            + "\n\nFound 0: the call was removed, reflowed, or gained an inline "
            "comment (the anchor is its exact source text) -- update or delete "
            "the entry. Found more than expected: a new call reused an "
            "authorized shape -- justify it explicitly."
        )

    def test_a_neighbouring_print_is_not_whitelisted(self):
        """Regression for gitlab#150.

        The whitelist used line numbers with a +/-50 tolerance, so an entry
        authorized every stdout print() within 50 lines of it. This asserts
        the replacement authorizes only the call it names, even when an
        unrelated print() sits directly beside it.
        """
        source = "def handler():\n    print(result_json)\n    print(secret_recovery_code)\n"
        tree = ast.parse(source)
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
        ]
        assert len(calls) == 2

        whitelisted, neighbour = calls
        path = "openssl_encrypt/modules/file_signature.py"
        assert _is_whitelisted(path, whitelisted, source)
        assert not _is_whitelisted(path, neighbour, source), (
            "A print() adjacent to a whitelisted call must not inherit its "
            "authorization (gitlab#150)."
        )

    def test_an_extended_payload_is_not_whitelisted(self):
        """Authorization covers the exact call, not a prefix of it.

        The recovery-slot JSON is authorized precisely because it carries no
        credential. Adding one to the payload must revoke the authorization
        rather than ride along on the matching prefix.
        """
        source = 'print(json.dumps({"output": args.output, "code": generated_code}, indent=2))\n'
        node = next(
            n
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
        )
        assert not _is_whitelisted("openssl_encrypt/modules/recovery_slots.py", node, source), (
            "Extending an authorized payload with a credential must not stay "
            "authorized (gitlab#150 review finding)."
        )

    def test_a_vendored_copy_does_not_inherit_authorization(self):
        """Path suffixes are matched on component boundaries.

        Without that, a future `gui_modules/crypt_cli.py` or a vendored copy
        would silently inherit every authorization of the real module.
        """
        source = "print(derived.hex())\n"
        node = next(
            n
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
        )
        assert _is_whitelisted("openssl_encrypt/modules/crypt_cli.py", node, source)
        assert not _is_whitelisted("third_party/gui_modules/crypt_cli.py", node, source)

    def test_a_truncated_entry_would_not_authorize(self):
        """Authorization is equality, not a prefix.

        Pinned by driving a deliberately truncated entry through the matcher:
        under prefix or substring matching this would authorize the real
        call, so reverting to either fails here.
        """
        source = 'print(json.dumps({"output": args.output, "code": generated_code}, indent=2))\n'
        node = next(
            n
            for n, _s in [
                (n, source)
                for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
            ]
        )
        truncated = [
            (
                "modules/recovery_slots.py",
                'print(json.dumps({"output": args.output',
                1,
                "deliberately truncated",
            )
        ]
        with mock.patch.object(module_under_test, "STDOUT_WHITELIST", truncated):
            assert not _is_whitelisted(
                "openssl_encrypt/modules/recovery_slots.py", node, source
            ), "A truncated entry must not authorize a longer call (gitlab#150)."

    def test_an_unreadable_call_is_not_authorized(self):
        """The empty-segment path must fail closed.

        ast.get_source_segment can return None; an empty segment matching
        anything is the one way this matcher could fail open.
        """
        node = next(
            n
            for n in ast.walk(ast.parse("print(result_json)\n"))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
        )
        assert not _is_whitelisted(
            "openssl_encrypt/modules/file_signature.py", node, ""
        ), "A call whose source cannot be recovered must be reported, not authorized."

    def test_whitelist_survives_reformatting(self):
        """Anchors must not break when black reflows a call.

        Line anchors drifted on nearly every commit; a raw-text anchor would
        break on a reflow. Matching is whitespace- and trailing-comma
        insensitive so neither happens.
        """
        one_line = "print(json.dumps(doc, indent=2))\n"
        reflowed = "print(\n    json.dumps(\n        doc,\n        indent=2,\n    )\n)\n"
        path = "openssl_encrypt/modules/recovery_slots.py"
        for source in (one_line, reflowed):
            node = next(
                n
                for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
            )
            assert _is_whitelisted(path, node, source), f"anchor broke on: {source!r}"
