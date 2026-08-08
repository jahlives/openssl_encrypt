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
# On this line the previous matcher was not the +/-50 line-number one; it
# matched a PREFIX against the call's first source line, and 9 of its 22
# entries were bare prefixes like `print(json.dumps(`. That authorized
# every json.dumps print in the file -- five distinct calls in crypt_cli.py
# alone -- and, being a prefix, left everything after it unconstrained, so
# widening an authorized payload to include a credential still matched. It
# also only looked at the FIRST line, so a call reformatted across lines
# was matched on its opening fragment (gitlab#184).
#
# The 1.4.x line replaced line-number anchors with a +/-50 line tolerance (gitlab#150),
# which authorized any stdout print() within 50 lines of an anchor. With
# several anchors in one file the windows merged and covered whole handler
# regions -- in recovery_slots.py they spanned the code that prints a
# generated recovery code, so turning that eprint into a print would not have
# tripped the lint that exists to guard exactly that. Line drift also forced a
# manual re-anchor on almost every commit touching a whitelisted file.
EXCLUDE_DIRS = {"unittests", "__pycache__", ".git", "examples", "scripts"}
EXCLUDE_FILES = {"version.py", "crypt_gui.py", "example_usage.py"}

STDOUT_WHITELIST = [
    # --- machine-readable JSON channels (the consumer parses stdout) ---
    (
        "modules/crypt_core.py",
        "print(json.dumps(metadata, indent=2, ensure_ascii=False))",
        1,
        "--info --json metadata document",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(result, indent=2))",
        1,
        "check-password --json document",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(events, indent=2))",
        1,
        "audit/event listing --json document",
    ),
    (
        "modules/crypt_cli.py",
        "print(json.dumps(bundle.to_dict(), indent=2))",
        1,
        "identity export --json bundle",
    ),
    ("modules/crypt_cli.py", "print(json.dumps(_report, indent=2))", 1, "report --json document"),
    (
        "modules/crypt_cli.py",
        'print(json.dumps({"error": f"Registry system not available: {e}"}))',
        1,
        "JSON-mode error document: the caller parses stdout, so the error has to "
        "arrive there in the same shape as a success",
    ),
    (
        "modules/keystore_cli.py",
        "print(json.dumps(keys, indent=2))",
        1,
        "keystore key listing --json",
    ),
    ("modules/verify.py", "print(json.dumps(output, indent=2))", 1, "verification result --json"),
    (
        "integrity/verify_cli.py",
        "print(json.dumps(payload, indent=2, sort_keys=True))",
        1,
        "verify-integrity --json report",
    ),
    ("modules/file_signature.py", "print(result_json)", 1, "verify-signature --json result"),
    # The same channel for the refusal outcomes (gitlab#160): a --json
    # consumer used to get an empty stdout and a bare exit code for exactly
    # the cases meaning "not from who you said". Two sites, before and after
    # the sidecar parses.
    ("modules/file_signature.py", "print(refusal_json)", 2, "verify-signature JSON refusal"),
    (
        "modules/identity_cli.py",
        "print(listing_json)",
        1,
        "identity list --json document (gitlab#183)",
    ),
    (
        "modules/crypt_cli.py",
        "print(password_json)",
        2,
        "generate-password --json document, one per mode (character and diceware); "
        "the password IS the payload and the human display path is skipped in this "
        "mode, so it never also reaches stderr (gitlab#187)",
    ),
    # --- audit_cli: a CLI whose whole output is meant to be piped ---
    (
        "modules/audit_cli.py",
        "print(json.dumps(_report_to_json(report)))",
        1,
        "audit verify --json report",
    ),
    ("modules/audit_cli.py", "print(json.dumps(info, sort_keys=True))", 1, "audit status --json"),
    (
        "modules/audit_cli.py",
        "print(_format_report_human(report, log_paths))",
        1,
        "audit verify human report",
    ),
    ("modules/audit_cli.py", 'print(f"{key}: {info[key]}")', 1, "audit status human fields"),
    (
        "modules/audit_cli.py",
        'print(json.dumps({"error": "missing_seed", "path": str(seed_path)}))',
        1,
        "audit JSON-mode error document",
    ),
    (
        "modules/audit_cli.py",
        'print(json.dumps({"error": "io_error", "message": str(exc)}))',
        1,
        "audit JSON-mode error document",
    ),
    (
        "modules/audit_cli.py",
        'print(json.dumps({"error": "state_load_error", "message": str(exc)}))',
        1,
        "audit JSON-mode error document",
    ),
    (
        "modules/audit_cli.py",
        'print(json.dumps({"error": "missing_log", "path": str(log_path)}))',
        1,
        "audit JSON-mode error document",
    ),
    (
        "modules/audit_cli.py",
        'print(json.dumps({"error": "anchor_pubkey_read_error", "message": str(exc)}))',
        1,
        "audit JSON-mode error document",
    ),
    # --- user data that IS the output ---
    (
        "modules/crypt_cli.py",
        'print(plaintext.decode("utf-8", errors="replace"))',
        4,
        "decrypted plaintext to stdout (one per output branch)",
    ),
    ("modules/crypt_cli.py", "print(decrypted.decode().rstrip())", 1, "decrypted text to stdout"),
    ("modules/crypt_cli.py", "print(derived.hex())", 1, "derive-password hex output"),
    (
        "modules/crypt_cli.py",
        'print(base64.b64encode(derived).decode("ascii"))',
        1,
        "derive-password base64 output",
    ),
    # --- protected blocks and the helper itself ---
    (
        "modules/crypt_core.py",
        'print("Successfully decrypted post-quantum private key from metadata")',
        1,
        "inside a DO NOT CHANGE block",
    ),
    (
        "modules/crypt_core.py",
        'print("Failed to decrypt post-quantum private key - wrong password")',
        1,
        "inside a DO NOT CHANGE block",
    ),
    (
        "modules/crypt_core.py",
        'print(f"Error decrypting private key: {str(e)}")',
        1,
        "inside a DO NOT CHANGE block",
    ),
    (
        "modules/crypt_utils.py",
        "print(*args, **kwargs)",
        1,
        "the eprint() helper's own implementation",
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
    """Non-test Python sources in the package.

    The exclusions are this line's, not 1.4.x's: `scripts/` and `examples/`
    hold developer tools whose stdout IS their interface, `crypt_gui.py`
    talks to a GUI toolkit rather than a pipe, and `example_usage.py` is a
    demo. None of them is reachable from the CLI whose stdout this lint
    protects.
    """
    source_files = []
    package_root = os.path.join(os.path.dirname(__file__), "..")

    for root, dirs, files in os.walk(package_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        if os.path.basename(root) in EXCLUDE_DIRS:
            continue

        for f in files:
            if not f.endswith(".py"):
                continue
            if f in EXCLUDE_FILES or f.startswith("test_"):
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
        one_line = "print(json.dumps(keys, indent=2))\n"
        reflowed = "print(\n    json.dumps(\n        keys,\n        indent=2,\n    )\n)\n"
        path = "openssl_encrypt/modules/keystore_cli.py"
        for source in (one_line, reflowed):
            node = next(
                n
                for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"
            )
            assert _is_whitelisted(path, node, source), f"anchor broke on: {source!r}"
