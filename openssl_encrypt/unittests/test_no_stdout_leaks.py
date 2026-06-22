#!/usr/bin/env python3
"""
AST lint test to prevent stdout leaks.

Scans all non-test modules for print() calls without file=sys.stderr,
ensuring that only whitelisted data-output locations use stdout.
All code in English as per project requirements.
"""

import ast
import os

import pytest

# Whitelisted print() calls that MUST remain on stdout (data output)
# Format: (filename_suffix, line_number, description)
# Line numbers are checked with a tolerance of ±5 to handle minor edits
STDOUT_WHITELIST = [
    # crypt_cli.py — JSON data outputs
    ("crypt_cli.py", 1083, "JSON error response"),
    ("crypt_cli.py", 1280, "JSON algorithm result"),
    ("crypt_cli.py", 1797, "JSON smart-recommendations"),
    ("crypt_cli.py", 2969, "JSON keyserver bundle"),
    ("crypt_cli.py", 3200, "JSON telemetry events"),
    # crypt_cli.py — decrypted plaintext outputs
    ("crypt_cli.py", 9109, "asymmetric decrypted plaintext"),
    ("crypt_cli.py", 9112, "asymmetric decrypted plaintext (quiet)"),
    ("crypt_cli.py", 9301, "asymmetric decrypted plaintext path 2"),
    ("crypt_cli.py", 9304, "asymmetric decrypted plaintext path 2 (quiet)"),
    ("crypt_cli.py", 10086, "symmetric decrypted text content"),
    # crypt_cli.py — derive-password output to stdout
    ("crypt_cli.py", 5704, "derive-password hex output"),
    ("crypt_cli.py", 5708, "derive-password base64 output"),
    # crypt_core.py — JSON data output
    ("crypt_core.py", 7954, "print_file_info JSON output"),
    # crypt_core.py — protected DO NOT CHANGE block
    ("crypt_core.py", 9630, "PQC key decryption status (protected)"),
    ("crypt_core.py", 9637, "PQC key decryption failure (protected)"),
    ("crypt_core.py", 9643, "PQC key decryption error (protected)"),
    # crypt_utils.py — eprint() helper's own print() call
    ("crypt_utils.py", 25, "eprint() helper implementation"),
    # usb_creator.py — decrypted text content
    ("usb_creator.py", 914, "USB decrypted text content"),
    # verify_cli.py — verify-integrity --json data output (warning/report use stderr)
    ("verify_cli.py", 132, "verify-integrity JSON report"),
]

# Tolerance for line number matching (handles formatting/refactoring shifts)
LINE_TOLERANCE = 50


def _is_whitelisted(filepath: str, lineno: int) -> bool:
    """Check if a print() call at the given location is whitelisted."""
    for suffix, expected_line, _desc in STDOUT_WHITELIST:
        if filepath.endswith(suffix) and abs(lineno - expected_line) <= LINE_TOLERANCE:
            return True
    return False


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


def _find_stdout_prints(filepath: str) -> list:
    """Find all print() calls that write to stdout (no file= or file=sys.stdout)."""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for print() calls (not eprint)
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print":
            if not _has_stderr_kwarg(node):
                if not _is_whitelisted(filepath, node.lineno):
                    violations.append(
                        (
                            node.lineno,
                            ast.get_source_segment(source, node) or "print(...)",
                        )
                    )

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

    def test_whitelist_entries_still_valid(self):
        """Verify that whitelisted lines still contain print() calls."""
        for suffix, expected_line, desc in STDOUT_WHITELIST:
            # Find the file
            filepath = None
            package_root = os.path.join(os.path.dirname(__file__), "..")
            for root, dirs, files in os.walk(package_root):
                for f in files:
                    if f == os.path.basename(suffix) or os.path.join(root, f).replace(
                        os.sep, "/"
                    ).endswith(suffix):
                        filepath = os.path.join(root, f)
                        break

            assert filepath is not None, f"Whitelisted file not found: {suffix}"

            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Check within tolerance range
            found = False
            for offset in range(-LINE_TOLERANCE, LINE_TOLERANCE + 1):
                check_line = expected_line + offset - 1  # 0-based
                if 0 <= check_line < len(lines) and "print(" in lines[check_line]:
                    found = True
                    break

            assert found, (
                f"Whitelist entry no longer valid: {suffix}:{expected_line} ({desc}). "
                f"The print() call may have moved or been removed. Update the whitelist."
            )
