#!/usr/bin/env python3
"""
AST lint test: ensure no unwhitelisted print() calls write to stdout.

This test scans all non-test Python modules for print() calls that do NOT
use file=sys.stderr (or eprint). Any unwhitelisted stdout print() is a
regression — it means status/diagnostic output would leak into piped data.

Whitelisted locations are data-output calls that MUST go to stdout
(decrypted content, JSON data, binary pipe output).
"""

import ast
import os
import unittest


# Directories to scan (relative to package root)
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories to exclude from scanning
EXCLUDE_DIRS = {"unittests", "__pycache__", ".git", "examples", "scripts"}

# Files to exclude entirely (test scripts, demos, auto-generated)
EXCLUDE_FILES = {
    "version.py",  # Auto-generated, gitignored
    "crypt_gui.py",  # GUI module — uses tkinter messagebox, not piped
    "example_usage.py",  # Demo/example scripts
}

# File prefixes to exclude (test scripts outside unittests/)
EXCLUDE_PREFIXES = ("test_",)

# Whitelisted print() calls that MUST stay on stdout.
# Format: (relative_path, line_number, reason)
# Line numbers are approximate — the test checks ±5 lines.
STDOUT_WHITELIST = [
    # crypt_core.py — JSON data output in print_file_info
    ("modules/crypt_core.py", "print(json.dumps(metadata", "JSON data output for --info --json"),
    # crypt_core.py — 3 print() calls in DO NOT CHANGE blocks
    ("modules/crypt_core.py", "Successfully decrypted post-quantum private key", "DO NOT CHANGE block"),
    ("modules/crypt_core.py", "Failed to decrypt post-quantum private key", "DO NOT CHANGE block"),
    ("modules/crypt_core.py", "Error decrypting private key", "DO NOT CHANGE block"),
    # crypt_cli.py — JSON data output
    ("modules/crypt_cli.py", "print(json.dumps(", "JSON data output"),
    # crypt_cli.py — Decrypted plaintext output
    ("modules/crypt_cli.py", "print(plaintext.decode(", "Decrypted plaintext to stdout"),
    ("modules/crypt_cli.py", "print(decrypted.decode(", "Decrypted text to stdout"),
    # crypt_cli.py — subprocess -c strings (print inside string literals, not actual calls)
    ("modules/crypt_cli.py", 'print(oqs.oqs_python_version())', "Subprocess -c string"),
    ("modules/crypt_cli.py", "print(getattr(randomx,", "Subprocess -c string"),
    # randomx.py — subprocess -c strings
    ("modules/randomx.py", 'print("SUCCESS")', "Subprocess -c string"),
    # crypt_utils.py — eprint() definition itself uses print()
    ("modules/crypt_utils.py", "print(*args, **kwargs)", "eprint helper definition"),
    # keystore_cli.py — JSON data output for key listing
    ("modules/keystore_cli.py", "print(json.dumps(", "JSON data output"),
    # verify.py — JSON data output for verification results
    ("modules/verify.py", "print(json.dumps(", "JSON data output"),
    # portable_media/usb_creator.py — decrypted content to stdout
    ("modules/portable_media/usb_creator.py", "sys.stdout.buffer.write(content)", "Decrypted data output"),
]


def _is_whitelisted(rel_path: str, node: ast.Call, source_lines: list) -> bool:
    """Check if a print() call is in the whitelist."""
    line_text = source_lines[node.lineno - 1] if node.lineno <= len(source_lines) else ""

    for wl_path, wl_pattern, _reason in STDOUT_WHITELIST:
        if rel_path.replace(os.sep, "/") == wl_path.replace(os.sep, "/"):
            if wl_pattern in line_text:
                return True

    return False


def _has_stderr_kwarg(node: ast.Call) -> bool:
    """Check if a print() call has file=sys.stderr."""
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


def _is_in_string_literal(node: ast.Call, source_lines: list) -> bool:
    """Check if the print() call is inside a string literal (e.g., subprocess -c)."""
    line_text = source_lines[node.lineno - 1] if node.lineno <= len(source_lines) else ""
    # If "print(" appears after a quote character, it's likely in a string
    stripped = line_text.lstrip()
    # Heuristic: if the line contains -c and a string with print, it's a subprocess
    if '"-c"' in line_text or "'-c'" in line_text:
        return True
    # Check if print is inside a string (rough heuristic)
    before_print = line_text[:line_text.find("print(")]
    quote_count = before_print.count("'") + before_print.count('"')
    if quote_count % 2 == 1:
        return True
    return False


def _is_in_comment(node: ast.Call, source_lines: list) -> bool:
    """Check if the print() call is in a commented line."""
    line_text = source_lines[node.lineno - 1] if node.lineno <= len(source_lines) else ""
    stripped = line_text.lstrip()
    return stripped.startswith("#")


class TestNoStdoutLeaks(unittest.TestCase):
    """Verify no unwhitelisted print() calls leak to stdout."""

    def test_no_unwhitelisted_stdout_prints(self):
        """Scan all modules for print() calls without file=sys.stderr."""
        violations = []

        for dirpath, dirnames, filenames in os.walk(PACKAGE_ROOT):
            # Skip excluded directories
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                if filename in EXCLUDE_FILES:
                    continue
                if any(filename.startswith(p) for p in EXCLUDE_PREFIXES):
                    continue

                filepath = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(filepath, PACKAGE_ROOT)

                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        source = f.read()
                    source_lines = source.splitlines()
                    tree = ast.parse(source, filename=filepath)
                except (SyntaxError, UnicodeDecodeError):
                    continue

                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue

                    # Check for print() calls
                    is_print = False
                    if isinstance(node.func, ast.Name) and node.func.id == "print":
                        is_print = True
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "print":
                        is_print = True

                    if not is_print:
                        continue

                    # Skip if already using file=sys.stderr
                    if _has_stderr_kwarg(node):
                        continue

                    # Skip if in a string literal (subprocess -c commands)
                    if _is_in_string_literal(node, source_lines):
                        continue

                    # Skip if commented out
                    if _is_in_comment(node, source_lines):
                        continue

                    # Skip if whitelisted
                    if _is_whitelisted(rel_path, node, source_lines):
                        continue

                    line_text = (
                        source_lines[node.lineno - 1].strip()
                        if node.lineno <= len(source_lines)
                        else "<unknown>"
                    )
                    violations.append(
                        f"  {rel_path}:{node.lineno}: {line_text}"
                    )

        if violations:
            msg = (
                f"\n\nFound {len(violations)} unwhitelisted print() call(s) that may "
                f"leak to stdout.\nUse eprint() or print(..., file=sys.stderr) instead:\n\n"
                + "\n".join(violations)
            )
            self.fail(msg)


if __name__ == "__main__":
    unittest.main()
