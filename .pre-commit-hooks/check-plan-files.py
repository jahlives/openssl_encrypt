#!/usr/bin/env python3
"""
Pre-commit hook to enforce branch-specific rules for plan files.

This hook auto-removes plan files from commits on production branches
(main, releases/*) while allowing them in development branches (dev, feature/*).

Plan files remain in the working directory but are not committed to protected branches.
"""

import subprocess
import sys
from pathlib import Path


def get_current_branch():
    """Get the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        # Handle detached HEAD state
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            # Fallback: return empty string if we can't determine branch
            return ""


def is_plan_file(filename):
    """
    Check if a file matches plan file patterns - .md files ONLY!

    Patterns: *plan*.md, *implementation*.md (case-insensitive)

    Args:
        filename: Path to the file

    Returns:
        True if file matches plan file pattern, False otherwise
    """
    filename_lower = filename.lower()

    # MUST be a markdown file
    if not filename_lower.endswith(".md"):
        return False

    # Get basename only (not full path)
    basename = Path(filename).name.lower()

    # Check for 'plan' or 'implementation' in basename
    return "plan" in basename or "implementation" in basename


def is_branch_allowed(branch_name):
    """
    Check if plan files are allowed on this branch.

    Allowed: dev, feature/*
    Blocked: main, releases/*, and all others

    Args:
        branch_name: Name of the current branch

    Returns:
        True if plan files are allowed, False otherwise
    """
    if not branch_name:
        # If we can't determine branch, be conservative and block
        return False

    # Normalize branch name
    branch = branch_name.strip()

    # Allowed branches
    if branch == "dev":
        return True
    if branch.startswith("feature/"):
        return True

    # All other branches are blocked
    return False


def get_staged_files():
    """Get list of staged files."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def unstage_files(files):
    """
    Remove files from staging area.

    Args:
        files: List of file paths to unstage

    Returns:
        True if successful, False otherwise
    """
    if not files:
        return True

    try:
        subprocess.run(["git", "reset", "HEAD"] + files, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def main(filenames=None):
    """
    Main hook logic.

    Args:
        filenames: List of staged files (provided by pre-commit framework)

    Returns:
        0 if check passes (or files auto-removed), 1 if error occurs
    """
    # Get current branch
    current_branch = get_current_branch()

    # If branch allows plan files, exit early
    if is_branch_allowed(current_branch):
        return 0

    # Get staged files
    if filenames is None:
        filenames = get_staged_files()

    # Check for plan files in staged files
    plan_files = [f for f in filenames if is_plan_file(f)]

    if not plan_files:
        return 0

    # Plan files found on restricted branch - auto-remove them
    print("\n" + "=" * 80)
    print("⚠️  WARNING: Plan files automatically removed from commit")
    print("=" * 80)
    print(f"\nCurrent branch: {current_branch} (protected)")
    print(f"\nPlan files removed from staging ({len(plan_files)}):")
    for pf in plan_files:
        print(f"  - {pf}")

    print("\nThese files will remain in your working directory but are NOT committed.")

    print("\n" + "-" * 80)
    print("Plan files (*plan*.md, *implementation*.md) are only committed on:")
    print("  ✓ dev branch")
    print("  ✓ feature/* branches")
    print("\nPlan files are auto-removed from commits on:")
    print("  ✗ main branch")
    print("  ✗ releases/* branches")
    print("  ✗ All other branches")
    print("-" * 80)

    print("\nCommit will proceed without plan files.")
    print("If you need these files on this branch, switch to dev or a feature branch.")
    print("\n" + "=" * 80)

    # Auto-unstage plan files
    if unstage_files(plan_files):
        print("\n✅ Commit completed successfully (without plan files)\n")
        return 0
    else:
        print("\n❌ ERROR: Failed to unstage plan files\n")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] if len(sys.argv) > 1 else None))
