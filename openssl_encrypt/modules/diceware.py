"""
Diceware passphrase generation.

This module implements the loader, validator, and generator for the
``--dice`` mode of the ``generate-password`` action. It uses the
bundled EFF Large Wordlist (7,776 words, CC BY 3.0 US) by default and
accepts user-supplied wordlists in either EFF format
(``<5-digit-dice><TAB><word>``) or plain text (one word per line).

Randomness is sourced exclusively from :class:`secrets.SystemRandom`,
which delegates to the operating system's cryptographically secure RNG.
The module does NOT expose any seedable / deterministic interface — a
deterministic diceware passphrase would defeat its security purpose.
"""

from __future__ import annotations

import importlib.resources
import re
from pathlib import Path
from typing import List, Optional, Union


_DEFAULT_WORDLIST_RESOURCE = "data/eff_large_wordlist.txt"

# A line is in EFF format iff it starts with digits followed by whitespace,
# e.g. "11111\tabacus". Anything else is treated as plain text.
_EFF_LINE_RE = re.compile(r"^\d+\s+\S+")


class WordlistValidationError(ValueError):
    """Raised when a wordlist fails strict validation (dups, whitespace, etc.)."""


def _default_wordlist_path() -> Path:
    """Return the filesystem path to the bundled EFF Large Wordlist."""
    return Path(
        str(
            importlib.resources.files("openssl_encrypt").joinpath(
                _DEFAULT_WORDLIST_RESOURCE
            )
        )
    )


def load_wordlist(
    path: Optional[Union[str, Path]] = None,
) -> List[str]:
    """
    Load a wordlist from disk, auto-detecting EFF vs plain text format.

    Args:
        path: Path to the wordlist file. If ``None``, loads the bundled
            EFF Large Wordlist.

    Returns:
        Words in file order, with blank lines skipped and surrounding
        whitespace stripped. For EFF format, the leading dice-roll
        prefix is removed and only the word is returned.

    Raises:
        FileNotFoundError / OSError: if the path cannot be read.
    """
    if path is None:
        path = _default_wordlist_path()
    elif isinstance(path, str):
        path = Path(path)

    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    # Detect format from the first non-blank line.
    is_eff_format = False
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _EFF_LINE_RE.match(stripped):
            is_eff_format = True
        break

    words: List[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if is_eff_format:
            # Split on whitespace (handles both TAB and spaces just in case);
            # the EFF convention is TAB but we don't enforce that.
            parts = stripped.split(None, 1)
            if len(parts) < 2:
                # A digit-only line with no word — skip it silently.
                continue
            words.append(parts[1].strip())
        else:
            words.append(stripped)

    _validate_wordlist(words)
    return words


def _validate_wordlist(words: List[str]) -> None:
    """
    Reject wordlists with duplicates or whitespace-containing words.

    Silent dedup is dangerous: it changes effective entropy without the
    user noticing. Embedded whitespace breaks --dice-sep boundary
    semantics. Per Q10, both cases are hard errors.
    """
    # Whitespace-in-words: every character of every word must be non-space.
    for w in words:
        if any(c.isspace() for c in w):
            raise WordlistValidationError(
                f"wordlist contains a word with embedded whitespace: {w!r}. "
                f"Words must not contain spaces or tabs because that would "
                f"break --dice-sep boundary semantics."
            )

    # Duplicates: a single pass over words catches the first repeat.
    seen = set()
    for w in words:
        if w in seen:
            raise WordlistValidationError(
                f"wordlist contains duplicate word: {w!r}. "
                f"Silent deduplication would mislead about effective entropy."
            )
        seen.add(w)
