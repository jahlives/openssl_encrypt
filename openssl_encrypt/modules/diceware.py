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
import warnings
from pathlib import Path
from typing import List, Optional, Union


# A wordlist smaller than this yields less than 10 bits of entropy per
# word, which is widely considered the minimum for passphrase use. The
# bundled EFF Large Wordlist (7776 words) provides ~12.92 bits/word.
MIN_WORDLIST_SIZE = 1024


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
    *,
    force_small: bool = False,
) -> List[str]:
    """
    Load a wordlist from disk, auto-detecting EFF vs plain text format.

    Args:
        path: Path to the wordlist file. If ``None``, loads the bundled
            EFF Large Wordlist.
        force_small: If True, allow wordlists smaller than
            :data:`MIN_WORDLIST_SIZE` (1024 words) — generation proceeds
            but a UserWarning is emitted. If False (default), a small
            wordlist raises :class:`WordlistValidationError`.

    Returns:
        Words in file order, with blank lines skipped and surrounding
        whitespace stripped. For EFF format, the leading dice-roll
        prefix is removed and only the word is returned.

    Raises:
        FileNotFoundError / OSError: if the path cannot be read.
        WordlistValidationError: on duplicates, whitespace-words, or a
            small list when ``force_small=False``.
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

    _validate_wordlist(words, force_small=force_small)
    return words


def _validate_wordlist(words: List[str], *, force_small: bool = False) -> None:
    """
    Reject wordlists with duplicates or whitespace-containing words.

    Silent dedup is dangerous: it changes effective entropy without the
    user noticing. Embedded whitespace breaks --dice-sep boundary
    semantics. Per Q10, both cases are hard errors.

    Small wordlists (< :data:`MIN_WORDLIST_SIZE`) are rejected unless
    ``force_small=True``; with the override they only emit a UserWarning.
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

    # Size threshold check (last so the more-specific errors above fire first).
    if len(words) < MIN_WORDLIST_SIZE:
        msg = (
            f"wordlist is small ({len(words)} words, < {MIN_WORDLIST_SIZE} "
            f"= 10 bits/word minimum). Passphrase entropy will be lower than "
            f"a standard wordlist provides."
        )
        if not force_small:
            raise WordlistValidationError(
                msg + " Pass force_small=True (or the --force-wordlist CLI "
                "flag) to allow this list anyway."
            )
        warnings.warn(msg, UserWarning, stacklevel=3)
