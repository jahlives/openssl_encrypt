#!/usr/bin/env python3
"""
Shared environment channel for credentials that must not reach the command line.

Every credential this tool accepts non-interactively faces the same problem:
``/proc/PID/cmdline`` is world-readable, so an argv value is visible to every
local process, while a ``getpass()`` prompt reads ``/dev/tty`` and cannot be
answered by a GUI or CI subprocess at all. The recovery-slot commands solved
this once (gitlab#144) with a read-once-and-delete environment variable; this
module is that mechanism generalized, so the next credential does not get a
fourth private copy of it (gitlab#154, gitlab#159).

Security properties, all load-bearing:

* **Read once, then deleted.** The variable is removed from ``os.environ``
  immediately, so it is not inherited by a child process — several call sites
  run ``subprocess.run()`` with no ``env=``.
* **Registered before deletion.** Between the read and the delete the value
  would match neither the live-environment redaction check nor the fingerprint
  registry, so a concurrent ``log_event`` from another thread could write it
  unredacted.
* **``None`` and ``""`` are different.** ``None`` means "not supplied";
  ``""`` means "supplied blank". Callers fail fast on the latter rather than
  falling through to a prompt a GUI subprocess could never answer. Do not
  collapse the two.
* **The environment never *selects* a credential path.** An explicit flag
  chooses which credential is used; a variable only supplies its value. This
  is why ``resolve_credential`` takes ``requested``: a planted variable must
  not be able to silently route a secret into a path the user did not ask for.

Known residual: ``unsetenv()`` does not scrub the exec-time copy in
``/proc/self/environ``, which is readable by the same uid. This converts a
world-readable ``cmdline`` leak into a same-uid residual rather than
eliminating it.
"""

import getpass
import os
from typing import Dict, Optional

from .security_logger import register_consumed_secret


class CredentialError(Exception):
    """A credential was supplied through an unusable channel or was blank."""


def consume_env(name: str) -> Optional[str]:
    """Read a secret-bearing environment variable and remove it.

    Args:
        name: Environment variable to read.

    Returns:
        The value — possibly the empty string when the variable is present but
        empty — or ``None`` only when the variable is absent.
    """
    if name not in os.environ:
        return None
    value = os.environ.get(name)
    # Register before deleting: see the module docstring.
    register_consumed_secret(name, value)
    try:
        del os.environ[name]
    except KeyError:  # pragma: no cover - racing removal, already gone
        pass
    return value


def consume_all(*names: str) -> Dict[str, Optional[str]]:
    """Consume several variables up front, before anything can raise.

    Consuming them all first means a later failure cannot leave one of them
    behind in the environment of a subsequently spawned process.

    Args:
        *names: Environment variables to read.

    Returns:
        Mapping of name to consumed value (``None`` when absent).
    """
    return {name: consume_env(name) for name in names}


def validated(value: str, source: str, reject_newline: bool = True) -> str:
    """Reject a blank credential without modifying it.

    Whitespace is *not* stripped: a passphrase supplied through one channel
    must open through another, so the value is validated rather than
    normalized. A blank credential is refused because it is almost always an
    unset variable expanding to nothing, and accepting it would wrap a key
    under a secret anyone can guess.

    A value containing a newline is refused rather than silently trimmed. The
    file-descriptor and prompt channels both stop at the first newline, so a
    trailing "\\n" here -- exactly what a GUI passing a text field's contents
    produces -- would derive a different key from the same passphrase typed at
    the prompt, with no error at any point. Silently stripping would create
    the mirror-image mismatch, so this fails loudly instead.

    That rule applies only to NEW channels. On a pre-existing channel the byte
    semantics are load-bearing: a file already encrypted with a newline-bearing
    credential must stay decryptable, so callers on those channels pass
    ``reject_newline=False``.

    Args:
        value: The credential as supplied.
        source: Human-readable channel name, for the error message.
        reject_newline: Whether to refuse embedded newlines. False for
            channels that predate this rule and may have existing files
            depending on the exact bytes.

    Returns:
        The value unchanged.

    Raises:
        CredentialError: If the value is blank, or contains a newline and
            ``reject_newline`` is set.
    """
    if not value or not value.strip():
        raise CredentialError(f"{source} is empty; refusing to use a blank credential")
    if reject_newline and ("\n" in value or "\r" in value):
        raise CredentialError(
            f"{source} contains a newline; other channels stop at the first "
            f"newline, so this would not match the same credential supplied "
            f"another way"
        )
    return value


def resolve_credential(
    requested: bool,
    env_name: str,
    prompt: str,
    explicit: Optional[str] = None,
    explicit_source: str = "the supplied credential",
) -> Optional[str]:
    """Resolve one credential from flag, environment, or prompt.

    The environment variable is consumed unconditionally when present, even if
    an explicit value supersedes it, so a superseded credential is not left
    behind for a child process to inherit.

    Args:
        requested: Whether the caller actually asked for this credential. When
            False the variable is still consumed but no value is returned, so
            a planted variable cannot select a path the user did not request.
        env_name: Environment variable carrying the credential.
        prompt: Prompt text used when no non-interactive source is available.
        explicit: A value supplied directly -- read from a file descriptor,
            or consumed from the environment earlier by a caller that had
            to consume it before this point. Takes precedence.
        explicit_source: Channel name for `explicit`, used in error messages.

    Returns:
        The credential, or ``None`` when it was not requested.

    Raises:
        CredentialError: If a supplied credential is blank.
    """
    env_value = consume_env(env_name)

    if not requested:
        return None
    if explicit is not None:
        return validated(explicit, explicit_source)
    if env_value is not None:
        return validated(env_value, f"${env_name}")
    # Validated like every other channel: pressing Enter at the prompt
    # would otherwise proceed with "" while the env channel hard-errors
    # on the same value. reject_newline=False -- getpass cannot return one.
    return validated(getpass.getpass(prompt), "interactive prompt",
                     reject_newline=False)
