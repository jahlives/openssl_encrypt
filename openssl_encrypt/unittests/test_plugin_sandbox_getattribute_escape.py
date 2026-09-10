#!/usr/bin/env python3
"""
Regression tests for the plugin sandbox escape reported as GHSA-mfpv-pq4w-727m
(gitlab#302).

Two independent gaps let a plugin declaring zero capabilities run arbitrary
commands:

1. AST analyzer blocklist gap - ``plugin_ast_analyzer.py``:
   ``DANGEROUS_DUNDER_ATTRIBUTES`` omitted ``__getattribute__``. Because
   ``visit_Attribute`` only flags names in that set, ``object.__getattribute__``
   passed as an ordinary attribute access. Bound and called with a plain string
   (``fetch(klass, "__mro__")``) it never touches the ``getattr()`` builtin the
   analyzer watches, giving the plugin full dunder traversal
   (``object -> __subclasses__() -> ... __init__.__globals__ -> os``).

2. Process-guard gap - ``plugin_sandbox.py`` ``_restrict_process_operations``:
   patched ``subprocess.Popen``, ``os.system``, ``os.popen`` and the eight
   ``spawn*`` names, but NOT ``os.posix_spawn``, ``os.execve``/``os.exec*`` or
   ``os.fork``/``os.forkpty``. The recovered ``os`` module reached
   ``posix_spawn`` directly.

These tests are written to be safe in the red (pre-fix) phase: the exec-family
behaviour checks use a guaranteed-nonexistent path, so an unpatched call raises
FileNotFoundError (no image replacement) rather than executing anything, and
fork/forkpty are checked by identity only and never actually called.
"""

import os
import unittest

from openssl_encrypt.modules.plugin_system import PluginSecurityContext
from openssl_encrypt.modules.plugin_system.plugin_ast_analyzer import analyze_plugin_code
from openssl_encrypt.modules.plugin_system.plugin_sandbox import (
    PluginSandbox,
    SandboxViolationError,
)

_IS_WINDOWS = os.name == "nt"
# A path that cannot exist, so a real exec*/posix_spawn call fails with
# FileNotFoundError instead of replacing/executing anything.
_NONEXISTENT = os.path.join(os.sep, "nonexistent-openssl-encrypt-escape-probe", "nope")


# ---------------------------------------------------------------------------
# Gap 1 - AST analyzer must flag __getattribute__ traversal
# ---------------------------------------------------------------------------


class TestAstGetattributeDenylist(unittest.TestCase):
    """The static analyzer must treat ``__getattribute__`` as a dangerous
    dunder, whether reached by attribute syntax or via ``getattr()``."""

    def _critical(self, code):
        is_safe, violations = analyze_plugin_code(code, "<test>", strict_mode=True)
        return is_safe, [v for v in violations if v.severity == "critical"]

    def test_object_getattribute_attribute_access_blocked(self):
        is_safe, critical = self._critical("fetch = object.__getattribute__")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_type_getattribute_attribute_access_blocked(self):
        is_safe, critical = self._critical("fetch = type.__getattribute__")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_getattribute_via_getattr_builtin_blocked(self):
        is_safe, critical = self._critical("fetch = getattr(object, '__getattribute__')")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_full_reporter_escape_chain_blocked(self):
        # The reporter's exact traversal, wrapped in a function body.
        code = (
            "def run():\n"
            "    fetch = object.__getattribute__\n"
            "    klass = fetch('', '__class__')\n"
            "    mro = fetch(klass, '__mro__')\n"
            "    root = mro[-1]\n"
            "    subclasses = fetch(root, '__subclasses__')()\n"
            "    return subclasses\n"
        )
        is_safe, critical = self._critical(code)
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_getattr_alias_chain_blocked(self):
        # Security review finding #1: aliasing the getattr builtin slid past the
        # literal-name check. f = getattr; f(o, "__mro__") must still be caught.
        code = (
            "def run():\n"
            "    f = getattr\n"
            "    klass = f('', '__class__')\n"
            "    mro = f(klass, '__mro__')\n"
            "    subs = f(mro[-1], '__subclasses__')()\n"
            "    return subs\n"
        )
        is_safe, critical = self._critical(code)
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_getattr_alias_dynamic_name_flagged(self):
        # An aliased getattr with a computed (non-constant) attribute name must
        # not pass either (the concatenation obfuscation route).
        code = "def run(o):\n    f = getattr\n    return f(o, '__mr' + 'o__')\n"
        is_safe, _ = self._critical(code)
        self.assertFalse(is_safe)

    def test_dunder_name_as_string_literal_blocked(self):
        # Security review findings #1/#2: naming an escape internal as a string
        # is flagged wherever it appears (getattr, attrgetter, reduce, ...).
        for name in ("__subclasses__", "__globals__", "__mro__", "__builtins__"):
            with self.subTest(name=name):
                is_safe, critical = self._critical(f"x = '{name}'\n")
                self.assertFalse(is_safe, f"{name} string not flagged")
                self.assertTrue(critical)

    def test_attrgetter_dotted_path_blocked(self):
        # operator.attrgetter accepts dotted paths; each segment is checked even
        # if operator itself were reachable.
        is_safe, _ = self._critical("p = '__class__.__mro__'\n")
        self.assertFalse(is_safe)

    def test_operator_and_inspect_imports_blocked(self):
        for mod in ("operator", "inspect"):
            with self.subTest(mod=mod):
                is_safe, critical = self._critical(f"import {mod}\n")
                self.assertFalse(is_safe, f"import {mod} not blocked")
                self.assertTrue(critical)

    def test_benign_string_with_dot_not_flagged(self):
        # A dotted string that is not an escape internal must remain allowed
        # (guards against the segment check over-matching).
        is_safe, critical = self._critical("m = 'my.module.name'\nk = 'value'\n")
        self.assertTrue(is_safe, f"unexpected critical violations: {critical}")

    def test_legitimate_dunder_method_definition_not_flagged(self):
        # Defining __getattribute__ (a FunctionDef, not an Attribute access)
        # and ordinary attributes must remain allowed.
        code = (
            "class P:\n"
            "    def __init__(self):\n"
            "        self.value = 1\n"
            "    def run(self):\n"
            "        return self.value\n"
        )
        is_safe, critical = self._critical(code)
        self.assertTrue(is_safe, f"unexpected critical violations: {critical}")


# ---------------------------------------------------------------------------
# Gap 2 - runtime process guard must block posix_spawn / exec* / fork
# ---------------------------------------------------------------------------


@unittest.skipIf(_IS_WINDOWS, "POSIX process primitives are not present on Windows")
class TestProcessGuardBlocksExecPrimitives(unittest.TestCase):
    """After the restricted environment is installed for a zero-capability
    plugin, the low-level process-spawning primitives must be blocked."""

    def setUp(self):
        self.sandbox = PluginSandbox()
        ctx = PluginSecurityContext("escape_probe", frozenset())
        # Record the genuine callables so tests can prove replacement.
        self._orig = {
            name: getattr(os, name)
            for name in ("posix_spawn", "execve", "execv", "fork", "forkpty")
            if hasattr(os, name)
        }
        self._saved_state = self.sandbox._setup_restricted_environment(ctx)
        self.addCleanup(self.sandbox._restore_original_environment, self._saved_state)

    def test_posix_spawn_blocked(self):
        self.assertTrue(hasattr(os, "posix_spawn"))
        with self.assertRaises(SandboxViolationError):
            os.posix_spawn(_NONEXISTENT, [_NONEXISTENT], os.environ)

    def test_execve_blocked(self):
        self.assertTrue(hasattr(os, "execve"))
        with self.assertRaises(SandboxViolationError):
            os.execve(_NONEXISTENT, [_NONEXISTENT], os.environ)

    def test_execv_blocked(self):
        self.assertTrue(hasattr(os, "execv"))
        with self.assertRaises(SandboxViolationError):
            os.execv(_NONEXISTENT, [_NONEXISTENT])

    def test_fork_replaced_by_guard(self):
        # fork() cannot be safely called in red phase, so assert by identity
        # that the guard replaced it rather than invoking it.
        if "fork" not in self._orig:
            self.skipTest("os.fork not available")
        self.assertIsNot(os.fork, self._orig["fork"])

    def test_forkpty_replaced_by_guard(self):
        if "forkpty" not in self._orig:
            self.skipTest("os.forkpty not available")
        self.assertIsNot(os.forkpty, self._orig["forkpty"])

    def test_guard_restored_after_context(self):
        # Sanity: restoration puts the genuine callables back so the host
        # process (and later tests) are unaffected.
        self.sandbox._restore_original_environment(self._saved_state)
        # Prevent addCleanup from double-restoring.
        self._saved_state = {}
        for name, original in self._orig.items():
            self.assertIs(getattr(os, name), original)


if __name__ == "__main__":
    unittest.main()
