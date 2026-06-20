#!/usr/bin/env python3
"""
Regression tests for H8: plugin sandbox bypass / not enforced on default path.

Three gaps were identified:

1. File/network/process restrictions were installed only in *threading* mode,
   but process isolation (the default _plugin_worker path) never patched
   open()/socket()/Popen. A plugin declaring no file capability could still
   read ~/.ssh/id_rsa under the default configuration.
2. The AST denylist missed the frame/traceback escape chain
   (e.__traceback__.tb_frame.f_back.f_globals -> real builtins -> eval).
3. Plugins were loadable from world/group-writable locations, so an attacker
   with write access to the plugins dir could drop or rewrite a plugin whose
   module top-level code runs at import (exec_module) time.

See SECURITY_REVIEW_FINDINGS.md (H8).
"""

import os
import queue
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
)
from openssl_encrypt.modules.plugin_system.plugin_ast_analyzer import analyze_plugin_code
from openssl_encrypt.modules.plugin_system.plugin_sandbox import (
    PluginSandbox,
    SandboxViolationError,
    _plugin_worker,
)

_IS_WINDOWS = os.name == "nt"
# os.geteuid() is POSIX-only; guard it so this module still imports on Windows.
_IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


# A module-level plugin so it is importable/picklable and runnable in-process.
class _OpenAttemptPlugin:
    """Minimal plugin stand-in that tries to read a disallowed file."""

    def __init__(self, target_path):
        self.plugin_id = "open_attempt"
        self._target = target_path
        self.executed = False

    def execute(self, context):
        self.executed = True
        with open(self._target, "r") as f:
            return PluginResult.success_result(f.read())


class _BenignPlugin:
    def __init__(self):
        self.plugin_id = "benign"
        self.executed = False

    def execute(self, context):
        self.executed = True
        return PluginResult.success_result("ok")


# ---------------------------------------------------------------------------
# Issue 2 - AST denylist must catch the frame/traceback escape chain
# ---------------------------------------------------------------------------


class TestAstFrameTracebackDenylist(unittest.TestCase):
    """The static analyzer must flag frame/traceback attribute traversal."""

    def _critical(self, code):
        is_safe, violations = analyze_plugin_code(code, "<test>", strict_mode=True)
        return is_safe, [v for v in violations if v.severity == "critical"]

    def test_traceback_frame_globals_chain_blocked(self):
        code = (
            "def f():\n"
            "    try:\n"
            "        raise ValueError()\n"
            "    except Exception as e:\n"
            "        g = e.__traceback__.tb_frame.f_back.f_globals\n"
            "        return g\n"
        )
        is_safe, critical = self._critical(code)
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_generator_frame_blocked(self):
        is_safe, critical = self._critical("x = (i for i in range(1)).gi_frame")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_coroutine_frame_blocked(self):
        is_safe, critical = self._critical("y = some_coro.cr_frame")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_f_locals_blocked(self):
        is_safe, critical = self._critical("z = sys._getframe().f_locals")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_getattr_frame_attr_blocked(self):
        is_safe, critical = self._critical("g = getattr(e, 'f_globals')")
        self.assertFalse(is_safe)
        self.assertTrue(critical)

    def test_legitimate_dunder_not_flagged(self):
        # __init__/__new__ and ordinary attributes must remain allowed
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
# Issue 1 - process-isolation worker must apply the runtime sandbox
# ---------------------------------------------------------------------------


class TestProcessWorkerAppliesSandbox(unittest.TestCase):
    """_plugin_worker (the default path) must restrict file access, not just
    the legacy threading path."""

    def _context(self, capabilities=frozenset()):
        return PluginSecurityContext("open_attempt", capabilities)

    def test_worker_denies_file_read_without_capability(self):
        """A plugin without READ_FILES must be blocked from reading an
        outside file when run through the worker (default process path)."""
        target = os.path.join(tempfile.gettempdir(), "h8_secret_probe.txt")
        with open(target, "w") as f:
            f.write("top secret")
        self.addCleanup(lambda: os.path.exists(target) and os.remove(target))

        plugin = _OpenAttemptPlugin(target)
        result_queue = queue.Queue()
        # Stub AST source validation: the plugin class lives in this test
        # module whose own source legitimately contains os.remove/shutil, so
        # _validate_plugin_source would reject it. Here we exercise the
        # runtime file restriction, not the static analyzer.
        import builtins

        original_open = builtins.open
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.plugin_sandbox._validate_plugin_source"
        ):
            try:
                _plugin_worker(plugin, self._context(), result_queue)
            finally:
                builtins.open = original_open

        status, data = result_queue.get_nowait()
        self.assertEqual(status, "error")
        self.assertIn("denied", str(data).lower())

    def test_worker_invokes_setup_restricted_environment(self):
        """Wiring guard: the worker must call _setup_restricted_environment
        (the full file/net/process sandbox), not only the import guard."""
        calls = []
        original = PluginSandbox._setup_restricted_environment

        def spy(self, context):
            calls.append(context)
            return original(self, context)

        plugin = _BenignPlugin()
        result_queue = queue.Queue()
        import builtins

        original_open = builtins.open
        PluginSandbox._setup_restricted_environment = spy
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.plugin_sandbox._validate_plugin_source"
        ):
            try:
                _plugin_worker(plugin, self._context(), result_queue)
            finally:
                PluginSandbox._setup_restricted_environment = original
                builtins.open = original_open

        self.assertEqual(len(calls), 1)
        self.assertTrue(plugin.executed)

    def test_restricted_open_blocks_outside_path(self):
        """Direct check of the restriction primitive used by the worker."""
        import shutil

        ctx = self._context()
        sandbox = PluginSandbox()
        sandbox.current_context = ctx
        sandbox.temp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(sandbox.temp_dir, ignore_errors=True))
        # An existing file outside the sandbox temp dir (cross-platform).
        outside_path = os.path.abspath(__file__)
        saved = sandbox._setup_restricted_environment(ctx)
        try:
            with self.assertRaises(SandboxViolationError):
                open(outside_path, "r")
        finally:
            sandbox._restore_original_environment(saved)
        # open() must work again after restoration
        with open(outside_path, "r") as f:
            self.assertIsNotNone(f.read())

    def test_worker_preserves_cwd(self):
        """The worker must not leak a changed working directory (it chdirs
        into a temp dir during execution); critical when called in-process."""
        cwd_before = os.getcwd()
        plugin = _BenignPlugin()
        result_queue = queue.Queue()
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.plugin_sandbox._validate_plugin_source"
        ):
            _plugin_worker(plugin, self._context(), result_queue)
        self.assertEqual(os.getcwd(), cwd_before)

    def test_worker_preserves_resource_limits(self):
        """The worker sets process-wide rlimits (RLIMIT_CPU=60s etc.); when
        called in-process these MUST be restored or the host process is later
        SIGXCPU-killed. Regression for the xdist worker crashes."""
        try:
            import resource
        except ImportError:
            self.skipTest("resource module not available")

        watched = [
            r for r in ("RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE") if hasattr(resource, r)
        ]
        before = {r: resource.getrlimit(getattr(resource, r)) for r in watched}

        plugin = _BenignPlugin()
        result_queue = queue.Queue()
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.plugin_sandbox._validate_plugin_source"
        ):
            _plugin_worker(plugin, self._context(), result_queue)

        after = {r: resource.getrlimit(getattr(resource, r)) for r in watched}
        self.assertEqual(before, after, "worker leaked a process resource limit")


# ---------------------------------------------------------------------------
# Issue 3 - refuse plugins from world/group-writable locations
# ---------------------------------------------------------------------------


@unittest.skipIf(_IS_WINDOWS, "POSIX permission semantics; see TestWindowsPluginLocationAcl")
class TestWritablePluginLocationRejected(unittest.TestCase):
    """A plugin file (or its directory) that is group/world-writable must be
    refused - that is the window an attacker uses to drop import-time code."""

    def setUp(self):
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
        from openssl_encrypt.modules.plugin_system.plugin_manager import PluginManager

        self.manager = PluginManager(
            config_manager=PluginConfigManager(), strict_security_mode=True
        )
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        os.chmod(self.temp_dir, 0o755)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_plugin(self, name="p.py"):
        path = os.path.join(self.temp_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# benign plugin\nVALUE = 1\n")
        os.chmod(path, 0o644)
        return path

    @unittest.skipIf(_IS_ROOT, "root bypasses file permission checks")
    def test_world_writable_plugin_file_rejected(self):
        path = self._write_plugin()
        os.chmod(path, 0o666)  # world-writable
        self.assertFalse(self.manager._validate_plugin_file(path))

    @unittest.skipIf(_IS_ROOT, "root bypasses file permission checks")
    def test_group_writable_plugin_file_rejected(self):
        path = self._write_plugin()
        os.chmod(path, 0o664)  # group-writable
        self.assertFalse(self.manager._validate_plugin_file(path))

    @unittest.skipIf(_IS_ROOT, "root bypasses file permission checks")
    def test_world_writable_plugin_dir_rejected(self):
        path = self._write_plugin()
        os.chmod(self.temp_dir, 0o777)  # world-writable directory
        self.assertFalse(self.manager._validate_plugin_file(path))

    def test_secure_plugin_file_accepted(self):
        path = self._write_plugin()
        os.chmod(self.temp_dir, 0o755)
        os.chmod(path, 0o644)
        self.assertTrue(self.manager._validate_plugin_file(path))


@unittest.skipUnless(_IS_WINDOWS, "Windows ACL semantics")
class TestWindowsPluginLocationAcl(unittest.TestCase):
    """On Windows the location check inspects the DACL instead of POSIX mode
    bits: a plugin is insecure only if a principal other than its owner (or
    SYSTEM/Administrators) has write access."""

    def setUp(self):
        import shutil

        from openssl_encrypt.modules.plugin_system.plugin_manager import PluginManager

        self.PluginManager = PluginManager
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.temp_dir, ignore_errors=True))
        self.path = os.path.join(self.temp_dir, "p.py")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("# benign plugin\nVALUE = 1\n")
        # Pin the file's DACL to owner-only so inherited ACEs don't influence
        # the result; tests then add broader ACEs as needed.
        self._set_dacl([(self._current_user_sid(), self._all_access())])

    @staticmethod
    def _current_user_sid():
        import win32api
        import win32security

        sid, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
        return sid

    @staticmethod
    def _all_access():
        import ntsecuritycon

        return ntsecuritycon.FILE_ALL_ACCESS

    def _set_dacl(self, entries):
        import win32security

        dacl = win32security.ACL()
        for sid, mask in entries:
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, sid)
        sd = win32security.GetFileSecurity(
            self.path, win32security.DACL_SECURITY_INFORMATION
        )
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            self.path, win32security.DACL_SECURITY_INFORMATION, sd
        )

    def _reason(self):
        # Check the file alone (the directory carries unrelated inherited ACEs).
        return self.PluginManager._windows_insecure_location_reason((self.path,))

    def test_owner_only_accepted(self):
        self.assertIsNone(self._reason())

    def test_everyone_writable_rejected(self):
        import ntsecuritycon
        import win32security

        everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
        self._set_dacl(
            [
                (self._current_user_sid(), self._all_access()),
                (everyone, ntsecuritycon.FILE_GENERIC_WRITE),
            ]
        )
        reason = self._reason()
        self.assertIsNotNone(reason)
        self.assertIn("S-1-1-0", reason)

    def test_authenticated_users_writable_rejected(self):
        import ntsecuritycon
        import win32security

        auth_users = win32security.CreateWellKnownSid(
            win32security.WinAuthenticatedUserSid
        )
        self._set_dacl(
            [
                (self._current_user_sid(), self._all_access()),
                (auth_users, ntsecuritycon.FILE_GENERIC_WRITE),
            ]
        )
        self.assertIsNotNone(self._reason())

    def test_administrators_write_allowed(self):
        import ntsecuritycon
        import win32security

        admins = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid
        )
        self._set_dacl(
            [
                (self._current_user_sid(), self._all_access()),
                (admins, ntsecuritycon.FILE_ALL_ACCESS),
            ]
        )
        self.assertIsNone(self._reason())


if __name__ == "__main__":
    unittest.main()
