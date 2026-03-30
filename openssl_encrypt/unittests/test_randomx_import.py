"""Tests for RandomX subprocess import test functions.

Verifies that the subprocess-based import tests correctly propagate
PYTHONPATH and VIRTUAL_ENV so that packages are discoverable in
sandboxed environments like Flatpak and virtualenvs.
"""

import os
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestRandomXImportSubprocess(unittest.TestCase):
    """Test that RandomX subprocess import tests pass PYTHONPATH."""

    def test_test_randomx_import_passes_pythonpath(self):
        """Verify _test_randomx_import passes PYTHONPATH with sys.path to subprocess."""
        from openssl_encrypt.modules.randomx import _test_randomx_import

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="SUCCESS\n")
            _test_randomx_import()

            call_kwargs = mock_run.call_args
            self.assertIn("env", call_kwargs.kwargs)
            env = call_kwargs.kwargs["env"]
            self.assertIn("PYTHONPATH", env)
            # All non-empty sys.path entries should be in PYTHONPATH
            for p in sys.path:
                if p:
                    self.assertIn(p, env["PYTHONPATH"])

    def test_test_pyrx_import_passes_pythonpath(self):
        """Verify _test_pyrx_import passes PYTHONPATH with sys.path to subprocess."""
        from openssl_encrypt.modules.randomx import _test_pyrx_import

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="SUCCESS\n")
            _test_pyrx_import()

            call_kwargs = mock_run.call_args
            self.assertIn("env", call_kwargs.kwargs)
            env = call_kwargs.kwargs["env"]
            self.assertIn("PYTHONPATH", env)
            for p in sys.path:
                if p:
                    self.assertIn(p, env["PYTHONPATH"])

    def test_subprocess_inherits_parent_environment(self):
        """Verify subprocess gets parent env vars plus PYTHONPATH."""
        from openssl_encrypt.modules.randomx import _test_randomx_import

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="SUCCESS\n")
            with patch.dict(os.environ, {"FLATPAK_ID": "com.test.App"}):
                _test_randomx_import()

            env = mock_run.call_args.kwargs["env"]
            # Parent env vars should be inherited
            self.assertEqual(env.get("FLATPAK_ID"), "com.test.App")

    def test_kdf_registry_randomx_passes_pythonpath(self):
        """Verify KDF registry RandomX.is_available passes PYTHONPATH."""
        from openssl_encrypt.modules.registry.kdf_registry import RandomX

        # Reset cached availability
        RandomX._available = None

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            RandomX.is_available()

            call_kwargs = mock_run.call_args
            self.assertIn("env", call_kwargs.kwargs)
            env = call_kwargs.kwargs["env"]
            self.assertIn("PYTHONPATH", env)

        # Reset so other tests aren't affected
        RandomX._available = None


class TestGetPythonExecutable(unittest.TestCase):
    """Test _get_python_executable fallback logic."""

    def test_returns_sys_executable_when_valid(self):
        """When sys.executable is a valid file, use it."""
        from openssl_encrypt.modules.randomx import _get_python_executable

        exe = _get_python_executable()
        # In our test environment sys.executable is valid
        self.assertEqual(exe, sys.executable)

    def test_falls_back_to_python3_when_empty(self):
        """When sys.executable is empty (e.g. Flatpak), fall back to python3."""
        from openssl_encrypt.modules.randomx import _get_python_executable

        with patch.object(sys, "executable", ""):
            exe = _get_python_executable()
            self.assertEqual(exe, "python3")

    def test_falls_back_to_python3_when_missing(self):
        """When sys.executable points to non-existent file, fall back to python3."""
        from openssl_encrypt.modules.randomx import _get_python_executable

        with patch.object(sys, "executable", "/nonexistent/python3.99"):
            exe = _get_python_executable()
            self.assertEqual(exe, "python3")


class TestGetSubprocessEnv(unittest.TestCase):
    """Test _get_subprocess_env environment construction."""

    def test_propagates_virtual_env_when_in_venv(self):
        """When running in a venv, VIRTUAL_ENV should be set in subprocess env."""
        from openssl_encrypt.modules.randomx import _get_subprocess_env

        # Simulate being inside a virtualenv (prefix != base_prefix)
        with patch.object(sys, "prefix", "/app/venv"), patch.object(sys, "base_prefix", "/usr"):
            env = _get_subprocess_env()
            self.assertEqual(env["VIRTUAL_ENV"], "/app/venv")

    def test_no_virtual_env_when_not_in_venv(self):
        """When NOT in a venv, VIRTUAL_ENV should not be injected."""
        from openssl_encrypt.modules.randomx import _get_subprocess_env

        # Simulate system Python (prefix == base_prefix)
        with patch.object(sys, "prefix", "/usr"), patch.object(
            sys, "base_prefix", "/usr"
        ), patch.dict(os.environ, {}, clear=True):
            env = _get_subprocess_env()
            self.assertNotIn("VIRTUAL_ENV", env)

    def test_pythonpath_contains_all_sys_path_entries(self):
        """PYTHONPATH must include every non-empty sys.path entry."""
        from openssl_encrypt.modules.randomx import _get_subprocess_env

        env = _get_subprocess_env()
        pythonpath_entries = env["PYTHONPATH"].split(os.pathsep)
        for p in sys.path:
            if p:
                self.assertIn(p, pythonpath_entries)


if __name__ == "__main__":
    unittest.main()
