#!/usr/bin/env python3
"""
Binding preference for the RandomX KDF (gitlab#285): prefer the
project-owned randomx_native, fall back to the PyPI/fork `randomx` binding,
then pyrx — with byte-identical KDF output on every path.

The preference is pinned three ways:
- modules/randomx.py's module-level selection (probed in fresh subprocesses
  so this test does not depend on / pollute the parent's import state);
- kdf_registry's RandomXKDF.derive(), which imports per call and must fall
  back cleanly when randomx_native is absent;
- output equality between the native and fallback paths for both the
  registry KDF and the legacy randomx_kdf chain.
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

try:
    import randomx_native
except ImportError:
    randomx_native = None

try:
    import randomx as reference_randomx
except ImportError:
    reference_randomx = None

# Runs in a fresh interpreter BEFORE importing the module under test: makes
# the PARENT-process `import randomx_native` fail so the in-process fallback
# branch is exercised. Note the subprocess PROBE still succeeds (children
# don't inherit sys.modules poisoning) — probe-level fallback is covered
# separately by the PYTHONPATH-shadowing tests below.
BLOCK_NATIVE_PRELUDE = """
import sys
sys.modules["randomx_native"] = None  # import raises ImportError
"""


def _run_python(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=180,
    )


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestModuleBindingSelection(unittest.TestCase):
    """modules/randomx.py must pick randomx_native first."""

    def test_native_preferred_when_available(self):
        proc = _run_python(
            "from openssl_encrypt.modules import randomx as m;"
            "print(m.RANDOMX_LIBRARY, m.RANDOMX_AVAILABLE)"
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.split(), ["randomx_native", "True"])

    @unittest.skipIf(reference_randomx is None, "fallback binding not installed")
    def test_fallback_to_reference_binding(self):
        """In-process fallback: parent import of randomx_native fails."""
        proc = _run_python(
            BLOCK_NATIVE_PRELUDE + "from openssl_encrypt.modules import randomx as m;"
            "print(m.RANDOMX_LIBRARY, m.RANDOMX_AVAILABLE)"
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.split(), ["randomx", "True"])

    @unittest.skipIf(reference_randomx is None, "fallback binding not installed")
    def test_randomx_kdf_output_identical_across_bindings(self):
        """The legacy sequential chain must not change under the switch."""
        probe = (
            "from openssl_encrypt.modules.randomx import randomx_kdf;"
            "print(randomx_kdf(b'pref-test-pw', b'pref-test-salt16', rounds=2).hex())"
        )
        native = _run_python(probe)
        fallback = _run_python(BLOCK_NATIVE_PRELUDE + probe)
        self.assertEqual(native.returncode, 0, msg=native.stderr)
        self.assertEqual(fallback.returncode, 0, msg=fallback.stderr)
        self.assertEqual(native.stdout.strip(), fallback.stdout.strip())
        self.assertEqual(len(native.stdout.strip()), 64)


@unittest.skipUnless(
    randomx_native is None and reference_randomx is not None,
    "covers hosts with ONLY the PyPI binding installed",
)
class TestPyPiOnlyHost(unittest.TestCase):
    """On a host without randomx_native, the cascade must land on the PyPI
    binding — so CI without the Rust build still asserts the fallback."""

    def test_module_selects_reference_binding(self):
        proc = _run_python(
            "from openssl_encrypt.modules import randomx as m;"
            "print(m.RANDOMX_LIBRARY, m.RANDOMX_AVAILABLE)"
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.split(), ["randomx", "True"])


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestRegistryKdfBindingSelection(unittest.TestCase):
    """kdf_registry's RandomXKDF must prefer native and fall back per call."""

    def _kdf(self):
        from openssl_encrypt.modules.registry.kdf_registry import RandomX as RandomXKDF

        return RandomXKDF()

    def test_derive_works_with_native(self):
        derived = self._kdf().derive(b"pref-test-pw", b"pref-test-salt16")
        self.assertEqual(len(bytes(derived)), 32)

    @unittest.skipIf(reference_randomx is None, "fallback binding not installed")
    def test_derive_identical_when_native_absent(self):
        kdf = self._kdf()
        with_native = bytes(kdf.derive(b"pref-test-pw", b"pref-test-salt16"))
        with mock.patch.dict(sys.modules, {"randomx_native": None}):
            without_native = bytes(kdf.derive(b"pref-test-pw", b"pref-test-salt16"))
        self.assertEqual(with_native, without_native)

    def test_derive_prefers_native_binding(self):
        """The preference ORDER is pinned, not just output equality (which
        holds by construction): a spy standing in for randomx_native must be
        the binding derive() actually uses."""
        import types

        calls = []

        class _SpyVM:
            def calculate_hash(self, data):
                calls.append(len(data))
                return b"\x5a" * 32

        spy = types.ModuleType("randomx_native")
        spy.RandomX = lambda key: _SpyVM()
        with mock.patch.dict(sys.modules, {"randomx_native": spy}):
            derived = bytes(self._kdf().derive(b"pref-test-pw", b"pref-test-salt16"))
        self.assertTrue(calls, "derive() did not use the preferred native binding")
        self.assertEqual(derived, b"\x5a" * 32)

    @unittest.skipIf(reference_randomx is None, "fallback binding not installed")
    def test_is_available_survives_fatally_crashing_native(self):
        """A randomx_native that KILLS its probe child (the SIGILL scenario
        these subprocess probes exist for) must not mask a working PyPI
        binding: candidates are probed in separate children."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as shadow_dir:
            (Path(shadow_dir) / "randomx_native.py").write_text(
                "import os, signal\nos.kill(os.getpid(), signal.SIGILL)\n"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = shadow_dir + os.pathsep + env.get("PYTHONPATH", "")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from openssl_encrypt.modules.registry.kdf_registry import RandomX as R\n"
                    "R._available = None\n"
                    "print(R.is_available())\n",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.strip(), "True")

    def test_is_available_true_with_native_only(self):
        """The availability probe must accept EITHER binding: a host with
        only randomx_native installed is fully RandomX-capable.

        The probe runs in its own subprocess, so the PyPI binding is hidden
        from it for real: a shadowing `randomx` module that raises
        ImportError is prepended to PYTHONPATH, which the probe environment
        inherits."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as shadow_dir:
            (Path(shadow_dir) / "randomx.py").write_text(
                "raise ImportError('PyPI randomx binding hidden for test')\n"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = shadow_dir + os.pathsep + env.get("PYTHONPATH", "")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from openssl_encrypt.modules.registry.kdf_registry import RandomX as RandomXKDF\n"
                    "RandomXKDF._available = None\n"
                    "print(RandomXKDF.is_available())\n",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.strip(), "True")


if __name__ == "__main__":
    unittest.main()
