#!/usr/bin/env python3
"""RandomX binding selection must not be fooled by namespace packages (gitlab#299).

In a source checkout without openssl-encrypt-randomx installed, ``import
randomx_native`` SUCCEEDS as an empty PEP-420 namespace package resolving to
the repo's ``randomx_native/`` Rust directory. The availability probes only
tested import success — and their subprocess env propagates the parent's
sys.path (including the repo root) into PYTHONPATH, so the probe child saw
the same empty package and reported SUCCESS. First use then crashed with
``module 'randomx_native' has no attribute 'RandomX'``.

Probes and selections must validate the binding's usable surface (the
``RandomX`` class), never bare import success.
"""

import hashlib
import sys
import types
import unittest
from unittest import mock

from openssl_encrypt.modules import randomx as randomx_module


class _FakeVM:
    """Stand-in RandomX VM: deterministic, instant."""

    def __init__(self, seed, full_mem=False):
        self._seed = bytes(seed)

    def calculate_hash(self, data):
        return hashlib.sha256(self._seed + bytes(data)).digest()


def _fake_binding(name):
    """A module exposing the usable RandomX surface."""
    mod = types.ModuleType(name)
    mod.RandomX = _FakeVM
    return mod


class TestProbesValidateUsableSurface(unittest.TestCase):
    """The subprocess probes must assert the RandomX class, not just import."""

    def _probe_code(self, probe):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["code"] = cmd[-1]
            return types.SimpleNamespace(returncode=0, stdout="SUCCESS")

        with mock.patch("subprocess.run", side_effect=fake_run):
            probe()
        return captured.get("code", "")

    def test_native_probe_asserts_randomx_class(self):
        """A namespace-package import must fail the native probe's code."""
        code = self._probe_code(randomx_module._test_native_import)
        self.assertIn("randomx_native.RandomX", code)

    def test_pypi_probe_asserts_randomx_class(self):
        """The PyPI binding probe pins the same usable surface."""
        code = self._probe_code(randomx_module._test_randomx_import)
        self.assertIn("randomx.RandomX", code)


class TestSelectionRejectsNamespacePackage(unittest.TestCase):
    """An attribute-less module must never be accepted as a binding."""

    def test_binding_usable_helper(self):
        """The usability check demands the RandomX class."""
        self.assertFalse(randomx_module._binding_usable(types.ModuleType("randomx_native")))
        self.assertTrue(randomx_module._binding_usable(_fake_binding("randomx_native")))


class TestRegistryFallsBackOnShadowedNative(unittest.TestCase):
    """The registry KDF falls through to the PyPI binding, never AttributeError."""

    def _derive(self):
        from openssl_encrypt.modules.registry.kdf_registry import RandomX

        kdf = RandomX()
        params = kdf.default_params()
        with mock.patch.object(RandomX, "check_available", lambda self=None: None):
            return bytes(kdf.derive(b"password-299", b"0123456789abcdef", params))

    def test_shadowed_native_falls_back_to_pypi_binding(self):
        """Empty randomx_native + working randomx => derives via the fallback."""
        shadow = types.ModuleType("randomx_native")
        fallback = _fake_binding("randomx")
        with mock.patch.dict(sys.modules, {"randomx_native": shadow, "randomx": fallback}):
            derived = self._derive()
        self.assertEqual(len(derived), 32)

    def test_both_bindings_unusable_raises_registry_error(self):
        """Empty modules for both bindings => the documented registry error."""
        from openssl_encrypt.modules.registry.kdf_registry import AlgorithmNotAvailableError

        with mock.patch.dict(
            sys.modules,
            {
                "randomx_native": types.ModuleType("randomx_native"),
                "randomx": types.ModuleType("randomx"),
            },
        ):
            with self.assertRaises(AlgorithmNotAvailableError):
                self._derive()
