"""Unit tests for PKCS11Library (verification-table items 1 and 2).

Item 1: the PKCS#11 library file exists (os.path.isfile before loading).
Item 2: the PKCS#11 library is loadable (load failures raise a clear error).

All PKCS#11 interaction is mocked; no hardware or real .so is loaded.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.piv_backend import (
    PIVConfigurationError,
    PIVDependencyError,
    PIVLibraryError,
    PKCS11Library,
)
from openssl_encrypt.unittests import _piv_mocks


class TestPKCS11LibraryConfig(unittest.TestCase):
    def test_empty_path_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PKCS11Library("")

    def test_none_path_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PKCS11Library(None)

    def test_non_string_path_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PKCS11Library(12345)


class TestPKCS11LibraryFileCheck(unittest.TestCase):
    """Item 1: file existence is verified before any load attempt."""

    def setUp(self):
        _piv_mocks.reset()

    def test_nonexistent_path_raises_library_error(self):
        lib = PKCS11Library("/no/such/path/opensc-pkcs11.so")
        with self.assertRaises(PIVLibraryError):
            lib.load()

    def test_nonexistent_path_error_names_the_path(self):
        path = "/no/such/path/ykcs11.so"
        lib = PKCS11Library(path)
        with self.assertRaises(PIVLibraryError) as ctx:
            lib.load()
        self.assertIn(path, str(ctx.exception))

    def test_directory_is_not_a_valid_library(self):
        with tempfile.TemporaryDirectory() as d:
            lib = PKCS11Library(d)
            with self.assertRaises(PIVLibraryError):
                lib.load()


class TestPKCS11LibraryLoad(unittest.TestCase):
    """Item 2: loadability is verified; failures are translated to PIVLibraryError."""

    def setUp(self):
        _piv_mocks.reset()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
        self._tmp.write(b"\x7fELF fake module")
        self._tmp.close()
        self.path = self._tmp.name

    def tearDown(self):
        _piv_mocks.reset()
        os.unlink(self.path)

    def test_successful_load_returns_lib_object(self):
        fake_lib = _piv_mocks.make_lib()
        _piv_mocks.set_library(fake_lib)
        lib = PKCS11Library(self.path)
        self.assertIs(lib.load(), fake_lib)

    def test_load_caches_lib_object(self):
        fake_lib = _piv_mocks.make_lib()
        _piv_mocks.set_library(fake_lib)
        lib = PKCS11Library(self.path)
        first = lib.load()
        self.assertIs(lib.load(), first)

    def test_oserror_on_load_becomes_library_error(self):
        _piv_mocks.set_library_error(OSError("cannot open shared object file"))
        lib = PKCS11Library(self.path)
        with self.assertRaises(PIVLibraryError):
            lib.load()

    def test_pkcs11_error_on_load_becomes_library_error(self):
        from pkcs11.exceptions import PKCS11Error

        _piv_mocks.set_library_error(PKCS11Error("module init failed"))
        lib = PKCS11Library(self.path)
        with self.assertRaises(PIVLibraryError):
            lib.load()

    def test_load_error_message_is_actionable(self):
        _piv_mocks.set_library_error(OSError("bad ELF"))
        lib = PKCS11Library(self.path)
        with self.assertRaises(PIVLibraryError) as ctx:
            lib.load()
        self.assertIn(self.path, str(ctx.exception))

    def test_missing_python_pkcs11_raises_dependency_error(self):
        # Simulate python-pkcs11 not being importable.
        with mock.patch.dict(sys.modules, {"pkcs11": None}):
            lib = PKCS11Library(self.path)
            with self.assertRaises(PIVDependencyError):
                lib.load()


if __name__ == "__main__":
    unittest.main()
