"""Regression tests for memory-locking correctness in SecureMemoryAllocator.

Security background:

* #61 (MEM-2): ``mlock``/``munlock``/``VirtualLock``/``VirtualUnlock`` were called
  through ctypes without setting ``.argtypes``. ctypes then marshals the Python
  integer address as a C ``int`` (32-bit), truncating the real 64-bit buffer
  address, so ``mlock`` fails with EINVAL and memory locking silently never works
  on 64-bit platforms.

* #62 (MEM-3): a locking failure was only reported when ``debug_mode`` was set
  (and ``quiet = not debug_mode``), so in normal operation a failure to lock
  sensitive memory was completely silent.

These tests verify that (a) when the environment demonstrably supports locking,
the allocator actually locks, and (b) a locking failure is surfaced regardless
of debug mode.
"""

import ctypes
import io
import platform
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.secure_memory import SecureBytes, SecureMemoryAllocator


def _reference_env_can_mlock(size: int) -> bool:
    """Independently confirm, with CORRECT argtypes, that this env can mlock `size`.

    Used to skip the locking assertion on platforms/containers where locking is
    genuinely unavailable (no privilege / low RLIMIT_MEMLOCK) -- there the bug
    cannot be distinguished from a legitimate failure.
    """
    if platform.system().lower() != "linux":
        return False
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return False
    if not hasattr(libc, "mlock"):
        return False
    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.mlock.restype = ctypes.c_int
    libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munlock.restype = ctypes.c_int
    buf = bytearray(size)
    c_buf = ctypes.c_char.from_buffer(buf)
    addr = ctypes.addressof(c_buf)
    ok = libc.mlock(addr, size) == 0
    if ok:
        libc.munlock(addr, size)
    del c_buf  # release the exported buffer view
    return ok


class TestMlockAddressHandling(unittest.TestCase):
    def test_try_lock_memory_succeeds_when_environment_supports_it(self):
        size = 4096
        if not _reference_env_can_mlock(size):
            self.skipTest(
                "environment cannot mlock (no privilege / RLIMIT_MEMLOCK); "
                "cannot distinguish the address-truncation bug from a genuine failure"
            )
        alloc = SecureMemoryAllocator()
        buf = SecureBytes(size)
        # With the argtypes bug the 64-bit address is truncated to a C int and
        # mlock fails with EINVAL even though the environment supports locking.
        self.assertTrue(
            alloc._try_lock_memory(buf),
            "mlock must succeed for a small buffer when the environment supports locking",
        )
        alloc._try_unlock_memory(buf)


class TestLockFailureSurfaced(unittest.TestCase):
    def test_lock_failure_is_warned_without_debug_mode(self):
        alloc = SecureMemoryAllocator()
        alloc.debug_mode = False  # non-debug: previously silenced the warning
        err = io.StringIO()
        with mock.patch.object(alloc, "_try_lock_memory", return_value=False):
            with redirect_stderr(err):
                alloc.allocate(64)
        out = err.getvalue().lower()
        self.assertIn("lock", out)
        self.assertTrue(
            any(tok in out for tok in ("swap", "memlock", "warning", "security")),
            f"expected a lock-failure warning on stderr, got: {out!r}",
        )

    def test_lock_status_is_exposed_to_caller(self):
        alloc = SecureMemoryAllocator()
        alloc.debug_mode = False
        with mock.patch.object(alloc, "_try_lock_memory", return_value=False):
            with redirect_stderr(io.StringIO()):
                alloc.allocate(64)
        self.assertFalse(alloc.last_lock_succeeded)
        self.assertGreaterEqual(alloc.lock_failure_count, 1)


if __name__ == "__main__":
    unittest.main()
