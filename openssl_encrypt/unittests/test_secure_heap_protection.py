"""Regression tests for SecureHeap key-material protection (#60, #63).

* #60 (MEM-1): allocate_bytes stored the secret in a detached bytearray while the
  canary-guarded block buffer stayed empty, so canaries/check_integrity guarded a
  region that never held the key. The key must live in the canary-protected block.

* #63 (MEM-4): the block buffer got no mlock / madvise(MADV_DONTDUMP), despite the
  docstrings, so asymmetric/PQC/identity private keys were swappable and dumpable.
  The block memory must be locked when the platform supports it.
"""

import ctypes
import platform
import unittest

from openssl_encrypt.modules.crypto_secure_memory import CryptoKey, CryptoSecureBuffer
from openssl_encrypt.modules.secure_allocator import _global_secure_heap


def _env_can_mlock(size: int) -> bool:
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
    del c_buf
    return ok


class TestKeyMaterialInProtectedRegion(unittest.TestCase):
    def test_secret_lives_in_canary_protected_block(self):
        secret = b"THIS_IS_A_32_BYTE_SECRET_KEY_012"  # 32 bytes
        buf = CryptoSecureBuffer(data=secret)
        try:
            block = _global_secure_heap.blocks[buf.block_id]
            # #60: the secret must now physically reside inside the canary-guarded
            # block buffer (previously it did not).
            self.assertIn(secret, bytes(block.buffer))
            self.assertEqual(bytes(buf.buffer), secret)
            self.assertTrue(buf.check_integrity())
        finally:
            buf.clear()

    def test_canary_corruption_is_detected(self):
        buf = CryptoSecureBuffer(data=b"another-secret-value!!")
        try:
            block = _global_secure_heap.blocks[buf.block_id]
            self.assertTrue(buf.check_integrity())
            original = block.buffer[0]
            block.buffer[0] = original ^ 0xFF  # corrupt the header canary
            self.assertFalse(
                buf.check_integrity(),
                "corrupting a canary must be detected now that it guards real data",
            )
            block.buffer[0] = original  # restore so free() is clean
        finally:
            buf.clear()

    def test_crypto_key_roundtrip_and_zeroing(self):
        key = CryptoKey(key_data=b"0123456789abcdef0123456789abcdef")
        self.assertEqual(key.get_bytes(), b"0123456789abcdef0123456789abcdef")
        key.clear()
        self.assertIsNone(key.buffer)


class TestBlockMemoryLocking(unittest.TestCase):
    def test_block_is_locked_when_environment_supports_it(self):
        if not _env_can_mlock(4096):
            self.skipTest("environment cannot mlock (no privilege / RLIMIT_MEMLOCK)")
        buf = CryptoSecureBuffer(size=64)
        try:
            block = _global_secure_heap.blocks[buf.block_id]
            self.assertTrue(
                block.locked,
                "block memory must be mlock'd when the platform supports locking (#63)",
            )
        finally:
            buf.clear()


if __name__ == "__main__":
    unittest.main()
