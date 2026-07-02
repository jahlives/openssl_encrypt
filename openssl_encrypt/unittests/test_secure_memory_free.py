"""Regression tests for identity-based block tracking in SecureMemoryAllocator.free.

Security background (#64 / MEM-5): ``SecureBytes`` subclasses ``bytearray``, so
``in`` / ``list.remove`` compare by CONTENT. ``free()`` zeroed the container
*before* removing it from ``allocated_blocks``, so an all-zero container would
compare equal to any other all-zero tracked block -- and ``remove()`` would drop
the *first* equal block, which may be a different, still-live allocation. Result:
a live buffer silently falls out of tracking (never swept on cleanup / accounting
drift), while a freed one may remain tracked. ``allocate(zero=True)`` is the
default, so equal-content blocks are the common case.

The fix locates the block to free by object identity.
"""

import unittest

from openssl_encrypt.modules.secure_memory import SecureBytes, SecureMemoryAllocator


class TestFreeIdentityTracking(unittest.TestCase):
    def test_free_removes_the_exact_block_even_when_contents_are_equal(self):
        alloc = SecureMemoryAllocator()
        a = alloc.allocate(64, zero=True)  # 64 zero bytes
        b = alloc.allocate(64, zero=True)  # equal to `a` by value; `a` is first in the list
        self.assertEqual(bytes(a), bytes(b), "precondition: the two blocks are equal by value")

        alloc.free(b)  # must remove *b* by identity, not the first value-equal block (a)

        tracked = alloc.allocated_blocks
        self.assertTrue(
            any(block is a for block in tracked),
            "freeing b must NOT drop the still-live block a from tracking",
        )
        self.assertFalse(
            any(block is b for block in tracked),
            "b must actually be removed from tracking after free",
        )

    def test_free_of_equal_but_unallocated_block_is_rejected(self):
        alloc = SecureMemoryAllocator()
        a = alloc.allocate(64, zero=True)
        foreign = SecureBytes(64)  # equal by value, but never allocated by this allocator

        self.assertFalse(
            alloc.free(foreign),
            "a value-equal but unallocated block must not be accepted for free",
        )
        self.assertTrue(
            any(block is a for block in alloc.allocated_blocks),
            "freeing a foreign equal block must not remove the real allocation a",
        )

    def test_free_double_free_returns_false(self):
        alloc = SecureMemoryAllocator()
        a = alloc.allocate(32, zero=True)
        self.assertTrue(alloc.free(a))
        self.assertFalse(alloc.free(a), "double free must return False")


if __name__ == "__main__":
    unittest.main()
