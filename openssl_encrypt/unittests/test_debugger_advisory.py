"""Regression tests for GitLab #105 [MEM-13]: debugger detection is advisory-only.

The tracer/debugger checks in secure_allocator and secure_memory can only
warn — TracerPid is non-zero under *any* ptrace (strace, container runtimes,
profilers), and no protective action is possible or taken. These tests pin
the advisory-only contract: detection must never block allocation, and the
emitted warning must present itself as advisory rather than implying a
defensive countermeasure.
"""

import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.secure_allocator import SecureHeap
from openssl_encrypt.modules.secure_memory import SecureMemoryAllocator


class TestDebuggerDetectionAdvisoryOnly(unittest.TestCase):
    """Detection may warn, but must never change allocation behavior."""

    def test_secure_heap_allocation_not_blocked_when_traced(self) -> None:
        """SecureHeap.allocate must succeed even when a tracer is detected."""
        heap = SecureHeap()
        heap.quiet = False  # force the warning path
        try:
            with mock.patch.object(heap, "_detect_debugger", return_value=True):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    block_id, view = heap.allocate(64)

            self.assertIsNotNone(block_id)
            self.assertEqual(len(view), 64)
            self.assertIn(
                "advisory",
                stderr.getvalue().lower(),
                "tracer warning must be clearly marked advisory-only",
            )
            heap.free(block_id)
        finally:
            heap.cleanup()

    def test_secure_memory_allocation_not_blocked_when_traced(self) -> None:
        """SecureMemoryAllocator.allocate must succeed when the check reports a tracer."""
        allocator = SecureMemoryAllocator()
        with mock.patch.object(allocator, "_anti_debug_check", return_value=False):
            buf = allocator.allocate(64)
        self.assertEqual(len(buf), 64)

    def test_anti_debug_check_has_no_countermeasure_theater(self) -> None:
        """_anti_debug_check must not claim or perform 'memory scanning countermeasures'.

        The former implementation wrote random bytes into a throwaway
        bytearray as a 'countermeasure' against memory scanners — pure
        security theater that implied protection it cannot provide.
        """
        import inspect

        from openssl_encrypt.modules import secure_memory

        source = inspect.getsource(secure_memory.SecureMemoryAllocator._anti_debug_check)
        self.assertNotIn("countermeasure", source.lower())
        self.assertIn(
            "advisory",
            source.lower(),
            "_anti_debug_check must document itself as advisory-only",
        )


if __name__ == "__main__":
    unittest.main()
