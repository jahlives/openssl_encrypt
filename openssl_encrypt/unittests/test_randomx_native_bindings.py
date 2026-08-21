#!/usr/bin/env python3
"""
TDD contract for the project-owned RandomX bindings (gitlab#285).

randomx_native wraps the official tevador/RandomX C library, pinned at the
v1.1.10 tag (commit f9ae3f235183c452962edd2a15384bdc67f7a11e) — the exact
version the abandoned PyPI binding vendors — and must produce byte-identical
KDF output. Three layers pin that contract:

1. Official RandomX v1.1.10 test vectors (from the vendored
   ``RandomX_src/tests/tests.cpp``), so correctness does not depend on any
   other binding being installed.
2. Equivalence against the reference binding (the PyPI/fork ``randomx``
   module) when it is importable, including the exact chained-hash pattern
   the openssl_encrypt KDF uses.
3. API-contract and security-behavior tests: minimal surface, input
   validation, thread safety, and the SECURE (W^X JIT) default this binding
   deliberately adds.
"""

import hashlib
import threading
import unittest

try:
    import randomx_native
except ImportError:
    randomx_native = None

try:
    import randomx as reference_randomx
except ImportError:
    reference_randomx = None

# Official test vectors from RandomX v1.1.10 src/tests/tests.cpp
# (light mode; output is flag- and mode-independent by design).
OFFICIAL_VECTORS = [
    (
        b"test key 000",
        b"This is a test",
        "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
    ),
    (
        b"test key 000",
        b"Lorem ipsum dolor sit amet",
        "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
    ),
    (
        b"test key 000",
        b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
        "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
    ),
    (
        b"test key 001",
        b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
        "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
    ),
]


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestOfficialVectors(unittest.TestCase):
    """The binding must reproduce the official RandomX v1.1.10 vectors."""

    def test_official_v1_1_10_vectors(self):
        for key, message, expected_hex in OFFICIAL_VECTORS:
            with self.subTest(key=key, message=message):
                vm = randomx_native.RandomX(key)
                self.assertEqual(bytes(vm.calculate_hash(message)).hex(), expected_hex)

    def test_vector_via_reused_vm(self):
        """One VM, several messages — same results as fresh VMs."""
        vm = randomx_native.RandomX(b"test key 000")
        for key, message, expected_hex in OFFICIAL_VECTORS:
            if key != b"test key 000":
                continue
            self.assertEqual(bytes(vm.calculate_hash(message)).hex(), expected_hex)


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestApiContract(unittest.TestCase):
    """Public surface: RandomX(key, full_mem=...) -> VM.calculate_hash()."""

    def test_hash_is_32_bytes_of_bytes(self):
        digest = randomx_native.RandomX(b"k" * 32).calculate_hash(b"input")
        self.assertIsInstance(digest, bytes)
        self.assertEqual(len(digest), randomx_native.HASH_SIZE)
        self.assertEqual(randomx_native.HASH_SIZE, 32)

    def test_deterministic(self):
        a = randomx_native.RandomX(b"k" * 32).calculate_hash(b"payload")
        b = randomx_native.RandomX(b"k" * 32).calculate_hash(b"payload")
        self.assertEqual(a, b)

    def test_key_sensitivity(self):
        a = randomx_native.RandomX(b"a" * 32).calculate_hash(b"payload")
        b = randomx_native.RandomX(b"b" * 32).calculate_hash(b"payload")
        self.assertNotEqual(a, b)

    def test_input_sensitivity(self):
        vm = randomx_native.RandomX(b"k" * 32)
        self.assertNotEqual(vm.calculate_hash(b"x"), vm.calculate_hash(b"y"))

    def test_accepts_bytearray_and_memoryview(self):
        expected = randomx_native.RandomX(b"k" * 32).calculate_hash(b"data")
        self.assertEqual(
            randomx_native.RandomX(bytearray(b"k" * 32)).calculate_hash(bytearray(b"data")),
            expected,
        )
        self.assertEqual(
            randomx_native.RandomX(memoryview(b"k" * 32)).calculate_hash(memoryview(b"data")),
            expected,
        )

    def test_empty_input_allowed(self):
        """Zero-length messages hash fine (parity with the C API)."""
        digest = randomx_native.RandomX(b"k" * 32).calculate_hash(b"")
        self.assertEqual(len(digest), 32)

    def test_empty_key_refused(self):
        """Deliberate hardening divergence: an empty KDF key is always a bug."""
        with self.assertRaises(ValueError):
            randomx_native.RandomX(b"")

    def test_wrong_types_refused(self):
        with self.assertRaises(TypeError):
            randomx_native.RandomX("not bytes")
        vm = randomx_native.RandomX(b"k" * 32)
        with self.assertRaises(TypeError):
            vm.calculate_hash("not bytes")
        with self.assertRaises(TypeError):
            vm.calculate_hash(None)

    def test_vm_is_thread_safe(self):
        """Concurrent calculate_hash on one VM must stay correct (the binding
        serializes access internally; the C VM is not thread-safe)."""
        vm = randomx_native.RandomX(b"k" * 32)
        expected = {
            i: randomx_native.RandomX(b"k" * 32).calculate_hash(b"m%d" % i) for i in range(4)
        }
        results = {}
        errors = []

        def worker(i):
            try:
                for _ in range(5):
                    results[i] = vm.calculate_hash(b"m%d" % i)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, expected)


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestSecurityBehavior(unittest.TestCase):
    """Hardening this binding adds on top of the reference API."""

    def test_secure_wx_flag_defaults_on(self):
        """SECURE (W^X JIT pages) is requested by default; opting out works."""
        vm_default = randomx_native.RandomX(b"k" * 32)
        self.assertTrue(vm_default.flags & randomx_native.FLAG_SECURE)
        vm_off = randomx_native.RandomX(b"k" * 32, secure=False)
        self.assertFalse(vm_off.flags & randomx_native.FLAG_SECURE)

    def test_secure_flag_does_not_change_output(self):
        self.assertEqual(
            randomx_native.RandomX(b"k" * 32, secure=True).calculate_hash(b"m"),
            randomx_native.RandomX(b"k" * 32, secure=False).calculate_hash(b"m"),
        )

    def test_upstream_pin_is_exposed(self):
        """Provenance must be introspectable: the vendored C library commit."""
        self.assertEqual(
            randomx_native.RANDOMX_UPSTREAM_COMMIT,
            "f9ae3f235183c452962edd2a15384bdc67f7a11e",
        )
        self.assertTrue(randomx_native.__version__)


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
@unittest.skipIf(reference_randomx is None, "reference randomx binding not installed")
class TestEquivalenceWithReferenceBinding(unittest.TestCase):
    """Byte-identical output against the PyPI/fork binding (gitlab#285 hard
    requirement: existing encrypted files must keep decrypting)."""

    def test_assorted_keys_and_inputs(self):
        cases = []
        seed = b"equivalence-seed"
        for key_len in (1, 8, 32, 60):
            key = hashlib.sha512(seed + bytes([key_len])).digest()[:key_len]
            for msg_len in (0, 1, 32, 64, 1024):
                msg = hashlib.sha512(key + bytes([msg_len % 256])).digest() * (msg_len // 64 + 1)
                cases.append((key, msg[:msg_len]))
        for key, msg in cases:
            with self.subTest(key_len=len(key), msg_len=len(msg)):
                ours = randomx_native.RandomX(key).calculate_hash(msg)
                theirs = bytes(reference_randomx.RandomX(key).calculate_hash(msg))
                self.assertEqual(ours, theirs)

    def test_kdf_chain_pattern(self):
        """The exact pattern from kdf_registry.py: 32-byte key from
        sha256(password+salt), then chained calculate_hash passes."""
        initial = hashlib.sha256(b"test-password" + b"test-salt-16byte").digest()
        vm_ours = randomx_native.RandomX(initial[:32])
        vm_ref = reference_randomx.RandomX(initial[:32])
        ours, theirs = initial, initial
        for _ in range(10):
            ours = vm_ours.calculate_hash(ours)
            theirs = bytes(vm_ref.calculate_hash(bytes(theirs)))
            self.assertEqual(ours, theirs)

    def test_modules_randomx_round_pattern(self):
        """The per-round fresh-VM pattern from modules/randomx.py."""
        current = hashlib.sha256(b"pw").digest()
        for round_num in range(3):
            seed = hashlib.sha256(b"salt" + round_num.to_bytes(4, "big")).digest()
            ours = randomx_native.RandomX(seed).calculate_hash(current)
            theirs = bytes(reference_randomx.RandomX(seed).calculate_hash(current))
            self.assertEqual(ours, theirs)
            current = ours


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestFullMemMode(unittest.TestCase):
    """fast mode (2080 MB dataset) — skipped when the host can't afford it."""

    def test_full_mem_matches_light_mode(self):
        try:
            vm_fast = randomx_native.RandomX(b"test key 000", full_mem=True)
        except MemoryError:
            self.skipTest("host cannot allocate the 2080 MB RandomX dataset")
        self.assertEqual(
            bytes(vm_fast.calculate_hash(b"This is a test")).hex(),
            OFFICIAL_VECTORS[0][2],
        )


if __name__ == "__main__":
    unittest.main()
