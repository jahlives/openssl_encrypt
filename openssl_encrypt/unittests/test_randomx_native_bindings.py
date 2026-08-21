#!/usr/bin/env python3
"""
TDD contract for the project-owned RandomX bindings (gitlab#285).

randomx_native wraps the official tevador/RandomX C library, pinned at the
v1.1.10 tag (commit f9ae3f235183c452962edd2a15384bdc67f7a11e) — the exact
version the abandoned PyPI binding vendors — and must produce byte-identical
KDF output. The guarantee rests on:

1. Official RandomX v1.1.10 test vectors (from the vendored
   ``RandomX_src/tests/tests.cpp``): these ARE the specification and do not
   depend on any other binding being installed.
2. The vendored-tree sha256 manifest (``RANDOMX_SRC.sha256``), recomputed
   here on every run, so an in-repo modification of the vendored C sources
   fails tests (review F3).
3. Equivalence against the reference binding (the PyPI/fork ``randomx``
   module) WHERE it is importable — an additional cross-check on hosts that
   still have the abandoned binding, not the primary guarantee.
4. API-contract and security-behavior tests: input validation, thread
   safety, the SECURE (W^X JIT) default, degradation reporting, and the
   interpreted-VM path (``jit=False``).
"""

import hashlib
import threading
import unittest
from pathlib import Path

try:
    import randomx_native
except ImportError:
    randomx_native = None

try:
    import randomx as reference_randomx
except ImportError:
    reference_randomx = None

REPO_ROOT = Path(__file__).resolve().parents[2]
NATIVE_DIR = REPO_ROOT / "randomx_native"

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

    def test_interpreted_vm_matches_vectors(self):
        """jit=False forces the interpreted VM — byte-identical output, and
        the degradation/creation fallback path gets real coverage."""
        vm = randomx_native.RandomX(b"test key 000", jit=False)
        self.assertFalse(vm.flags & randomx_native.FLAG_JIT)
        self.assertFalse(vm.flags & randomx_native.FLAG_SECURE)
        self.assertEqual(
            bytes(vm.calculate_hash(b"This is a test")).hex(),
            OFFICIAL_VECTORS[0][2],
        )

    def test_interpreted_equals_jit(self):
        """Direct interpreted-vs-JIT equivalence on a non-vector input."""
        key = hashlib.sha256(b"jit-vs-interp").digest()
        msg = b"equivalence probe"
        self.assertEqual(
            randomx_native.RandomX(key).calculate_hash(msg),
            randomx_native.RandomX(key, jit=False).calculate_hash(msg),
        )


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestVendoredTreeIntegrity(unittest.TestCase):
    """RANDOMX_SRC.sha256 must match the vendored tree bit-for-bit (F3)."""

    @unittest.skipUnless(NATIVE_DIR.is_dir(), "requires a repository checkout")
    def test_vendored_sources_match_manifest(self):
        manifest_path = NATIVE_DIR / "RANDOMX_SRC.sha256"
        entries = {}
        for line in manifest_path.read_text().splitlines():
            digest, _, name = line.partition("  ")
            entries[name] = digest
        self.assertGreaterEqual(len(entries), 100, "manifest suspiciously short")

        on_disk = {
            str(p.relative_to(NATIVE_DIR))
            for p in (NATIVE_DIR / "RandomX_src").rglob("*")
            if p.is_file()
        }
        on_disk.add("RANDOMX_LICENSE")
        self.assertEqual(
            on_disk,
            set(entries),
            msg="vendored file set differs from RANDOMX_SRC.sha256 manifest",
        )
        mismatches = []
        for name, expected in entries.items():
            actual = hashlib.sha256((NATIVE_DIR / name).read_bytes()).hexdigest()
            if actual != expected:
                mismatches.append(name)
        self.assertEqual(
            mismatches,
            [],
            msg="vendored files differ from the pinned manifest (supply-chain "
            "red flag — see RANDOMX_PIN): " + repr(mismatches),
        )

    def test_upstream_pin_matches_pin_file(self):
        """The runtime constant must agree with the RANDOMX_PIN document."""
        self.assertEqual(len(randomx_native.RANDOMX_UPSTREAM_COMMIT), 40)
        if NATIVE_DIR.is_dir():
            pin_text = (NATIVE_DIR / "RANDOMX_PIN").read_text()
            self.assertIn(randomx_native.RANDOMX_UPSTREAM_COMMIT, pin_text)
        self.assertTrue(randomx_native.__version__)


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

    def test_non_contiguous_input_is_logical_order(self):
        """A strided memoryview hashes its LOGICAL content (deliberate pin)."""
        strided = memoryview(b"axbxcxdx")[::2]  # -> b"abcd"
        vm = randomx_native.RandomX(b"k" * 32)
        self.assertEqual(vm.calculate_hash(strided), vm.calculate_hash(b"abcd"))

    def test_calculate_hash_into_bytearray(self):
        """Digests can land in a caller-owned wipeable buffer (F5)."""
        vm = randomx_native.RandomX(b"k" * 32)
        out = bytearray(32)
        vm.calculate_hash_into(b"payload", out)
        self.assertEqual(bytes(out), vm.calculate_hash(b"payload"))
        with self.assertRaises(ValueError):
            vm.calculate_hash_into(b"payload", bytearray(31))
        with self.assertRaises((TypeError, ValueError)):
            vm.calculate_hash_into(b"payload", b"x" * 32)  # read-only buffer

    def test_empty_input_allowed(self):
        """Zero-length messages hash fine (parity with the C API)."""
        digest = randomx_native.RandomX(b"k" * 32).calculate_hash(b"")
        self.assertEqual(len(digest), 32)

    def test_empty_key_refused(self):
        """Deliberate hardening divergence: an empty KDF key is always a bug."""
        with self.assertRaises(ValueError):
            randomx_native.RandomX(b"")

    def test_oversized_threads_refused(self):
        """Unbounded/lossy thread counts must fail loudly, never partition to
        zero workers (F6: an uninitialized dataset silently corrupts KDF
        output)."""
        with self.assertRaises(ValueError):
            randomx_native.RandomX(b"k" * 32, full_mem=True, threads=2**32)

    def test_wrong_types_refused(self):
        with self.assertRaises(TypeError):
            randomx_native.RandomX("not bytes")
        vm = randomx_native.RandomX(b"k" * 32)
        with self.assertRaises(TypeError):
            vm.calculate_hash("not bytes")
        with self.assertRaises(TypeError):
            vm.calculate_hash(None)

    def test_vm_is_thread_safe(self):
        """Concurrent calculate_hash on one VM must stay correct on EVERY
        iteration (the binding serializes access internally; the C VM is not
        thread-safe), and a reintroduced GIL/lock inversion must fail the
        test rather than hang the suite."""
        vm = randomx_native.RandomX(b"k" * 32)
        expected = {
            i: randomx_native.RandomX(b"k" * 32).calculate_hash(b"m%d" % i) for i in range(4)
        }
        lock = threading.Lock()
        mismatches = []
        errors = []

        def worker(i):
            try:
                for _ in range(8):
                    digest = vm.calculate_hash(b"m%d" % i)
                    if digest != expected[i]:
                        with lock:
                            mismatches.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        alive = [t for t in threads if t.is_alive()]
        self.assertEqual(alive, [], msg="calculate_hash deadlocked (GIL/lock inversion)")
        self.assertEqual(errors, [])
        self.assertEqual(mismatches, [])

    def test_concurrent_vm_construction(self):
        """Several constructors at once (each runs a 256 MB argon2 fill)."""
        results = {}
        errors = []
        lock = threading.Lock()

        def build(i):
            try:
                digest = randomx_native.RandomX(b"conc-key-%d" % i).calculate_hash(b"m")
                with lock:
                    results[i] = digest
            except Exception as exc:  # pragma: no cover - failure path
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=build, args=(i,), daemon=True) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=300)
        self.assertEqual([t for t in threads if t.is_alive()], [])
        self.assertEqual(errors, [])
        for i, digest in results.items():
            self.assertEqual(
                digest,
                randomx_native.RandomX(b"conc-key-%d" % i).calculate_hash(b"m"),
            )


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
class TestSecurityBehavior(unittest.TestCase):
    """Hardening this binding adds on top of the reference API."""

    def test_secure_wx_flag_defaults_on_with_jit(self):
        """SECURE (W^X) is requested by default; it is REPORTED only when a
        JIT is actually active (F9: no misleading SECURE on interpreted VMs)."""
        vm_default = randomx_native.RandomX(b"k" * 32)
        if vm_default.flags & randomx_native.FLAG_JIT:
            self.assertTrue(vm_default.flags & randomx_native.FLAG_SECURE)
        else:
            self.assertFalse(vm_default.flags & randomx_native.FLAG_SECURE)
        vm_off = randomx_native.RandomX(b"k" * 32, secure=False)
        self.assertFalse(vm_off.flags & randomx_native.FLAG_SECURE)

    def test_secure_flag_does_not_change_output(self):
        self.assertEqual(
            randomx_native.RandomX(b"k" * 32, secure=True).calculate_hash(b"m"),
            randomx_native.RandomX(b"k" * 32, secure=False).calculate_hash(b"m"),
        )

    def test_degradation_reporting(self):
        """requested_flags/degraded expose what actually happened (F9)."""
        vm = randomx_native.RandomX(b"k" * 32)
        self.assertIsInstance(vm.requested_flags, int)
        self.assertEqual(vm.degraded, vm.flags != vm.requested_flags)
        # jit=False is a request, not a degradation:
        vm_interp = randomx_native.RandomX(b"k" * 32, jit=False)
        self.assertFalse(vm_interp.degraded)

    def test_strict_mode_accepts_satisfiable_request(self):
        """strict=True must not raise when the request is satisfiable — and
        on hosts where it is not, it must raise rather than degrade."""
        try:
            vm = randomx_native.RandomX(b"k" * 32, strict=True)
        except RuntimeError:
            return  # host genuinely cannot satisfy the default request
        self.assertFalse(vm.degraded)

    def test_hardware_aes_matches_runtime_detection(self):
        """HARD_AES must be available exactly where the CPU supports it (F2:
        the build must not silently force table-based soft AES everywhere).
        Cross-checked against the reference binding when present."""
        flags = randomx_native.get_flags()
        if reference_randomx is not None:
            self.assertEqual(
                flags & randomx_native.FLAG_HARD_AES,
                reference_randomx.get_flags() & randomx_native.FLAG_HARD_AES,
                msg="hardware-AES detection diverges from the reference binding",
            )


@unittest.skipIf(randomx_native is None, "randomx_native not built/installed")
@unittest.skipIf(reference_randomx is None, "reference randomx binding not installed")
class TestEquivalenceWithReferenceBinding(unittest.TestCase):
    """Byte-identical output against the PyPI/fork binding — an additional
    cross-check where that binding is installed; the official vectors plus
    the vendored-tree manifest are the primary guarantee (see module
    docstring)."""

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

    def test_full_mem_thread_partitions(self):
        """Odd worker counts exercise the division-remainder partitioning of
        dataset init (F6: the most dangerous arithmetic in the binding)."""
        for threads in (1, 3, 7):
            with self.subTest(threads=threads):
                try:
                    vm = randomx_native.RandomX(b"test key 000", full_mem=True, threads=threads)
                except MemoryError:
                    self.skipTest("host cannot allocate the 2080 MB dataset")
                self.assertEqual(
                    bytes(vm.calculate_hash(b"This is a test")).hex(),
                    OFFICIAL_VECTORS[0][2],
                )
                del vm


if __name__ == "__main__":
    unittest.main()
