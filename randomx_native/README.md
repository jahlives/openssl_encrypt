# openssl-encrypt-randomx

Project-owned RandomX KDF bindings for openssl-encrypt (gitlab#285), wrapping
the official [tevador/RandomX](https://github.com/tevador/RandomX) C library —
vendored in-tree and pinned at **v1.1.10**
(`f9ae3f235183c452962edd2a15384bdc67f7a11e`, see `RANDOMX_PIN`). This is the
exact upstream version the abandoned PyPI `RandomX` binding vendors, so KDF
output is byte-identical and existing encrypted files keep decrypting.

## API

```python
import randomx_native

vm = randomx_native.RandomX(key)              # light mode (256 MB cache)
vm = randomx_native.RandomX(key, full_mem=True)  # fast mode (2080 MB dataset)
digest = vm.calculate_hash(data)              # -> 32 bytes
```

The constructor signature matches the reference binding
(`RandomX(key, full_mem=False, secure=..., large_pages=False, threads=0)`),
so it is a drop-in for the surface `openssl_encrypt` uses.

## Security posture

Deliberate divergences from the reference binding (output is unaffected):

- **`secure=True` by default**: JIT pages are never writable and executable
  at the same time (W^X). Opt out explicitly if you must. `jit=False`
  forces the interpreted VM entirely; `strict=True` raises instead of
  silently degrading when a requested configuration is unavailable, and
  `vm.flags` / `vm.requested_flags` / `vm.degraded` expose what actually
  happened (SECURE is reported only while a JIT is active).
- **No process aborts from the C++ library**: page-protection or allocation
  failures inside RandomX (SELinux/PaX/seccomp denying `mprotect`,
  exhausted mappings) throw C++ exceptions with no internal catch; a
  project-owned shim (`src/rxs_shim.cpp`) converts them into Python
  `RuntimeError`s instead of undefined behavior at the FFI boundary.
- **Empty keys are refused** (`ValueError`) — an empty KDF key is always a bug.
- **Zeroization (Rust side)**: the binding's own copies of keys and hashed
  messages live in buffers wiped on drop (Rust `zeroize`), and
  `calculate_hash_into(data, bytearray(32))` lets callers keep digests in
  wipeable buffers.
- **Thread safety**: the VM serializes access internally; concurrent use
  from Python threads cannot corrupt the non-thread-safe C VM.
- **Portable hardware AES**: no `-march=native` (builds are reproducible
  per architecture), but AES intrinsics are compiled in and runtime-gated
  (cpuid/hwcaps) — on AES-capable CPUs RandomX uses constant-time hardware
  AES exactly like the reference binding, instead of the table-based soft
  AES fallback (a cache-timing side channel and a KDF slowdown).
- **Supply chain**: the C library is vendored verbatim (no network at build
  time) with recorded provenance (`RANDOMX_PIN`), a sha256 manifest
  (`RANDOMX_SRC.sha256`) recomputed by the test suite on every run, a
  committed `Cargo.lock`, and a build that refuses fast-math-style
  `CFLAGS`/`CXXFLAGS` (they would change KDF output).
  `randomx_native.RANDOMX_UPSTREAM_COMMIT` exposes the pin at runtime.

Known residuals, stated plainly: the vendored C library keeps a **verbatim
copy of the key** in `randomx_cache::cacheKey` and (light mode) a second
one in `randomx_vm::cacheKey` — both `std::string`s freed without wiping —
and the 256 MB cache / 2080 MB dataset hold key-derived state the C API
cannot wipe before release. In fast mode the cache (and its key copy) is
released as soon as the dataset is initialized. Digests returned by
`calculate_hash` are immutable Python `bytes`; use `calculate_hash_into`
where the caller needs wipeable output. These residuals match or improve on
the reference binding's behavior.

## Building

```bash
pip install maturin
maturin build --release   # or: maturin develop --release
```

Requires a C/C++ toolchain (the vendored RandomX library is compiled into
the extension) and Rust.
