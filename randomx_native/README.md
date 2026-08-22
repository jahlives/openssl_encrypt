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

## Releasing (maintainer, user-owned step)

CI (`randomx-wheel` job) builds the wheel + sdist on every development-branch
pipeline and verifies the official RandomX v1.1.10 vector against the
produced wheel. Publishing to PyPI is a manual release step, triggered from
CI (preferred) or done locally as a fallback.

**Preferred: the `publish-randomx-pypi` CI job** (gitlab#285). On a pipeline
whose `randomx-wheel` job succeeded, press its play button — it uploads the
exact integrity-gated, vector-smoked `randomx-dist/` artifact via twine.
Prerequisite: the `PYPI_API_TOKEN_RANDOMX` CI variable (masked + protected).
The very first upload creates the PyPI project and needs an **account-scoped**
token (PyPI trusted publishing supports gitlab.com only, not this self-hosted
instance); after the project exists, replace it with a token scoped to
`openssl-encrypt-randomx`. Note: PyPI accepts only manylinux/musllinux-tagged
Linux wheels — if the wheel is rejected as plain `linux_x86_64`, upload the
sdist alone and fix the wheel tagging (maturin audits the wheel automatically
when the build environment allows it).

**Fallback: local upload.** Rebuild locally and re-run the same gates the CI
job applies before uploading:

```bash
cd randomx_native
sha256sum -c --quiet RANDOMX_SRC.sha256      # vendored-tree integrity
maturin build --release -o dist && maturin sdist -o dist
pip install dist/openssl_encrypt_randomx-*.whl --force-reinstall
python3 -c "import randomx_native; \
  assert randomx_native.RandomX(b'test key 000').calculate_hash(b'This is a test').hex() \
  == '639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f'"
twine upload dist/*            # needs the maintainer's PyPI credentials
```

After the first publish, the requirements files can pin
`openssl-encrypt-randomx` by version + `--hash` (closing review finding F3:
`--require-hashes` becomes possible on every arch), and the aarch64 fork pin
for the abandoned `RandomX` package can be retired.
