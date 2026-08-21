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
  at the same time (W^X). Opt out explicitly if you must.
- **Empty keys are refused** (`ValueError`) — an empty KDF key is always a bug.
- **Zeroization**: internal copies of keys and hashed messages live in
  buffers wiped on drop (Rust `zeroize`).
- **Thread safety**: the VM serializes access internally; concurrent use
  from Python threads cannot corrupt the non-thread-safe C VM.
- **No `-march=native`**: builds are portable and reproducible per
  architecture.
- **Supply chain**: the C library is vendored verbatim (no network at build
  time) with recorded provenance; `randomx_native.RANDOMX_UPSTREAM_COMMIT`
  exposes the pin at runtime.

Accepted residual: RandomX's 256 MB cache / 2080 MB dataset hold key-derived
state that the upstream C API provides no way to wipe before release; this
matches the reference binding's behavior.

## Building

```bash
pip install maturin
maturin build --release   # or: maturin develop --release
```

Requires a C/C++ toolchain (the vendored RandomX library is compiled into
the extension) and Rust.
