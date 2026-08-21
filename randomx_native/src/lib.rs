//! RandomX KDF Python bindings for openssl-encrypt (gitlab#285).
//!
//! Wraps the official tevador/RandomX C library, vendored and pinned at the
//! v1.1.10 tag (commit f9ae3f235183c452962edd2a15384bdc67f7a11e) — the exact
//! version the reference PyPI binding vendors — so KDF output stays
//! byte-identical to files encrypted with that binding.
//!
//! API contract (matching the surface openssl_encrypt uses):
//!   vm = RandomX(key, full_mem=False)   # plus secure/large_pages/threads/
//!                                       # jit/strict
//!   digest = vm.calculate_hash(data)    # -> 32 bytes
//!   vm.calculate_hash_into(data, out)   # -> into a wipeable bytearray
//!
//! Security posture (deliberate divergences from the reference binding):
//! - SECURE (W^X JIT pages) is requested by DEFAULT; opt out explicitly.
//! - An empty key is refused (ValueError) — an empty KDF key is always a bug.
//! - Key and message copies on the Rust side live in zeroizing buffers wiped
//!   on drop.
//! - C++ exceptions from the vendored library (page-protection failures
//!   under SELinux/PaX/seccomp, allocation exhaustion) are caught in a
//!   project-owned shim (rxs_shim.cpp) and surfaced as Python exceptions
//!   instead of aborting the process (review F1).
//! - The VM is internally serialized (the Mutex is locked INSIDE the
//!   GIL-released section — locking under the GIL deadlocks): concurrent
//!   use from Python threads cannot corrupt the non-thread-safe C VM.
//! - Failed allocations degrade flags like the reference binding (drop JIT,
//!   then optimized Argon2); the VM is created with the flags the cache was
//!   ACTUALLY allocated with, `flags` reports the effective configuration
//!   (SECURE is masked out when no JIT is active, review F9), and
//!   `strict=True` turns any degradation into an error.
//!
//! Known residuals (review F5 — stated plainly): the vendored C library
//! keeps a VERBATIM copy of the key in randomx_cache::cacheKey and a second
//! one in randomx_vm::cacheKey (std::string, freed without wiping), and the
//! 256 MB cache / 2080 MB dataset hold key-derived state the C API cannot
//! wipe before release. In fast mode the cache (and its key copy) is
//! released as soon as the dataset is initialized (review F4). Digests
//! returned by calculate_hash are immutable Python bytes; use
//! calculate_hash_into with a bytearray where the caller needs wipeable
//! output.

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyMemoryError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::os::raw::{c_int, c_ulong, c_void};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Commit of the vendored tevador/RandomX tree (tag v1.1.10). See RANDOMX_PIN.
const RANDOMX_UPSTREAM_COMMIT: &str = "f9ae3f235183c452962edd2a15384bdc67f7a11e";
const HASH_SIZE: usize = 32;
const MAX_DATASET_INIT_THREADS: usize = 1024;

// randomx_flags values from RandomX_src/randomx.h (v1.1.10).
const FLAG_DEFAULT: c_int = 0;
const FLAG_LARGE_PAGES: c_int = 1;
const FLAG_HARD_AES: c_int = 2;
const FLAG_FULL_MEM: c_int = 4;
const FLAG_JIT: c_int = 8;
const FLAG_SECURE: c_int = 16;
const FLAG_ARGON2_SSSE3: c_int = 32;
const FLAG_ARGON2_AVX2: c_int = 64;
const FLAG_ARGON2: c_int = 96;

mod ffi {
    use std::os::raw::{c_int, c_ulong, c_void};

    #[repr(C)]
    pub struct randomx_cache {
        _opaque: [u8; 0],
    }
    #[repr(C)]
    pub struct randomx_dataset {
        _opaque: [u8; 0],
    }
    #[repr(C)]
    pub struct randomx_vm {
        _opaque: [u8; 0],
    }

    extern "C" {
        pub fn randomx_get_flags() -> c_int;
        pub fn randomx_alloc_cache(flags: c_int) -> *mut randomx_cache;
        pub fn randomx_release_cache(cache: *mut randomx_cache);
        pub fn randomx_alloc_dataset(flags: c_int) -> *mut randomx_dataset;
        pub fn randomx_dataset_item_count() -> c_ulong;
        pub fn randomx_release_dataset(dataset: *mut randomx_dataset);
        pub fn randomx_create_vm(
            flags: c_int,
            cache: *mut randomx_cache,
            dataset: *mut randomx_dataset,
        ) -> *mut randomx_vm;
        pub fn randomx_destroy_vm(vm: *mut randomx_vm);

        // Project-owned exception shim (src/rxs_shim.cpp): the underlying
        // calls throw C++ exceptions with no internal catch, and unwinding
        // across extern "C" is UB / process abort (review F1). 0 = ok.
        pub fn rxs_init_cache(
            cache: *mut randomx_cache,
            key: *const c_void,
            key_size: usize,
        ) -> c_int;
        pub fn rxs_calculate_hash(
            vm: *mut randomx_vm,
            input: *const c_void,
            input_size: usize,
            output: *mut c_void,
        ) -> c_int;
        pub fn rxs_init_dataset(
            dataset: *mut randomx_dataset,
            cache: *mut randomx_cache,
            start_item: c_ulong,
            item_count: c_ulong,
        ) -> c_int;
    }
}

/// Raw pointer made Send for a specific, documented sharing pattern.
///
/// SAFETY (per use): dataset initialization over disjoint
/// [start, start+count) item ranges from one initialized cache is explicitly
/// supported by the C API (randomx.h documents multi-call initialization
/// with non-overlapping sequences; upstream tests/benchmark.cpp does exactly
/// this multithreaded). The cache is read-only for the duration; regions
/// written by different workers do not overlap. Outside that pattern the
/// wrapped pointer is moved, not shared, between threads.
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}
// Manual Copy/Clone: the derives would demand T: Copy, but only the pointer
// itself is copied.
impl<T> Copy for SendPtr<T> {}
impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> SendPtr<T> {
    /// By-value accessor: closures capture the whole SendPtr (keeping the
    /// Send impl in force) instead of disjointly capturing the raw field.
    fn get(self) -> *mut T {
        self.0
    }
}

/// Owned RandomX cache; released on drop.
///
/// The wrapper is created around a freshly allocated cache which is then
/// MUTATED once by rxs_init_cache and used read-only afterwards; it is
/// moved, not shared, between threads except via SendPtr (see above).
struct Cache(NonNull<ffi::randomx_cache>);
unsafe impl Send for Cache {}
impl Drop for Cache {
    fn drop(&mut self) {
        unsafe { ffi::randomx_release_cache(self.0.as_ptr()) };
    }
}

/// Owned RandomX dataset; released on drop. Same sharing discipline as Cache.
struct Dataset(NonNull<ffi::randomx_dataset>);
unsafe impl Send for Dataset {}
impl Drop for Dataset {
    fn drop(&mut self) {
        unsafe { ffi::randomx_release_dataset(self.0.as_ptr()) };
    }
}

struct VmState {
    vm: NonNull<ffi::randomx_vm>,
    // Held only to keep the C structures alive as long as the VM lives;
    // dropped (and released) after the VM itself is destroyed. In fast mode
    // the cache is already released before VM creation (review F4) and this
    // is None.
    _cache: Option<Cache>,
    _dataset: Option<Dataset>,
}
// SAFETY: VmState is only reachable through the Mutex in Vm, which
// serializes every use of the (non-thread-safe) C VM.
unsafe impl Send for VmState {}
impl Drop for VmState {
    fn drop(&mut self) {
        // Destroy the VM first; _cache/_dataset release afterwards by
        // field-drop order.
        unsafe { ffi::randomx_destroy_vm(self.vm.as_ptr()) };
    }
}

/// Copy any buffer-protocol object into a zeroizing byte vector.
/// The copy is taken under the GIL, before any detach.
fn buffer_to_zeroizing(obj: &Bound<'_, PyAny>) -> PyResult<Zeroizing<Vec<u8>>> {
    let buffer = PyBuffer::<u8>::get(obj)?;
    Ok(Zeroizing::new(buffer.to_vec(obj.py())?))
}

/// A RandomX virtual machine bound to one key.
#[pyclass(module = "randomx_native", name = "VM")]
struct Vm {
    state: Mutex<VmState>,
    flags: c_int,
    requested_flags: c_int,
}

impl Vm {
    /// Run one hash with the VM lock taken inside the GIL-released section.
    fn hash_locked(&self, py: Python<'_>, data: &[u8], output: &mut [u8; HASH_SIZE]) -> PyResult<()> {
        let state_mutex = &self.state;
        let in_addr = data.as_ptr() as usize;
        let in_len = data.len();
        let out_addr = output.as_mut_ptr() as usize;
        // The Mutex MUST be taken inside the detached (GIL-free) section:
        // locking it while holding the GIL deadlocks against a second thread
        // that holds the GIL while waiting for the Mutex. Addresses are
        // passed as usize because detach requires a Send closure; both
        // buffers outlive this call (owned by the caller).
        let result = py.detach(move || match state_mutex.lock() {
            Ok(state) => {
                // SAFETY: pointers are valid for the duration of the call;
                // the Mutex guarantees exclusive access to the C VM.
                let rc = unsafe {
                    ffi::rxs_calculate_hash(
                        state.vm.as_ptr(),
                        in_addr as *const c_void,
                        in_len,
                        out_addr as *mut c_void,
                    )
                };
                if rc == 0 {
                    Ok(())
                } else {
                    Err("RandomX hash calculation failed (page-protection or allocation failure in the native library)")
                }
            }
            Err(_) => Err("RandomX VM lock poisoned"),
        });
        result.map_err(PyRuntimeError::new_err)
    }
}

#[pymethods]
impl Vm {
    /// The effective randomx_flags this VM runs with. SECURE is reported
    /// only when a JIT is actually active (W^X is meaningless without one).
    #[getter]
    fn flags(&self) -> c_int {
        self.flags
    }

    /// The randomx_flags that were requested before any degradation.
    #[getter]
    fn requested_flags(&self) -> c_int {
        self.requested_flags
    }

    /// True if the effective configuration is weaker than requested.
    #[getter]
    fn degraded(&self) -> bool {
        self.flags != self.requested_flags
    }

    /// Calculate the 32-byte RandomX hash of `input`, returned as bytes.
    fn calculate_hash<'py>(
        &self,
        py: Python<'py>,
        input: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = buffer_to_zeroizing(input)?;
        let mut output = Zeroizing::new([0u8; HASH_SIZE]);
        self.hash_locked(py, &data, &mut output)?;
        Ok(PyBytes::new(py, &output[..]))
    }

    /// Calculate the hash of `input` INTO `output` (a writable 32-byte
    /// buffer, e.g. a bytearray), so the caller can wipe it afterwards.
    fn calculate_hash_into<'py>(
        &self,
        py: Python<'py>,
        input: &Bound<'py, PyAny>,
        output: &Bound<'py, PyAny>,
    ) -> PyResult<()> {
        let data = buffer_to_zeroizing(input)?;
        let out_buffer = PyBuffer::<u8>::get(output)?;
        if out_buffer.readonly() {
            return Err(PyValueError::new_err(
                "output buffer must be writable (e.g. a bytearray)",
            ));
        }
        if out_buffer.item_count() != HASH_SIZE {
            return Err(PyValueError::new_err(format!(
                "output buffer must be exactly {HASH_SIZE} bytes"
            )));
        }
        let mut digest = Zeroizing::new([0u8; HASH_SIZE]);
        self.hash_locked(py, &data, &mut digest)?;
        out_buffer.copy_from_slice(py, &digest[..])
    }

    /// Alias for calculate_hash (parity with the reference binding).
    fn __call__<'py>(
        &self,
        py: Python<'py>,
        input: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.calculate_hash(py, input)
    }
}

/// Allocate a cache with the reference binding's degradation chain.
/// Returns the cache and the flags it was actually allocated with.
fn alloc_cache_with_fallback(requested: c_int, large_pages: bool) -> PyResult<(Cache, c_int)> {
    let candidates = [
        requested,
        requested & !FLAG_JIT,
        requested & !FLAG_ARGON2_SSSE3 & !FLAG_ARGON2_AVX2,
        requested & !FLAG_JIT & !FLAG_ARGON2_SSSE3 & !FLAG_ARGON2_AVX2,
    ];
    for flags in candidates {
        let ptr = unsafe { ffi::randomx_alloc_cache(flags) };
        if let Some(cache) = NonNull::new(ptr) {
            return Ok((Cache(cache), flags));
        }
    }
    Err(PyMemoryError::new_err(if large_pages {
        "could not allocate the RandomX cache (large_pages was requested — \
         is the host configured with huge pages?)"
    } else {
        "could not allocate the RandomX cache"
    }))
}

/// Initialize `cache` with `key` via the exception shim; on failure with an
/// active JIT, fall back to a non-JIT cache before giving up.
fn init_cache_with_fallback(
    py: Python<'_>,
    cache: Cache,
    effective: c_int,
    key: &[u8],
) -> PyResult<(Cache, c_int)> {
    let run_init = |py: Python<'_>, cache_ptr: SendPtr<ffi::randomx_cache>, key: &[u8]| {
        let key_addr = key.as_ptr() as usize;
        let key_len = key.len();
        // SAFETY: cache is freshly allocated; key buffer outlives the call.
        py.detach(move || unsafe {
            ffi::rxs_init_cache(cache_ptr.get(), key_addr as *const c_void, key_len)
        })
    };

    if run_init(py, SendPtr(cache.0.as_ptr()), key) == 0 {
        return Ok((cache, effective));
    }
    if effective & FLAG_JIT != 0 {
        drop(cache);
        let (retry_cache, retry_flags) =
            alloc_cache_with_fallback(effective & !FLAG_JIT, false)?;
        if run_init(py, SendPtr(retry_cache.0.as_ptr()), key) == 0 {
            return Ok((retry_cache, retry_flags));
        }
    }
    Err(PyRuntimeError::new_err(
        "RandomX cache initialization failed in the native library",
    ))
}

/// Create a RandomX VM for `key`.
///
/// Mirrors the reference binding's convenience constructor. `secure`
/// defaults to True here (W^X JIT pages) — a deliberate hardening
/// divergence; RandomX output is identical either way. `jit=False` forces
/// the interpreted VM (byte-identical, slower). `strict=True` raises
/// instead of silently degrading when the requested configuration is
/// unavailable.
#[pyfunction]
#[pyo3(signature = (key, full_mem=false, secure=true, large_pages=false, threads=0, jit=true, strict=false))]
#[allow(non_snake_case, clippy::too_many_arguments)]
fn RandomX(
    py: Python<'_>,
    key: &Bound<'_, PyAny>,
    full_mem: bool,
    secure: bool,
    large_pages: bool,
    threads: usize,
    jit: bool,
    strict: bool,
) -> PyResult<Vm> {
    let key_bytes = buffer_to_zeroizing(key)?;
    if key_bytes.is_empty() {
        return Err(PyValueError::new_err("RandomX key must not be empty"));
    }
    if threads > MAX_DATASET_INIT_THREADS {
        return Err(PyValueError::new_err(format!(
            "threads must be <= {MAX_DATASET_INIT_THREADS}"
        )));
    }

    let mut requested = unsafe { ffi::randomx_get_flags() };
    if !jit {
        requested &= !FLAG_JIT;
    }
    if full_mem {
        requested |= FLAG_FULL_MEM;
    }
    if secure {
        requested |= FLAG_SECURE;
    }
    if large_pages {
        requested |= FLAG_LARGE_PAGES;
    }
    // SECURE is meaningful only alongside a JIT; report both requested and
    // effective flags with it masked when no JIT is in play (review F9).
    let reported_requested = if requested & FLAG_JIT == 0 {
        requested & !FLAG_SECURE
    } else {
        requested
    };

    let (cache, effective) = alloc_cache_with_fallback(requested, large_pages)?;
    let (cache, effective) = init_cache_with_fallback(py, cache, effective, &key_bytes)?;

    let dataset = if full_mem {
        let ptr = unsafe { ffi::randomx_alloc_dataset(effective) };
        let dataset = NonNull::new(ptr).map(Dataset).ok_or_else(|| {
            PyMemoryError::new_err(if large_pages {
                "could not allocate the RandomX dataset (2080 MB; large_pages \
                 was requested — is the host configured with huge pages?)"
            } else {
                "could not allocate the RandomX dataset (2080 MB)"
            })
        })?;
        let item_count = unsafe { ffi::randomx_dataset_item_count() };
        // clamp(1, ..) is load-bearing: a zero-worker partition would leave
        // the dataset UNINITIALIZED and silently corrupt KDF output
        // (review F6). threads is already bounded above, so the cast is
        // lossless on every platform.
        let workers: c_ulong = if threads > 0 {
            threads as c_ulong
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get() as c_ulong)
                .unwrap_or(1)
        }
        .clamp(1, item_count.max(1));
        let dataset_ptr = SendPtr(dataset.0.as_ptr());
        let cache_ptr = SendPtr(cache.0.as_ptr());
        let failed = AtomicBool::new(false);
        // move-capture: SendPtr copies plus a &AtomicBool (Sync) — a non-move
        // closure would borrow the SendPtrs and demand Sync on raw pointers.
        let failed_flag = &failed;
        py.detach(move || {
            std::thread::scope(|scope| {
                let mut start: c_ulong = 0;
                for worker in 0..workers {
                    let count = if worker == workers - 1 {
                        item_count - start
                    } else {
                        item_count / workers
                    };
                    let begin = start;
                    let failed = failed_flag;
                    scope.spawn(move || {
                        // SAFETY: disjoint item ranges from one initialized,
                        // read-only cache — the documented multithreaded
                        // initialization pattern (see SendPtr).
                        let rc = unsafe {
                            ffi::rxs_init_dataset(dataset_ptr.get(), cache_ptr.get(), begin, count)
                        };
                        if rc != 0 {
                            failed.store(true, Ordering::Relaxed);
                        }
                    });
                    start += count;
                }
            });
        });
        if failed.load(Ordering::Relaxed) {
            return Err(PyRuntimeError::new_err(
                "RandomX dataset initialization failed in the native library",
            ));
        }
        Some(dataset)
    } else {
        None
    };

    // In fast mode the VM runs from the dataset alone; releasing the cache
    // now frees ~256 MB of key-derived state AND the verbatim key copy in
    // randomx_cache::cacheKey as early as possible (review F4/F5). The C API
    // documents cache=NULL as valid when FULL_MEM is set.
    let (kept_cache, cache_arg): (Option<Cache>, *mut ffi::randomx_cache) = if full_mem {
        drop(cache);
        (None, std::ptr::null_mut())
    } else {
        let ptr = cache.0.as_ptr();
        (Some(cache), ptr)
    };

    let dataset_ptr = dataset
        .as_ref()
        .map(|d| d.0.as_ptr())
        .unwrap_or(std::ptr::null_mut());

    let mut vm_flags = effective;
    let mut vm_ptr = unsafe { ffi::randomx_create_vm(vm_flags, cache_arg, dataset_ptr) };
    if vm_ptr.is_null() && (vm_flags & FLAG_JIT) != 0 {
        // Fall back to the interpreted VM (no JIT pages at all) rather than
        // silently dropping only the W^X protection.
        vm_flags &= !(FLAG_JIT | FLAG_SECURE);
        vm_ptr = unsafe { ffi::randomx_create_vm(vm_flags, cache_arg, dataset_ptr) };
    }
    let vm = NonNull::new(vm_ptr).ok_or_else(|| {
        PyMemoryError::new_err("out of memory or unsupported RandomX flags")
    })?;

    let reported_flags = if vm_flags & FLAG_JIT == 0 {
        vm_flags & !FLAG_SECURE
    } else {
        vm_flags
    };
    if strict && reported_flags != reported_requested {
        return Err(PyRuntimeError::new_err(format!(
            "strict: requested RandomX configuration unavailable \
             (requested flags {reported_requested:#x}, effective {reported_flags:#x})"
        )));
    }

    Ok(Vm {
        state: Mutex::new(VmState {
            vm,
            _cache: kept_cache,
            _dataset: dataset,
        }),
        flags: reported_flags,
        requested_flags: reported_requested,
    })
}

/// The recommended randomx_flags for this machine (parity helper).
#[pyfunction]
fn get_flags() -> c_int {
    unsafe { ffi::randomx_get_flags() }
}

#[pymodule]
fn randomx_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(RandomX, m)?)?;
    m.add_function(wrap_pyfunction!(get_flags, m)?)?;
    m.add_class::<Vm>()?;
    m.add("HASH_SIZE", HASH_SIZE)?;
    m.add("FLAG_DEFAULT", FLAG_DEFAULT)?;
    m.add("FLAG_LARGE_PAGES", FLAG_LARGE_PAGES)?;
    m.add("FLAG_HARD_AES", FLAG_HARD_AES)?;
    m.add("FLAG_FULL_MEM", FLAG_FULL_MEM)?;
    m.add("FLAG_JIT", FLAG_JIT)?;
    m.add("FLAG_SECURE", FLAG_SECURE)?;
    m.add("FLAG_ARGON2_SSSE3", FLAG_ARGON2_SSSE3)?;
    m.add("FLAG_ARGON2_AVX2", FLAG_ARGON2_AVX2)?;
    m.add("FLAG_ARGON2", FLAG_ARGON2)?;
    m.add("RANDOMX_UPSTREAM_COMMIT", RANDOMX_UPSTREAM_COMMIT)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
