//! RandomX KDF Python bindings for openssl-encrypt (gitlab#285).
//!
//! Wraps the official tevador/RandomX C library, vendored and pinned at the
//! v1.1.10 tag (commit f9ae3f235183c452962edd2a15384bdc67f7a11e) — the exact
//! version the reference PyPI binding vendors — so KDF output stays
//! byte-identical to files encrypted with that binding.
//!
//! API contract (matching the surface openssl_encrypt uses):
//!   vm = RandomX(key, full_mem=False)   # plus secure/large_pages/threads
//!   digest = vm.calculate_hash(data)    # -> 32 bytes
//!
//! Security posture (deliberate divergences from the reference binding):
//! - SECURE (W^X JIT pages) is requested by DEFAULT; opt out explicitly.
//! - An empty key is refused (ValueError) — an empty KDF key is always a bug.
//! - Key and message copies live in zeroizing buffers wiped on drop.
//! - The VM is internally serialized (Mutex): concurrent use from Python
//!   threads cannot corrupt the non-thread-safe C VM.
//! - Failed allocations degrade flags exactly like the reference binding
//!   (drop JIT, then optimized Argon2), but the VM is created with the flags
//!   the cache was ACTUALLY allocated with, never with stale requested flags.

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyMemoryError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::os::raw::{c_int, c_ulong, c_void};
use std::ptr::NonNull;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Commit of the vendored tevador/RandomX tree (tag v1.1.10). See RANDOMX_PIN.
const RANDOMX_UPSTREAM_COMMIT: &str = "f9ae3f235183c452962edd2a15384bdc67f7a11e";
const HASH_SIZE: usize = 32;

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
        pub fn randomx_init_cache(
            cache: *mut randomx_cache,
            key: *const c_void,
            key_size: usize,
        );
        pub fn randomx_release_cache(cache: *mut randomx_cache);
        pub fn randomx_alloc_dataset(flags: c_int) -> *mut randomx_dataset;
        pub fn randomx_dataset_item_count() -> c_ulong;
        pub fn randomx_init_dataset(
            dataset: *mut randomx_dataset,
            cache: *mut randomx_cache,
            start_item: c_ulong,
            item_count: c_ulong,
        );
        pub fn randomx_release_dataset(dataset: *mut randomx_dataset);
        pub fn randomx_create_vm(
            flags: c_int,
            cache: *mut randomx_cache,
            dataset: *mut randomx_dataset,
        ) -> *mut randomx_vm;
        pub fn randomx_destroy_vm(vm: *mut randomx_vm);
        pub fn randomx_calculate_hash(
            vm: *mut randomx_vm,
            input: *const c_void,
            input_size: usize,
            output: *mut c_void,
        );
    }
}

/// Owned RandomX cache; released on drop.
struct Cache(NonNull<ffi::randomx_cache>);
// SAFETY: the cache pointer is only ever used behind &self after full
// initialization; RandomX caches are immutable once initialized.
unsafe impl Send for Cache {}
impl Drop for Cache {
    fn drop(&mut self) {
        unsafe { ffi::randomx_release_cache(self.0.as_ptr()) };
    }
}

/// Owned RandomX dataset; released on drop.
struct Dataset(NonNull<ffi::randomx_dataset>);
// SAFETY: as for Cache — immutable after initialization.
unsafe impl Send for Dataset {}
impl Drop for Dataset {
    fn drop(&mut self) {
        unsafe { ffi::randomx_release_dataset(self.0.as_ptr()) };
    }
}

struct VmState {
    vm: NonNull<ffi::randomx_vm>,
    // Held only to keep the C structures alive as long as the VM lives;
    // dropped (and released) after the VM itself is destroyed.
    _cache: Cache,
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
fn buffer_to_zeroizing(obj: &Bound<'_, PyAny>) -> PyResult<Zeroizing<Vec<u8>>> {
    let buffer = PyBuffer::<u8>::get(obj)?;
    Ok(Zeroizing::new(buffer.to_vec(obj.py())?))
}

/// A RandomX virtual machine bound to one key.
#[pyclass(module = "randomx_native", name = "VM")]
struct Vm {
    state: Mutex<VmState>,
    flags: c_int,
}

#[pymethods]
impl Vm {
    /// The effective randomx_flags this VM runs with.
    #[getter]
    fn flags(&self) -> c_int {
        self.flags
    }

    /// Calculate the 32-byte RandomX hash of `input`.
    fn calculate_hash<'py>(
        &self,
        py: Python<'py>,
        input: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = buffer_to_zeroizing(input)?;
        let mut output = Zeroizing::new([0u8; HASH_SIZE]);
        let state_mutex = &self.state;
        let in_addr = data.as_ptr() as usize;
        let in_len = data.len();
        let out_addr = output.as_mut_ptr() as usize;
        // The Mutex MUST be taken inside the detached (GIL-free) section:
        // locking it while holding the GIL deadlocks against a second thread
        // that holds the GIL while waiting for the Mutex. Addresses are
        // passed as usize because detach requires a Send closure.
        let locked = py.detach(move || match state_mutex.lock() {
            Ok(state) => {
                // SAFETY: pointers are valid for the duration of the call;
                // the Mutex guarantees exclusive access to the C VM.
                unsafe {
                    ffi::randomx_calculate_hash(
                        state.vm.as_ptr(),
                        in_addr as *const c_void,
                        in_len,
                        out_addr as *mut c_void,
                    )
                };
                true
            }
            Err(_) => false,
        });
        if !locked {
            return Err(PyRuntimeError::new_err("RandomX VM lock poisoned"));
        }
        Ok(PyBytes::new(py, &output[..]))
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
fn alloc_cache_with_fallback(requested: c_int) -> PyResult<(Cache, c_int)> {
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
    Err(PyMemoryError::new_err(
        "could not allocate the RandomX cache",
    ))
}

/// Create a RandomX VM for `key`.
///
/// Mirrors the reference binding's convenience constructor. `secure`
/// defaults to True here (W^X JIT pages) — a deliberate hardening
/// divergence; RandomX output is identical either way.
#[pyfunction]
#[pyo3(signature = (key, full_mem=false, secure=true, large_pages=false, threads=0))]
#[allow(non_snake_case)]
fn RandomX(
    py: Python<'_>,
    key: &Bound<'_, PyAny>,
    full_mem: bool,
    secure: bool,
    large_pages: bool,
    threads: usize,
) -> PyResult<Vm> {
    let key_bytes = buffer_to_zeroizing(key)?;
    if key_bytes.is_empty() {
        return Err(PyValueError::new_err(
            "RandomX key must not be empty",
        ));
    }

    let mut requested = unsafe { ffi::randomx_get_flags() };
    if full_mem {
        requested |= FLAG_FULL_MEM;
    }
    if secure {
        requested |= FLAG_SECURE;
    }
    if large_pages {
        requested |= FLAG_LARGE_PAGES;
    }

    let (cache, effective) = alloc_cache_with_fallback(requested)?;
    {
        let cache_addr = cache.0.as_ptr() as usize;
        let key_addr = key_bytes.as_ptr() as usize;
        let key_len = key_bytes.len();
        // SAFETY: cache is freshly allocated; key buffer outlives the call.
        // Addresses are passed as usize because detach requires Send.
        py.detach(move || unsafe {
            ffi::randomx_init_cache(
                cache_addr as *mut ffi::randomx_cache,
                key_addr as *const c_void,
                key_len,
            )
        });
    }

    let dataset = if full_mem {
        let ptr = unsafe { ffi::randomx_alloc_dataset(effective) };
        let dataset = NonNull::new(ptr).map(Dataset).ok_or_else(|| {
            PyMemoryError::new_err("could not allocate the RandomX dataset (2080 MB)")
        })?;
        let item_count = unsafe { ffi::randomx_dataset_item_count() };
        let workers = if threads > 0 {
            threads as c_ulong
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get() as c_ulong)
                .unwrap_or(1)
        }
        .min(item_count.max(1));
        let dataset_ptr = dataset.0.as_ptr() as usize;
        let cache_ptr = cache.0.as_ptr() as usize;
        py.detach(|| {
            std::thread::scope(|scope| {
                let mut start: c_ulong = 0;
                for worker in 0..workers {
                    let count = if worker == workers - 1 {
                        item_count - start
                    } else {
                        item_count / workers
                    };
                    let begin = start;
                    scope.spawn(move || {
                        // SAFETY: disjoint item ranges; randomx_init_dataset
                        // is safe for concurrent non-overlapping ranges.
                        unsafe {
                            ffi::randomx_init_dataset(
                                dataset_ptr as *mut ffi::randomx_dataset,
                                cache_ptr as *mut ffi::randomx_cache,
                                begin,
                                count,
                            )
                        };
                    });
                    start += count;
                }
            });
        });
        Some(dataset)
    } else {
        None
    };

    let dataset_ptr = dataset
        .as_ref()
        .map(|d| d.0.as_ptr())
        .unwrap_or(std::ptr::null_mut());

    let mut vm_flags = effective;
    let mut vm_ptr = unsafe { ffi::randomx_create_vm(vm_flags, cache.0.as_ptr(), dataset_ptr) };
    if vm_ptr.is_null() && (vm_flags & FLAG_JIT) != 0 {
        // Fall back to the interpreted VM (no JIT pages at all) rather than
        // silently dropping only the W^X protection.
        vm_flags &= !(FLAG_JIT | FLAG_SECURE);
        vm_ptr = unsafe { ffi::randomx_create_vm(vm_flags, cache.0.as_ptr(), dataset_ptr) };
    }
    let vm = NonNull::new(vm_ptr).ok_or_else(|| {
        PyMemoryError::new_err("out of memory or unsupported RandomX flags")
    })?;

    Ok(Vm {
        state: Mutex::new(VmState {
            vm,
            _cache: cache,
            _dataset: dataset,
        }),
        flags: vm_flags,
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
