// Project-owned exception shim over the vendored RandomX C API (review F1).
//
// The vendored library throws std::runtime_error from page-protection
// failures (virtual_memory.cpp: mprotect/VirtualProtect), and with
// RANDOMX_FLAG_SECURE the W^X toggling runs on EVERY hash
// (vm_compiled.cpp: enableWriting/enableExecution). randomx_calculate_hash,
// randomx_init_cache and randomx_init_dataset have no internal try/catch,
// and a C++ exception unwinding into a Rust extern "C" frame is undefined
// behavior (in practice: process abort mid-KDF). These wrappers convert any
// C++ exception into a -1 return the Rust side maps to a Python exception.
//
// RandomX_src/ stays verbatim (see RANDOMX_PIN); this shim is project code.

#include <cstddef>

#include "randomx.h"

// glibc thread cancellation unwinds with abi::__forced_unwind; a bare
// catch(...) that does not rethrow it would convert cancellation into
// std::terminate. Not reachable from CPython threads today, but guard anyway.
#if defined(__GLIBCXX__) || defined(__GLIBCPP__)
#include <cxxabi.h>
#define RXS_RETHROW_FORCED_UNWIND catch (abi::__forced_unwind &) { throw; }
#else
#define RXS_RETHROW_FORCED_UNWIND
#endif

extern "C" {

int rxs_init_cache(randomx_cache *cache, const void *key, size_t key_size) {
    try {
        randomx_init_cache(cache, key, key_size);
        return 0;
    } RXS_RETHROW_FORCED_UNWIND catch (...) {
        return -1;
    }
}

int rxs_calculate_hash(randomx_vm *machine, const void *input, size_t input_size,
                       void *output) {
    try {
        randomx_calculate_hash(machine, input, input_size, output);
        return 0;
    } RXS_RETHROW_FORCED_UNWIND catch (...) {
        return -1;
    }
}

int rxs_init_dataset(randomx_dataset *dataset, randomx_cache *cache,
                     unsigned long start_item, unsigned long item_count) {
    try {
        randomx_init_dataset(dataset, cache, start_item, item_count);
        return 0;
    } RXS_RETHROW_FORCED_UNWIND catch (...) {
        return -1;
    }
}

}  // extern "C"
