//! Builds the vendored RandomX C library (tevador/RandomX, pinned v1.1.10,
//! commit f9ae3f235183c452962edd2a15384bdc67f7a11e — see RANDOMX_PIN) plus
//! the project-owned exception shim (src/rxs_shim.cpp, review F1).
//!
//! Source selection mirrors the reference PyPI binding's proven build
//! (xloem/RandomX-Python setup.py): every .c/.cpp except JIT compilers and
//! tests, plus the JIT compiler pair for the target architecture.
//!
//! Flag policy (review F2/F8):
//! - No -march=native: wheels must be portable and reproducible across
//!   machines of one architecture.
//! - Hardware-AES intrinsics ARE compiled in (x86_64: -maes; aarch64:
//!   -march=armv8-a+crypto) — the library gates their use at runtime via
//!   cpuid/hwcaps (randomx_get_flags), so wheels still run on CPUs without
//!   AES support. Without this, RandomX silently falls back to table-based
//!   soft AES everywhere: slower for the defender (KDF-calibration
//!   regression vs the reference binding) and a classic cache-timing side
//!   channel on password-derived state.
//! - Optimized Argon2 kernels are compiled per-file (x86_64 only); their
//!   translation units self-neutralize without the flags and selection is
//!   runtime-gated either way. Output is byte-identical in all cases.
//! - -fno-fast-math -ffp-contract=off appended last: RandomX depends on
//!   exact IEEE semantics, and inherited CFLAGS/CXXFLAGS like -Ofast would
//!   silently change KDF output; such environments are rejected outright.
//!
//! Windows/MSVC note: the MASM variant of the x86 JIT assembly
//! (jit_compiler_x86_static.asm) is not wired up; an MSVC build gets the
//! interpreted VM only (byte-identical, slower). Revisit when Windows
//! wheels are actually produced.

use std::env;
use std::path::{Path, PathBuf};

const FLAG_ENV_VARS: [&str; 6] = [
    "CFLAGS",
    "CXXFLAGS",
    "TARGET_CFLAGS",
    "TARGET_CXXFLAGS",
    "HOST_CFLAGS",
    "HOST_CXXFLAGS",
];

const FORBIDDEN_FLAG_FRAGMENTS: [&str; 3] = ["fast-math", "-Ofast", "unsafe-math"];

fn reject_output_changing_env_flags() {
    for var in FLAG_ENV_VARS {
        println!("cargo:rerun-if-env-changed={var}");
        if let Ok(value) = env::var(var) {
            for fragment in FORBIDDEN_FLAG_FRAGMENTS {
                assert!(
                    !value.contains(fragment),
                    "{var} contains '{fragment}': fast-math-style flags change RandomX \
                     KDF output (byte-identity violation); refusing to build"
                );
            }
        }
    }
}

fn collect_sources(dir: &Path, c_files: &mut Vec<PathBuf>, cpp_files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read vendored RandomX_src") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if path.is_dir() {
            if name == "tests" {
                continue;
            }
            collect_sources(&path, c_files, cpp_files);
            continue;
        }
        if name.contains("jit_") {
            continue; // arch-specific JIT sources are added explicitly below
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("c") => c_files.push(path),
            Some("cpp") => cpp_files.push(path),
            _ => {}
        }
    }
}

fn main() {
    reject_output_changing_env_flags();

    let src = PathBuf::from("RandomX_src");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");

    let mut c_files: Vec<PathBuf> = Vec::new();
    let mut cpp_files: Vec<PathBuf> = Vec::new();
    let mut asm_files: Vec<PathBuf> = Vec::new();
    collect_sources(&src, &mut c_files, &mut cpp_files);

    // The optimized Argon2 kernels need their SIMD flags per translation
    // unit; they self-neutralize (impl getter returns NULL) when built into
    // a wheel that then runs on a CPU without the feature. x86_64 only.
    let argon2_simd: Vec<(PathBuf, &str)> = if arch == "x86_64" {
        vec![
            (src.join("argon2_ssse3.c"), "-mssse3"),
            (src.join("argon2_avx2.c"), "-mavx2"),
        ]
    } else {
        Vec::new()
    };
    c_files.retain(|f| !argon2_simd.iter().any(|(simd, _)| simd == f));

    // 32-bit x86 deliberately gets NO JIT pair: jit_compiler.hpp selects the
    // x86 JIT only for __x86_64__, and the .S file is x86-64-only assembly
    // (review F7). Unlisted arches fall back to the interpreted VM.
    match arch.as_str() {
        "x86_64" => {
            cpp_files.push(src.join("jit_compiler_x86.cpp"));
            asm_files.push(src.join("jit_compiler_x86_static.S"));
        }
        "aarch64" => {
            cpp_files.push(src.join("jit_compiler_a64.cpp"));
            asm_files.push(src.join("jit_compiler_a64_static.S"));
        }
        _ => {}
    }

    let define_hwcap = arch == "aarch64";
    let hard_aes_flag: Option<&str> = match arch.as_str() {
        "x86_64" => Some("-maes"),
        "aarch64" => Some("-march=armv8-a+crypto"),
        _ => None,
    };

    let mut cpp = cc::Build::new();
    cpp.cpp(true).std("c++11").opt_level(3).pic(true);
    if define_hwcap {
        cpp.define("HAVE_HWCAP", None);
    }
    if let Some(flag) = hard_aes_flag {
        cpp.flag(flag);
    }
    cpp.flag("-fno-fast-math").flag("-ffp-contract=off");
    for f in &cpp_files {
        cpp.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    cpp.file("src/rxs_shim.cpp");
    println!("cargo:rerun-if-changed=src/rxs_shim.cpp");
    cpp.include(&src).compile("randomx_cpp");

    let mut c = cc::Build::new();
    c.opt_level(3).pic(true);
    if define_hwcap {
        c.define("HAVE_HWCAP", None);
    }
    c.flag("-fno-fast-math").flag("-ffp-contract=off");
    for f in c_files.iter().chain(asm_files.iter()) {
        c.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    c.include(&src).compile("randomx_c");

    for (simd_file, simd_flag) in &argon2_simd {
        let stem = simd_file.file_stem().and_then(|s| s.to_str()).unwrap();
        let mut simd = cc::Build::new();
        simd.opt_level(3)
            .pic(true)
            .flag(simd_flag)
            .flag("-fno-fast-math")
            .flag("-ffp-contract=off")
            .file(simd_file)
            .include(&src)
            .compile(stem);
        println!("cargo:rerun-if-changed={}", simd_file.display());
    }

    println!("cargo:rerun-if-changed=build.rs");
}
