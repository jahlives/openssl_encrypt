//! Builds the vendored RandomX C library (tevador/RandomX, pinned v1.1.10,
//! commit f9ae3f235183c452962edd2a15384bdc67f7a11e — see RANDOMX_PIN).
//!
//! Source selection mirrors the reference PyPI binding's proven build
//! (xloem/RandomX-Python setup.py): every .c/.cpp except JIT compilers and
//! tests, plus the JIT compiler pair for the target architecture. No
//! -march=native: wheels must be portable and reproducible across machines
//! of one architecture.

use std::env;
use std::path::{Path, PathBuf};

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
    let src = PathBuf::from("RandomX_src");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");

    let mut c_files: Vec<PathBuf> = Vec::new();
    let mut cpp_files: Vec<PathBuf> = Vec::new();
    let mut asm_files: Vec<PathBuf> = Vec::new();
    collect_sources(&src, &mut c_files, &mut cpp_files);

    match arch.as_str() {
        "x86_64" | "x86" => {
            cpp_files.push(src.join("jit_compiler_x86.cpp"));
            asm_files.push(src.join("jit_compiler_x86_static.S"));
        }
        "aarch64" => {
            cpp_files.push(src.join("jit_compiler_a64.cpp"));
            asm_files.push(src.join("jit_compiler_a64_static.S"));
        }
        // Other architectures build without a JIT compiler; RandomX falls
        // back to the (byte-identical, slower) interpreted VM at runtime.
        _ => {}
    }

    let define_hwcap = arch == "aarch64";

    let mut cpp = cc::Build::new();
    cpp.cpp(true).std("c++11").opt_level(3).pic(true);
    if define_hwcap {
        cpp.define("HAVE_HWCAP", None);
    }
    for f in &cpp_files {
        cpp.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    cpp.include(&src).compile("randomx_cpp");

    let mut c = cc::Build::new();
    c.opt_level(3).pic(true);
    if define_hwcap {
        c.define("HAVE_HWCAP", None);
    }
    for f in c_files.iter().chain(asm_files.iter()) {
        c.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    c.include(&src).compile("randomx_c");

    println!("cargo:rerun-if-changed=build.rs");
}
