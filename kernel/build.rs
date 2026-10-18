//! Generates the tables that derive from the system DLLs' export specs
//! (`userland/<dll>/exports.toml`, read through `tools/exportgen`): the kernel's service registry
//! (`compat::kernel32`'s `SERVICES`), and kernel32's native exports' and all its exports' declared
//! argument blocks, for the tests that check the built DLLs against the specs. The generated files
//! land in OUT_DIR, included where the tables live.
//!
//! It also points the kernel at the system DLLs it embeds (userland/: ntdll.dll and kernel32.dll,
//! mapped into every process). They are built first, by the userland workspace (`make userland`);
//! the kernel rebuilds when they change.

use std::path::{Path, PathBuf};

fn main() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .expect("the kernel lives in the repository root");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    println!("cargo:rerun-if-changed=build.rs");
    let kernel32 = load(repo, "userland/kernel32/exports.toml");
    let ntdll = load(repo, "userland/ntdll/exports.toml");
    exportgen::check_together(&[("kernel32", &kernel32), ("ntdll", &ntdll)])
        .unwrap_or_else(|error| panic!("the export specs disagree: {error}"));

    let source = "userland/kernel32/exports.toml";
    // The registry runs across both DLLs: ntdll's RtlUnwind is a served export too.
    write(
        &out,
        "kernel32_services.rs",
        exportgen::emit::kernel_services(&[&kernel32, &ntdll], "userland/<dll>/exports.toml"),
    );
    write(
        &out,
        "kernel32_natives.rs",
        exportgen::emit::kernel_natives(&kernel32, source),
    );
    write(
        &out,
        "kernel32_exports.rs",
        exportgen::emit::dll_exports(&kernel32, source),
    );

    let dlls = manifest.join("../target/userland/i686-f2k-pe/release");
    for dll in ["ntdll.dll", "kernel32.dll"] {
        let path = dlls.join(dll);
        if !path.exists() {
            panic!(
                "{} is missing: build the system DLLs first (`make userland`, or \
                 `cd userland && cargo build --release`)",
                path.display()
            );
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rustc-env=F2K_SYSTEM_DLLS={}", dlls.display());
}

fn load(repo: &Path, relative: &str) -> exportgen::Spec {
    let path = repo.join(relative);
    println!("cargo:rerun-if-changed={}", path.display());
    exportgen::load(&path).unwrap_or_else(|error| panic!("the export spec does not read: {error}"))
}

fn write(out: &Path, name: &str, text: String) {
    let path = out.join(name);
    std::fs::write(&path, text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}
