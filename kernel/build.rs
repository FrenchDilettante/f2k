//! Generates the tables that derive from the system DLLs' export specs
//! (`userland/<dll>/exports.toml`, read through `tools/exportgen`): the kernel's two service tables
//! (`nt`'s `NT_SERVICES`, ntdll's system services, and `win32k`'s `WIN32K_SERVICES`, user32's
//! internal NtUser* calls, both by Windows 2000's numbers), and, for the tests
//! that check the built DLLs against the specs, kernel32's native exports' and every DLL's exports'
//! declared argument blocks, stubs and variables. The generated files land in OUT_DIR, included
//! where the tables live.
//!
//! It also points the kernel at the system DLLs the userland workspace builds (userland/):
//! ntdll.dll, which it embeds and maps into every process, and kernel32.dll, msvcrt.dll,
//! advapi32.dll and user32.dll, which its tests read (the disk image carries them for ntdll to
//! load). They are built first (`make userland`); the kernel rebuilds when they change.

use std::path::{Path, PathBuf};

/// The system DLLs the userland workspace builds, ntdll first.
const DLLS: [&str; 5] = ["ntdll", "kernel32", "msvcrt", "advapi32", "user32"];

fn main() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .expect("the kernel lives in the repository root");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    println!("cargo:rerun-if-changed=build.rs");
    let specs: Vec<(&str, exportgen::Spec)> = DLLS
        .iter()
        .map(|&dll| (dll, load(repo, &source(dll))))
        .collect();
    let specs: Vec<(&str, &exportgen::Spec)> =
        specs.iter().map(|(dll, spec)| (*dll, spec)).collect();
    exportgen::check_together(&specs)
        .unwrap_or_else(|error| panic!("the export specs disagree: {error}"));

    let (_, ntdll) = specs[0];
    write(
        &out,
        "nt_services.rs",
        exportgen::emit::nt_services(ntdll, &source("ntdll")),
    );
    write(
        &out,
        "win32k_services.rs",
        exportgen::emit::win32k_services(&specs, &source("user32")),
    );
    for &(dll, spec) in &specs[1..] {
        let source = source(dll);
        if dll == "kernel32" {
            write(
                &out,
                "kernel32_natives.rs",
                exportgen::emit::kernel_natives(spec, &source),
            );
        }
        write(
            &out,
            &format!("{dll}_exports.rs"),
            exportgen::emit::dll_exports(spec, &source),
        );
        write(
            &out,
            &format!("{dll}_stubs.rs"),
            exportgen::emit::stub_exports(spec, &source),
        );
        write(
            &out,
            &format!("{dll}_data.rs"),
            exportgen::emit::data_exports(spec, &source),
        );
    }

    let dlls = manifest.join("../target/userland/i686-f2k-pe/release");
    for dll in DLLS {
        let path = dlls.join(format!("{dll}.dll"));
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

/// A DLL's export spec, repository-relative.
fn source(dll: &str) -> String {
    format!("userland/{dll}/exports.toml")
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
