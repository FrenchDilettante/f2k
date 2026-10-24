// Shared by the system DLLs' build scripts (`include!`d): generate the DLL's assembly constants,
// system-service stubs and .def from the export specs (userland/<dll>/exports.toml, through
// tools/exportgen), then link it as a DLL at its base.
//
// Symbol conventions the .def maps to export names (exportgen's `nt_stub_symbol` / `hand_symbol`):
// - `_f2k_nt_<Export>`: a system service's generated stub in ntdll (mov eax,N; lea edx,[esp+4];
//   int 2Eh; ret <argument bytes>), N its Windows 2000 number; the .def exports it under its `Nt`
//   and its `Zw` name.
// - `_f2k_export_<Export>`: a hand-written export in the crate's assembly sources (a `.globl` line
//   names it) or its Rust sources (an `export_name = "f2k_export_<Export>"` stdcall function); they
//   must be exactly the spec's natives. A stubbed export's body is generated (`exports.rs`, which
//   the crate includes: exportgen's `dll_rust`) under the same symbol.
// An export the spec forwards (`impl = { forward = "NTDLL.X" }`) becomes a forwarder.

use std::path::{Path, PathBuf};

/// The system DLLs whose specs are read and checked together (a forward names another's export).
const DLLS: [&str; 5] = ["kernel32", "ntdll", "msvcrt", "advapi32", "user32"];

/// The hand-written exports a source declares: an assembly source's `.globl _f2k_export_<Name>`
/// lines, a Rust source's `#[unsafe(export_name = "f2k_export_<Name>")]` functions (stdcall: the
/// linker matches the .def's undecorated name to the decorated `_f2k_export_<Name>@N`).
fn hand_exports(source: &Path) -> Vec<String> {
    let text =
        std::fs::read_to_string(source).unwrap_or_else(|e| panic!("{}: {e}", source.display()));
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix(".globl _f2k_export_").or_else(|| {
                l.strip_prefix("#[unsafe(export_name = \"f2k_export_")?
                    .strip_suffix("\")]")
            })
        })
        .map(|name| name.trim().to_string())
        .collect()
}

/// The Rust sources under `dir`, recursively, in a stable order.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

/// Generate `dll`'s build inputs into OUT_DIR and link it: `consts.s` (the kernel ABI constants as
/// `.set`s), `stubs.s` (its system services' stubs), `exports.rs` (its exports' descriptions and
/// its stubbed exports' bodies), and the .def (the hand-written exports of `asm_sources` and the
/// Rust sources, the stubbed exports, the system services' stubs, and its forwarders). `entry`
/// names its entry point (a stdcall `DllMain`-shaped function the loader calls with each
/// DLL_PROCESS_ and DLL_THREAD_ reason), or none: the image has no entry point.
fn build_dll(dll: &str, base: u32, entry: Option<&str>, asm_sources: &[&str]) {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let repo = manifest.join("../..");
    println!("cargo:rerun-if-changed=../build-support/stubs.rs");

    let specs: Vec<(&str, exportgen::Spec)> = DLLS
        .iter()
        .map(|&name| {
            let path = manifest.join(format!("../{name}/exports.toml"));
            println!("cargo:rerun-if-changed={}", path.display());
            (
                name,
                exportgen::load(&path)
                    .unwrap_or_else(|e| panic!("the export spec does not read: {e}")),
            )
        })
        .collect();
    let specs: Vec<(&str, &exportgen::Spec)> =
        specs.iter().map(|(name, spec)| (*name, spec)).collect();
    exportgen::check_together(&specs).unwrap_or_else(|e| panic!("the export specs disagree: {e}"));

    for relative in ["kernel/src/user/syscall.rs", "kernel/src/user/teb.rs"] {
        println!("cargo:rerun-if-changed={}", repo.join(relative).display());
    }
    let constants = exportgen::abi::kernel_constants(&repo).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(out.join("consts.s"), exportgen::abi::consts_s(&constants)).unwrap();
    std::fs::write(out.join("stubs.s"), exportgen::emit::dll_stubs(&specs, dll)).unwrap();
    let source = format!("userland/{dll}/exports.toml");
    std::fs::write(out.join("exports.rs"), exportgen::emit::dll_rust(&specs, dll, &source)).unwrap();

    let mut hand = Vec::new();
    for source in asm_sources {
        let path = manifest.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        hand.extend(hand_exports(&path));
    }
    for path in rust_sources(&manifest.join("src")) {
        println!("cargo:rerun-if-changed={}", path.display());
        hand.extend(hand_exports(&path));
    }
    let def = exportgen::emit::dll_def(&specs, dll, &hand).unwrap_or_else(|e| panic!("{e}"));
    let def_path = out.join(format!("{dll}.def"));
    std::fs::write(&def_path, def).unwrap();

    for arg in [
        "/DLL".to_string(),
        // ntdll's loader calls a DLL's entry point when its image has one (ntdll's and kernel32's
        // have none).
        match entry {
            Some(symbol) => format!("/ENTRY:{symbol}"),
            None => "/NOENTRY".to_string(),
        },
        format!("/DEF:{}", def_path.display()),
        format!("/BASE:{base:#x}"),
        // File offsets equal RVAs: the kernel reads the embedded file (ntdll's) as the mapped
        // image. A DLL with zero-initialized data alone in its writable section has no file bytes
        // for it, and the sections after it start a page earlier in the file.
        "/FILEALIGN:0x1000".to_string(),
        // Windows 2000-era characteristics (rustc's own /NXCOMPAT precedes these).
        "/NXCOMPAT:NO".to_string(),
        "/SAFESEH:NO".to_string(),
        // Every export keeps its own code: identical bodies are not folded into one address.
        "/OPT:NOICF".to_string(),
    ] {
        println!("cargo:rustc-link-arg-bins={arg}");
    }
}
