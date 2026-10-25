// Shared by the build scripts of F2K's own programs (`include!`d): link the crate's binary as a
// Win32 console program with the header MSVC 6's linker writes for one (the corpus's programs,
// built with it on Windows 2000, carry the same fields), so it loads on F2K and on Windows 2000
// alike. Its imports are the runtime crate's (userland/exe): kernel32's alone.

/// The program's entry point, the runtime's (`exe::entry!`): a cdecl function, as MSVC's
/// `mainCRTStartup` is, that never returns.
const ENTRY: &str = "f2k_start";

/// Link the crate's binary as a console program at the executables' base, 0x00400000.
fn build_exe() {
    println!("cargo:rerun-if-changed=../build-support/exe.rs");
    for arg in [
        format!("/ENTRY:{ENTRY}"),
        // A console program for Windows NT 4.0 and later, as MSVC 6 marks one (the target's own
        // /SUBSYSTEM and /OSVERSION, a DLL's, come first: the last one given counts).
        "/SUBSYSTEM:CONSOLE,4.0".to_string(),
        "/OSVERSION:4.0".to_string(),
        "/BASE:0x400000".to_string(),
        // No relocations: the image loads at its base, the first thing in its address space.
        "/FIXED".to_string(),
        // File offsets equal RVAs, as in the DLLs and in MSVC 6's images.
        "/FILEALIGN:0x1000".to_string(),
        // Windows 2000-era characteristics (rustc's own /NXCOMPAT precedes these).
        "/NXCOMPAT:NO".to_string(),
        "/SAFESEH:NO".to_string(),
        // Not marked Terminal Server aware, as MSVC 6 leaves a program.
        "/TSAWARE:NO".to_string(),
    ] {
        println!("cargo:rustc-link-arg-bins={arg}");
    }
}
