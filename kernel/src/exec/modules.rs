//! Modules: the system DLL the kernel maps into every process, ntdll, and the entry points the
//! kernel sends user code to.
//!
//! The kernel maps a process's image and ntdll, as Windows 2000's does; every other DLL, kernel32
//! included, is ntdll's to load from the volume (its process initialization, LdrInitializeThunk on
//! the first thread: `userland/ntdll/src/loader.rs`), which builds the PEB's module lists and snaps
//! the imports in user mode. ntdll is a real PE image built by the userland workspace (userland/),
//! embedded in the kernel and mapped into every process at its preferred base (Windows 2000's,
//! 0x77F80000; images are never relocated). A module's handle is its base.
//!
//! The kernel finds the entry points it sends user code to by name: ntdll's LdrInitializeThunk for
//! every thread's start, KiUserExceptionDispatcher for an exception and KiUserApcDispatcher for a
//! user APC, read from the embedded file's export directory (the DLL is linked with file offsets
//! equal to its RVAs, so the file is its mapped image, its zero tail aside, and the kernel reads
//! kernel-owned bytes a program cannot revoke); and kernel32's BaseProcessStartThunk for a main
//! thread, as a parent's CreateProcess starts one on Windows 2000, read once at boot from the
//! export directory of kernel32.dll on the boot volume, under the system root
//! ([`kernel32_volume_path`], [`process_start_in`]): kernel32 always maps at its preferred base,
//! never relocated, so the thunk is that base plus the export's RVA in every process. A program
//! that does not import kernel32 still starts there, with no kernel32 mapped: out of scope (every
//! program the corpus runs imports it).
//!
//! Names compare as the platform compares them: module names without regard to case (a name
//! without an extension is taken as `.dll`), export names exactly. A forwarder splits at its first
//! dot and may name its target by ordinal (`MODULE.#n`). The DLLs' ordinals are their export specs'
//! numbering, not Windows 2000's. The tests resolve in kernel32 too, as the userland build left it
//! (`target/userland/`): the built DLLs against their export specs and the corpus's imports.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::exec::pe::{
    same_module,
    split_forwarder,
    Export,
    Exports,
    ForwardTarget,
    Image,
    Unresolved,
};

/// ntdll's base and module handle.
pub const NTDLL_BASE: u32 = 0x77F8_0000;

/// The embedded ntdll.dll (see `kernel/build.rs`).
const NTDLL_FILE: &[u8] = include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/ntdll.dll"));

/// A system DLL: its file name, its base, and its file.
pub struct SystemDll {
    pub file_name: &'static str,
    pub base: u32,
    pub file: &'static [u8],
}

/// ntdll, the DLL every process maps.
pub static NTDLL: SystemDll = SystemDll {
    file_name: "ntdll.dll",
    base: NTDLL_BASE,
    file: NTDLL_FILE,
};

/// kernel32's base, as the tests read the built DLL (the kernel reads it from the file on the
/// volume).
#[cfg(test)]
pub const KERNEL32_BASE: u32 = 0x7C4E_0000;

/// kernel32, as the userland build left it: the tests check it against its spec and the corpus.
#[cfg(test)]
pub static KERNEL32: SystemDll = SystemDll {
    file_name: "kernel32.dll",
    base: KERNEL32_BASE,
    file: include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/kernel32.dll")),
};

/// A DLL file's SizeOfImage, at build time (the system regions reserve the image's extent).
const fn size_of_image(file: &[u8]) -> u32 {
    let lfanew = u32::from_le_bytes([file[0x3C], file[0x3D], file[0x3E], file[0x3F]]) as usize;
    // The PE signature, the 20-byte file header, then the optional header: SizeOfImage at +56.
    let at = lfanew + 4 + 20 + 56;
    u32::from_le_bytes([file[at], file[at + 1], file[at + 2], file[at + 3]])
}

/// ntdll's image size.
pub const NTDLL_SIZE: u32 = size_of_image(NTDLL_FILE);

impl SystemDll {
    /// The DLL's parsed headers. The files are the build's own output, checked by the host tests.
    pub fn image(&self) -> Image {
        Image::parse(self.file)
            .unwrap_or_else(|reject| panic!("{} does not parse: {reject:?}", self.file_name))
    }

    /// The export named `name`, as the DLL's export directory holds it. Read from the headers
    /// alone, not through a parsed [`Image`]: the lookup runs on system services' small gate
    /// stacks (a thread's creation).
    fn export(&self, name: &str) -> Option<Export<'static>> {
        Exports::in_headers(self.file)?.by_name(self.file, name)
    }

    /// The export with ordinal `ordinal` (biased by the directory's base), read as [`Self::export`]
    /// reads names.
    fn export_by_ordinal(&self, ordinal: u32) -> Option<Export<'static>> {
        Exports::in_headers(self.file)?.by_ordinal(self.file, ordinal)
    }
}

/// How many forwarders a resolution follows before it is refused (a cycle in the DLLs' build).
const FORWARD_DEPTH: u32 = 4;

/// The DLLs a resolution reaches: ntdll, and in the tests kernel32 too.
#[cfg(not(test))]
static SYSTEM_DLLS: [&SystemDll; 1] = [&NTDLL];
#[cfg(test)]
static SYSTEM_DLLS: [&SystemDll; 2] = [&NTDLL, &KERNEL32];

/// The DLL `name` (as an import descriptor or a forwarder spells it) designates.
fn system_dll(name: &str) -> Option<&'static SystemDll> {
    SYSTEM_DLLS
        .iter()
        .copied()
        .find(|dll| same_module(name, dll.file_name))
}

/// The address of the entry point `name` that `dll` exports, its forwarders followed.
pub(crate) fn resolve_in(dll: &SystemDll, name: &str, depth: u32) -> Result<u32, Unresolved> {
    resolve_target(dll, ForwardTarget::Name(name), depth)
}

/// The address of `target` (a name or an ordinal) in `dll`, its forwarders followed (each one
/// split at its first dot).
fn resolve_target(dll: &SystemDll, target: ForwardTarget, depth: u32) -> Result<u32, Unresolved> {
    let export = match target {
        ForwardTarget::Name(name) => dll.export(name),
        ForwardTarget::Ordinal(ordinal) => dll.export_by_ordinal(ordinal),
    };
    match export.ok_or(Unresolved::NoEntry)? {
        Export::Address(rva) => Ok(dll.base + rva),
        Export::Forwarder(forwarder) => {
            let (module, target) = split_forwarder(forwarder).ok_or(Unresolved::NoEntry)?;
            if depth >= FORWARD_DEPTH {
                return Err(Unresolved::NoEntry);
            }
            resolve_target(
                system_dll(module).ok_or(Unresolved::NoModule)?,
                target,
                depth + 1,
            )
        }
    }
}

/// The address `name` in `module` resolves to, as an import descriptor or a forwarder spells the
/// module.
#[cfg(test)]
pub fn resolve(module: &str, name: &str) -> Result<u32, Unresolved> {
    resolve_in(system_dll(module).ok_or(Unresolved::NoModule)?, name, 0)
}

/// The module name kernel32's imports resolve against; the PE import descriptor must name it
/// (ASCII-case-insensitively).
#[cfg(test)]
pub const KERNEL32_NAME: &str = "KERNEL32.dll";

/// Resolve a kernel32 export name to its code's address in kernel32.dll (a forwarder followed into
/// ntdll). Exact match: export names are case-sensitive.
#[cfg(test)]
pub fn kernel32_export(name: &str) -> Option<u32> {
    resolve(KERNEL32_NAME, name).ok()
}

/// An entry point the kernel redirects user code to, resolved once into `slot` (0: not yet).
/// Resolving one parses a DLL's export directory, which takes most of a clock tick in the
/// unoptimized kernel; ntdll is embedded and mapped at its fixed base, so an address holds for the
/// whole boot.
fn redirect_target(slot: &AtomicU32, resolve: impl FnOnce() -> u32) -> u32 {
    match slot.load(Ordering::Relaxed) {
        0 => {
            let address = resolve();
            slot.store(address, Ordering::Relaxed);
            address
        }
        address => address,
    }
}

/// kernel32.dll's path on the boot volume, root-relative: `<system root>\system32\kernel32.dll`,
/// the system root's drive (`C:\`) dropped, into `out`: its length.
pub fn kernel32_volume_path(out: &mut [u8; 64]) -> usize {
    let root = &crate::user::shared::NT_SYSTEM_ROOT[3..];
    let file = b"\\system32\\kernel32.dll";
    out[..root.len()].copy_from_slice(root);
    out[root.len()..root.len() + file.len()].copy_from_slice(file);
    root.len() + file.len()
}

/// Why kernel32's start thunk could not be found in its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartThunkError {
    /// The file is no image the loader parses.
    NotAnImage,
    /// The image does not fit the staging it is mapped into.
    TooLarge,
    /// It exports no BaseProcessStartThunk (or forwards it).
    NoExport,
}

/// The address of BaseProcessStartThunk in the kernel32 image `file`, as every process maps it: the
/// image's preferred base plus the export's RVA, read from its export directory with the image
/// mapped into `staging`.
pub fn process_start_in(file: &[u8], staging: &mut [u8]) -> Result<u32, StartThunkError> {
    let image = Image::parse(file).map_err(|_| StartThunkError::NotAnImage)?;
    let mapped = staging
        .get_mut(..image.size_of_image as usize)
        .ok_or(StartThunkError::TooLarge)?;
    mapped.fill(0);
    image.map_into(file, mapped);
    match Exports::in_headers(mapped).and_then(|exports| exports.by_name(mapped, START_THUNK)) {
        Some(Export::Address(rva)) => Ok(image.image_base + rva),
        _ => Err(StartThunkError::NoExport),
    }
}

/// kernel32's start thunk for a main thread, by its export name.
const START_THUNK: &str = "BaseProcessStartThunk";

/// kernel32's BaseProcessStartThunk, once found at boot ([`set_process_start_thunk`]).
static PROCESS_START: AtomicU32 = AtomicU32::new(0);

/// Record where kernel32's BaseProcessStartThunk is (the boot's reading of kernel32.dll,
/// `exec::loader::locate_process_start`).
pub fn set_process_start_thunk(address: u32) {
    PROCESS_START.store(address, Ordering::Relaxed);
}

/// kernel32's BaseProcessStartThunk (userland/kernel32/src/start.s), where every image's main
/// thread starts (EAX its entry point; see `user::main_thread_start`). An F2K-internal export:
/// Windows 2000's kernel32 exports none of its start thunks, its CreateProcess finding them in its
/// own code — F2K's kernel creates the process, and finds it by name, at boot.
pub fn process_start_thunk() -> u32 {
    let address = PROCESS_START.load(Ordering::Relaxed);
    assert_ne!(address, 0, "kernel32's start thunk is found at boot");
    address
}

/// ntdll's LdrInitializeThunk: a fresh thread's first user-mode work, delivered over its initial
/// context like a user APC (see `user::apc::deliver_initialization`).
pub fn ldr_initialize_thunk() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(&NTDLL, "LdrInitializeThunk", 0).expect("ntdll exports LdrInitializeThunk")
    })
}

/// ntdll's KiUserApcDispatcher: a user APC's delivery enters user mode there (see
/// [`crate::user::apc`]).
pub fn apc_dispatcher() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(&NTDLL, "KiUserApcDispatcher", 0).expect("ntdll exports KiUserApcDispatcher")
    })
}

/// ntdll's KiUserExceptionDispatcher: an exception's dispatch enters user mode there (see
/// [`crate::user::seh`]).
pub fn exception_dispatcher() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(&NTDLL, "KiUserExceptionDispatcher", 0)
            .expect("ntdll exports KiUserExceptionDispatcher")
    })
}

#[cfg(test)]
mod tests {
    //! The system DLLs as the userland build left them: ntdll as the kernel embeds it, kernel32 as
    //! the volume carries it; their images, the resolution of their exports, the built DLLs against
    //! the export specs (the natives, the forwarders), and the import surface of the corpus
    //! binaries the kernel runs, resolved as ntdll's loader resolves it.

    use rtl::modules::{self as ldr, Memory, MemoryMut};

    use super::*;

    // `NATIVE_EXPORTS`: kernel32's native exports (its user-mode code), (export, argument bytes),
    // as the spec declares them.
    include!(concat!(env!("OUT_DIR"), "/kernel32_natives.rs"));

    // `DLL_EXPORTS`: every export kernel32's table carries that it implements, from its export
    // spec.
    include!(concat!(env!("OUT_DIR"), "/kernel32_exports.rs"));

    // `STUB_EXPORTS`: the exports kernel32's table carries whose generated bodies fail (programs
    // load against them).
    include!(concat!(env!("OUT_DIR"), "/kernel32_stubs.rs"));

    /// The system DLLs: i386 DLL images at their bases, clear of each other and of kernel space,
    /// with file offsets equal to RVAs (the export reads rely on it: the file is the mapped image,
    /// its zero tail aside), and no entry point (the loader calls none for them), ntdll importing
    /// nothing (the kernel maps it as it is).
    #[test]
    fn the_system_dlls_are_images_at_their_bases() {
        for dll in [&NTDLL, &KERNEL32] {
            let image = dll.image();
            assert!(image.is_dll(), "{}", dll.file_name);
            assert_eq!(image.image_base, dll.base, "{}", dll.file_name);
            assert!(
                dll.base as u64 + image.size_of_image as u64
                    <= crate::mem::paging::KERNEL_BASE as u64
            );
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(dll.file, &mut mapped);
            let shared = dll.file.len().min(mapped.len());
            assert!(
                mapped[..shared] == dll.file[..shared],
                "{}: the file is its mapped image",
                dll.file_name
            );
            assert_eq!(
                image.entry_va(),
                dll.base,
                "{}: no entry point",
                dll.file_name
            );
        }
        assert_eq!(NTDLL.image().size_of_image, NTDLL_SIZE);
        assert!(NTDLL_BASE + NTDLL_SIZE <= KERNEL32_BASE);
        assert_eq!(imports_of(NTDLL.file), [], "ntdll imports nothing");
        assert!(
            imports_of(KERNEL32.file)
                .iter()
                .all(|(module, _)| module.eq_ignore_ascii_case("ntdll.dll")),
            "kernel32 imports ntdll alone"
        );
    }

    /// kernel32's path on the volume comes from the system root, and the start thunk read from its
    /// file is the export's address as kernel32 maps in every process.
    #[test]
    fn the_start_thunk_is_found_in_kernel32s_file() {
        let mut path = [0u8; 64];
        let length = kernel32_volume_path(&mut path);
        assert_eq!(&path[..length], b"WINNT\\system32\\kernel32.dll");
        let mut staging = vec![0u8; 0x8_0000];
        let thunk = process_start_in(KERNEL32.file, &mut staging).unwrap();
        assert_eq!(Some(thunk), kernel32_export(START_THUNK));
        assert!((KERNEL32_BASE..KERNEL32_BASE + KERNEL32.image().size_of_image).contains(&thunk));
        assert_eq!(
            process_start_in(KERNEL32.file, &mut staging[..0x1000]),
            Err(StartThunkError::TooLarge)
        );
        assert_eq!(
            process_start_in(NTDLL.file, &mut staging),
            Err(StartThunkError::NoExport),
            "ntdll exports no start thunk"
        );
        assert_eq!(
            process_start_in(b"MZ", &mut staging),
            Err(StartThunkError::NotAnImage)
        );
    }

    /// Exports resolve by exact name, kernel32's forwarder lands in ntdll, unknown names and
    /// modules do not resolve, and the kernel's internal entry point exists (in ntdll only:
    /// kernel32's surface carries Windows 2000's names alone).
    #[test]
    fn exports_resolve_through_the_module_table() {
        let kernel32_size = KERNEL32.image().size_of_image;
        let exit = resolve("KERNEL32.dll", "ExitProcess").unwrap();
        assert!((KERNEL32_BASE..KERNEL32_BASE + kernel32_size).contains(&exit));
        assert_eq!(resolve("kernel32", "ExitProcess"), Ok(exit));
        assert_eq!(kernel32_export("ExitProcess"), Some(exit));
        assert_eq!(
            resolve("KERNEL32.dll", "exitprocess"),
            Err(Unresolved::NoEntry)
        );
        assert_eq!(
            resolve("USER32.dll", "MessageBoxA"),
            Err(Unresolved::NoModule)
        );
        let unwind = resolve("KERNEL32.dll", "RtlUnwind").unwrap();
        assert_eq!(resolve("ntdll.dll", "RtlUnwind"), Ok(unwind));
        assert!(
            (NTDLL_BASE..NTDLL_BASE + NTDLL_SIZE).contains(&unwind),
            "the forwarder resolves in ntdll"
        );
        // The thread-exit trampoline is gone: every thread's start routine returns into kernel32's
        // start frame, which calls ExitThread.
        assert_eq!(
            resolve("ntdll", "F2kThreadExitTrampoline"),
            Err(Unresolved::NoEntry)
        );
        assert_eq!(
            Some(ldr_initialize_thunk()),
            resolve("ntdll", "LdrInitializeThunk").ok(),
            "the cache holds the export"
        );
    }

    /// The bytes at `address` in the system DLL holding it, as its file holds them.
    fn bytes_at(address: u32) -> &'static [u8] {
        let dll = [&NTDLL, &KERNEL32]
            .into_iter()
            .find(|dll| address >= dll.base && ((address - dll.base) as usize) < dll.file.len())
            .unwrap_or_else(|| panic!("{address:#x} lies in no system DLL"));
        &dll.file[(address - dll.base) as usize..]
    }

    /// kernel32's surface is its own code: every native export, and the start thunks, has its own
    /// code (no two share an address). A DLL built from another version of the specs fails
    /// here.
    #[test]
    fn every_export_has_its_own_code() {
        let mut addresses = Vec::new();
        // The natives: kernel32's own code (the trivial ones, the exception filter and the pointer
        // probes its assembly, the TLS slots' reads and writes; the console, start-up, locale,
        // clock, virtual-memory, mapping, synchronization, timer, sleep, APC, affinity,
        // TLS-index, environment, file (the write side's included), current-directory and
        // module calls and RaiseException its Rust, the heap and Local/Global calls its own
        // over ntdll's heap). The internal start thunks are not among them.
        assert_eq!(NATIVE_EXPORTS.len(), 217);
        for &(name, _) in &NATIVE_EXPORTS {
            let address =
                kernel32_export(name).unwrap_or_else(|| panic!("kernel32 exports no {name}"));
            addresses.push(address);
        }
        for thunk in ["BaseProcessStartThunk", "BaseThreadStartThunk"] {
            addresses.push(
                kernel32_export(thunk).unwrap_or_else(|| panic!("kernel32 exports no {thunk}")),
            );
        }
        // The stubs' generated bodies: each its own, handing its own export's description on.
        for &(name, _) in &STUB_EXPORTS {
            addresses.push(
                kernel32_export(name).unwrap_or_else(|| panic!("kernel32 exports no {name}")),
            );
        }
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(
            addresses.len(),
            NATIVE_EXPORTS.len() + 2 + STUB_EXPORTS.len(),
            "every export has its own code"
        );
    }

    /// The entry points the kernel sends user code to keep their protocols: ntdll's exception
    /// dispatcher calls its body with the two pointers the kernel left on top (it never returns: a
    /// `ud2` follows), its APC dispatcher calls the routine the kernel left on top, then resumes
    /// the context above it, and its LdrInitializeThunk runs its body over the context, then
    /// resumes the same; kernel32's start thunks clear EBP and push their registers (the main
    /// thread's entry point; a child's parameter, then its start address) under a zero return
    /// address, then jump to their bodies. The exception-filter natives address the top-level
    /// filter's slot in the PEB page.
    #[test]
    fn the_entry_points_keep_their_protocols() {
        let dispatcher = bytes_at(exception_dispatcher());
        assert_eq!(dispatcher[0], 0xE8, "KiUserExceptionDispatcher: a call");
        assert_eq!(
            &dispatcher[5..7],
            &[0x0F, 0x0B],
            "KiUserExceptionDispatcher: then ud2"
        );
        assert_eq!(
            Some(exception_dispatcher()),
            resolve("ntdll.dll", "KiUserExceptionDispatcher").ok()
        );
        // The APC dispatcher keeps the context's address (past the four-word call frame) in EDI,
        // pops and calls the routine, then NtContinue(context, TRUE); a failed one's status
        // is raised.
        let apc = bytes_at(apc_dispatcher());
        assert_eq!(
            &apc[..10],
            &[0x8D, 0x7C, 0x24, 0x10, 0x58, 0xFF, 0xD0, 0x6A, 0x01, 0x57],
            "KiUserApcDispatcher"
        );
        assert_eq!(apc[10], 0xE8, "KiUserApcDispatcher: NtContinue's call");
        assert_eq!(apc[15], 0x50, "KiUserApcDispatcher: then the status pushed");
        assert_eq!(crate::user::apc::CALL_WORDS * 4, 0x10);
        // LdrInitializeThunk keeps the context's address (past the same call frame) in EDI across
        // its body's call, which takes it, then NtContinue(context, TRUE).
        let ldr = bytes_at(ldr_initialize_thunk());
        assert_eq!(
            &ldr[..5],
            &[0x8D, 0x7C, 0x24, 0x10, 0x57],
            "LdrInitializeThunk"
        );
        assert_eq!(ldr[5], 0xE8, "LdrInitializeThunk: its body's call");
        assert_eq!(
            &ldr[10..16],
            &[0x83, 0xC4, 0x04, 0x6A, 0x01, 0x57],
            "LdrInitializeThunk: NtContinue(context, TRUE)"
        );
        assert_eq!(ldr[16], 0xE8, "LdrInitializeThunk: NtContinue's call");
        assert_eq!(
            Some(ldr_initialize_thunk()),
            resolve("ntdll.dll", "LdrInitializeThunk").ok()
        );
        let thunk = bytes_at(kernel32_export("BaseProcessStartThunk").unwrap());
        assert_eq!(
            &thunk[..5],
            &[0x31, 0xED, 0x50, 0x6A, 0x00],
            "BaseProcessStartThunk"
        );
        assert!(
            matches!(thunk[5], 0xE9 | 0xEB),
            "BaseProcessStartThunk: a jump"
        );
        let thunk = bytes_at(kernel32_export("BaseThreadStartThunk").unwrap());
        assert_eq!(
            &thunk[..6],
            &[0x31, 0xED, 0x53, 0x50, 0x6A, 0x00],
            "BaseThreadStartThunk"
        );
        assert!(
            matches!(thunk[6], 0xE9 | 0xEB),
            "BaseThreadStartThunk: a jump"
        );
        let slot = crate::user::teb::peb_offset::TOP_LEVEL_FILTER.to_le_bytes();
        for name in ["SetUnhandledExceptionFilter", "UnhandledExceptionFilter"] {
            let body = bytes_at(kernel32_export(name).unwrap());
            assert!(body[..32].windows(4).any(|w| w == slot), "{name}");
        }
    }

    /// The corpus binaries (the smokes in the root directory, the sectioned fixtures in \CORPUS):
    /// the import surface kernel32 exports.
    const CORPUS: [(&str, &[u8]); 11] = [
        ("bare", include_bytes!("../../../tests/core/bare/bare.exe")),
        (
            "files",
            include_bytes!("../../../tests/kernel32/files/files.exe"),
        ),
        (
            "fswrite",
            include_bytes!("../../../tests/kernel32/fswrite/fswrite.exe"),
        ),
        (
            "memory",
            include_bytes!("../../../tests/kernel32/memory/memory.exe"),
        ),
        (
            "runtime",
            include_bytes!("../../../tests/kernel32/runtime/runtime.exe"),
        ),
        (
            "sched",
            include_bytes!("../../../tests/kernel32/sched/sched.exe"),
        ),
        (
            "sync",
            include_bytes!("../../../tests/kernel32/sync/sync.exe"),
        ),
        (
            "threads",
            include_bytes!("../../../tests/kernel32/threads/threads.exe"),
        ),
        (
            "exit0",
            include_bytes!("../../../tests/core/exit0/exit0.exe"),
        ),
        ("ret0", include_bytes!("../../../tests/core/ret0/ret0.exe")),
        (
            "hello",
            include_bytes!("../../../tests/core/hello/hello.exe"),
        ),
    ];

    /// The exports kernel32 implements ahead of the corpus binary that imports them: a fixture
    /// declared before its real-machine build (tests/kernel32/dllmain, awaited). Once its program
    /// is checked in, it joins [`CORPUS`] (its companion DLLs' imports aside) and these leave.
    const AWAITED: [&str; 1] = ["DisableThreadLibraryCalls"];

    /// A binary's imports, as (module, name), read through the PE parser's import walk.
    fn imports_of(file: &[u8]) -> Vec<(String, String)> {
        let image = Image::parse(file).expect("the binary parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let mut imports = Vec::new();
        image.snap_imports(file, &mut mapped, |module, name| {
            imports.push((module.to_string(), name.to_string()));
            Ok(0)
        });
        imports
    }

    /// kernel32 implements exactly what the corpus binaries import: every import of every corpus
    /// binary resolves, and every export it implements is imported by some corpus binary (its
    /// stubs are for programs outside the corpus; the awaited fixtures' exports wait for theirs).
    /// The export names are unique.
    #[test]
    fn the_surface_is_the_corpus_import_surface() {
        let names: Vec<&str> = DLL_EXPORTS.iter().map(|&(name, _)| name).collect();
        assert_eq!(names.len(), 226, "the corpus's import surface");
        for (i, name) in names.iter().enumerate() {
            assert!(!names[i + 1..].contains(name), "{name} listed twice");
            assert!(
                kernel32_export(name).is_some(),
                "kernel32.dll does not export {name}"
            );
        }
        let mut imported: Vec<String> = Vec::new();
        for (fixture, file) in CORPUS {
            for (module, name) in imports_of(file) {
                assert!(
                    module.eq_ignore_ascii_case(KERNEL32_NAME),
                    "{fixture} imports {module}"
                );
                assert!(
                    kernel32_export(&name).is_some(),
                    "{fixture} imports {name}, which is not exported"
                );
                imported.push(name);
            }
        }
        for name in names {
            assert!(
                imported.iter().any(|import| import == name) || AWAITED.contains(&name),
                "{name} is exported but no corpus binary imports it"
            );
        }
        for name in AWAITED {
            assert!(
                !imported.iter().any(|import| import == name),
                "{name} has its corpus binary: it leaves AWAITED"
            );
        }
    }

    /// A process's memory as ntdll's process initialization leaves it, modelled: the DLLs mapped at
    /// their bases, and a heap region holding the lists it builds.
    struct Process {
        regions: Vec<(u32, Vec<u8>)>,
    }

    impl Memory for Process {
        fn byte(&self, at: u32) -> u8 {
            for (base, bytes) in &self.regions {
                if at >= *base && ((at - base) as usize) < bytes.len() {
                    return bytes[(at - base) as usize];
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    impl MemoryMut for Process {
        fn set_word(&mut self, at: u32, value: u32) {
            for (base, bytes) in &mut self.regions {
                if at >= *base && ((at - *base) as usize) + 4 <= bytes.len() {
                    let offset = (at - *base) as usize;
                    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                    return;
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    /// Where the modelled heap holds the lists.
    const HEAP: u32 = 0x0010_0000;

    /// ntdll's and kernel32's images mapped, and their entries in the lists, as ntdll's process
    /// initialization builds them (`rtl::modules`): ntdll, then kernel32 once its imports are
    /// snapped.
    fn process() -> Process {
        let mut regions: Vec<(u32, Vec<u8>)> = [&NTDLL, &KERNEL32]
            .into_iter()
            .map(|dll| {
                let image = dll.image();
                let mut mapped = vec![0u8; image.size_of_image as usize];
                image.map_into(dll.file, &mut mapped);
                (dll.base, mapped)
            })
            .collect();
        regions.push((HEAP, ldr::empty_lists(HEAP).to_vec()));
        regions[2].1.resize(0x1000, 0);
        let mut process = Process { regions };
        for (index, (dll, path)) in [
            (&NTDLL, "C:\\WINNT\\system32\\ntdll.dll"),
            (&KERNEL32, "C:\\WINNT\\system32\\KERNEL32.dll"),
        ]
        .into_iter()
        .enumerate()
        {
            let at = HEAP + 0x100 + 0x200 * index as u32;
            let units: Vec<u16> = path.encode_utf16().collect();
            let buffer = at + 0x100;
            let module = ldr::loaded(&process, dll.base, None);
            let entry = ldr::loaded_entry(at, &module, buffer, &units, 2 * units.len() as u32 + 2);
            let heap = &mut process.regions[2].1;
            let offset = (at - HEAP) as usize;
            heap[offset..offset + entry.len()].copy_from_slice(&entry);
            let start = (buffer - HEAP) as usize;
            for (index, unit) in units.iter().enumerate() {
                heap[start + 2 * index..start + 2 * index + 2].copy_from_slice(&unit.to_le_bytes());
            }
            ldr::insert(&mut process, HEAP, at);
            ldr::insert_initialized(&mut process, HEAP, at);
        }
        process
    }

    /// The corpus's imports resolve in user mode, through ntdll's own lookups over the lists, where
    /// the DLLs' export directories say: every import of every corpus binary names an export the
    /// built kernel32 carries, kernel32's forwarders landing in ntdll. ret0 imports 35 entry points
    /// and hello 40 (ret0's and the console-stdio group).
    #[test]
    fn the_corpus_resolves_in_user_mode() {
        let process = process();
        let names = |name: &str| -> u32 {
            let units: Vec<u16> = name.encode_utf16().collect();
            let mut formed = [0u16; 32];
            let length = ldr::module_name(&units, &mut formed).unwrap();
            let entry = ldr::by_name(&process, HEAP, &formed[..length]).unwrap();
            process.word(entry + ldr::entry::DLL_BASE)
        };
        assert_eq!(names("KERNEL32.dll"), KERNEL32_BASE);
        assert_eq!(names("ntdll"), NTDLL_BASE);
        for (fixture, file) in CORPUS {
            let imports = imports_of(file);
            for (module, name) in &imports {
                assert_eq!(
                    ldr::procedure_address(&process, HEAP, names(module), name.as_bytes()),
                    resolve(module, name).map_err(|_| 0),
                    "{fixture}: {module}!{name}"
                );
            }
            match fixture {
                "ret0" => assert_eq!(imports.len(), 35),
                "hello" => assert_eq!(imports.len(), 40),
                _ => {}
            }
        }
        let initialized: Vec<u32> = ldr::initialization_order(&process, HEAP, false)
            .map(|entry| process.word(entry + ldr::entry::DLL_BASE))
            .collect();
        assert_eq!(initialized, [NTDLL_BASE, KERNEL32_BASE]);
    }

    /// The module name matches the corpus's import descriptors.
    #[test]
    fn module_name_is_kernel32() {
        assert_eq!(KERNEL32_NAME, "KERNEL32.dll");
    }

    /// A lookup by ordinal lands where the lookup by name does: kernel32's ExitProcess by the
    /// ordinal its name table gives it, and an ordinal outside the directory's range is no
    /// entry.
    #[test]
    fn ordinals_resolve_through_the_export_directory() {
        let dll = &KERNEL32;
        let exports = Exports::in_headers(dll.file).unwrap();
        let ordinal = (0..exports.num_functions)
            .map(|slot| exports.ordinal_base + slot)
            .find(|&ordinal| {
                exports.by_ordinal(dll.file, ordinal) == exports.by_name(dll.file, "ExitProcess")
            })
            .expect("ExitProcess has an ordinal");
        assert_eq!(
            resolve_target(dll, ForwardTarget::Ordinal(ordinal), 0),
            resolve("KERNEL32.dll", "ExitProcess")
        );
        let past = exports.ordinal_base + exports.num_functions;
        assert_eq!(
            resolve_target(dll, ForwardTarget::Ordinal(past), 0),
            Err(Unresolved::NoEntry)
        );
        assert_eq!(
            resolve_target(
                dll,
                ForwardTarget::Ordinal(exports.ordinal_base.wrapping_sub(1)),
                0
            ),
            Err(Unresolved::NoEntry)
        );
    }
}
