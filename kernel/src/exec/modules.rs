//! Modules: the system DLLs every process maps, and the resolution of the image's imports against
//! them.
//!
//! The system DLLs are real PE images built by the userland workspace (userland/: ntdll.dll and
//! kernel32.dll), embedded in the kernel and mapped into every process at their preferred bases
//! (the bases Windows 2000 gives them; kernel32's was measured on the capture machine,
//! tests/hello/trace.txt), in Windows 2000's load order: ntdll, then kernel32. A module's handle is
//! its base.
//!
//! Exports come from the DLLs' real export directories, read from the embedded files: the DLLs are
//! linked with file offsets equal to their RVAs, so each file is its mapped image (its zero tail
//! aside), and the kernel reads kernel-owned bytes a program cannot revoke. A forwarder
//! (kernel32's RtlUnwind names NTDLL.RtlUnwind) resolves in the module it names. Names compare as
//! the platform compares them: module names without regard to case (a name without an extension is
//! taken as `.dll`), export names exactly. A forwarder splits at its first dot and may name its
//! target by ordinal (`MODULE.#n`). The DLLs' ordinals are their export specs' numbering, not
//! Windows 2000's.
//!
//! The kernel's loader snaps the image's imports through this table (`exec::loader`), and the
//! kernel finds here the entry points it sends user code to (kernel32's BaseProcessStartThunk for a
//! main thread, ntdll's LdrInitializeThunk for every thread's start, KiUserExceptionDispatcher for
//! an exception and KiUserApcDispatcher for a user APC). The Win32 module calls are kernel32's and
//! ntdll's own code (GetModuleHandleA and the rest over LdrGetDllHandle and the rest), over the
//! PEB's module lists the kernel builds at the process's creation (`user::ldr`). Any other DLL is
//! ntdll's to load at run time (LdrLoadDll, over an image section: `nt::section`), its imports
//! snapped in user mode against the lists.

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

/// kernel32's base and module handle.
pub const KERNEL32_BASE: u32 = 0x7C4E_0000;

/// kernel32's full path, as its module list entry (and GetModuleFileNameA) gives it.
pub const KERNEL32_PATH: &[u8] = b"C:\\WINNT\\system32\\KERNEL32.DLL";

/// ntdll's full path, as its module list entry (and GetModuleFileNameA) gives it.
pub const NTDLL_PATH: &[u8] = b"C:\\WINNT\\system32\\ntdll.dll";

/// The embedded system DLL files (see `kernel/build.rs`).
const NTDLL_FILE: &[u8] = include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/ntdll.dll"));
const KERNEL32_FILE: &[u8] = include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/kernel32.dll"));

/// A system DLL: its file name, its full path, its base, and its embedded file.
pub struct SystemDll {
    pub file_name: &'static str,
    pub path: &'static [u8],
    pub base: u32,
    pub file: &'static [u8],
}

/// The system DLLs, in load order.
pub static SYSTEM_DLLS: [SystemDll; 2] = [
    SystemDll {
        file_name: "ntdll.dll",
        path: NTDLL_PATH,
        base: NTDLL_BASE,
        file: NTDLL_FILE,
    },
    SystemDll {
        file_name: "kernel32.dll",
        path: KERNEL32_PATH,
        base: KERNEL32_BASE,
        file: KERNEL32_FILE,
    },
];

/// ntdll's and kernel32's places in [`SYSTEM_DLLS`].
pub const NTDLL: usize = 0;
pub const KERNEL32: usize = 1;

/// A DLL file's SizeOfImage, at build time (the system regions reserve the images' extents).
const fn size_of_image(file: &[u8]) -> u32 {
    let lfanew = u32::from_le_bytes([file[0x3C], file[0x3D], file[0x3E], file[0x3F]]) as usize;
    // The PE signature, the 20-byte file header, then the optional header: SizeOfImage at +56.
    let at = lfanew + 4 + 20 + 56;
    u32::from_le_bytes([file[at], file[at + 1], file[at + 2], file[at + 3]])
}

/// The system DLLs' image sizes.
pub const NTDLL_SIZE: u32 = size_of_image(NTDLL_FILE);
pub const KERNEL32_SIZE: u32 = size_of_image(KERNEL32_FILE);

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

/// The system DLL `name` (as an import descriptor or a forwarder spells it) designates.
fn system_dll(name: &str) -> Option<usize> {
    SYSTEM_DLLS
        .iter()
        .position(|dll| same_module(name, dll.file_name))
}

/// The address of the entry point `name` that system DLL `index` exports, its forwarders followed.
pub(crate) fn resolve_in(index: usize, name: &str, depth: u32) -> Result<u32, Unresolved> {
    resolve_target(index, ForwardTarget::Name(name), depth)
}

/// The address of `target` (a name or an ordinal) in system DLL `index`, its forwarders followed
/// (each one split at its first dot).
fn resolve_target(index: usize, target: ForwardTarget, depth: u32) -> Result<u32, Unresolved> {
    let dll = &SYSTEM_DLLS[index];
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

/// The module table's import resolution: the address an IAT slot receives for `name` in `module`,
/// as an import descriptor or a forwarder spells the module.
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
/// unoptimized kernel; the DLLs are embedded and mapped at their fixed bases, so an address holds
/// for the whole boot.
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

/// kernel32's BaseProcessStartThunk (userland/kernel32/src/start.s), where every image's main
/// thread starts (EAX its entry point; see `user::main_thread_start`). An F2K-internal export:
/// Windows 2000's kernel32 exports none of its start thunks, its CreateProcess finding them in its
/// own code — F2K's kernel creates the process, and finds it by name.
pub fn process_start_thunk() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(KERNEL32, "BaseProcessStartThunk", 0)
            .expect("kernel32 exports BaseProcessStartThunk")
    })
}

/// ntdll's LdrInitializeThunk: a fresh thread's first user-mode work, delivered over its initial
/// context like a user APC (see `user::apc::deliver_initialization`).
pub fn ldr_initialize_thunk() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(NTDLL, "LdrInitializeThunk", 0).expect("ntdll exports LdrInitializeThunk")
    })
}

/// ntdll's KiUserApcDispatcher: a user APC's delivery enters user mode there (see
/// [`crate::user::apc`]).
pub fn apc_dispatcher() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(NTDLL, "KiUserApcDispatcher", 0).expect("ntdll exports KiUserApcDispatcher")
    })
}

/// ntdll's KiUserExceptionDispatcher: an exception's dispatch enters user mode there (see
/// [`crate::user::seh`]).
pub fn exception_dispatcher() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(NTDLL, "KiUserExceptionDispatcher", 0)
            .expect("ntdll exports KiUserExceptionDispatcher")
    })
}

#[cfg(test)]
mod tests {
    //! The system DLLs as the kernel embeds them: the module table's images and resolution, the
    //! built DLLs against the export specs (the natives, the forwarders), and the import
    //! surface of the corpus binaries the kernel runs.

    use super::*;

    // `NATIVE_EXPORTS`: kernel32's native exports (its user-mode code), (export, argument bytes),
    // as the spec declares them.
    include!(concat!(env!("OUT_DIR"), "/kernel32_natives.rs"));

    // `DLL_EXPORTS`: every export kernel32's table carries, from its export spec.
    include!(concat!(env!("OUT_DIR"), "/kernel32_exports.rs"));

    /// The embedded system DLLs: i386 DLL images at their bases, clear of each other and of kernel
    /// space, with file offsets equal to RVAs (the export reads rely on it: the file is the mapped
    /// image, its zero tail aside), and no entry point (no DllMain runs).
    #[test]
    fn the_system_dlls_are_images_at_their_bases() {
        let sizes = [NTDLL_SIZE, KERNEL32_SIZE];
        for (dll, size) in SYSTEM_DLLS.iter().zip(sizes) {
            let image = dll.image();
            assert!(image.is_dll(), "{}", dll.file_name);
            assert_eq!(image.image_base, dll.base, "{}", dll.file_name);
            assert_eq!(image.size_of_image, size, "{}", dll.file_name);
            assert!(dll.base as u64 + size as u64 <= crate::mem::paging::KERNEL_BASE as u64);
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
        assert!(NTDLL_BASE + NTDLL_SIZE <= KERNEL32_BASE);
    }

    /// Exports resolve by exact name, kernel32's forwarder lands in ntdll, unknown names and
    /// modules do not resolve, and the kernel's internal entry point exists (in ntdll only:
    /// kernel32's surface carries Windows 2000's names alone).
    #[test]
    fn exports_resolve_through_the_module_table() {
        let exit = resolve("KERNEL32.dll", "ExitProcess").unwrap();
        assert!((KERNEL32_BASE..KERNEL32_BASE + KERNEL32_SIZE).contains(&exit));
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

    /// The bytes at `address` in the system DLL holding it, as the embedded file holds them.
    fn bytes_at(address: u32) -> &'static [u8] {
        let dll = SYSTEM_DLLS
            .iter()
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
        assert_eq!(NATIVE_EXPORTS.len(), 174);
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
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(
            addresses.len(),
            NATIVE_EXPORTS.len() + 2,
            "every export has its own code"
        );
    }

    /// The entry points the kernel sends user code to keep their protocols: ntdll's exception
    /// dispatcher calls its body with the two pointers the kernel left on top (it never returns: a
    /// `ud2` follows), its APC dispatcher calls the routine the kernel left on top, then resumes
    /// the context above it, and its LdrInitializeThunk runs its body, then resumes the same;
    /// kernel32's start thunks clear EBP and push their registers (the main thread's entry
    /// point; a child's parameter, then its start address) under a zero return address, then
    /// jump to their bodies. The exception-filter natives address the top-level filter's slot
    /// in the PEB page.
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
        // its body's call, then NtContinue(context, TRUE).
        let ldr = bytes_at(ldr_initialize_thunk());
        assert_eq!(&ldr[..4], &[0x8D, 0x7C, 0x24, 0x10], "LdrInitializeThunk");
        assert_eq!(ldr[4], 0xE8, "LdrInitializeThunk: its body's call");
        assert_eq!(
            &ldr[9..12],
            &[0x6A, 0x01, 0x57],
            "LdrInitializeThunk: NtContinue(context, TRUE)"
        );
        assert_eq!(ldr[12], 0xE8, "LdrInitializeThunk: NtContinue's call");
        assert_eq!(
            Some(ldr_initialize_thunk()),
            resolve("ntdll.dll", "LdrInitializeThunk").ok()
        );
        let thunk = bytes_at(process_start_thunk());
        assert_eq!(
            &thunk[..5],
            &[0x31, 0xED, 0x50, 0x6A, 0x00],
            "BaseProcessStartThunk"
        );
        assert!(
            matches!(thunk[5], 0xE9 | 0xEB),
            "BaseProcessStartThunk: a jump"
        );
        assert_eq!(
            Some(process_start_thunk()),
            kernel32_export("BaseProcessStartThunk")
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
        ("bare", include_bytes!("../../../tests/bare/bare.exe")),
        ("files", include_bytes!("../../../tests/files/files.exe")),
        (
            "fswrite",
            include_bytes!("../../../tests/fswrite/fswrite.exe"),
        ),
        ("memory", include_bytes!("../../../tests/memory/memory.exe")),
        (
            "runtime",
            include_bytes!("../../../tests/runtime/runtime.exe"),
        ),
        ("sched", include_bytes!("../../../tests/sched/sched.exe")),
        ("sync", include_bytes!("../../../tests/sync/sync.exe")),
        (
            "threads",
            include_bytes!("../../../tests/threads/threads.exe"),
        ),
        ("exit0", include_bytes!("../../../tests/exit0/exit0.exe")),
        ("ret0", include_bytes!("../../../tests/ret0/ret0.exe")),
        ("hello", include_bytes!("../../../tests/hello/hello.exe")),
    ];

    /// A binary's imports, as (module, name), read through the loader's own import walk.
    fn imports_of(file: &[u8]) -> Vec<(String, String)> {
        let image = Image::parse(file).expect("the fixture parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let mut imports = Vec::new();
        image.snap_imports(file, &mut mapped, |module, name| {
            imports.push((module.to_string(), name.to_string()));
            Ok(0)
        });
        imports
    }

    /// kernel32 exports exactly what the corpus binaries import: every import of every corpus
    /// binary resolves, and every export is imported by some corpus binary. The export names
    /// are unique.
    #[test]
    fn the_surface_is_the_corpus_import_surface() {
        let names: Vec<&str> = DLL_EXPORTS.iter().map(|&(name, _)| name).collect();
        assert_eq!(names.len(), 184, "the corpus's import surface");
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
                imported.iter().any(|import| import == name),
                "{name} is exported but no corpus binary imports it"
            );
        }
    }

    /// Each corpus binary snaps every import through the module table: the counts are each binary's
    /// import surface (ret0's 35, hello's 40 — ret0's plus the console-stdio group).
    #[test]
    fn the_corpus_snaps_fully_against_the_module_table() {
        for (fixture, thunks) in [("ret0", 35), ("hello", 40)] {
            let (_, file) = CORPUS.iter().find(|(name, _)| *name == fixture).unwrap();
            let image = Image::parse(file).expect("the fixture parses");
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(file, &mut mapped);
            let result = image.snap_imports(file, &mut mapped, crate::exec::loader::resolve_import);
            assert_eq!(result.thunks, thunks, "{fixture}");
        }
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
        let dll = &SYSTEM_DLLS[KERNEL32];
        let exports = Exports::in_headers(dll.file).unwrap();
        let ordinal = (0..exports.num_functions)
            .map(|slot| exports.ordinal_base + slot)
            .find(|&ordinal| {
                exports.by_ordinal(dll.file, ordinal) == exports.by_name(dll.file, "ExitProcess")
            })
            .expect("ExitProcess has an ordinal");
        assert_eq!(
            resolve_target(KERNEL32, ForwardTarget::Ordinal(ordinal), 0),
            resolve("KERNEL32.dll", "ExitProcess")
        );
        let past = exports.ordinal_base + exports.num_functions;
        assert_eq!(
            resolve_target(KERNEL32, ForwardTarget::Ordinal(past), 0),
            Err(Unresolved::NoEntry)
        );
        assert_eq!(
            resolve_target(
                KERNEL32,
                ForwardTarget::Ordinal(exports.ordinal_base.wrapping_sub(1)),
                0
            ),
            Err(Unresolved::NoEntry)
        );
    }
}
