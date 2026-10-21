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
mod tests;
