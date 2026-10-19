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
//! taken as `.dll`), export names exactly. A lookup by ordinal finds nothing: the DLLs' ordinals
//! are sequential placeholders, not the real system's.
//!
//! The kernel's loader snaps the image's imports through this table (`exec::loader`), the kernel
//! finds here the entry points it sends user code to (kernel32's BaseProcessStartThunk for a main
//! thread, ntdll's KiUserExceptionDispatcher for an exception, ntdll's thread-exit trampoline for a
//! returning child thread), and kernel32's served GetProcAddress and LoadLibraryA look the system
//! DLLs up here.
//! No other DLL loads.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::exec::pe::{
    same_module, split_forwarder, Export, Exports, ForwardTarget, Image, Unresolved,
};

/// ntdll's base and module handle.
pub const NTDLL_BASE: u32 = 0x77F8_0000;

/// kernel32's base and module handle.
pub const KERNEL32_BASE: u32 = 0x7C4E_0000;

/// The embedded system DLL files (see `kernel/build.rs`).
const NTDLL_FILE: &[u8] = include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/ntdll.dll"));
const KERNEL32_FILE: &[u8] = include_bytes!(concat!(env!("F2K_SYSTEM_DLLS"), "/kernel32.dll"));

/// A system DLL: its file name, its base, and its embedded file.
pub struct SystemDll {
    pub file_name: &'static str,
    pub base: u32,
    pub file: &'static [u8],
}

/// The system DLLs, in load order.
pub static SYSTEM_DLLS: [SystemDll; 2] = [
    SystemDll {
        file_name: "ntdll.dll",
        base: NTDLL_BASE,
        file: NTDLL_FILE,
    },
    SystemDll {
        file_name: "kernel32.dll",
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
    /// stacks (GetProcAddress, a thread's creation).
    fn export(&self, name: &str) -> Option<Export<'static>> {
        Exports::in_headers(self.file)?.by_name(self.file, name)
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
    let dll = &SYSTEM_DLLS[index];
    match dll.export(name).ok_or(Unresolved::NoEntry)? {
        Export::Address(rva) => Ok(dll.base + rva),
        Export::Forwarder(forwarder) => {
            let (module, target) = split_forwarder(forwarder).ok_or(Unresolved::NoEntry)?;
            let (ForwardTarget::Name(target), true) = (target, depth < FORWARD_DEPTH) else {
                return Err(Unresolved::NoEntry);
            };
            resolve_in(
                system_dll(module).ok_or(Unresolved::NoModule)?,
                target,
                depth + 1,
            )
        }
    }
}

/// The module table's import resolution: the address an IAT slot (or GetProcAddress) receives for
/// `name` in `module`, as an import descriptor or a forwarder spells the module.
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

/// ntdll's F2kThreadExitTrampoline (userland/ntdll/src/internal.s): a child thread's user function
/// returns onto it, and it raises the internal thread-exit service with the function's return
/// value. An F2K-internal export, found by name.
pub fn thread_exit_trampoline() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(NTDLL, "F2kThreadExitTrampoline", 0)
            .expect("ntdll exports F2kThreadExitTrampoline")
    })
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

/// kernel32's BaseProcessStartThunk (userland/kernel32/src/start.s), where every image's main thread
/// starts (EAX its entry point; see `user::main_thread_start`). An F2K-internal export: Windows
/// 2000's kernel32 exports none of its start thunks, its CreateProcess finding them in its own code
/// — F2K's kernel creates the process, and finds it by name.
pub fn process_start_thunk() -> u32 {
    static RESOLVED: AtomicU32 = AtomicU32::new(0);
    redirect_target(&RESOLVED, || {
        resolve_in(KERNEL32, "BaseProcessStartThunk", 0)
            .expect("kernel32 exports BaseProcessStartThunk")
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

/// The system DLL a module name names: a path or a bare file name, in any case, the extension
/// `.dll` when it has none (`KERNEL32`, `C:\WINNT\system32\ntdll.dll`).
pub fn module_named(name: &[u8]) -> Option<usize> {
    let file = &name[name
        .iter()
        .rposition(|&b| b == b'\\' || b == b'/')
        .map_or(0, |i| i + 1)..];
    let has_extension = file.contains(&b'.');
    SYSTEM_DLLS.iter().position(|dll| {
        let candidate = dll.file_name.as_bytes();
        if has_extension {
            file.eq_ignore_ascii_case(candidate)
        } else {
            candidate.len() == file.len() + 4
                && candidate[..file.len()].eq_ignore_ascii_case(file)
                && candidate[file.len()..].eq_ignore_ascii_case(b".dll")
        }
    })
}

/// The system DLL a module handle is (its base).
pub fn module_of(handle: u32) -> Option<usize> {
    SYSTEM_DLLS.iter().position(|dll| dll.base == handle)
}

// --- kernel32's served module exports (the export spec's `legacy` handlers) ----------------------

/// The longest module or procedure name the services read, terminator excluded (MAX_PATH less
/// its NUL).
const NAME_ROOM: usize = 259;

/// A NUL-terminated name in user memory, into `out`: its length, or none when it is unreadable or
/// longer than the room.
fn user_name(pointer: u32, out: &mut [u8; NAME_ROOM]) -> Option<usize> {
    for (length, slot) in out.iter_mut().enumerate() {
        let mut byte = [0u8];
        crate::user::syscall::read_user(pointer.checked_add(length as u32)?, &mut byte).ok()?;
        if byte[0] == 0 {
            return Some(length);
        }
        *slot = byte[0];
    }
    let mut byte = [0u8];
    crate::user::syscall::read_user(pointer.checked_add(NAME_ROOM as u32)?, &mut byte).ok()?;
    (byte[0] == 0).then_some(NAME_ROOM)
}

/// GetProcAddress: a system DLL's export, by its exact name, forwarders followed; NULL for a name
/// the DLL does not export, an ordinal (the DLLs' ordinals are not Windows 2000's yet), and a
/// handle naming no system DLL (the image exports nothing; no other module loads). The last error
/// is not set: the surface keeps none yet.
pub fn svc_get_proc_address(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (module, name) = (args[0], args[1]);
    frame.eax = 0;
    let Some(index) = module_of(module) else {
        return;
    };
    if name < 0x1_0000 {
        return;
    }
    let mut bytes = [0u8; NAME_ROOM];
    let Some(length) = user_name(name, &mut bytes) else {
        return;
    };
    if let Some(address) = core::str::from_utf8(&bytes[..length])
        .ok()
        .and_then(|name| resolve_in(index, name, 0).ok())
    {
        frame.eax = address;
    }
}

/// LoadLibraryA: a system DLL is already loaded, so loading it hands back its handle; NULL for a
/// NULL name and any other name (no other DLL loads; the image's own name is not looked at). The
/// last error is not set: the surface keeps none yet.
pub fn svc_load_library_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] == 0 {
        frame.eax = 0;
        return;
    }
    let mut bytes = [0u8; NAME_ROOM];
    frame.eax = user_name(args[0], &mut bytes)
        .and_then(|length| module_named(&bytes[..length]))
        .map_or(0, |index| SYSTEM_DLLS[index].base);
}

#[cfg(test)]
mod tests;
