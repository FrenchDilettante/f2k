//! shell32's seam to the other system DLLs: what its code calls, imported by name as Windows 2000's
//! shell32 imports it (kernel32), and the memory probe its stub routine reads arguments through.
//! The host tests replace the imports with stand-ins of the same shape ([`host`]).
//!
//! Each import is wrapped once here in a safe function; the only `unsafe` the rest of the DLL's
//! code reaches for an import is here. One import is not Windows 2000's: ntdll's DbgPrint, which
//! the stub routine logs through (`scripts/compat.py` tolerates exactly that one, for the stubs'
//! log line).

use core::ffi::CStr;

#[cfg(all(target_arch = "x86", not(test)))]
mod raw {
    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        /// SetLastError: the calling thread's last error.
        pub fn SetLastError(code: u32);
        /// RaiseException: an exception raised with the code, flags and arguments (a
        /// noncontinuable one does not return).
        pub fn RaiseException(code: u32, flags: u32, count: u32, arguments: *const usize);
    }

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "C" {
        /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:`
        /// lines).
        pub fn DbgPrint(format: *const u8, ...) -> u32;
    }
}

#[cfg(test)]
use host as raw;
#[cfg(test)]
pub use host::Probed;
/// The caller's memory as the stub routine reads it: probed byte by byte (Windows 2000's
/// shell32 imports IsBadReadPtr, but the probe needs no import).
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

// --- kernel32 ------------------------------------------------------------------------------------

/// SetLastError: the calling thread's last error.
pub fn set_last_error(code: u32) {
    // SAFETY: no pointers; it writes the thread's own TEB.
    unsafe { raw::SetLastError(code) }
}

/// RaiseException: `code` raised with `flags` and `arguments` (a noncontinuable exception does not
/// return to its raiser).
pub fn raise_exception(code: u32, flags: u32, arguments: &[usize]) {
    // SAFETY: the call reads the arguments' count of them.
    unsafe { raw::RaiseException(code, flags, arguments.len() as u32, arguments.as_ptr()) }
}

// --- ntdll ---------------------------------------------------------------------------------------

/// DbgPrint of `text`, as is (through `"%s"`).
pub fn debug_print(text: &CStr) {
    // SAFETY: the format and the text are NUL-terminated; the format takes the one string.
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr().cast::<u8>()) };
}

/// The host tests' stand-ins, rtl's ([`rtl::host`]): the last error and the debug prints kept in
/// thread-locals, a raise a panic.
#[cfg(test)]
pub mod host {
    pub use rtl::host::{DbgPrint, Probed, RaiseException, SetLastError, DEBUG_PRINTS, LAST_ERROR};
}
