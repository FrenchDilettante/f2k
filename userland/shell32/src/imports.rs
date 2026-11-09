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
    unsafe { raw::DbgPrint(c"%s".as_ptr().cast(), text.as_ptr()) };
}

/// The host tests' stand-ins: the last error and the debug prints kept in thread-locals, a raise a
/// panic.
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub mod host {
    use std::cell::{Cell, RefCell};

    std::thread_local! {
        /// The calling thread's last error, as SetLastError left it.
        pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        /// The text each DbgPrint printed, in order.
        pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
    }

    pub unsafe extern "system" fn SetLastError(code: u32) {
        LAST_ERROR.with(|error| error.set(code));
    }

    pub unsafe extern "system" fn RaiseException(
        code: u32,
        flags: u32,
        _count: u32,
        _arguments: *const usize,
    ) {
        panic!("RaiseException({code:#010x}, {flags:#x})")
    }

    /// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
    /// format alone), kept.
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const core::ffi::c_char) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text),
            )
        };
        assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
        DEBUG_PRINTS.with(|prints| {
            prints
                .borrow_mut()
                .push(text.to_string_lossy().into_owned())
        });
        0
    }

    /// The host process's memory: every address the tests hand over is their own.
    pub struct Probed;

    impl rtl::stub::Memory for Probed {
        fn readable(&self, _address: usize) -> bool {
            true
        }
    }
}
