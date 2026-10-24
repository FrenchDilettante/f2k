//! user32's seam to the other system DLLs: what its code calls, imported by name as Windows 2000's
//! user32 imports it (ntdll and kernel32), and the memory probe its stub routine reads arguments
//! through (its import table holds no memory query). The host tests replace them with stand-ins of
//! the same shape ([`host`]).
//!
//! One import is not Windows 2000's: ntdll's DbgPrint, which the stub routine logs through
//! (`scripts/compat.py` tolerates exactly that one, for the stubs' log line).

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "kernel32", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// SetLastError: the calling thread's last error.
    pub fn SetLastError(code: u32);
}

#[cfg(all(target_arch = "x86", not(test)))]
#[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "C" {
    /// DbgPrint: the text the format makes, to the debugger (F2K: COM1, as `F2K: debug:` lines).
    pub fn DbgPrint(format: *const u8, ...) -> u32;
}

/// The caller's memory as the stub routine reads it: probed byte by byte.
#[cfg(all(target_arch = "x86", not(test)))]
pub use rtl::probe::Probed;

#[cfg(test)]
pub use host::*;

/// The host tests' imports: stand-ins with the imports' shapes, recording what they were given.
#[cfg(test)]
#[allow(non_snake_case)]
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

    /// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
    /// format alone), kept.
    pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const u8) -> u32 {
        // SAFETY: the caller's NUL-terminated format and text.
        let (format, text) = unsafe {
            (
                core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
                core::ffi::CStr::from_ptr(text.cast()),
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
