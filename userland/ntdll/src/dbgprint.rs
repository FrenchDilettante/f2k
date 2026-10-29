//! DbgPrint's body (its cdecl entry is src/dbgprint.s): the format's text, made by `rtl::printf`
//! over the caller's variable arguments, handed to the kernel's debugger channel (the internal
//! service SYS_DEBUG_PRINT: the kernel writes it to COM1). Windows 2000's DbgPrint hands its text
//! to the kernel debugger, and with none attached it goes nowhere; F2K's log keeps it.
//!
//! A conversion the formatter does not serve (floating point, `%n`) is the stub path: nothing of
//! the format is printed, the stub line names the conversion, and the answer is
//! STATUS_NOT_IMPLEMENTED.

use rtl::printf::{self, Args, Unsupported};
use rtl::stub::Line;

use crate::service;
use crate::stub::{self, Mapped};

/// The caller's variable arguments, in place on its stack, a dword at a time.
struct Stack(*const u32);

impl Args for Stack {
    fn next_u32(&mut self) -> u32 {
        // SAFETY: the caller pushed an argument for each conversion its format holds.
        let value = unsafe { self.0.read_unaligned() };
        // SAFETY: the next argument's place.
        self.0 = unsafe { self.0.add(1) };
        value
    }

    fn next_u64(&mut self) -> u64 {
        let low = u64::from(self.next_u32());
        low | u64::from(self.next_u32()) << 32
    }

    fn next_ptr(&mut self) -> usize {
        self.next_u32() as usize
    }
}

/// Hand `text` to the debugger's channel.
pub fn print(text: &[u8]) {
    service::debug_print(text);
}

/// DbgPrint's body: STATUS_SUCCESS, or the stub path's answer.
#[unsafe(no_mangle)]
extern "C" fn f2k_dbg_print(format: *const u8, args: *const u32) -> u32 {
    // SAFETY: the caller's NUL-terminated format (a bad one faults the caller, as on Windows).
    let text = unsafe { core::ffi::CStr::from_ptr(format.cast()) }.to_bytes();
    let mut line = Line::new();
    match printf::format(text, &mut Stack(args), &Mapped, &mut line) {
        Ok(()) => {
            // The text as formatted: Windows 2000's DbgPrint adds no line end (its callers end
            // their own lines; a stub's line, printed through "%s", already carries its LF).
            print(line.shown());
            0
        }
        Err(Unsupported { at, length }) => {
            let mut reason = [0u8; 48];
            let prefix = b"the conversion ";
            let conversion = &text[at..at + length.min(reason.len() - prefix.len())];
            reason[..prefix.len()].copy_from_slice(prefix);
            reason[prefix.len()..prefix.len() + conversion.len()].copy_from_slice(conversion);
            let reason = core::str::from_utf8(&reason[..prefix.len() + conversion.len()])
                .unwrap_or("a conversion it does not serve");
            // SAFETY: the format is the caller's string.
            unsafe { stub::stubbed(&crate::spec::DbgPrint, reason, &[format as u64]) }
        }
    }
}
