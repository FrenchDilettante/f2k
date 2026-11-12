//! OutputDebugStringA and W, as Windows 2000's kernel32 makes them: the text is offered to a
//! debugger first, as a DBG_PRINTEXCEPTION_C exception raised inside the call's own `__try`, which
//! a debugger takes and continues; with none, the call's own handler takes it (the caller's
//! handlers never see it), and the text goes to a debug monitor's shared buffer (the DBWIN_BUFFER
//! mapping in `\BaseNamedObjects`), or, with no monitor either, to the kernel's debugger channel
//! (DbgPrint: F2K's COM1). Opening the monitor's buffer is what leaves the last error at
//! ERROR_FILE_NOT_FOUND when no monitor runs (the runtime capture).
//!
//! The `__try` is the pointer probes' guarded call ([`crate::lstr::guarded`]): its frame takes any
//! exception the body raises, a fault reading the caller's text (NULL among them) too.

use rtl::cstr::len_until_nul;

use crate::edge::{wide_units, InWStr};
use crate::heap::HeapArray;
use crate::ntcall;

/// DBG_PRINTEXCEPTION_C: a debugger's print, its arguments the text's length (its terminator
/// counted) and its address.
const DBG_PRINTEXCEPTION_C: u32 = 0x4001_0006;

/// FILE_MAP_WRITE, the access a monitor's buffer is opened with.
const FILE_MAP_WRITE: u32 = 0x0002;

/// The monitor's buffer's name, NUL-terminated UTF-16.
const DBWIN_BUFFER: [u16; 13] = {
    let name = *b"DBWIN_BUFFER\0";
    let mut units = [0u16; 13];
    let mut at = 0;
    while at < name.len() {
        units[at] = name[at] as u16;
        at += 1;
    }
    units
};

/// The guarded body: DBG_PRINTEXCEPTION_C raised for the NUL-terminated text at `text`
/// (RaiseException, as Windows 2000's raises it), once the text was read through — which it notes
/// in the dword at `read`. It returns 1 when a debugger continued the exception; the guard answers
/// 0 when the call's own handler took it, or a read of the text faulted.
///
/// # Safety
///
/// `text` is null or the address of a NUL-terminated string (one the caller cannot read faults
/// inside the guard); `read` is the address of a writable dword.
unsafe extern "C" fn raise_print(text: usize, read: usize, _: usize) -> usize {
    if text == 0 {
        // Windows 2000's length of a null text faults inside its `__try`: the handler's path.
        return 0;
    }
    // SAFETY: the contract: the text is read to its terminator (a fault is the guard's).
    let length = unsafe { len_until_nul(text as *const u8) };
    // SAFETY: the contract: the caller's dword.
    unsafe { (read as *mut u32).write_volatile(1) };
    let arguments = [length as u32 + 1, text as u32];
    // SAFETY: the two arguments, on this frame.
    unsafe { crate::except::raise_exception(DBG_PRINTEXCEPTION_C, 0, 2, arguments.as_ptr()) };
    1
}

/// OutputDebugStringA's work: the text offered to a debugger, then (none took it) to a monitor or
/// the kernel's debugger channel.
///
/// # Safety
///
/// `text` is null or a NUL-terminated string (one the caller cannot read is passed over, as on
/// Windows 2000).
unsafe fn output(text: *const u8) {
    let mut read = 0u32;
    let noted = &raw mut read as usize;
    // SAFETY: the guard runs the body over the caller's text (the contract) and the local dword.
    if unsafe { crate::lstr::guarded(raise_print, text as usize, noted, 0) } != 0 {
        return;
    }
    // SAFETY: kernel32's own NUL-terminated name.
    let monitor =
        unsafe { crate::filemap::open_file_mapping_w(FILE_MAP_WRITE, 0, DBWIN_BUFFER.as_ptr()) };
    if monitor != 0 {
        // A debug monitor's protocol (its buffer-ready and data-ready events) is not served: the
        // text goes to the kernel's debugger channel as with no monitor.
        let args = [text as u64];
        // SAFETY: the caller's argument, as the export's kind reads it.
        unsafe {
            crate::stub::stubbed(
                &crate::spec::OutputDebugStringA,
                "not yet implemented: a debug monitor's DBWIN_BUFFER",
                &args,
            )
        };
        let _ = ntcall::close(monitor);
    }
    // SAFETY: the guard's body wrote the dword (a volatile read: the write was made under the
    // guard, through its address).
    if unsafe { (&raw const read).read_volatile() } != 0 {
        // SAFETY: ntdll's export; the format and the caller's text are NUL-terminated (the text
        // was read through to its terminator above).
        unsafe { crate::nt::DbgPrint(c"%s".as_ptr().cast(), text) };
    }
}

/// OutputDebugStringA: the text to a debugger, a monitor or the kernel's debugger channel (see the
/// module). With no debugger, the caller's handlers see no exception, and the last error is the
/// monitor's open's (ERROR_FILE_NOT_FOUND with none).
///
/// # Safety
///
/// `text` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OutputDebugStringA")]
pub unsafe extern "system" fn output_debug_string_a(text: *const u8) {
    // SAFETY: the contract.
    unsafe { output(text) }
}

/// OutputDebugStringW: the text narrowed through the ANSI code page into a block on the process
/// heap, then [`output_debug_string_a`]'s path, as Windows 2000's (a null text is the empty one).
///
/// # Safety
///
/// `text` is null or a NUL-terminated UTF-16 string (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_OutputDebugStringW")]
pub unsafe extern "system" fn output_debug_string_w(text: *const u16) {
    // SAFETY: the caller's string, when given (the contract).
    let text = unsafe { InWStr::optional(text) };
    let units = text.as_ref().and_then(wide_units);
    let units: &[u16] = units.as_deref().unwrap_or(&[]);
    let Ok(mut narrow) = HeapArray::<u8>::new(ntcall::unicode_to_multi_byte_size(units) + 1) else {
        return;
    };
    let length = narrow.len() - 1;
    ntcall::unicode_to_multi_byte_into(&mut narrow[..length], units);
    // SAFETY: kernel32's own block, NUL-terminated (HeapArray's values start zero).
    unsafe { output(narrow.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt;

    /// The text is raised as DBG_PRINTEXCEPTION_C, its length with the terminator and its address
    /// the arguments; the stand-in's raise returns, as a debugger's continue does, and the call
    /// ends there.
    #[test]
    fn the_text_is_offered_to_a_debugger() {
        nt::RAISED.with(|raised| raised.borrow_mut().clear());
        let text = b"f2k: a line\n\0";
        // SAFETY: a NUL-terminated string.
        unsafe { output_debug_string_a(text.as_ptr()) };
        nt::RAISED.with(|raised| {
            let raised = raised.borrow();
            assert_eq!(raised.len(), 1);
            let record = raised[0];
            assert_eq!((record.code, record.count), (DBG_PRINTEXCEPTION_C, 2));
            assert_eq!(record.information[0], 13);
            assert_eq!(record.information[1], text.as_ptr() as usize as u32);
        });
    }

    /// A null text raises nothing (its length faults inside the call's own `__try` on Windows
    /// 2000).
    #[test]
    fn a_null_text_raises_nothing() {
        nt::RAISED.with(|raised| raised.borrow_mut().clear());
        // SAFETY: null is allowed.
        unsafe { output_debug_string_a(core::ptr::null()) };
        nt::RAISED.with(|raised| assert!(raised.borrow().is_empty()));
    }
}
