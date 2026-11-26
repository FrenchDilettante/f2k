//! The clipboard: OpenClipboard, CloseClipboard, EmptyClipboard, SetClipboardData,
//! GetClipboardData, IsClipboardFormatAvailable, CountClipboardFormats, EnumClipboardFormats,
//! GetClipboardOwner, GetOpenClipboardWindow, RegisterClipboardFormat and
//! GetClipboardFormatName, each over its win32k service ([`imports`]); the clipboard itself is
//! win32k's (kernel/src/win32k/clipboard.rs).
//!
//! The data crosses as Windows 2000's user32 hands it over: SetClipboardData copies the global
//! memory block it is given into a data object of win32k's (NtUserConvertMemHandle), then puts
//! that object on the clipboard (NtUserSetClipboardData); GetClipboardData asks for a format's
//! data object (NtUserGetClipboardData) and copies its bytes into a new global memory block
//! (NtUserCreateLocalMemHandle). The system owns both blocks once they cross: this process frees
//! them at its next CloseClipboard or EmptyClipboard ([`HELD_BLOCKS`]), after which, the
//! documentation says, the program uses neither. kernel32 reuses a freed handle first, so the block
//! a program put comes back under the handle it gave as soon as it asks for it again in its next
//! open, as the clipbrd capture shows.
//!
//! Delayed rendering is win32k's: SetClipboardData with no block puts the format with no data
//! object (NtUserSetClipboardData of 0), and GetClipboardData of it has win32k send the owner
//! WM_RENDERFORMAT before it answers, the owner's procedure putting the data meanwhile; the
//! owner's destruction sends it WM_RENDERALLFORMATS.

use rtl::edge::{InStr, OutBuf};
use rtl::status::NtStatus;
use rtl::user::ONE_PARAM_ENUM_CLIPBOARD_FORMATS;

use crate::imports::{self, GlobalLocked, UserBuffer};
use crate::records::Table;
use crate::{failed_with, window_error};

/// GlobalAlloc's flags for a block GetClipboardData makes: movable, and shareable as clipboard
/// data is (GMEM_MOVEABLE | GMEM_DDESHARE).
const GMEM_CLIPBOARD: u32 = 0x0002 | 0x2000;

/// The longest registered name, in UTF-16 units (an atom's).
const MAX_NAME: usize = 255;

/// A clipboard service's answer: its value, or none with its error made the last error (the
/// kernel's own, ERROR_CLIPBOARD_NOT_OPEN among them, as for any call naming a window).
fn answered<T>(answer: Result<T, NtStatus>) -> Option<T> {
    failed_with(answer, window_error)
}

// --- The blocks the clipboard owns
// -----------------------------------------------------------------------

/// The global memory blocks of this process the clipboard owns: the ones SetClipboardData was
/// given and the ones GetClipboardData made, each a record of its handle, in the order they came,
/// freed at the next CloseClipboard or EmptyClipboard. As many as the program hands over between
/// two closes (Windows 2000 keeps no count of them: the clipboard's own data objects are the
/// window manager's); a block the heap has no room to record is left to the process's end. Shared
/// by the process's threads under user32's lock: any of them may make the calls.
static HELD_BLOCKS: Table<1> = Table::new();

/// Hold `memory` (once, however often it is handed over).
fn hold(memory: usize) {
    let _ = HELD_BLOCKS.with(|held| held.set([memory]));
}

/// Free every block held, in the order they were taken: the records taken out under the lock, the
/// blocks freed after it.
fn release() {
    let held = HELD_BLOCKS.with(core::mem::take);
    for index in 0..held.len() {
        if let Some([memory]) = held.record_at(index) {
            imports::global_free(memory);
        }
    }
}

// --- Opening and closing
// -------------------------------------------------------------------------------

/// OpenClipboard: the clipboard open for the calling thread, with `window` (NULL for none, which
/// an EmptyClipboard then leaves without an owner); TRUE, or FALSE with the last error (5 while
/// another thread has it open, 1400 for a handle naming no window).
#[unsafe(export_name = "f2k_export_OpenClipboard")]
pub extern "system" fn open_clipboard(window: usize) -> u32 {
    answered(imports::open_clipboard(window)).is_some() as u32
}

/// CloseClipboard: the clipboard closed, the blocks this process gave or got through it freed;
/// TRUE, or FALSE with ERROR_CLIPBOARD_NOT_OPEN.
#[unsafe(export_name = "f2k_export_CloseClipboard")]
pub extern "system" fn close_clipboard() -> u32 {
    let closed = answered(imports::close_clipboard()).is_some();
    if closed {
        release();
    }
    closed as u32
}

/// EmptyClipboard: every format gone, the window the clipboard was opened with its owner, the
/// owner before sent WM_DESTROYCLIPBOARD (received before the call returns when it is this
/// thread's); TRUE, or FALSE with ERROR_CLIPBOARD_NOT_OPEN.
#[unsafe(export_name = "f2k_export_EmptyClipboard")]
pub extern "system" fn empty_clipboard() -> u32 {
    let answer = imports::empty_clipboard();
    let emptied = answered(answer).is_some();
    if emptied {
        release();
    }
    emptied as u32
}

/// GetOpenClipboardWindow: the window the clipboard is open with; NULL when it is closed or was
/// opened with none.
#[unsafe(export_name = "f2k_export_GetOpenClipboardWindow")]
pub extern "system" fn get_open_clipboard_window() -> usize {
    imports::open_clipboard_window().unwrap_or(0) as usize
}

/// GetClipboardOwner: the window that last emptied the clipboard, while it lives; NULL for none.
#[unsafe(export_name = "f2k_export_GetClipboardOwner")]
pub extern "system" fn get_clipboard_owner() -> usize {
    imports::clipboard_owner().unwrap_or(0) as usize
}

// --- The data
// ------------------------------------------------------------------------------------------

/// SetClipboardData: the bytes of the global memory block `memory` put on the clipboard as
/// `format`, the block the system's from then on (freed at this process's next close or empty).
/// The answer is the block, the last error 0 (as the clipbrd capture shows); NULL with
/// ERROR_CLIPBOARD_NOT_OPEN when the calling thread does not have the clipboard open (and is not
/// the owner's, rendering a delayed format). A NULL block puts the format delayed, its owner to
/// render it when asked (WM_RENDERFORMAT): the answer is that NULL, the last error untouched, as
/// the clipbrd capture's delayed section shows.
#[unsafe(export_name = "f2k_export_SetClipboardData")]
pub extern "system" fn set_clipboard_data(format: u32, memory: usize) -> usize {
    if memory == 0 {
        let _ = answered(imports::set_clipboard_data(format, 0));
        return 0;
    }
    let converted = match GlobalLocked::new(memory) {
        Some(locked) => imports::convert_mem_handle(locked.address(), locked.size()),
        // A block with no data (a discarded one): no bytes.
        None => imports::convert_mem_handle(0, 0),
    };
    let put = converted.and_then(|data| imports::set_clipboard_data(format, data));
    if answered(put).is_none() {
        return 0;
    }
    hold(memory);
    imports::set_last_error(0);
    memory
}

/// GetClipboardData: a new global memory block holding the clipboard's `format` data, rendered
/// first when the system synthesises the format from another; the system's (freed at this
/// process's next close or empty). NULL, the last error untouched, for a format the clipboard
/// has none of; NULL with ERROR_CLIPBOARD_NOT_OPEN when the calling thread does not have it open,
/// or with kernel32's error when there is no room for the block. The copy into the block leaves the
/// last error as it was, as the clipbrd capture shows Windows 2000's: F2K's copy goes through
/// GlobalLock and GlobalUnlock, whose last unlock leaves NO_ERROR, so the error is kept across it.
#[unsafe(export_name = "f2k_export_GetClipboardData")]
pub extern "system" fn get_clipboard_data(format: u32) -> usize {
    let Some((data, length)) = answered(imports::get_clipboard_data(format)) else {
        return 0;
    };
    if data == 0 {
        return 0;
    }
    let Some(memory) = imports::global_alloc(GMEM_CLIPBOARD, length) else {
        return 0;
    };
    if length > 0 {
        let kept = imports::last_error();
        let copied = match GlobalLocked::new(memory) {
            Some(mut locked) => answered(imports::create_local_mem_handle(data, locked.buffer())),
            None => None,
        };
        if copied.is_some() {
            imports::set_last_error(kept);
        }
        if copied.is_none() {
            imports::global_free(memory);
            return 0;
        }
    }
    hold(memory);
    memory
}

/// IsClipboardFormatAvailable: whether the clipboard has `format`, put or synthesised; the
/// clipboard need not be open, and the last error is untouched.
#[unsafe(export_name = "f2k_export_IsClipboardFormatAvailable")]
pub extern "system" fn is_clipboard_format_available(format: u32) -> u32 {
    imports::is_clipboard_format_available(format).unwrap_or(false) as u32
}

/// CountClipboardFormats: how many formats the clipboard has, put or synthesised (those a close
/// adds counted once it closed); the last error untouched.
#[unsafe(export_name = "f2k_export_CountClipboardFormats")]
pub extern "system" fn count_clipboard_formats() -> i32 {
    imports::count_clipboard_formats().unwrap_or(0) as i32
}

/// EnumClipboardFormats: the format after `format` (the first for 0), in the order they were put,
/// the synthesised ones after; 0 past the last with the last error 0 (ERROR_SUCCESS), or 0 with
/// ERROR_CLIPBOARD_NOT_OPEN when the calling thread does not have the clipboard open.
#[unsafe(export_name = "f2k_export_EnumClipboardFormats")]
pub extern "system" fn enum_clipboard_formats(format: u32) -> u32 {
    match answered(imports::call_one_param(
        format,
        ONE_PARAM_ENUM_CLIPBOARD_FORMATS,
    )) {
        Some(0) => {
            imports::set_last_error(0);
            0
        }
        Some(next) => next,
        None => 0,
    }
}

// --- The registered formats
// ---------------------------------------------------------------------------

/// RegisterClipboardFormatW: the format registered for the name, in 0xC000..=0xFFFF: the one it
/// has already when registered before, in any case (Windows 2000: NtUserRegisterWindowMessage,
/// as RegisterWindowMessage's, in the atom table class names share); 0 with the last error for
/// an empty name or a full table. The kernel reads the name.
#[unsafe(export_name = "f2k_export_RegisterClipboardFormatW")]
pub extern "system" fn register_clipboard_format_w(name: *const u16) -> u32 {
    answered(imports::register_window_message(name as usize)).unwrap_or(0)
}

/// RegisterClipboardFormatA: RegisterClipboardFormatW's format, the name converted from the ANSI
/// code page first.
///
/// # Safety
///
/// `name` is a NUL-terminated string, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterClipboardFormatA")]
pub unsafe extern "system" fn register_clipboard_format_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { InStr::new(name) };
    crate::with_wide_z(name.bytes(), |units| {
        answered(imports::register_window_message(units.as_ptr() as usize)).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// GetClipboardFormatNameW: the registered format's name into the caller's `max` units, cut to fit
/// with its NUL: the units copied before the NUL; 0 with ERROR_INVALID_PARAMETER for a predefined
/// format or one never registered.
///
/// # Safety
///
/// `name` is the caller's buffer of `max` units, as for the platform's.
#[unsafe(export_name = "f2k_export_GetClipboardFormatNameW")]
pub unsafe extern "system" fn get_clipboard_format_name_w(
    format: u32,
    name: *mut u16,
    max: i32,
) -> i32 {
    let max = max.max(0) as u32;
    // SAFETY: the caller's buffer of `max` units, which the kernel writes.
    let buffer = unsafe { UserBuffer::new(name.cast(), 2 * max) };
    answered(imports::clipboard_format_name(format, buffer)).unwrap_or(0) as i32
}

/// GetClipboardFormatNameA: GetClipboardFormatNameW's name converted to the ANSI code page, into
/// the caller's `max` bytes, cut to fit with its NUL: the bytes copied before the NUL.
///
/// # Safety
///
/// `name` is the caller's buffer of `max` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetClipboardFormatNameA")]
pub unsafe extern "system" fn get_clipboard_format_name_a(
    format: u32,
    name: *mut u8,
    max: i32,
) -> i32 {
    // SAFETY: the caller's buffer of `max` bytes.
    let mut out = unsafe { OutBuf::new(name, max.max(0) as usize) };
    let mut units = [0u16; MAX_NAME + 1];
    let Some(count) = answered(imports::clipboard_format_name(
        format,
        UserBuffer::from(&mut units[..]),
    )) else {
        return 0;
    };
    if out.is_empty() {
        return 0;
    }
    let mut bytes = [0u8; 2 * MAX_NAME];
    let length = imports::unicode_to_multi_byte(&mut bytes, &units[..count as usize]);
    let copied = length.min(out.len() - 1);
    out.put(&bytes[..copied]);
    out.set(copied, 0);
    copied as i32
}

#[cfg(test)]
mod tests {
    use rtl::user::{CF_TEXT, CF_UNICODETEXT};
    use rtl::winerror::ERROR_CLIPBOARD_NOT_OPEN;

    use super::*;
    use crate::imports::host::{live_globals, LAST_ERROR};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2_F2F2));
    }

    /// A movable block of the stand-ins' holding `bytes`.
    fn block(bytes: &[u8]) -> usize {
        let memory = imports::global_alloc(2, bytes.len()).unwrap();
        let mut locked = GlobalLocked::new(memory).unwrap();
        let at = locked.address() as *mut u8;
        // SAFETY: the stand-in's block, as long as the bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), at, bytes.len()) };
        let _ = locked.buffer();
        memory
    }

    fn bytes_of(memory: usize) -> std::vec::Vec<u8> {
        let locked = GlobalLocked::new(memory).unwrap();
        // SAFETY: the stand-in's block, as long as its size.
        unsafe { core::slice::from_raw_parts(locked.address() as *const u8, locked.size()) }
            .to_vec()
    }

    /// The calls a closed clipboard refuses: ERROR_CLIPBOARD_NOT_OPEN, the block refused.
    #[test]
    fn a_closed_clipboard_refuses() {
        arm();
        assert_eq!(close_clipboard(), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        arm();
        assert_eq!(empty_clipboard(), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        let memory = block(b"closed\0");
        arm();
        assert_eq!(set_clipboard_data(CF_TEXT, memory), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        arm();
        assert_eq!(get_clipboard_data(CF_TEXT), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        arm();
        assert_eq!(enum_clipboard_formats(0), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        arm();
        assert_eq!(is_clipboard_format_available(CF_TEXT), 0);
        assert_eq!(last_error(), 0xF2F2_F2F2);
    }

    /// A put block is the system's: freed at the close, its handle the first the next get's block
    /// takes; the gets' blocks are new ones, freed at the close too.
    #[test]
    fn the_blocks_cross_and_come_back() {
        assert_eq!(open_clipboard(0), 1);
        assert_eq!(empty_clipboard(), 1);
        let given = block(b"text\0");
        arm();
        assert_eq!(set_clipboard_data(CF_TEXT, given), given);
        assert_eq!(last_error(), 0, "SetClipboardData's success sets 0");
        assert_eq!(close_clipboard(), 1);
        assert!(
            live_globals().is_empty(),
            "the put block freed at the close"
        );
        assert_eq!(is_clipboard_format_available(CF_TEXT), 1);
        assert_eq!(open_clipboard(0), 1);
        arm();
        let got = get_clipboard_data(CF_TEXT);
        assert_eq!(got, given, "the handle given back");
        assert_eq!(bytes_of(got), b"text\0");
        let again = get_clipboard_data(CF_TEXT);
        assert_ne!(again, got);
        assert_eq!(get_clipboard_data(CF_UNICODETEXT), 0);
        assert_eq!(last_error(), 0xF2F2_F2F2, "a missing format sets no error");
        assert_eq!(close_clipboard(), 1);
        assert!(live_globals().is_empty());
    }

    /// However many blocks cross between two closes, far past the 64 a fixed list held, each is
    /// freed at the close (none left to the process's end), and no record stays behind.
    #[test]
    fn every_block_crossed_is_freed() {
        assert_eq!(open_clipboard(0), 1);
        assert_eq!(empty_clipboard(), 1);
        for index in 0..200u8 {
            let given = block(&[b'a' + index % 26, 0]);
            assert_eq!(set_clipboard_data(CF_TEXT, given), given);
            assert_eq!(set_clipboard_data(CF_TEXT, given), given, "held once");
            assert_ne!(get_clipboard_data(CF_TEXT), 0);
        }
        assert_eq!(HELD_BLOCKS.with(|held| held.len()), 400);
        assert_eq!(close_clipboard(), 1);
        assert!(live_globals().is_empty(), "every block freed at the close");
        assert!(HELD_BLOCKS.with(|held| held.is_empty()));
    }

    /// SetClipboardData of no block puts the format delayed: NULL, the last error untouched, the
    /// format available (its data the owner's to render); a closed clipboard refuses it with
    /// ERROR_CLIPBOARD_NOT_OPEN.
    ///
    /// Pins: user32.SetClipboardData, user32.IsClipboardFormatAvailable
    #[test]
    fn no_block_puts_the_format_delayed() {
        arm();
        assert_eq!(set_clipboard_data(CF_UNICODETEXT, 0), 0);
        assert_eq!(last_error(), ERROR_CLIPBOARD_NOT_OPEN);
        assert_eq!(open_clipboard(0), 1);
        assert_eq!(empty_clipboard(), 1);
        arm();
        assert_eq!(set_clipboard_data(CF_UNICODETEXT, 0), 0);
        assert_eq!(last_error(), 0xF2F2_F2F2, "the last error untouched");
        assert_eq!(is_clipboard_format_available(CF_UNICODETEXT), 1);
        assert_eq!(get_clipboard_data(CF_UNICODETEXT), 0, "nothing rendered it");
        assert_eq!(last_error(), 0xF2F2_F2F2);
        assert_eq!(close_clipboard(), 1);
        assert!(live_globals().is_empty());
    }

    /// EnumClipboardFormats lists the formats in order and ends with 0, the last error 0.
    #[test]
    fn the_formats_enumerate_in_order() {
        assert_eq!(open_clipboard(0), 1);
        assert_eq!(empty_clipboard(), 1);
        arm();
        assert_eq!(enum_clipboard_formats(0), 0);
        assert_eq!(last_error(), 0);
        set_clipboard_data(CF_UNICODETEXT, block(&[0x77, 0, 0, 0]));
        set_clipboard_data(CF_TEXT, block(b"w\0"));
        assert_eq!(count_clipboard_formats(), 2);
        assert_eq!(enum_clipboard_formats(0), CF_UNICODETEXT);
        assert_eq!(enum_clipboard_formats(CF_UNICODETEXT), CF_TEXT);
        assert_eq!(enum_clipboard_formats(CF_TEXT), 0);
        assert_eq!(close_clipboard(), 1);
    }

    /// A registered name is one format in either case and either width, its name given back cut
    /// to the caller's buffer; a predefined format has no name.
    #[test]
    fn registered_formats_have_names() {
        let wide: std::vec::Vec<u16> = "F2K Clipbrd Format\0".encode_utf16().collect();
        let format = register_clipboard_format_w(wide.as_ptr());
        // SAFETY: a NUL-terminated string of the test's own.
        let again = unsafe { register_clipboard_format_a(c"f2k clipbrd format".as_ptr().cast()) };
        assert!(format >= 0xC000);
        assert_eq!(again, format);
        let mut narrow = [b'#'; 64];
        // SAFETY: the test's own buffers.
        unsafe {
            assert_eq!(
                get_clipboard_format_name_a(format, narrow.as_mut_ptr(), 64),
                18
            );
            assert_eq!(&narrow[..19], b"F2K Clipbrd Format\0");
            assert_eq!(
                get_clipboard_format_name_a(format, narrow.as_mut_ptr(), 4),
                3
            );
            assert_eq!(&narrow[..4], b"F2K\0");
            let mut units = [0u16; 64];
            assert_eq!(
                get_clipboard_format_name_w(format, units.as_mut_ptr(), 64),
                18
            );
            assert_eq!(&units[..19], &wide[..]);
            arm();
            assert_eq!(
                get_clipboard_format_name_w(CF_TEXT, units.as_mut_ptr(), 64),
                0
            );
        }
        assert_eq!(last_error(), 87);
    }
}
