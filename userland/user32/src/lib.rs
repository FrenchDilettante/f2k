//! user32's user-mode code: the bodies of its exports (the window station and desktop calls,
//! [`winsta`]; the display settings, devices, monitors, metrics and system colors, [`display`];
//! MessageBeep, [`sound`]; ExitWindowsEx, [`shutdown`]; the window classes and the stock cursors,
//! [`class`]; the windows, their geometry, coordinates, visibility, data and text, [`window`];
//! their focus, enabling and activation, [`focus`]; the message loop and the default window
//! procedure, [`message`]; the procedures' narrow and wide forms and CallWindowProc,
//! [`procedure`]; the painting, [`paint`]; the GetDC family, [`dc`]; the drawing calls, [`draw`];
//! the string tables, [`resource`]; the dialog manager, [`dialog`]; the Button, Static and Edit
//! controls, [`button`], [`static_control`] and [`edit`]; MessageBox, [`msgbox`]; the menus,
//! [`menu`]; the menu bar, its popups and the keyboard menu loop, [`menubar`]; the non-client area,
//! [`nonclient`]; the caret, [`caret`]; the keyboard accelerators, [`accel`]; the icons, [`icon`];
//! the clipboard, [`clipboard`]; the keyboard layout, [`keyboard`]; the rectangles, [`rect`]; the
//! character walks, case and types, [`string`]; wsprintf, [`wsprintf`]; WinHelp, [`help`]), as
//! Windows 2000's user32 runs them, over ntdll's, kernel32's and gdi32's exports and win32k's
//! services ([`imports`]: as Windows 2000's user32 imports the first and enters the kernel itself
//! for the others, through its own stubs), and csrss's user server (the kernel's stand-in, through
//! ntdll's CsrClientCallServer).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`imports`]' stand-ins.
//!
//! An export converts its caller's pointers once, on entry: a buffer it writes into a slice
//! ([`caller_bytes_mut`]), one a service writes into an [`imports::UserBuffer`], an out parameter
//! into an [`Out`]. So does a message's lParam that points at memory, where the message is read:
//! the default procedure's ([`message`]) and the translation of the text messages
//! ([`procedure`]). The code below them is safe.
//!
//! A service answers with an NTSTATUS; a failure becomes the last error. win32k's window
//! decisions report Win32 errors that have no NTSTATUS of their own, so the kernel answers the
//! closest documented status and each family of calls maps it back ([`failed_with`]).
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

pub mod accel;
pub mod button;
pub mod caret;
pub mod class;
pub mod clipboard;
pub mod dc;
pub mod dialog;
pub mod display;
pub mod draw;
pub mod edit;
pub mod focus;
pub mod help;
pub mod icon;
pub mod imports;
pub mod keyboard;
pub mod menu;
pub mod menubar;
pub mod message;
pub mod msgbox;
pub mod nonclient;
pub mod paint;
pub mod procedure;
pub mod rect;
pub mod resource;
pub mod shutdown;
pub mod sound;
pub mod static_control;
pub mod string;
pub mod stub;
pub mod window;
pub mod winsta;
pub mod wsprintf;

use rtl::edge::InStr;
/// A caller's out parameter and buffers, as every system DLL's exports take them.
pub use rtl::edge::{caller_bytes_mut, Out};
use rtl::status::{NtStatus, STATUS_INVALID_HANDLE};

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));

/// ERROR_NOT_ENOUGH_MEMORY: a buffer the call needs could not be had.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// ERROR_INVALID_PARAMETER: an argument the call does not take.
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_INVALID_WINDOW_HANDLE: a handle that names no window.
pub const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;

/// The Win32 error of a failed service that names a window: STATUS_INVALID_HANDLE is
/// ERROR_INVALID_WINDOW_HANDLE (the window manager's InvalidWindowHandle), any other status what
/// ntdll's RtlNtStatusToDosError maps it to.
pub fn window_error(status: NtStatus) -> u32 {
    match status.0 {
        STATUS_INVALID_HANDLE => ERROR_INVALID_WINDOW_HANDLE,
        _ => imports::dos_error(status),
    }
}

/// A service's answer: its value, or none with `error` (the failure's Win32 error, as the call's
/// family maps it) made the last error.
pub fn failed_with<T>(
    answer: Result<T, NtStatus>,
    error: impl FnOnce(NtStatus) -> u32,
) -> Option<T> {
    answer
        .map_err(|status| imports::set_last_error(error(status)))
        .ok()
}

/// A service's answer for a call naming a window: see [`window_error`].
pub fn answered<T>(answer: Result<T, NtStatus>) -> Option<T> {
    failed_with(answer, window_error)
}

/// A failure of the call's own: `error` made the last error, nothing answered.
pub fn failed<T>(error: u32) -> Option<T> {
    imports::set_last_error(error);
    None
}

/// The units a narrow string converts into without the heap: its wide form on the stack.
const STACK_UNITS: usize = 260;

/// Run `f` on the wide form of the narrow `bytes`, NUL-terminated (the ANSI code page's, through
/// ntdll's RtlMultiByteToUnicodeN, as Windows 2000's user32 converts), on the stack when it is
/// short and in a block of the process heap otherwise; none, with ERROR_NOT_ENOUGH_MEMORY, when
/// the heap has no room for it. `f` gets the units, the terminator included.
pub fn with_wide<R>(bytes: &[u8], f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    if bytes.len() < STACK_UNITS {
        let mut units = [0u16; STACK_UNITS];
        let length = imports::multi_byte_to_unicode(&mut units[..bytes.len()], bytes);
        return Some(f(&units[..=length]));
    }
    let Some(mut block) = imports::HeapBlock::new(2 * (bytes.len() + 1)) else {
        return failed(ERROR_NOT_ENOUGH_MEMORY);
    };
    let units = block.units_mut();
    let room = units.len() - 1;
    let length = imports::multi_byte_to_unicode(&mut units[..room], bytes);
    units[length] = 0;
    Some(f(&units[..=length]))
}

/// A name as the narrow calls take one (a class name, a cursor's resource name): a NUL-terminated
/// string, or an integer atom or resource id in a pointer's place (its high word zero).
#[derive(Clone, Copy)]
pub enum NameA<'a> {
    Text(InStr<'a>),
    Id(u16),
}

impl<'a> NameA<'a> {
    /// The name the caller's `raw` argument is.
    ///
    /// # Safety
    ///
    /// `raw` is an integer below 0x10000, or the address of a NUL-terminated string the call may
    /// read for `'a`, as for the platform's.
    pub unsafe fn new(raw: *const u8) -> Self {
        if (raw as usize) >> 16 == 0 {
            NameA::Id(raw as usize as u16)
        } else {
            // SAFETY: the caller's contract: a string's address.
            NameA::Text(unsafe { InStr::new(raw) })
        }
    }

    /// Run `f` on the name's wide form as the services take it: the address of its UTF-16 units,
    /// NUL-terminated, or the atom itself. None when the conversion's buffer could not be had.
    pub fn with_wide<R>(&self, f: impl FnOnce(usize) -> R) -> Option<R> {
        match self {
            NameA::Id(id) => Some(f(*id as usize)),
            NameA::Text(text) => with_wide(text.bytes(), |units| f(units.as_ptr() as usize)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    /// A short string converts on the stack, a long one through the heap, each NUL-terminated.
    #[test]
    fn narrow_strings_convert_to_wide() {
        let wide = with_wide(b"Hi\x80", |units| units.to_vec()).unwrap();
        assert_eq!(wide, [0x48, 0x69, 0x20AC, 0]);
        let long = std::vec![b'x'; 1000];
        let wide = with_wide(&long, |units| units.to_vec()).unwrap();
        assert_eq!(wide.len(), 1001);
        assert_eq!(wide[1000], 0);
        assert!(wide[..1000].iter().all(|&unit| unit == 0x78));
    }

    /// A window's dead handle is ERROR_INVALID_WINDOW_HANDLE, other statuses ntdll's mapping.
    #[test]
    fn window_failures_map_to_their_errors() {
        assert_eq!(answered::<()>(Err(NtStatus(STATUS_INVALID_HANDLE))), None);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 1400);
        assert_eq!(answered::<()>(Err(NtStatus(0xC000_0005))), None);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 998);
        assert_eq!(answered(Ok(3)), Some(3));
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            998,
            "a success leaves it"
        );
    }

    /// An atom or a resource id is a name of its own; a string's address is a string.
    #[test]
    fn narrow_names_are_atoms_or_strings() {
        // SAFETY: an integer atom, then a NUL-terminated string.
        let (atom, text) = unsafe {
            (
                NameA::new(0xC012 as *const u8),
                NameA::new(c"Name".as_ptr().cast()),
            )
        };
        assert_eq!(atom.with_wide(|raw| raw), Some(0xC012));
        let units = text
            .with_wide(|raw| {
                // SAFETY: the converted name, alive for the call, NUL-terminated.
                unsafe { rtl::cstr::units_until_nul(raw as *const u16) }.to_vec()
            })
            .unwrap();
        assert_eq!(units, "Name".encode_utf16().collect::<std::vec::Vec<_>>());
    }
}
