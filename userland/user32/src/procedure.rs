//! Window procedures in their two forms: a procedure takes the narrow (ANSI) or the wide (Unicode)
//! forms of the messages, as its window's class was registered (RegisterClassA or
//! RegisterClassW), or as SetWindowLongA or SetWindowLongW subclassed the window ([`Procedure`]).
//! A message reaches a procedure of the other form translated ([`call`]); GetWindowLong and
//! SetWindowLong answer a procedure of the other form as a handle that names it ([`value_for`]),
//! which CallWindowProc and SetWindowLong take back ([`resolve`]). CallWindowProcA and
//! CallWindowProcW live here.
//!
//! Windows 2000 keeps those handles as the window manager's objects (its call-procedure data,
//! made through NtUserGetCPD). F2K's are user32's own, a table in each process: the addresses they
//! name are the process's own, and only its user32 calls them. Their values have Windows 2000's
//! shape, the high word 0xFFFF, which no procedure's address has (the user half of the address
//! space ends below it). A handle lives as long as its process; the table holds
//! [`HANDLES`] procedures of each form, and a procedure past them is answered as its address.
//!
//! user32's own procedures have both forms, an entry point each (DefWindowProcA and DefWindowProcW,
//! DefDlgProcA and DefDlgProcW, the controls' procedures): a window whose procedure is one of them
//! answers the entry point of the caller's form, never a handle, and either entry point handed back
//! names the procedure in its own form ([`own_pair`]). As the wndlong capture shows Windows 2000's
//! dialog: GWL_WNDPROC is DefDlgProcW through GetWindowLongW and DefDlgProcA through
//! GetWindowLongA.
//!
//! The messages translated are the ones that carry text: WM_SETTEXT, WM_GETTEXT,
//! WM_GETTEXTLENGTH, WM_NCCREATE's and WM_CREATE's CREATESTRUCT, and the edit control's
//! EM_REPLACESEL (a string, as WM_SETTEXT's) and EM_GETLINE (a buffer whose first unit holds its
//! size; the line comes back converted, terminated when there is room, as the editctl capture shows
//! Windows 2000's narrow caller's). As the wintext capture shows Windows 2000's:
//!
//! - a wide caller's WM_GETTEXT reaches a narrow procedure with a buffer of twice its units in
//!   bytes (the most a double-byte code page's text takes), a narrow caller's reaches a wide
//!   procedure with as many units as it has bytes; the text comes back converted, cut to the
//!   caller's buffer, terminated;
//! - a WM_GETTEXTLENGTH of the other form is the procedure's text read whole (its WM_GETTEXTLENGTH,
//!   then WM_GETTEXT of one more than that) and measured in the caller's form.
//!
//! The other messages reach the procedure as they are. The messages the window manager sends are
//! wide; a message another thread sent reaches the procedure as it was sent.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::edge::{In, InStr, InWStr, OutBuf};
use rtl::user::{CreateStructW, WM_CREATE, WM_GETTEXT, WM_GETTEXTLENGTH, WM_NCCREATE, WM_SETTEXT};

use crate::edit::{EM_GETLINE, EM_REPLACESEL};
use crate::imports;

/// A window procedure, and whether it takes the narrow forms of the messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub address: u32,
    pub ansi: bool,
}

// --- The call-procedure handles ------------------------------------------------------------------

/// How many procedures of each form the handles name.
pub const HANDLES: usize = 128;

/// A handle's high word, and the bit of its low word that marks a narrow procedure's handle (the
/// rest of the low word is the table's index).
const HANDLE_TAG: u32 = 0xFFFF_0000;
const NARROW_HANDLE: u32 = 0x8000;

/// The procedures the handles name, by form: an address, 0 for a free entry. An entry, once
/// claimed, names its procedure for the process's life.
static WIDE: [AtomicU32; HANDLES] = [const { AtomicU32::new(0) }; HANDLES];
static NARROW: [AtomicU32; HANDLES] = [const { AtomicU32::new(0) }; HANDLES];

fn table(ansi: bool) -> &'static [AtomicU32; HANDLES] {
    if ansi {
        &NARROW
    } else {
        &WIDE
    }
}

/// The handle naming `proc`: its entry, or a free one claimed for it; none when the table is full.
fn handle_of(proc: Procedure) -> Option<u32> {
    let tag = |index: usize| HANDLE_TAG | if proc.ansi { NARROW_HANDLE } else { 0 } | index as u32;
    for (index, entry) in table(proc.ansi).iter().enumerate() {
        let held = entry.load(Ordering::Acquire);
        if held == proc.address {
            return Some(tag(index));
        }
        if held == 0 {
            match entry.compare_exchange(0, proc.address, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(tag(index)),
                Err(other) if other == proc.address => return Some(tag(index)),
                Err(_) => {}
            }
        }
    }
    None
}

/// One of user32's own procedures, by the entry points of its two forms.
#[derive(Clone, Copy)]
struct OwnPair {
    wide: u32,
    narrow: u32,
}

/// The pair `address` is an entry point of, when it is one of user32's own procedures.
fn own_pair(address: u32) -> Option<OwnPair> {
    let pair = |wide: usize, narrow: usize| OwnPair {
        wide: wide as u32,
        narrow: narrow as u32,
    };
    [
        pair(
            crate::message::def_window_proc_w as *const () as usize,
            crate::message::def_window_proc_a as *const () as usize,
        ),
        pair(
            crate::dialog::def_dlg_proc_w as *const () as usize,
            crate::dialog::def_dlg_proc_a as *const () as usize,
        ),
        pair(
            crate::button::button_proc_w as *const () as usize,
            crate::button::button_proc_a as *const () as usize,
        ),
        pair(
            crate::static_control::static_proc_w as *const () as usize,
            crate::static_control::static_proc_a as *const () as usize,
        ),
        pair(
            crate::edit::edit_proc_w as *const () as usize,
            crate::edit::edit_proc_a as *const () as usize,
        ),
    ]
    .into_iter()
    .find(|pair| pair.wide == address || pair.narrow == address)
}

/// The value GetWindowLong and SetWindowLong answer a caller of the narrow (`caller_ansi`) or wide
/// form for the procedure `proc`: its address when it takes the caller's form (or is none), the
/// entry point of the caller's form for one of user32's own procedures, a handle naming it
/// otherwise.
pub fn value_for(proc: Procedure, caller_ansi: bool) -> u32 {
    if proc.address == 0 || proc.ansi == caller_ansi {
        return proc.address;
    }
    if let Some(pair) = own_pair(proc.address) {
        return if caller_ansi { pair.narrow } else { pair.wide };
    }
    handle_of(proc).unwrap_or(proc.address)
}

/// The procedure a value a caller of the narrow (`caller_ansi`) or wide form hands over names: a
/// handle's procedure, in its own form; an entry point of user32's own procedures, in its own
/// form; another address, in the caller's.
pub fn resolve(value: u32, caller_ansi: bool) -> Procedure {
    if let Some(pair) = own_pair(value) {
        return Procedure {
            address: value,
            ansi: value == pair.narrow,
        };
    }
    if value & 0xFFFF_0000 == HANDLE_TAG {
        let ansi = value & NARROW_HANDLE != 0;
        let index = (value & (NARROW_HANDLE - 1)) as usize;
        if let Some(entry) = table(ansi).get(index) {
            let address = entry.load(Ordering::Acquire);
            if address != 0 {
                return Procedure { address, ansi };
            }
        }
    }
    Procedure {
        address: value,
        ansi: caller_ansi,
    }
}

// --- Calling a procedure -------------------------------------------------------------------------

/// Whether `message` is one a procedure of the other form receives translated.
pub fn translates(message: u32) -> bool {
    matches!(
        message,
        WM_SETTEXT
            | WM_GETTEXT
            | WM_GETTEXTLENGTH
            | WM_NCCREATE
            | WM_CREATE
            | EM_REPLACESEL
            | EM_GETLINE
    )
}

/// The procedure `proc` called with a message its caller has in the narrow (`caller_ansi`) or wide
/// form: as it is when the procedure takes that form, translated otherwise (see the module notes);
/// the procedure's answer, translated with it. No procedure answers 0.
pub fn call(
    proc: Procedure,
    caller_ansi: bool,
    window: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    if proc.address == 0 {
        return 0;
    }
    if proc.ansi == caller_ansi || !translates(message) {
        return imports::call_procedure(proc.address, window, message, wparam, lparam);
    }
    if caller_ansi {
        to_wide(proc.address, window, message, wparam, lparam)
    } else {
        to_narrow(proc.address, window, message, wparam, lparam)
    }
}

/// A wide message handed to the narrow procedure at `proc`.
fn to_narrow(proc: u32, window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
    let call =
        |message, wparam, lparam| imports::call_procedure(proc, window, message, wparam, lparam);
    match message {
        WM_SETTEXT | EM_REPLACESEL if lparam != 0 => {
            // SAFETY: WM_SETTEXT's and EM_REPLACESEL's lParam as its sender hands it over: a
            // NUL-terminated string, wide in this form.
            let text = unsafe { InWStr::new(lparam as usize as *const u16) };
            with_narrow(text, |bytes| call(message, wparam, bytes.as_ptr() as i32)).unwrap_or(0)
        }
        EM_GETLINE if lparam != 0 => {
            // SAFETY: EM_GETLINE's lParam as its sender hands it over: a buffer of as many units as
            // its first unit says.
            let room = unsafe { In::new(lparam as usize as *const u16) }.read() as usize;
            // SAFETY: as above.
            let mut out = unsafe { OutBuf::new(lparam as usize as *mut u16, room) };
            with_bytes((2 * room).max(2), |bytes| {
                let size = (2 * room).min(0xFFFF) as u16;
                bytes[..2].copy_from_slice(&size.to_le_bytes());
                let got = call(EM_GETLINE, wparam, bytes.as_mut_ptr() as i32);
                put_line(&mut out, &bytes[..(got.max(0) as usize).min(bytes.len())])
            })
            .unwrap_or(0)
        }
        WM_GETTEXT if lparam != 0 => {
            // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam units.
            let mut out = unsafe { OutBuf::new(lparam as usize as *mut u16, wparam as usize) };
            with_bytes(2 * wparam as usize, |bytes| {
                let got = call(WM_GETTEXT, bytes.len() as u32, bytes.as_mut_ptr() as i32);
                put_wide(&mut out, got_text(bytes, got)) as i32
            })
            .unwrap_or(0)
        }
        WM_GETTEXTLENGTH => {
            let length = call(WM_GETTEXTLENGTH, wparam, lparam);
            if length <= 0 {
                return length;
            }
            with_bytes(length as usize + 1, |bytes| {
                let got = call(WM_GETTEXT, bytes.len() as u32, bytes.as_mut_ptr() as i32);
                let text = got_text(bytes, got);
                with_units(text.len(), |units| {
                    imports::multi_byte_to_unicode(units, text) as i32
                })
            })
            .flatten()
            .unwrap_or(0)
        }
        WM_NCCREATE | WM_CREATE if lparam != 0 => {
            // SAFETY: WM_NCCREATE's and WM_CREATE's lParam as the window manager hands it over: a
            // CREATESTRUCTW, its strings NUL-terminated (or a class's atom).
            let create = unsafe { In::new(lparam as usize as *const CreateStructW) }.read();
            narrow_name(create.name, |name| {
                narrow_name(create.class, |class| {
                    let mut narrow = CreateStructW {
                        name,
                        class,
                        ..create
                    };
                    call(message, wparam, &mut narrow as *mut CreateStructW as i32)
                })
            })
            .flatten()
            .unwrap_or(0)
        }
        _ => call(message, wparam, lparam),
    }
}

/// A narrow message handed to the wide procedure at `proc`.
fn to_wide(proc: u32, window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
    let call =
        |message, wparam, lparam| imports::call_procedure(proc, window, message, wparam, lparam);
    match message {
        WM_SETTEXT | EM_REPLACESEL if lparam != 0 => {
            // SAFETY: WM_SETTEXT's and EM_REPLACESEL's lParam as its sender hands it over: a
            // NUL-terminated string, narrow in this form.
            let text = unsafe { InStr::new(lparam as usize as *const u8) };
            crate::with_wide(text.bytes(), |units| {
                call(message, wparam, units.as_ptr() as i32)
            })
            .unwrap_or(0)
        }
        EM_GETLINE if lparam != 0 => {
            // SAFETY: EM_GETLINE's lParam as its sender hands it over: a buffer of as many bytes
            // as its first two say.
            let room = unsafe { In::new(lparam as usize as *const u16) }.read() as usize;
            // SAFETY: as above.
            let mut out = unsafe { OutBuf::new(lparam as usize as *mut u8, room) };
            with_units(room.max(1), |units| {
                units[0] = room as u16;
                let got = call(EM_GETLINE, wparam, units.as_mut_ptr() as i32);
                put_line_narrow(&mut out, &units[..(got.max(0) as usize).min(units.len())])
            })
            .unwrap_or(0)
        }
        WM_GETTEXT if lparam != 0 => {
            // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam bytes.
            let mut out = unsafe { OutBuf::new(lparam as usize as *mut u8, wparam as usize) };
            with_units(wparam as usize, |units| {
                let got = call(WM_GETTEXT, units.len() as u32, units.as_mut_ptr() as i32);
                put_narrow(&mut out, got_text(units, got)) as i32
            })
            .unwrap_or(0)
        }
        WM_GETTEXTLENGTH => {
            let length = call(WM_GETTEXTLENGTH, wparam, lparam);
            if length <= 0 {
                return length;
            }
            with_units(length as usize + 1, |units| {
                let got = call(WM_GETTEXT, units.len() as u32, units.as_mut_ptr() as i32);
                narrow_length(got_text(units, got)) as i32
            })
            .unwrap_or(0)
        }
        _ => call(message, wparam, lparam),
    }
}

// --- The text's conversions ----------------------------------------------------------------------

/// How many bytes of scratch a conversion takes on the stack; more come from the process heap.
const STACK_BYTES: usize = 512;

/// Run `f` on `len` zeroed bytes of scratch; none when the heap has no room for them.
fn with_bytes<R>(len: usize, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    if len <= STACK_BYTES {
        let mut bytes = [0u8; STACK_BYTES];
        return Some(f(&mut bytes[..len]));
    }
    let mut block = imports::HeapBlock::new(len)?;
    Some(f(block.bytes_mut()))
}

/// Run `f` on `len` zeroed units of scratch; none when the heap has no room for them.
fn with_units<R>(len: usize, f: impl FnOnce(&mut [u16]) -> R) -> Option<R> {
    if 2 * len <= STACK_BYTES {
        let mut units = [0u16; STACK_BYTES / 2];
        return Some(f(&mut units[..len]));
    }
    let mut block = imports::HeapBlock::new(2 * len)?;
    Some(f(&mut block.units_mut()[..len]))
}

/// The text a procedure's WM_GETTEXT left in `buffer`, its answer `got`: as many of the buffer's
/// values as it counts, to a terminator.
fn got_text<T: Copy + Default + PartialEq>(buffer: &[T], got: i32) -> &[T] {
    let text = &buffer[..(got.max(0) as usize).min(buffer.len())];
    &text[..rtl::cstr::nul_len(text)]
}

/// Run `f` on the narrow form of the wide string `text`, NUL-terminated.
fn with_narrow<R>(text: InWStr<'_>, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let source = text.units();
    with_units(source.len(), |units| {
        source.copy_to(units);
        with_bytes(2 * units.len() + 1, |bytes| {
            let room = bytes.len() - 1;
            let length = imports::unicode_to_multi_byte(&mut bytes[..room], units);
            bytes[length] = 0;
            f(&bytes[..=length])
        })
    })
    .flatten()
}

/// Run `f` on a CREATESTRUCT's string `name` in the narrow form, as an address: a string's
/// converted, NUL-terminated; an atom, a resource id or none as it is.
fn narrow_name<R>(name: u32, f: impl FnOnce(u32) -> R) -> Option<R> {
    if name >> 16 == 0 {
        return Some(f(name));
    }
    // SAFETY: a CREATESTRUCTW's string as the window manager hands it over: NUL-terminated.
    let text = unsafe { InWStr::new(name as usize as *const u16) };
    with_narrow(text, |bytes| f(bytes.as_ptr() as u32))
}

/// The narrow form's length of the wide `text`, in bytes.
pub fn narrow_length(text: &[u16]) -> usize {
    with_bytes(2 * text.len(), |bytes| {
        imports::unicode_to_multi_byte(bytes, text)
    })
    .unwrap_or(0)
}

/// The narrow `text` converted into the caller's wide buffer `out`, cut to leave room for the
/// terminator, terminated: the units written before it. An empty buffer is left as it is.
pub fn put_wide(out: &mut OutBuf<'_, u16>, text: &[u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let room = out.len() - 1;
    with_units(text.len(), |units| {
        let length = imports::multi_byte_to_unicode(units, text).min(room);
        out.put(&units[..length]);
        out.set(length, 0);
        length
    })
    .unwrap_or(0)
}

/// The wide `text` converted into the caller's narrow buffer `out`, cut to leave room for the
/// terminator, terminated: the bytes written before it. An empty buffer is left as it is.
pub fn put_narrow(out: &mut OutBuf<'_, u8>, text: &[u16]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let room = out.len() - 1;
    with_bytes(2 * text.len(), |bytes| {
        let length = imports::unicode_to_multi_byte(bytes, text).min(room);
        out.put(&bytes[..length]);
        out.set(length, 0);
        length
    })
    .unwrap_or(0)
}

/// A narrow procedure's EM_GETLINE line `line` converted into the wide caller's buffer `out`, as
/// much as fits, terminated when there is room: the units written before the terminator.
fn put_line(out: &mut OutBuf<'_, u16>, line: &[u8]) -> i32 {
    with_units(line.len(), |units| {
        let length = imports::multi_byte_to_unicode(units, line).min(out.len());
        out.put(&units[..length]);
        if length < out.len() {
            out.set(length, 0);
        }
        length as i32
    })
    .unwrap_or(0)
}

/// A wide procedure's EM_GETLINE line `line` converted into the narrow caller's buffer `out`, as
/// much as fits, terminated when there is room (the editctl capture's narrow EM_GETLINE): the
/// bytes written before the terminator.
fn put_line_narrow(out: &mut OutBuf<'_, u8>, line: &[u16]) -> i32 {
    with_bytes(2 * line.len(), |bytes| {
        let length = imports::unicode_to_multi_byte(bytes, line).min(out.len());
        out.put(&bytes[..length]);
        if length < out.len() {
            out.set(length, 0);
        }
        length as i32
    })
    .unwrap_or(0)
}

// --- CallWindowProc ------------------------------------------------------------------------------

/// CallWindowProcA: the procedure `proc` names (an address, or a handle GetWindowLongA answered for
/// a wide procedure) called with the narrow message, translated for a wide one; its answer, 0 for
/// no procedure.
#[unsafe(export_name = "f2k_export_CallWindowProcA")]
pub extern "system" fn call_window_proc_a(
    proc: usize,
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    call(
        resolve(proc as u32, true),
        true,
        window as u32,
        message,
        wparam,
        lparam,
    )
}

/// CallWindowProcW: CallWindowProcA's, for a wide message.
#[unsafe(export_name = "f2k_export_CallWindowProcW")]
pub extern "system" fn call_window_proc_w(
    proc: usize,
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    call(
        resolve(proc as u32, false),
        false,
        window as u32,
        message,
        wparam,
        lparam,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A procedure of the caller's form is its address; one of the other form a handle, the same
    /// each time, which resolves to it in its own form; a value that is no handle resolves to an
    /// address in the caller's form; none stays none.
    #[test]
    fn handles_name_the_other_form() {
        let wide = Procedure {
            address: 0x0041_2340,
            ansi: false,
        };
        assert_eq!(value_for(wide, false), 0x0041_2340);
        let handle = value_for(wide, true);
        assert_eq!(handle >> 16, 0xFFFF);
        assert_eq!(handle & NARROW_HANDLE, 0);
        assert_eq!(value_for(wide, true), handle);
        assert_eq!(resolve(handle, true), wide);
        let narrow = Procedure {
            address: 0x0041_2340,
            ansi: true,
        };
        let other = value_for(narrow, false);
        assert_ne!(other, handle);
        assert_eq!(resolve(other, false), narrow);
        assert_eq!(resolve(0x0041_5550, true).ansi, true);
        assert_eq!(
            resolve(0xFFFF_7FFF, false).address,
            0xFFFF_7FFF,
            "an unclaimed handle"
        );
        assert_eq!(
            value_for(
                Procedure {
                    address: 0,
                    ansi: true
                },
                false
            ),
            0
        );
    }

    /// The text conversions: cut to the buffer with room for the terminator, terminated, an empty
    /// buffer untouched; an answer's text taken to its count and its terminator; a narrow length.
    #[test]
    fn the_text_conversions() {
        let mut wide = [0x23u16; 5];
        assert_eq!(put_wide(&mut OutBuf::from(&mut wide[..]), b"caf\xE9!"), 4);
        assert_eq!(wide, [0x63, 0x61, 0x66, 0xE9, 0]);
        let mut narrow = [b'#'; 4];
        let text: std::vec::Vec<u16> = "ab\u{4E00}d".encode_utf16().collect();
        assert_eq!(put_narrow(&mut OutBuf::from(&mut narrow[..]), &text), 3);
        assert_eq!(&narrow, b"ab?\0");
        let mut empty: [u8; 0] = [];
        assert_eq!(put_narrow(&mut OutBuf::from(&mut empty[..]), &text), 0);
        assert_eq!(got_text(&[1u16, 2, 0, 4], 4), &[1, 2]);
        assert_eq!(got_text(&[1u8, 2, 3], 2), &[1, 2]);
        assert_eq!(got_text(&[1u8, 2, 3], -1), &[] as &[u8]);
        assert_eq!(narrow_length(&text), 4);
        assert!(translates(WM_GETTEXTLENGTH) && !translates(rtl::user::WM_USER));
    }
}
