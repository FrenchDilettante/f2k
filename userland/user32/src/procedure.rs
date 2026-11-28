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
//! space ends below it). A handle lives as long as its process, one for each procedure of each
//! form handed out (Windows 2000 makes one per window or class that asks, and frees it with them;
//! F2K's handle names the procedure alone, so a process has as many as it has procedures). The
//! table grows on the process heap ([`crate::records`]); the handle's low word holds its index,
//! so a form names at most [`HANDLES`] procedures, and a procedure past them (or one the heap has
//! no room for) is answered as its address.
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
//! WM_SETTINGCHANGE's and WM_DEVMODECHANGE's string (lParam, when there is one) is converted as
//! WM_SETTEXT's is.
//!
//! A list box's string messages are translated when the list box holds strings (an owner-drawn list
//! box without LBS_HASSTRINGS holds values; [`translates_to`]): the strings LB_ADDSTRING,
//! LB_INSERTSTRING, LB_FINDSTRING, LB_FINDSTRINGEXACT, LB_SELECTSTRING, LB_ADDFILE and LB_DIR read;
//! LB_GETTEXT's item read whole (its LB_GETTEXTLEN first) and written converted, terminated, its
//! length in the caller's form answered; LB_GETTEXTLEN measured in the caller's form for a narrow
//! caller (a wide caller's is the narrow procedure's answer, which is no less). A combo box's
//! twins of them are translated the same way when it holds strings: CB_ADDSTRING, CB_INSERTSTRING,
//! CB_FINDSTRING, CB_FINDSTRINGEXACT, CB_SELECTSTRING and CB_DIR, CB_GETLBTEXT (CB_GETLBTEXTLEN
//! first) and CB_GETLBTEXTLEN.
//!
//! The character messages' character is converted too ([`char_message`]), through the ANSI code
//! page (code page 1252's 0x80 is U+20AC): WM_CHAR, WM_SYSCHAR, WM_DEADCHAR, WM_SYSDEADCHAR and
//! EM_SETPASSWORDCHAR carry it in wParam, WM_IME_CHAR too (a double-byte character whole, its lead
//! byte in the high byte), WM_MENUCHAR and WM_CHARTOITEM in wParam's low word, the high word kept.
//! A narrow character whose high byte is a lead byte of the code page is that double-byte
//! character; a wide one that takes two bytes reaches a narrow WM_CHAR, WM_SYSCHAR, WM_DEADCHAR or
//! WM_SYSDEADCHAR procedure a byte at a time, lead byte first (the answer the last call's), and the
//! other messages' with both bytes in the low word, the lead byte high.
//!
//! The other messages reach the procedure as they are. The messages the window manager sends are
//! wide, the character messages its queues hold too (user32's narrow calls convert theirs on the
//! way in and out, [`char_to_wide`] and [`char_to_narrow`]); a message another thread sent reaches
//! the procedure as it was sent.

use rtl::edge::{In, InStr, InWStr, OutBuf};
use rtl::user::{
    CreateStructW,
    WM_CHAR,
    WM_CHARTOITEM,
    WM_CREATE,
    WM_DEADCHAR,
    WM_DEVMODECHANGE,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
    WM_IME_CHAR,
    WM_MENUCHAR,
    WM_NCCREATE,
    WM_SETTEXT,
    WM_SETTINGCHANGE,
    WM_SYSCHAR,
    WM_SYSDEADCHAR,
};

use crate::combobox::{
    CB_ADDSTRING,
    CB_DIR,
    CB_FINDSTRING,
    CB_FINDSTRINGEXACT,
    CB_GETLBTEXT,
    CB_GETLBTEXTLEN,
    CB_INSERTSTRING,
    CB_SELECTSTRING,
};
use crate::edit::{EM_GETLINE, EM_REPLACESEL, EM_SETPASSWORDCHAR};
use crate::imports;
use crate::listbox::{
    LB_ADDFILE,
    LB_ADDSTRING,
    LB_DIR,
    LB_FINDSTRING,
    LB_FINDSTRINGEXACT,
    LB_GETTEXT,
    LB_GETTEXTLEN,
    LB_INSERTSTRING,
    LB_SELECTSTRING,
};
use crate::records::Table;

/// A window procedure, and whether it takes the narrow forms of the messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub address: u32,
    pub ansi: bool,
}

// --- The call-procedure handles ------------------------------------------------------------------

/// How many procedures of each form the handles can name: the index the low word holds below the
/// narrow form's bit.
pub const HANDLES: usize = NARROW_HANDLE as usize;

/// A handle's high word, and the bit of its low word that marks a narrow procedure's handle (the
/// rest of the low word is the table's index).
const HANDLE_TAG: u32 = 0xFFFF_0000;
const NARROW_HANDLE: u32 = 0x8000;

/// The procedures the handles name, by form: each record a procedure's address, at the index its
/// handle holds. A record, once set, is never taken: it names its procedure for the process's
/// life, and keeps its place (shared by the process's threads under user32's lock).
static WIDE: Table<1> = Table::new();
static NARROW: Table<1> = Table::new();

fn table(ansi: bool) -> &'static Table<1> {
    if ansi {
        &NARROW
    } else {
        &WIDE
    }
}

/// The handle naming `proc`: its record's, or a new record's; none when the form names as many
/// procedures as its handles can, or the heap has no room for another.
fn handle_of(proc: Procedure) -> Option<u32> {
    let address = proc.address as usize;
    let index = table(proc.ansi).with(|procedures| {
        procedures.index_of(address).or_else(|| {
            (procedures.len() < HANDLES && procedures.set([address])).then(|| procedures.len() - 1)
        })
    })?;
    Some(HANDLE_TAG | if proc.ansi { NARROW_HANDLE } else { 0 } | index as u32)
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
        pair(
            crate::listbox::list_box_proc_w as *const () as usize,
            crate::listbox::list_box_proc_a as *const () as usize,
        ),
        pair(
            crate::combobox::combo_box_proc_w as *const () as usize,
            crate::combobox::combo_box_proc_a as *const () as usize,
        ),
        pair(
            crate::combobox::combo_list_proc_w as *const () as usize,
            crate::combobox::combo_list_proc_a as *const () as usize,
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
        if let Some([address]) = table(ansi).with(|procedures| procedures.record_at(index)) {
            return Procedure {
                address: address as u32,
                ansi,
            };
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
    char_message(message)
        || matches!(
            message,
            WM_SETTEXT
                | WM_GETTEXT
                | WM_GETTEXTLENGTH
                | WM_NCCREATE
                | WM_CREATE
                | EM_REPLACESEL
                | EM_GETLINE
                | WM_SETTINGCHANGE
                | WM_DEVMODECHANGE
        )
}

/// Whether `message` is one a procedure of the other form receives translated when it goes to
/// `window`: [`translates`]' messages, and a list box's string messages when the list box holds
/// strings (LB_DIR's always; see the module notes).
pub fn translates_to(window: u32, message: u32) -> bool {
    translates(message)
        || (list_box_string_message(message)
            && crate::listbox::is_list_box(window as usize)
            && (message == LB_DIR || crate::listbox::holds_strings(window as usize)))
        || (combo_box_string_message(message)
            && crate::combobox::is_combo_box(window as usize)
            && (message == CB_DIR || crate::combobox::holds_strings(window as usize)))
}

/// Whether `message` is a combo box message that carries a string, in or out, or the length of
/// one: the list box's twins.
fn combo_box_string_message(message: u32) -> bool {
    matches!(
        message,
        CB_ADDSTRING
            | CB_INSERTSTRING
            | CB_FINDSTRING
            | CB_FINDSTRINGEXACT
            | CB_SELECTSTRING
            | CB_DIR
            | CB_GETLBTEXT
            | CB_GETLBTEXTLEN
    )
}

/// The message that measures the item text `message` (LB_GETTEXT, CB_GETLBTEXT, or their lengths')
/// reads.
fn text_length_message(message: u32) -> u32 {
    match message {
        CB_GETLBTEXT | CB_GETLBTEXTLEN => CB_GETLBTEXTLEN,
        _ => LB_GETTEXTLEN,
    }
}

/// The message that reads the item text `message` (LB_GETTEXT, CB_GETLBTEXT, or their lengths')
/// measures.
fn text_message(message: u32) -> u32 {
    match message {
        CB_GETLBTEXT | CB_GETLBTEXTLEN => CB_GETLBTEXT,
        _ => LB_GETTEXT,
    }
}

/// Whether `message` is a list box message that carries a string: one in (LB_ADDSTRING,
/// LB_INSERTSTRING, LB_FINDSTRING, LB_FINDSTRINGEXACT, LB_SELECTSTRING, LB_DIR, LB_ADDFILE) or one
/// out (LB_GETTEXT), or the length of one (LB_GETTEXTLEN).
fn list_box_string_message(message: u32) -> bool {
    // The list box's own (its range, past the combo box's).
    (list_box_string_in(message) && message >= LB_ADDSTRING)
        || matches!(message, LB_GETTEXT | LB_GETTEXTLEN)
}

/// Whether `message` is a list box (or combo box) message whose lParam is a string it reads.
fn list_box_string_in(message: u32) -> bool {
    matches!(
        message,
        LB_ADDSTRING
            | LB_INSERTSTRING
            | LB_FINDSTRING
            | LB_FINDSTRINGEXACT
            | LB_SELECTSTRING
            | LB_DIR
            | LB_ADDFILE
            | CB_ADDSTRING
            | CB_INSERTSTRING
            | CB_FINDSTRING
            | CB_FINDSTRINGEXACT
            | CB_SELECTSTRING
            | CB_DIR
    )
}

/// Whether `message` carries a character in wParam (see the module notes).
pub fn char_message(message: u32) -> bool {
    matches!(
        message,
        WM_CHAR
            | WM_SYSCHAR
            | WM_DEADCHAR
            | WM_SYSDEADCHAR
            | WM_IME_CHAR
            | WM_MENUCHAR
            | WM_CHARTOITEM
            | EM_SETPASSWORDCHAR
    )
}

/// The character message `message`'s narrow wParam in the wide form: its character (a double-byte
/// one when the high byte is a lead byte of the ANSI code page, the low byte alone otherwise)
/// converted, the rest of wParam kept (WM_MENUCHAR's menu kind, WM_CHARTOITEM's caret position).
/// Another message's wParam as it is.
pub fn char_to_wide(message: u32, wparam: u32) -> u32 {
    if !char_message(message) {
        return wparam;
    }
    let bytes = [(wparam >> 8) as u8, wparam as u8];
    let mut units = [0u16; 2];
    // A lead byte and its trail byte make one character; two single-byte ones are not one.
    let unit = if bytes[0] != 0 && imports::multi_byte_to_unicode(&mut units, &bytes) == 1 {
        units[0]
    } else {
        imports::multi_byte_to_unicode(&mut units[..1], &bytes[1..]);
        units[0]
    };
    (wparam & 0xFFFF_0000) | u32::from(unit)
}

/// The narrow form of the wide character in wParam's low word: its bytes (one, or a double-byte
/// character's two, lead byte first) and how many there are.
fn narrow_bytes(wparam: u32) -> ([u8; 2], usize) {
    let mut bytes = [0u8; 2];
    let length = imports::unicode_to_multi_byte(&mut bytes, &[wparam as u16]);
    (bytes, length.clamp(1, 2))
}

/// The character message `message`'s wide wParam in the narrow form: its character converted, a
/// double-byte character's two bytes in the low word, the lead byte high; the rest of wParam kept.
/// Another message's wParam as it is.
pub fn char_to_narrow(message: u32, wparam: u32) -> u32 {
    if !char_message(message) {
        return wparam;
    }
    let (bytes, length) = narrow_bytes(wparam);
    let low = match length {
        2 => u32::from(bytes[0]) << 8 | u32::from(bytes[1]),
        _ => u32::from(bytes[0]),
    };
    (wparam & 0xFFFF_0000) | low
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
    if proc.ansi == caller_ansi || !translates_to(window, message) {
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
        WM_SETTEXT | EM_REPLACESEL | WM_SETTINGCHANGE | WM_DEVMODECHANGE if lparam != 0 => {
            // SAFETY: WM_SETTEXT's, EM_REPLACESEL's, WM_SETTINGCHANGE's and WM_DEVMODECHANGE's
            // lParam as its sender hands it over: a NUL-terminated string, wide in this form.
            let text = unsafe { InWStr::new(lparam as usize as *const u16) };
            with_narrow(text, |bytes| call(message, wparam, bytes.as_ptr() as i32)).unwrap_or(0)
        }
        WM_CHAR | WM_SYSCHAR | WM_DEADCHAR | WM_SYSDEADCHAR => {
            // A double-byte character a byte at a time, lead byte first.
            let (bytes, length) = narrow_bytes(wparam);
            let high = wparam & 0xFFFF_0000;
            let mut answer = 0;
            for &byte in &bytes[..length] {
                answer = call(message, high | u32::from(byte), lparam);
            }
            answer
        }
        _ if char_message(message) => call(message, char_to_narrow(message, wparam), lparam),
        _ if list_box_string_in(message) && lparam != 0 => {
            // SAFETY: the list box message's lParam as its sender hands it over: a NUL-terminated
            // string, wide in this form.
            let text = unsafe { InWStr::new(lparam as usize as *const u16) };
            with_narrow(text, |bytes| call(message, wparam, bytes.as_ptr() as i32)).unwrap_or(-1)
        }
        LB_GETTEXT | CB_GETLBTEXT if lparam != 0 => {
            let length = call(text_length_message(message), wparam, 0);
            if length < 0 {
                return length;
            }
            with_bytes(length as usize + 1, |bytes| {
                let got = call(message, wparam, bytes.as_mut_ptr() as i32);
                if got < 0 {
                    return got;
                }
                let text = got_text(bytes, got);
                // SAFETY: LB_GETTEXT's lParam as its sender hands it over: a buffer that holds the
                // item's text and its terminator.
                let mut out = unsafe { OutBuf::new(lparam as usize as *mut u16, text.len() + 1) };
                put_wide(&mut out, text) as i32
            })
            .unwrap_or(-1)
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
    narrow_to_wide(message, wparam, lparam, |message, wparam, lparam| {
        imports::call_procedure(proc, window, message, wparam, lparam)
    })
}

/// A narrow message handed on in the wide form through `call` (a wide procedure, or the window
/// manager carrying a text to another process): its text converted on the way in, and on the way
/// back into the narrow caller's buffer.
pub fn narrow_to_wide(
    message: u32,
    wparam: u32,
    lparam: i32,
    mut call: impl FnMut(u32, u32, i32) -> i32,
) -> i32 {
    match message {
        WM_SETTEXT | EM_REPLACESEL | WM_SETTINGCHANGE | WM_DEVMODECHANGE if lparam != 0 => {
            // SAFETY: WM_SETTEXT's, EM_REPLACESEL's, WM_SETTINGCHANGE's and WM_DEVMODECHANGE's
            // lParam as its sender hands it over: a NUL-terminated string, narrow in this form.
            let text = unsafe { InStr::new(lparam as usize as *const u8) };
            crate::with_wide_z(text.bytes(), |units| {
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
        _ if char_message(message) => call(message, char_to_wide(message, wparam), lparam),
        _ if list_box_string_in(message) && lparam != 0 => {
            // SAFETY: the list box message's lParam as its sender hands it over: a NUL-terminated
            // string, narrow in this form.
            let text = unsafe { InStr::new(lparam as usize as *const u8) };
            crate::with_wide_z(text.bytes(), |units| {
                call(message, wparam, units.as_ptr() as i32)
            })
            .unwrap_or(-1)
        }
        LB_GETTEXT | LB_GETTEXTLEN | CB_GETLBTEXT | CB_GETLBTEXTLEN => {
            let length = call(text_length_message(message), wparam, 0);
            if length < 0 {
                return length;
            }
            with_units(length as usize + 1, |units| {
                let got = call(text_message(message), wparam, units.as_mut_ptr() as i32);
                if got < 0 {
                    return got;
                }
                let text = got_text(units, got);
                if message == LB_GETTEXTLEN || message == CB_GETLBTEXTLEN {
                    return narrow_length(text) as i32;
                }
                if lparam == 0 {
                    return -1;
                }
                // SAFETY: LB_GETTEXT's lParam as its sender hands it over: a buffer that holds the
                // item's text, narrow, and its terminator.
                let mut out =
                    unsafe { OutBuf::new(lparam as usize as *mut u8, narrow_length(text) + 1) };
                put_narrow(&mut out, text) as i32
            })
            .unwrap_or(-1)
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
    use rtl::user::{WM_KEYDOWN, WM_USER};

    use super::*;

    /// The handles name as many procedures as a process has, far past the 128 of each form a
    /// fixed table held: each its own handle, the same each time, resolving to its procedure.
    #[test]
    fn handles_name_any_number_of_procedures() {
        let procedures: std::vec::Vec<Procedure> = (0..600u32)
            .map(|index| Procedure {
                address: 0x0050_0000 + 16 * index,
                ansi: index % 2 == 0,
            })
            .collect();
        let handles: std::vec::Vec<u32> = procedures
            .iter()
            .map(|&proc| value_for(proc, !proc.ansi))
            .collect();
        assert!(handles.iter().all(|&handle| handle >> 16 == 0xFFFF));
        for (&proc, &handle) in procedures.iter().zip(&handles) {
            assert_eq!(value_for(proc, !proc.ansi), handle);
            assert_eq!(resolve(handle, !proc.ansi), proc);
        }
        let mut distinct = handles.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), handles.len());
    }

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
        assert!(translates(WM_GETTEXTLENGTH) && !translates(WM_USER));
        assert!(translates(WM_SETTINGCHANGE) && translates(WM_DEVMODECHANGE));
    }

    std::thread_local! {
        static GOT: core::cell::RefCell<std::vec::Vec<(u32, u32)>> =
            const { core::cell::RefCell::new(std::vec::Vec::new()) };
    }

    /// A procedure that records the message and wParam it gets, answering 7.
    fn recording(_: u32, message: u32, wparam: u32, _: i32) -> i32 {
        GOT.with(|got| got.borrow_mut().push((message, wparam)));
        7
    }

    fn got() -> std::vec::Vec<(u32, u32)> {
        GOT.with(|got| got.take())
    }

    /// The character messages.
    const CHARS: [u32; 8] = [
        WM_CHAR,
        WM_SYSCHAR,
        WM_DEADCHAR,
        WM_SYSDEADCHAR,
        WM_IME_CHAR,
        WM_MENUCHAR,
        WM_CHARTOITEM,
        EM_SETPASSWORDCHAR,
    ];

    /// The character conversions through code page 1252: 0x80 is U+20AC, 0x9F U+0178, ASCII and
    /// Latin-1 as they are; every byte comes back from its wide form; the high word is kept; a
    /// character the code page lacks is '?'; another message's wParam is left.
    #[test]
    fn the_character_conversions() {
        for message in CHARS {
            assert!(char_message(message) && translates(message));
            assert_eq!(char_to_wide(message, 0x80), 0x20AC);
            assert_eq!(char_to_wide(message, 0x9F), 0x0178);
            assert_eq!(char_to_wide(message, 0xE9), 0x00E9);
            assert_eq!(char_to_wide(message, b'a'.into()), u32::from(b'a'));
            assert_eq!(char_to_narrow(message, 0x20AC), 0x80);
            assert_eq!(char_to_narrow(message, 0x0178), 0x9F);
            assert_eq!(char_to_narrow(message, 0x4E00), u32::from(b'?'));
            assert_eq!(char_to_wide(message, 0x0003_0080), 0x0003_20AC);
            assert_eq!(char_to_narrow(message, 0x0003_20AC), 0x0003_0080);
            for byte in 0..=0xFFu32 {
                assert_eq!(
                    char_to_narrow(message, char_to_wide(message, byte)),
                    byte,
                    "{message:#x} {byte:#x}"
                );
            }
        }
        assert!(!char_message(WM_KEYDOWN));
        assert_eq!(char_to_wide(WM_KEYDOWN, 0x80), 0x80);
        assert_eq!(char_to_narrow(WM_USER, 0x20AC), 0x20AC);
    }

    /// A character message crossing between the forms: a narrow caller's 0x80 reaches a wide
    /// procedure as U+20AC, a wide caller's U+20AC a narrow one as 0x80, WM_MENUCHAR's high word
    /// kept; the same form's reaches it as it is; the procedure's answer comes back.
    ///
    /// Pins: user32.CallWindowProcA, user32.CallWindowProcW
    #[test]
    fn characters_cross_between_the_forms() {
        let address = crate::imports::host::procedure(recording);
        let wide = Procedure {
            address,
            ansi: false,
        };
        let narrow = Procedure {
            address,
            ansi: true,
        };
        for message in CHARS {
            assert_eq!(call(wide, true, 1, message, 0x80, 0), 7);
            assert_eq!(call(narrow, false, 1, message, 0x20AC, 0), 7);
            assert_eq!(call(wide, false, 1, message, 0x20AC, 0), 7);
            assert_eq!(call(narrow, true, 1, message, 0x80, 0), 7);
            assert_eq!(
                got(),
                [
                    (message, 0x20AC),
                    (message, 0x80),
                    (message, 0x20AC),
                    (message, 0x80)
                ]
            );
        }
        let menu_char = 0x0010_0000 | 0x00E9;
        call(narrow, false, 1, WM_MENUCHAR, menu_char, 0);
        call(wide, true, 1, WM_MENUCHAR, menu_char, 0);
        assert_eq!(got(), [(WM_MENUCHAR, menu_char), (WM_MENUCHAR, menu_char)]);
        // Through the exports: a handle for the other form's procedure.
        assert_eq!(
            call_window_proc_a(value_for(wide, true) as usize, 1, WM_CHAR, 0x80, 0),
            7
        );
        assert_eq!(
            call_window_proc_w(value_for(narrow, false) as usize, 1, WM_SYSCHAR, 0x20AC, 0),
            7
        );
        assert_eq!(got(), [(WM_CHAR, 0x20AC), (WM_SYSCHAR, 0x80)]);
    }
}
