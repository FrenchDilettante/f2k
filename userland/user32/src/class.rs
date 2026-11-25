//! The window classes: the RegisterClass family, UnregisterClass, GetClassInfo, GetClassInfoEx
//! and GetClassName, GetClassLong and SetClassLong, each over its win32k service ([`imports`]);
//! and the stock cursors LoadCursor answers.
//!
//! The wide forms hand the caller's names to the kernel as they are; the narrow ones convert the
//! class name and the menu name to UTF-16 first (an integer atom or menu id goes as it is). A
//! registration is 4.0-compatible (MSVC 6 links its programs for subsystem 4.0). The kernel answers
//! the class decisions' Win32 errors themselves, which [`crate::window_error`] hands on as they
//! are.
//!
//! A class's string menu name is kept in the process twice, wide and narrow, in one block of
//! user32's own ([`menu_copies`]), as Windows 2000's class keeps its client-side copies: the window
//! manager holds the name and the block's address, and GetClassInfo, GetClassInfoEx and
//! GetClassLong answer the copy of the caller's form, never the string the registration was handed
//! (the guiclass capture). A class's procedure answers a caller of the other form as a handle
//! naming it, as GetWindowLong answers a window's ([`procedure::value_for`]); GetClassLong reads
//! the class's fields and extra bytes through NtUserQueryWindow, as GetWindowLong reads the
//! window's.
//!
//! The stock cursors are the system's records in win32k (made at its boot, as Windows 2000 loads
//! them from user32's resources): LoadCursor with no module finds the one of its IDC_ id there
//! (NtUserFindExistingCursorIcon on the module 0), and a class names it to the kernel as any other
//! cursor. A module's cursors are a seam: LoadCursor loads none yet.

#[cfg(not(test))]
use core::sync::atomic::{AtomicBool, Ordering};

use rtl::edge::In;
use rtl::icon::{ICON_SIZE, RT_CURSOR};

use crate::imports::{self, UserBuffer};
use crate::procedure::{self, Procedure};
use crate::{caller_bytes_mut, failed, failed_with, spec, NameA, Out, ERROR_INVALID_PARAMETER};

/// WNDCLASSA and WNDCLASSW (40 bytes): a class as RegisterClass takes it, its two names narrow or
/// wide as the call is.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WndClass {
    pub style: u32,
    pub wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub instance: usize,
    pub icon: usize,
    pub cursor: usize,
    pub background: usize,
    pub menu_name: usize,
    pub class_name: usize,
}

/// WNDCLASSEXA and WNDCLASSEXW (48 bytes): WNDCLASS with its size first and the small icon last;
/// the wide form is what win32k's class services take.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WndClassEx {
    pub cb_size: u32,
    pub style: u32,
    pub wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub instance: usize,
    pub icon: usize,
    pub cursor: usize,
    pub background: usize,
    pub menu_name: usize,
    pub class_name: usize,
    pub icon_sm: usize,
}

// The pointers and handles are the platform's pointer size: on x86, Windows 2000's layouts (the
// host tests' structures are wider, with their own addresses in them).
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<WndClass>() == 40);
    assert!(core::mem::size_of::<WndClassEx>() == 48);
    assert!(core::mem::offset_of!(WndClassEx, class_name) == 40);
};

/// The structure win32k's class services take.
pub type WndClassExW = WndClassEx;

impl WndClassEx {
    /// The WNDCLASSEX form of `class`: its fields, the size the extended form's, no small icon.
    fn of(class: &WndClass) -> WndClassEx {
        WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: class.style,
            wnd_proc: class.wnd_proc,
            cb_cls_extra: class.cb_cls_extra,
            cb_wnd_extra: class.cb_wnd_extra,
            instance: class.instance,
            icon: class.icon,
            cursor: class.cursor,
            background: class.background,
            menu_name: class.menu_name,
            class_name: class.class_name,
            icon_sm: 0,
        }
    }
}

/// NtUserRegisterClassExWOW's flags word: the caller is 4.0-compatible; the class's procedure
/// takes the narrow forms of the messages (a narrow registration's, Windows 2000's CSF_ANSIPROC).
const REGISTER_WIN40_COMPAT: u32 = 0x1;
pub const REGISTER_ANSI_PROC: u32 = 0x10;

/// The longest class name the services answer, its terminator included: an atom's name, or '#'
/// and an integer atom's digits.
const CLASS_NAME_UNITS: usize = 130;

// ERROR_FILE_NOT_FOUND: what a registration leaves as the last error.
use rtl::winerror::ERROR_FILE_NOT_FOUND;
// ERROR_NOACCESS: a buffer the call cannot reach.
use rtl::winerror::ERROR_NOACCESS;
// ERROR_RESOURCE_TYPE_NOT_FOUND: LoadCursor's answer for a stock cursor id there is none of.
use rtl::winerror::ERROR_RESOURCE_TYPE_NOT_FOUND;

// --- The stock cursors ---------------------------------------------------------------------------

/// The system's stock cursor or icon (`kind` RT_CURSOR or RT_ICON) of the IDC_ or IDI_ id `id`:
/// its handle, NULL with ERROR_RESOURCE_TYPE_NOT_FOUND for an id that names none.
pub fn stock(id: u16, kind: u16) -> usize {
    match imports::find_existing_cursor_icon(0, usize::from(id), ICON_SIZE, ICON_SIZE, kind) {
        Ok(0) => failed(ERROR_RESOURCE_TYPE_NOT_FOUND),
        Ok(handle) => Some(handle),
        Err(status) => failed(imports::dos_error(status)),
    }
    .unwrap_or(0)
}

/// LoadCursorA: a stock cursor (no module, an IDC_ id); see [`load_cursor`].
///
/// # Safety
///
/// `name` is a resource id or a NUL-terminated string, as for the platform's.
#[unsafe(export_name = "f2k_export_LoadCursorA")]
pub unsafe extern "system" fn load_cursor_a(instance: usize, name: *const u8) -> usize {
    // SAFETY: the caller's contract.
    let id = match unsafe { NameA::new(name) } {
        NameA::Id(id) => Some(id),
        NameA::Text(_) => None,
    };
    load_cursor(&spec::LoadCursorA, instance, name as usize, id)
}

/// LoadCursorW: a stock cursor (no module, an IDC_ id); see [`load_cursor`].
#[unsafe(export_name = "f2k_export_LoadCursorW")]
pub extern "system" fn load_cursor_w(instance: usize, name: *const u16) -> usize {
    let raw = name as usize;
    let id = (raw >> 16 == 0).then_some(raw as u16);
    load_cursor(&spec::LoadCursorW, instance, raw, id)
}

/// LoadCursor's core: with no module, the stock cursor the id names (the same handle from either
/// form), NULL with ERROR_RESOURCE_TYPE_NOT_FOUND for an id that names none (as the guiwin capture
/// shows); a module's cursor, or one by name, goes to the stub routine (LoadCursor reads no
/// cursor resource yet).
fn load_cursor(entry: &rtl::stub::Entry, instance: usize, raw: usize, id: Option<u16>) -> usize {
    match (instance, id) {
        (0, Some(id)) => stock(id, RT_CURSOR),
        _ => {
            // SAFETY: the arguments as the export's kinds read them: a handle and an address,
            // neither read as memory.
            unsafe {
                crate::stub::stubbed(
                    entry,
                    "cursors from a module's resources: no cursor resource is read yet",
                    &[instance as u64, raw as u64],
                ) as usize
            }
        }
    }
}

// --- Registration --------------------------------------------------------------------------------

/// The registration of `class`, its two names already as the service takes them (`name` the class
/// name's), through the narrow entry point when `ansi` (its procedure takes the narrow forms of the
/// messages): the atom, the last error ERROR_FILE_NOT_FOUND for a string name (as every such
/// registration the captures show leaves it; a name written as an integer atom, "#123", leaves it
/// alone: guiclass `intname`); 0 with the class decision's error. A string menu name goes to the
/// window manager as the copies the class keeps ([`menu_copies`]), freed when the registration
/// fails.
///
/// # Safety
///
/// The class's menu name is an integer or a NUL-terminated UTF-16 string the call may read.
unsafe fn register(mut class: WndClassEx, name: usize, ansi: bool) -> u16 {
    class.cb_size = core::mem::size_of::<WndClassEx>() as u32;
    class.class_name = name;
    let mut copies = None;
    if class.menu_name >> 16 != 0 {
        // SAFETY: the caller's contract: a NUL-terminated string.
        let units = unsafe { rtl::cstr::units_until_nul(class.menu_name as *const u16) };
        if !units.is_empty() {
            let Some(block) = menu_copies(units) else {
                return failed(crate::ERROR_NOT_ENOUGH_MEMORY).unwrap_or(0);
            };
            class.menu_name = block;
            copies = Some(block);
        }
    }
    match failed_with(
        imports::register_class(
            &class,
            name,
            REGISTER_WIN40_COMPAT | if ansi { REGISTER_ANSI_PROC } else { 0 },
            0,
        ),
        crate::window_error,
    ) {
        Some(atom) => {
            // SAFETY: the class name, a NUL-terminated UTF-16 string when no integer (the
            // caller's).
            if !unsafe { integer_name(name) } {
                imports::set_last_error(ERROR_FILE_NOT_FOUND);
            }
            atom
        }
        None => {
            if let Some(block) = copies {
                imports::local_free(block);
            }
            0
        }
    }
}

/// Whether the class name `name` is an integer atom, or a string of '#' and decimal digits alone
/// (an integer atom's written form).
///
/// # Safety
///
/// `name` is an integer atom or the address of a NUL-terminated UTF-16 string.
unsafe fn integer_name(name: usize) -> bool {
    if name >> 16 == 0 {
        return true;
    }
    // SAFETY: the caller's contract: a NUL-terminated string.
    let units = unsafe { rtl::cstr::units_until_nul(name as *const u16) };
    matches!(units, [hash, digits @ ..] if *hash == u16::from(b'#')
        && !digits.is_empty()
        && digits.iter().all(|&unit| (u16::from(b'0')..=u16::from(b'9')).contains(&unit)))
}

/// A string menu name's two copies, as a class keeps them in the process: one fixed block holding
/// the name's UTF-16 units and their terminator, then its narrow form (the ANSI code page's) and
/// its terminator. The block's address is the wide copy's, which the window manager keeps as the
/// class's menu name; the narrow copy follows it ([`narrow_menu`]). None when there is no room.
fn menu_copies(units: &[u16]) -> Option<usize> {
    let wide = 2 * (units.len() + 1);
    // A double-byte code page's narrow form takes at most two bytes a unit.
    let narrow = 2 * units.len() + 1;
    let block = imports::local_alloc(imports::LMEM_FIXED | imports::LMEM_ZEROINIT, wide + narrow)?;
    // SAFETY: the fixed block just allocated: `wide + narrow` bytes, its address 8-aligned, ours.
    let bytes = unsafe { core::slice::from_raw_parts_mut(block as *mut u8, wide + narrow) };
    for (at, unit) in units.iter().enumerate() {
        bytes[2 * at..2 * at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let written = imports::unicode_to_multi_byte(&mut bytes[wide..wide + narrow - 1], units);
    bytes[wide + written] = 0;
    Some(block)
}

/// The menu name a caller of the narrow (`ansi`) or wide form is answered for the window manager's
/// `value`: none or an integer id as it is, a string as the copy of the caller's form
/// ([`menu_copies`]: the wide one is the block's start, the narrow one follows its terminator).
fn menu_for(value: usize, ansi: bool) -> usize {
    if value >> 16 == 0 || !ansi {
        return value;
    }
    // SAFETY: a string menu name the window manager holds is a block menu_copies made: its wide
    // copy, NUL-terminated, first.
    let units = unsafe { rtl::cstr::units_until_nul(value as *const u16) };
    value + 2 * (units.len() + 1)
}

/// A narrow class's registration: its class name and menu name converted, then [`register`].
///
/// # Safety
///
/// The class's names are integers or NUL-terminated strings, as for the platform's.
unsafe fn register_a(mut class: WndClassEx) -> u16 {
    // SAFETY: the caller's contract.
    let (name, menu) = unsafe {
        (
            NameA::new(class.class_name as *const u8),
            NameA::new(class.menu_name as *const u8),
        )
    };
    name.with_wide(|name| {
        menu.with_wide(|menu| {
            class.menu_name = menu;
            // SAFETY: the menu name converted: an integer or a NUL-terminated string.
            unsafe { register(class, name, true) }
        })
    })
    .flatten()
    .unwrap_or(0)
}

/// RegisterClassW: the class registered; its atom, or 0 with the last error (1410 for a class of
/// that name and module already registered).
///
/// # Safety
///
/// The caller's WNDCLASSW, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterClassW")]
pub unsafe extern "system" fn register_class_w(class: *const WndClass) -> u16 {
    // SAFETY: the caller's structure.
    let class = unsafe { In::new(class) }.read();
    // SAFETY: the caller's contract, for the class's menu name.
    unsafe { register(WndClassEx::of(&class), class.class_name, false) }
}

/// RegisterClassA: RegisterClassW's, the class's names converted first.
///
/// # Safety
///
/// The caller's WNDCLASSA, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterClassA")]
pub unsafe extern "system" fn register_class_a(class: *const WndClass) -> u16 {
    // SAFETY: the caller's structure, and its names.
    unsafe { register_a(WndClassEx::of(&In::new(class).read())) }
}

/// RegisterClassExW: RegisterClassW's, with the small icon; ERROR_INVALID_PARAMETER for a cbSize
/// that is not the structure's.
///
/// # Safety
///
/// The caller's WNDCLASSEXW, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterClassExW")]
pub unsafe extern "system" fn register_class_ex_w(class: *const WndClassEx) -> u16 {
    // SAFETY: the caller's structure.
    let class = unsafe { In::new(class) }.read();
    if class.cb_size as usize != core::mem::size_of::<WndClassEx>() {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's contract, for the class's menu name.
    unsafe { register(class, class.class_name, false) }
}

/// RegisterClassExA: RegisterClassExW's, the class's names converted first.
///
/// # Safety
///
/// The caller's WNDCLASSEXA, as for the platform's.
#[unsafe(export_name = "f2k_export_RegisterClassExA")]
pub unsafe extern "system" fn register_class_ex_a(class: *const WndClassEx) -> u16 {
    // SAFETY: the caller's structure.
    let class = unsafe { In::new(class) }.read();
    if class.cb_size as usize != core::mem::size_of::<WndClassEx>() {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's contract, for the class's names.
    unsafe { register_a(class) }
}

// --- user32's own classes ------------------------------------------------------------------------

/// user32's module handle, under which the classes it registers sit: its base, the module the
/// window manager looks every process's classes up under after the process's own.
pub const USER32_MODULE: usize = 0x77E1_0000;

/// The class styles user32's own classes have (winuser.h's CS_*).
const CS_VREDRAW: u32 = 0x0001;
const CS_HREDRAW: u32 = 0x0002;
const CS_DBLCLKS: u32 = 0x0008;
const CS_PARENTDC: u32 = 0x0080;
const CS_SAVEBITS: u32 = 0x0800;

/// The dialog class's atom: the documented #32770.
pub const DIALOG_CLASS_ATOM: u16 = 0x8002;

/// Whether this process has registered user32's own classes.
#[cfg(not(test))]
static SYSTEM_CLASSES: AtomicBool = AtomicBool::new(false);

/// Whether user32's own classes are still to be registered: once per process.
#[cfg(not(test))]
fn system_classes_due() -> bool {
    !SYSTEM_CLASSES.swap(true, Ordering::AcqRel)
}

#[cfg(test)]
std::thread_local! {
    /// A host test that wants user32's own classes asks for them here; the others' window
    /// managers hold only their own.
    pub static SYSTEM_CLASSES_WANTED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
fn system_classes_due() -> bool {
    SYSTEM_CLASSES_WANTED.with(|wanted| wanted.replace(false))
}

/// user32's own classes registered in the calling process, once: the Button, Static, ScrollBar and
/// Edit controls, the dialog class (#32770) and the menu class (#32768), as Windows 2000's user32
/// registers them in every process it connects. Each names its procedure's two forms, so a window
/// takes the form of the call that created it (CreateWindowExA's is no Unicode window). They are
/// registered when the process first creates a window, not when user32 loads, so a console program
/// that loads user32 makes no connection to the window manager; the last error is left as it was.
pub fn register_system_classes() {
    if !system_classes_due() {
        return;
    }
    let arrow = stock(32512, RT_CURSOR);
    let classes: [(usize, u32, usize, usize, i32); 5] = [
        (
            BUTTON_NAME.as_ptr() as usize,
            CS_DBLCLKS | CS_PARENTDC | CS_VREDRAW | CS_HREDRAW,
            procedures::button().0,
            procedures::button().1,
            crate::button::BUTTON_EXTRA,
        ),
        (
            STATIC_NAME.as_ptr() as usize,
            CS_DBLCLKS | CS_PARENTDC,
            procedures::static_control().0,
            procedures::static_control().1,
            crate::static_control::STATIC_EXTRA,
        ),
        (
            SCROLLBAR_NAME.as_ptr() as usize,
            CS_DBLCLKS | CS_PARENTDC | CS_VREDRAW | CS_HREDRAW,
            procedures::scroll_bar().0,
            procedures::scroll_bar().1,
            crate::scrollbar::SCROLLBAR_EXTRA,
        ),
        (
            usize::from(DIALOG_CLASS_ATOM),
            CS_DBLCLKS | CS_SAVEBITS,
            procedures::dialog().0,
            procedures::dialog().1,
            crate::dialog::DLGWINDOWEXTRA,
        ),
        (
            usize::from(crate::menubar::MENU_CLASS_ATOM),
            CS_DBLCLKS | CS_SAVEBITS,
            procedures::menu().0,
            procedures::menu().1,
            crate::menubar::MENU_EXTRA,
        ),
    ];
    for (name, style, wide, narrow, extra) in classes {
        let class = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style,
            wnd_proc: wide,
            cb_wnd_extra: extra,
            instance: USER32_MODULE,
            cursor: arrow,
            class_name: name,
            ..WndClassEx::default()
        };
        let atom = imports::register_class(&class, name, REGISTER_WIN40_COMPAT, narrow as u32);
        if name == SCROLLBAR_NAME.as_ptr() as usize {
            if let Ok(atom) = atom {
                crate::scrollbar::SCROLLBAR_ATOM
                    .store(u32::from(atom), core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    // The Edit control, with the I-beam cursor.
    let edit = WndClassEx {
        cb_size: core::mem::size_of::<WndClassEx>() as u32,
        style: CS_DBLCLKS | CS_PARENTDC,
        wnd_proc: procedures::edit().0,
        instance: USER32_MODULE,
        cursor: stock(IDC_IBEAM, RT_CURSOR),
        class_name: EDIT_NAME.as_ptr() as usize,
        ..WndClassEx::default()
    };
    let _ = imports::register_class(
        &edit,
        edit.class_name,
        REGISTER_WIN40_COMPAT,
        procedures::edit().1 as u32,
    );
}

/// The I-beam cursor's IDC_ id, the Edit class's.
const IDC_IBEAM: u16 = 32513;

/// The system classes Windows 2000 has (user32's and win32k's, as the platform documents them)
/// that F2K does not register yet: each one's name, and what it is, as a log line names it.
const MISSING_SYSTEM_CLASSES: [(&str, &str); 8] = [
    ("ListBox", "the ListBox control class"),
    ("ComboBox", "the ComboBox control class"),
    (
        "ComboLBox",
        "the ComboLBox class (a combo box's drop-down list)",
    ),
    ("MDIClient", "the MDIClient class"),
    ("Message", "the Message class (message-only windows)"),
    ("DDEMLEvent", "the DDEMLEvent class"),
    ("#32771", "the task switch window class (#32771)"),
    ("#32772", "the icon title class (#32772)"),
];

/// The system class Windows 2000 has and F2K does not register yet that `class` names (an atom,
/// or the address of its wide name, matched as class names are, ignoring case): its name and what
/// it is, as a log line names them; none for any other class.
///
/// # Safety
///
/// A name's address is a NUL-terminated UTF-16 string the call may read (one the creation's
/// service has read).
pub unsafe fn missing_system_class(class: usize) -> Option<(&'static str, &'static str)> {
    let named = |name: &str| {
        MISSING_SYSTEM_CLASSES
            .iter()
            .find(|(missing, _)| *missing == name)
            .copied()
    };
    if class >> 16 == 0 {
        // The integer atoms of the numbered classes (#32771 is 0x8003).
        return match class {
            0x8003 => named("#32771"),
            0x8004 => named("#32772"),
            _ => None,
        };
    }
    // SAFETY: the caller's contract.
    let units = unsafe { rtl::edge::InWStr::new(class as *const u16) }.units();
    MISSING_SYSTEM_CLASSES
        .iter()
        .find(|(name, _)| {
            name.len() == units.len()
                && name.bytes().enumerate().all(|(index, byte)| {
                    let unit = units.get(index);
                    unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte)
                })
        })
        .copied()
}

/// The names of the controls' classes, NUL-terminated.
const BUTTON_NAME: [u16; 7] = units::<7>("Button");
const STATIC_NAME: [u16; 7] = units::<7>("Static");
const EDIT_NAME: [u16; 5] = units::<5>("Edit");
const SCROLLBAR_NAME: [u16; 10] = units::<10>("ScrollBar");

/// `text`'s units, NUL-terminated, in an array of `N` (its length plus one).
const fn units<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    let mut out = [0u16; N];
    let mut at = 0;
    while at < bytes.len() {
        out[at] = bytes[at] as u16;
        at += 1;
    }
    out
}

/// The entry points user32's classes are registered with: the procedures' addresses on the target,
/// the stand-ins' numbers for them in the host tests (whose procedure calls go through a table).
#[cfg(not(test))]
mod procedures {
    pub fn button() -> (usize, usize) {
        (
            crate::button::button_proc_w as *const () as usize,
            crate::button::button_proc_a as *const () as usize,
        )
    }

    pub fn static_control() -> (usize, usize) {
        (
            crate::static_control::static_proc_w as *const () as usize,
            crate::static_control::static_proc_a as *const () as usize,
        )
    }

    pub fn dialog() -> (usize, usize) {
        (
            crate::dialog::def_dlg_proc_w as *const () as usize,
            crate::dialog::def_dlg_proc_a as *const () as usize,
        )
    }

    pub fn edit() -> (usize, usize) {
        (
            crate::edit::edit_proc_w as *const () as usize,
            crate::edit::edit_proc_a as *const () as usize,
        )
    }

    pub fn scroll_bar() -> (usize, usize) {
        (
            crate::scrollbar::scroll_bar_proc_w as *const () as usize,
            crate::scrollbar::scroll_bar_proc_a as *const () as usize,
        )
    }

    pub fn menu() -> (usize, usize) {
        (
            crate::menubar::menu_proc_w as *const () as usize,
            crate::menubar::menu_proc_a as *const () as usize,
        )
    }
}

#[cfg(test)]
mod procedures {
    use crate::imports::host::procedure;

    fn button_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::button::button_proc_w(window as usize, message, wparam, lparam)
    }

    fn button_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::button::button_proc_a(window as usize, message, wparam, lparam)
    }

    fn static_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::static_control::static_proc_w(window as usize, message, wparam, lparam)
    }

    fn static_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::static_control::static_proc_a(window as usize, message, wparam, lparam)
    }

    fn dialog_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::dialog::def_dlg_proc_w(window as usize, message, wparam, lparam)
    }

    fn dialog_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::dialog::def_dlg_proc_a(window as usize, message, wparam, lparam)
    }

    pub fn button() -> (usize, usize) {
        (procedure(button_w) as usize, procedure(button_a) as usize)
    }

    pub fn static_control() -> (usize, usize) {
        (procedure(static_w) as usize, procedure(static_a) as usize)
    }

    pub fn dialog() -> (usize, usize) {
        (procedure(dialog_w) as usize, procedure(dialog_a) as usize)
    }

    fn menu_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::menubar::menu_proc_w(window as usize, message, wparam, lparam)
    }

    fn menu_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::menubar::menu_proc_a(window as usize, message, wparam, lparam)
    }

    pub fn menu() -> (usize, usize) {
        (procedure(menu_w) as usize, procedure(menu_a) as usize)
    }

    fn edit_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::edit::edit_proc_w(window as usize, message, wparam, lparam)
    }

    fn edit_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::edit::edit_proc_a(window as usize, message, wparam, lparam)
    }

    pub fn edit() -> (usize, usize) {
        (procedure(edit_w) as usize, procedure(edit_a) as usize)
    }

    fn scroll_bar_w(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::scrollbar::scroll_bar_proc_w(window as usize, message, wparam, lparam)
    }

    fn scroll_bar_a(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::scrollbar::scroll_bar_proc_a(window as usize, message, wparam, lparam)
    }

    pub fn scroll_bar() -> (usize, usize) {
        (
            procedure(scroll_bar_w) as usize,
            procedure(scroll_bar_a) as usize,
        )
    }
}

// --- Unregistration ------------------------------------------------------------------------------

/// UnregisterClass's core over the name as the service takes it: TRUE, or FALSE with the
/// kernel's error (1411 for no such class, 1412 for a class that still has windows).
fn unregister(name: usize, instance: usize) -> u32 {
    crate::answered(imports::unregister_class(name, instance)).is_some() as u32
}

/// UnregisterClassW: the class of the module unregistered (by name or atom).
#[unsafe(export_name = "f2k_export_UnregisterClassW")]
pub extern "system" fn unregister_class_w(name: *const u16, instance: usize) -> u32 {
    unregister(name as usize, instance)
}

/// UnregisterClassA: UnregisterClassW's, the name converted first.
///
/// # Safety
///
/// `name` is an atom or a NUL-terminated string, as for the platform's.
#[unsafe(export_name = "f2k_export_UnregisterClassA")]
pub unsafe extern "system" fn unregister_class_a(name: *const u8, instance: usize) -> u32 {
    // SAFETY: the caller's contract.
    let name = unsafe { NameA::new(name) };
    name.with_wide(|name| unregister(name, instance))
        .unwrap_or(0)
}

// --- Class information ---------------------------------------------------------------------------

/// GetClassInfoEx's core over the name as the service takes it (`raw` the caller's, which the
/// answer names), for a caller of the narrow (`ansi`) or wide form: the class's fields, its
/// procedure and menu name in the caller's form, its small icon none when the window manager made
/// it, and its atom; none with 1411 for a class the module does not see (a NULL module looks
/// among user32's and the system's). user32's own classes are registered first, when the process
/// has not created a window yet: Windows 2000's are there from the process's connection on.
fn class_info_ex(
    instance: usize,
    name: usize,
    raw: usize,
    ansi: bool,
) -> Option<(WndClassEx, u16)> {
    register_system_classes();
    let mut class = WndClassEx {
        cb_size: core::mem::size_of::<WndClassEx>() as u32,
        ..WndClassEx::default()
    };
    let answer = failed_with(
        imports::class_info(instance, name, &mut class),
        crate::window_error,
    )?;
    let proc = Procedure {
        address: class.wnd_proc as u32,
        ansi: answer & rtl::window::CLASS_INFO_ANSI_PROC != 0,
    };
    class.wnd_proc = procedure::value_for(proc, ansi) as usize;
    class.menu_name = menu_for(class.menu_name, ansi);
    class.class_name = raw;
    Some((class, answer as u16))
}

/// GetClassInfo's core: GetClassInfoEx's fields into the caller's WNDCLASS; the class's atom.
fn class_info(
    instance: usize,
    name: usize,
    raw: usize,
    ansi: bool,
    out: &mut Out<'_, WndClass>,
) -> u32 {
    let Some((class, atom)) = class_info_ex(instance, name, raw, ansi) else {
        return 0;
    };
    out.set(WndClass {
        style: class.style,
        wnd_proc: class.wnd_proc,
        cb_cls_extra: class.cb_cls_extra,
        cb_wnd_extra: class.cb_wnd_extra,
        instance: class.instance,
        icon: class.icon,
        cursor: class.cursor,
        background: class.background,
        menu_name: class.menu_name,
        class_name: raw,
    });
    u32::from(atom)
}

/// GetClassInfoEx's answer into the caller's WNDCLASSEX: every field but cbSize, which is left as
/// the caller set it (the capture's cbSize of 0 is answered and kept); the class's atom.
fn put_class_info_ex(
    instance: usize,
    name: usize,
    raw: usize,
    ansi: bool,
    out: &mut Out<'_, WndClassEx>,
) -> u32 {
    let Some((class, atom)) = class_info_ex(instance, name, raw, ansi) else {
        return 0;
    };
    out.set(WndClassEx {
        cb_size: out.get().cb_size,
        ..class
    });
    u32::from(atom)
}

/// GetClassInfoW: the class's WNDCLASSW, as the module sees it.
///
/// # Safety
///
/// The caller's WNDCLASSW to fill, as for the platform's.
#[unsafe(export_name = "f2k_export_GetClassInfoW")]
pub unsafe extern "system" fn get_class_info_w(
    instance: usize,
    name: *const u16,
    out: *mut WndClass,
) -> u32 {
    // SAFETY: the caller's structure.
    let mut out = unsafe { Out::new(out) };
    class_info(instance, name as usize, name as usize, false, &mut out)
}

/// GetClassInfoA: GetClassInfoW's, the name converted first.
///
/// # Safety
///
/// `name` is an atom or a NUL-terminated string, and the caller's WNDCLASSA to fill, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_GetClassInfoA")]
pub unsafe extern "system" fn get_class_info_a(
    instance: usize,
    name: *const u8,
    out: *mut WndClass,
) -> u32 {
    // SAFETY: the caller's contract.
    let (wide, mut out) = unsafe { (NameA::new(name), Out::new(out)) };
    wide.with_wide(|wide| class_info(instance, wide, name as usize, true, &mut out))
        .unwrap_or(0)
}

/// GetClassInfoExW: the class's WNDCLASSEXW, as the module sees it (GetClassInfoW's, with the
/// small icon: none when the window manager made it from the large one); the class's atom, by name
/// or by atom.
///
/// # Safety
///
/// The caller's WNDCLASSEXW to fill, as for the platform's.
#[unsafe(export_name = "f2k_export_GetClassInfoExW")]
pub unsafe extern "system" fn get_class_info_ex_w(
    instance: usize,
    name: *const u16,
    out: *mut WndClassEx,
) -> u32 {
    // SAFETY: the caller's structure.
    let mut out = unsafe { Out::new(out) };
    put_class_info_ex(instance, name as usize, name as usize, false, &mut out)
}

/// GetClassInfoExA: GetClassInfoExW's, the name converted first, the procedure and the menu name
/// in the narrow form.
///
/// # Safety
///
/// `name` is an atom or a NUL-terminated string, and the caller's WNDCLASSEXA to fill, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_GetClassInfoExA")]
pub unsafe extern "system" fn get_class_info_ex_a(
    instance: usize,
    name: *const u8,
    out: *mut WndClassEx,
) -> u32 {
    // SAFETY: the caller's contract.
    let (wide, mut out) = unsafe { (NameA::new(name), Out::new(out)) };
    wide.with_wide(|wide| put_class_info_ex(instance, wide, name as usize, true, &mut out))
        .unwrap_or(0)
}

// --- Class data ----------------------------------------------------------------------------------

/// The GetClassLong and SetClassLong indexes of a class's own fields (winuser.h's GCL_* and
/// GCW_ATOM); an index of 0 or more is an offset into the class's extra bytes.
pub const GCL_MENUNAME: i32 = -8;
pub const GCL_HBRBACKGROUND: i32 = -10;
pub const GCL_HCURSOR: i32 = -12;
pub const GCL_HICON: i32 = -14;
pub const GCL_HMODULE: i32 = -16;
pub const GCL_CBWNDEXTRA: i32 = -18;
pub const GCL_CBCLSEXTRA: i32 = -20;
pub const GCL_WNDPROC: i32 = -24;
pub const GCL_STYLE: i32 = -26;
pub const GCW_ATOM: i32 = -32;
pub const GCL_HICONSM: i32 = -34;

/// GetClassLong's core, for a caller of the narrow (`ansi`) or wide form: the field of the window's
/// class at `index` (its procedure and menu name in the caller's form), or the dword of its extra
/// bytes at that offset; 0 with the last error for a failure (1400 for a handle naming no window,
/// 1413 for an index naming no field or extra bytes past the class's own).
fn get_class_long(window: usize, index: i32, ansi: bool) -> u32 {
    if index >= 0 {
        let mut value = 0u32;
        let index = rtl::window::QUERY_CLASS_EXTRA | index as u32;
        return failed_with(
            imports::query_window(window, index, &mut value),
            crate::window_error,
        )
        .map_or(0, |()| value);
    }
    let mut class = rtl::window::WindowClass::default();
    if crate::answered(imports::query_window(
        window,
        rtl::window::QUERY_WINDOW_CLASS,
        &mut class,
    ))
    .is_none()
    {
        return 0;
    }
    match index {
        GCL_MENUNAME => menu_for(class.menu_name as usize, ansi) as u32,
        GCL_HBRBACKGROUND => class.background,
        GCL_HCURSOR => class.cursor,
        GCL_HICON => class.icon,
        GCL_HMODULE => class.module,
        GCL_CBWNDEXTRA => class.cb_wnd_extra,
        GCL_CBCLSEXTRA => class.cb_cls_extra,
        GCL_WNDPROC => procedure::value_for(
            Procedure {
                address: class.wnd_proc,
                ansi: class.flags & rtl::window::CLASS_ANSI_PROC != 0,
            },
            ansi,
        ),
        GCL_STYLE => class.style,
        GCW_ATOM => class.atom,
        GCL_HICONSM => class.icon_sm,
        _ => failed(crate::window::ERROR_INVALID_INDEX).unwrap_or(0),
    }
}

/// SetClassLong's core, for a caller of the narrow (`ansi`) or wide form: the field of the window's
/// class at `index` set to `value` (a procedure handle sets the procedure it names; a string menu
/// name the copies the class keeps), or the dword of its extra bytes at that offset; the value it
/// held (in the caller's form, as GetClassLong answers it), or 0 with the last error for a
/// failure. A class's procedure keeps its form: the window manager's class records the form it was
/// registered with.
///
/// # Safety
///
/// For GCL_MENUNAME, `value` is an integer or a NUL-terminated string of the caller's form.
unsafe fn set_class_long(window: usize, index: i32, value: u32, ansi: bool) -> u32 {
    let mut copies = None;
    let value = match index {
        GCL_WNDPROC => procedure::resolve(value, ansi).address,
        GCL_MENUNAME if value >> 16 != 0 => {
            let block = if ansi {
                // SAFETY: the caller's contract: a NUL-terminated narrow string.
                let name = unsafe { NameA::new(value as usize as *const u8) };
                match name {
                    NameA::Text(text) => crate::with_wide(text.bytes(), menu_copies).flatten(),
                    NameA::Id(id) => Some(usize::from(id)),
                }
            } else {
                // SAFETY: the caller's contract: a NUL-terminated wide string.
                menu_copies(unsafe { rtl::cstr::units_until_nul(value as usize as *const u16) })
            };
            let Some(block) = block else {
                return failed(crate::ERROR_NOT_ENOUGH_MEMORY).unwrap_or(0);
            };
            copies = Some(block);
            block as u32
        }
        _ => value,
    };
    let Some(previous) = failed_with(
        imports::set_class_long(window, index, value),
        crate::window_error,
    ) else {
        if let Some(block) = copies {
            imports::local_free(block);
        }
        return 0;
    };
    match index {
        GCL_WNDPROC => {
            let mut class = rtl::window::WindowClass::default();
            let _ = imports::query_window(window, rtl::window::QUERY_WINDOW_CLASS, &mut class);
            let form = class.flags & rtl::window::CLASS_ANSI_PROC != 0;
            procedure::value_for(
                Procedure {
                    address: previous,
                    ansi: form,
                },
                ansi,
            )
        }
        GCL_MENUNAME => menu_for(previous as usize, ansi) as u32,
        _ => previous,
    }
}

/// GetClassLongW: the field of the window's class at `index` (GCL_*, GCW_ATOM, or an offset into
/// its extra bytes), a narrow procedure as a handle naming it; 0 with the last error for a
/// failure.
#[unsafe(export_name = "f2k_export_GetClassLongW")]
pub extern "system" fn get_class_long_w(window: usize, index: i32) -> u32 {
    get_class_long(window, index, false)
}

/// GetClassLongA: GetClassLongW's, a wide procedure as a handle naming it, the menu name narrow.
#[unsafe(export_name = "f2k_export_GetClassLongA")]
pub extern "system" fn get_class_long_a(window: usize, index: i32) -> u32 {
    get_class_long(window, index, true)
}

/// SetClassLongW: the field of the window's class at `index` set; the value it held, or 0 with the
/// last error.
///
/// # Safety
///
/// For GCL_MENUNAME, `value` is an integer or a NUL-terminated wide string, as for the platform's.
#[unsafe(export_name = "f2k_export_SetClassLongW")]
pub unsafe extern "system" fn set_class_long_w(window: usize, index: i32, value: i32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { set_class_long(window, index, value as u32, false) }
}

/// SetClassLongA: SetClassLongW's, a procedure given as an address taking the narrow forms, a menu
/// name narrow.
///
/// # Safety
///
/// For GCL_MENUNAME, `value` is an integer or a NUL-terminated narrow string, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_SetClassLongA")]
pub unsafe extern "system" fn set_class_long_a(window: usize, index: i32, value: i32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { set_class_long(window, index, value as u32, true) }
}

/// GetClassNameW: the name of the window's class, at most `max - 1` characters and a NUL into the
/// caller's buffer; the characters copied, or 0 with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_GetClassNameW")]
pub extern "system" fn get_class_name_w(window: usize, name: *mut u16, max: i32) -> i32 {
    let max = max.max(0) as u32;
    // SAFETY: the caller's buffer of `max` characters, handed to the kernel unread.
    let buffer = unsafe { UserBuffer::new(name.cast(), 2 * max) };
    crate::answered(imports::class_name(window, buffer, max)).map_or(0, |copied| copied as i32)
}

/// GetClassNameA: GetClassNameW's name converted to the ANSI code page, at most `max - 1` bytes
/// and a NUL; the bytes copied.
///
/// # Safety
///
/// The caller's buffer of `max` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_GetClassNameA")]
pub unsafe extern "system" fn get_class_name_a(window: usize, name: *mut u8, max: i32) -> i32 {
    // SAFETY: the caller's buffer.
    let buffer = unsafe { caller_bytes_mut(name, max.max(0) as usize) };
    class_name_a(window, buffer)
}

/// GetClassNameA's core, into the caller's buffer (none: one the call cannot reach).
fn class_name_a(window: usize, buffer: Option<&mut [u8]>) -> i32 {
    let mut units = [0u16; CLASS_NAME_UNITS];
    let max = units.len() as u32;
    let Some(copied) = crate::answered(imports::class_name(
        window,
        UserBuffer::from(&mut units[..]),
        max,
    )) else {
        return 0;
    };
    let Some(buffer) = buffer else {
        return failed(ERROR_NOACCESS).unwrap_or(0);
    };
    let Some(room) = buffer.len().checked_sub(1) else {
        return 0;
    };
    let written = imports::unicode_to_multi_byte(&mut buffer[..room], &units[..copied as usize]);
    buffer[written] = 0;
    written as i32
}

#[cfg(test)]
mod tests {
    use rtl::winerror::{
        ERROR_CLASS_ALREADY_EXISTS,
        ERROR_CLASS_DOES_NOT_EXIST,
        ERROR_CLASS_HAS_WINDOWS,
    };

    use super::*;
    use crate::imports::host::{procedure, wm, LAST_ERROR};

    const UNSET: u32 = 0xF2F2_F2F2;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    fn proc(_: u32, _: u32, _: u32, _: i32) -> i32 {
        0
    }

    fn class_a(name: &core::ffi::CStr) -> WndClass {
        WndClass {
            style: 3,
            wnd_proc: procedure(proc) as usize,
            instance: 0x40_0000,
            cursor: stock(32512, RT_CURSOR),
            background: 6,
            class_name: name.as_ptr() as usize,
            ..WndClass::default()
        }
    }

    /// An integer atom, or '#' and digits alone, is an integer name; another string is not.
    #[test]
    fn integer_names() {
        let wide = |text: &str| -> std::vec::Vec<u16> { text.encode_utf16().chain([0]).collect() };
        for (text, integer) in [("#123", true), ("#0", true), ("#", false), ("#12a", false)] {
            let units = wide(text);
            // SAFETY: a NUL-terminated string.
            assert_eq!(
                unsafe { integer_name(units.as_ptr() as usize) },
                integer,
                "{text}"
            );
        }
        // SAFETY: an integer atom, not read.
        assert!(unsafe { integer_name(123) });
    }

    /// The narrow form reaches the kernel wide, its stock cursor as it is; the atom comes back
    /// with the last error 2; a second registration of the name is 1410.
    ///
    /// Pins: user32.RegisterClassA, user32.RegisterClassW
    #[test]
    fn registration_answers_the_atom() {
        // The tests' strings live in the host's address space: the class names go through
        // pointers the stand-ins read as such.
        let class = class_a(c"F2KGuiClass");
        arm();
        // SAFETY: a WNDCLASSA of the tests' own, its name NUL-terminated.
        let atom = unsafe { register_class_a(&class) };
        assert_ne!(atom, 0);
        assert_eq!(last_error(), ERROR_FILE_NOT_FOUND);
        let held = wm(|wm| wm.classes[0].clone());
        assert_eq!(
            held.name,
            "F2KGuiClass".encode_utf16().collect::<std::vec::Vec<_>>()
        );
        assert_eq!(held.class.cursor, class.cursor);
        assert_ne!(class.cursor, 0);
        assert_eq!(held.class.style, 3);
        arm();
        // SAFETY: as above.
        assert_eq!(unsafe { register_class_a(&class) }, 0);
        assert_eq!(last_error(), ERROR_CLASS_ALREADY_EXISTS);
        let wide: std::vec::Vec<u16> = "F2KGuiClass\0".encode_utf16().collect();
        let mut class_w = class;
        class_w.class_name = wide.as_ptr() as usize;
        // SAFETY: a WNDCLASSW of the tests' own.
        assert_eq!(unsafe { register_class_w(&class_w) }, 0);
        assert_eq!(last_error(), ERROR_CLASS_ALREADY_EXISTS);
    }

    /// The extended forms check their size first.
    ///
    /// Pins: user32.RegisterClassExA, user32.RegisterClassExW
    #[test]
    fn the_extended_forms_check_their_size() {
        let base = class_a(c"F2KGuiClassEx");
        let mut class = WndClassEx::of(&base);
        // SAFETY: a WNDCLASSEXA of the tests' own.
        assert_ne!(unsafe { register_class_ex_a(&class) }, 0);
        let wide: std::vec::Vec<u16> = "F2KGuiClassExW\0".encode_utf16().collect();
        class.class_name = wide.as_ptr() as usize;
        class.cb_size = 40;
        arm();
        // SAFETY: a WNDCLASSEXW of the tests' own.
        assert_eq!(unsafe { register_class_ex_w(&class) }, 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        class.cb_size = core::mem::size_of::<WndClassEx>() as u32;
        // SAFETY: as above.
        assert_ne!(unsafe { register_class_ex_w(&class) }, 0);
    }

    /// GetClassInfo by atom or by name answers the atom and the class's fields, the name the
    /// caller's; a class there is none of is 1411.
    ///
    /// Pins: user32.GetClassInfoA, user32.GetClassInfoW
    #[test]
    fn class_info_reads_the_class_back() {
        let class = class_a(c"F2KGuiClass");
        // SAFETY: a WNDCLASSA of the tests' own.
        let atom = unsafe { register_class_a(&class) };
        let mut out = WndClass::default();
        // SAFETY: an atom, and the tests' own structure.
        let answer = unsafe { get_class_info_a(0x40_0000, atom as usize as *const u8, &mut out) };
        assert_eq!(answer, u32::from(atom));
        assert_eq!(
            (out.style, out.wnd_proc, out.background, out.class_name),
            (3, class.wnd_proc, 6, atom as usize)
        );
        // SAFETY: the tests' own structure, a name string.
        let answer =
            unsafe { get_class_info_a(0x40_0000, c"F2KGuiClass".as_ptr().cast(), &mut out) };
        assert_eq!(answer, u32::from(atom), "the atom, by name too");
        arm();
        // SAFETY: an atom no class has.
        let answer = unsafe { get_class_info_w(0x40_0000, 0x7FFF as *const u16, &mut out) };
        assert_eq!((answer, last_error()), (0, ERROR_CLASS_DOES_NOT_EXIST));
    }

    /// UnregisterClass: TRUE, then 1411; a class with windows is 1412.
    ///
    /// Pins: user32.UnregisterClassA, user32.UnregisterClassW
    #[test]
    fn unregistration_reports_its_errors() {
        let class = class_a(c"F2KGuiClass");
        // SAFETY: a WNDCLASSA of the tests' own.
        let atom = unsafe { register_class_a(&class) };
        wm(|wm| wm.classes[0].windows = 1);
        arm();
        assert_eq!(
            unregister_class_w(atom as usize as *const u16, 0x40_0000),
            0
        );
        assert_eq!(last_error(), ERROR_CLASS_HAS_WINDOWS);
        wm(|wm| wm.classes[0].windows = 0);
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe { unregister_class_a(c"F2KGuiClass".as_ptr().cast(), 0x40_0000) },
            1
        );
        // SAFETY: an atom.
        assert_eq!(
            unsafe { unregister_class_a(atom as usize as *const u8, 0x40_0000) },
            0
        );
        assert_eq!(last_error(), ERROR_CLASS_DOES_NOT_EXIST);
    }

    /// GetClassInfoEx: the class's atom by name too, its menu name the class's own copy in the
    /// caller's form (never the string registered), cbSize left as the caller set it; 1411 for a
    /// class there is none of.
    ///
    /// Pins: user32.GetClassInfoExW, user32.GetClassInfoExA
    #[test]
    fn class_info_ex_answers_the_copies() {
        let name: std::vec::Vec<u16> = "F2KGuiClassInfo\0".encode_utf16().collect();
        let menu: std::vec::Vec<u16> = "F2KMenu\0".encode_utf16().collect();
        let class = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: 3,
            wnd_proc: procedure(proc) as usize,
            cb_cls_extra: 8,
            instance: 0x40_0000,
            menu_name: menu.as_ptr() as usize,
            class_name: name.as_ptr() as usize,
            ..WndClassEx::default()
        };
        // SAFETY: a WNDCLASSEXW of the tests' own.
        let atom = unsafe { register_class_ex_w(&class) };
        assert_ne!(atom, 0);
        let mut out = WndClassEx::default();
        // SAFETY: the tests' own name and structure.
        let answer = unsafe { get_class_info_ex_w(0x40_0000, name.as_ptr(), &mut out) };
        assert_eq!(answer, u32::from(atom));
        assert_eq!((out.cb_size, out.style, out.cb_cls_extra), (0, 3, 8));
        assert_eq!(out.wnd_proc, class.wnd_proc);
        assert_eq!(out.class_name, name.as_ptr() as usize);
        assert_ne!(out.menu_name, class.menu_name, "a copy");
        // SAFETY: the copy the class keeps, NUL-terminated.
        let copy = unsafe { rtl::cstr::units_until_nul(out.menu_name as *const u16) };
        assert_eq!(copy, &menu[..7]);
        let mut narrow = WndClassEx::default();
        // SAFETY: the tests' own name and structure.
        let answer = unsafe {
            get_class_info_ex_a(0x40_0000, c"F2KGuiClassInfo".as_ptr().cast(), &mut narrow)
        };
        assert_eq!(answer, u32::from(atom));
        // SAFETY: the narrow copy the class keeps, NUL-terminated.
        let text = unsafe { core::ffi::CStr::from_ptr(narrow.menu_name as *const _) };
        assert_eq!(text, c"F2KMenu");
        arm();
        let none: std::vec::Vec<u16> = "F2KGuiClassNone\0".encode_utf16().collect();
        // SAFETY: as above.
        assert_eq!(
            unsafe { get_class_info_ex_w(0x40_0000, none.as_ptr(), &mut out) },
            0
        );
        assert_eq!(last_error(), ERROR_CLASS_DOES_NOT_EXIST);
    }

    /// GetClassLong and SetClassLong: the extra bytes by offset (a dword straddling their end
    /// 1413), the fields by GCL_ index (the previous value answered), a wide procedure as a handle
    /// naming it to the narrow form; 1400 for no window.
    ///
    /// Pins: user32.GetClassLongW, user32.GetClassLongA, user32.SetClassLongW,
    /// user32.SetClassLongA
    #[test]
    fn class_longs_and_extra_bytes() {
        let name: std::vec::Vec<u16> = "F2KGuiClassLong\0".encode_utf16().collect();
        let class = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: 3,
            wnd_proc: procedure(proc) as usize,
            cb_cls_extra: 8,
            instance: 0x40_0000,
            background: 6,
            class_name: name.as_ptr() as usize,
            ..WndClassEx::default()
        };
        // SAFETY: a WNDCLASSEXW of the tests' own.
        let atom = unsafe { register_class_ex_w(&class) };
        let window = wm(|wm| {
            wm.windows.push(crate::imports::host::HostWindow {
                handle: 0x44,
                atom,
                parent: crate::imports::host::DESKTOP_WINDOW,
                alive: true,
                ..Default::default()
            });
            0x44
        });
        arm();
        assert_eq!(get_class_long_w(window, GCL_STYLE), 3);
        assert_eq!(get_class_long_a(window, GCL_CBCLSEXTRA), 8);
        assert_eq!(get_class_long_w(window, GCL_HBRBACKGROUND), 6);
        assert_eq!(get_class_long_w(window, GCW_ATOM), u32::from(atom));
        assert_eq!(get_class_long_w(window, GCL_WNDPROC), class.wnd_proc as u32);
        assert_ne!(get_class_long_a(window, GCL_WNDPROC), class.wnd_proc as u32);
        // SAFETY: no pointers among the values.
        unsafe {
            assert_eq!(set_class_long_w(window, 0, 0x1122_3344), 0);
            assert_eq!(set_class_long_a(window, 4, 0x5566_7788), 0);
            assert_eq!(set_class_long_w(window, GCL_STYLE, 2), 3);
        }
        assert_eq!(get_class_long_w(window, 2), 0x7788_1122);
        assert_eq!(last_error(), UNSET);
        assert_eq!(get_class_long_a(window, 5), 0);
        assert_eq!(last_error(), crate::window::ERROR_INVALID_INDEX);
        arm();
        assert_eq!(get_class_long_w(window, -100), 0);
        assert_eq!(last_error(), crate::window::ERROR_INVALID_INDEX);
        arm();
        assert_eq!(get_class_long_w(0, GCL_STYLE), 0);
        assert_eq!(last_error(), 1400);
    }

    /// GetClassName: the name, narrow or wide, cut to the buffer; 1400 for a dead window.
    ///
    /// Pins: user32.GetClassNameA, user32.GetClassNameW
    #[test]
    fn class_names_come_back_in_either_form() {
        let class = class_a(c"F2KGuiClass");
        // SAFETY: a WNDCLASSA of the tests' own.
        let atom = unsafe { register_class_a(&class) };
        let window = wm(|wm| {
            wm.windows.push(crate::imports::host::HostWindow {
                handle: 0x40,
                atom,
                proc: 0,
                rect: Default::default(),
                style: 0,
                ex_style: 0,
                parent: crate::imports::host::DESKTOP_WINDOW,
                visible: false,
                alive: true,
                update: None,
                ..Default::default()
            });
            0x40
        });
        let mut narrow = [0xCCu8; 64];
        // SAFETY: the tests' own buffer.
        assert_eq!(
            unsafe { get_class_name_a(window, narrow.as_mut_ptr(), 64) },
            11
        );
        assert_eq!(&narrow[..12], b"F2KGuiClass\0");
        // SAFETY: as above, five bytes of it.
        assert_eq!(
            unsafe { get_class_name_a(window, narrow.as_mut_ptr(), 5) },
            4
        );
        assert_eq!(&narrow[..5], b"F2KG\0");
        let mut wide = [0xCCCCu16; 64];
        assert_eq!(get_class_name_w(window, wide.as_mut_ptr(), 64), 11);
        assert_eq!(wide[11], 0);
        arm();
        assert_eq!(get_class_name_w(0x7FFF_FFFC, wide.as_mut_ptr(), 64), 0);
        assert_eq!(last_error(), 1400);
    }

    /// The stock cursors: the system's, the same handle from either form; another id is 1813; a
    /// module's cursor is a stub.
    ///
    /// Pins: user32.LoadCursorA, user32.LoadCursorW
    #[test]
    fn the_stock_cursors_are_the_systems() {
        arm();
        // SAFETY: a resource id.
        let arrow = unsafe { load_cursor_a(0, 32512 as *const u8) };
        assert_ne!(arrow, 0);
        assert_eq!(load_cursor_w(0, 32512 as *const u16), arrow);
        assert_eq!(last_error(), UNSET);
        // SAFETY: a resource id.
        assert_eq!(unsafe { load_cursor_a(0, 32767 as *const u8) }, 0);
        assert_eq!(last_error(), ERROR_RESOURCE_TYPE_NOT_FOUND);
        assert_eq!(load_cursor_w(0x40_0000, 1 as *const u16), 0);
        assert_eq!(last_error(), rtl::winerror::ERROR_CALL_NOT_IMPLEMENTED);
    }
}
