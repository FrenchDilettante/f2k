//! The window classes: the RegisterClass family, UnregisterClass, GetClassInfo and GetClassName,
//! each over its win32k service ([`imports`]); and the stock cursors LoadCursor answers.
//!
//! The wide forms hand the caller's names to the kernel as they are; the narrow ones convert the
//! class name and the menu name to UTF-16 first (an integer atom or menu id goes as it is). A
//! registration is 4.0-compatible (MSVC 6 links its programs for subsystem 4.0). The kernel answers
//! the class decisions' errors as the closest documented NTSTATUS ([`class_error`] maps them back).
//!
//! The cursors are a seam: there are no cursor objects yet. LoadCursor answers the stock cursors
//! as constant handles of user32's own ([`stock_cursor`]), which the kernel's cursor table does not
//! hold, so a class names its stock cursor to the kernel as none.

use rtl::edge::In;
use rtl::status::{
    NtStatus,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_EXISTS,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

use crate::imports::{self, UserBuffer};
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

/// ERROR_FILE_NOT_FOUND: what a registration leaves as the last error.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// ERROR_NOACCESS: a buffer the call cannot reach.
pub const ERROR_NOACCESS: u32 = 998;
/// The class decisions' errors (winerror.h).
pub const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
pub const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1411;
pub const ERROR_CLASS_HAS_WINDOWS: u32 = 1412;
/// ERROR_RESOURCE_TYPE_NOT_FOUND: LoadCursor's answer for a stock cursor id there is none of.
pub const ERROR_RESOURCE_TYPE_NOT_FOUND: u32 = 1813;

/// The Win32 error of a failed class service: the class decisions' own errors, from the statuses
/// that stand in for them (see the kernel's class notes), and 1400 for a window's dead handle.
pub fn class_error(status: NtStatus) -> u32 {
    match status.0 {
        STATUS_OBJECT_NAME_EXISTS => ERROR_CLASS_ALREADY_EXISTS,
        STATUS_OBJECT_NAME_NOT_FOUND => ERROR_CLASS_DOES_NOT_EXIST,
        STATUS_INVALID_HANDLE => crate::ERROR_INVALID_WINDOW_HANDLE,
        _ => imports::dos_error(status),
    }
}

// --- The stock cursors ---------------------------------------------------------------------------

/// The stock cursors' resource ids (winuser.h's IDC_*), in the order of their handles.
const STOCK_CURSORS: [u16; 16] = [
    32512, // IDC_ARROW
    32513, // IDC_IBEAM
    32514, // IDC_WAIT
    32515, // IDC_CROSS
    32516, // IDC_UPARROW
    32640, // IDC_SIZE
    32641, // IDC_ICON
    32642, // IDC_SIZENWSE
    32643, // IDC_SIZENESW
    32644, // IDC_SIZEWE
    32645, // IDC_SIZENS
    32646, // IDC_SIZEALL
    32648, // IDC_NO
    32649, // IDC_HAND
    32650, // IDC_APPSTARTING
    32651, // IDC_HELP
];

/// The stock cursors' handles: F2K's own constants, the high word 1 and the resource id in the low
/// one. No handle table's handle reaches that high.
const STOCK_CURSOR_BASE: u32 = 0x0001_0000;

/// The handle of the stock cursor whose resource id is `id`; none for an id that names none.
pub fn stock_cursor(id: u16) -> Option<usize> {
    STOCK_CURSORS
        .contains(&id)
        .then_some((STOCK_CURSOR_BASE | u32::from(id)) as usize)
}

/// Whether `handle` is a stock cursor's.
pub fn is_stock_cursor(handle: usize) -> bool {
    stock_cursor(handle as u16) == Some(handle)
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
/// shows); a module's cursor, or one by name, goes to the stub routine (there are no cursor
/// objects to load one into).
fn load_cursor(entry: &rtl::stub::Entry, instance: usize, raw: usize, id: Option<u16>) -> usize {
    match (instance, id) {
        (0, Some(id)) => stock_cursor(id)
            .or_else(|| failed(ERROR_RESOURCE_TYPE_NOT_FOUND))
            .unwrap_or(0),
        _ => {
            // SAFETY: the arguments as the export's kinds read them: a handle and an address,
            // neither read as memory.
            unsafe {
                crate::stub::stubbed(
                    entry,
                    "cursors from a module's resources: no cursor objects yet",
                    &[instance as u64, raw as u64],
                ) as usize
            }
        }
    }
}

// --- Registration --------------------------------------------------------------------------------

/// The registration of `class`, its two names already as the service takes them (`name` the class
/// name's), through the narrow entry point when `ansi` (its procedure takes the narrow forms of the
/// messages): the atom, the last error ERROR_FILE_NOT_FOUND (as every registration the captures
/// show leaves it); 0 with the class decision's error. A stock cursor goes to the kernel as none
/// (see the module notes).
fn register(mut class: WndClassEx, name: usize, ansi: bool) -> u16 {
    if is_stock_cursor(class.cursor) {
        class.cursor = 0;
    }
    class.cb_size = core::mem::size_of::<WndClassEx>() as u32;
    class.class_name = name;
    match failed_with(
        imports::register_class(
            &class,
            name,
            REGISTER_WIN40_COMPAT | if ansi { REGISTER_ANSI_PROC } else { 0 },
        ),
        class_error,
    ) {
        Some(atom) => {
            imports::set_last_error(ERROR_FILE_NOT_FOUND);
            atom
        }
        None => 0,
    }
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
            register(class, name, true)
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
    register(WndClassEx::of(&class), class.class_name, false)
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
    register(class, class.class_name, false)
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

// --- Unregistration ------------------------------------------------------------------------------

/// UnregisterClass's core over the name as the service takes it: TRUE, or FALSE with the error
/// (1411 for no such class, 1412 for a class that still has windows).
fn unregister(name: usize, instance: usize) -> u32 {
    let error = |status: NtStatus| match status.0 {
        STATUS_INVALID_PARAMETER => ERROR_CLASS_HAS_WINDOWS,
        _ => class_error(status),
    };
    failed_with(imports::unregister_class(name, instance), error).is_some() as u32
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

/// GetClassInfo's core over the name as the service takes it (`raw` the caller's, which the
/// answer names): the class's fields into `out`; the atom for a name that is one, TRUE for a string
/// (the service answers no atom); 0 with 1411 for a class the module does not see.
fn class_info(instance: usize, name: usize, raw: usize, out: &mut Out<'_, WndClass>) -> u32 {
    let mut class = WndClassEx {
        cb_size: core::mem::size_of::<WndClassEx>() as u32,
        ..WndClassEx::default()
    };
    if failed_with(imports::class_info(instance, name, &mut class), class_error).is_none() {
        return 0;
    }
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
    if raw >> 16 == 0 {
        raw as u32
    } else {
        1
    }
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
    class_info(instance, name as usize, name as usize, &mut out)
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
    wide.with_wide(|wide| class_info(instance, wide, name as usize, &mut out))
        .unwrap_or(0)
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
            cursor: stock_cursor(32512).unwrap(),
            background: 6,
            class_name: name.as_ptr() as usize,
            ..WndClass::default()
        }
    }

    /// The narrow form reaches the kernel wide, its stock cursor as none; the atom comes back
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
        assert_eq!(
            held.class.cursor, 0,
            "the stock cursor is none to the kernel"
        );
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

    /// GetClassInfo by atom answers the atom and the class's fields, the name the caller's;
    /// a class there is none of is 1411.
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
        assert_eq!(answer, 1);
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

    /// The stock cursors: the same handle from either form; another id is 1813; a module's cursor
    /// is a stub.
    ///
    /// Pins: user32.LoadCursorA, user32.LoadCursorW
    #[test]
    fn the_stock_cursors_are_constants() {
        arm();
        // SAFETY: a resource id.
        let arrow = unsafe { load_cursor_a(0, 32512 as *const u8) };
        assert_ne!(arrow, 0);
        assert_eq!(load_cursor_w(0, 32512 as *const u16), arrow);
        assert_eq!(last_error(), UNSET);
        assert!(is_stock_cursor(arrow));
        // SAFETY: a resource id.
        assert_eq!(unsafe { load_cursor_a(0, 32767 as *const u8) }, 0);
        assert_eq!(last_error(), ERROR_RESOURCE_TYPE_NOT_FOUND);
        assert_eq!(load_cursor_w(0x40_0000, 1 as *const u16), 0);
        assert_eq!(last_error(), crate::stub::ERROR_CALL_NOT_IMPLEMENTED);
    }
}
