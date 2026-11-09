//! The windows: CreateWindowEx and DestroyWindow, the desktop window, the visibility and geometry
//! calls (IsWindow, IsWindowVisible, GetWindowRect, ShowWindow, ShowWindowAsync, SetWindowPos,
//! MoveWindow) and UpdateWindow, each over its win32k service ([`imports`]).
//!
//! The messages the window manager sends while it decides (the creation's WM_NCCREATE to WM_MOVE,
//! the destruction's WM_DESTROY and WM_NCDESTROY, UpdateWindow's WM_PAINT) are queued for the
//! window's thread: the kernel calls no user-mode code. Each call here that can send them receives
//! them once its service returns ([`message::receive_sent`]), so a program sees its procedure
//! called before the call returns, as on Windows 2000.
//!
//! NtUserQueryWindow answers what Windows 2000's user32 reads from the window manager's records
//! mapped into its process: a window's WINDOWINFO, its visibility.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::gdi::Rect;
use rtl::status::{
    NtStatus,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use rtl::user::HWND_LOCK_UPDATE_WINDOW;
use rtl::window::{WindowInfo, QUERY_WINDOW_INFO, QUERY_WINDOW_VISIBLE};

use crate::imports::{self, Creation};
use crate::{
    answered,
    failed,
    failed_with,
    message,
    window_error,
    NameA,
    Out,
    ERROR_INVALID_PARAMETER,
};

/// The private extended-style bit a narrow caller's creation carries (the window remembers it was
/// made through the ANSI entry point; the kernel takes it out of the stored style).
const ANSI_CREATOR: u32 = 0x8000_0000;

/// WS_CHILD: a child window, which needs a parent.
const WS_CHILD: u32 = 0x4000_0000;

/// The Windows version a window's creator expects: 4.0, the subsystem version MSVC 6 links its
/// programs for.
const EXPECTED_VERSION: u32 = 0x0004_0000;

/// The desktop window's class: the documented #32769.
const DESKTOP_CLASS_ATOM: u16 = 0x8001;

/// How many of the window table's first handles GetDesktopWindow looks at: the boot makes the
/// desktop's windows before any other.
const BOOT_HANDLES: u32 = 16;

/// The Win32 errors of a failed creation (winerror.h): the class decision's 1407, a child without
/// a parent's 1406, the out-of-memory paths' ERROR_OUTOFMEMORY.
const ERROR_OUTOFMEMORY: u32 = 14;
const ERROR_TLW_WITH_WSCHILD: u32 = 1406;
const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;

/// CreateWindowEx's core: the window made, the messages its creation sent received; its handle, or
/// NULL with the creation's error.
fn create(creation: &Creation) -> usize {
    let answer = imports::create_window(creation);
    message::receive_sent();
    let error = |status: NtStatus| match status.0 {
        STATUS_OBJECT_NAME_NOT_FOUND => ERROR_CANNOT_FIND_WND_CLASS,
        STATUS_INVALID_PARAMETER if creation.style & WS_CHILD != 0 && creation.parent == 0 => {
            ERROR_TLW_WITH_WSCHILD
        }
        STATUS_NO_MEMORY => ERROR_OUTOFMEMORY,
        _ => window_error(status),
    };
    failed_with(answer, error).map_or(0, |window| window as usize)
}

/// CreateWindowExW: the window, its class named by a string or an atom; NULL with the last error
/// (1407 for a class there is none of).
#[unsafe(export_name = "f2k_export_CreateWindowExW")]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn create_window_ex_w(
    ex_style: u32,
    class: *const u16,
    name: *const u16,
    style: u32,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    parent: usize,
    menu: usize,
    instance: usize,
    param: usize,
) -> usize {
    create(&Creation {
        ex_style: ex_style & !ANSI_CREATOR,
        class: class as usize,
        name: name as usize,
        style,
        x,
        y,
        cx,
        cy,
        parent,
        menu,
        instance,
        param,
        version: EXPECTED_VERSION,
    })
}

/// CreateWindowExA: CreateWindowExW's window, the class name and the window name converted first,
/// the window marked as a narrow caller's.
///
/// # Safety
///
/// `class` is an atom or a NUL-terminated string, `name` a NUL-terminated string or null, as for
/// the platform's.
#[unsafe(export_name = "f2k_export_CreateWindowExA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn create_window_ex_a(
    ex_style: u32,
    class: *const u8,
    name: *const u8,
    style: u32,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    parent: usize,
    menu: usize,
    instance: usize,
    param: usize,
) -> usize {
    // SAFETY: the caller's contract.
    let (class, name) = unsafe { (NameA::new(class), rtl::edge::InStr::optional(name)) };
    let mut creation = Creation {
        ex_style: ex_style | ANSI_CREATOR,
        style,
        x,
        y,
        cx,
        cy,
        parent,
        menu,
        instance,
        param,
        version: EXPECTED_VERSION,
        ..Creation::default()
    };
    class
        .with_wide(|class| {
            creation.class = class;
            match name {
                None => Some(create(&creation)),
                Some(name) => crate::with_wide(name.bytes(), |units| {
                    creation.name = units.as_ptr() as usize;
                    create(&creation)
                }),
            }
        })
        .flatten()
        .unwrap_or(0)
}

/// DestroyWindow: the window destroyed, the messages its destruction sent received; TRUE, or FALSE
/// with the last error (1400 for a handle naming no window).
#[unsafe(export_name = "f2k_export_DestroyWindow")]
pub extern "system" fn destroy_window(window: usize) -> u32 {
    let answer = imports::destroy_window(window);
    message::receive_sent();
    answered(answer).is_some() as u32
}

/// The cached desktop window: found once per process.
static DESKTOP_WINDOW: AtomicU32 = AtomicU32::new(0);

/// GetDesktopWindow: the desktop window, the parent of every top-level window. No service names
/// it, so it is the window of the documented desktop class among the first handles of the window
/// table, which the boot makes before any other (found once, then kept); NULL when there is none.
#[unsafe(export_name = "f2k_export_GetDesktopWindow")]
pub extern "system" fn get_desktop_window() -> usize {
    let known = DESKTOP_WINDOW.load(Ordering::Relaxed);
    if known != 0 {
        return known as usize;
    }
    let found = (1..=BOOT_HANDLES).map(|index| index << 2).find(|&handle| {
        window_info(handle as usize).is_ok_and(|info| info.atom_window_type == DESKTOP_CLASS_ATOM)
    });
    let found = found.unwrap_or(0);
    DESKTOP_WINDOW.store(found, Ordering::Relaxed);
    found as usize
}

/// The window's WINDOWINFO.
fn window_info(window: usize) -> Result<WindowInfo, NtStatus> {
    let mut info = WindowInfo {
        size: core::mem::size_of::<WindowInfo>() as u32,
        ..WindowInfo::default()
    };
    imports::query_window(window, QUERY_WINDOW_INFO, &mut info)?;
    Ok(info)
}

/// The window's visibility: whether it and every window above it have WS_VISIBLE.
fn visible(window: usize) -> Result<bool, NtStatus> {
    let mut visible = 0u32;
    imports::query_window(window, QUERY_WINDOW_VISIBLE, &mut visible)?;
    Ok(visible != 0)
}

/// Whether `window` names a window (the last error untouched either way).
pub fn is_window_alive(window: usize) -> bool {
    visible(window).is_ok()
}

/// IsWindow: whether the handle names a window; the last error untouched (as the guiwin capture
/// shows for a destroyed one).
#[unsafe(export_name = "f2k_export_IsWindow")]
pub extern "system" fn is_window(window: usize) -> u32 {
    is_window_alive(window) as u32
}

/// IsWindowVisible: whether the window and every window above it have WS_VISIBLE; FALSE with 1400
/// for a handle naming no window.
#[unsafe(export_name = "f2k_export_IsWindowVisible")]
pub extern "system" fn is_window_visible(window: usize) -> u32 {
    answered(visible(window)).unwrap_or(false) as u32
}

/// GetWindowRect: the window's rectangle in screen coordinates; FALSE with 1400 for a handle
/// naming no window (the caller's RECT untouched).
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_GetWindowRect")]
pub unsafe extern "system" fn get_window_rect(window: usize, rect: *mut Rect) -> u32 {
    // SAFETY: the caller's RECT.
    let mut rect = unsafe { Out::new(rect) };
    match answered(window_info(window)) {
        Some(info) => {
            rect.set(info.window);
            1
        }
        None => 0,
    }
}

/// ShowWindow: the show command carried out, the messages it sent received; nonzero when the
/// window was visible before (the kernel's answer), 0 with the last error for a failure.
#[unsafe(export_name = "f2k_export_ShowWindow")]
pub extern "system" fn show_window(window: usize, command: i32) -> u32 {
    let answer = imports::show_window(window, command);
    message::receive_sent();
    answered(answer).unwrap_or(0)
}

/// ShowWindowAsync: the show command posted to the window's thread (the kernel carries it out at
/// once); TRUE, or FALSE with the last error. It waits for nothing, so it receives nothing.
#[unsafe(export_name = "f2k_export_ShowWindowAsync")]
pub extern "system" fn show_window_async(window: usize, command: i32) -> u32 {
    answered(imports::show_window_async(window, command)).is_some() as u32
}

/// SetWindowPos: the window's place, size and z-order changed as the SWP_ flags say; TRUE, or
/// FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_SetWindowPos")]
pub extern "system" fn set_window_pos(
    window: usize,
    insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> u32 {
    let answer = imports::set_window_pos(window, insert_after, x, y, cx, cy, flags);
    message::receive_sent();
    answered(answer).is_some() as u32
}

/// MoveWindow: the window's place and size changed; TRUE, or FALSE with 1400 for a handle naming
/// no window.
#[unsafe(export_name = "f2k_export_MoveWindow")]
pub extern "system" fn move_window(
    window: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    repaint: u32,
) -> u32 {
    let answer = imports::move_window(window, x, y, cx, cy, repaint != 0);
    message::receive_sent();
    answered(answer).is_some() as u32
}

/// UpdateWindow: a WM_PAINT sent to the window when its update region is not empty, received
/// before the call returns; TRUE, or FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_UpdateWindow")]
pub extern "system" fn update_window(window: usize) -> u32 {
    let answer = imports::call_hwnd_lock(window, HWND_LOCK_UPDATE_WINDOW);
    message::receive_sent();
    answered(answer).is_some() as u32
}

/// LAYOUT_RTL: a right-to-left (mirrored) default layout.
const LAYOUT_RTL: u32 = 1;

/// GetProcessDefaultLayout: the layout windows the process creates take by default; always 0, left
/// to right: F2K mirrors no window. TRUE.
///
/// # Safety
///
/// The caller's DWORD, as for the platform's.
#[unsafe(export_name = "f2k_export_GetProcessDefaultLayout")]
pub unsafe extern "system" fn get_process_default_layout(layout: *mut u32) -> u32 {
    // SAFETY: the caller's DWORD.
    unsafe { Out::new(layout) }.set(0);
    1
}

/// SetProcessDefaultLayout: TRUE for the two layouts Windows 2000 documents, 0 and LAYOUT_RTL,
/// FALSE with ERROR_INVALID_PARAMETER for any other. F2K mirrors no window, so the default layout
/// stays 0 whichever is asked.
#[unsafe(export_name = "f2k_export_SetProcessDefaultLayout")]
pub extern "system" fn set_process_default_layout(layout: u32) -> u32 {
    match layout {
        0 | LAYOUT_RTL => 1,
        _ => failed(ERROR_INVALID_PARAMETER).unwrap_or(0),
    }
}

/// A wide name's units, for the tests' reading of what a creation was given.
#[cfg(test)]
fn units(name: &str) -> std::vec::Vec<u16> {
    name.encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_CREATE, WM_DESTROY, WM_NCCREATE, WM_NCDESTROY};

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{procedure, wm, DESKTOP_WINDOW as BOOT_DESKTOP, LAST_ERROR};

    const UNSET: u32 = 0xF2F2_F2F2;

    std::thread_local! {
        static SEEN: core::cell::RefCell<std::vec::Vec<u32>> =
            const { core::cell::RefCell::new(std::vec::Vec::new()) };
    }

    fn recorder(_: u32, message: u32, _: u32, _: i32) -> i32 {
        SEEN.with(|seen| seen.borrow_mut().push(message));
        0
    }

    fn seen() -> std::vec::Vec<u32> {
        SEEN.with(|seen| seen.take())
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    /// A class "F2KGuiWin" of the recorder.
    fn register() {
        let class = WndClass {
            wnd_proc: procedure(recorder) as usize,
            instance: 0x40_0000,
            class_name: c"F2KGuiWin".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the tests' own.
        assert_ne!(unsafe { register_class_a(&class) }, 0);
    }

    /// A window of the class, through the narrow form.
    fn make() -> usize {
        // SAFETY: the tests' own NUL-terminated names.
        unsafe {
            create_window_ex_a(
                0,
                c"F2KGuiWin".as_ptr().cast(),
                c"t".as_ptr().cast(),
                0x00CF_0000,
                10,
                20,
                320,
                200,
                0,
                0,
                0x40_0000,
                0,
            )
        }
    }

    /// The narrow form reaches the kernel wide with the ANSI-creator bit; the procedure has seen
    /// the creation's messages when the call returns, and the answers went back.
    ///
    /// Pins: user32.CreateWindowExA, user32.IsWindow
    #[test]
    fn creation_delivers_its_messages() {
        register();
        arm();
        let window = make();
        assert_ne!(window, 0);
        assert_eq!(last_error(), UNSET);
        assert_eq!(seen(), [WM_NCCREATE, WM_CREATE]);
        let (created, answers) = wm(|wm| (wm.created[0].clone(), wm.answers.clone()));
        assert_eq!(created.ex_style, ANSI_CREATOR);
        assert_eq!(created.class, Ok(units("F2KGuiWin")));
        assert_eq!(created.name, Some(units("t")));
        assert_eq!(created.version, EXPECTED_VERSION);
        assert_eq!(answers, [(WM_NCCREATE, 0), (WM_CREATE, 0)]);
        assert_eq!(is_window(window), 1);
    }

    /// The wide form hands its names over as they are; an unknown class is 1407.
    ///
    /// Pins: user32.CreateWindowExW
    #[test]
    fn the_wide_form_and_an_unknown_class() {
        register();
        let class = units("F2KGuiWin\0");
        let window = create_window_ex_w(
            ANSI_CREATOR,
            class.as_ptr(),
            core::ptr::null(),
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
        );
        assert_ne!(window, 0);
        let created = wm(|wm| wm.created[0].clone());
        assert_eq!((created.ex_style, created.name), (0, None));
        arm();
        let other = units("NoSuchClass\0");
        assert_eq!(
            create_window_ex_w(
                0,
                other.as_ptr(),
                core::ptr::null(),
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0
            ),
            0
        );
        assert_eq!(last_error(), ERROR_CANNOT_FIND_WND_CLASS);
    }

    /// DestroyWindow: the destruction's messages seen before it returns; a dead handle is 1400,
    /// and IsWindow says no without a last error.
    ///
    /// Pins: user32.DestroyWindow, user32.IsWindow
    #[test]
    fn destruction_delivers_its_messages() {
        register();
        let window = make();
        seen();
        assert_eq!(destroy_window(window), 1);
        assert_eq!(seen(), [WM_DESTROY, WM_NCDESTROY]);
        arm();
        assert_eq!(is_window(window), 0);
        assert_eq!(last_error(), UNSET);
        assert_eq!(destroy_window(window), 0);
        assert_eq!(last_error(), 1400);
    }

    /// The desktop window is the boot's, found by its class, and a window.
    ///
    /// Pins: user32.GetDesktopWindow
    #[test]
    fn the_desktop_window_is_found_by_its_class() {
        let desktop = get_desktop_window();
        assert_eq!(desktop, BOOT_DESKTOP as usize);
        assert_eq!(get_desktop_window(), desktop);
        assert_eq!(is_window(desktop), 1);
    }

    /// The geometry and visibility: the rectangle as moved and placed, the visibility as shown,
    /// ShowWindow's answer the previous visibility; a bogus handle is 1400 everywhere.
    ///
    /// Pins: user32.MoveWindow, user32.SetWindowPos, user32.GetWindowRect, user32.ShowWindow,
    /// user32.ShowWindowAsync, user32.IsWindowVisible
    #[test]
    fn geometry_and_visibility() {
        register();
        let window = make();
        let mut rect = Rect::default();
        assert_eq!(move_window(window, 100, 100, 300, 250, 1), 1);
        // SAFETY: the tests' own RECT.
        assert_eq!(unsafe { get_window_rect(window, &mut rect) }, 1);
        assert_eq!(
            (rect.left, rect.top, rect.right, rect.bottom),
            (100, 100, 400, 350)
        );
        assert_eq!(set_window_pos(window, 0, 50, 60, 200, 150, 0x10), 1);
        // SAFETY: as above.
        unsafe { get_window_rect(window, &mut rect) };
        assert_eq!(
            (rect.left, rect.top, rect.right, rect.bottom),
            (50, 60, 250, 210)
        );
        assert_eq!(show_window(window, 5), 0);
        assert_eq!(is_window_visible(window), 1);
        assert_eq!(show_window(window, 0), 16);
        assert_eq!(is_window_visible(window), 0);
        assert_eq!(show_window_async(window, 5), 1);
        assert_eq!(is_window_visible(window), 1);
        assert_eq!(update_window(window), 1);
        let bogus = 0x7FFF_FFFC;
        for answer in [
            move_window(bogus, 1, 2, 3, 4, 1),
            // SAFETY: the tests' own RECT.
            unsafe { get_window_rect(bogus, &mut rect) },
            set_window_pos(bogus, 0, 0, 0, 0, 0, 3),
            is_window_visible(bogus),
            update_window(bogus),
        ] {
            assert_eq!(answer, 0);
        }
        arm();
        assert_eq!(is_window_visible(bogus), 0);
        assert_eq!(last_error(), 1400);
    }

    /// The default layout is 0, left to right, and stays so: setting accepts 0 and LAYOUT_RTL and
    /// refuses any other value with ERROR_INVALID_PARAMETER.
    #[test]
    fn the_default_layout_is_left_to_right() {
        let mut layout = UNSET;
        // SAFETY: the tests' own DWORD.
        assert_eq!(unsafe { get_process_default_layout(&mut layout) }, 1);
        assert_eq!(layout, 0);
        arm();
        assert_eq!(set_process_default_layout(0), 1);
        assert_eq!(set_process_default_layout(LAYOUT_RTL), 1);
        assert_eq!(last_error(), UNSET);
        assert_eq!(set_process_default_layout(2), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        layout = UNSET;
        // SAFETY: as above.
        assert_eq!(unsafe { get_process_default_layout(&mut layout) }, 1);
        assert_eq!(layout, 0);
    }
}
