//! The windows: CreateWindowEx and DestroyWindow, the desktop window, the visibility and geometry
//! calls (IsWindow, IsWindowVisible, GetWindowRect, ShowWindow, ShowWindowAsync, SetWindowPos,
//! MoveWindow) and UpdateWindow, the window's data (GetWindowLong and SetWindowLong,
//! GetWindowWord and SetWindowWord, IsWindowUnicode) and its text (GetWindowText,
//! GetWindowTextLength, SetWindowText), each over its win32k service ([`imports`]).
//!
//! The messages the window manager sends while it decides (the creation's WM_NCCREATE to WM_MOVE,
//! the destruction's WM_DESTROY and WM_NCDESTROY, UpdateWindow's WM_PAINT) are queued for the
//! window's thread: the kernel calls no user-mode code. Each call here that can send them receives
//! them once its service returns ([`message::receive_sent`]), so a program sees its procedure
//! called before the call returns, as on Windows 2000.
//!
//! NtUserQueryWindow answers what Windows 2000's user32 reads from the window manager's records
//! mapped into its process: a window's WINDOWINFO, its visibility, its own fields, its extra bytes
//! and its text. The changes go through the window manager's services: NtUserSetWindowLong (whose
//! style changes send WM_STYLECHANGING and WM_STYLECHANGED, received before SetWindowLong returns),
//! NtUserSetWindowWord.
//!
//! A window's text is its procedure's to answer: GetWindowText, GetWindowTextLength and
//! SetWindowText send it WM_GETTEXT, WM_GETTEXTLENGTH and WM_SETTEXT, in the caller's form, which
//! its DefWindowProc answers from the text the window manager holds ([`message`]). A window of
//! another process is not sent WM_GETTEXT or WM_GETTEXTLENGTH: its text is read as the window
//! manager holds it, as the platform documents.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::edge::OutBuf;
use rtl::gdi::Rect;
use rtl::status::{
    NtStatus,
    STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use rtl::user::{HWND_LOCK_UPDATE_WINDOW, WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT};
use rtl::window::*;

use crate::imports::{self, Creation};
use crate::procedure::{self, Procedure};
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

// --- The window's data ---------------------------------------------------------------------------

/// ERROR_INVALID_INDEX: a GetWindowLong/SetWindowLong index that names no field of the window, or
/// extra bytes past the window's own.
pub const ERROR_INVALID_INDEX: u32 = 1413;

/// The Win32 error of a failed window-data call: STATUS_INVALID_INFO_CLASS, the window manager's
/// answer for an index it does not know (its InvalidIndex), is ERROR_INVALID_INDEX; the rest as
/// [`window_error`] maps them.
fn data_error(status: NtStatus) -> u32 {
    match status.0 {
        STATUS_INVALID_INFO_CLASS => ERROR_INVALID_INDEX,
        _ => window_error(status),
    }
}

/// The window's own fields, as the window manager holds them.
pub fn window_data(window: usize) -> Result<WindowData, NtStatus> {
    let mut data = WindowData::default();
    imports::query_window(window, QUERY_WINDOW_DATA, &mut data)?;
    Ok(data)
}

/// Whether the window's procedure takes the narrow forms of the messages; none (the last error
/// untouched) for a handle naming no window.
pub fn procedure_is_ansi(window: usize) -> Option<bool> {
    let data = window_data(window).ok()?;
    Some(data.flags & WINDOW_ANSI_PROC != 0)
}

/// The window's procedure as GetWindowLong answers a caller of the narrow (`ansi`) or wide form:
/// its address, or a handle naming it when it takes the other form ([`procedure::value_for`]).
/// The window manager's own procedure answers as DefWindowProc of the caller's form.
fn procedure_value(data: &WindowData, ansi: bool) -> u32 {
    if data.proc == 0 {
        return if ansi {
            message::def_window_proc_a as *const () as usize as u32
        } else {
            message::def_window_proc_w as *const () as usize as u32
        };
    }
    let proc = Procedure {
        address: data.proc,
        ansi: data.flags & WINDOW_ANSI_PROC != 0,
    };
    procedure::value_for(proc, ansi)
}

/// GetWindowLong's core, for a caller of the narrow (`ansi`) or wide form: the field at `index`
/// (GWL_*, or an offset into the extra bytes); 0 with the last error for a failure (1400 for a
/// handle naming no window, 1413 for an index naming no field or bytes past the extra bytes').
/// The last error is untouched otherwise, whatever the value.
fn get_long(window: usize, index: i32, ansi: bool) -> i32 {
    if index >= 0 {
        let mut value = 0u32;
        let index = QUERY_WINDOW_EXTRA | index as u32;
        return failed_with(imports::query_window(window, index, &mut value), data_error)
            .map_or(0, |()| value as i32);
    }
    let Some(data) = answered(window_data(window)) else {
        return 0;
    };
    let value = match index {
        GWL_STYLE => data.style,
        GWL_EXSTYLE => data.ex_style,
        GWL_ID => data.id,
        GWL_USERDATA => data.user_data,
        GWL_HINSTANCE => data.instance,
        GWL_HWNDPARENT => data.parent,
        GWL_WNDPROC => procedure_value(&data, ansi),
        _ => return failed(ERROR_INVALID_INDEX).unwrap_or(0),
    };
    value as i32
}

/// SetWindowLong's core, for a caller of the narrow (`ansi`) or wide form: the field at `index`
/// set to `value`, the messages the change sent received; the value it held (a procedure of the
/// other form as a handle naming it), or 0 with the last error for a failure. A GWL_WNDPROC value
/// that is a handle sets the procedure it names, in that procedure's own form.
fn set_long(window: usize, index: i32, value: i32, ansi: bool) -> i32 {
    let target = if index == GWL_WNDPROC {
        procedure::resolve(value as u32, ansi)
    } else {
        Procedure {
            address: value as u32,
            ansi,
        }
    };
    let answer = imports::set_window_long(window, index, target.address, target.ansi);
    message::receive_sent();
    match failed_with(answer, data_error) {
        Some((previous, previous_ansi)) if index == GWL_WNDPROC => {
            let previous = Procedure {
                address: previous,
                ansi: previous_ansi,
            };
            procedure::value_for(previous, ansi) as i32
        }
        Some((previous, _)) => previous as i32,
        None => 0,
    }
}

/// GetWindowLongA: the window's field at `index` (GWL_*, or an offset into its extra bytes), a
/// wide procedure as a handle naming it; 0 with the last error for a failure.
#[unsafe(export_name = "f2k_export_GetWindowLongA")]
pub extern "system" fn get_window_long_a(window: usize, index: i32) -> i32 {
    get_long(window, index, true)
}

/// GetWindowLongW: GetWindowLongA's, a narrow procedure as a handle naming it.
#[unsafe(export_name = "f2k_export_GetWindowLongW")]
pub extern "system" fn get_window_long_w(window: usize, index: i32) -> i32 {
    get_long(window, index, false)
}

/// SetWindowLongA: the window's field at `index` set (GWL_WNDPROC subclasses the window with a
/// narrow procedure, or the one a handle names); the value it held, or 0 with the last error.
#[unsafe(export_name = "f2k_export_SetWindowLongA")]
pub extern "system" fn set_window_long_a(window: usize, index: i32, value: i32) -> i32 {
    set_long(window, index, value, true)
}

/// SetWindowLongW: SetWindowLongA's, a procedure given as an address taking the wide forms.
#[unsafe(export_name = "f2k_export_SetWindowLongW")]
pub extern "system" fn set_window_long_w(window: usize, index: i32, value: i32) -> i32 {
    set_long(window, index, value, false)
}

/// GetWindowWord: the word at offset `index` of the window's extra bytes; 0 with the last error
/// for a failure (1413 for a negative offset or one past the extra bytes).
#[unsafe(export_name = "f2k_export_GetWindowWord")]
pub extern "system" fn get_window_word(window: usize, index: i32) -> u16 {
    if index < 0 {
        return match answered(window_data(window)) {
            Some(_) => failed(ERROR_INVALID_INDEX).unwrap_or(0),
            None => 0,
        };
    }
    let mut value = 0u16;
    let index = QUERY_WINDOW_EXTRA | index as u32;
    failed_with(imports::query_window(window, index, &mut value), data_error).map_or(0, |()| value)
}

/// SetWindowWord: the word at offset `index` of the window's extra bytes set; the word it held,
/// or 0 with the last error for a failure.
#[unsafe(export_name = "f2k_export_SetWindowWord")]
pub extern "system" fn set_window_word(window: usize, index: i32, value: u32) -> u16 {
    failed_with(
        imports::set_window_word(window, index, value as u16),
        data_error,
    )
    .unwrap_or(0)
}

/// IsWindowUnicode: whether the window's procedure takes the wide forms of the messages; FALSE
/// with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_IsWindowUnicode")]
pub extern "system" fn is_window_unicode(window: usize) -> u32 {
    answered(window_data(window)).is_some_and(|data| data.flags & WINDOW_ANSI_PROC == 0) as u32
}

// --- The window's text ---------------------------------------------------------------------------

/// Whether the window is another process's (its text read as held, not asked for); none, with
/// 1400, for a handle naming no window.
fn text_held_elsewhere(window: usize) -> Option<bool> {
    answered(window_data(window)).map(|data| data.flags & WINDOW_OTHER_PROCESS != 0)
}

/// GetWindowTextW: the window's text into the caller's buffer of `max` units, cut to leave room for
/// the terminator, terminated: the units copied before it. The procedure answers it (WM_GETTEXT),
/// another process's window's text is read as held. A positive `max` empties the buffer first; a
/// count of 0 or less copies nothing and sends nothing. 0 with 1400 for a handle naming no window.
///
/// # Safety
///
/// `buffer` holds `max` units the call may write, as for the platform's.
#[unsafe(export_name = "f2k_export_GetWindowTextW")]
pub unsafe extern "system" fn get_window_text_w(window: usize, buffer: *mut u16, max: i32) -> i32 {
    let max = max.max(0) as usize;
    // SAFETY: the caller's buffer of `max` units.
    let mut out = unsafe { OutBuf::new(buffer, max) };
    if max > 0 {
        out.set(0, 0);
    }
    let Some(elsewhere) = text_held_elsewhere(window) else {
        return 0;
    };
    if max == 0 {
        return 0;
    }
    if elsewhere {
        let text = message::window_text(window).unwrap_or_default();
        let text = text.as_slice();
        let length = text.len().min(max - 1);
        out.put(&text[..length]);
        out.set(length, 0);
        return length as i32;
    }
    let buffer = out.as_mut_ptr() as i32;
    message::send_as(window, WM_GETTEXT, max as u32, buffer, false).unwrap_or(0)
}

/// GetWindowTextA: GetWindowTextW's, into a buffer of `max` bytes, the text in the narrow form.
///
/// # Safety
///
/// `buffer` holds `max` bytes the call may write, as for the platform's.
#[unsafe(export_name = "f2k_export_GetWindowTextA")]
pub unsafe extern "system" fn get_window_text_a(window: usize, buffer: *mut u8, max: i32) -> i32 {
    let max = max.max(0) as usize;
    // SAFETY: the caller's buffer of `max` bytes.
    let mut out = unsafe { OutBuf::new(buffer, max) };
    if max > 0 {
        out.set(0, 0);
    }
    let Some(elsewhere) = text_held_elsewhere(window) else {
        return 0;
    };
    if max == 0 {
        return 0;
    }
    if elsewhere {
        let text = message::window_text(window).unwrap_or_default();
        return procedure::put_narrow(&mut out, text.as_slice()) as i32;
    }
    let buffer = out.as_mut_ptr() as i32;
    message::send_as(window, WM_GETTEXT, max as u32, buffer, true).unwrap_or(0)
}

/// GetWindowTextLengthW: the window's text's length in units, as its procedure answers it
/// (WM_GETTEXTLENGTH; another process's window's text as held); 0 with 1400 for a handle naming
/// no window.
#[unsafe(export_name = "f2k_export_GetWindowTextLengthW")]
pub extern "system" fn get_window_text_length_w(window: usize) -> i32 {
    match text_held_elsewhere(window) {
        None => 0,
        Some(true) => message::window_text(window).map_or(0, |text| text.as_slice().len() as i32),
        Some(false) => message::send_as(window, WM_GETTEXTLENGTH, 0, 0, false).unwrap_or(0),
    }
}

/// GetWindowTextLengthA: GetWindowTextLengthW's, in bytes of the narrow form.
#[unsafe(export_name = "f2k_export_GetWindowTextLengthA")]
pub extern "system" fn get_window_text_length_a(window: usize) -> i32 {
    match text_held_elsewhere(window) {
        None => 0,
        Some(true) => message::window_text(window)
            .map_or(0, |text| procedure::narrow_length(text.as_slice()) as i32),
        Some(false) => message::send_as(window, WM_GETTEXTLENGTH, 0, 0, true).unwrap_or(0),
    }
}

/// SetWindowTextW: the window's procedure sent WM_SETTEXT with the text at `text` (null: the empty
/// text), handed over as it is; TRUE whatever it answers (the wintext capture's refusing
/// procedure's call answers TRUE), FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_SetWindowTextW")]
pub extern "system" fn set_window_text_w(window: usize, text: usize) -> u32 {
    if text_held_elsewhere(window).is_none() {
        return 0;
    }
    message::send_as(window, WM_SETTEXT, 0, text as i32, false).is_some() as u32
}

/// SetWindowTextA: SetWindowTextW's, the text in the narrow form.
#[unsafe(export_name = "f2k_export_SetWindowTextA")]
pub extern "system" fn set_window_text_a(window: usize, text: usize) -> u32 {
    if text_held_elsewhere(window).is_none() {
        return 0;
    }
    message::send_as(window, WM_SETTEXT, 0, text as i32, true).is_some() as u32
}

/// A wide name's units, for the tests' reading of what a creation was given.
#[cfg(test)]
fn units(name: &str) -> std::vec::Vec<u16> {
    name.encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use rtl::user::{WM_CREATE, WM_DESTROY, WM_NCCREATE, WM_NCDESTROY, WM_USER};

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

    /// A window of a class of `proc` named `name` with `extra` extra bytes, registered through the
    /// narrow form when `ansi`, the wide one otherwise.
    fn data_window(
        name: &str,
        proc: fn(u32, u32, u32, i32) -> i32,
        extra: i32,
        ansi: bool,
    ) -> usize {
        let wide: std::vec::Vec<u16> = name.encode_utf16().chain([0]).collect();
        let narrow: std::vec::Vec<u8> = name.bytes().chain([0]).collect();
        let class = WndClass {
            wnd_proc: procedure(proc) as usize,
            cb_wnd_extra: extra,
            instance: 0x40_0000,
            class_name: if ansi {
                narrow.as_ptr() as usize
            } else {
                wide.as_ptr() as usize
            },
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASS of the tests' own, its name alive for the call.
        let atom = unsafe {
            if ansi {
                register_class_a(&class)
            } else {
                crate::class::register_class_w(&class)
            }
        };
        assert_ne!(atom, 0);
        let window = create_window_ex_w(
            0,
            wide.as_ptr(),
            core::ptr::null(),
            0x00C0_0000,
            0,
            0,
            100,
            100,
            0,
            0,
            0x40_0000,
            0,
        );
        assert_ne!(window, 0);
        seen();
        window
    }

    /// The window's fields and extra bytes through GetWindowLong/SetWindowLong and
    /// GetWindowWord/SetWindowWord: the previous values answered, the last error untouched by a
    /// success; ERROR_INVALID_INDEX past the extra bytes, at a negative offset and for an index
    /// naming no field; 1400 for no window.
    ///
    /// Pins: user32.GetWindowLongA, user32.GetWindowLongW, user32.SetWindowLongA,
    /// user32.SetWindowLongW, user32.GetWindowWord, user32.SetWindowWord
    #[test]
    fn window_longs_and_extra_bytes() {
        let window = data_window("F2KLongs", recorder, 12, false);
        arm();
        assert_eq!(get_window_long_w(window, GWL_USERDATA), 0);
        assert_eq!(set_window_long_a(window, GWL_USERDATA, 0x1234_5678), 0);
        assert_eq!(set_window_long_w(window, GWL_USERDATA, -5), 0x1234_5678);
        assert_eq!(get_window_long_a(window, GWL_USERDATA), -5);
        assert_eq!(get_window_long_w(window, GWL_STYLE), 0x00C0_0000);
        assert_eq!(get_window_long_a(window, GWL_HINSTANCE), 0x40_0000);
        assert_eq!(set_window_long_w(window, 0, 0x1111_1111), 0);
        assert_eq!(set_window_long_w(window, 4, 0x2222_2222), 0);
        assert_eq!(get_window_long_w(window, 2), 0x2222_1111);
        assert_eq!(set_window_word(window, 0, 0xABCD), 0x1111);
        assert_eq!(get_window_word(window, 0), 0xABCD);
        assert_eq!(get_window_long_w(window, 0), 0x1111_ABCDu32 as i32);
        assert_eq!(last_error(), UNSET);
        let failures: [(&dyn Fn() -> u32, u32); 8] = [
            (&|| get_window_long_w(window, 9) as u32, ERROR_INVALID_INDEX),
            (
                &|| set_window_long_w(window, 12, 1) as u32,
                ERROR_INVALID_INDEX,
            ),
            (
                &|| get_window_long_w(window, -100) as u32,
                ERROR_INVALID_INDEX,
            ),
            (&|| get_window_word(window, 11) as u32, ERROR_INVALID_INDEX),
            (
                &|| set_window_word(window, 11, 1) as u32,
                ERROR_INVALID_INDEX,
            ),
            (&|| get_window_word(window, -2) as u32, ERROR_INVALID_INDEX),
            (&|| get_window_long_w(0, GWL_STYLE) as u32, 1400),
            (&|| set_window_long_w(0, GWL_USERDATA, 1) as u32, 1400),
        ];
        for (call, error) in failures {
            arm();
            assert_eq!((call(), last_error()), (0, error));
        }
    }

    std::thread_local! {
        /// The procedure the subclass hands its messages on to.
        static PREVIOUS: core::cell::Cell<i32> = const { core::cell::Cell::new(0) };
    }

    /// The class's procedure: answers WM_USER + 1 with 10.
    fn base(_: u32, message: u32, _: u32, _: i32) -> i32 {
        SEEN.with(|seen| seen.borrow_mut().push(message));
        if message == WM_USER + 1 {
            10
        } else {
            0
        }
    }

    /// A narrow subclass: hands WM_USER + 1 on through CallWindowProcA, adding 100.
    fn subclass(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        let previous = PREVIOUS.with(|previous| previous.get()) as usize;
        let answer = crate::procedure::call_window_proc_a(
            previous,
            window as usize,
            message,
            wparam,
            lparam,
        );
        answer + 100
    }

    /// GWL_WNDPROC across the forms: a wide window's procedure is its address through the W form
    /// and a handle (high word 0xFFFF) through the A form; a narrow subclass makes the window
    /// narrow, its previous procedure a handle that CallWindowProcA calls through; setting that
    /// handle back restores the wide procedure.
    ///
    /// Pins: user32.GetWindowLongA, user32.GetWindowLongW, user32.SetWindowLongA,
    /// user32.CallWindowProcA, user32.CallWindowProcW, user32.IsWindowUnicode
    #[test]
    fn subclassing_across_the_forms() {
        let window = data_window("F2KSubclass", base, 0, false);
        let wide = get_window_long_w(window, GWL_WNDPROC);
        let narrow = get_window_long_a(window, GWL_WNDPROC);
        let class_proc = wm(|wm| wm.windows.last().unwrap().proc);
        assert_eq!(wide as u32, class_proc, "the class's procedure");
        assert_eq!(narrow as u32 >> 16, 0xFFFF);
        assert_eq!(is_window_unicode(window), 1);
        assert_eq!(
            crate::procedure::call_window_proc_a(narrow as usize, window, WM_USER + 1, 0, 0),
            10
        );
        assert_eq!(
            crate::procedure::call_window_proc_w(wide as usize, window, WM_USER + 1, 0, 0),
            10
        );

        let sub = procedure(subclass) as i32;
        let previous = set_window_long_a(window, GWL_WNDPROC, sub);
        assert_eq!(
            previous, narrow,
            "the wide procedure as the A form's handle"
        );
        PREVIOUS.with(|cell| cell.set(previous));
        assert_eq!(is_window_unicode(window), 0);
        assert_eq!(get_window_long_a(window, GWL_WNDPROC), sub);
        assert_eq!(get_window_long_w(window, GWL_WNDPROC) as u32 >> 16, 0xFFFF);
        seen();
        assert_eq!(
            crate::message::send_message_w(window, WM_USER + 1, 0, 0),
            110
        );
        assert_eq!(seen(), [WM_USER + 1]);

        assert_eq!(set_window_long_a(window, GWL_WNDPROC, previous), sub);
        assert_eq!(is_window_unicode(window), 1);
        assert_eq!(get_window_long_w(window, GWL_WNDPROC), wide);
        arm();
        assert_eq!(is_window_unicode(0x7FFF_FFFC), 0);
        assert_eq!(last_error(), 1400);
    }

    /// A narrow procedure handing everything to DefWindowProcA.
    fn narrow_default(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        SEEN.with(|seen| seen.borrow_mut().push(message));
        crate::message::def_window_proc_a(window as usize, message, wparam, lparam)
    }

    /// The text calls: the length the procedure answers from the text the window manager holds;
    /// a buffer emptied first and 1400 for no window; nothing sent for an empty buffer.
    ///
    /// Pins: user32.GetWindowTextLengthA, user32.GetWindowTextA, user32.GetWindowTextW,
    /// user32.SetWindowTextW
    #[test]
    fn window_text_lengths_and_errors() {
        let window = data_window("F2KText", narrow_default, 0, true);
        wm(|wm| wm.windows.last_mut().unwrap().text = "hello".encode_utf16().collect());
        assert_eq!(get_window_text_length_a(window), 5);
        assert_eq!(seen(), [rtl::user::WM_GETTEXTLENGTH]);
        let mut narrow = [b'#'; 4];
        // SAFETY: the tests' own buffer, of the length given.
        assert_eq!(
            unsafe { get_window_text_a(window, narrow.as_mut_ptr(), 0) },
            0
        );
        assert_eq!(narrow, [b'#'; 4]);
        assert!(seen().is_empty());
        let mut wide = [0x23u16; 4];
        arm();
        // SAFETY: as above.
        assert_eq!(unsafe { get_window_text_w(0, wide.as_mut_ptr(), 4) }, 0);
        assert_eq!((wide[0], wide[1], last_error()), (0, 0x23, 1400));
        arm();
        assert_eq!(get_window_text_length_w(0x7FFF_FFFC), 0);
        assert_eq!(last_error(), 1400);
        arm();
        assert_eq!(set_window_text_w(0, 0), 0);
        assert_eq!(last_error(), 1400);
    }
}
