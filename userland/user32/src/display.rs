//! The display settings: the ChangeDisplaySettings family, each over win32k's
//! NtUserChangeDisplaySettings ([`imports::change_display_settings`]), as Windows 2000's user32
//! calls it: the wide forms hand the caller's name and DEVMODEW to the kernel unread, the narrow
//! ones convert theirs to the wide form first. The answer is the kernel's DISP_CHANGE code, as it
//! is; no last error is set (ChangeDisplaySettings documents none).
//!
//! What the kernel's minimal subset serves is in its display service's notes (one display,
//! `\\.\DISPLAY1`; its graphics mode set once; the flags 0, CDS_FULLSCREEN and CDS_TEST).
//!
//! The rest of the display's face, over win32k's display services the same way (the narrow forms
//! converting to and from the wide ones): the modes (EnumDisplaySettings) and the devices
//! (EnumDisplayDevices); the monitors (EnumDisplayMonitors, whose callback user32 calls with the
//! monitors the kernel selects; GetMonitorInfoA; MonitorFromWindow, MonitorFromPoint and
//! MonitorFromRect, which ask the same selection about a place); the system metrics
//! (GetSystemMetrics: the screen and the work area from the services, the standard scheme's
//! constants), SystemParametersInfo (SPI_GETWORKAREA); and the system colors (SetSysColors,
//! GetSysColor, GetSysColorBrush).

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use rtl::display::{
    wide_dev_mode,
    DevModeA,
    DevModeW,
    DisplayDeviceA,
    DisplayDeviceW,
    CCHDEVICENAME,
    DEFAULT_SYSTEM_COLORS,
    DEV_MODE_A_SIZE,
    DISP_CHANGE_BADPARAM,
    PRIMARY_MONITOR_HANDLE,
    SPI_GETWORKAREA,
    SYSTEM_COLORS,
};
use rtl::edge::{In, InBuf, InStr};
use rtl::gdi::Rect;
use rtl::nonclient;
use rtl::pod::Pod;

use crate::{caller_bytes_mut, imports};

/// ChangeDisplaySettingsA: ChangeDisplaySettingsExA for the primary display.
///
/// # Safety
///
/// The caller's DEVMODEA (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_ChangeDisplaySettingsA")]
pub unsafe extern "system" fn change_display_settings_a(
    dev_mode: *const DevModeA,
    flags: u32,
) -> i32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { change_display_settings_ex_a(core::ptr::null(), dev_mode, 0, flags, 0) }
}

/// ChangeDisplaySettingsW: ChangeDisplaySettingsExW for the primary display.
#[unsafe(export_name = "f2k_export_ChangeDisplaySettingsW")]
pub extern "system" fn change_display_settings_w(dev_mode: *const DevModeW, flags: u32) -> i32 {
    change_display_settings_ex_w(core::ptr::null(), dev_mode, 0, flags, 0)
}

/// ChangeDisplaySettingsExW: the change, the name and the DEVMODEW handed to the kernel unread (it
/// reads the caller's memory through its fault-tolerant copies; nothing here does).
#[unsafe(export_name = "f2k_export_ChangeDisplaySettingsExW")]
pub extern "system" fn change_display_settings_ex_w(
    device: *const u16,
    dev_mode: *const DevModeW,
    window: usize,
    flags: u32,
    param: usize,
) -> i32 {
    imports::change_display_settings(device as usize, dev_mode as usize, window, flags, param)
}

/// ChangeDisplaySettingsExA: the name and the DEVMODEA converted to their wide forms, then
/// ChangeDisplaySettingsExW's change. A name longer than a device name's room is
/// DISP_CHANGE_BADPARAM.
///
/// # Safety
///
/// The caller's name (a NUL-terminated string, or null) and DEVMODEA (as long as its dmSize says,
/// or null), as for the platform's.
#[unsafe(export_name = "f2k_export_ChangeDisplaySettingsExA")]
pub unsafe extern "system" fn change_display_settings_ex_a(
    device: *const u8,
    dev_mode: *const DevModeA,
    window: usize,
    flags: u32,
    param: usize,
) -> i32 {
    // SAFETY: the caller's string, or null.
    let device = unsafe { InStr::optional(device) };
    // SAFETY: the caller's DEVMODEA, or null: its dmSize read first, then as much of it as that
    // says (up to the structure's size).
    let dev_mode = (!dev_mode.is_null()).then(|| unsafe {
        let size = In::new(dev_mode.cast::<u8>().add(DEV_MODE_A_SIZE).cast::<u16>()).read();
        InBuf::new(
            dev_mode.cast::<u8>(),
            (size as usize).min(size_of::<DevModeA>()),
        )
    });
    change_ex_a(device, dev_mode, window, flags, param)
}

/// ChangeDisplaySettingsExA's core, over the caller's name and the bytes of its DEVMODEA.
fn change_ex_a(
    device: Option<InStr>,
    dev_mode: Option<InBuf<u8>>,
    window: usize,
    flags: u32,
    param: usize,
) -> i32 {
    // The name in UTF-16, NUL-terminated.
    let mut units = [0u16; CCHDEVICENAME];
    let name = match device {
        None => None,
        Some(device) => {
            let Some(bytes) = device.bytes_within(CCHDEVICENAME - 1) else {
                return DISP_CHANGE_BADPARAM;
            };
            imports::multi_byte_to_unicode(&mut units[..CCHDEVICENAME - 1], bytes);
            Some(&units)
        }
    };
    let wide = dev_mode.map(|bytes| {
        let mut narrow = DevModeA::zeroed();
        bytes.copy_to(narrow.as_bytes_mut());
        wide_dev_mode(&narrow, |units, bytes| {
            let room = units.len() - 1;
            imports::multi_byte_to_unicode(&mut units[..room], bytes);
        })
    });
    // Both live until the call returns: the kernel reads them meanwhile.
    imports::change_display_settings(
        name.map_or(0, |name| name.as_ptr() as usize),
        wide.as_ref()
            .map_or(0, |wide| wide as *const DevModeW as usize),
        window,
        flags,
        param,
    )
}

/// The wide form of a narrow display name, NUL-terminated, in `units`: `Some(None)` for no name,
/// none for a name longer than a device name's room.
fn wide_name<'a>(
    name: Option<InStr>,
    units: &'a mut [u16; CCHDEVICENAME],
) -> Option<Option<&'a [u16]>> {
    let Some(name) = name else {
        return Some(None);
    };
    let bytes = name.bytes_within(CCHDEVICENAME - 1)?;
    let length = imports::multi_byte_to_unicode(&mut units[..CCHDEVICENAME - 1], bytes);
    units[length] = 0;
    Some(Some(&units[..=length]))
}

/// The narrow form of the UTF-16 field `units` (to its NUL) into the bytes `out`, NUL-padded.
fn narrow_text(units: &[u16], out: &mut [u8]) {
    let length = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    let room = out.len() - 1;
    let written = imports::unicode_to_multi_byte(&mut out[..room], &units[..length]);
    out[written..].fill(0);
}

// --- The display modes ---------------------------------------------------------------------------

/// EnumDisplaySettingsW: mode `mode` of the display (NULL: the primary one; ENUM_CURRENT_SETTINGS:
/// the current mode) described into the caller's DEVMODEW in the version win32k describes modes in,
/// dmSize 188 whatever the caller's (as the guidisp capture shows), the caller's bytes past it
/// untouched; FALSE past the modes, the last error untouched (as the capture shows too).
#[unsafe(export_name = "f2k_export_EnumDisplaySettingsW")]
pub extern "system" fn enum_display_settings_w(
    device: *const u16,
    mode: u32,
    dev_mode: *mut DevModeW,
) -> u32 {
    imports::enum_display_settings(device as usize, mode, dev_mode as usize, 0).is_ok() as u32
}

/// EnumDisplaySettingsA: EnumDisplaySettingsW's description, asked into a DEVMODEW of the same
/// version (the caller's dmSize and the names' 64 bytes) and converted to the narrow form, which
/// the caller's DEVMODEA receives as far as the shorter of its dmSize and the narrow form's goes;
/// its dmSize the narrow form of the version the wide answer names (124: the guidisp capture shows
/// Windows 2000 answering its own version there, whatever the caller's).
///
/// # Safety
///
/// The caller's name (a NUL-terminated string, or null) and DEVMODEA (as long as its dmSize says),
/// as for the platform's.
#[unsafe(export_name = "f2k_export_EnumDisplaySettingsA")]
pub unsafe extern "system" fn enum_display_settings_a(
    device: *const u8,
    mode: u32,
    dev_mode: *mut DevModeA,
) -> u32 {
    // SAFETY: the caller's name, or null; its DEVMODEA's dmSize, then as much of it as that says.
    let (device, size) = unsafe {
        (
            InStr::optional(device),
            In::new(dev_mode.cast::<u8>().add(DEV_MODE_A_SIZE).cast::<u16>()).read(),
        )
    };
    let length = (size as usize).min(size_of::<DevModeA>());
    // SAFETY: as above.
    let out = unsafe { caller_bytes_mut(dev_mode.cast(), length) };
    settings_a(device, mode, size, out)
}

/// EnumDisplaySettingsA's core: the mode into the caller's DEVMODEA bytes, `size` its dmSize.
fn settings_a(device: Option<InStr>, mode: u32, size: u16, out: Option<&mut [u8]>) -> u32 {
    let mut units = [0u16; CCHDEVICENAME];
    let Some(name) = wide_name(device, &mut units) else {
        return 0;
    };
    let mut wide = DevModeW::zeroed();
    wide.size = (size as usize + size_of::<DevModeW>() - size_of::<DevModeA>())
        .min(size_of::<DevModeW>()) as u16;
    let name = name.map_or(0, |name| name.as_ptr() as usize);
    if imports::enum_display_settings(name, mode, &mut wide as *mut DevModeW as usize, 0).is_err() {
        return 0;
    }
    let narrow = narrow_dev_mode(&wide);
    let Some(out) = out else {
        return 0;
    };
    let length = out.len().min(narrow.size as usize);
    out[..length].copy_from_slice(&narrow.as_bytes()[..length]);
    1
}

/// The narrow form of `mode`: the two names converted, every other field as it is, dmSize the
/// narrow form's of the same version.
fn narrow_dev_mode(mode: &DevModeW) -> DevModeA {
    let mut narrow = DevModeA::zeroed();
    narrow_text(&mode.device_name, &mut narrow.device_name);
    narrow_text(&mode.form_name, &mut narrow.form_name);
    narrow.spec_version = mode.spec_version;
    narrow.driver_version = mode.driver_version;
    narrow.size = mode
        .size
        .saturating_sub((size_of::<DevModeW>() - size_of::<DevModeA>()) as u16);
    narrow.driver_extra = 0;
    narrow.fields = mode.fields;
    narrow.printer = mode.printer;
    narrow.color = mode.color;
    narrow.duplex = mode.duplex;
    narrow.y_resolution = mode.y_resolution;
    narrow.tt_option = mode.tt_option;
    narrow.collate = mode.collate;
    narrow.log_pixels = mode.log_pixels;
    narrow.bits_per_pel = mode.bits_per_pel;
    narrow.pels_width = mode.pels_width;
    narrow.pels_height = mode.pels_height;
    narrow.display_flags = mode.display_flags;
    narrow.display_frequency = mode.display_frequency;
    narrow.icm_method = mode.icm_method;
    narrow.icm_intent = mode.icm_intent;
    narrow.media_type = mode.media_type;
    narrow.dither_type = mode.dither_type;
    narrow.reserved1 = mode.reserved1;
    narrow.reserved2 = mode.reserved2;
    narrow.panning_width = mode.panning_width;
    narrow.panning_height = mode.panning_height;
    narrow
}

// --- The display devices -------------------------------------------------------------------------

/// The end of a DISPLAY_DEVICEA's StateFlags: the smallest `cb` a caller's structure may have.
const DISPLAY_DEVICE_STATE_END_A: usize = offset_of!(DisplayDeviceA, device_id);

/// EnumDisplayDevicesW: display device `number` (the adapters for a NULL name, an adapter's
/// monitors for its name) into the caller's DISPLAY_DEVICEW as far as its cb goes; FALSE past the
/// devices, the last error untouched.
#[unsafe(export_name = "f2k_export_EnumDisplayDevicesW")]
pub extern "system" fn enum_display_devices_w(
    device: *const u16,
    number: u32,
    out: *mut DisplayDeviceW,
    flags: u32,
) -> u32 {
    imports::enum_display_devices(device as usize, number, out as usize, flags).is_ok() as u32
}

/// EnumDisplayDevicesA: EnumDisplayDevicesW's device, its strings converted to the narrow form,
/// into the caller's DISPLAY_DEVICEA as far as its cb goes (its cb kept).
///
/// # Safety
///
/// The caller's name (a NUL-terminated string, or null) and DISPLAY_DEVICEA (as long as its cb
/// says), as for the platform's.
#[unsafe(export_name = "f2k_export_EnumDisplayDevicesA")]
pub unsafe extern "system" fn enum_display_devices_a(
    device: *const u8,
    number: u32,
    out: *mut DisplayDeviceA,
    flags: u32,
) -> u32 {
    // SAFETY: the caller's name, or null; its structure's cb, then as much of it as that says.
    let (device, cb) = unsafe { (InStr::optional(device), In::new(out.cast::<u32>()).read()) };
    let length = (cb as usize).min(size_of::<DisplayDeviceA>());
    // SAFETY: as above.
    let out = unsafe { caller_bytes_mut(out.cast(), length) };
    devices_a(device, number, cb, out, flags)
}

/// EnumDisplayDevicesA's core: the device into the caller's DISPLAY_DEVICEA bytes.
fn devices_a(
    device: Option<InStr>,
    number: u32,
    cb: u32,
    out: Option<&mut [u8]>,
    flags: u32,
) -> u32 {
    if (cb as usize) < DISPLAY_DEVICE_STATE_END_A {
        return 0;
    }
    let mut units = [0u16; CCHDEVICENAME];
    let Some(name) = wide_name(device, &mut units) else {
        return 0;
    };
    let mut wide = DisplayDeviceW::zeroed();
    wide.cb = size_of::<DisplayDeviceW>() as u32;
    let name = name.map_or(0, |name| name.as_ptr() as usize);
    let address = &mut wide as *mut DisplayDeviceW as usize;
    if imports::enum_display_devices(name, number, address, flags).is_err() {
        return 0;
    }
    let mut narrow = DisplayDeviceA::zeroed();
    narrow.cb = cb;
    narrow_text(&wide.device_name, &mut narrow.device_name);
    narrow_text(&wide.device_string, &mut narrow.device_string);
    narrow.state_flags = wide.state_flags;
    narrow_text(&wide.device_id, &mut narrow.device_id);
    narrow_text(&wide.device_key, &mut narrow.device_key);
    let Some(out) = out else {
        return 0;
    };
    let length = out.len();
    out.copy_from_slice(&narrow.as_bytes()[..length]);
    1
}

// --- The monitors --------------------------------------------------------------------------------

/// How many monitors EnumDisplayMonitors visits at most.
const MONITORS: usize = 4;

/// MonitorFrom*'s flags: what to answer for a place off every monitor.
pub const MONITOR_DEFAULTTONULL: u32 = 0;
pub const MONITOR_DEFAULTTOPRIMARY: u32 = 1;
pub const MONITOR_DEFAULTTONEAREST: u32 = 2;

/// MONITORINFO's dwFlags: the primary monitor.
pub const MONITORINFOF_PRIMARY: u32 = 1;

/// ERROR_INVALID_MONITOR_HANDLE: a handle that names no monitor.
pub const ERROR_INVALID_MONITOR_HANDLE: u32 = 1461;

/// MONITORINFOEXA (72 bytes): MONITORINFO (40 bytes: its size, the monitor's rectangle, its work
/// area, its flags) and the display's name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonitorInfoExA {
    pub cb_size: u32,
    pub monitor: Rect,
    pub work: Rect,
    pub flags: u32,
    pub device: [u8; CCHDEVICENAME],
}

const _: () = {
    assert!(size_of::<MonitorInfoExA>() == 72);
    assert!(offset_of!(MonitorInfoExA, device) == 40);
};

// SAFETY: integers, RECTs and bytes, without padding (the asserts above pin the offsets); any bit
// pattern is a value.
unsafe impl Pod for MonitorInfoExA {}

/// The monitors the RECT at `clip` (zero: none) meets, their handles and rectangles inside it.
fn monitors(clip: usize) -> ([(u32, Rect); MONITORS], usize) {
    let mut handles = [0u32; MONITORS];
    let mut rects = [Rect::default(); MONITORS];
    let found = imports::enum_display_monitors(0, clip, &mut handles, &mut rects).unwrap_or(0);
    let mut both = [(0, Rect::default()); MONITORS];
    for (slot, pair) in both.iter_mut().zip(handles.into_iter().zip(rects)) {
        *slot = pair;
    }
    (both, (found as usize).min(MONITORS))
}

/// The primary monitor: the first one the display lists, and its rectangle (the screen's).
fn primary() -> Option<(u32, Rect)> {
    let (found, count) = monitors(0);
    (count != 0).then_some(found[0])
}

/// The monitor `rect` meets, or as `flags` say for a place off every monitor (none at all, or the
/// primary one).
fn monitor_for(rect: Option<Rect>, flags: u32) -> usize {
    if let Some(rect) = rect {
        let (found, count) = monitors(&rect as *const Rect as usize);
        if count != 0 {
            return found[0].0 as usize;
        }
    }
    match flags {
        MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST => {
            primary().map_or(0, |(monitor, _)| monitor as usize)
        }
        _ => 0,
    }
}

/// MonitorFromRect: the monitor the rectangle meets; off every monitor, as the flags say.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_MonitorFromRect")]
pub unsafe extern "system" fn monitor_from_rect(rect: *const Rect, flags: u32) -> usize {
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect) }.read();
    monitor_for(Some(rect), flags)
}

/// MonitorFromPoint: the monitor the point is on; off every monitor, as the flags say.
#[unsafe(export_name = "f2k_export_MonitorFromPoint")]
pub extern "system" fn monitor_from_point(x: i32, y: i32, flags: u32) -> usize {
    let rect = Rect {
        left: x,
        top: y,
        right: x.saturating_add(1),
        bottom: y.saturating_add(1),
    };
    monitor_for(Some(rect), flags)
}

/// MonitorFromWindow: the monitor the window's rectangle meets; off every monitor (or for a handle
/// naming no window), as the flags say.
#[unsafe(export_name = "f2k_export_MonitorFromWindow")]
pub extern "system" fn monitor_from_window(window: usize, flags: u32) -> usize {
    let mut info = rtl::window::WindowInfo {
        size: size_of::<rtl::window::WindowInfo>() as u32,
        ..Default::default()
    };
    let rect = imports::query_window(window, rtl::window::QUERY_WINDOW_INFO, &mut info)
        .ok()
        .map(|()| info.window);
    monitor_for(rect, flags)
}

/// EnumDisplayMonitors: the callback called for each monitor the DC's area and the clipping
/// rectangle meet (each optional), with its handle, the DC and the part of its rectangle inside
/// the clip, until it answers FALSE; TRUE, or FALSE with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_EnumDisplayMonitors")]
pub extern "system" fn enum_display_monitors(
    dc: usize,
    clip: *const Rect,
    proc: usize,
    data: usize,
) -> u32 {
    let mut handles = [0u32; MONITORS];
    let mut rects = [Rect::default(); MONITORS];
    let Some(found) = crate::failed_with(
        imports::enum_display_monitors(dc, clip as usize, &mut handles, &mut rects),
        imports::dos_error,
    ) else {
        return 0;
    };
    let count = (found as usize).min(MONITORS);
    for (monitor, rect) in handles[..count].iter().zip(&rects[..count]) {
        if imports::call_monitor_procedure(proc as u32, *monitor, dc, rect, data) == 0 {
            break;
        }
    }
    1
}

/// GetMonitorInfoA: the monitor's rectangle, its work area and its flags into the caller's
/// MONITORINFO, and the display's name too into a MONITORINFOEXA (by its cbSize); FALSE with
/// ERROR_INVALID_PARAMETER for another cbSize, ERROR_INVALID_MONITOR_HANDLE for a handle that
/// names no monitor.
///
/// # Safety
///
/// The caller's MONITORINFO or MONITORINFOEXA, as for the platform's.
#[unsafe(export_name = "f2k_export_GetMonitorInfoA")]
pub unsafe extern "system" fn get_monitor_info_a(monitor: usize, info: *mut MonitorInfoExA) -> u32 {
    // SAFETY: the caller's structure's cbSize, then as much of it as that says.
    let size = unsafe { In::new(info.cast::<u32>()) }.read();
    let length = (size as usize).min(size_of::<MonitorInfoExA>());
    // SAFETY: as above.
    let out = unsafe { caller_bytes_mut(info.cast(), length) };
    monitor_info_a(monitor, size, out)
}

/// The size of MONITORINFO, the extended form's first part.
const MONITOR_INFO_SIZE: u32 = offset_of!(MonitorInfoExA, device) as u32;

/// GetMonitorInfoA's core, into the caller's bytes.
fn monitor_info_a(monitor: usize, size: u32, out: Option<&mut [u8]>) -> u32 {
    if size != MONITOR_INFO_SIZE && size as usize != size_of::<MonitorInfoExA>() {
        return crate::failed(crate::ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let (found, count) = monitors(0);
    let Some(&(handle, rect)) = found[..count]
        .iter()
        .find(|(handle, _)| *handle as usize == monitor)
    else {
        return crate::failed(ERROR_INVALID_MONITOR_HANDLE).unwrap_or(0);
    };
    let mut work = Rect::default();
    if imports::system_parameters_info(SPI_GETWORKAREA, 0, &mut work as *mut Rect as usize, 0)
        .is_err()
    {
        work = rect;
    }
    let mut answer = MonitorInfoExA {
        cb_size: size,
        monitor: rect,
        work,
        flags: if handle == PRIMARY_MONITOR_HANDLE {
            MONITORINFOF_PRIMARY
        } else {
            0
        },
        ..MonitorInfoExA::default()
    };
    answer.device[..12].copy_from_slice(b"\\\\.\\DISPLAY1");
    let Some(out) = out else {
        return 0;
    };
    let length = out.len();
    out.copy_from_slice(&answer.as_bytes()[..length]);
    1
}

// --- The system metrics and parameters -----------------------------------------------------------

/// GetSystemMetrics' indexes (winuser.h's SM_*) the served set names.
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SM_CXFULLSCREEN: i32 = 16;
const SM_CYFULLSCREEN: i32 = 17;
const SM_CXVIRTUALSCREEN: i32 = 78;
const SM_CYVIRTUALSCREEN: i32 = 79;
const SM_CMONITORS: i32 = 80;

/// The caption's height, SM_CYCAPTION (the guidisp capture's).
const CAPTION: i32 = nonclient::CAPTION;

/// The metrics that are constants of Windows 2000's standard scheme at 96 dpi, and of a machine
/// without a mouse, by index: SM_CXVSCROLL to SM_CYMENU, SM_MOUSEPRESENT to SM_SWAPBUTTON, the
/// frame and the caption buttons, SM_CMOUSEBUTTONS, the edge, the smallest window, the small
/// icon and caption, the menu buttons, the check mark, SM_MOUSEWHEELPRESENT, the virtual screen's
/// origin and SM_SAMEDISPLAYFORMAT. The non-client ones are rtl::nonclient's, the frame win32k and
/// the default window procedure draw.
const METRICS: [(i32, i32); 46] = [
    (2, 16),                     // SM_CXVSCROLL
    (3, 16),                     // SM_CYHSCROLL
    (4, CAPTION),                // SM_CYCAPTION
    (5, nonclient::BORDER),      // SM_CXBORDER
    (6, nonclient::BORDER),      // SM_CYBORDER
    (7, nonclient::DLG_FRAME),   // SM_CXDLGFRAME
    (8, nonclient::DLG_FRAME),   // SM_CYDLGFRAME
    (28, nonclient::MIN_X),      // SM_CXMIN
    (29, nonclient::MIN_Y),      // SM_CYMIN
    (30, nonclient::SIZE),       // SM_CXSIZE
    (31, nonclient::SIZE),       // SM_CYSIZE
    (34, nonclient::MIN_X),      // SM_CXMINTRACK
    (35, nonclient::MIN_Y),      // SM_CYMINTRACK
    (49, nonclient::SM_ICON),    // SM_CXSMICON
    (50, nonclient::SM_ICON),    // SM_CYSMICON
    (51, nonclient::SM_CAPTION), // SM_CYSMCAPTION
    (52, nonclient::SM_SIZE_X),  // SM_CXSMSIZE
    (53, nonclient::SM_SIZE_Y),  // SM_CYSMSIZE
    (54, nonclient::MENU_SIZE),  // SM_CXMENUSIZE
    (55, nonclient::MENU_SIZE),  // SM_CYMENUSIZE
    (71, nonclient::MENU_CHECK), // SM_CXMENUCHECK
    (72, nonclient::MENU_CHECK), // SM_CYMENUCHECK
    (9, 16),                     // SM_CYVTHUMB
    (10, 16),                    // SM_CXHTHUMB
    (11, 32),                    // SM_CXICON
    (12, 32),                    // SM_CYICON
    (13, 32),                    // SM_CXCURSOR
    (14, 32),                    // SM_CYCURSOR
    (15, nonclient::MENU),       // SM_CYMENU
    (18, 0),                     // SM_CYKANJIWINDOW
    (19, 0),                     // SM_MOUSEPRESENT
    (20, 16),                    // SM_CYVSCROLL
    (21, 16),                    // SM_CXHSCROLL
    (22, 0),                     // SM_DEBUG
    (23, 0),                     // SM_SWAPBUTTON
    (32, nonclient::FRAME),      // SM_CXFRAME
    (33, nonclient::FRAME),      // SM_CYFRAME
    (43, 0),                     // SM_CMOUSEBUTTONS
    (45, nonclient::EDGE),       // SM_CXEDGE
    (46, nonclient::EDGE),       // SM_CYEDGE
    (67, 0),                     // SM_CLEANBOOT
    (75, 0),                     // SM_MOUSEWHEELPRESENT
    (76, 0),                     // SM_XVIRTUALSCREEN
    (77, 0),                     // SM_YVIRTUALSCREEN
    (81, 1),                     // SM_SAMEDISPLAYFORMAT
    (42, 0),                     // SM_DBCSENABLED
];

/// The metric `index`: the screen's (the primary monitor's rectangle), the work area's, the
/// monitors' count, or a constant ([`METRICS`]); none for an index outside the served set.
fn metric(index: i32) -> Option<i32> {
    let screen = || primary().map_or(Rect::default(), |(_, rect)| rect);
    let work = || {
        let mut work = Rect::default();
        imports::system_parameters_info(SPI_GETWORKAREA, 0, &mut work as *mut Rect as usize, 0)
            .map_or_else(|_| screen(), |()| work)
    };
    let width = |rect: Rect| rect.right - rect.left;
    let height = |rect: Rect| rect.bottom - rect.top;
    Some(match index {
        SM_CXSCREEN | SM_CXVIRTUALSCREEN => width(screen()),
        SM_CYSCREEN | SM_CYVIRTUALSCREEN => height(screen()),
        SM_CXFULLSCREEN => width(work()),
        SM_CYFULLSCREEN => height(work()) - CAPTION,
        SM_CMONITORS => monitors(0).1 as i32,
        _ => METRICS.iter().find(|(i, _)| *i == index)?.1,
    })
}

/// GetSystemMetrics: the metric; an index outside the served set goes to the stub routine (0).
#[unsafe(export_name = "f2k_export_GetSystemMetrics")]
pub extern "system" fn get_system_metrics(index: i32) -> i32 {
    metric(index).unwrap_or_else(|| {
        // SAFETY: the argument as GetSystemMetrics' kind reads it: no memory.
        unsafe {
            crate::stub::stubbed(
                &crate::spec::GetSystemMetrics,
                "the metric is not served yet",
                &[index as u32 as u64],
            ) as i32
        }
    })
}

/// SystemParametersInfo's core: SPI_GETWORKAREA from the kernel (TRUE, or FALSE with the last
/// error); another action to the stub routine.
fn parameters(
    entry: &rtl::stub::Entry,
    action: u32,
    ui_param: u32,
    param: usize,
    win_ini: u32,
) -> u32 {
    if action != SPI_GETWORKAREA {
        let args = [
            u64::from(action),
            u64::from(ui_param),
            param as u64,
            u64::from(win_ini),
        ];
        // SAFETY: the arguments as the export's kinds read them: the parameter is an address,
        // not read.
        return unsafe { crate::stub::stubbed(entry, "SPI_GETWORKAREA alone is served", &args) };
    }
    crate::failed_with(
        imports::system_parameters_info(action, ui_param, param, win_ini),
        imports::dos_error,
    )
    .is_some() as u32
}

/// SystemParametersInfoW: SPI_GETWORKAREA, the primary monitor's work area into pvParam's RECT.
#[unsafe(export_name = "f2k_export_SystemParametersInfoW")]
pub extern "system" fn system_parameters_info_w(
    action: u32,
    ui_param: u32,
    param: usize,
    win_ini: u32,
) -> u32 {
    parameters(
        &crate::spec::SystemParametersInfoW,
        action,
        ui_param,
        param,
        win_ini,
    )
}

/// SystemParametersInfoA: SystemParametersInfoW's (SPI_GETWORKAREA carries no text).
#[unsafe(export_name = "f2k_export_SystemParametersInfoA")]
pub extern "system" fn system_parameters_info_a(
    action: u32,
    ui_param: u32,
    param: usize,
    win_ini: u32,
) -> u32 {
    parameters(
        &crate::spec::SystemParametersInfoA,
        action,
        ui_param,
        param,
        win_ini,
    )
}

// --- The system colors ---------------------------------------------------------------------------

/// The system colors as this process knows them: Windows 2000's default scheme, as win32k starts
/// with it, and the changes this process's SetSysColors made. win32k serves no read of its own
/// table, so another process's changes are not seen (the read path is a seam).
static SYSTEM_COLORS_SEEN: [AtomicU32; SYSTEM_COLORS] = {
    let mut colors = [const { AtomicU32::new(0) }; SYSTEM_COLORS];
    let mut index = 0;
    while index < SYSTEM_COLORS {
        colors[index] = AtomicU32::new(DEFAULT_SYSTEM_COLORS[index]);
        index += 1;
    }
    colors
};

/// GetSysColor: the system color `index`'s COLORREF; 0 for an index past the table.
#[unsafe(export_name = "f2k_export_GetSysColor")]
pub extern "system" fn get_sys_color(index: i32) -> u32 {
    SYSTEM_COLORS_SEEN
        .get(index as usize)
        .map_or(0, |color| color.load(Ordering::Relaxed))
}

/// GetSysColorBrush: the system color `index`'s brush, a global brush every process names by the
/// same handle, which a DC selects and which paints in the system color as it is when it draws
/// (rtl::gdi's [`sys_color_brush`](rtl::gdi::sys_color_brush)); NULL for an index past the table.
#[unsafe(export_name = "f2k_export_GetSysColorBrush")]
pub extern "system" fn get_sys_color_brush(index: i32) -> usize {
    rtl::gdi::sys_color_brush(index as u32).map_or(0, |brush| brush as usize)
}

/// SetSysColors: `count` system colors set, their indexes and COLORREFs in the caller's arrays;
/// TRUE, or FALSE with ERROR_INVALID_PARAMETER for an index past the table (nothing set).
///
/// # Safety
///
/// The caller's two arrays of `count` entries, as for the platform's.
#[unsafe(export_name = "f2k_export_SetSysColors")]
pub unsafe extern "system" fn set_sys_colors(
    count: i32,
    indexes: *const u32,
    colors: *const u32,
) -> u32 {
    let count = count.max(0) as usize;
    // SAFETY: the caller's arrays.
    let (indexes, colors) = unsafe { (InBuf::new(indexes, count), InBuf::new(colors, count)) };
    set_colors(indexes, colors)
}

/// SetSysColors' core: the kernel's table changed (it reads the arrays), then this process's copy.
fn set_colors(indexes: InBuf<u32>, colors: InBuf<u32>) -> u32 {
    let changed = imports::set_sys_colors(
        indexes.len() as u32,
        indexes.as_ptr() as usize,
        colors.as_ptr() as usize,
    );
    if crate::failed_with(changed, imports::dos_error).is_none() {
        return 0;
    }
    for (index, color) in indexes.iter().zip(colors.iter()) {
        if let Some(seen) = SYSTEM_COLORS_SEEN.get(index as usize) {
            seen.store(color & rtl::gdi::RGB_MASK, Ordering::Relaxed);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use rtl::display::*;

    use super::*;
    use crate::imports::host::{DisplayChange, DISPLAY_ANSWER, DISPLAY_CHANGES, LAST_ERROR};

    fn changes() -> std::vec::Vec<DisplayChange> {
        DISPLAY_CHANGES.with(|changes| changes.take())
    }

    fn narrow(fields: u32, bits: u32, width: u32, height: u32) -> DevModeA {
        let mut mode = DevModeA::zeroed();
        mode.size = size_of::<DevModeA>() as u16;
        mode.fields = fields;
        mode.bits_per_pel = bits;
        mode.pels_width = width;
        mode.pels_height = height;
        mode
    }

    /// The narrow form reaches the kernel wide: the display fields as given, dmSize the wide
    /// form's, the name converted; the kernel's code is the answer, and no last error is set.
    ///
    /// Pins: user32.ChangeDisplaySettingsA, user32.ChangeDisplaySettingsExA
    #[test]
    fn the_narrow_forms_widen() {
        changes();
        LAST_ERROR.with(|error| error.set(0xF2F2_F2F2));
        let all = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;
        let mode = narrow(all, 32, 640, 480);
        // SAFETY: a DEVMODEA of the size it says.
        assert_eq!(
            unsafe { change_display_settings_a(&mode, CDS_FULLSCREEN) },
            0
        );
        DISPLAY_ANSWER.with(|answer| answer.set(DISP_CHANGE_BADMODE));
        // SAFETY: as above, and a NUL-terminated name.
        let answer = unsafe {
            change_display_settings_ex_a(c"\\\\.\\DISPLAY1".as_ptr().cast(), &mode, 0, CDS_TEST, 0)
        };
        DISPLAY_ANSWER.with(|answer| answer.set(0));
        assert_eq!(answer, DISP_CHANGE_BADMODE);
        let seen = changes();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].device, None);
        assert_eq!(seen[0].flags, CDS_FULLSCREEN);
        let wide = seen[0].dev_mode.unwrap();
        assert_eq!(wide.size as usize, size_of::<DevModeW>());
        assert_eq!(wide.fields, all);
        assert_eq!(
            (wide.bits_per_pel, wide.pels_width, wide.pels_height),
            (32, 640, 480)
        );
        assert_eq!(
            seen[1].device.as_deref(),
            Some(
                &"\\\\.\\DISPLAY1"
                    .encode_utf16()
                    .collect::<std::vec::Vec<_>>()[..]
            )
        );
        assert_eq!(seen[1].flags, CDS_TEST);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 0xF2F2_F2F2);
    }

    /// A DEVMODEA shorter than Windows 2000's is read only as far as its dmSize goes, and its
    /// wide form names the same version; a null one is the default mode.
    ///
    /// Pins: user32.ChangeDisplaySettingsA
    #[test]
    fn a_short_dev_mode_is_read_to_its_size() {
        changes();
        let mut mode = narrow(DM_PELSWIDTH, 0, 640, 0);
        mode.size = DISPLAY_FIELDS_END_A as u16;
        mode.panning_width = 99; // past dmSize: not read
                                 // SAFETY: a DEVMODEA at least as long as it says.
        assert_eq!(unsafe { change_display_settings_a(&mode, 0) }, 0);
        // SAFETY: null, the default mode.
        assert_eq!(
            unsafe { change_display_settings_a(core::ptr::null(), 0) },
            0
        );
        let seen = changes();
        let wide = seen[0].dev_mode.unwrap();
        assert_eq!(wide.size as usize, DISPLAY_FIELDS_END_W);
        assert_eq!(wide.pels_width, 640);
        assert_eq!(wide.panning_width, 0);
        assert_eq!(seen[1].dev_mode, None);
    }

    /// A name longer than a device name's room never reaches the kernel.
    ///
    /// Pins: user32.ChangeDisplaySettingsExA
    #[test]
    fn a_long_name_is_a_bad_parameter() {
        changes();
        let long = [b'A'; 40];
        let mut name = long.to_vec();
        name.push(0);
        // SAFETY: a NUL-terminated name; no DEVMODE.
        let answer =
            unsafe { change_display_settings_ex_a(name.as_ptr(), core::ptr::null(), 0, 0, 0) };
        assert_eq!(answer, DISP_CHANGE_BADPARAM);
        assert!(changes().is_empty());
    }

    /// The wide forms hand everything to the kernel as given.
    ///
    /// Pins: user32.ChangeDisplaySettingsW, user32.ChangeDisplaySettingsExW
    #[test]
    fn the_wide_forms_pass_through() {
        changes();
        let mut mode = DevModeW::zeroed();
        mode.size = size_of::<DevModeW>() as u16;
        mode.fields = DM_BITSPERPEL;
        mode.bits_per_pel = 32;
        assert_eq!(change_display_settings_w(&mode, 0), 0);
        let name: std::vec::Vec<u16> = "\\\\.\\DISPLAY1\0".encode_utf16().collect();
        assert_eq!(
            change_display_settings_ex_w(name.as_ptr(), &mode, 7, CDS_TEST, 9),
            0
        );
        let seen = changes();
        assert_eq!(seen[0].dev_mode, Some(mode));
        assert_eq!(
            (seen[1].window, seen[1].flags, seen[1].param),
            (7, CDS_TEST, 9)
        );
        assert_eq!(seen[1].device.as_deref(), Some(&name[..name.len() - 1]));
    }

    /// EnumDisplaySettingsA: the current mode, converted, into the caller's DEVMODEA, its dmSize
    /// answered as 124 (the guidisp capture's, for MSVC 6's 156-byte DEVMODEA) and nothing past
    /// that written; past the modes FALSE with the last error untouched; the wide form's dmSize
    /// answered as 188 (the capture's, for the 220-byte DEVMODEW), nothing past it written.
    ///
    /// Pins: user32.EnumDisplaySettingsA, user32.EnumDisplaySettingsW
    #[test]
    fn modes_are_described() {
        let mut mode = DevModeA::zeroed();
        mode.size = size_of::<DevModeA>() as u16;
        mode.icm_method = 0x5A5A;
        let current = ENUM_CURRENT_SETTINGS;
        // SAFETY: a DEVMODEA of the tests' own, as long as it says.
        assert_eq!(
            unsafe { enum_display_settings_a(core::ptr::null(), current, &mut mode) },
            1
        );
        assert_eq!(mode.size, 124);
        assert_eq!(mode.size as usize, DISPLAY_FIELDS_END_A);
        assert_eq!(
            (
                mode.pels_width,
                mode.pels_height,
                mode.bits_per_pel,
                mode.fields
            ),
            (640, 480, 32, 0x7E_0020)
        );
        assert_eq!(
            mode.icm_method, 0x5A5A,
            "past the answered dmSize: not written"
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { enum_display_settings_a(core::ptr::null(), 0, &mut mode) },
            1
        );
        assert_eq!((mode.pels_width, mode.fields), (800, 0x7C_0000));
        LAST_ERROR.with(|error| error.set(0xF2F2_F2F2));
        // SAFETY: as above.
        assert_eq!(
            unsafe { enum_display_settings_a(core::ptr::null(), 9999, &mut mode) },
            0
        );
        assert_eq!(LAST_ERROR.with(|error| error.get()), 0xF2F2_F2F2);
        let mut wide = DevModeW::zeroed();
        wide.size = size_of::<DevModeW>() as u16;
        wide.panning_height = 0x5A5A;
        assert_eq!(
            enum_display_settings_w(core::ptr::null(), current, &mut wide),
            1
        );
        assert_eq!((wide.size, wide.pels_width), (188, 640));
        assert_eq!(wide.size as usize, DISPLAY_FIELDS_END_W);
        assert_eq!(wide.panning_height, 0x5A5A, "past the answered dmSize");
    }

    /// EnumDisplayDevicesA: the adapters' names and strings converted; past them FALSE.
    ///
    /// Pins: user32.EnumDisplayDevicesA, user32.EnumDisplayDevicesW
    #[test]
    fn devices_are_listed() {
        let mut device = DisplayDeviceA::zeroed();
        device.cb = size_of::<DisplayDeviceA>() as u32;
        let display = br"\\.\DISPLAY1";
        // SAFETY: a DISPLAY_DEVICEA of the tests' own.
        unsafe {
            assert_eq!(
                enum_display_devices_a(core::ptr::null(), 0, &mut device, 0),
                1
            );
            assert_eq!(&device.device_name[..12], display);
            assert_eq!(device.device_name[12], 0);
            assert_ne!(device.device_string[0], 0);
            assert_eq!(device.cb as usize, size_of::<DisplayDeviceA>());
            assert_eq!(
                enum_display_devices_a(core::ptr::null(), 1, &mut device, 0),
                1
            );
            assert_eq!(
                enum_display_devices_a(core::ptr::null(), 2, &mut device, 0),
                0
            );
        }
        let mut wide = DisplayDeviceW::zeroed();
        wide.cb = size_of::<DisplayDeviceW>() as u32;
        assert_eq!(
            enum_display_devices_w(core::ptr::null(), 0, &mut wide, 0),
            1
        );
        assert_eq!(wide.device_name[4], u16::from(b'D'));
    }

    fn count_monitor(_: u32, _: usize, _: Rect, data: usize) -> u32 {
        // SAFETY: the test's own counter.
        unsafe { *(data as *mut i32) += 1 };
        1
    }

    /// The one monitor: EnumDisplayMonitors calls back once; MonitorFrom* find it where the place
    /// meets the screen, and answer as their flags say elsewhere; GetMonitorInfoA describes it.
    ///
    /// Pins: user32.EnumDisplayMonitors, user32.MonitorFromWindow, user32.MonitorFromPoint,
    /// user32.MonitorFromRect, user32.GetMonitorInfoA
    #[test]
    fn the_one_monitor() {
        use crate::imports::host::{monitor_procedure, DESKTOP_WINDOW, SCREEN};
        let mut count = 0i32;
        let proc = monitor_procedure(count_monitor) as usize;
        let data = &mut count as *mut i32 as usize;
        assert_eq!(enum_display_monitors(0, core::ptr::null(), proc, data), 1);
        assert_eq!(count, 1);
        let monitor = monitor_from_window(DESKTOP_WINDOW as usize, MONITOR_DEFAULTTOPRIMARY);
        assert_eq!(monitor, PRIMARY_MONITOR_HANDLE as usize);
        assert_eq!(monitor_from_point(-10000, -10000, MONITOR_DEFAULTTONULL), 0);
        assert_eq!(
            monitor_from_point(-10000, -10000, MONITOR_DEFAULTTONEAREST),
            monitor
        );
        let rect = Rect {
            left: 0,
            top: 0,
            right: 100,
            bottom: 100,
        };
        // SAFETY: the test's own RECT.
        assert_eq!(
            unsafe { monitor_from_rect(&rect, MONITOR_DEFAULTTONULL) },
            monitor
        );
        assert_eq!(monitor_from_window(0x7FFF_FFFC, MONITOR_DEFAULTTONULL), 0);
        let mut info = MonitorInfoExA {
            cb_size: MONITOR_INFO_SIZE,
            ..MonitorInfoExA::default()
        };
        // SAFETY: the test's own MONITORINFO.
        assert_eq!(unsafe { get_monitor_info_a(monitor, &mut info) }, 1);
        assert_eq!((info.monitor, info.work), (SCREEN, SCREEN));
        assert_eq!(info.flags, MONITORINFOF_PRIMARY);
        assert_eq!(info.device, [0; CCHDEVICENAME], "MONITORINFO has no name");
        info.cb_size = size_of::<MonitorInfoExA>() as u32;
        // SAFETY: as above, the extended form.
        assert_eq!(unsafe { get_monitor_info_a(monitor, &mut info) }, 1);
        assert_eq!(&info.device[..12], br"\\.\DISPLAY1");
        // SAFETY: as above.
        assert_eq!(unsafe { get_monitor_info_a(monitor + 4, &mut info) }, 0);
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_MONITOR_HANDLE
        );
    }

    /// The metrics: the screen's and the work area's from the services, the scheme's constants;
    /// an index outside the served set is the stub routine's 0.
    ///
    /// Pins: user32.GetSystemMetrics, user32.SystemParametersInfoA, user32.SystemParametersInfoW
    #[test]
    fn metrics_and_parameters() {
        assert_eq!(get_system_metrics(0), 640);
        assert_eq!(get_system_metrics(1), 480);
        assert_eq!(get_system_metrics(4), 19);
        assert_eq!(get_system_metrics(32), 4);
        assert_eq!(get_system_metrics(43), 0);
        assert_eq!(get_system_metrics(17), 480 - 19);
        assert_eq!(get_system_metrics(80), 1);
        assert_eq!(get_system_metrics(1000), 0);
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            crate::stub::ERROR_CALL_NOT_IMPLEMENTED
        );
        let mut work = Rect::default();
        let address = &mut work as *mut Rect as usize;
        assert_eq!(system_parameters_info_a(SPI_GETWORKAREA, 0, address, 0), 1);
        assert_eq!(work, crate::imports::host::SCREEN);
        assert_eq!(system_parameters_info_w(SPI_GETWORKAREA, 0, address, 0), 1);
        assert_eq!(system_parameters_info_w(0x1234, 0, address, 0), 0);
    }

    /// The colors: the default scheme, a set color read back, the kernel given the change; an
    /// index past the table changes nothing; the brushes are constants per color.
    ///
    /// Pins: user32.GetSysColor, user32.GetSysColorBrush, user32.SetSysColors
    #[test]
    fn system_colors_round_trip() {
        assert_eq!(get_sys_color(COLOR_DESKTOP as i32), 0xA5_6E3A);
        assert_eq!(get_sys_color(COLOR_BTNTEXT as i32), 0);
        assert_eq!(get_sys_color(99), 0);
        assert_ne!(get_sys_color_brush(COLOR_WINDOW as i32), 0);
        assert_ne!(
            get_sys_color_brush(COLOR_WINDOW as i32),
            get_sys_color_brush(COLOR_DESKTOP as i32)
        );
        assert_eq!(get_sys_color_brush(29), 0);
        let old = get_sys_color(COLOR_WINDOW as i32);
        let (index, color) = (COLOR_WINDOW, 0x0003_0201u32);
        // SAFETY: one-entry arrays of the test's own.
        assert_eq!(unsafe { set_sys_colors(1, &index, &color) }, 1);
        assert_eq!(get_sys_color(COLOR_WINDOW as i32), 0x03_0201);
        let bad = 29u32;
        // SAFETY: as above.
        assert_eq!(unsafe { set_sys_colors(1, &bad, &color) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { set_sys_colors(1, &index, &old) }, 1);
        assert_eq!(get_sys_color(COLOR_WINDOW as i32), old);
        let given = crate::imports::host::wm(|wm| wm.colors.clone());
        assert_eq!(given, [(COLOR_WINDOW, 0x03_0201), (COLOR_WINDOW, old)]);
    }
}
