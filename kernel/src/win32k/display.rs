//! The display services, as far as the VBE framebuffer goes: `NtUserChangeDisplaySettings`, behind
//! user32's ChangeDisplaySettings family, sets the graphics mode through the VBE driver
//! ([`crate::hw::vbe`]), as on Windows 2000, where a display-settings change reaches the video
//! port.
//!
//! NtUserChangeDisplaySettings(ptr DeviceName, ptr DevMode, handle Window, u32 Flags, ptr Param)
//! answers a DISP_CHANGE code, not an NTSTATUS: Windows 2000's service answers
//! ChangeDisplaySettingsEx's own return value, which user32 hands back as it is. Its arguments are
//! ChangeDisplaySettingsExW's: the display's name (NUL-terminated UTF-16; null for the primary
//! display), the DEVMODEW asked for (null for the default mode), the reserved window and parameter
//! (null), and the CDS_ flags.
//!
//! What the minimal subset serves: one display, `\\.\DISPLAY1`; its graphics mode set once (a VBE
//! mode with a linear framebuffer, 32 bpp, 640x480 unless the DEVMODE asks another resolution the
//! BIOS lists; the window manager's work area and desktop windows follow it), after which only
//! requests that mode answers succeed; and the flags 0 (a dynamic change), CDS_FULLSCREEN (the
//! same, here) and CDS_TEST (the mode checked, nothing set). The registry holds no display
//! settings, so CDS_UPDATEREGISTRY and the rest are refused as flags the subset does not take.
//!
//! The other services answer from the same geometry (F2K's argument lists, see [`crate::win32k`];
//! Windows 2000's numbers), each an NTSTATUS:
//!
//! - NtUserEnumDisplaySettings (0x116B): a mode described into a DEVMODEW — the current one (the
//!   mode that was set, or the default 640x480 before it), or one of the VBE driver's listed 32-bpp
//!   modes by its number;
//! - NtUserEnumDisplayDevices (0x1169): the display adapters — the VBE adapter, `\\.\DISPLAY1`, and
//!   the VGA text display the console uses before the graphics mode, `\\.\DISPLAY2`, on no desktop
//!   — or the primary display's monitor, into a DISPLAY_DEVICEW;
//! - NtUserEnumDisplayMonitors (0x116A): the monitors a DC and a clipping rectangle cross, the one
//!   monitor being the whole screen; the handles and rectangles into the caller's arrays, the
//!   callback left to user32 (the kernel calls nothing back in user mode);
//! - NtUserSetSysColors (0x1204): the system colors, Windows 2000's default scheme until set;
//! - NtUserSystemParametersInfo (0x121C): SPI_GETWORKAREA, the primary monitor's work area (the
//!   window manager's, the whole screen: no taskbar takes any of it).

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use rtl::display::*;
use rtl::gdi::Rect;
use rtl::pod::Pod;

use crate::hw::vbe::{self, ModeError, ModeList, ModeRequest};
use crate::nt::call::{Fault, Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// The primary display's name, as EnumDisplayDevices names it.
const PRIMARY_DISPLAY: &str = "\\\\.\\DISPLAY1";

/// NtUserChangeDisplaySettings(DeviceName, DevMode, Window, Flags, Param): see the module notes.
pub fn change_display_settings(
    _call: &mut NtCall,
    device: UserAddr,
    dev_mode: UserAddr,
    window: Handle,
    flags: u32,
    param: UserAddr,
) -> NtResult {
    let code = change(device, dev_mode, window, flags, param).unwrap_or_else(|code| code);
    // The answer is the DISP_CHANGE code itself, in EAX (see the module notes).
    Ok(NtStatus(code as u32))
}

/// The change: DISP_CHANGE_SUCCESSFUL, or the failure's DISP_CHANGE code.
fn change(
    device: UserAddr,
    dev_mode: UserAddr,
    window: Handle,
    flags: u32,
    param: UserAddr,
) -> Result<i32, i32> {
    if window.raw() != 0 || !param.is_null() {
        return Err(DISP_CHANGE_BADPARAM);
    }
    if !device.is_null() && !names_primary_display(device)? {
        return Err(DISP_CHANGE_BADPARAM);
    }
    let mode = if dev_mode.is_null() {
        None
    } else {
        Some(read_dev_mode(dev_mode)?)
    };
    let change = parse(mode.as_ref(), flags)?;
    if change.test {
        return vbe::test_graphics_mode(&change.request)
            .map(|_| DISP_CHANGE_SUCCESSFUL)
            .map_err(disp_change);
    }
    let geometry = vbe::enter_graphics_mode(&change.request).map_err(disp_change)?;
    #[cfg(target_arch = "x86")]
    crate::serial_println!(
        "F2K: vbe: {}x{}x32, LFB at {:#010x}, mapped at {:#010x}",
        geometry.width,
        geometry.height,
        geometry.lfb_phys,
        crate::mem::layout::FRAMEBUFFER.start,
    );
    // The window manager follows the screen: the primary monitor's work area and the desktop
    // windows.
    #[cfg(target_arch = "x86")]
    super::window::locked(|manager| {
        manager.display_changed(geometry.width as i32, geometry.height as i32)
    });
    #[cfg(not(target_arch = "x86"))]
    let _ = geometry;
    Ok(DISP_CHANGE_SUCCESSFUL)
}

/// What a change asks: the mode, and whether only to test it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    request: ModeRequest,
    test: bool,
}

/// The change `mode` (none: the default mode) and `flags` ask for, or the DISP_CHANGE code that
/// refuses it.
fn parse(mode: Option<&DevModeW>, flags: u32) -> Result<Change, i32> {
    if flags & !(CDS_TEST | CDS_FULLSCREEN) != 0 {
        return Err(DISP_CHANGE_BADFLAGS);
    }
    let mut request = ModeRequest::default();
    if let Some(mode) = mode {
        if (mode.size as usize) < DISPLAY_FIELDS_END_W {
            return Err(DISP_CHANGE_BADMODE);
        }
        let asked = |field: u32| mode.fields & field != 0;
        if asked(DM_BITSPERPEL) {
            request.bits_per_pixel = Some(mode.bits_per_pel);
        }
        if asked(DM_PELSWIDTH) {
            request.width = Some(mode.pels_width as usize);
        }
        if asked(DM_PELSHEIGHT) {
            request.height = Some(mode.pels_height as usize);
        }
        // The BIOS's mode set chooses no refresh rate (0 and 1 ask for the hardware's default) and
        // no interlacing.
        if asked(DM_DISPLAYFREQUENCY) && mode.display_frequency > 1 {
            return Err(DISP_CHANGE_BADMODE);
        }
        if asked(DM_DISPLAYFLAGS) && mode.display_flags != 0 {
            return Err(DISP_CHANGE_BADMODE);
        }
    }
    Ok(Change {
        request,
        test: flags & CDS_TEST != 0,
    })
}

/// The DISP_CHANGE code for a mode set's failure.
fn disp_change(error: ModeError) -> i32 {
    match error {
        ModeError::Unsupported => DISP_CHANGE_BADMODE,
        ModeError::Refused | ModeError::Busy => DISP_CHANGE_FAILED,
    }
}

/// The caller's DEVMODEW at `at`: as much of it as its dmSize says it holds (the rest zero), or
/// DISP_CHANGE_BADPARAM for memory the caller cannot read.
fn read_dev_mode(at: UserAddr) -> Result<DevModeW, i32> {
    let size = at
        .offset(DEV_MODE_W_SIZE as u32)
        .cast::<u16>()
        .read()
        .map_err(|_| DISP_CHANGE_BADPARAM)?;
    let mut mode = DevModeW::zeroed();
    let length = (size as usize).min(size_of::<DevModeW>());
    at.read(&mut mode.as_bytes_mut()[..length])
        .map_err(|_| DISP_CHANGE_BADPARAM)?;
    // The bytes read cover dmSize itself only when it is that long; keep the caller's value.
    mode.size = size;
    Ok(mode)
}

/// Whether the NUL-terminated name at `at` is the primary display's, compared without regard to
/// case; DISP_CHANGE_BADPARAM for memory the caller cannot read.
fn names_primary_display(at: UserAddr) -> Result<bool, i32> {
    reads_primary_display(at).map_err(|_| DISP_CHANGE_BADPARAM)
}

/// Whether `units` name the primary display, without regard to case.
pub(super) fn is_primary_display(units: &[u16]) -> bool {
    units.len() == PRIMARY_DISPLAY.len()
        && units
            .iter()
            .zip(PRIMARY_DISPLAY.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

// --- The settings, the devices and the monitors
// ----------------------------------------------------------------

/// dmLogPixels: the display's logical pixels per inch (GetDeviceCaps(LOGPIXELSX)'s 96).
const LOG_PIXELS: u16 = 96;

/// dmDisplayFrequency: the hardware's default refresh rate (the BIOS's mode set chooses none).
const DEFAULT_FREQUENCY: u32 = 1;

/// The resolution of the display's current mode: the mode that was set, or the default mode the
/// work area assumes before one is.
pub fn current_mode() -> (usize, usize) {
    vbe::current_geometry()
        .map(|geometry| (geometry.width, geometry.height))
        .unwrap_or((vbe::DEFAULT_WIDTH, vbe::DEFAULT_HEIGHT))
}

/// The screen's rectangle: the current mode's, from the origin.
pub fn screen_rect() -> Rect {
    let (width, height) = current_mode();
    Rect {
        left: 0,
        top: 0,
        right: width as i32,
        bottom: height as i32,
    }
}

/// A mode as EnumDisplaySettings answers it: its resolution (always 32 bpp) and whether it is the
/// current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Setting {
    width: usize,
    height: usize,
    current: bool,
}

/// The mode the number `number` names: ENUM_CURRENT_SETTINGS and ENUM_REGISTRY_SETTINGS the
/// current one (`current`: the registry keeps no display settings of its own), any other the listed
/// mode of that number (`listed`: none when the display lists none); STATUS_NO_MORE_ENTRIES past
/// the list.
fn setting(
    number: u32,
    current: (usize, usize),
    listed: Option<&ModeList>,
) -> Result<Setting, NtStatus> {
    if number == ENUM_CURRENT_SETTINGS || number == ENUM_REGISTRY_SETTINGS {
        return Ok(Setting {
            width: current.0,
            height: current.1,
            current: true,
        });
    }
    let (width, height) = listed
        .and_then(|list| list.get(number as usize))
        .ok_or(STATUS_NO_MORE_ENTRIES)?;
    Ok(Setting {
        width,
        height,
        current: false,
    })
}

/// The dmSize a mode's description answers, whatever the caller's: the DEVMODEW ending at
/// dmDisplayFrequency, the version Windows 2000 describes display modes in (the guidisp capture
/// shows 188 for a DEVMODEW, and so 124 for a DEVMODEA, where the caller's structures are longer).
/// A caller's DEVMODEW holds at least that much, or the service refuses it.
const DESCRIBED_SIZE: usize = DISPLAY_FIELDS_END_W;

/// The DEVMODEW describing `setting`: the spec version, the described version's dmSize
/// ([`DESCRIBED_SIZE`]), no driver extra; the display fields, 32 bpp at the hardware's default
/// frequency, no display flags; the current mode also with its position on the virtual screen
/// (the origin) and its logical pixels per inch — the dmFields the guidisp capture shows
/// (0x7C0000 for a listed mode, 0x7E0020 for the current one).
fn describe(setting: &Setting) -> DevModeW {
    let mut mode = DevModeW::zeroed();
    mode.spec_version = DM_SPECVERSION;
    mode.size = DESCRIBED_SIZE as u16;
    mode.fields =
        DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY;
    if setting.current {
        mode.fields |= DM_POSITION | DM_LOGPIXELS;
    }
    mode.log_pixels = LOG_PIXELS;
    mode.bits_per_pel = 32;
    mode.pels_width = setting.width as u32;
    mode.pels_height = setting.height as u32;
    mode.display_frequency = DEFAULT_FREQUENCY;
    mode
}

/// NtUserEnumDisplaySettings(DeviceName, ModeNum, DevMode, Flags): EnumDisplaySettingsW's
/// arguments, the mode described into the caller's DEVMODEW (its dmSize covering at least the
/// display fields: STATUS_INVALID_PARAMETER otherwise) as far as the described version goes, its
/// dmSize answered as that version's ([`DESCRIBED_SIZE`]), the caller's bytes past it untouched.
/// The device is the primary display (null names it too); the mode one [`setting`] knows. The modes
/// are the VBE driver's list ([`vbe::display_modes`]); a list being made by another caller at that
/// moment is STATUS_UNSUCCESSFUL (a call that may be tried again). The flags (EDS_RAWMODE) change
/// nothing: every mode listed is one the driver sets.
pub fn enum_display_settings(
    _call: &mut NtCall,
    device: UserAddr,
    number: u32,
    dev_mode: UserAddr,
    _flags: u32,
) -> NtResult {
    if !device.is_null() && !reads_primary_display(device)? {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = dev_mode
        .offset(DEV_MODE_W_SIZE as u32)
        .cast::<u16>()
        .read()?;
    if (size as usize) < DISPLAY_FIELDS_END_W {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let listed = if number == ENUM_CURRENT_SETTINGS || number == ENUM_REGISTRY_SETTINGS {
        None
    } else {
        match vbe::display_modes() {
            Ok(list) => Some(list),
            Err(ModeError::Busy) => return Err(STATUS_UNSUCCESSFUL),
            Err(_) => None,
        }
    };
    let described = describe(&setting(number, current_mode(), listed)?);
    dev_mode.write(&described.as_bytes()[..DESCRIBED_SIZE])?;
    Ok(STATUS_SUCCESS)
}

/// A display device as EnumDisplayDevices answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Device {
    name: &'static str,
    string: &'static str,
    state: u32,
}

/// The display adapters: the VBE adapter, the primary display, on the desktop; and the VGA text
/// display F2K's console draws on before the graphics mode is set, which no desktop is on.
const ADAPTERS: [Device; 2] = [
    Device {
        name: PRIMARY_DISPLAY,
        string: "VBE Display Adapter",
        state: DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
            | DISPLAY_DEVICE_PRIMARY_DEVICE
            | DISPLAY_DEVICE_VGA_COMPATIBLE,
    },
    Device {
        name: "\\\\.\\DISPLAY2",
        string: "VGA Text Display",
        state: DISPLAY_DEVICE_VGA_COMPATIBLE,
    },
];

/// The primary display's monitors: the one it drives.
const MONITORS: [Device; 1] = [Device {
    name: "\\\\.\\DISPLAY1\\Monitor0",
    string: "Default Monitor",
    state: DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_ATTACHED,
}];

/// The devices EnumDisplayDevices numbers under `parent`: the adapters for none, an adapter's
/// monitors for the adapter's name; none for another name.
fn devices(parent: Option<&[u16]>) -> Option<&'static [Device]> {
    match parent {
        None => Some(&ADAPTERS),
        Some(name) if is_primary_display(name) => Some(&MONITORS),
        Some(_) => None,
    }
}

/// NtUserEnumDisplayDevices(DeviceName, DevNum, DisplayDevice, Flags): EnumDisplayDevicesW's
/// arguments: the device numbered `number` among the adapters (a null name) or among the named
/// adapter's monitors, into the caller's DISPLAY_DEVICEW as far as its cb goes (at least to
/// StateFlags: STATUS_INVALID_PARAMETER otherwise), its cb kept. A name naming no adapter is
/// STATUS_INVALID_PARAMETER, a number past the devices STATUS_NO_MORE_ENTRIES. The device
/// interface and registry key strings are empty: no device has either. The flags change nothing
/// (Windows 2000 defines none).
pub fn enum_display_devices(
    _call: &mut NtCall,
    parent: UserAddr,
    number: u32,
    out: UserAddr,
    _flags: u32,
) -> NtResult {
    let mut units = [0u16; CCHDEVICENAME];
    let parent = if parent.is_null() {
        None
    } else {
        Some(read_device_name(parent, &mut units)?)
    };
    let list = devices(parent).ok_or(STATUS_INVALID_PARAMETER)?;
    let cb = out.cast::<u32>().read()? as usize;
    if cb < DISPLAY_DEVICE_STATE_END_W {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let device = list.get(number as usize).ok_or(STATUS_NO_MORE_ENTRIES)?;
    let field = |offset: usize| out.offset(offset as u32);
    write_text(
        field(offset_of!(DisplayDeviceW, device_name)),
        CCHDEVICENAME,
        device.name,
    )?;
    write_text(
        field(offset_of!(DisplayDeviceW, device_string)),
        DEVICE_STRING_CHARS,
        device.string,
    )?;
    field(offset_of!(DisplayDeviceW, state_flags))
        .cast::<u32>()
        .write(device.state)?;
    for (offset, end) in [
        (
            offset_of!(DisplayDeviceW, device_id),
            offset_of!(DisplayDeviceW, device_key),
        ),
        (
            offset_of!(DisplayDeviceW, device_key),
            size_of::<DisplayDeviceW>(),
        ),
    ] {
        if cb >= end {
            write_text(field(offset), DEVICE_STRING_CHARS, "")?;
        }
    }
    Ok(STATUS_SUCCESS)
}

/// Write `text` (ASCII) at `at` as a NUL-padded UTF-16 field of `room` characters.
fn write_text(at: UserAddr, room: usize, text: &str) -> Result<(), Fault> {
    let mut units = [0u16; DEVICE_STRING_CHARS];
    for (unit, byte) in units[..room - 1].iter_mut().zip(text.bytes()) {
        *unit = byte as u16;
    }
    at.write(&units.as_bytes()[..2 * room])
}

/// The NUL-terminated device name at `at`, into `units` (a name longer than a device name's room
/// names no device, and reads as empty).
fn read_device_name(at: UserAddr, units: &mut [u16; CCHDEVICENAME]) -> Result<&[u16], Fault> {
    for index in 0..CCHDEVICENAME {
        units[index] = at.offset(2 * index as u32).cast::<u16>().read()?;
        if units[index] == 0 {
            return Ok(&units[..index]);
        }
    }
    Ok(&units[..0])
}

/// Whether the NUL-terminated name at `at` is the primary display's.
fn reads_primary_display(at: UserAddr) -> Result<bool, Fault> {
    let mut units = [0u16; CCHDEVICENAME];
    Ok(is_primary_display(read_device_name(at, &mut units)?))
}

/// The monitors EnumDisplayMonitors visits for the clipping rectangle `clip` (none: everywhere),
/// into `out`: each monitor's handle and the part of its rectangle inside the clip, skipping a
/// monitor the clip misses. The answer is how many there are, `out` holding the first of them.
/// The one monitor is the primary, the whole screen (`screen`).
fn monitors_in(clip: Option<Rect>, screen: Rect, out: &mut [(u32, Rect)]) -> usize {
    let mut found = 0;
    for (index, bounds) in [screen].into_iter().enumerate() {
        let part = match clip {
            None => bounds,
            Some(clip) => Rect {
                left: bounds.left.max(clip.left),
                top: bounds.top.max(clip.top),
                right: bounds.right.min(clip.right),
                bottom: bounds.bottom.min(clip.bottom),
            },
        };
        if part.left >= part.right || part.top >= part.bottom {
            continue;
        }
        if let Some(slot) = out.get_mut(found) {
            *slot = (PRIMARY_MONITOR_HANDLE + index as u32, part);
        }
        found += 1;
    }
    found
}

/// How many monitors the display has.
const MONITOR_COUNT: usize = 1;

/// NtUserEnumDisplayMonitors(Dc, Clip, Monitors, Rects, Count, Found): EnumDisplayMonitors'
/// selection, its callback left to user32 (the kernel calls nothing back in user mode): the
/// monitors the DC's area and the clipping rectangle (each optional; a screen DC's coordinates
/// are the screen's) cross, at most `count` of them, their handles into `monitors` and their
/// rectangles inside the clip into `rects`; how many there are into `found`. A DC handle naming no
/// DC is STATUS_INVALID_HANDLE.
#[allow(clippy::too_many_arguments)]
pub fn enum_display_monitors(
    call: &mut NtCall,
    dc: Handle,
    clip: UserAddr,
    monitors: UserAddr,
    rects: UserAddr,
    count: u32,
    found: UserPtr<u32>,
) -> NtResult {
    if dc.raw() != 0 && !names_dc(call, dc) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let clip = if clip.is_null() {
        None
    } else {
        Some(clip.cast::<Rect>().read()?)
    };
    let mut visited = [(0, Rect::default()); MONITOR_COUNT];
    let total = monitors_in(clip, screen_rect(), &mut visited);
    for (index, (monitor, rect)) in visited.iter().take(total.min(count as usize)).enumerate() {
        monitors
            .offset(4 * index as u32)
            .cast::<u32>()
            .write(*monitor)?;
        rects
            .offset((size_of::<Rect>() * index) as u32)
            .cast::<Rect>()
            .write(*rect)?;
    }
    found.write(total as u32)?;
    Ok(STATUS_SUCCESS)
}

/// The system colors, by index (Windows 2000 keeps them for every desktop at once): its default
/// scheme's until SetSysColors changes them.
static SYSTEM_COLOR_TABLE: [AtomicU32; SYSTEM_COLORS] = {
    let mut colors = [const { AtomicU32::new(0) }; SYSTEM_COLORS];
    let mut index = 0;
    while index < SYSTEM_COLORS {
        colors[index] = AtomicU32::new(DEFAULT_SYSTEM_COLORS[index]);
        index += 1;
    }
    colors
};

/// The system color `index` (GetSysColor's answer); none past the table.
pub fn sys_color(index: u32) -> Option<u32> {
    SYSTEM_COLOR_TABLE
        .get(index as usize)
        .map(|color| color.load(Ordering::Relaxed))
}

/// Set the system color `index` (one [`sys_color`] has) to `color`'s RGB.
fn set_sys_color(index: u32, color: u32) {
    SYSTEM_COLOR_TABLE[index as usize].store(color & rtl::gdi::RGB_MASK, Ordering::Relaxed);
}

/// The entries SetSysColors reads from the caller at a time.
const COLOR_CHUNK: usize = 64;

/// NtUserSetSysColors(Count, Indexes, Colors, Flags): SetSysColors' arguments, `count` system
/// color indexes and as many COLORREFs. Every index is read and checked before any color changes:
/// an index past the table is STATUS_INVALID_PARAMETER, nothing changed. The flags change nothing
/// (the notification that would follow, WM_SYSCOLORCHANGE to every top-level window, comes with
/// the message queue).
pub fn set_sys_colors(
    _call: &mut NtCall,
    count: u32,
    indexes: UserAddr,
    colors: UserAddr,
    _flags: u32,
) -> NtResult {
    let mut index_chunk = [0u32; COLOR_CHUNK];
    let mut color_chunk = [0u32; COLOR_CHUNK];
    let chunks = || (0..count as usize).step_by(COLOR_CHUNK);
    for first in chunks() {
        let length = COLOR_CHUNK.min(count as usize - first);
        indexes
            .offset(4 * first as u32)
            .read(&mut index_chunk.as_bytes_mut()[..4 * length])?;
        if index_chunk[..length]
            .iter()
            .any(|&index| sys_color(index).is_none())
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    for first in chunks() {
        let length = COLOR_CHUNK.min(count as usize - first);
        indexes
            .offset(4 * first as u32)
            .read(&mut index_chunk.as_bytes_mut()[..4 * length])?;
        colors
            .offset(4 * first as u32)
            .read(&mut color_chunk.as_bytes_mut()[..4 * length])?;
        for (&index, &color) in index_chunk[..length].iter().zip(&color_chunk[..length]) {
            // Checked above; the caller may have changed its array since.
            if sys_color(index).is_some() {
                set_sys_color(index, color);
            }
        }
    }
    Ok(STATUS_SUCCESS)
}

/// NtUserSystemParametersInfo(Action, UiParam, Param, WinIni): SystemParametersInfoW's
/// arguments. SPI_GETWORKAREA answers the primary monitor's work area into `param`, a RECT; any
/// other action is STATUS_INVALID_PARAMETER, as no other is served yet.
pub fn system_parameters_info(
    call: &mut NtCall,
    action: u32,
    _ui_param: u32,
    param: UserAddr,
    _win_ini: u32,
) -> NtResult {
    match action {
        SPI_GETWORKAREA => {
            let area = work_area(call);
            param.cast::<Rect>().write(area)?;
            Ok(STATUS_SUCCESS)
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// The primary monitor's work area, read under the window manager's lock (the caller's memory is
/// written after it).
#[cfg(target_arch = "x86")]
fn work_area(call: &mut NtCall) -> Rect {
    let area = super::window::lock(call.passive())
        .windows
        .work_area(super::window::PRIMARY_MONITOR);
    Rect {
        left: area.left,
        top: area.top,
        right: area.right,
        bottom: area.bottom,
    }
}

/// Whether the calling process's `handle` names a DC.
#[cfg(target_arch = "x86")]
fn names_dc(call: &mut NtCall, handle: Handle) -> bool {
    call.process()
        .lookup_handle(handle.raw())
        .and_then(|entry| entry.object_id())
        .is_some_and(|id| id.kind == crate::ob::ObjectType::Dc)
}

// The host builds have no window manager behind a lock and no processes: the work area is the
// screen's, and no handle names a DC (the host tests drive the decisions themselves).

#[cfg(not(target_arch = "x86"))]
fn work_area(_: &mut NtCall) -> Rect {
    screen_rect()
}

#[cfg(not(target_arch = "x86"))]
fn names_dc(_: &mut NtCall, _: Handle) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_mode(fields: u32, bits: u32, width: u32, height: u32) -> DevModeW {
        let mut mode = DevModeW::zeroed();
        mode.size = size_of::<DevModeW>() as u16;
        mode.fields = fields;
        mode.bits_per_pel = bits;
        mode.pels_width = width;
        mode.pels_height = height;
        mode
    }

    /// The fields dmFields marks become the request; the others stay open.
    #[test]
    fn the_dev_mode_is_the_request() {
        let all = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;
        let change = parse(Some(&dev_mode(all, 32, 640, 480)), 0).unwrap();
        assert_eq!(
            change,
            Change {
                request: ModeRequest {
                    width: Some(640),
                    height: Some(480),
                    bits_per_pixel: Some(32),
                },
                test: false,
            }
        );
        let change = parse(Some(&dev_mode(DM_PELSWIDTH, 16, 800, 600)), CDS_TEST).unwrap();
        assert_eq!(change.request.width, Some(800));
        assert_eq!(change.request.height, None);
        assert_eq!(change.request.bits_per_pixel, None);
        assert!(change.test);
        assert_eq!(
            parse(None, CDS_FULLSCREEN).unwrap().request,
            ModeRequest::default()
        );
    }

    /// Flags the subset does not take, a DEVMODE too short for the display fields, a refresh rate
    /// or interlacing are refused with their codes.
    #[test]
    fn what_the_subset_refuses() {
        assert_eq!(parse(None, CDS_UPDATEREGISTRY), Err(DISP_CHANGE_BADFLAGS));
        assert_eq!(parse(None, 0x8000_0000), Err(DISP_CHANGE_BADFLAGS));
        let mut short = dev_mode(0, 0, 0, 0);
        short.size = (DISPLAY_FIELDS_END_W - 4) as u16;
        assert_eq!(parse(Some(&short), 0), Err(DISP_CHANGE_BADMODE));
        let mut rate = dev_mode(DM_DISPLAYFREQUENCY, 0, 0, 0);
        rate.display_frequency = 60;
        assert_eq!(parse(Some(&rate), 0), Err(DISP_CHANGE_BADMODE));
        rate.display_frequency = 1;
        assert!(parse(Some(&rate), 0).is_ok(), "the hardware's default rate");
        let mut flags = dev_mode(DM_DISPLAYFLAGS, 0, 0, 0);
        flags.display_flags = 2; // DM_INTERLACED
        assert_eq!(parse(Some(&flags), 0), Err(DISP_CHANGE_BADMODE));
        assert_eq!(disp_change(ModeError::Unsupported), DISP_CHANGE_BADMODE);
        assert_eq!(disp_change(ModeError::Refused), DISP_CHANGE_FAILED);
        assert_eq!(disp_change(ModeError::Busy), DISP_CHANGE_FAILED);
    }

    /// The primary display's name, in any case; nothing else.
    #[test]
    fn the_primary_display_is_display1() {
        let units = |text: &str| text.encode_utf16().collect::<std::vec::Vec<_>>();
        assert!(is_primary_display(&units("\\\\.\\DISPLAY1")));
        assert!(is_primary_display(&units("\\\\.\\display1")));
        assert!(!is_primary_display(&units("\\\\.\\DISPLAY2")));
        assert!(!is_primary_display(&units("DISPLAY1")));
        assert!(!is_primary_display(&units("")));
    }

    /// The caller's memory: a page at 0x1000, anything else faults.
    struct Page(std::vec::Vec<u8>);

    impl crate::user::syscall::host::UserMemory for Page {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let at = (pointer as usize)
                .checked_sub(0x1000)
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            let source = self
                .0
                .get(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            bytes.copy_from_slice(source);
            Ok(())
        }

        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            let at = (pointer as usize)
                .checked_sub(0x1000)
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            let target = self
                .0
                .get_mut(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            target.copy_from_slice(bytes);
            Ok(())
        }
    }

    type Shared = std::rc::Rc<core::cell::RefCell<Page>>;

    /// A page of the caller's memory, installed, filled with 0xCC.
    fn page() -> (Shared, crate::user::syscall::host::Installed) {
        let page = std::rc::Rc::new(core::cell::RefCell::new(Page(std::vec![0xCC; 0x1000])));
        let installed = crate::user::syscall::host::install(page.clone());
        (page, installed)
    }

    /// Run `f` with a call of the tests' own.
    fn with_call<R>(f: impl FnOnce(&mut NtCall) -> R) -> R {
        let mut frame = crate::user::TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        f(&mut NtCall::new(&mut frame, &mut passive))
    }

    fn utf16(text: &str) -> std::vec::Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// The modes' numbers: the current and registry settings are the current mode, any other the
    /// listed mode of its number; past the list, or with no list, STATUS_NO_MORE_ENTRIES.
    #[test]
    fn the_mode_numbers() {
        let current = |width, height| Setting {
            width,
            height,
            current: true,
        };
        assert_eq!(
            setting(ENUM_CURRENT_SETTINGS, (1024, 768), None),
            Ok(current(1024, 768))
        );
        assert_eq!(
            setting(ENUM_REGISTRY_SETTINGS, (1024, 768), None),
            Ok(current(1024, 768))
        );
        assert_eq!(setting(0, (640, 480), None), Err(STATUS_NO_MORE_ENTRIES));
        assert_eq!(setting(9999, (640, 480), None), Err(STATUS_NO_MORE_ENTRIES));
    }

    /// A mode's description: dmFields as the guidisp capture shows them (0x7E0020 for the current
    /// mode, 0x7C0000 for a listed one), 32 bpp, the resolution, dmSize 188 (the capture's), the
    /// spec version, 96 logical pixels per inch.
    #[test]
    fn the_descriptions_are_the_captures() {
        let mode = describe(&Setting {
            width: 1024,
            height: 768,
            current: true,
        });
        assert_eq!(mode.fields, 0x7E_0020);
        assert_eq!(mode.size, 188);
        assert_eq!(mode.driver_extra, 0);
        assert_eq!(mode.spec_version, 0x0401);
        assert_eq!(
            (mode.pels_width, mode.pels_height, mode.bits_per_pel),
            (1024, 768, 32)
        );
        assert_eq!(mode.log_pixels, 96);
        assert_eq!(mode.display_flags, 0);
        assert!(mode.display_frequency <= 1, "the hardware's default");
        let listed = describe(&Setting {
            width: 800,
            height: 600,
            current: false,
        });
        assert_eq!((listed.fields, listed.size), (0x7C_0000, 188));
        // ChangeDisplaySettings takes the current mode's description back as it is.
        assert!(parse(Some(&mode), 0).is_ok());
    }

    /// The service: the description written as far as its own version goes (188 bytes), its
    /// dmSize that version's whatever the caller's (the guidisp capture's 188 for MSVC 6's 220-byte
    /// DEVMODEW), the caller's bytes past it untouched; the display named by its name or by none; a
    /// DEVMODE too short for the display fields, or another display's name,
    /// STATUS_INVALID_PARAMETER; a number past the list STATUS_NO_MORE_ENTRIES.
    #[test]
    fn the_settings_service_answers_its_own_dm_size() {
        let (page, _installed) = page();
        let dev_mode = UserAddr(0x1100);
        let set_size = |size: u16| {
            dev_mode
                .offset(DEV_MODE_W_SIZE as u32)
                .cast::<u16>()
                .write(size)
                .unwrap()
        };
        for size in [220, 188] {
            set_size(size);
            assert_eq!(
                with_call(|call| enum_display_settings(
                    call,
                    UserAddr(0),
                    ENUM_CURRENT_SETTINGS,
                    dev_mode,
                    0
                )),
                Ok(STATUS_SUCCESS)
            );
            let mode = DevModeW::from_bytes(&page.borrow().0[0x100..0x100 + 220]).unwrap();
            assert_eq!(mode.size, 188, "a caller's dmSize of {size}");
            assert_eq!(
                (mode.pels_width, mode.pels_height),
                (640, 480),
                "the default mode"
            );
            assert_eq!(mode.fields, 0x7E_0020);
            assert!(
                page.borrow().0[0x100 + 188..0x100 + 220]
                    .iter()
                    .all(|&byte| byte == 0xCC),
                "nothing past the described version"
            );
        }

        // The display by its name.
        page.borrow_mut().0[0x800..0x800 + 26].copy_from_slice(&utf16("\\\\.\\DISPLAY1"));
        assert_eq!(
            with_call(|call| enum_display_settings(
                call,
                UserAddr(0x1800),
                ENUM_CURRENT_SETTINGS,
                dev_mode,
                0
            )),
            Ok(STATUS_SUCCESS)
        );
        page.borrow_mut().0[0x800..0x800 + 26].copy_from_slice(&utf16("\\\\.\\DISPLAY2"));
        assert_eq!(
            with_call(|call| enum_display_settings(
                call,
                UserAddr(0x1800),
                ENUM_CURRENT_SETTINGS,
                dev_mode,
                0
            )),
            Err(STATUS_INVALID_PARAMETER)
        );
        set_size((DISPLAY_FIELDS_END_W - 4) as u16);
        assert_eq!(
            with_call(|call| enum_display_settings(
                call,
                UserAddr(0),
                ENUM_CURRENT_SETTINGS,
                dev_mode,
                0
            )),
            Err(STATUS_INVALID_PARAMETER)
        );
        set_size(220);
        assert_eq!(
            with_call(|call| enum_display_settings(call, UserAddr(0), 9999, dev_mode, 0)),
            Err(STATUS_NO_MORE_ENTRIES)
        );
    }

    /// The devices: two adapters, the primary first (\\.\DISPLAY1, on the desktop, its string
    /// nonempty), and the primary display's one monitor; DISPLAY_DEVICEW written as far as its cb
    /// goes, cb kept; a cb short of StateFlags, or a name naming no adapter,
    /// STATUS_INVALID_PARAMETER; a number past the devices STATUS_NO_MORE_ENTRIES.
    #[test]
    fn the_devices() {
        let (page, _installed) = page();
        let out = UserAddr(0x1000);
        let set_cb = |cb: u32| out.cast::<u32>().write(cb).unwrap();
        set_cb(840);
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0), 0, out, 0)),
            Ok(STATUS_SUCCESS)
        );
        {
            let bytes = &page.borrow().0;
            let device = DisplayDeviceW::from_bytes(&bytes[..840]).unwrap();
            assert_eq!(device.cb, 840);
            assert_eq!(
                &device.device_name.as_bytes()[..26],
                &utf16("\\\\.\\DISPLAY1")[..]
            );
            assert_ne!(device.device_string[0], 0);
            assert_eq!(
                device.state_flags
                    & (DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE),
                DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE
            );
            assert_eq!(device.device_id, [0; DEVICE_STRING_CHARS]);
            assert_eq!(device.device_key, [0; DEVICE_STRING_CHARS]);
            assert_eq!(bytes[840], 0xCC);
        }
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0), 1, out, 0)),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0), 2, out, 0)),
            Err(STATUS_NO_MORE_ENTRIES)
        );

        // The older structure ends at StateFlags: nothing past it is written.
        page.borrow_mut().0.fill(0xCC);
        set_cb(DISPLAY_DEVICE_STATE_END_W as u32);
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0), 0, out, 0)),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(page.borrow().0[DISPLAY_DEVICE_STATE_END_W], 0xCC);
        set_cb(DISPLAY_DEVICE_STATE_END_W as u32 - 1);
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0), 0, out, 0)),
            Err(STATUS_INVALID_PARAMETER)
        );

        // The primary display's monitors.
        set_cb(840);
        page.borrow_mut().0[0x800..0x800 + 26].copy_from_slice(&utf16("\\\\.\\display1"));
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0x1800), 0, out, 0)),
            Ok(STATUS_SUCCESS)
        );
        let device = DisplayDeviceW::from_bytes(&page.borrow().0[..840]).unwrap();
        assert_eq!(
            &device.device_name.as_bytes()[..44],
            &utf16("\\\\.\\DISPLAY1\\Monitor0")[..]
        );
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0x1800), 1, out, 0)),
            Err(STATUS_NO_MORE_ENTRIES)
        );
        page.borrow_mut().0[0x800..0x800 + 26].copy_from_slice(&utf16("\\\\.\\DISPLAY9"));
        assert_eq!(
            with_call(|call| enum_display_devices(call, UserAddr(0x1800), 0, out, 0)),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// The monitors: the one, the whole screen, cut by the clip; a clip that misses it visits none.
    #[test]
    fn the_monitors_are_the_screen() {
        let screen = Rect {
            left: 0,
            top: 0,
            right: 1024,
            bottom: 768,
        };
        let mut out = [(0, Rect::default()); 2];
        assert_eq!(monitors_in(None, screen, &mut out), 1);
        assert_eq!(out[0], (PRIMARY_MONITOR_HANDLE, screen));
        let clip = Rect {
            left: -50,
            top: 10,
            right: 100,
            bottom: 100,
        };
        assert_eq!(monitors_in(Some(clip), screen, &mut out), 1);
        assert_eq!(
            out[0].1,
            Rect {
                left: 0,
                top: 10,
                right: 100,
                bottom: 100
            }
        );
        let far = Rect {
            left: -10000,
            top: -10000,
            right: -9999,
            bottom: -9999,
        };
        assert_eq!(monitors_in(Some(far), screen, &mut out), 0);
        assert_eq!(
            monitors_in(None, screen, &mut []),
            1,
            "counted, not written"
        );

        // The service: the handle and the rectangle into the arrays, the count through the last
        // pointer; a DC handle naming no DC is refused.
        let (page, _installed) = page();
        let found = UserPtr::<u32>::at(0x1000);
        assert_eq!(
            with_call(|call| enum_display_monitors(
                call,
                Handle(0),
                UserAddr(0),
                UserAddr(0x1100),
                UserAddr(0x1200),
                4,
                found
            )),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(found.read(), Ok(1));
        assert_eq!(
            UserPtr::<u32>::at(0x1100).read(),
            Ok(PRIMARY_MONITOR_HANDLE)
        );
        assert_eq!(UserPtr::<Rect>::at(0x1200).read(), Ok(screen_rect()));
        assert_eq!(page.borrow().0[0x104], 0xCC, "one monitor");
        assert_eq!(
            with_call(|call| enum_display_monitors(
                call,
                Handle(0x44),
                UserAddr(0),
                UserAddr(0x1100),
                UserAddr(0x1200),
                4,
                found
            )),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    /// The system colors: Windows 2000's default scheme (the guidisp capture's COLOR_WINDOW,
    /// COLOR_DESKTOP and COLOR_BTNTEXT); SetSysColors' round trip; an index past the table refuses
    /// the whole call, nothing changed.
    #[test]
    fn the_system_colors() {
        assert_eq!(sys_color(COLOR_WINDOW), Some(0xFF_FFFF));
        assert_eq!(sys_color(COLOR_DESKTOP), Some(0xA5_6E3A));
        assert_eq!(sys_color(COLOR_BTNTEXT), Some(0));
        assert_eq!(sys_color(SYSTEM_COLORS as u32), None);

        let (_page, _installed) = page();
        let indexes = UserAddr(0x1000);
        let colors = UserAddr(0x1800);
        let set = |index: u32, color: u32| {
            indexes.cast::<u32>().write(index).unwrap();
            colors.cast::<u32>().write(color).unwrap();
            with_call(|call| set_sys_colors(call, 1, indexes, colors, 0))
        };
        // COLOR_BTNTEXT, which no other test reads, round-trips.
        assert_eq!(set(COLOR_BTNTEXT, 0x0003_0201), Ok(STATUS_SUCCESS));
        assert_eq!(sys_color(COLOR_BTNTEXT), Some(0x03_0201));
        assert_eq!(set(COLOR_BTNTEXT, 0x0100_0000), Ok(STATUS_SUCCESS));
        assert_eq!(sys_color(COLOR_BTNTEXT), Some(0), "the RGB alone");
        // Two entries, the second past the table: neither applies.
        indexes.offset(4).cast::<u32>().write(99).unwrap();
        colors.offset(4).cast::<u32>().write(0x00AB_CDEF).unwrap();
        indexes.cast::<u32>().write(COLOR_BTNTEXT).unwrap();
        colors.cast::<u32>().write(0x00FF_0000).unwrap();
        assert_eq!(
            with_call(|call| set_sys_colors(call, 2, indexes, colors, 0)),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(sys_color(COLOR_BTNTEXT), Some(0));
        assert_eq!(
            with_call(|call| set_sys_colors(call, 0, indexes, colors, 0)),
            Ok(STATUS_SUCCESS)
        );
    }

    /// SystemParametersInfo: SPI_GETWORKAREA's RECT (the host's work area: the default screen);
    /// another action STATUS_INVALID_PARAMETER.
    #[test]
    fn the_work_area() {
        let (_page, _installed) = page();
        let rect = UserAddr(0x1000);
        assert_eq!(
            with_call(|call| system_parameters_info(call, SPI_GETWORKAREA, 0, rect, 0)),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            rect.cast::<Rect>().read(),
            Ok(Rect {
                left: 0,
                top: 0,
                right: 640,
                bottom: 480
            })
        );
        assert_eq!(
            with_call(|call| system_parameters_info(call, 0x0029, 0, rect, 0)),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
