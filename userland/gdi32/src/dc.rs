//! The screen DC: CreateDC of the display, DeleteDC and GetDeviceCaps, the objects (GetStockObject,
//! SelectObject, DeleteObject), the text and background colors and the background mode, and single
//! pixels, each over its win32k service ([`imports`]: gdi32's own stubs, as Windows 2000's gdi32
//! enters the kernel itself), the screen's size over user32's GetSystemMetrics. What the kernel
//! serves is in its DC services' notes (kernel/src/win32k/dc.rs): the screen's and the windows'
//! DCs, stock objects as constant handles, brushes ([`crate::brush`]), one font.

use rtl::edge::{InStr, InWStr};
use rtl::gdi::*;

use crate::imports::{self, Caller, Selected};
use crate::{answered, failed, stub, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};

/// The display driver's name, as CreateDC takes it (without regard to case).
const DISPLAY: &str = "DISPLAY";

/// The longest driver or device name CreateDCA converts, its terminator included (MAX_PATH).
const MAX_NAME: usize = 260;

/// Whether `units` spell `text` (ASCII), without regard to case.
fn names(units: &[u16], text: &str) -> bool {
    units.len() == text.len()
        && units
            .iter()
            .zip(text.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// CreateDCW: a DC of the display: the DISPLAY driver (its device the one named, or the primary
/// display), or no driver and a display's device name (`\\.\DISPLAY1`); NULL with the last error
/// for a display the kernel does not know. Another driver's DC (a printer's) goes to the stub
/// routine.
///
/// # Safety
///
/// The caller's names (NUL-terminated strings, or null), as for the platform's.
#[unsafe(export_name = "f2k_export_CreateDCW")]
pub unsafe extern "system" fn create_dc_w(
    driver: *const u16,
    device: *const u16,
    output: *const u16,
    init: usize,
) -> usize {
    // SAFETY: the caller's strings, or null.
    let (driver_name, device_name) =
        unsafe { (InWStr::optional(driver), InWStr::optional(device)) };
    let display = match driver_name {
        Some(name) => {
            let mut units = [0u16; DISPLAY.len()];
            name.len() == DISPLAY.len() && {
                name.units().copy_to(&mut units);
                names(&units, DISPLAY)
            }
        }
        None => device_name.is_some(),
    };
    if !display {
        let args = [driver as u64, device as u64, output as u64, init as u64];
        // SAFETY: the arguments as CreateDCW's kinds read them.
        return unsafe {
            stub::stubbed(
                &crate::spec::CreateDCW,
                "printer DCs not yet implemented",
                &args,
            )
        } as usize;
    }
    // The device's name, handed to the kernel unread (it reads it to its terminator).
    answered(imports::open_dc(Caller(device as usize))).map_or(0, |dc| dc as usize)
}

/// CreateDCA: the driver's and the device's names converted to their wide forms, then CreateDCW's
/// DC. A name longer than MAX_PATH is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// The caller's names (NUL-terminated strings, or null), as for the platform's.
#[unsafe(export_name = "f2k_export_CreateDCA")]
pub unsafe extern "system" fn create_dc_a(
    driver: *const u8,
    device: *const u8,
    _output: *const u8,
    init: usize,
) -> usize {
    // SAFETY: the caller's strings, or null.
    let (driver, device) = unsafe { (InStr::optional(driver), InStr::optional(device)) };
    let mut driver_units = [0u16; MAX_NAME];
    let mut device_units = [0u16; MAX_NAME];
    let Some(driver) = widen(driver, &mut driver_units) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let Some(device) = widen(device, &mut device_units) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    // SAFETY: the converted names, NUL-terminated, live until the call returns.
    unsafe {
        create_dc_w(
            driver.map_or(core::ptr::null(), <[u16]>::as_ptr),
            device.map_or(core::ptr::null(), <[u16]>::as_ptr),
            core::ptr::null(),
            init,
        )
    }
}

/// The wide form of an optional narrow name, NUL-terminated, in `units`: `Some(None)` for no name,
/// none for a name longer than the room.
fn widen<'a>(name: Option<InStr>, units: &'a mut [u16; MAX_NAME]) -> Option<Option<&'a [u16]>> {
    let Some(name) = name else {
        return Some(None);
    };
    let bytes = name.bytes_within(MAX_NAME - 1)?;
    let length = imports::multi_byte_to_unicode(&mut units[..MAX_NAME - 1], bytes);
    units[length] = 0;
    Some(Some(&units[..=length]))
}

/// DeleteDC: the DC deleted (its handle closed); FALSE with ERROR_INVALID_HANDLE for a stock
/// object's handle, with the service's error for a handle that names no DC.
#[unsafe(export_name = "f2k_export_DeleteDC")]
pub extern "system" fn delete_dc(dc: usize) -> u32 {
    if stock_object(dc as u32).is_some() {
        return failed(ERROR_INVALID_HANDLE).unwrap_or(0);
    }
    answered(imports::delete_object(dc)).map_or(0, |()| 1)
}

/// DeleteObject: the object deleted, a DC or a brush (a global object, a stock one or a global
/// brush, is never deleted: TRUE all the same).
#[unsafe(export_name = "f2k_export_DeleteObject")]
pub extern "system" fn delete_object(object: usize) -> u32 {
    answered(imports::delete_object(object)).map_or(0, |()| 1)
}

/// GetStockObject: the stock object's handle; NULL with the last error for an index that names
/// none.
#[unsafe(export_name = "f2k_export_GetStockObject")]
pub extern "system" fn get_stock_object(index: i32) -> usize {
    answered(imports::stock_object(index as u32)).map_or(0, |object| object as usize)
}

/// SelectObject: the brush, pen or font `object` is selected into the DC, the object of its kind
/// it replaces answered; the kind is the handle's own (a stock object's, a global brush's, or a
/// process's object's kind bits: rtl::gdi's `object_kind`), as Windows 2000's gdi32 reads it from
/// the handle. NULL with ERROR_INVALID_HANDLE for a handle of no kind a DC selects (a palette's is
/// SelectPalette's, a DC's none), with the service's error for a DC or an object that is none.
#[unsafe(export_name = "f2k_export_SelectObject")]
pub extern "system" fn select_object(dc: usize, object: usize) -> usize {
    let kind = match object_kind(object as u32) {
        Some(OBJ_BRUSH) => Selected::Brush,
        Some(OBJ_PEN) => Selected::Pen,
        Some(OBJ_FONT) => Selected::Font,
        _ => return failed(ERROR_INVALID_HANDLE).unwrap_or(0),
    };
    answered(imports::select(kind, dc, object)).map_or(0, |previous| previous as usize)
}

/// The DC's attribute `index`, or `failure` with the last error.
fn attribute(dc: usize, index: u32, failure: u32) -> u32 {
    answered(imports::dc_dword(dc, index)).unwrap_or(failure)
}

/// The DC's attribute `index` set to `value`: the value it had, or `failure` with the last error.
fn set_attribute(dc: usize, index: u32, value: u32, failure: u32) -> u32 {
    answered(imports::set_dc_dword(dc, index, value)).unwrap_or(failure)
}

/// GetTextColor: the DC's text color; CLR_INVALID with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetTextColor")]
pub extern "system" fn get_text_color(dc: usize) -> u32 {
    attribute(dc, DC_TEXT_COLOR, CLR_INVALID)
}

/// GetBkColor: the DC's background color.
#[unsafe(export_name = "f2k_export_GetBkColor")]
pub extern "system" fn get_bk_color(dc: usize) -> u32 {
    attribute(dc, DC_BK_COLOR, CLR_INVALID)
}

/// SetTextColor: the DC's text color set, the one it had answered; CLR_INVALID with the last
/// error for a DC that is none.
#[unsafe(export_name = "f2k_export_SetTextColor")]
pub extern "system" fn set_text_color(dc: usize, color: u32) -> u32 {
    set_attribute(dc, DC_TEXT_COLOR, color, CLR_INVALID)
}

/// SetBkColor: the DC's background color set, the one it had answered.
#[unsafe(export_name = "f2k_export_SetBkColor")]
pub extern "system" fn set_bk_color(dc: usize, color: u32) -> u32 {
    set_attribute(dc, DC_BK_COLOR, color, CLR_INVALID)
}

/// SetBkMode: the DC's background mode set (TRANSPARENT or OPAQUE), the one it had answered; 0
/// with the last error for another mode (ERROR_INVALID_PARAMETER) or a DC that is none.
#[unsafe(export_name = "f2k_export_SetBkMode")]
pub extern "system" fn set_bk_mode(dc: usize, mode: i32) -> i32 {
    set_attribute(dc, DC_BK_MODE, mode as u32, 0) as i32
}

/// SetPixel: the pixel set, the color set answered (the one asked for: the framebuffer is 32 bpp);
/// -1 outside the DC's clipping region, and with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_SetPixel")]
pub extern "system" fn set_pixel(dc: usize, x: i32, y: i32, color: u32) -> u32 {
    answered(imports::set_pixel(dc, x, y, color)).unwrap_or(CLR_INVALID)
}

/// GetPixel: the pixel's color; CLR_INVALID outside the DC's clipping region, and with the last
/// error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetPixel")]
pub extern "system" fn get_pixel(dc: usize, x: i32, y: i32) -> u32 {
    answered(imports::get_pixel(dc, x, y)).unwrap_or(CLR_INVALID)
}

/// GetDeviceCaps' indexes (wingdi.h) the screen DC answers.
const TECHNOLOGY: i32 = 2;
const HORZRES: i32 = 8;
const VERTRES: i32 = 10;
const BITSPIXEL: i32 = 12;
const PLANES: i32 = 14;
const NUMCOLORS: i32 = 24;
const LOGPIXELSX: i32 = 88;
const LOGPIXELSY: i32 = 90;
const SIZEPALETTE: i32 = 104;
const NUMRESERVED: i32 = 106;
const DESKTOPVERTRES: i32 = 117;
const DESKTOPHORZRES: i32 = 118;

/// TECHNOLOGY's answer for the display: a raster display.
const DT_RASDISPLAY: i32 = 1;

/// GetSystemMetrics' indexes (winuser.h) for the screen's size.
pub(crate) const SM_CXSCREEN: i32 = 0;
pub(crate) const SM_CYSCREEN: i32 = 1;

/// GetDeviceCaps: a capability of the screen DC — its size (the screen's, user32's
/// GetSystemMetrics as Windows 2000's gdi32 imports it: no DC service answers a capability), its
/// 32 bits per pixel in one plane (the framebuffer's), 96 logical pixels per inch, more colors
/// than a palette holds (NUMCOLORS -1, no palette); 0 with the last error for a DC that is none.
/// Another index goes to the stub routine.
#[unsafe(export_name = "f2k_export_GetDeviceCaps")]
pub extern "system" fn get_device_caps(dc: usize, index: i32) -> i32 {
    if answered(imports::dc_dword(dc, DC_TEXT_COLOR)).is_none() {
        return 0;
    }
    match index {
        TECHNOLOGY => DT_RASDISPLAY,
        HORZRES | DESKTOPHORZRES => imports::system_metric(SM_CXSCREEN),
        VERTRES | DESKTOPVERTRES => imports::system_metric(SM_CYSCREEN),
        BITSPIXEL => 32,
        PLANES => 1,
        NUMCOLORS => -1,
        LOGPIXELSX | LOGPIXELSY => 96,
        SIZEPALETTE | NUMRESERVED => 0,
        _ => {
            let args = [dc as u64, index as u32 as u64];
            // SAFETY: the arguments as GetDeviceCaps' kinds read them: no memory.
            let answer = unsafe {
                stub::stubbed(
                    &crate::spec::GetDeviceCaps,
                    "the capability is not served yet",
                    &args,
                )
            };
            answer as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{
        HostDc,
        BAD,
        DC,
        DEBUG_PRINTS,
        HOST_DC,
        LAST_ERROR,
        OPENED,
        SCREEN_HEIGHT,
        SCREEN_WIDTH,
        SERVICES,
    };

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn untouched() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn reset() {
        HOST_DC.with(|state| *state.borrow_mut() = HostDc::new());
        OPENED.with(|opened| opened.borrow_mut().clear());
        untouched();
    }

    /// The DISPLAY driver (in any case) opens the primary display; a device name goes to the
    /// kernel as it is; the narrow forms convert their names first.
    #[test]
    fn create_dc_opens_the_display() {
        reset();
        let display = wide("DISPLAY");
        let lower = wide("display");
        let device = wide("\\\\.\\DISPLAY1");
        // SAFETY: the tests' own NUL-terminated names.
        unsafe {
            assert_eq!(
                create_dc_w(display.as_ptr(), core::ptr::null(), core::ptr::null(), 0),
                DC
            );
            assert_eq!(
                create_dc_w(lower.as_ptr(), core::ptr::null(), core::ptr::null(), 0),
                DC
            );
            assert_eq!(
                create_dc_w(core::ptr::null(), device.as_ptr(), core::ptr::null(), 0),
                DC
            );
            assert_eq!(
                create_dc_a(
                    c"DISPLAY".as_ptr().cast(),
                    core::ptr::null(),
                    core::ptr::null(),
                    0
                ),
                DC
            );
            assert_eq!(
                create_dc_a(
                    c"DISPLAY".as_ptr().cast(),
                    c"\\\\.\\DISPLAY1".as_ptr().cast(),
                    core::ptr::null(),
                    0
                ),
                DC
            );
        }
        assert_eq!(last_error(), 0xF2F2, "a success leaves the last error");
        let opened = OPENED.with(|opened| opened.borrow().clone());
        assert_eq!(
            opened,
            [
                None,
                None,
                Some(device[..12].to_vec()),
                None,
                Some(device[..12].to_vec())
            ]
        );
    }

    /// Another display is the kernel's ERROR_INVALID_PARAMETER; another driver is a printer's,
    /// the stub routine's; a name past MAX_PATH is refused before any service.
    #[test]
    fn create_dc_refuses_what_is_no_display() {
        reset();
        let other = wide("\\\\.\\DISPLAY2");
        let printer = wide("WINSPOOL");
        // SAFETY: the tests' own NUL-terminated names.
        unsafe {
            assert_eq!(
                create_dc_w(core::ptr::null(), other.as_ptr(), core::ptr::null(), 0),
                0
            );
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
            assert_eq!(
                create_dc_w(printer.as_ptr(), core::ptr::null(), core::ptr::null(), 0),
                0
            );
            assert_eq!(last_error(), crate::stub::ERROR_CALL_NOT_IMPLEMENTED);
            assert_eq!(
                create_dc_w(core::ptr::null(), core::ptr::null(), core::ptr::null(), 0),
                0
            );
            let long = std::vec![b'D'; 300]
                .into_iter()
                .chain([0])
                .collect::<std::vec::Vec<u8>>();
            untouched();
            assert_eq!(
                create_dc_a(long.as_ptr(), core::ptr::null(), core::ptr::null(), 0),
                0
            );
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        }
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert!(
            printed
                .iter()
                .any(|line| line.contains("printer DCs not yet implemented")),
            "{printed:?}"
        );
    }

    /// DeleteDC closes the DC (a second delete finds none); a stock object is no DC to delete,
    /// while DeleteObject of one succeeds and leaves it.
    #[test]
    fn delete_dc_and_delete_object() {
        reset();
        let brush = stock_handle(WHITE_BRUSH).unwrap() as usize;
        assert_eq!(delete_object(brush), 1);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(delete_dc(brush), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(delete_dc(DC), 1);
        assert_eq!(delete_dc(DC), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(delete_object(BAD), 0);
    }

    /// The guidc capture's objects: GetStockObject(WHITE_BRUSH) and (SYSTEM_FONT) non-NULL, the
    /// brush selected over the default one (non-NULL), DeleteObject of it TRUE; an unknown index
    /// is NULL, a palette or a bad handle no object SelectObject takes.
    #[test]
    fn stock_objects_select_by_kind() {
        reset();
        let brush = get_stock_object(WHITE_BRUSH as i32);
        let font = get_stock_object(SYSTEM_FONT as i32);
        assert_ne!(brush, 0);
        assert_ne!(font, 0);
        assert_eq!(
            select_object(DC, brush),
            brush,
            "a DC starts with the white brush"
        );
        let black = get_stock_object(BLACK_BRUSH as i32);
        assert_eq!(select_object(DC, black), brush);
        assert_eq!(select_object(DC, brush), black);
        assert_eq!(select_object(DC, font), font);
        let pen = get_stock_object(NULL_PEN as i32);
        assert_eq!(
            select_object(DC, pen),
            stock_handle(BLACK_PEN).unwrap() as usize
        );
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(delete_object(brush), 1);
        assert_eq!(get_stock_object(9), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        untouched();
        assert_eq!(
            select_object(DC, get_stock_object(DEFAULT_PALETTE as i32)),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(select_object(DC, BAD), 0);
        assert_eq!(select_object(BAD, brush), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// The guidc capture's colors and modes: SetTextColor's previous black, SetBkColor's previous
    /// white, SetBkMode's previous OPAQUE (2) then TRANSPARENT (1); a mode that is neither fails.
    #[test]
    fn colors_and_modes_answer_the_previous_value() {
        reset();
        assert_eq!(set_text_color(DC, 0x0000_00FF), 0x0000_0000);
        assert_eq!(set_bk_color(DC, 0x00FF_0000), 0x00FF_FFFF);
        assert_eq!(set_bk_mode(DC, TRANSPARENT as i32), 2);
        assert_eq!(set_bk_mode(DC, OPAQUE as i32), 1);
        assert_eq!(get_text_color(DC), 0x0000_00FF);
        assert_eq!(get_bk_color(DC), 0x00FF_0000);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(set_bk_mode(DC, 3), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(set_text_color(BAD, 0), CLR_INVALID);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(get_bk_color(BAD), CLR_INVALID);
    }

    /// The guidc capture's pixel: SetPixel(100, 100, RGB(1,2,3)) answers 0x030201, GetPixel reads
    /// it back; outside the clipping region both answer -1 with the last error untouched.
    #[test]
    fn pixels_answer_their_colors() {
        reset();
        assert_eq!(set_pixel(DC, 100, 100, 0x0003_0201), 0x0003_0201);
        assert_eq!(get_pixel(DC, 100, 100), 0x0003_0201);
        assert_eq!(
            set_pixel(DC, 100, 100, 0x0100_0005),
            0x0000_0005,
            "the RGB part"
        );
        assert_eq!(set_pixel(DC, -1, 0, 0), CLR_INVALID);
        assert_eq!(get_pixel(DC, 640, 0), CLR_INVALID);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(get_pixel(BAD, 100, 100), CLR_INVALID);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
    }

    /// The screen DC's capabilities: the screen's size (GetSystemMetrics', the DC's check the one
    /// service called), 32 bits in one plane, 96 pixels per inch, NUMCOLORS -1; a DC that is none
    /// is 0 with ERROR_INVALID_HANDLE; another index is a stub.
    ///
    /// Pins: gdi32.GetDeviceCaps
    #[test]
    fn device_caps_describe_the_screen() {
        reset();
        let services = SERVICES.with(|count| count.get());
        let size: std::vec::Vec<i32> = [HORZRES, VERTRES, DESKTOPHORZRES, DESKTOPVERTRES]
            .into_iter()
            .map(|index| get_device_caps(DC, index))
            .collect();
        assert_eq!(
            size,
            [SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH, SCREEN_HEIGHT]
        );
        assert_eq!(SERVICES.with(|count| count.get()), services + 4);
        let answers: std::vec::Vec<i32> = [BITSPIXEL, PLANES, LOGPIXELSX, NUMCOLORS]
            .into_iter()
            .map(|index| get_device_caps(DC, index))
            .collect();
        assert_eq!(answers, [32, 1, 96, -1]);
        assert_eq!(get_device_caps(DC, TECHNOLOGY), DT_RASDISPLAY);
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(get_device_caps(BAD, HORZRES), 0);
        assert_eq!(last_error(), ERROR_INVALID_HANDLE);
        assert_eq!(get_device_caps(DC, 36), 0);
        assert_eq!(last_error(), crate::stub::ERROR_CALL_NOT_IMPLEMENTED);
    }
}
