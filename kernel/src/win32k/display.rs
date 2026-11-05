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
//! BIOS lists), after which only requests that mode answers succeed; and the flags 0 (a dynamic
//! change), CDS_FULLSCREEN (the same, here) and CDS_TEST (the mode checked, nothing set). The
//! registry holds no display settings, so CDS_UPDATEREGISTRY and the rest are refused as flags the
//! subset does not take. The enum side (`NtUserEnumDisplaySettings` and friends) lands with the
//! display group's fixtures, answering from the same geometry.

use core::mem::size_of;

use rtl::display::*;
use rtl::pod::Pod;

use crate::hw::vbe::{self, ModeError, ModeRequest};
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr};
use crate::status::NtStatus;

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
    let mut units = [0u16; CCHDEVICENAME];
    for (index, unit) in units.iter_mut().enumerate() {
        *unit = at
            .offset(2 * index as u32)
            .cast::<u16>()
            .read()
            .map_err(|_| DISP_CHANGE_BADPARAM)?;
        if *unit == 0 {
            return Ok(is_primary_display(&units[..index]));
        }
    }
    Ok(false)
}

/// Whether `units` name the primary display, without regard to case.
pub(super) fn is_primary_display(units: &[u16]) -> bool {
    units.len() == PRIMARY_DISPLAY.len()
        && units
            .iter()
            .zip(PRIMARY_DISPLAY.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
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
}
