//! The display settings: the ChangeDisplaySettings family, each over win32k's
//! NtUserChangeDisplaySettings ([`imports::change_display_settings`]), as Windows 2000's user32
//! calls it: the wide forms hand the caller's name and DEVMODEW to the kernel unread, the narrow
//! ones convert theirs to the wide form first. The answer is the kernel's DISP_CHANGE code, as it
//! is; no last error is set (ChangeDisplaySettings documents none).
//!
//! What the kernel's minimal subset serves is in its display service's notes (one display,
//! `\\.\DISPLAY1`; its graphics mode set once; the flags 0, CDS_FULLSCREEN and CDS_TEST).

use core::mem::size_of;

use rtl::display::{
    wide_dev_mode,
    DevModeA,
    DevModeW,
    CCHDEVICENAME,
    DEV_MODE_A_SIZE,
    DISP_CHANGE_BADPARAM,
};
use rtl::edge::{In, InBuf, InStr};
use rtl::pod::Pod;

use crate::imports;

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
}
