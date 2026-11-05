//! The display settings' shared shapes: DEVMODEA and DEVMODEW as Windows 2000's wingdi.h lays them
//! out on x86 ([`DevModeA`], [`DevModeW`]), the fields and flags ChangeDisplaySettings reads, and
//! the DISP_CHANGE codes it answers; DISPLAY_DEVICEA and DISPLAY_DEVICEW ([`DisplayDeviceA`],
//! [`DisplayDeviceW`]) and their state flags, EnumDisplaySettings' mode numbers, the monitor
//! handles, the SystemParametersInfo actions and the system colors win32k answers. user32's
//! ChangeDisplaySettings family converts the narrow form to the wide one ([`wide_dev_mode`]) and
//! hands it to win32k's NtUserChangeDisplaySettings, which the kernel serves from the same
//! definitions.
//!
//! A DEVMODE's dmSize says which version of the structure the caller has: the fields past it are
//! not there. The display fields (dmBitsPerPel to dmDisplayFrequency) are in every version from
//! Windows NT 3.5's on ([`DISPLAY_FIELDS_END_W`]); Windows 2000's adds the ICM and panning fields.

use core::mem::{offset_of, size_of};

use crate::pod::Pod;

/// CCHDEVICENAME and CCHFORMNAME: the device and form names' room, in characters.
pub const CCHDEVICENAME: usize = 32;
pub const CCHFORMNAME: usize = 32;

/// dmFields' bits for the display fields.
pub const DM_BITSPERPEL: u32 = 0x0004_0000;
pub const DM_PELSWIDTH: u32 = 0x0008_0000;
pub const DM_PELSHEIGHT: u32 = 0x0010_0000;
pub const DM_DISPLAYFLAGS: u32 = 0x0020_0000;
pub const DM_DISPLAYFREQUENCY: u32 = 0x0040_0000;

/// ChangeDisplaySettings' flags.
pub const CDS_UPDATEREGISTRY: u32 = 0x0000_0001;
pub const CDS_TEST: u32 = 0x0000_0002;
pub const CDS_FULLSCREEN: u32 = 0x0000_0004;

/// ChangeDisplaySettings' answers (a LONG).
pub const DISP_CHANGE_SUCCESSFUL: i32 = 0;
pub const DISP_CHANGE_RESTART: i32 = 1;
pub const DISP_CHANGE_FAILED: i32 = -1;
pub const DISP_CHANGE_BADMODE: i32 = -2;
pub const DISP_CHANGE_NOTUPDATED: i32 = -3;
pub const DISP_CHANGE_BADFLAGS: i32 = -4;
pub const DISP_CHANGE_BADPARAM: i32 = -5;

/// DEVMODEA, Windows 2000's (156 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevModeA {
    pub device_name: [u8; CCHDEVICENAME],
    pub spec_version: u16,
    pub driver_version: u16,
    pub size: u16,
    pub driver_extra: u16,
    pub fields: u32,
    /// The printer fields (dmOrientation to dmPrintQuality; dmPosition overlays the first four).
    pub printer: [i16; 8],
    pub color: i16,
    pub duplex: i16,
    pub y_resolution: i16,
    pub tt_option: i16,
    pub collate: i16,
    pub form_name: [u8; CCHFORMNAME],
    pub log_pixels: u16,
    pub bits_per_pel: u32,
    pub pels_width: u32,
    pub pels_height: u32,
    pub display_flags: u32,
    pub display_frequency: u32,
    pub icm_method: u32,
    pub icm_intent: u32,
    pub media_type: u32,
    pub dither_type: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub panning_width: u32,
    pub panning_height: u32,
}

/// DEVMODEW, Windows 2000's (220 bytes): DEVMODEA with its two names in UTF-16.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevModeW {
    pub device_name: [u16; CCHDEVICENAME],
    pub spec_version: u16,
    pub driver_version: u16,
    pub size: u16,
    pub driver_extra: u16,
    pub fields: u32,
    pub printer: [i16; 8],
    pub color: i16,
    pub duplex: i16,
    pub y_resolution: i16,
    pub tt_option: i16,
    pub collate: i16,
    pub form_name: [u16; CCHFORMNAME],
    pub log_pixels: u16,
    pub bits_per_pel: u32,
    pub pels_width: u32,
    pub pels_height: u32,
    pub display_flags: u32,
    pub display_frequency: u32,
    pub icm_method: u32,
    pub icm_intent: u32,
    pub media_type: u32,
    pub dither_type: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub panning_width: u32,
    pub panning_height: u32,
}

const _: () = {
    assert!(size_of::<DevModeA>() == 156);
    assert!(offset_of!(DevModeA, size) == 36);
    assert!(offset_of!(DevModeA, fields) == 40);
    assert!(offset_of!(DevModeA, form_name) == 70);
    assert!(offset_of!(DevModeA, bits_per_pel) == 104);
    assert!(offset_of!(DevModeA, display_frequency) == 120);
    assert!(size_of::<DevModeW>() == 220);
    assert!(offset_of!(DevModeW, size) == 68);
    assert!(offset_of!(DevModeW, fields) == 72);
    assert!(offset_of!(DevModeW, form_name) == 102);
    assert!(offset_of!(DevModeW, bits_per_pel) == 168);
    assert!(offset_of!(DevModeW, display_frequency) == 184);
};

// SAFETY: integers and arrays of them, without padding (the asserts above pin every offset and the
// sizes, which leave no gap); any bit pattern is a value.
unsafe impl Pod for DevModeA {}
// SAFETY: as DevModeA's.
unsafe impl Pod for DevModeW {}

/// The offset of dmSize in a DEVMODEW: read first, to know how much of the structure is there.
pub const DEV_MODE_W_SIZE: usize = offset_of!(DevModeW, size);
/// The offset of dmSize in a DEVMODEA.
pub const DEV_MODE_A_SIZE: usize = offset_of!(DevModeA, size);
/// The smallest dmSize of a DEVMODEW that holds the display fields: the end of dmDisplayFrequency.
pub const DISPLAY_FIELDS_END_W: usize = offset_of!(DevModeW, icm_method);
/// The narrow form's: the two names are 32 bytes each shorter.
pub const DISPLAY_FIELDS_END_A: usize = offset_of!(DevModeA, icm_method);

/// dmFields' bits for the fields a display mode's description carries besides the display
/// fields: the desktop's position on the virtual screen and the logical pixels per inch.
pub const DM_POSITION: u32 = 0x0000_0020;
pub const DM_LOGPIXELS: u32 = 0x0002_0000;

/// DM_SPECVERSION: the DEVMODE version Windows 2000 describes its modes in.
pub const DM_SPECVERSION: u16 = 0x0401;

/// EnumDisplaySettings' mode numbers for the current mode and the registry's.
pub const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
pub const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;

/// DISPLAY_DEVICE's StateFlags.
pub const DISPLAY_DEVICE_ATTACHED_TO_DESKTOP: u32 = 0x0000_0001;
pub const DISPLAY_DEVICE_PRIMARY_DEVICE: u32 = 0x0000_0004;
pub const DISPLAY_DEVICE_VGA_COMPATIBLE: u32 = 0x0000_0010;
/// A monitor's StateFlags: it is on, and attached to its adapter.
pub const DISPLAY_DEVICE_ACTIVE: u32 = 0x0000_0001;
pub const DISPLAY_DEVICE_ATTACHED: u32 = 0x0000_0002;

/// DISPLAY_DEVICE's string fields' room, in characters.
pub const DEVICE_STRING_CHARS: usize = 128;

/// DISPLAY_DEVICEW, Windows 2000's (840 bytes): a display device's names and state, as
/// EnumDisplayDevicesW answers them. Its `cb` says which version of the structure the caller has:
/// Windows NT 4.0's ends at StateFlags ([`DISPLAY_DEVICE_STATE_END_W`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayDeviceW {
    pub cb: u32,
    pub device_name: [u16; CCHDEVICENAME],
    pub device_string: [u16; DEVICE_STRING_CHARS],
    pub state_flags: u32,
    pub device_id: [u16; DEVICE_STRING_CHARS],
    pub device_key: [u16; DEVICE_STRING_CHARS],
}

/// DISPLAY_DEVICEA, Windows 2000's (424 bytes): DISPLAY_DEVICEW with its strings in bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayDeviceA {
    pub cb: u32,
    pub device_name: [u8; CCHDEVICENAME],
    pub device_string: [u8; DEVICE_STRING_CHARS],
    pub state_flags: u32,
    pub device_id: [u8; DEVICE_STRING_CHARS],
    pub device_key: [u8; DEVICE_STRING_CHARS],
}

const _: () = {
    assert!(size_of::<DisplayDeviceW>() == 840);
    assert!(offset_of!(DisplayDeviceW, device_string) == 68);
    assert!(offset_of!(DisplayDeviceW, state_flags) == 324);
    assert!(offset_of!(DisplayDeviceW, device_id) == 328);
    assert!(offset_of!(DisplayDeviceW, device_key) == 584);
    assert!(size_of::<DisplayDeviceA>() == 424);
    assert!(offset_of!(DisplayDeviceA, state_flags) == 164);
};

// SAFETY: integers and arrays of them, without padding (the asserts above pin the offsets and the
// sizes, which leave no gap); any bit pattern is a value.
unsafe impl Pod for DisplayDeviceW {}
// SAFETY: as DisplayDeviceW's.
unsafe impl Pod for DisplayDeviceA {}

/// The end of a DISPLAY_DEVICEW's StateFlags: the smallest `cb` a caller's structure may have.
pub const DISPLAY_DEVICE_STATE_END_W: usize = offset_of!(DisplayDeviceW, device_id);

/// The primary monitor's HMONITOR, as win32k's monitor services answer it (F2K's own value, a
/// user handle's shape: the first index, the first generation); the others follow it.
pub const PRIMARY_MONITOR_HANDLE: u32 = 0x0001_0001;

/// SystemParametersInfo's actions win32k answers.
///
/// SPI_GETWORKAREA: the primary monitor's work area, a RECT into pvParam.
pub const SPI_GETWORKAREA: u32 = 0x0030;

/// The system colors' indexes (winuser.h's COLOR_*), and how many Windows 2000 has.
pub const COLOR_DESKTOP: u32 = 1;
pub const COLOR_WINDOW: u32 = 5;
pub const COLOR_BTNTEXT: u32 = 18;
pub const SYSTEM_COLORS: usize = 29;

/// The system colors of Windows 2000's default scheme ("Windows Standard"), by index, as
/// COLORREFs (0x00BBGGRR). Index 25 has no name in winuser.h.
pub const DEFAULT_SYSTEM_COLORS: [u32; SYSTEM_COLORS] = [
    0x00C8_D0D4, // COLOR_SCROLLBAR
    0x00A5_6E3A, // COLOR_BACKGROUND (COLOR_DESKTOP)
    0x006A_240A, // COLOR_ACTIVECAPTION
    0x0080_8080, // COLOR_INACTIVECAPTION
    0x00C8_D0D4, // COLOR_MENU
    0x00FF_FFFF, // COLOR_WINDOW
    0x0000_0000, // COLOR_WINDOWFRAME
    0x0000_0000, // COLOR_MENUTEXT
    0x0000_0000, // COLOR_WINDOWTEXT
    0x00FF_FFFF, // COLOR_CAPTIONTEXT
    0x00C8_D0D4, // COLOR_ACTIVEBORDER
    0x00C8_D0D4, // COLOR_INACTIVEBORDER
    0x0080_8080, // COLOR_APPWORKSPACE
    0x006A_240A, // COLOR_HIGHLIGHT
    0x00FF_FFFF, // COLOR_HIGHLIGHTTEXT
    0x00C8_D0D4, // COLOR_BTNFACE
    0x0080_8080, // COLOR_BTNSHADOW
    0x0080_8080, // COLOR_GRAYTEXT
    0x0000_0000, // COLOR_BTNTEXT
    0x00C8_D0D4, // COLOR_INACTIVECAPTIONTEXT
    0x00FF_FFFF, // COLOR_BTNHIGHLIGHT
    0x0040_4040, // COLOR_3DDKSHADOW
    0x00C8_D0D4, // COLOR_3DLIGHT
    0x0000_0000, // COLOR_INFOTEXT
    0x00E1_FFFF, // COLOR_INFOBK
    0x00B5_B5B5, // (index 25)
    0x0080_0000, // COLOR_HOTLIGHT
    0x00F0_CAA6, // COLOR_GRADIENTACTIVECAPTION
    0x00C0_C0C0, // COLOR_GRADIENTINACTIVECAPTION
];

/// The wide form of the narrow `mode`, as ChangeDisplaySettingsExA hands it on: the two names
/// converted through `convert` (into the units' room, from the bytes up to their NUL), every other
/// field as it is, and dmSize grown by the names' 64 bytes so it names the same version. The
/// driver's private bytes past the structure (dmDriverExtra) are not carried: none are kept.
pub fn wide_dev_mode(mode: &DevModeA, mut convert: impl FnMut(&mut [u16], &[u8])) -> DevModeW {
    let mut wide = DevModeW::zeroed();
    let narrow = |name: &[u8]| -> usize { name.iter().position(|&b| b == 0).unwrap_or(name.len()) };
    convert(
        &mut wide.device_name,
        &mode.device_name[..narrow(&mode.device_name)],
    );
    convert(
        &mut wide.form_name,
        &mode.form_name[..narrow(&mode.form_name)],
    );
    wide.spec_version = mode.spec_version;
    wide.driver_version = mode.driver_version;
    wide.size = mode
        .size
        .saturating_add((size_of::<DevModeW>() - size_of::<DevModeA>()) as u16);
    wide.driver_extra = 0;
    wide.fields = mode.fields;
    wide.printer = mode.printer;
    wide.color = mode.color;
    wide.duplex = mode.duplex;
    wide.y_resolution = mode.y_resolution;
    wide.tt_option = mode.tt_option;
    wide.collate = mode.collate;
    wide.log_pixels = mode.log_pixels;
    wide.bits_per_pel = mode.bits_per_pel;
    wide.pels_width = mode.pels_width;
    wide.pels_height = mode.pels_height;
    wide.display_flags = mode.display_flags;
    wide.display_frequency = mode.display_frequency;
    wide.icm_method = mode.icm_method;
    wide.icm_intent = mode.icm_intent;
    wide.media_type = mode.media_type;
    wide.dither_type = mode.dither_type;
    wide.reserved1 = mode.reserved1;
    wide.reserved2 = mode.reserved2;
    wide.panning_width = mode.panning_width;
    wide.panning_height = mode.panning_height;
    wide
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names go through the conversion, the rest as it is, and dmSize names the wide form of
    /// the same version.
    #[test]
    fn the_narrow_form_widens() {
        let mut narrow = DevModeA::zeroed();
        narrow.device_name[..12].copy_from_slice(b"\\\\.\\DISPLAY1");
        narrow.size = size_of::<DevModeA>() as u16;
        narrow.driver_extra = 16;
        narrow.fields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;
        narrow.bits_per_pel = 32;
        narrow.pels_width = 640;
        narrow.pels_height = 480;
        narrow.panning_height = 7;
        let wide = wide_dev_mode(&narrow, |units, bytes| {
            for (unit, &byte) in units.iter_mut().zip(bytes) {
                *unit = byte as u16;
            }
        });
        assert_eq!(
            &wide.device_name[..12],
            &"\\\\.\\DISPLAY1".encode_utf16().collect::<Vec<_>>()[..]
        );
        assert_eq!(wide.device_name[12], 0);
        assert_eq!(wide.form_name, [0; CCHFORMNAME]);
        assert_eq!(wide.size as usize, size_of::<DevModeW>());
        assert_eq!(wide.driver_extra, 0);
        assert_eq!(wide.fields, narrow.fields);
        assert_eq!(
            (wide.bits_per_pel, wide.pels_width, wide.pels_height),
            (32, 640, 480)
        );
        assert_eq!(wide.panning_height, 7);
        // Windows NT 4.0's narrow DEVMODE, without the panning fields: 148 bytes, 212 wide.
        narrow.size = 148;
        assert_eq!(wide_dev_mode(&narrow, |_, _| {}).size, 212);
        assert_eq!(DISPLAY_FIELDS_END_A + 64, DISPLAY_FIELDS_END_W);
    }
}
