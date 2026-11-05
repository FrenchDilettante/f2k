//! The VBE framebuffer: the screen in a VESA graphics mode, which replaces the VGA text mode when
//! the graphics mode is set — from user mode, through win32k's display service (FiSH's call), as
//! on Windows 2000, where a display-settings change reaches the video port.
//!
//! The mode set itself is a BIOS call (`int 10h`, `AX=4F02h`), and the BIOS is real-mode only:
//! on target it runs through the real-mode trampoline in [`trampoline`] — a blob copied into a run
//! of conventional memory reserved at boot for it alone (see
//! [`crate::mem::bootmem::TRAMPOLINE_FIRST_FRAME`]), entered with paging off and back. Both boot
//! paths are Multiboot 1, which carries no framebuffer, so the kernel issues the mode set itself,
//! uniformly. The linear framebuffer's physical address, pitch and geometry come from the
//! `AX=4F01h` mode-info block, never hardcoded (QEMU's PCI-variant VGA does not mirror the LFB at a
//! fixed address), and are mapped into [`crate::mem::layout::FRAMEBUFFER`], uncached.
//!
//! The driver's logic runs against two seams — the BIOS calls ([`Bios`]) and the pixel memory
//! ([`PixelMemory`]) — so the host tests drive it against fakes, as the other drivers' are. The
//! mode set's one-time state ([`ModeSet`]) is host-tested the same way.

use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(target_arch = "x86")]
pub mod trampoline;

#[cfg(target_arch = "x86")]
pub use trampoline::{
    current_geometry,
    display_modes,
    enter_graphics_mode,
    graphics_mode_set,
    test_graphics_mode,
    with_framebuffer,
};

/// The host build has no trampoline: the mode set is not servable there.
#[cfg(not(target_arch = "x86"))]
pub fn enter_graphics_mode(_request: &ModeRequest) -> Result<Geometry, ModeError> {
    Err(ModeError::Unsupported)
}

/// Nor is the test of a mode.
#[cfg(not(target_arch = "x86"))]
pub fn test_graphics_mode(_request: &ModeRequest) -> Result<Geometry, ModeError> {
    Err(ModeError::Unsupported)
}

/// The host build never sets the graphics mode.
#[cfg(not(target_arch = "x86"))]
pub fn graphics_mode_set() -> bool {
    false
}

/// Nor lists the display's modes.
#[cfg(not(target_arch = "x86"))]
pub fn display_modes() -> Result<&'static ModeList, ModeError> {
    Err(ModeError::Unsupported)
}

/// Nor has a mode's geometry.
#[cfg(not(target_arch = "x86"))]
pub fn current_geometry() -> Option<Geometry> {
    None
}

/// How many modes of the list the driver looks at, at most: the trampoline's scan fetches as many
/// mode information blocks.
pub const MAX_MODES: usize = 128;
/// The `AX=4F02h` BX bit 14: request the linear framebuffer rather than a banked one.
pub const LFB_REQUEST: u16 = 0x4000;
/// The resolution the mode set prefers where its caller leaves it open: the display's default
/// mode, which the boot's work area assumes until a mode is set.
pub const DEFAULT_WIDTH: usize = 640;
pub const DEFAULT_HEIGHT: usize = 480;

/// Why the graphics mode was not set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    /// The machine has no such mode: no trampoline run, no VBE 2.0 BIOS, or no 32-bpp linear mode
    /// in its list.
    Unsupported,
    /// The BIOS refused the mode set.
    Refused,
    /// Another caller is setting the mode at this moment.
    Busy,
}

/// The color the screen is cleared to when the mode is set: the desktop's, Redmond blue
/// (`0x3A6EA5`, Windows 2000's default desktop color).
pub const DESKTOP_RGB: u32 = 0x003A_6EA5;

/// The `AX=4F00h` VBE information block's size.
pub const VBE_INFO_BYTES: usize = 512;
/// The VBE information block's leading fields the driver reads: the signature, the version, the
/// OEM string's far pointer, the capabilities and the mode list's far pointer.
pub const VBE_HEADER_BYTES: usize = 18;
/// The `AX=4F01h` mode information block's size.
pub const MODE_INFO_BYTES: usize = 256;

// Offsets in the VBE information block.
const VBE_INFO_SIGNATURE: usize = 0; // "VESA"
const VBE_INFO_VERSION: usize = 4; // BCD version, 0x0200 for VBE 2.0
/// The mode list's far pointer (offset, then segment) in the VBE information block.
pub const VBE_INFO_MODE_LIST: usize = 14;

// Offsets in the mode information block.
const MI_ATTRIBUTES: usize = 0; // u16: bit 0 the mode is supported, bit 7 a linear framebuffer
pub const MI_PITCH: usize = 16; // u16: bytes per scan line
const MI_WIDTH: usize = 18; // u16
const MI_HEIGHT: usize = 20; // u16
const MI_BPP: usize = 25; // u8
const MI_RED_FIELD: usize = 32; // u8: the red mask's field position
const MI_GREEN_FIELD: usize = 34; // u8
const MI_BLUE_FIELD: usize = 36; // u8
const MI_LFB: usize = 40; // u32: the linear framebuffer's physical address

/// Mode-attributes bit 0: the mode is supported in this configuration.
pub const ATTR_SUPPORTED: u16 = 0x01;
/// Mode-attributes bit 7: the mode has a linear framebuffer.
pub const ATTR_LFB: u16 = 0x80;

/// The BIOS's VBE calls (`int 10h`), the seam the mode set runs behind: on target the real-mode
/// trampoline ([`trampoline`]), in the host tests a fake.
pub trait Bios {
    /// `AX=4F00h`: the VBE information block's header into `header`; whether the call succeeded
    /// (AL = 4Fh).
    fn vbe_info(&mut self, header: &mut [u8; VBE_HEADER_BYTES]) -> bool;
    /// The mode at `index` in the video mode list (the `AX=4F00h` block's far pointer's list,
    /// `0xFFFF`-terminated); none at the list's end, and from [`MAX_MODES`] on.
    fn mode(&mut self, index: usize) -> Option<u16>;
    /// `AX=4F01h`: the mode information block for `mode` into `bytes`; whether it succeeded.
    fn mode_info(&mut self, mode: u16, bytes: &mut [u8; MODE_INFO_BYTES]) -> bool;
    /// `AX=4F02h`: set `mode` as given (the LFB bit included); whether it succeeded.
    fn set_mode(&mut self, mode: u16) -> bool;
}

/// The framebuffer's pixel memory, by byte offset from the LFB's first page.
pub trait PixelMemory {
    /// Store the 32-bit pixel `value` at byte `offset`.
    fn store(&mut self, offset: usize, value: u32);
    /// The 32-bit pixel at byte `offset` (GetPixel's read).
    fn load(&mut self, offset: usize) -> u32;
}

/// The geometry of the mode that was set, decoded from its mode information block: the scan-line
/// pitch, the resolution, the LFB's physical address and the direct-color masks' field positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub width: usize,
    pub height: usize,
    pub pitch: usize,
    pub lfb_phys: u32,
    red_field: u8,
    green_field: u8,
    blue_field: u8,
}

impl Geometry {
    /// The mode information block at `bytes` decoded as the graphics mode's geometry; none when the
    /// mode is not supported, has no linear framebuffer, or is not 32 bpp.
    pub fn decode(bytes: &[u8; MODE_INFO_BYTES]) -> Option<Geometry> {
        let attributes = u16::from_le_bytes([bytes[MI_ATTRIBUTES], bytes[MI_ATTRIBUTES + 1]]);
        if attributes & ATTR_SUPPORTED == 0 || attributes & ATTR_LFB == 0 {
            return None;
        }
        if bytes[MI_BPP] != 32 {
            return None;
        }
        Some(Geometry {
            width: u16::from_le_bytes([bytes[MI_WIDTH], bytes[MI_WIDTH + 1]]) as usize,
            height: u16::from_le_bytes([bytes[MI_HEIGHT], bytes[MI_HEIGHT + 1]]) as usize,
            pitch: u16::from_le_bytes([bytes[MI_PITCH], bytes[MI_PITCH + 1]]) as usize,
            lfb_phys: u32::from_le_bytes([
                bytes[MI_LFB],
                bytes[MI_LFB + 1],
                bytes[MI_LFB + 2],
                bytes[MI_LFB + 3],
            ]),
            red_field: bytes[MI_RED_FIELD],
            green_field: bytes[MI_GREEN_FIELD],
            blue_field: bytes[MI_BLUE_FIELD],
        })
    }

    /// The framebuffer's size in bytes: the pitch times the height.
    pub fn bytes(&self) -> u32 {
        self.pitch as u32 * self.height as u32
    }

    /// The 32-bit pixel value for an `0xRRGGBB` color in this mode's masks.
    pub fn pixel(&self, rgb: u32) -> u32 {
        let red = (rgb >> 16) & 0xFF;
        let green = (rgb >> 8) & 0xFF;
        let blue = rgb & 0xFF;
        (red << self.red_field) | (green << self.green_field) | (blue << self.blue_field)
    }

    /// The `0xRRGGBB` color of a 32-bit pixel value in this mode's masks ([`Geometry::pixel`]'s
    /// inverse).
    pub fn rgb(&self, pixel: u32) -> u32 {
        let red = (pixel >> self.red_field) & 0xFF;
        let green = (pixel >> self.green_field) & 0xFF;
        let blue = (pixel >> self.blue_field) & 0xFF;
        (red << 16) | (green << 8) | blue
    }

    /// A `width` by `height` 32-bpp mode, its scan lines packed, its masks 8/8/8 at 16/8/0: the
    /// fakes' geometry in the host tests of the framebuffer's consumers.
    #[cfg(test)]
    pub fn packed(width: usize, height: usize) -> Geometry {
        Geometry {
            width,
            height,
            pitch: width * 4,
            lfb_phys: 0xE000_0000,
            red_field: 16,
            green_field: 8,
            blue_field: 0,
        }
    }
}

/// The screen in the linear framebuffer mode: the geometry, and the pixel memory the pixels land
/// in. Writes outside the mode's resolution do nothing.
pub struct Framebuffer<M: PixelMemory> {
    memory: M,
    pub geometry: Geometry,
}

impl<M: PixelMemory> Framebuffer<M> {
    pub const fn new(memory: M, geometry: Geometry) -> Self {
        Framebuffer { memory, geometry }
    }

    /// The pixel memory (the host tests' look at their fakes).
    #[cfg(test)]
    pub fn memory(&mut self) -> &mut M {
        &mut self.memory
    }

    /// Store the `0xRRGGBB` pixel at (`x`, `y`).
    pub fn put_pixel(&mut self, x: usize, y: usize, rgb: u32) {
        if x < self.geometry.width && y < self.geometry.height {
            let offset = y * self.geometry.pitch + x * 4;
            let pixel = self.geometry.pixel(rgb);
            self.memory.store(offset, pixel);
        }
    }

    /// The `0xRRGGBB` pixel at (`x`, `y`); none outside the mode's resolution.
    pub fn get_pixel(&mut self, x: usize, y: usize) -> Option<u32> {
        if x < self.geometry.width && y < self.geometry.height {
            let offset = y * self.geometry.pitch + x * 4;
            Some(self.geometry.rgb(self.memory.load(offset)))
        } else {
            None
        }
    }

    /// Fill the rectangle at (`x`, `y`), `width` by `height`, clipped to the mode.
    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, rgb: u32) {
        let right = x.saturating_add(width).min(self.geometry.width);
        let bottom = y.saturating_add(height).min(self.geometry.height);
        for row in y..bottom {
            for column in x..right {
                self.put_pixel(column, row, rgb);
            }
        }
    }

    /// Clear the whole screen to `rgb`.
    pub fn clear(&mut self, rgb: u32) {
        self.fill_rect(0, 0, self.geometry.width, self.geometry.height, rgb);
    }
}

/// Whether the VBE BIOS is there: the `AX=4F00h` block's signature and a VBE 2.0+ version.
pub fn vbe_present<B: Bios>(bios: &mut B) -> bool {
    let mut info = [0u8; VBE_HEADER_BYTES];
    bios.vbe_info(&mut info)
        && &info[VBE_INFO_SIGNATURE..VBE_INFO_SIGNATURE + 4] == b"VESA"
        && u16::from_le_bytes([info[VBE_INFO_VERSION], info[VBE_INFO_VERSION + 1]]) >= 0x0200
}

/// What the caller asks of the mode: each field a requirement when given, open when not (a
/// DEVMODE's display fields, as its dmFields marks them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModeRequest {
    pub width: Option<usize>,
    pub height: Option<usize>,
    pub bits_per_pixel: Option<u32>,
}

impl ModeRequest {
    /// Whether `geometry` (a 32-bpp mode) answers the request.
    pub fn matches(&self, geometry: &Geometry) -> bool {
        self.width.is_none_or(|width| width == geometry.width)
            && self.height.is_none_or(|height| height == geometry.height)
            && self.bits_per_pixel.is_none_or(|bits| bits == 32)
    }
}

/// Choose the mode for `request` from the BIOS's list: the first 32-bpp linear mode it matches,
/// 640x480 preferred where the request leaves the resolution open.
pub fn choose_mode<B: Bios>(
    bios: &mut B,
    request: &ModeRequest,
) -> Result<(u16, Geometry), ModeError> {
    if !vbe_present(bios) {
        return Err(ModeError::Unsupported);
    }
    let preferred = (
        request.width.unwrap_or(DEFAULT_WIDTH),
        request.height.unwrap_or(DEFAULT_HEIGHT),
    );
    let mut chosen: Option<(u16, Geometry)> = None;
    for index in 0..MAX_MODES {
        let Some(mode) = bios.mode(index) else {
            break;
        };
        let mut info = [0u8; MODE_INFO_BYTES];
        if !bios.mode_info(mode, &mut info) {
            continue;
        }
        let Some(geometry) = Geometry::decode(&info) else {
            continue;
        };
        if !request.matches(&geometry) {
            continue;
        }
        if (geometry.width, geometry.height) == preferred {
            return Ok((mode, geometry));
        }
        if chosen.is_none() {
            chosen = Some((mode, geometry));
        }
    }
    chosen.ok_or(ModeError::Unsupported)
}

/// The display modes the driver can set, as EnumDisplaySettings numbers them: the resolutions of
/// the BIOS list's 32-bpp linear modes, in the list's order, each once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeList {
    sizes: [(u16, u16); MAX_MODES],
    count: usize,
}

impl ModeList {
    pub const EMPTY: Self = ModeList {
        sizes: [(0, 0); MAX_MODES],
        count: 0,
    };

    /// The resolution of the mode numbered `index`; none past the list.
    pub fn get(&self, index: usize) -> Option<(usize, usize)> {
        self.sizes[..self.count]
            .get(index)
            .map(|&(width, height)| (width as usize, height as usize))
    }
}

/// List the modes the driver can set into `list` ([`ModeList`]), from the BIOS's mode list and
/// mode information blocks; unsupported without a VBE 2.0 BIOS.
pub fn list_modes<B: Bios>(bios: &mut B, list: &mut ModeList) -> Result<(), ModeError> {
    if !vbe_present(bios) {
        return Err(ModeError::Unsupported);
    }
    list.count = 0;
    for index in 0..MAX_MODES {
        let Some(mode) = bios.mode(index) else {
            break;
        };
        let mut info = [0u8; MODE_INFO_BYTES];
        if !bios.mode_info(mode, &mut info) {
            continue;
        }
        let Some(geometry) = Geometry::decode(&info) else {
            continue;
        };
        let size = (geometry.width as u16, geometry.height as u16);
        if !list.sizes[..list.count].contains(&size) {
            list.sizes[list.count] = size;
            list.count += 1;
        }
    }
    Ok(())
}

/// Set the graphics mode `request` asks for: choose it ([`choose_mode`]), set it with the linear
/// framebuffer requested, and map the framebuffer. `map` maps the LFB (physical `base`, `bytes` of
/// it) and answers the region's virtual address of `base`'s page — on target the framebuffer
/// region's, in the host tests wherever the fake wants.
pub fn set_graphics_mode<B: Bios>(
    bios: &mut B,
    request: &ModeRequest,
    map: &mut impl FnMut(u32, u32) -> u32,
) -> Result<(Geometry, u32), ModeError> {
    let (mode, geometry) = choose_mode(bios, request)?;
    if !bios.set_mode(mode | LFB_REQUEST) {
        return Err(ModeError::Refused);
    }
    // The LFB is page-aligned; map its whole span, rounded up to pages.
    let base = geometry.lfb_phys & !0xFFF;
    let bytes = (geometry.lfb_phys - base + geometry.bytes()).div_ceil(0x1000) * 0x1000;
    let virtual_base = map(base, bytes);
    Ok((geometry, virtual_base + (geometry.lfb_phys - base)))
}

/// The graphics mode's one-time set: who sets it, and what the callers that come meanwhile or
/// after are answered. Nobody waits on it: a caller arriving while another sets the mode is
/// answered busy at once (a service runs masked until its first wait, and the mode set waits
/// nowhere, so a caller spinning for it could spin forever on the one processor). A failed set
/// leaves the mode unset, so a later call tries again.
pub struct ModeSet(AtomicU8);

/// What [`ModeSet::enter`] tells its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The mode is set: answer its geometry.
    Set,
    /// Another caller is setting it: answer busy.
    Busy,
    /// This caller sets it, and reports how it went through [`ModeSet::finish`].
    Proceed,
}

const UNSET: u8 = 0;
const SETTING: u8 = 1;
const SET: u8 = 2;

impl ModeSet {
    pub const fn new() -> Self {
        ModeSet(AtomicU8::new(UNSET))
    }

    /// Enter the mode set: the caller that finds the mode unset claims it.
    pub fn enter(&self) -> Entry {
        match self
            .0
            .compare_exchange(UNSET, SETTING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Entry::Proceed,
            Err(SET) => Entry::Set,
            Err(_) => Entry::Busy,
        }
    }

    /// The claiming caller's end of the set: the mode set, or left unset for a later try.
    pub fn finish(&self, set: bool) {
        self.0
            .store(if set { SET } else { UNSET }, Ordering::Release);
    }

    /// Whether the mode is set.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire) == SET
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The mode the fakes answer for (0x112, which is 24 bpp on QEMU's VBE BIOS: the scan picks by
    /// geometry, never by number).
    const MODE: u16 = 0x112;

    /// A fake BIOS answering the VBE calls from canned blocks, recording what it was asked.
    struct FakeBios {
        info_ok: bool,
        mode: u16,
        mode_ok: bool,
        set_ok: bool,
        asked_set: Vec<u16>,
    }

    impl FakeBios {
        fn new() -> Self {
            FakeBios {
                info_ok: true,
                mode: MODE,
                mode_ok: true,
                set_ok: true,
                asked_set: Vec::new(),
            }
        }
    }

    /// The mode list: the 32-bpp linear modes in the BIOS's order, each resolution once; none
    /// without a VBE BIOS.
    #[test]
    fn the_mode_list_is_the_bioss_32_bpp_modes() {
        struct Several;
        impl Bios for Several {
            fn vbe_info(&mut self, info: &mut [u8; VBE_HEADER_BYTES]) -> bool {
                info[..4].copy_from_slice(b"VESA");
                info[4..6].copy_from_slice(&0x0300u16.to_le_bytes());
                true
            }

            fn mode(&mut self, index: usize) -> Option<u16> {
                [0x100, 0x101, 0x102, 0x103, 0x104].get(index).copied()
            }

            fn mode_info(&mut self, mode: u16, bytes: &mut [u8; MODE_INFO_BYTES]) -> bool {
                *bytes = mode_info_block();
                let (width, height, bpp): (u16, u16, u8) = match mode {
                    0x100 => (800, 600, 8),
                    0x101 => (640, 480, 32),
                    0x102 => (1024, 768, 32),
                    0x103 => (640, 480, 32),
                    _ => return false,
                };
                bytes[MI_WIDTH..MI_WIDTH + 2].copy_from_slice(&width.to_le_bytes());
                bytes[MI_HEIGHT..MI_HEIGHT + 2].copy_from_slice(&height.to_le_bytes());
                bytes[MI_BPP] = bpp;
                true
            }

            fn set_mode(&mut self, _mode: u16) -> bool {
                false
            }
        }
        let mut list = ModeList::EMPTY;
        list_modes(&mut Several, &mut list).unwrap();
        assert_eq!(list.get(0), Some((640, 480)));
        assert_eq!(list.get(1), Some((1024, 768)));
        assert_eq!(list.get(2), None);
        let mut bios = FakeBios::new();
        bios.info_ok = false;
        assert_eq!(
            list_modes(&mut bios, &mut list),
            Err(ModeError::Unsupported)
        );
    }

    /// The mode information block for 640x480x32 with the LFB at 0xE0000000, masks 8/8/8 at
    /// 16/8/0, pitch 2560.
    fn mode_info_block() -> [u8; MODE_INFO_BYTES] {
        let mut bytes = [0u8; MODE_INFO_BYTES];
        bytes[MI_ATTRIBUTES..MI_ATTRIBUTES + 2]
            .copy_from_slice(&(ATTR_SUPPORTED | ATTR_LFB).to_le_bytes());
        bytes[MI_PITCH..MI_PITCH + 2].copy_from_slice(&2560u16.to_le_bytes());
        bytes[MI_WIDTH..MI_WIDTH + 2].copy_from_slice(&640u16.to_le_bytes());
        bytes[MI_HEIGHT..MI_HEIGHT + 2].copy_from_slice(&480u16.to_le_bytes());
        bytes[MI_BPP] = 32;
        bytes[MI_RED_FIELD] = 16;
        bytes[MI_GREEN_FIELD] = 8;
        bytes[MI_BLUE_FIELD] = 0;
        bytes[MI_LFB..MI_LFB + 4].copy_from_slice(&0xE000_0000u32.to_le_bytes());
        bytes
    }

    impl Bios for FakeBios {
        fn vbe_info(&mut self, info: &mut [u8; VBE_HEADER_BYTES]) -> bool {
            info[VBE_INFO_SIGNATURE..VBE_INFO_SIGNATURE + 4].copy_from_slice(b"VESA");
            info[VBE_INFO_VERSION..VBE_INFO_VERSION + 2].copy_from_slice(&0x0300u16.to_le_bytes());
            self.info_ok
        }

        fn mode(&mut self, index: usize) -> Option<u16> {
            [0x101, self.mode].get(index).copied()
        }

        fn mode_info(&mut self, mode: u16, bytes: &mut [u8; MODE_INFO_BYTES]) -> bool {
            if mode != self.mode {
                return false; // 0x101: not our block
            }
            *bytes = mode_info_block();
            self.mode_ok
        }

        fn set_mode(&mut self, mode: u16) -> bool {
            self.asked_set.push(mode);
            self.set_ok
        }
    }

    struct Memory(Vec<u32>);

    impl PixelMemory for Memory {
        fn store(&mut self, offset: usize, value: u32) {
            self.0[offset / 4] = value;
        }

        fn load(&mut self, offset: usize) -> u32 {
            self.0[offset / 4]
        }
    }

    /// The geometry decodes, and the pixel composition follows the masks.
    #[test]
    fn the_mode_info_block_decodes() {
        let geometry = Geometry::decode(&mode_info_block()).unwrap();
        assert_eq!(geometry.width, 640);
        assert_eq!(geometry.height, 480);
        assert_eq!(geometry.pitch, 2560);
        assert_eq!(geometry.lfb_phys, 0xE000_0000);
        assert_eq!(geometry.bytes(), 2560 * 480);
        assert_eq!(geometry.pixel(0x00FF_0000), 0x00FF_0000, "red at field 16");
        assert_eq!(geometry.pixel(0x0000_FF00), 0x0000_FF00, "green at field 8");
        assert_eq!(geometry.pixel(0x0000_00FF), 0x0000_00FF, "blue at field 0");
        assert_eq!(geometry.pixel(0x00FF_FF00), 0x00FF_FF00);
    }

    /// A mode without the LFB bit, without support, or not 32 bpp decodes to nothing.
    #[test]
    fn an_unsuitable_mode_decodes_to_nothing() {
        let mut block = mode_info_block();
        block[MI_ATTRIBUTES] = 0;
        assert_eq!(Geometry::decode(&block), None);
        let mut block = mode_info_block();
        block[MI_ATTRIBUTES] &= !0x80; // clear the LFB bit
        assert_eq!(Geometry::decode(&block), None);
        let mut block = mode_info_block();
        block[MI_BPP] = 24;
        assert_eq!(Geometry::decode(&block), None);
    }

    /// The mode set: the BIOS is asked for the mode with the LFB bit, the LFB is mapped from its
    /// physical base, and the virtual base comes back offset to the LFB itself.
    #[test]
    fn the_mode_set_maps_the_lfb() {
        let mut bios = FakeBios::new();
        let mut mapped = Vec::new();
        let map = |base: u32, bytes: u32| {
            mapped.push((base, bytes));
            0xC080_0000
        };
        let mut map = map;
        let (geometry, va) =
            set_graphics_mode(&mut bios, &ModeRequest::default(), &mut map).unwrap();
        assert_eq!(bios.asked_set, [MODE | LFB_REQUEST]);
        assert_eq!(mapped, [(0xE000_0000, 2560 * 480)]);
        assert_eq!(va, 0xC080_0000);
        assert_eq!(geometry.lfb_phys, 0xE000_0000);
    }

    /// A non-page-aligned LFB is mapped from its page, and the virtual base follows the offset.
    #[test]
    fn an_unaligned_lfb_maps_from_its_page() {
        let mut bios = FakeBios::new();
        let mut block = mode_info_block();
        block[MI_LFB..MI_LFB + 4].copy_from_slice(&0xE000_0123u32.to_le_bytes());
        // A fake whose mode info carries the unaligned LFB.
        struct Unaligned([u8; MODE_INFO_BYTES]);
        impl Bios for Unaligned {
            fn vbe_info(&mut self, info: &mut [u8; VBE_HEADER_BYTES]) -> bool {
                info[..4].copy_from_slice(b"VESA");
                info[4..6].copy_from_slice(&0x0300u16.to_le_bytes());
                true
            }

            fn mode(&mut self, index: usize) -> Option<u16> {
                (index == 0).then_some(0x112)
            }

            fn mode_info(&mut self, _mode: u16, bytes: &mut [u8; MODE_INFO_BYTES]) -> bool {
                *bytes = self.0;
                true
            }

            fn set_mode(&mut self, _mode: u16) -> bool {
                true
            }
        }
        let mut mapped = Vec::new();
        let mut map = |base: u32, bytes: u32| {
            mapped.push((base, bytes));
            0xC080_0000
        };
        let (geometry, va) =
            set_graphics_mode(&mut Unaligned(block), &ModeRequest::default(), &mut map).unwrap();
        assert_eq!(
            mapped,
            [(
                0xE000_0000,
                (0x123u32 + 2560 * 480).div_ceil(0x1000) * 0x1000
            )]
        );
        assert_eq!(va, 0xC080_0000 + 0x123);
        assert_eq!(geometry.lfb_phys, 0xE000_0123);
        let _ = &mut bios;
    }

    /// No VBE BIOS, or a failing call, refuses the mode set.
    #[test]
    fn a_failing_bios_refuses() {
        let mut bios = FakeBios::new();
        bios.info_ok = false;
        assert!(set_graphics_mode(&mut bios, &ModeRequest::default(), &mut |_, _| 0).is_err());
        let mut bios = FakeBios::new();
        bios.mode_ok = false;
        assert!(set_graphics_mode(&mut bios, &ModeRequest::default(), &mut |_, _| 0).is_err());
        let mut bios = FakeBios::new();
        bios.set_ok = false;
        assert_eq!(
            set_graphics_mode(&mut bios, &ModeRequest::default(), &mut |_, _| 0),
            Err(ModeError::Refused)
        );
    }

    /// A request is matched against the list: what it asks must be the mode's, what it leaves open
    /// is not looked at; a mode the list lacks is unsupported, and nothing is set for it.
    #[test]
    fn the_request_picks_the_mode() {
        let asked = |width, height, bits| ModeRequest {
            width,
            height,
            bits_per_pixel: bits,
        };
        for request in [
            asked(None, None, None),
            asked(Some(640), Some(480), Some(32)),
            asked(Some(640), None, None),
            asked(None, None, Some(32)),
        ] {
            let mut bios = FakeBios::new();
            assert_eq!(
                choose_mode(&mut bios, &request).map(|(mode, _)| mode),
                Ok(MODE),
                "{request:?}"
            );
        }
        for request in [
            asked(Some(800), Some(600), None),
            asked(None, Some(600), None),
            asked(None, None, Some(16)),
        ] {
            let mut bios = FakeBios::new();
            assert_eq!(
                set_graphics_mode(&mut bios, &request, &mut |_, _| 0),
                Err(ModeError::Unsupported),
                "{request:?}"
            );
            assert!(bios.asked_set.is_empty());
        }
    }

    /// Pixels land at their scan-line offset, composed through the masks, and read back as the
    /// colors they were; writes outside the mode do nothing and reads there answer none; a clear
    /// covers every pixel.
    #[test]
    fn pixels_land_in_the_framebuffer() {
        let geometry = Geometry::decode(&mode_info_block()).unwrap();
        let mut fb = Framebuffer::new(Memory(std::vec![0; 2560 * 480 / 4]), geometry);
        fb.put_pixel(0, 0, 0x00FF_FFFF);
        assert_eq!(fb.memory().0[0], 0x00FF_FFFF);
        fb.put_pixel(3, 2, 0x00FF_0000);
        assert_eq!(fb.memory().0[2 * 2560 / 4 + 3], 0x00FF_0000);
        assert_eq!(fb.get_pixel(3, 2), Some(0x00FF_0000));
        assert_eq!(fb.get_pixel(640, 0), None);
        assert_eq!(fb.get_pixel(0, 480), None);
        assert_eq!(geometry.rgb(geometry.pixel(0x0003_0201)), 0x0003_0201);
        fb.put_pixel(640, 0, 0x00FF_FFFF);
        fb.put_pixel(0, 480, 0x00FF_FFFF);
        assert_eq!(
            fb.memory().0.iter().filter(|&&p| p == 0x00FF_FFFF).count(),
            1
        );
        fb.clear(0x0000_8080);
        assert!(fb.memory().0.iter().all(|&p| p == 0x0000_8080));
        fb.fill_rect(10, 10, 5, 5, 0x00FF_FFFF);
        assert_eq!(fb.memory().0[10 * 2560 / 4 + 10], 0x00FF_FFFF);
        assert_eq!(fb.memory().0[14 * 2560 / 4 + 14], 0x00FF_FFFF);
        assert_eq!(
            fb.memory().0[15 * 2560 / 4 + 15],
            0x0000_8080,
            "the rect stops at its edge"
        );
    }

    /// The first caller claims the set; a caller meanwhile is answered busy, never made to wait;
    /// a failed set leaves the mode unset for a later try; once it is set, every caller is
    /// answered the mode.
    #[test]
    fn the_mode_set_never_waits() {
        let state = ModeSet::new();
        assert!(!state.is_set());
        assert_eq!(state.enter(), Entry::Proceed);
        assert_eq!(state.enter(), Entry::Busy, "a caller during the set");
        state.finish(false);
        assert!(!state.is_set(), "a failed set");
        assert_eq!(state.enter(), Entry::Proceed, "the next call tries again");
        state.finish(true);
        assert!(state.is_set());
        assert_eq!(state.enter(), Entry::Set);
        assert_eq!(state.enter(), Entry::Set);
    }
}
