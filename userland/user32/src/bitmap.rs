//! Bitmaps: LoadBitmapW and LoadBitmapA, and LoadImageW and LoadImageA of IMAGE_BITMAP, over
//! gdi32's bitmaps ([`imports`]).
//!
//! A module's bitmap is its RT_BITMAP resource: a packed DIB (a BITMAPINFOHEADER, its color table
//! or masks, its rows), found through kernel32's FindResourceEx as LoadIcon finds a group icon.
//! What LoadImage makes of it, as Windows 2000's does (the bitmaps capture):
//!
//! - by default (LoadBitmap's), a device-dependent bitmap of the screen's format (CreateDIBitmap of
//!   the screen's DC);
//! - LR_CREATEDIBSECTION, a DIB section of the resource's own format, its color table and its rows
//!   (the last error ERROR_NOT_ENOUGH_MEMORY, as CreateDIBSection leaves it);
//! - LR_MONOCHROME, a monochrome bitmap, each pixel black or white, the nearer of the two;
//! - a size asked for (`cx`, `cy`, either 0 taking the resource's), the rows stretched to it, each
//!   pixel the one under its center (StretchBlt's COLORONCOLOR).
//!
//! A resource the module lacks is NULL with FindResourceEx's last error
//! (ERROR_RESOURCE_NAME_NOT_FOUND). With no module, the name is a system bitmap's id (winuser.h's
//! OBM_*, under OEMRESOURCE), loaded as a module's is from the packed DIB [`crate::obm`] holds, a
//! new bitmap at each call (as Windows 2000's are); one it does not hold is NULL with
//! ERROR_RESOURCE_NAME_NOT_FOUND. A monochrome DIB (its two colors black and white) is loaded as a
//! monochrome bitmap, as Windows 2000's OBM_CHECK is.
//!
//! The other image types (IMAGE_ICON, IMAGE_CURSOR) and LR_LOADFROMFILE go to the stub routine.

use rtl::dib::{
    default_masks,
    dword_stride,
    get_packed,
    is_dib_depth,
    nearest,
    rgb_of_quad,
    sample,
    set_packed,
    table_size,
    word_stride,
    BitmapInfoHeader,
    Format,
    BI_BITFIELDS,
    BI_RGB,
    HEADER_SIZE,
    MONO_COLORS,
};
use rtl::pod::Pod;

use crate::imports::{self, HeapBlock, ResourceName};
use crate::{failed, spec};

/// RT_BITMAP: the resource type of a module's bitmaps.
const RT_BITMAP: u16 = 2;

/// LoadImage's image types: a bitmap (the one served here).
const IMAGE_BITMAP: u32 = 0;

/// LoadImage's flags (winuser.h's LR_*): a monochrome bitmap, the image read from a file, a DIB
/// section.
const LR_MONOCHROME: u32 = 0x0001;
const LR_LOADFROMFILE: u32 = 0x0010;
const LR_CREATEDIBSECTION: u32 = 0x2000;

// ERROR_RESOURCE_NAME_NOT_FOUND: no bitmap of that name.
// ERROR_INVALID_DATA: a resource that is no DIB.
use rtl::winerror::{ERROR_INVALID_DATA, ERROR_RESOURCE_NAME_NOT_FOUND};

/// LoadBitmapW: the module's bitmap `name` as a device-dependent bitmap of the screen's format, or
/// with no module the system bitmap `name` names; see the module notes.
///
/// # Safety
///
/// `name` is a resource id or the address of a NUL-terminated UTF-16 string, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_LoadBitmapW")]
pub unsafe extern "system" fn load_bitmap_w(instance: usize, name: *const u16) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load(instance, ResourceName::Wide(name as usize), 0, 0, 0) }
}

/// LoadBitmapA: LoadBitmapW's, the name an ANSI string or a number.
///
/// # Safety
///
/// As LoadBitmapW's, the string ANSI.
#[unsafe(export_name = "f2k_export_LoadBitmapA")]
pub unsafe extern "system" fn load_bitmap_a(instance: usize, name: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { load(instance, ResourceName::Narrow(name as usize), 0, 0, 0) }
}

/// LoadImageW: a bitmap (IMAGE_BITMAP) as the module notes say; another type, or a file, goes to
/// the stub routine.
///
/// # Safety
///
/// As LoadBitmapW's.
#[unsafe(export_name = "f2k_export_LoadImageW")]
pub unsafe extern "system" fn load_image_w(
    instance: usize,
    name: *const u16,
    kind: u32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> usize {
    if kind != IMAGE_BITMAP || flags & LR_LOADFROMFILE != 0 {
        let args = [
            instance as u64,
            name as u64,
            kind as u64,
            cx as u32 as u64,
            cy as u32 as u64,
            flags as u64,
        ];
        // SAFETY: the arguments as LoadImageW's kinds read them (the name a pointer, not read).
        return unsafe {
            crate::stub::stubbed(
                &spec::LoadImageW,
                "icons, cursors and files not yet implemented",
                &args,
            )
        } as usize;
    }
    // SAFETY: the caller's contract.
    unsafe { load(instance, ResourceName::Wide(name as usize), cx, cy, flags) }
}

/// LoadImageA: LoadImageW's, the name an ANSI string or a number.
///
/// # Safety
///
/// As LoadBitmapA's.
#[unsafe(export_name = "f2k_export_LoadImageA")]
pub unsafe extern "system" fn load_image_a(
    instance: usize,
    name: *const u8,
    kind: u32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> usize {
    if kind != IMAGE_BITMAP || flags & LR_LOADFROMFILE != 0 {
        let args = [
            instance as u64,
            name as u64,
            kind as u64,
            cx as u32 as u64,
            cy as u32 as u64,
            flags as u64,
        ];
        // SAFETY: as LoadImageW's.
        return unsafe {
            crate::stub::stubbed(
                &spec::LoadImageA,
                "icons, cursors and files not yet implemented",
                &args,
            )
        } as usize;
    }
    // SAFETY: the caller's contract.
    unsafe { load(instance, ResourceName::Narrow(name as usize), cx, cy, flags) }
}

/// The bitmap `name` of the module `instance` (none: a system bitmap) at `cx` by `cy` (0: the
/// resource's), as `flags` ask; NULL with the last error when there is none.
///
/// # Safety
///
/// A string name is the address of a NUL-terminated string the call may read.
unsafe fn load(instance: usize, name: ResourceName, cx: i32, cy: i32, flags: u32) -> usize {
    if instance == 0 {
        let Some(art) = name.id().and_then(crate::obm::find) else {
            return failed(ERROR_RESOURCE_NAME_NOT_FOUND).unwrap_or(0);
        };
        let Some(mut block) = HeapBlock::new(art.packed_size()) else {
            return 0;
        };
        art.write_packed(block.bytes_mut());
        let Some(dib) = Packed::parse(block.bytes()) else {
            return 0;
        };
        return made_of(&dib, cx, cy, flags);
    }
    // SAFETY: the caller's name (the contract).
    let Some(resource) = (unsafe { imports::find_named_resource(instance, RT_BITMAP, name) })
    else {
        return 0;
    };
    let Some(data) = imports::resource_data(instance, resource) else {
        return 0;
    };
    let Some(dib) = Packed::parse(data) else {
        return failed(ERROR_INVALID_DATA).unwrap_or(0);
    };
    made_of(&dib, cx, cy, flags)
}

/// The bitmap `flags` ask of `dib` at `cx` by `cy` (0: its own); NULL when none is made.
fn made_of(dib: &Packed, cx: i32, cy: i32, flags: u32) -> usize {
    let width = if cx > 0 { cx } else { dib.width() };
    let height = if cy > 0 { cy } else { dib.height() };
    let made = if flags & LR_MONOCHROME != 0
        || (flags & LR_CREATEDIBSECTION == 0 && dib.is_monochrome())
    {
        monochrome(dib, width, height)
    } else {
        stretched(dib, width, height, |info, rows| {
            if flags & LR_CREATEDIBSECTION != 0 {
                let (section, bits) = imports::create_dib_section(info)?;
                // SAFETY: the section's rows, `rows.len()` bytes of them (its header's), ours.
                let into = unsafe { core::slice::from_raw_parts_mut(bits as *mut u8, rows.len()) };
                into.copy_from_slice(rows);
                Some(section)
            } else {
                let screen = imports::get_dc(0).ok()? as usize;
                let made = imports::create_di_bitmap(screen, info, rows);
                let _ = imports::close(screen);
                made
            }
        })
    };
    made.unwrap_or(0)
}

/// A packed DIB, a bitmap resource's data: its BITMAPINFO (the header and its table or masks) and
/// its rows.
struct Packed<'a> {
    header: BitmapInfoHeader,
    info: &'a [u8],
    rows: &'a [u8],
}

impl<'a> Packed<'a> {
    /// The DIB `data` holds; none for one F2K cannot lay out (a header too short, no depth it
    /// takes, a compression but BI_RGB and BI_BITFIELDS, rows past the data).
    fn parse(data: &'a [u8]) -> Option<Packed<'a>> {
        let header = BitmapInfoHeader::from_bytes(data.get(..HEADER_SIZE as usize)?)?;
        let bpp = header.bit_count as u32;
        if header.size < HEADER_SIZE
            || header.width <= 0
            || header.height == 0
            || !is_dib_depth(bpp)
            || !matches!(header.compression, BI_RGB | BI_BITFIELDS)
        {
            return None;
        }
        let entries = match header.compression {
            BI_BITFIELDS => 3,
            _ if header.clr_used != 0 => (header.clr_used as usize).min(table_size(bpp)),
            _ => table_size(bpp),
        };
        let info_size = header.size as usize + 4 * entries;
        let stride = dword_stride(header.width, bpp) as usize;
        let rows = stride * header.height.unsigned_abs() as usize;
        Some(Packed {
            header,
            info: data.get(..info_size)?,
            rows: data.get(info_size..info_size + rows)?,
        })
    }

    fn width(&self) -> i32 {
        self.header.width
    }

    fn height(&self) -> i32 {
        self.header.height.saturating_abs()
    }

    fn bpp(&self) -> u32 {
        self.header.bit_count as u32
    }

    /// The row `y` (from the top).
    fn row(&self, y: i32) -> &'a [u8] {
        let stride = dword_stride(self.width(), self.bpp()) as usize;
        let stored = if self.header.height < 0 {
            y
        } else {
            self.height() - 1 - y
        };
        &self.rows[stride * stored as usize..stride * (stored as usize + 1)]
    }

    /// Whether it is monochrome: one bit a pixel, its two colors black and white.
    fn is_monochrome(&self) -> bool {
        let (table, _) = self.colors();
        self.bpp() == 1 && table[..2] == MONO_COLORS
    }

    /// Its colors: its table, or its masks.
    fn colors(&self) -> ([u32; 256], [u32; 3]) {
        let mut table = [0u32; 256];
        let entries = &self.info[self.header.size as usize..];
        let masks = if self.header.compression == BI_BITFIELDS {
            let mask = |index: usize| {
                let bytes = &entries[4 * index..4 * index + 4];
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            };
            [mask(0), mask(1), mask(2)]
        } else {
            let (quads, _) = entries.as_chunks::<4>();
            for (entry, &quad) in table.iter_mut().zip(quads) {
                *entry = rgb_of_quad(quad);
            }
            default_masks(self.bpp())
        };
        (table, masks)
    }
}

/// `dib`'s rows stretched to `width` by `height` at its own depth (each pixel the one under its
/// center), handed to `make` with a BITMAPINFO of that size (its table or masks the DIB's); the
/// resource's own when its size is asked for.
fn stretched(
    dib: &Packed,
    width: i32,
    height: i32,
    make: impl FnOnce(&[u8], &[u8]) -> Option<usize>,
) -> Option<usize> {
    let mut info = [0u8; HEADER_SIZE as usize + 4 * 256];
    let length = dib.info.len().min(info.len());
    info[..length].copy_from_slice(&dib.info[..length]);
    if width == dib.width() && height == dib.height() {
        return make(&info[..length], dib.rows);
    }
    let mut header = dib.header;
    header.size = HEADER_SIZE;
    header.width = width;
    header.height = if dib.header.height < 0 {
        -height
    } else {
        height
    };
    header.size_image = 0;
    let tail = &dib.info[dib.header.size as usize..];
    info[..HEADER_SIZE as usize].copy_from_slice(header.as_bytes());
    let length = (HEADER_SIZE as usize + tail.len()).min(info.len());
    info[HEADER_SIZE as usize..length].copy_from_slice(&tail[..length - HEADER_SIZE as usize]);
    let bpp = dib.bpp();
    let stride = dword_stride(width, bpp) as usize;
    let mut block = HeapBlock::new(stride * height as usize)?;
    let rows = block.bytes_mut();
    for y in 0..height {
        let from = dib.row(sample(y, height, dib.height()));
        let stored = if dib.header.height < 0 {
            y
        } else {
            height - 1 - y
        } as usize;
        let into = &mut rows[stride * stored..stride * (stored + 1)];
        for x in 0..width {
            let pixel = get_packed(from, sample(x, width, dib.width()) as usize, bpp);
            set_packed(into, x as usize, bpp, pixel);
        }
    }
    make(&info[..length], rows)
}

/// `dib` as a monochrome bitmap of `width` by `height`: each pixel (stretched as [`stretched`]
/// does) black or white, the nearer of the two to its color.
fn monochrome(dib: &Packed, width: i32, height: i32) -> Option<usize> {
    let (table, masks) = dib.colors();
    let colors = Format {
        bpp: dib.bpp(),
        table: &table[..table_size(dib.bpp())],
        masks,
    };
    let stride = word_stride(width, 1) as usize;
    let mut block = HeapBlock::new(stride * height as usize)?;
    let rows = block.bytes_mut();
    for y in 0..height {
        let from = dib.row(sample(y, height, dib.height()));
        let into = &mut rows[stride * y as usize..stride * (y as usize + 1)];
        for x in 0..width {
            let pixel = get_packed(from, sample(x, width, dib.width()) as usize, dib.bpp());
            set_packed(
                into,
                x as usize,
                1,
                nearest(&MONO_COLORS, colors.rgb(pixel)),
            );
        }
    }
    imports::create_bitmap(width, height, 1, Some(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packed DIB of the bitmaps fixture's shape: 8 by 8 at 4 bits, the VGA's colors, the pixel
    /// x, y holding (x + 2y) mod 16; rows bottom-up.
    fn own_bitmap() -> std::vec::Vec<u8> {
        let vga = [
            0x000000u32,
            0x800000,
            0x008000,
            0x808000,
            0x000080,
            0x800080,
            0x008080,
            0xC0C0C0,
            0x808080,
            0xFF0000,
            0x00FF00,
            0xFFFF00,
            0x0000FF,
            0xFF00FF,
            0x00FFFF,
            0xFFFFFF,
        ];
        let header = BitmapInfoHeader {
            size: 40,
            width: 8,
            height: 8,
            planes: 1,
            bit_count: 4,
            ..BitmapInfoHeader::default()
        };
        let mut data = header.as_bytes().to_vec();
        for rgb in vga {
            data.extend_from_slice(&rtl::dib::quad_of_rgb(rgb));
        }
        for stored in 0..8 {
            let y = 7 - stored;
            let mut row = [0u8; 4];
            for x in 0..8 {
                set_packed(&mut row, x, 4, ((x + 2 * y) % 16) as u32);
            }
            data.extend_from_slice(&row);
        }
        data
    }

    /// The program's bitmap parses: its rows from the top, the capture's stored rows.
    #[test]
    fn a_packed_dib_parses() {
        let data = own_bitmap();
        let dib = Packed::parse(&data).unwrap();
        assert_eq!((dib.width(), dib.height(), dib.bpp()), (8, 8, 4));
        assert_eq!(dib.row(0), [0x01, 0x23, 0x45, 0x67]);
        assert_eq!(dib.row(7), [0xEF, 0x01, 0x23, 0x45]);
        assert!(Packed::parse(&data[..100]).is_none(), "rows past the data");
    }

    /// LR_MONOCHROME's rows, as the capture prints them: 01 06 19 65 97 5C 70 C0 (silver, gray,
    /// yellow, magenta, cyan and white nearer white).
    #[test]
    fn monochrome_takes_the_nearer_of_black_and_white() {
        let data = own_bitmap();
        let dib = Packed::parse(&data).unwrap();
        let (table, masks) = dib.colors();
        let colors = Format {
            bpp: 4,
            table: &table[..16],
            masks,
        };
        let rows: std::vec::Vec<u8> = (0..8)
            .map(|y| {
                let mut row = [0u8; 2];
                for x in 0..8 {
                    let rgb = colors.rgb(get_packed(dib.row(y), x, 4));
                    set_packed(&mut row, x, 1, nearest(&MONO_COLORS, rgb));
                }
                row[0]
            })
            .collect();
        assert_eq!(rows, [0x01, 0x06, 0x19, 0x65, 0x97, 0x5C, 0x70, 0xC0]);
    }
}
