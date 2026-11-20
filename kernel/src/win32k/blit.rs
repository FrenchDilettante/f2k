//! The blits: BitBlt's and StretchBlt's pixels, from one [`Surface`] to another (or within one),
//! combined with the destination and a brush's pattern by any of the 256 ternary raster
//! operations. The services ([`super::bitmap`]) hand it the surfaces and the DCs' state; the host
//! tests drive it against bitmaps in memory and assert exact pixels.
//!
//! What a blit does, as Windows 2000's does it:
//!
//! - every destination pixel inside the destination rectangle, the DC's clipping region and the
//!   surface takes its source pixel (BitBlt: at the same offset in the source rectangle;
//!   StretchBlt: the one under its center, [`rtl::dib::sample`]); a pixel whose source lies outside
//!   the source surface is left as it was;
//! - the source pixel is converted to the destination's format: a monochrome bitmap's 0 bits become
//!   the destination DC's text color and its 1 bits its background color; a color pixel going to a
//!   monochrome bitmap becomes 1 when it is the source DC's background color and 0 otherwise;
//!   between monochrome bitmaps the bits go as they are, between surfaces of one format the pixels
//!   too (a 32-bit pixel's top byte with it); otherwise the color goes to the destination's nearest
//!   pixel;
//! - the pattern (the destination DC's brush) is the destination's nearest pixel to its color at
//!   the pixel's place;
//! - the raster operation combines pattern, source and destination pixels bit for bit
//!   ([`rtl::dib::rop3`]); the destination is read only when the operation reads it;
//! - a shrinking StretchBlt under BLACKONWHITE ANDs the converted pixels it eliminates into each
//!   destination pixel, under WHITEONBLACK ORs them; any other mode (COLORONCOLOR, HALFTONE, and
//!   any value SetStretchBltMode took) samples one;
//! - a negative extent mirrors: the rectangle reaches back from the point, the point's pixel
//!   included (StretchBlt(x 3, width -4) covers columns 0 to 3, column 3 the source's first);
//! - within one surface, a blit of the same size reads every source pixel before it is overwritten
//!   (the rows and columns walked away from the overlap).

use rtl::dib::{rop3, sample, span, BLACKONWHITE, WHITEONBLACK};
use rtl::gdi::{rop3 as rop_code, rop_uses_destination, Rect};

use super::raster::{intersect, Pattern, Surface};

/// Where a blit's source pixels come from.
pub enum Source<'a> {
    /// None: the raster operation reads no source.
    None,
    /// The destination surface itself.
    Same,
    /// Another surface.
    Other(&'a mut dyn Surface),
}

/// One blit's geometry and colors: the destination rectangle (the surface's coordinates) and the
/// source's (its own), each as the call named it (a negative extent mirrors), the clipping
/// region, the raster operation, the stretch mode, the destination DC's text and background
/// colors and the source DC's background color (`0xRRGGBB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blit {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub source_x: i32,
    pub source_y: i32,
    pub source_width: i32,
    pub source_height: i32,
    pub clip: Rect,
    pub rop: u32,
    pub mode: u32,
    pub text: u32,
    pub background: u32,
    pub source_background: u32,
}

/// The span an extent names from a point: its first pixel, its length, and whether it runs
/// backwards (a negative extent: the point's pixel its last, `at + extent + 1` its first).
pub fn normalize(at: i32, extent: i32) -> (i32, i32, bool) {
    if extent < 0 {
        (
            at.saturating_add(extent).saturating_add(1),
            extent.saturating_neg(),
            true,
        )
    } else {
        (at, extent, false)
    }
}

/// How a source pixel becomes a destination pixel (see the module notes).
struct Convert {
    text: u32,
    background: u32,
    source_background: u32,
    same_format: bool,
    source_mono: bool,
    destination_mono: bool,
}

impl Convert {
    fn new(destination: &dyn Surface, source: &dyn Surface, blit: &Blit) -> Self {
        Convert {
            text: destination.pixel(blit.text),
            background: destination.pixel(blit.background),
            source_background: source.rgb(source.pixel(blit.source_background)),
            same_format: destination.format() == source.format(),
            source_mono: source.is_mono(),
            destination_mono: destination.is_mono(),
        }
    }

    fn convert(&self, destination: &dyn Surface, source: &dyn Surface, pixel: u32) -> u32 {
        match (self.source_mono, self.destination_mono) {
            (true, true) => pixel & 1,
            (true, false) if pixel & 1 == 0 => self.text,
            (true, false) => self.background,
            (false, true) => (source.rgb(pixel) == self.source_background) as u32,
            (false, false) if self.same_format => pixel,
            (false, false) => destination.pixel(source.rgb(pixel)),
        }
    }
}

/// The blit `blit` from `source` onto `destination` with `pattern` (none: the null brush, its
/// pixels zero). Nothing is drawn for an empty rectangle.
pub fn blit(
    destination: &mut dyn Surface,
    mut source: Source,
    pattern: Option<&Pattern>,
    blit: &Blit,
) {
    let (left, width, flip_x) = normalize(blit.x, blit.width);
    let (top, height, flip_y) = normalize(blit.y, blit.height);
    let (source_left, source_width, source_flip_x) = normalize(blit.source_x, blit.source_width);
    let (source_top, source_height, source_flip_y) = normalize(blit.source_y, blit.source_height);
    if width == 0 || height == 0 {
        return;
    }
    let target = Rect {
        left,
        top,
        right: left.saturating_add(width),
        bottom: top.saturating_add(height),
    };
    let area = intersect(intersect(target, blit.clip), destination.bounds());
    if area.left >= area.right || area.top >= area.bottom {
        return;
    }
    let code = rop_code(blit.rop);
    let reads = rop_uses_destination(blit.rop);
    let solid = match pattern {
        Some(&Pattern::Solid(color)) => Some(destination.pixel(color)),
        None => Some(0),
        _ => None,
    };
    let mirror_x = flip_x != source_flip_x;
    let mirror_y = flip_y != source_flip_y;
    let stretched = source_width != width || source_height != height || mirror_x || mirror_y;
    if matches!(source, Source::None) || source_width == 0 || source_height == 0 {
        if !matches!(source, Source::None) {
            return;
        }
        for y in area.top..area.bottom {
            for x in area.left..area.right {
                let paint = paint_at(destination, solid, pattern, x, y);
                let old = if reads { destination.load(x, y) } else { 0 };
                destination.store(x, y, rop3(code, paint, 0, old));
            }
        }
        return;
    }

    let convert = match &source {
        Source::Other(surface) => Some(Convert::new(destination, &**surface, blit)),
        _ => None,
    };
    let convert = convert.as_ref();

    // The source's pixel (its column or row) for destination column or row `at`.
    let column = |at: i32| {
        let mut index = at - left;
        if mirror_x {
            index = width - 1 - index;
        }
        index
    };
    let row = |at: i32| {
        let mut index = at - top;
        if mirror_y {
            index = height - 1 - index;
        }
        index
    };

    if !stretched {
        // Within one surface, walk away from the overlap: backwards when the destination lies
        // after the source.
        let backwards = matches!(source, Source::Same)
            && (top > source_top || (top == source_top && left > source_left));
        let rows = area.top..area.bottom;
        let columns = area.left..area.right;
        let each = |destination: &mut dyn Surface, y: i32, x: i32, source: &mut Source| {
            let (sx, sy) = (source_left + column(x), source_top + row(y));
            let converted = match source {
                Source::Other(surface) => {
                    let (sw, sh) = surface.extent();
                    if sx < 0 || sy < 0 || sx >= sw || sy >= sh {
                        return;
                    }
                    let pixel = surface.load(sx, sy);
                    convert.expect("another surface's conversion").convert(
                        destination,
                        &**surface,
                        pixel,
                    )
                }
                Source::Same => {
                    let (sw, sh) = destination.extent();
                    if sx < 0 || sy < 0 || sx >= sw || sy >= sh {
                        return;
                    }
                    destination.load(sx, sy)
                }
                Source::None => 0,
            };
            let paint = paint_at(destination, solid, pattern, x, y);
            let old = if reads { destination.load(x, y) } else { 0 };
            destination.store(x, y, rop3(code, paint, converted, old));
        };
        if backwards {
            for y in rows.rev() {
                for x in columns.clone().rev() {
                    each(destination, y, x, &mut source);
                }
            }
        } else {
            for y in rows {
                for x in columns.clone() {
                    each(destination, y, x, &mut source);
                }
            }
        }
        return;
    }

    let combine = match blit.mode {
        BLACKONWHITE => Some(true),
        WHITEONBLACK => Some(false),
        _ => None,
    };
    for y in area.top..area.bottom {
        for x in area.left..area.right {
            let (i, j) = (column(x), row(y));
            let converted = match &mut source {
                Source::Other(surface) => {
                    let surface: &mut dyn Surface = &mut **surface;
                    stretched_pixel(
                        destination,
                        surface,
                        convert.expect("another surface's conversion"),
                        (i, width, source_left, source_width),
                        (j, height, source_top, source_height),
                        combine,
                    )
                }
                Source::Same => {
                    let (sx, sy) = (
                        source_left + sample(i, width, source_width),
                        source_top + sample(j, height, source_height),
                    );
                    let (sw, sh) = destination.extent();
                    if sx < 0 || sy < 0 || sx >= sw || sy >= sh {
                        None
                    } else {
                        Some(destination.load(sx, sy))
                    }
                }
                Source::None => Some(0),
            };
            let Some(converted) = converted else {
                continue;
            };
            let paint = paint_at(destination, solid, pattern, x, y);
            let old = if reads { destination.load(x, y) } else { 0 };
            destination.store(x, y, rop3(code, paint, converted, old));
        }
    }
}

/// The pattern's pixel at (`x`, `y`): the solid one, or the pattern's color's nearest.
fn paint_at(
    destination: &dyn Surface,
    solid: Option<u32>,
    pattern: Option<&Pattern>,
    x: i32,
    y: i32,
) -> u32 {
    match (solid, pattern) {
        (Some(pixel), _) => pixel,
        (None, Some(pattern)) => destination.pixel(pattern.at(x, y)),
        (None, None) => 0,
    }
}

/// The converted source pixel a stretch takes for destination column `i` of `width` and row `j`
/// of `height` (from the rectangle's first, mirrored already) out of the source rectangle at
/// `source_left` (`source_width` wide) and `source_top`, through `convert`: the one sampled, or
/// under `combine` (AND
/// for `Some(true)`, OR for `Some(false)`) the ones eliminated on a shrink; none when they lie
/// outside the source surface.
fn stretched_pixel(
    destination: &dyn Surface,
    source: &mut dyn Surface,
    convert: &Convert,
    (i, width, source_left, source_width): (i32, i32, i32, i32),
    (j, height, source_top, source_height): (i32, i32, i32, i32),
    combine: Option<bool>,
) -> Option<u32> {
    let (sw, sh) = source.extent();
    let inside = |sx: i32, sy: i32| sx >= 0 && sy >= 0 && sx < sw && sy < sh;
    let shrinking = source_width > width || source_height > height;
    match combine {
        Some(and) if shrinking => {
            let (x0, x1) = if source_width > width {
                span(i, width, source_width)
            } else {
                let at = sample(i, width, source_width);
                (at, at + 1)
            };
            let (y0, y1) = if source_height > height {
                span(j, height, source_height)
            } else {
                let at = sample(j, height, source_height);
                (at, at + 1)
            };
            let mut result: Option<u32> = None;
            for sy in y0..y1 {
                for sx in x0..x1 {
                    let (px, py) = (source_left + sx, source_top + sy);
                    if !inside(px, py) {
                        continue;
                    }
                    let pixel = source.load(px, py);
                    let value = convert.convert(destination, source, pixel);
                    result = Some(match result {
                        None => value,
                        Some(sum) if and => sum & value,
                        Some(sum) => sum | value,
                    });
                }
            }
            result
        }
        _ => {
            let (px, py) = (
                source_left + sample(i, width, source_width),
                source_top + sample(j, height, source_height),
            );
            if !inside(px, py) {
                return None;
            }
            let pixel = source.load(px, py);
            Some(convert.convert(destination, source, pixel))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::dib::*;
    use rtl::gdi::{BLACKNESS, DSTINVERT, PATCOPY, PATINVERT, WHITENESS};

    use super::*;
    use crate::win32k::raster::FormatKey;

    /// A bitmap in memory: `bpp` bits a pixel, kept one `u32` a pixel, mono or with a table.
    struct Pixels {
        width: i32,
        height: i32,
        bpp: u32,
        mono: bool,
        table: Vec<u32>,
        pixels: Vec<u32>,
    }

    impl Pixels {
        fn new(width: i32, height: i32, bpp: u32, pixels: &[u32]) -> Pixels {
            let mut all = std::vec![0; (width * height) as usize];
            all[..pixels.len()].copy_from_slice(pixels);
            Pixels {
                width,
                height,
                bpp,
                mono: false,
                table: Vec::new(),
                pixels: all,
            }
        }

        fn mono(width: i32, height: i32, bits: &[u32]) -> Pixels {
            Pixels {
                mono: true,
                table: MONO_COLORS.to_vec(),
                ..Pixels::new(width, height, 1, bits)
            }
        }

        fn format(&self) -> Format<'_> {
            Format {
                bpp: self.bpp,
                table: &self.table,
                masks: default_masks(self.bpp),
            }
        }
    }

    impl Surface for Pixels {
        fn extent(&self) -> (i32, i32) {
            (self.width, self.height)
        }

        fn format(&self) -> FormatKey {
            FormatKey {
                bpp: self.bpp,
                masks: default_masks(self.bpp),
                table: self.table.len() as u32,
            }
        }

        fn is_mono(&self) -> bool {
            self.mono
        }

        fn load(&mut self, x: i32, y: i32) -> u32 {
            self.pixels[(y * self.width + x) as usize]
        }

        fn store(&mut self, x: i32, y: i32, pixel: u32) {
            self.pixels[(y * self.width + x) as usize] = pixel & depth_mask(self.bpp);
        }

        fn rgb(&self, pixel: u32) -> u32 {
            self.format().rgb(pixel)
        }

        fn pixel(&self, rgb: u32) -> u32 {
            self.format().pixel(rgb)
        }
    }

    fn all(width: i32, height: i32) -> Rect {
        Rect {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        }
    }

    fn bit_blt(x: i32, y: i32, width: i32, height: i32, sx: i32, sy: i32, rop: u32) -> Blit {
        Blit {
            x,
            y,
            width,
            height,
            source_x: sx,
            source_y: sy,
            source_width: width,
            source_height: height,
            clip: all(1000, 1000),
            rop,
            mode: BLACKONWHITE,
            text: 0,
            background: 0xFF_FFFF,
            source_background: 0xFF_FFFF,
        }
    }

    const D: [u32; 6] = [0, 0, 0xFF_FFFF, 0xFF_FFFF, 0xF0_CC0F, 0x33_6699];
    const S: [u32; 6] = [0, 0xFF_FFFF, 0, 0xFF_FFFF, 0x0F_33F0, 0xCC_9966];

    /// The blit capture's raster operations over its fixed 32-bit values: the top byte goes with
    /// the pixel (NOTSRCCOPY, DSTINVERT, WHITENESS set it).
    #[test]
    fn the_capture_raster_operations() {
        let brush = Pattern::Solid(0x20_4080);
        let run = |rop| {
            let mut destination = Pixels::new(6, 1, 32, &D);
            let mut source = Pixels::new(6, 1, 32, &S);
            blit(
                &mut destination,
                Source::Other(&mut source),
                Some(&brush),
                &bit_blt(0, 0, 6, 1, 0, 0, rop),
            );
            destination.pixels
        };
        assert_eq!(run(SRCCOPY), S);
        assert_eq!(
            run(SRCPAINT),
            [0, 0xFF_FFFF, 0xFF_FFFF, 0xFF_FFFF, 0xFF_FFFF, 0xFF_FFFF]
        );
        assert_eq!(run(SRCAND), [0, 0, 0, 0xFF_FFFF, 0, 0]);
        assert_eq!(run(SRCERASE), [0, 0xFF_FFFF, 0, 0, 0x0F_33F0, 0xCC_9966]);
        assert_eq!(
            run(NOTSRCCOPY),
            [
                0xFFFF_FFFF,
                0xFF00_0000,
                0xFFFF_FFFF,
                0xFF00_0000,
                0xFFF0_CC0F,
                0xFF33_6699
            ]
        );
        assert_eq!(run(MERGECOPY), [0, 0x20_4080, 0, 0x20_4080, 0x80, 0]);
        assert_eq!(run(PATCOPY), [0x20_4080; 6]);
        assert_eq!(
            run(PATINVERT),
            [0x20_4080, 0x20_4080, 0xDF_BF7F, 0xDF_BF7F, 0xD0_8C8F, 0x13_2619]
        );
        assert_eq!(
            run(DSTINVERT),
            [
                0xFFFF_FFFF,
                0xFFFF_FFFF,
                0xFF00_0000,
                0xFF00_0000,
                0xFF0F_33F0,
                0xFFCC_9966
            ]
        );
        assert_eq!(run(BLACKNESS), [0; 6]);
        assert_eq!(run(WHITENESS), [u32::MAX; 6]);
    }

    /// Offsets, overlaps within one surface (either way), the surface's edge and a source origin
    /// left of the source: the pixels whose source lies outside it stay.
    #[test]
    fn offsets_overlaps_and_edges() {
        let mut destination = Pixels::new(6, 1, 32, &D);
        let mut source = Pixels::new(6, 1, 32, &S);
        let run = |destination: &mut Pixels, source: Source, b: Blit| {
            destination.pixels = D.to_vec();
            blit(destination, source, None, &b);
            destination.pixels.clone()
        };
        assert_eq!(
            run(
                &mut destination,
                Source::Other(&mut source),
                bit_blt(1, 0, 3, 1, 2, 0, SRCCOPY)
            ),
            [0, 0, 0xFF_FFFF, 0x0F_33F0, 0xF0_CC0F, 0x33_6699]
        );
        assert_eq!(
            run(
                &mut destination,
                Source::Same,
                bit_blt(1, 0, 5, 1, 0, 0, SRCCOPY)
            ),
            [0, 0, 0, 0xFF_FFFF, 0xFF_FFFF, 0xF0_CC0F]
        );
        assert_eq!(
            run(
                &mut destination,
                Source::Same,
                bit_blt(0, 0, 5, 1, 1, 0, SRCCOPY)
            ),
            [0, 0xFF_FFFF, 0xFF_FFFF, 0xF0_CC0F, 0x33_6699, 0x33_6699]
        );
        assert_eq!(
            run(
                &mut destination,
                Source::Other(&mut source),
                bit_blt(4, 0, 6, 1, 0, 0, SRCCOPY)
            ),
            [0, 0, 0xFF_FFFF, 0xFF_FFFF, 0, 0xFF_FFFF]
        );
        assert_eq!(
            run(
                &mut destination,
                Source::Other(&mut source),
                bit_blt(0, 0, 6, 1, -2, 0, SRCCOPY)
            ),
            [0, 0, 0, 0xFF_FFFF, 0, 0xFF_FFFF]
        );
    }

    /// The mono capture: a monochrome bitmap's 0 bits are the destination DC's text color and its
    /// 1 bits its background color; color to monochrome is 1 for the source DC's background color;
    /// monochrome to monochrome copies the bits.
    #[test]
    fn monochrome_conversions() {
        let row = |byte: u32| (0..8).map(|x| (byte >> (7 - x)) & 1).collect::<Vec<u32>>();
        let mut bits = row(0xA5);
        bits.extend(row(0x0F));
        let mut source = Pixels::mono(8, 2, &bits);
        let mut destination = Pixels::new(8, 2, 32, &[0xFF_FFFF; 16]);
        let mut b = bit_blt(0, 0, 8, 2, 0, 0, SRCCOPY);
        b.text = 0xFF_0000;
        b.background = 0x00_00FF;
        blit(&mut destination, Source::Other(&mut source), None, &b);
        let (r, bl) = (0xFF_0000, 0x00_00FF);
        assert_eq!(destination.pixels[..8], [bl, r, bl, r, r, bl, r, bl]);
        assert_eq!(destination.pixels[8..], [r, r, r, r, bl, bl, bl, bl]);

        let colors = [
            0x00_FF00, 0xFF_0000, 0x00_FF00, 0xFF_FFFF, 0, 0x00_FF00, 0x00_00FF, 0x00_FE00,
        ];
        let mut source = Pixels::new(8, 1, 32, &colors);
        let mut mono = Pixels::mono(8, 1, &[]);
        let mut b = bit_blt(0, 0, 8, 1, 0, 0, SRCCOPY);
        b.source_background = 0x00_FF00;
        blit(&mut mono, Source::Other(&mut source), None, &b);
        assert_eq!(mono.pixels, row(0xA4));

        let mut from = Pixels::mono(8, 1, &row(0xA5));
        let mut to = Pixels::mono(8, 1, &[]);
        let mut b = bit_blt(0, 0, 8, 1, 0, 0, SRCCOPY);
        b.text = 0xFF_0000;
        b.background = 0x00_00FF;
        blit(&mut to, Source::Other(&mut from), None, &b);
        assert_eq!(to.pixels, row(0xA5));

        // A 1-bit bitmap with a color table is no monochrome bitmap: its table's colors go.
        let mut dib = Pixels::new(8, 1, 1, &row(0xA5));
        dib.table = std::vec![0xFF_0000, 0x00_FF00];
        let mut destination = Pixels::new(8, 1, 32, &[]);
        blit(
            &mut destination,
            Source::Other(&mut dib),
            None,
            &bit_blt(0, 0, 8, 1, 0, 0, SRCCOPY),
        );
        let (g, r) = (0x00_FF00, 0xFF_0000);
        assert_eq!(destination.pixels, [g, r, g, r, r, g, r, g]);
    }

    fn stretch(
        (x, y, width, height): (i32, i32, i32, i32),
        (sx, sy, sw, sh): (i32, i32, i32, i32),
        mode: u32,
    ) -> Blit {
        Blit {
            source_x: sx,
            source_y: sy,
            source_width: sw,
            source_height: sh,
            mode,
            ..bit_blt(x, y, width, height, 0, 0, SRCCOPY)
        }
    }

    /// The stretch capture: an 8x2 color source shrunk to 4x1 under each mode, a monochrome 8x1
    /// shrunk to 4x1, 3x2 enlarged to 7x5, and mirroring by either extent.
    #[test]
    fn stretching_under_the_modes() {
        let source_pixels = [
            0xFF_0000, 0x00_FF00, 0x00_00FF, 0xFF_FFFF, 0, 0xFF_00FF, 0x80_8080, 0x00_FFFF,
            0x0F_0F0F, 0xF0_F0F0, 0x00_FF00, 0xFF_0000, 0xFF_FFFF, 0, 0x12_3456, 0x65_4321,
        ];
        let shrink = |mode| {
            let mut source = Pixels::new(8, 2, 32, &source_pixels);
            let mut destination = Pixels::new(4, 1, 32, &[0x77_7777; 4]);
            blit(
                &mut destination,
                Source::Other(&mut source),
                None,
                &stretch((0, 0, 4, 1), (0, 0, 8, 2), mode),
            );
            destination.pixels
        };
        assert_eq!(shrink(BLACKONWHITE), [0; 4]);
        assert_eq!(
            shrink(WHITEONBLACK),
            [0xFF_FFFF, 0xFF_FFFF, 0xFF_FFFF, 0xF7_FFFF]
        );
        assert_eq!(shrink(COLORONCOLOR), [0xF0_F0F0, 0xFF_0000, 0, 0x65_4321]);

        let b4 = [1, 0, 1, 1, 0, 1, 0, 0];
        let mono = |mode| {
            let mut source = Pixels::mono(8, 1, &b4);
            let mut destination = Pixels::mono(4, 1, &[]);
            blit(
                &mut destination,
                Source::Other(&mut source),
                None,
                &stretch((0, 0, 4, 1), (0, 0, 8, 1), mode),
            );
            destination.pixels
        };
        assert_eq!(mono(BLACKONWHITE), [0, 1, 0, 0]);
        assert_eq!(mono(WHITEONBLACK), [1, 1, 1, 0]);
        assert_eq!(mono(COLORONCOLOR), [0, 1, 1, 0]);

        let small: Vec<u32> = (0..6)
            .map(|i| 0x11_0000 * (i / 3 + 1) + 0x11 * (i % 3 + 1))
            .collect();
        let mut source = Pixels::new(3, 2, 32, &small);
        let mut big = Pixels::new(7, 5, 32, &[]);
        blit(
            &mut big,
            Source::Other(&mut source),
            None,
            &stretch((0, 0, 7, 5), (0, 0, 3, 2), COLORONCOLOR),
        );
        assert_eq!(
            big.pixels[..7],
            [0x11_0011, 0x11_0011, 0x11_0022, 0x11_0022, 0x11_0022, 0x11_0033, 0x11_0033]
        );
        assert_eq!(big.pixels[14], 0x22_0011, "row 2 is the source's second");

        let mirror = |destination_rect, source_rect| {
            let mut source = Pixels::new(8, 2, 32, &source_pixels);
            let mut destination = Pixels::new(4, 1, 32, &[0x77_7777; 4]);
            blit(
                &mut destination,
                Source::Other(&mut source),
                None,
                &stretch(destination_rect, source_rect, COLORONCOLOR),
            );
            destination.pixels
        };
        let reversed = [0xFF_FFFF, 0x00_00FF, 0x00_FF00, 0xFF_0000];
        assert_eq!(mirror((3, 0, -4, 1), (0, 0, 4, 1)), reversed);
        assert_eq!(mirror((0, 0, 4, 1), (3, 0, -4, 1)), reversed);
    }

    /// PatBlt's path: no source, a pattern's pixels from its origin.
    #[test]
    fn no_source_paints_the_pattern() {
        let mut destination = Pixels::new(4, 1, 32, &[1, 2, 3, 4]);
        let mut b = bit_blt(0, 0, 4, 1, 0, 0, PATCOPY);
        b.clip = all(3, 1);
        blit(
            &mut destination,
            Source::None,
            Some(&Pattern::Solid(0x12_3456)),
            &b,
        );
        assert_eq!(destination.pixels, [0x12_3456, 0x12_3456, 0x12_3456, 4]);
        // A palettized surface takes the pattern's nearest entry.
        let mut eight = Pixels::new(2, 1, 8, &[]);
        eight.table = std::vec![0, 0xFF_0000, 0x00_FF00, 0xFF_FFFF];
        blit(
            &mut eight,
            Source::None,
            Some(&Pattern::Solid(0xC0_1010)),
            &bit_blt(0, 0, 2, 1, 0, 0, PATCOPY),
        );
        assert_eq!(eight.pixels, [1, 1]);
    }
}
