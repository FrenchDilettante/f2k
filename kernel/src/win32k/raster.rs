//! The rasterizer: text in the built-in font ([`super::font`]) and single pixels, drawn into the
//! framebuffer through its [`PixelMemory`] seam, every pixel clipped to a clipping region. The DC
//! services ([`super::dc`]) hand it a DC's state; the host tests drive it against a fake pixel
//! memory and assert exact pixels.
//!
//! Text is ExtTextOutW's: each character's glyph drawn with its cell's top left at the pen, the
//! pen moving a cell's width on (or the caller's advance for the character); the glyph's pixels in
//! the text color, the cell's others in the background color when the background mode is OPAQUE
//! (TRANSPARENT leaves them as they were); ETO_OPAQUE fills the rectangle with the background
//! color first, whatever the mode, and ETO_CLIPPED clips the text to the rectangle too.
//!
//! Fills are PatBlt's ([`pat_blt`]): a rectangle's pixels combined with a pattern, a brush's
//! (one color, or an 8x8 monochrome pattern aligned to the brush origin), by a sourceless raster
//! operation, every pixel clipped.
//!
//! The colors come as COLORREFs (`0x00BBGGRR`, the high byte's palette flags ignored: the
//! framebuffer is 32 bpp) and go to the framebuffer as its `0xRRGGBB` ([`screen_rgb`]).

use rtl::gdi::{
    apply_rop,
    rop_uses_destination,
    Rect,
    CLR_INVALID,
    ETO_CLIPPED,
    ETO_OPAQUE,
    RGB_MASK,
};

use super::font;
use crate::hw::vbe::{Framebuffer, PixelMemory};

/// The rectangle both `a` and `b` cover (empty when they do not meet).
pub fn intersect(a: Rect, b: Rect) -> Rect {
    Rect {
        left: a.left.max(b.left),
        top: a.top.max(b.top),
        right: a.right.min(b.right),
        bottom: a.bottom.min(b.bottom),
    }
}

/// Whether (`x`, `y`) lies in `rect` (its right and bottom edges outside it).
pub fn contains(rect: &Rect, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

/// The framebuffer's `0xRRGGBB` for a COLORREF (`0x00BBGGRR`; its high byte, a palette's flags,
/// ignored).
pub fn screen_rgb(color: u32) -> u32 {
    ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF)
}

/// The COLORREF of the framebuffer's `0xRRGGBB` ([`screen_rgb`]'s inverse).
pub fn colorref(rgb: u32) -> u32 {
    screen_rgb(rgb)
}

/// One ExtTextOutW's drawing: where it may draw, where, and in which colors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextOut {
    /// What every pixel is clipped to: the DC's clipping region, and the rectangle under
    /// ETO_CLIPPED.
    clip: Rect,
    /// The rectangle ETO_OPAQUE fills with the background color first, clipped; none without it.
    fill: Option<Rect>,
    /// The row of the cells' top.
    y: i32,
    /// The framebuffer's colors: the glyphs', the fill's (the background color), and the cells'
    /// background (the background color under OPAQUE; none, the cells left, under TRANSPARENT).
    text: u32,
    fill_color: u32,
    background: Option<u32>,
}

impl TextOut {
    /// The drawing ExtTextOut's `options` and `rect` ask, inside the DC's clipping region `clip`,
    /// in its `text_color` and `bk_color` (COLORREFs), the cells' background filled when `opaque`
    /// (the background mode OPAQUE), the cells' top at `y`. ETO_OPAQUE and ETO_CLIPPED take effect
    /// only with a rectangle.
    pub fn new(
        clip: Rect,
        text_color: u32,
        bk_color: u32,
        opaque: bool,
        y: i32,
        options: u32,
        rect: Option<Rect>,
    ) -> Self {
        let clipped = rect.filter(|_| options & ETO_CLIPPED != 0);
        TextOut {
            clip: clipped.map_or(clip, |rect| intersect(clip, rect)),
            fill: rect
                .filter(|_| options & ETO_OPAQUE != 0)
                .map(|rect| intersect(clip, rect)),
            y,
            text: screen_rgb(text_color),
            fill_color: screen_rgb(bk_color),
            background: opaque.then(|| screen_rgb(bk_color)),
        }
    }

    /// The ETO_OPAQUE fill, before any glyph: the background color, whatever the background
    /// mode.
    pub fn fill_background<M: PixelMemory>(&self, screen: &mut Framebuffer<M>) {
        if let Some(rect) = self.fill {
            for y in rect.top..rect.bottom {
                for x in rect.left..rect.right {
                    screen.put_pixel(x as usize, y as usize, self.fill_color);
                }
            }
        }
    }

    /// Draw `units` from the pen's column `pen`, each character's cell `advances[i]` after the
    /// one before (its own cell's width without them); the pen's column after them.
    pub fn draw<M: PixelMemory>(
        &self,
        screen: &mut Framebuffer<M>,
        pen: i32,
        units: &[u16],
        advances: Option<&[i32]>,
    ) -> i32 {
        let mut pen = pen;
        for (index, &unit) in units.iter().enumerate() {
            self.draw_glyph(screen, pen, font::glyph(font::glyph_index(unit)));
            pen = pen.saturating_add(advance(advances, index));
        }
        pen
    }

    /// Draw one glyph with its cell's top left at (`x`, the text's row).
    fn draw_glyph<M: PixelMemory>(&self, screen: &mut Framebuffer<M>, x: i32, glyph: &[u8; 16]) {
        for (row, &bits) in glyph.iter().enumerate() {
            let y = self.y.saturating_add(row as i32);
            for column in 0..font::WIDTH {
                let x = x.saturating_add(column);
                if !contains(&self.clip, x, y) {
                    continue;
                }
                let color = if bits & (0x80 >> column) != 0 {
                    self.text
                } else if let Some(background) = self.background {
                    background
                } else {
                    continue;
                };
                screen.put_pixel(x as usize, y as usize, color);
            }
        }
    }
}

/// The pen's column after `count` characters from `pen` ([`TextOut::draw`]'s, without drawing).
pub fn advanced(pen: i32, count: usize, advances: Option<&[i32]>) -> i32 {
    (0..count).fold(pen, |pen, index| {
        pen.saturating_add(advance(advances, index))
    })
}

/// Character `index`'s advance: its `Dx` entry, or the font's cell width.
fn advance(advances: Option<&[i32]>, index: usize) -> i32 {
    advances.map_or(font::WIDTH, |advances| advances[index])
}

/// What a fill paints with: a brush as it draws (its colors the framebuffer's `0xRRGGBB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// One color.
    Solid(u32),
    /// An 8x8 monochrome pattern: `rows[y]`'s bit `7 - x` is the pixel at (x, y) from `origin`
    /// (the brush origin, in screen coordinates), `one` where it is set and `zero` where it is
    /// clear, repeated across the screen.
    Mono {
        rows: [u8; 8],
        origin: (i32, i32),
        one: u32,
        zero: u32,
    },
}

impl Pattern {
    /// The pattern's color at the screen's (`x`, `y`).
    pub fn at(&self, x: i32, y: i32) -> u32 {
        match *self {
            Pattern::Solid(color) => color,
            Pattern::Mono {
                rows,
                origin,
                one,
                zero,
            } => {
                let row = rows[(y.wrapping_sub(origin.1) & 7) as usize];
                if row & (0x80 >> (x.wrapping_sub(origin.0) & 7)) != 0 {
                    one
                } else {
                    zero
                }
            }
        }
    }
}

/// PatBlt on `screen`: every pixel of `rect` inside `clip` (both screen coordinates, `clip` within
/// the screen) combined with `pattern` by the sourceless raster operation `rop` (its result for a
/// source of zero), the pattern taken as black when there is none (a raster operation that reads
/// none). The destination is read only when the operation reads it.
pub fn pat_blt<M: PixelMemory>(
    screen: &mut Framebuffer<M>,
    clip: Rect,
    rect: Rect,
    rop: u32,
    pattern: Option<&Pattern>,
) {
    let area = intersect(clip, rect);
    let reads = rop_uses_destination(rop);
    for y in area.top..area.bottom {
        for x in area.left..area.right {
            let paint = pattern.map_or(0, |pattern| pattern.at(x, y));
            let destination = if reads {
                screen.get_pixel(x as usize, y as usize).unwrap_or(0)
            } else {
                0
            };
            let color = apply_rop(rop, paint, destination) & RGB_MASK;
            screen.put_pixel(x as usize, y as usize, color);
        }
    }
}

/// SetPixel on `screen` (none: the graphics mode is not set) inside `clip`: the COLORREF set (the
/// one asked for, its RGB part), or CLR_INVALID outside the clipping region (the screen
/// untouched).
pub fn set_pixel_on<M: PixelMemory>(
    screen: Option<&mut Framebuffer<M>>,
    clip: &Rect,
    x: i32,
    y: i32,
    color: u32,
) -> u32 {
    match screen {
        Some(screen) if contains(clip, x, y) => {
            screen.put_pixel(x as usize, y as usize, screen_rgb(color));
            color & RGB_MASK
        }
        _ => CLR_INVALID,
    }
}

/// GetPixel on `screen` inside `clip`: the pixel's COLORREF, or CLR_INVALID outside the clipping
/// region.
pub fn get_pixel_on<M: PixelMemory>(
    screen: Option<&mut Framebuffer<M>>,
    clip: &Rect,
    x: i32,
    y: i32,
) -> u32 {
    match screen {
        Some(screen) if contains(clip, x, y) => screen
            .get_pixel(x as usize, y as usize)
            .map_or(CLR_INVALID, colorref),
        _ => CLR_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::gdi::{Rect, CLR_INVALID, ETO_CLIPPED, ETO_OPAQUE};

    use super::*;
    use crate::hw::vbe::Geometry;

    /// A screen's pixel memory: 32-bit pixels, packed.
    struct Memory(Vec<u32>);

    impl PixelMemory for Memory {
        fn store(&mut self, offset: usize, value: u32) {
            self.0[offset / 4] = value;
        }

        fn load(&mut self, offset: usize) -> u32 {
            self.0[offset / 4]
        }
    }

    /// The screen's background before anything is drawn: the desktop's blue.
    const DESKTOP: u32 = 0x003A_6EA5;

    fn desktop(width: usize, height: usize) -> Framebuffer<Memory> {
        let mut screen = Framebuffer::new(
            Memory(std::vec![0; width * height]),
            Geometry::packed(width, height),
        );
        screen.clear(DESKTOP);
        screen
    }

    /// The screen's pixel at (`x`, `y`), as `0xRRGGBB`.
    fn at(screen: &mut Framebuffer<Memory>, x: usize, y: usize) -> u32 {
        screen.get_pixel(x, y).unwrap()
    }

    /// Every pixel that is not the desktop's, as (x, y, `0xRRGGBB`), row by row.
    fn drawn(screen: &mut Framebuffer<Memory>) -> Vec<(usize, usize, u32)> {
        let (width, height) = (screen.geometry.width, screen.geometry.height);
        let mut found = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let pixel = at(screen, x, y);
                if pixel != DESKTOP {
                    found.push((x, y, pixel));
                }
            }
        }
        found
    }

    /// The pixels `text` draws at (`x`, `y`) in the font: its glyphs' inked pixels in `ink`, the
    /// cells' others in `paper` when there is one, those inside `clip` alone, row by row.
    fn expected(
        text: &str,
        x: i32,
        y: i32,
        ink: u32,
        paper: Option<u32>,
        clip: Rect,
    ) -> Vec<(usize, usize, u32)> {
        let mut pixels = Vec::new();
        for (index, unit) in text.encode_utf16().enumerate() {
            let glyph = font::glyph(font::glyph_index(unit));
            for (row, bits) in glyph.iter().enumerate() {
                for column in 0..8 {
                    let (px, py) = (x + 8 * index as i32 + column, y + row as i32);
                    let color = if bits & (0x80 >> column) != 0 {
                        Some(ink)
                    } else {
                        paper
                    };
                    if let Some(color) = color.filter(|_| contains(&clip, px, py)) {
                        pixels.push((px as usize, py as usize, color));
                    }
                }
            }
        }
        pixels.sort_by_key(|&(x, y, _)| (y, x));
        pixels
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// ExtTextOut's drawing in a DC's default colors: black on white, OPAQUE.
    fn black_on_white(clip: Rect, y: i32, options: u32, rect: Option<Rect>) -> TextOut {
        TextOut::new(clip, 0x00_0000, 0xFF_FFFF, true, y, options, rect)
    }

    /// COLORREFs (0x00BBGGRR) become the framebuffer's 0xRRGGBB and back.
    #[test]
    fn colors_convert_to_the_framebuffers() {
        assert_eq!(screen_rgb(0x0003_0201), 0x0001_0203);
        assert_eq!(screen_rgb(0x0000_00FF), 0x00FF_0000, "red");
        assert_eq!(screen_rgb(0x00FF_0000), 0x0000_00FF, "blue");
        assert_eq!(
            screen_rgb(0x0100_0005),
            0x0005_0000,
            "the flags byte ignored"
        );
        assert_eq!(colorref(0x0001_0203), 0x0003_0201);
    }

    /// "Hi" at (5, 5), OPAQUE: every pixel of the two cells drawn, the glyphs' in the text color
    /// and the rest in the background color, nothing outside them; the pen ends 16 columns on.
    #[test]
    fn text_draws_exact_pixels() {
        let mut screen = desktop(40, 30);
        let clip = rect(0, 0, 40, 30);
        let text = black_on_white(clip, 5, 0, None);
        assert_eq!(text.draw(&mut screen, 5, &units("Hi"), None), 21);
        let clip = rect(0, 0, 40, 30);
        assert_eq!(
            drawn(&mut screen),
            expected("Hi", 5, 5, 0x00_0000, Some(0xFF_FFFF), clip)
        );
        // By hand: H's third row is ##...##. (its cell's columns 5 to 12).
        assert_eq!(at(&mut screen, 5, 7), 0x00_0000);
        assert_eq!(at(&mut screen, 6, 7), 0x00_0000);
        assert_eq!(at(&mut screen, 7, 7), 0xFF_FFFF);
        assert_eq!(at(&mut screen, 10, 7), 0x00_0000);
        assert_eq!(at(&mut screen, 12, 7), 0xFF_FFFF, "the cell's last column");
        assert_eq!(at(&mut screen, 5, 5), 0xFF_FFFF, "the cell's top row");
        assert_eq!(at(&mut screen, 4, 7), DESKTOP, "left of the text");
        assert_eq!(at(&mut screen, 21, 7), DESKTOP, "right of the text");
        assert_eq!(at(&mut screen, 5, 21), DESKTOP, "below the cells");
        assert_eq!(drawn(&mut screen).len(), 2 * 8 * 16);
    }

    /// TRANSPARENT draws the glyphs' pixels alone, in the text color (red here, from its
    /// COLORREF); the cells' others keep what was there.
    #[test]
    fn transparent_text_leaves_the_background() {
        let mut screen = desktop(40, 30);
        let clip = rect(0, 0, 40, 30);
        TextOut::new(clip, 0x00_00FF, 0xFF_FFFF, false, 5, 0, None).draw(
            &mut screen,
            5,
            &units("Hi"),
            None,
        );
        let clip = rect(0, 0, 40, 30);
        assert_eq!(
            drawn(&mut screen),
            expected("Hi", 5, 5, 0xFF_0000, None, clip)
        );
        assert_eq!(at(&mut screen, 7, 7), DESKTOP, "between H's strokes");
    }

    /// Text that crosses the screen's or the DC's edges is clipped at each of them: the pixels
    /// inside the clipping region alone, nothing written outside (a write past the memory would
    /// panic the fake).
    #[test]
    fn text_is_clipped_at_every_edge() {
        let screen_clip = rect(0, 0, 24, 20);
        for (x, y) in [(-4, 2), (2, -6), (18, 2), (2, 10), (-6, -6), (20, 16)] {
            let mut screen = desktop(24, 20);
            let clip = rect(0, 0, 24, 20);
            black_on_white(clip, y, 0, None).draw(&mut screen, x, &units("AB"), None);
            assert_eq!(
                drawn(&mut screen),
                expected("AB", x, y, 0x00_0000, Some(0xFF_FFFF), screen_clip),
                "at ({x}, {y})"
            );
        }
        // A DC whose clipping region is smaller than the screen: nothing past it.
        let mut screen = desktop(24, 20);
        let clip = rect(3, 4, 10, 12);
        black_on_white(clip, 0, 0, None).draw(&mut screen, 0, &units("AB"), None);
        assert_eq!(
            drawn(&mut screen),
            expected("AB", 0, 0, 0x00_0000, Some(0xFF_FFFF), clip)
        );
        // Far outside every edge: nothing at all.
        let mut screen = desktop(24, 20);
        let clip = rect(0, 0, 24, 20);
        for (x, y) in [(i32::MIN, 0), (0, i32::MAX - 3), (100, 100), (-100, -100)] {
            black_on_white(clip, y, 0, None).draw(&mut screen, x, &units("AB"), None);
        }
        assert!(drawn(&mut screen).is_empty());
    }

    /// ETO_OPAQUE fills the rectangle with the background color first (TRANSPARENT or not), then
    /// the text; ETO_CLIPPED clips the text to the rectangle; neither without a rectangle.
    #[test]
    fn ext_text_out_fills_and_clips_to_its_rectangle() {
        let mut screen = desktop(40, 30);
        let clip = rect(0, 0, 40, 30);
        let area = rect(0, 2, 30, 22);
        let text = TextOut::new(
            clip,
            0x00_0000,
            0x00FF_0000,
            false,
            4,
            ETO_OPAQUE,
            Some(area),
        );
        text.fill_background(&mut screen);
        text.draw(&mut screen, 1, &units("abc"), None);
        assert_eq!(
            at(&mut screen, 0, 2),
            0x00_00FF,
            "the fill, in the background color"
        );
        assert_eq!(at(&mut screen, 29, 21), 0x00_00FF);
        assert_eq!(
            at(&mut screen, 30, 21),
            DESKTOP,
            "the fill stops at the rectangle"
        );
        assert_eq!(at(&mut screen, 0, 22), DESKTOP);
        let inked = expected("abc", 1, 4, 0x00_0000, None, rect(0, 0, 40, 30));
        for &(x, y, color) in &inked {
            assert_eq!(at(&mut screen, x, y), color);
        }

        let mut screen = desktop(40, 30);
        let clip = rect(0, 0, 40, 30);
        let narrow = rect(2, 6, 12, 14);
        let text = black_on_white(clip, 4, ETO_CLIPPED, Some(narrow));
        text.fill_background(&mut screen);
        text.draw(&mut screen, 1, &units("abc"), None);
        assert_eq!(
            drawn(&mut screen),
            expected("abc", 1, 4, 0x00_0000, Some(0xFF_FFFF), narrow)
        );

        let mut screen = desktop(40, 30);
        let text = black_on_white(clip, 4, ETO_OPAQUE | ETO_CLIPPED, None);
        text.fill_background(&mut screen);
        assert!(drawn(&mut screen).is_empty(), "no rectangle, no fill");
    }

    /// Wide characters beyond ASCII draw their code page 437 glyphs; the advances, when given,
    /// place each cell; the pen moves without a screen as it would with one.
    #[test]
    fn wide_strings_and_advances() {
        let mut screen = desktop(64, 20);
        let clip = rect(0, 0, 64, 20);
        let text = black_on_white(clip, 0, 0, None);
        let wide = [0x00E9u16, 0x2588, 0x4E00];
        assert_eq!(text.draw(&mut screen, 0, &wide, None), 24);
        assert_eq!(
            drawn(&mut screen),
            expected(
                "\u{E9}\u{2588}?",
                0,
                0,
                0x00_0000,
                Some(0xFF_FFFF),
                rect(0, 0, 64, 20)
            )
        );
        assert_eq!(
            at(&mut screen, 8, 0),
            0x00_0000,
            "the full block inks its every pixel"
        );
        assert_eq!(at(&mut screen, 15, 15), 0x00_0000);

        let mut screen = desktop(64, 20);
        let advances = [20, 3];
        assert_eq!(text.draw(&mut screen, 2, &units("AB"), Some(&advances)), 25);
        assert_eq!(advanced(2, 2, Some(&advances)), 25);
        assert_eq!(advanced(2, 3, None), 26);
        let all = rect(0, 0, 64, 20);
        let mut placed = expected("A", 2, 0, 0x00_0000, Some(0xFF_FFFF), all);
        placed.extend(expected("B", 22, 0, 0x00_0000, Some(0xFF_FFFF), all));
        placed.sort_by_key(|&(x, y, _)| (y, x));
        assert_eq!(drawn(&mut screen), placed);
    }

    /// SetPixel and GetPixel inside a clipping region: the guidc capture's RGB(1,2,3) at (100, 100)
    /// answered and read back as set; outside the clipping region, or with no screen (the mode
    /// not set), CLR_INVALID and nothing written.
    #[test]
    fn pixels_inside_the_clip() {
        let mut screen = desktop(640, 480);
        let clip = rect(0, 0, 640, 480);
        assert_eq!(
            set_pixel_on(Some(&mut screen), &clip, 100, 100, 0x0003_0201),
            0x0003_0201
        );
        assert_eq!(at(&mut screen, 100, 100), 0x0001_0203, "stored as 0xRRGGBB");
        assert_eq!(
            get_pixel_on(Some(&mut screen), &clip, 100, 100),
            0x0003_0201
        );
        assert_eq!(
            get_pixel_on(Some(&mut screen), &clip, 0, 0),
            colorref(DESKTOP)
        );
        for (x, y) in [(-1, 0), (0, -1), (640, 0), (0, 480)] {
            assert_eq!(set_pixel_on(Some(&mut screen), &clip, x, y, 0), CLR_INVALID);
            assert_eq!(get_pixel_on(Some(&mut screen), &clip, x, y), CLR_INVALID);
        }
        assert_eq!(drawn(&mut screen), [(100, 100, 0x0001_0203)]);
        assert_eq!(
            set_pixel_on(Some(&mut screen), &rect(0, 0, 0, 0), 5, 5, 0),
            CLR_INVALID
        );
        assert_eq!(set_pixel_on::<Memory>(None, &clip, 5, 5, 0), CLR_INVALID);
        assert_eq!(get_pixel_on::<Memory>(None, &clip, 5, 5), CLR_INVALID);
    }

    /// The screen's pixels in `area` as rows of characters, each pixel's character the one
    /// `legend` gives its color ('?' for a color not in it).
    fn picture(
        screen: &mut Framebuffer<Memory>,
        area: Rect,
        legend: &[(u32, char)],
    ) -> Vec<std::string::String> {
        (area.top..area.bottom)
            .map(|y| {
                (area.left..area.right)
                    .map(|x| {
                        let pixel = at(screen, x as usize, y as usize);
                        legend
                            .iter()
                            .find(|&&(color, _)| color == pixel)
                            .map_or('?', |&(_, c)| c)
                    })
                    .collect()
            })
            .collect()
    }

    const RED: u32 = 0x00FF_0000;
    const WHITE: u32 = 0x00FF_FFFF;
    const BLACK: u32 = 0x0000_0000;

    /// PATCOPY paints the rectangle's pixels in the pattern, its right and bottom edges outside
    /// it, exactly; BLACKNESS and WHITENESS paint black and white without a pattern.
    #[test]
    fn a_fill_paints_its_rectangle_exactly() {
        let mut screen = desktop(8, 6);
        let all = rect(0, 0, 8, 6);
        pat_blt(
            &mut screen,
            all,
            rect(1, 1, 5, 3),
            rtl::gdi::PATCOPY,
            Some(&Pattern::Solid(RED)),
        );
        pat_blt(
            &mut screen,
            all,
            rect(6, 0, 8, 2),
            rtl::gdi::BLACKNESS,
            None,
        );
        pat_blt(
            &mut screen,
            all,
            rect(6, 4, 7, 6),
            rtl::gdi::WHITENESS,
            None,
        );
        let legend = [(DESKTOP, '.'), (RED, 'R'), (BLACK, 'K'), (WHITE, 'W')];
        assert_eq!(
            picture(&mut screen, all, &legend),
            [
                "......KK", //
                ".RRRR.KK", ".RRRR...", "........", "......W.", "......W.",
            ]
        );
    }

    /// A fill is clipped to the clipping region and the screen: nothing outside either is written
    /// (a write past the fake's memory would panic), and an empty or inverted rectangle paints
    /// nothing.
    #[test]
    fn a_fill_is_clipped() {
        let mut screen = desktop(8, 6);
        let solid = Pattern::Solid(RED);
        let clip = rect(2, 1, 6, 5);
        pat_blt(
            &mut screen,
            clip,
            rect(-10, -10, 100, 100),
            rtl::gdi::PATCOPY,
            Some(&solid),
        );
        let legend = [(DESKTOP, '.'), (RED, 'R')];
        assert_eq!(
            picture(&mut screen, rect(0, 0, 8, 6), &legend),
            [
                "........", //
                "..RRRR..", "..RRRR..", "..RRRR..", "..RRRR..", "........",
            ]
        );
        let mut screen = desktop(8, 6);
        let all = rect(0, 0, 8, 6);
        pat_blt(
            &mut screen,
            all,
            rect(5, 5, 2, 2),
            rtl::gdi::PATCOPY,
            Some(&solid),
        );
        pat_blt(
            &mut screen,
            all,
            rect(3, 3, 3, 6),
            rtl::gdi::PATCOPY,
            Some(&solid),
        );
        pat_blt(
            &mut screen,
            all,
            rect(i32::MIN, 0, i32::MIN + 2, 2),
            rtl::gdi::PATCOPY,
            Some(&solid),
        );
        assert!(drawn(&mut screen).is_empty());
    }

    /// DSTINVERT inverts each pixel (twice: as it was); PATINVERT XORs the pattern in, the
    /// destination read before it is written.
    #[test]
    fn the_inverting_operations_read_the_destination() {
        let mut screen = desktop(4, 2);
        let all = rect(0, 0, 4, 2);
        pat_blt(
            &mut screen,
            all,
            rect(0, 0, 2, 1),
            rtl::gdi::DSTINVERT,
            None,
        );
        assert_eq!(at(&mut screen, 0, 0), !DESKTOP & 0x00FF_FFFF);
        assert_eq!(at(&mut screen, 2, 0), DESKTOP);
        pat_blt(
            &mut screen,
            all,
            rect(0, 0, 2, 1),
            rtl::gdi::DSTINVERT,
            None,
        );
        assert!(drawn(&mut screen).is_empty(), "inverted back");
        let red = Pattern::Solid(RED);
        pat_blt(
            &mut screen,
            all,
            rect(1, 0, 3, 2),
            rtl::gdi::PATINVERT,
            Some(&red),
        );
        assert_eq!(at(&mut screen, 1, 1), DESKTOP ^ RED);
        pat_blt(
            &mut screen,
            all,
            rect(1, 0, 3, 2),
            rtl::gdi::PATINVERT,
            Some(&red),
        );
        assert!(drawn(&mut screen).is_empty(), "XORed back");
    }

    /// A monochrome pattern repeats every 8 pixels from the brush origin: the gray brush's
    /// checkerboard, its set bits in `one`, PATINVERTed with white set bits and black clear ones,
    /// inverts every other pixel, the origin's own among them.
    #[test]
    fn a_pattern_repeats_from_its_origin() {
        let checker = Pattern::Mono {
            rows: rtl::gdi::HALFTONE_ROWS,
            origin: (1, 0),
            one: WHITE,
            zero: BLACK,
        };
        assert_eq!(checker.at(1, 0), WHITE, "the origin's pixel is set");
        assert_eq!(checker.at(2, 0), BLACK);
        assert_eq!(checker.at(1, 1), BLACK);
        assert_eq!(checker.at(9, 8), WHITE, "8 pixels on");
        assert_eq!(checker.at(-7, -8), WHITE, "and 8 pixels back");
        let mut screen = desktop(6, 3);
        let all = rect(0, 0, 6, 3);
        pat_blt(&mut screen, all, all, rtl::gdi::PATINVERT, Some(&checker));
        let inverted = !DESKTOP & 0x00FF_FFFF;
        let legend = [(DESKTOP, '.'), (inverted, 'X')];
        assert_eq!(
            picture(&mut screen, all, &legend),
            [
                ".X.X.X", //
                "X.X.X.", ".X.X.X",
            ]
        );
        let stripes = Pattern::Mono {
            rows: [0xF0; 8],
            origin: (0, 0),
            one: RED,
            zero: BLACK,
        };
        let mut screen = desktop(10, 1);
        let all = rect(0, 0, 10, 1);
        pat_blt(&mut screen, all, all, rtl::gdi::PATCOPY, Some(&stripes));
        let legend = [(RED, 'R'), (BLACK, 'K')];
        assert_eq!(picture(&mut screen, all, &legend), ["RRRRKKKKRR"]);
    }

    /// The rectangles' meeting and membership, the right and bottom edges outside.
    #[test]
    fn rectangles_meet_and_hold() {
        assert_eq!(
            intersect(rect(0, 0, 10, 10), rect(5, -5, 20, 6)),
            rect(5, 0, 10, 6)
        );
        let apart = intersect(rect(0, 0, 4, 4), rect(6, 6, 8, 8));
        assert!(!contains(&apart, 6, 6) && !contains(&apart, 3, 3), "empty");
        assert!(contains(&rect(0, 0, 2, 2), 1, 1));
        assert!(!contains(&rect(0, 0, 2, 2), 2, 1));
        assert!(!contains(&rect(0, 0, 2, 2), 1, 2));
    }
}
