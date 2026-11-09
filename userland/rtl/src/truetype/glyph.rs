//! A glyph at a size, as GetGlyphOutline answers GGO_METRICS and GGO_BITMAP: its GLYPHMETRICS and
//! its monochrome bitmap, from the font's embedded strike at that size when the strike holds the
//! glyph, else from its outline, unhinted.
//!
//! The capture of Windows 2000 on the fixtures' font settles the choices made here:
//! - at a size the font has a strike for (lfHeight -11 is the 11-ppem strike), GetGlyphOutline
//!   answers from the strike: its bitmaps and metrics are the strike's, bit for bit; a glyph the
//!   strike leaves out (the missing glyph, the space) comes from the outline;
//! - from the outline, the black box is the bounding box of the outline's points (control points
//!   among them) with each edge rounded to the nearest whole pixel (at least one pixel each way),
//!   its origin the box's left and top;
//! - the cell increment is the advance width rounded twice, to 26.6 and then to a whole pixel
//!   (lfHeight -24's 'i' advances 469 units, 5.496 pixels: 352/64, 5.5, then 6); a font with an
//!   `hdmx` record for the size gives its width instead, the advance its instructions make, which
//!   this engine does not run;
//! - a glyph with no contours is a 1-by-1 black box at the origin, with no bitmap;
//! - a font with no control-value program scan-converts without dropout control, the graphics
//!   state's default (the capture's missing glyph at 11 ppem loses its top stroke, thinner than a
//!   pixel and between two rows' centres).
//!
//! The outline's own x = 0 is the origin: the glyph's left side bearing is taken to be its x_min,
//! as fonts that set head's flag bit 1 promise.

use super::embedded::StrikeGlyph;
use super::glyf::{Outline, Point};
use super::raster::{self, Crossing, Dropout, Target};
use super::scale::{round_pixel, Scale};
use super::{Error, Font, Tag};

/// GLYPHMETRICS, as wingdi.h lays it out: the black box's size, its top-left corner from the
/// origin (y up), and the advance to the next glyph's origin.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlyphMetrics {
    pub black_box_x: u32,
    pub black_box_y: u32,
    pub origin_x: i32,
    pub origin_y: i32,
    pub cell_inc_x: i16,
    pub cell_inc_y: i16,
}

// SAFETY: a #[repr(C)] structure of 32- and 16-bit integers, its two 16-bit fields last and
// filling its final 32 bits, so no padding; any bits make one.
unsafe impl crate::pod::Pod for GlyphMetrics {}

/// Where a glyph's bitmap came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The font's embedded strike at the size.
    Strike,
    /// The outline, scan-converted.
    Outline,
}

/// How to render: the size, and the engine's two choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The em height in pixels ([`ppem_for_height`] makes it from a LOGFONT's height).
    pub ppem: u16,
    /// Whether a strike at the size answers for the glyphs it holds, as Windows 2000's
    /// GetGlyphOutline does.
    pub use_strikes: bool,
    /// The dropout control for outlines; None for the font's own default.
    pub dropout: Option<Dropout>,
}

impl Options {
    /// Windows 2000's choices at `ppem`: strikes first, and the font's own dropout control.
    pub fn new(ppem: u16) -> Self {
        Self {
            ppem,
            use_strikes: true,
            dropout: None,
        }
    }
}

/// The buffers the caller lends the rasteriser: an outline's points and contour ends (a glyph with
/// more is [`Error::BufferTooSmall`]), and one scan line's crossings. A few hundred points, a few
/// dozen contours and a few hundred crossings serve any ordinary font.
pub struct Workspace<'w> {
    pub points: &'w mut [Point],
    pub contour_ends: &'w mut [u16],
    pub crossings: &'w mut [Crossing],
}

/// A rendered glyph: its metrics, where its bitmap came from, and the bitmap's size in bytes
/// (GetGlyphOutline's answer for GGO_BITMAP: 0 for a glyph with nothing to draw).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub metrics: GlyphMetrics,
    pub source: Source,
    pub size: usize,
}

/// The bytes of a GGO_BITMAP row `width` pixels wide: whole 32-bit words.
pub fn stride(width: u32) -> usize {
    width.div_ceil(32) as usize * 4
}

/// The ppem a LOGFONT height asks for: a negative height is the em height in pixels; a positive
/// one is the cell height, the ascent plus the descent (OS/2's Windows pair, else hhea's), so the
/// ppem is the height times the units per em over that sum, rounded to the nearest (a half up;
/// the capture's +16 is 13.25, and its metrics are -13's). 0 is the font mapper's own default
/// size, which it chooses; the answer here is then 0.
pub fn ppem_for_height(font: &Font, height: i32) -> Result<u16, Error> {
    if height <= 0 {
        return Ok(height.unsigned_abs().min(u16::MAX as u32) as u16);
    }
    let os2 = font.os2()?;
    let cell = match os2 {
        Some(os2) if os2.us_win_ascent as u32 + os2.us_win_descent as u32 > 0 => {
            os2.us_win_ascent as i64 + os2.us_win_descent as i64
        }
        _ => font.hhea.ascender as i64 - font.hhea.descender as i64,
    };
    if cell <= 0 {
        return Err(Error::Malformed);
    }
    let units_per_em = font.head.units_per_em as i64;
    let ppem = (2 * height as i64 * units_per_em + cell).div_euclid(2 * cell);
    Ok(ppem.clamp(1, u16::MAX as i64) as u16)
}

/// Renders glyph `glyph` as GetGlyphOutline's GGO_BITMAP lays it out into `buffer`, and answers
/// its metrics and its bitmap's size. An empty `buffer` asks for the metrics and the size alone,
/// as GetGlyphOutline's NULL buffer does; one shorter than the bitmap is
/// [`Error::BufferTooSmall`].
pub fn render(
    font: &Font,
    glyph: u16,
    options: &Options,
    workspace: &mut Workspace,
    buffer: &mut [u8],
) -> Result<Rendered, Error> {
    if glyph >= font.glyph_count() {
        return Err(Error::BadGlyph);
    }
    if options.use_strikes {
        if let Some(image) = strike_glyph(font, glyph, options.ppem)? {
            return render_strike(&image, buffer);
        }
    }
    render_outline(font, glyph, options, workspace, buffer)
}

/// Glyph `glyph`'s image in the font's strike at `ppem`, if it has one that holds it.
pub fn strike_glyph<'a>(
    font: &Font<'a>,
    glyph: u16,
    ppem: u16,
) -> Result<Option<StrikeGlyph<'a>>, Error> {
    let Some(strikes) = font.strikes()? else {
        return Ok(None);
    };
    match strikes.strike(ppem)? {
        Some(strike) => strike.glyph(glyph),
        None => Ok(None),
    }
}

/// A strike's glyph: its own metrics and pixels.
fn render_strike(image: &StrikeGlyph, buffer: &mut [u8]) -> Result<Rendered, Error> {
    let metrics = image.metrics;
    let (width, height) = (metrics.width as u32, metrics.height as u32);
    let rendered = Rendered {
        metrics: GlyphMetrics {
            black_box_x: width.max(1),
            black_box_y: height.max(1),
            origin_x: metrics.bearing_x as i32,
            origin_y: metrics.bearing_y as i32,
            cell_inc_x: metrics.advance as i16,
            cell_inc_y: 0,
        },
        source: Source::Strike,
        size: stride(width) * height as usize,
    };
    if buffer.is_empty() || rendered.size == 0 {
        return Ok(rendered);
    }
    let bits = buffer
        .get_mut(..rendered.size)
        .ok_or(Error::BufferTooSmall)?;
    bits.fill(0);
    let stride = stride(width);
    for y in 0..height {
        for x in 0..width {
            if image.pixel(x, y) {
                bits[y as usize * stride + x as usize / 8] |= 0x80 >> (x % 8);
            }
        }
    }
    Ok(rendered)
}

/// An outline glyph: scaled, its black box rounded out of its points, and scan-converted.
fn render_outline(
    font: &Font,
    glyph: u16,
    options: &Options,
    workspace: &mut Workspace,
    buffer: &mut [u8],
) -> Result<Rendered, Error> {
    let scale = Scale::pixels(options.ppem, font.head.units_per_em);
    let mut outline = Outline::new(workspace.points, workspace.contour_ends);
    font.glyphs()?.outline(glyph, scale, &mut outline)?;
    let cell_inc_x = advance(font, outline.metrics_glyph(), options.ppem, scale)?;

    let Some((x_min, y_min, x_max, y_max)) = outline.bounds().filter(|_| !outline.is_empty())
    else {
        return Ok(Rendered {
            metrics: GlyphMetrics {
                black_box_x: 1,
                black_box_y: 1,
                origin_x: 0,
                origin_y: 0,
                cell_inc_x,
                cell_inc_y: 0,
            },
            source: Source::Outline,
            size: 0,
        });
    };
    let (left, bottom) = (round_pixel(x_min), round_pixel(y_min));
    let right = round_pixel(x_max).max(left + 1);
    let top = round_pixel(y_max).max(bottom + 1);
    let (width, height) = ((right - left) as u32, (top - bottom) as u32);
    let rendered = Rendered {
        metrics: GlyphMetrics {
            black_box_x: width,
            black_box_y: height,
            origin_x: left,
            origin_y: top,
            cell_inc_x,
            cell_inc_y: 0,
        },
        source: Source::Outline,
        size: stride(width)
            .checked_mul(height as usize)
            .ok_or(Error::BufferTooSmall)?,
    };
    if buffer.is_empty() {
        return Ok(rendered);
    }
    let bits = buffer
        .get_mut(..rendered.size)
        .ok_or(Error::BufferTooSmall)?;
    bits.fill(0);
    let dropout = options.dropout.unwrap_or(match font.table(Tag::PREP) {
        // Without a control-value program, nothing turns dropout control on.
        None => Dropout::Off,
        // A program that may turn it on is not run: rule 3, the simplest form, stands in for
        // whatever it asks.
        Some(_) => Dropout::Simple,
    });
    let mut target = Target {
        bits,
        stride: stride(width),
        width,
        height,
        left,
        top,
    };
    raster::fill(&outline, &mut target, dropout, workspace.crossings)?;
    Ok(rendered)
}

/// The advance in whole pixels of glyph `glyph` (the glyph whose metrics an outline takes) at
/// `ppem`: the `hdmx` width if the font has one for the size, else the advance width scaled to
/// 26.6 and rounded to a whole pixel.
fn advance(font: &Font, glyph: u16, ppem: u16, scale: Scale) -> Result<i16, Error> {
    if let Some(widths) = font.hdmx()?.and_then(|hdmx| hdmx.widths(ppem)) {
        if let Some(&width) = widths.get(glyph as usize) {
            return Ok(width as i16);
        }
    }
    let metric = font.hmtx()?.metric(glyph).ok_or(Error::BadGlyph)?;
    let advance = round_pixel(scale.apply(metric.advance_width as i32));
    Ok(advance.clamp(i16::MIN as i32, i16::MAX as i32) as i16)
}
