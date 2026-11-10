//! gdi32's stand-ins: one DC ([`CANVAS_DC`]) drawing into a canvas of COLORREFs ([`Canvas`]), with
//! the kernel's rules for brushes and PatBlt (a solid brush's color, a global brush's, the gray
//! brush's checkerboard in the DC's colors from the canvas's origin; the raster operations through
//! rtl's), so the drawing calls' host tests assert exact pixels. Text is recorded rather than
//! drawn ([`TextCall`]), in a font of fixed 8x16 cells, its ascent 12, as the built-in font's.

use std::cell::RefCell;
use std::string::String;
use std::vec::Vec;

use rtl::display::DEFAULT_SYSTEM_COLORS;
use rtl::gdi::*;

/// The one DC the stand-ins draw with.
pub const CANVAS_DC: usize = 0x5C;
/// The canvas's size, and its pixels' color before anything is drawn.
pub const CANVAS_WIDTH: i32 = 40;
pub const CANVAS_HEIGHT: i32 = 30;
pub const PAPER: u32 = 0x00AB_CDEF;
/// The first brush object's handle (the brush kind's bits over a handle-table handle, as the
/// kernel hands them out): each next one 4 past the one before.
pub const FIRST_BRUSH: usize = 0x0002_0008;
/// The font's cell and ascent.
pub const CELL_WIDTH: i32 = 8;
pub const CELL_HEIGHT: i32 = 16;
pub const ASCENT: i32 = 12;

/// One ExtTextOutW call, as the stand-in read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextCall {
    pub x: i32,
    pub y: i32,
    pub options: u32,
    pub rect: Option<Rect>,
    pub text: String,
}

/// The canvas and its DC's state.
pub struct Canvas {
    /// The pixels, row by row, as COLORREFs.
    pub pixels: Vec<u32>,
    /// The DC's selected brush and colors.
    pub brush: usize,
    pub text_color: u32,
    pub bk_color: u32,
    /// The brush objects made and not deleted: their handles and colors.
    pub brushes: Vec<(usize, u32)>,
    made: usize,
    /// The text drawn, in order.
    pub text: Vec<TextCall>,
}

impl Canvas {
    fn new() -> Self {
        Canvas {
            pixels: std::vec![PAPER; (CANVAS_WIDTH * CANVAS_HEIGHT) as usize],
            brush: stock_handle(WHITE_BRUSH).unwrap() as usize,
            text_color: DEFAULT_TEXT_COLOR,
            bk_color: DEFAULT_BK_COLOR,
            brushes: Vec::new(),
            made: 0,
            text: Vec::new(),
        }
    }

    /// The pixel at (`x`, `y`).
    pub fn at(&self, x: i32, y: i32) -> u32 {
        self.pixels[(y * CANVAS_WIDTH + x) as usize]
    }

    /// The selected brush's color at (`x`, `y`); none for the null brush.
    fn paint(&self, x: i32, y: i32) -> Option<u32> {
        let handle = self.brush as u32;
        match global_brush(handle) {
            Some(GlobalBrush::Stock(index)) => match index {
                WHITE_BRUSH => Some(0x00FF_FFFF),
                LTGRAY_BRUSH => Some(0x00C0_C0C0),
                GRAY_BRUSH => Some(0x0080_8080),
                DKGRAY_BRUSH => Some(0x0040_4040),
                BLACK_BRUSH => Some(0),
                _ => None,
            },
            Some(GlobalBrush::SysColor(index)) => Some(DEFAULT_SYSTEM_COLORS[index as usize]),
            Some(GlobalBrush::Halftone) => {
                let set = HALFTONE_ROWS[(y & 7) as usize] & (0x80 >> (x & 7)) != 0;
                Some(if set { self.bk_color } else { self.text_color })
            }
            None => self
                .brushes
                .iter()
                .find(|&&(brush, _)| brush == self.brush)
                .map(|&(_, color)| color),
        }
    }

    /// The pixels in `area` as rows of characters, each the one `legend` gives its color ('?'
    /// for a color not in it).
    pub fn picture(&self, area: Rect, legend: &[(u32, char)]) -> Vec<String> {
        (area.top..area.bottom)
            .map(|y| {
                (area.left..area.right)
                    .map(|x| {
                        let pixel = self.at(x, y);
                        legend
                            .iter()
                            .find(|&&(color, _)| color == pixel)
                            .map_or('?', |&(_, c)| c)
                    })
                    .collect()
            })
            .collect()
    }
}

std::thread_local! {
    pub static CANVAS: RefCell<Canvas> = RefCell::new(Canvas::new());
}

/// Run `f` on the canvas.
pub fn canvas<R>(f: impl FnOnce(&mut Canvas) -> R) -> R {
    CANVAS.with(|canvas| f(&mut canvas.borrow_mut()))
}

/// A fresh canvas: every pixel the paper's, the DC at its defaults, no brush made, no text.
pub fn reset_canvas() {
    CANVAS.with(|canvas| *canvas.borrow_mut() = Canvas::new());
}

/// Run `f` on the canvas when `dc` is its DC; `failure` otherwise.
fn on_canvas<R>(dc: usize, failure: R, f: impl FnOnce(&mut Canvas) -> R) -> R {
    if dc != CANVAS_DC {
        return failure;
    }
    canvas(f)
}

pub unsafe extern "system" fn CreateSolidBrush(color: u32) -> usize {
    canvas(|canvas| {
        let brush = FIRST_BRUSH + 4 * canvas.made;
        canvas.made += 1;
        canvas.brushes.push((brush, color & RGB_MASK));
        brush
    })
}

pub unsafe extern "system" fn DeleteObject(object: usize) -> u32 {
    canvas(|canvas| {
        let before = canvas.brushes.len();
        canvas.brushes.retain(|&(brush, _)| brush != object);
        (before != canvas.brushes.len() || global_object_kind(object as u32).is_some()) as u32
    })
}

pub unsafe extern "system" fn SelectObject(dc: usize, object: usize) -> usize {
    on_canvas(dc, 0, |canvas| {
        let brush = global_brush(object as u32).is_some()
            || canvas.brushes.iter().any(|&(brush, _)| brush == object);
        if brush {
            core::mem::replace(&mut canvas.brush, object)
        } else {
            0
        }
    })
}

pub unsafe extern "system" fn PatBlt(
    dc: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: u32,
) -> u32 {
    on_canvas(dc, 0, |canvas| {
        if !rop_is_sourceless(rop) {
            return 0;
        }
        let (left, right) = (x.min(x + width), x.max(x + width));
        let (top, bottom) = (y.min(y + height), y.max(y + height));
        for py in top.max(0)..bottom.min(CANVAS_HEIGHT) {
            for px in left.max(0)..right.min(CANVAS_WIDTH) {
                let pattern = canvas.paint(px, py);
                if pattern.is_none() && rop_uses_pattern(rop) {
                    return 1;
                }
                let at = (py * CANVAS_WIDTH + px) as usize;
                canvas.pixels[at] =
                    apply_rop(rop, pattern.unwrap_or(0), canvas.pixels[at]) & RGB_MASK;
            }
        }
        1
    })
}

pub unsafe extern "system" fn GetTextColor(dc: usize) -> u32 {
    on_canvas(dc, CLR_INVALID, |canvas| canvas.text_color)
}

pub unsafe extern "system" fn SetTextColor(dc: usize, color: u32) -> u32 {
    on_canvas(dc, CLR_INVALID, |canvas| {
        core::mem::replace(&mut canvas.text_color, color)
    })
}

pub unsafe extern "system" fn SetBkColor(dc: usize, color: u32) -> u32 {
    on_canvas(dc, CLR_INVALID, |canvas| {
        core::mem::replace(&mut canvas.bk_color, color)
    })
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn ExtTextOutW(
    dc: usize,
    x: i32,
    y: i32,
    options: u32,
    rect: *const Rect,
    string: *const u16,
    count: u32,
    _dx: *const i32,
) -> u32 {
    // SAFETY: the code under test's own rectangle and units, of the length given.
    let (rect, units) = unsafe {
        (
            (!rect.is_null()).then(|| rect.read()),
            std::slice::from_raw_parts(string, count as usize),
        )
    };
    let text = String::from_utf16_lossy(units);
    on_canvas(dc, 0, |canvas| {
        canvas.text.push(TextCall {
            x,
            y,
            options,
            rect,
            text,
        });
        1
    })
}

pub unsafe extern "system" fn GetTextExtentPointW(
    dc: usize,
    _string: *const u16,
    count: i32,
    size: *mut Size,
) -> u32 {
    on_canvas(dc, 0, |_| {
        // SAFETY: the code under test's own SIZE.
        unsafe {
            size.write(Size {
                cx: CELL_WIDTH * count,
                cy: CELL_HEIGHT,
            })
        };
        1
    })
}

pub unsafe extern "system" fn GetTextMetricsW(dc: usize, metric: *mut TextMetricW) -> u32 {
    on_canvas(dc, 0, |_| {
        // SAFETY: the code under test's own structure.
        unsafe {
            metric.write(TextMetricW {
                height: CELL_HEIGHT,
                ascent: ASCENT,
                descent: CELL_HEIGHT - ASCENT,
                ave_char_width: CELL_WIDTH,
                max_char_width: CELL_WIDTH,
                ..TextMetricW::default()
            })
        };
        1
    })
}
