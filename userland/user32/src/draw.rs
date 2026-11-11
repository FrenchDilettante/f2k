//! The drawing calls the controls and the dialogs draw with: FillRect, FrameRect, InvertRect,
//! DrawFocusRect, DrawEdge and DrawText, written over gdi32 as Windows 2000's user32 writes them
//! ([`imports`]: SelectObject and PatBlt for the fills, in the system colors' brushes;
//! GetTextMetricsW, GetTextExtentPointW and ExtTextOutW for the text, in the DC's font and colors,
//! whatever font that is).
//!
//! The fills paint with a brush selected into the DC for the call and the DC's own brush put back
//! after it. The rectangles are logical coordinates of the DC, their right and bottom edges
//! outside them.
//!
//! DrawEdge draws each border (the outer, then the inner) one pixel wide, its top and left sides
//! first and its bottom and right sides over them, so the corners at the top right and the bottom
//! left are the bottom-right color's; each border moves the rectangle in by a pixel on the sides
//! it draws. The colors are the 3D system colors: a raised outer border COLOR_3DLIGHT above and to
//! the left, COLOR_3DDKSHADOW below and to the right; a raised inner one COLOR_3DHILIGHT and
//! COLOR_3DSHADOW; a sunken outer one COLOR_3DSHADOW and COLOR_3DHILIGHT; a sunken inner one
//! COLOR_3DDKSHADOW and COLOR_3DLIGHT. BF_SOFT swaps the two borders' top-left colors (the
//! stronger one outside: a push button's white outer edge). BF_MIDDLE fills what the borders leave
//! with COLOR_3DFACE; BF_ADJUST hands that rectangle back. BF_FLAT and BF_MONO draw as the 3D
//! borders; BF_DIAGONAL goes to the stub routine.
//!
//! DrawText lays its text out in lines: a single line with DT_SINGLELINE (carriage returns and
//! line feeds drawn as characters), lines broken at CR, LF and CR LF otherwise, and with
//! DT_WORDBREAK at the spaces before a word that would cross the rectangle's right side (a word
//! wider than the rectangle has a line of its own, crossing it; the spaces at a break are not
//! drawn). A break at the text's end starts no empty line. Each line is DT_LEFT, DT_CENTER or
//! DT_RIGHT in the rectangle, the lines from its top; a single line is DT_TOP, DT_VCENTER or
//! DT_BOTTOM in it. Unless DT_NOPREFIX, `&` underlines the character after it and `&&` draws one
//! `&` (DT_HIDEPREFIX draws no underline, DT_PREFIXONLY the underlines alone): the underline is a
//! line of the text color one pixel high, on the second row below the baseline (the line's top
//! plus the font's ascent plus one: the built-in font's underscore row), as wide as the character.
//! DT_EXPANDTABS moves a tab to the next stop, every eight average character widths (or the
//! DT_TABSTOP count's), from the line's start. The text is clipped to the rectangle unless
//! DT_NOCLIP. A line is the font's height high (DT_EXTERNALLEADING adds its external leading).
//! DT_CALCRECT draws nothing and sets the rectangle's right side to bound its widest line and its
//! bottom its last. The answer is the text's height, or, for DT_VCENTER and DT_BOTTOM, the bottom
//! of the drawn text from the rectangle's top. The ellipsis flags draw as without them.

use rtl::display::SYSTEM_COLORS;
use rtl::edge::{In, InBuf, InStr, InWStr, Out};
use rtl::gdi::*;

use crate::imports;

/// The system colors the drawing calls paint with (winuser.h's COLOR_*).
pub const COLOR_3DFACE: u32 = 15;
pub const COLOR_3DSHADOW: u32 = 16;
pub const COLOR_3DHILIGHT: u32 = 20;
pub const COLOR_3DDKSHADOW: u32 = 21;
pub const COLOR_3DLIGHT: u32 = 22;

/// DrawEdge's borders (winuser.h): the outer border raised or sunken, the inner one raised or
/// sunken, and the edges they make.
pub const BDR_RAISEDOUTER: u32 = 0x0001;
pub const BDR_SUNKENOUTER: u32 = 0x0002;
pub const BDR_RAISEDINNER: u32 = 0x0004;
pub const BDR_SUNKENINNER: u32 = 0x0008;
pub const EDGE_RAISED: u32 = BDR_RAISEDOUTER | BDR_RAISEDINNER;
pub const EDGE_SUNKEN: u32 = BDR_SUNKENOUTER | BDR_SUNKENINNER;
pub const EDGE_ETCHED: u32 = BDR_SUNKENOUTER | BDR_RAISEDINNER;
pub const EDGE_BUMP: u32 = BDR_RAISEDOUTER | BDR_SUNKENINNER;

/// DrawEdge's flags (winuser.h): the sides drawn, and how.
pub const BF_LEFT: u32 = 0x0001;
pub const BF_TOP: u32 = 0x0002;
pub const BF_RIGHT: u32 = 0x0004;
pub const BF_BOTTOM: u32 = 0x0008;
pub const BF_RECT: u32 = BF_LEFT | BF_TOP | BF_RIGHT | BF_BOTTOM;
pub const BF_DIAGONAL: u32 = 0x0010;
pub const BF_MIDDLE: u32 = 0x0800;
pub const BF_SOFT: u32 = 0x1000;
pub const BF_ADJUST: u32 = 0x2000;
pub const BF_FLAT: u32 = 0x4000;
pub const BF_MONO: u32 = 0x8000;

/// DrawText's format (winuser.h).
pub const DT_TOP: u32 = 0x0000;
pub const DT_LEFT: u32 = 0x0000;
pub const DT_CENTER: u32 = 0x0001;
pub const DT_RIGHT: u32 = 0x0002;
pub const DT_VCENTER: u32 = 0x0004;
pub const DT_BOTTOM: u32 = 0x0008;
pub const DT_WORDBREAK: u32 = 0x0010;
pub const DT_SINGLELINE: u32 = 0x0020;
pub const DT_EXPANDTABS: u32 = 0x0040;
pub const DT_TABSTOP: u32 = 0x0080;
pub const DT_NOCLIP: u32 = 0x0100;
pub const DT_EXTERNALLEADING: u32 = 0x0200;
pub const DT_CALCRECT: u32 = 0x0400;
pub const DT_NOPREFIX: u32 = 0x0800;
pub const DT_HIDEPREFIX: u32 = 0x0010_0000;
pub const DT_PREFIXONLY: u32 = 0x0020_0000;

// --- The fills -----------------------------------------------------------------------------------

/// The brush a FillRect argument names: a handle, or a system color as COLOR_* + 1; none for
/// NULL.
fn brush_of(brush: usize) -> Option<usize> {
    match brush {
        0 => None,
        color if color <= SYSTEM_COLORS => sys_color_brush(color as u32 - 1).map(|b| b as usize),
        handle => Some(handle),
    }
}

/// The DC's brush for a drawing call: each [`Brushed::paint`] selects its brush (the DC's own
/// kept), and the DC's own goes back when it drops.
struct Brushed {
    dc: usize,
    own: Option<usize>,
}

impl Brushed {
    fn new(dc: usize) -> Self {
        Brushed { dc, own: None }
    }

    /// The rectangle at (`x`, `y`), `width` by `height`, painted with `brush` by `rop`; whether it
    /// was (nothing painted for an empty extent).
    fn paint(&mut self, brush: usize, x: i32, y: i32, width: i32, height: i32, rop: u32) -> bool {
        let Some(previous) = imports::select_object(self.dc, brush) else {
            return false;
        };
        self.own.get_or_insert(previous);
        imports::pat_blt(self.dc, x, y, width, height, rop)
    }

    /// `rect`'s pixels painted with `brush` by `rop`, when it holds any.
    fn rect(&mut self, brush: usize, rect: Rect, rop: u32) -> bool {
        let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
        width <= 0 || height <= 0 || self.paint(brush, rect.left, rect.top, width, height, rop)
    }
}

impl Drop for Brushed {
    fn drop(&mut self) {
        if let Some(own) = self.own {
            imports::select_object(self.dc, own);
        }
    }
}

/// FillRect: the rectangle painted with the brush (a handle, or COLOR_* + 1 for a system color's),
/// its right and bottom edges left; nonzero, or 0 for a brush or a DC gdi32 refuses.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_FillRect")]
pub unsafe extern "system" fn fill_rect(dc: usize, rect: *const Rect, brush: usize) -> i32 {
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect) }.read();
    fill(dc, rect, brush) as i32
}

/// FillRect's work, for user32's own drawing (the controls, the dialogs, the default window
/// procedure's erase): `rect` painted with `brush` (a handle, or COLOR_* + 1); whether it was.
pub fn fill(dc: usize, rect: Rect, brush: usize) -> bool {
    let Some(brush) = brush_of(brush) else {
        return false;
    };
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    Brushed::new(dc).paint(brush, rect.left, rect.top, width, height, PATCOPY)
}

/// FrameRect: a frame one pixel wide just inside the rectangle, painted with the brush; nonzero
/// (nothing drawn for a rectangle whose right or bottom is before its left or top), or 0 for a
/// brush or a DC gdi32 refuses.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_FrameRect")]
pub unsafe extern "system" fn frame_rect(dc: usize, rect: *const Rect, brush: usize) -> i32 {
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect) }.read();
    frame_in(dc, rect, brush) as i32
}

/// FrameRect's work, for user32's own drawing: a frame one pixel wide just inside `rect`, painted
/// with `brush` (a handle, or COLOR_* + 1); whether it was.
pub fn frame_in(dc: usize, rect: Rect, brush: usize) -> bool {
    if rect.right < rect.left || rect.bottom < rect.top {
        return true;
    }
    let Some(brush) = brush_of(brush) else {
        return false;
    };
    let mut brushed = Brushed::new(dc);
    frame(&mut brushed, brush, rect, PATCOPY)
}

/// The frame just inside `rect`, painted with `brush` by `rop`, each pixel once (an XOR frame
/// stays a frame): the top and bottom rows whole, the sides between them; nothing for an empty
/// rectangle.
fn frame(brushed: &mut Brushed, brush: usize, rect: Rect, rop: u32) -> bool {
    let Rect {
        left,
        top,
        right,
        bottom,
    } = rect;
    if right <= left || bottom <= top {
        return true;
    }
    let row = |y| Rect {
        left,
        top: y,
        right,
        bottom: y + 1,
    };
    let column = |x| Rect {
        left: x,
        top: top + 1,
        right: x + 1,
        bottom: bottom - 1,
    };
    let mut done = brushed.rect(brush, row(top), rop);
    if bottom - top > 1 {
        done &= brushed.rect(brush, row(bottom - 1), rop);
    }
    done &= brushed.rect(brush, column(left), rop);
    if right - left > 1 {
        done &= brushed.rect(brush, column(right - 1), rop);
    }
    done
}

/// InvertRect: the rectangle's pixels inverted (PatBlt's DSTINVERT); TRUE, or FALSE for a DC
/// gdi32 refuses.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_InvertRect")]
pub unsafe extern "system" fn invert_rect(dc: usize, rect: *const Rect) -> u32 {
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect) }.read();
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    imports::pat_blt(dc, rect.left, rect.top, width, height, DSTINVERT) as u32
}

/// DrawFocusRect: the dotted frame just inside the rectangle, every other pixel inverted (the gray
/// brush, Windows 2000's checkerboard, PATINVERTed in black and white: drawn twice, the frame is
/// gone), the DC's colors and brush as they were after it; TRUE, or FALSE for a DC gdi32 refuses.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_DrawFocusRect")]
pub unsafe extern "system" fn draw_focus_rect(dc: usize, rect: *const Rect) -> u32 {
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect) }.read();
    focus_rect_in(dc, rect) as u32
}

/// DrawFocusRect's work, for user32's own drawing: the dotted frame just inside `rect`; whether it
/// was drawn.
pub fn focus_rect_in(dc: usize, rect: Rect) -> bool {
    if rect.right <= rect.left || rect.bottom <= rect.top {
        return true;
    }
    let text = imports::set_text_color(dc, 0x0000_0000);
    if text == CLR_INVALID {
        return false;
    }
    let background = imports::set_bk_color(dc, 0x00FF_FFFF);
    let done = frame(
        &mut Brushed::new(dc),
        HALFTONE_BRUSH as usize,
        rect,
        PATINVERT,
    );
    imports::set_bk_color(dc, background);
    imports::set_text_color(dc, text);
    done
}

// --- DrawEdge ------------------------------------------------------------------------------------

/// A border's colors, above and to the left and below and to the right: a raised or sunken, outer
/// or inner one's; BF_SOFT (`soft`) gives it the other border's top-left color.
fn border_colors(raised: bool, outer: bool, soft: bool) -> (u32, u32) {
    let colors = |outer: bool| match (raised, outer) {
        (true, true) => (COLOR_3DLIGHT, COLOR_3DDKSHADOW),
        (true, false) => (COLOR_3DHILIGHT, COLOR_3DSHADOW),
        (false, true) => (COLOR_3DSHADOW, COLOR_3DHILIGHT),
        (false, false) => (COLOR_3DDKSHADOW, COLOR_3DLIGHT),
    };
    let (light, dark) = colors(outer);
    if soft {
        (colors(!outer).0, dark)
    } else {
        (light, dark)
    }
}

/// DrawEdge's work on `rect` (logical coordinates): see the module notes. The rectangle the borders
/// leave is answered; whether gdi32 painted every side.
pub fn draw_edge_in(dc: usize, rect: Rect, edge: u32, flags: u32) -> (Rect, bool) {
    let mut brushed = Brushed::new(dc);
    let mut done = true;
    let mut rect = rect;
    let soft = flags & BF_SOFT != 0;
    let layers = [(edge & 0x3, true), ((edge >> 2) & 0x3, false)];
    for (border, outer) in layers {
        if rect.right <= rect.left || rect.bottom <= rect.top {
            break;
        }
        if border == 0 {
            continue;
        }
        let raised = border & 0x1 != 0;
        let (light, dark) = border_colors(raised, outer, soft);
        let brush = |color| sys_color_brush(color).map_or(0, |brush| brush as usize);
        let Rect {
            left,
            top,
            right,
            bottom,
        } = rect;
        let sides = [
            (
                BF_LEFT,
                light,
                Rect {
                    right: left + 1,
                    ..rect
                },
            ),
            (
                BF_TOP,
                light,
                Rect {
                    bottom: top + 1,
                    ..rect
                },
            ),
            (
                BF_RIGHT,
                dark,
                Rect {
                    left: right - 1,
                    ..rect
                },
            ),
            (
                BF_BOTTOM,
                dark,
                Rect {
                    top: bottom - 1,
                    ..rect
                },
            ),
        ];
        for (side, color, line) in sides {
            if flags & side != 0 {
                done &= brushed.rect(brush(color), line, PATCOPY);
            }
        }
        rect = Rect {
            left: left + (flags & BF_LEFT != 0) as i32,
            top: top + (flags & BF_TOP != 0) as i32,
            right: right - (flags & BF_RIGHT != 0) as i32,
            bottom: bottom - (flags & BF_BOTTOM != 0) as i32,
        };
    }
    if flags & BF_MIDDLE != 0 {
        let face = sys_color_brush(COLOR_3DFACE).map_or(0, |brush| brush as usize);
        done &= brushed.rect(face, rect, PATCOPY);
    }
    (rect, done)
}

/// DrawEdge: the borders `edge` names drawn on the sides `flags` names (see the module notes),
/// the rectangle moved in past them when BF_ADJUST; TRUE, or FALSE for a DC gdi32 refuses.
/// BF_DIAGONAL goes to the stub routine.
///
/// # Safety
///
/// The caller's RECT, read and (with BF_ADJUST) written, as for the platform's.
#[unsafe(export_name = "f2k_export_DrawEdge")]
pub unsafe extern "system" fn draw_edge(dc: usize, rect: *mut Rect, edge: u32, flags: u32) -> u32 {
    if flags & BF_DIAGONAL != 0 {
        let args = [dc as u64, rect as u64, edge as u64, flags as u64];
        // SAFETY: the arguments as DrawEdge's kinds read them.
        return unsafe {
            crate::stub::stubbed(
                &crate::spec::DrawEdge,
                "diagonal edges not yet implemented",
                &args,
            )
        };
    }
    // SAFETY: the caller's RECT.
    let mut place = unsafe { Out::new(rect) };
    let (inside, done) = draw_edge_in(dc, place.get(), edge, flags);
    if flags & BF_ADJUST != 0 {
        place.set(inside);
    }
    done as u32
}

// --- DrawText ------------------------------------------------------------------------------------

/// Carriage return, line feed, tab, space and the prefix character.
const CR: u16 = 0x0D;
const LF: u16 = 0x0A;
const TAB: u16 = 0x09;
const SPACE: u16 = 0x20;
const PREFIX: u16 = b'&' as u16;

/// The units a run of text is measured and drawn in at a time.
const RUN: usize = 64;

/// What DrawText's format asks for, decoded once.
#[derive(Clone, Copy, Debug)]
struct Format {
    /// The flags (with DT_TABSTOP, its count's bits taken out).
    flags: u32,
    /// The tab stops' spacing, in pixels, when DT_EXPANDTABS.
    tabs: Option<i32>,
}

impl Format {
    fn new(format: u32, metric: &TextMetricW) -> Self {
        let (flags, stops) = if format & DT_TABSTOP != 0 {
            (format & !0xFF00, ((format >> 8) & 0xFF) as i32)
        } else {
            (format, 8)
        };
        let tabs = (flags & DT_EXPANDTABS != 0).then(|| (stops * metric.ave_char_width).max(1));
        Format { flags, tabs }
    }

    fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Whether `&` is a prefix.
    fn prefixes(&self) -> bool {
        !self.has(DT_NOPREFIX)
    }
}

/// A walk along one line's units: its runs of shown units and the underlined ones, each at its
/// distance from the line's start, measured in the DC's font as it goes.
struct Walk<'a> {
    dc: usize,
    buffer: [u16; RUN],
    length: usize,
    /// The distance of the buffer's first unit from the line's start.
    x: i32,
    /// What a run of units does at its distance (drawn, or nothing when measuring).
    run: &'a mut dyn FnMut(i32, &[u16]),
    /// What an underlined unit does at its distance and width.
    mark: &'a mut dyn FnMut(i32, i32),
}

impl Walk<'_> {
    /// The buffer's units handed on and measured.
    fn flush(&mut self) {
        if self.length == 0 {
            return;
        }
        let units = &self.buffer[..self.length];
        let width = imports::text_width(self.dc, units).unwrap_or(0);
        (self.run)(self.x, units);
        self.x += width;
        self.length = 0;
    }

    fn push(&mut self, unit: u16) {
        if self.length == RUN {
            self.flush();
        }
        self.buffer[self.length] = unit;
        self.length += 1;
    }

    /// A tab: on to the next stop `spacing` apart.
    fn tab(&mut self, spacing: i32) {
        self.flush();
        self.x = (self.x.div_euclid(spacing) + 1) * spacing;
    }

    /// A unit underlined: its own distance and width marked, then it joins the next run.
    fn underlined(&mut self, unit: u16) {
        self.flush();
        let width = imports::text_width(self.dc, &[unit]).unwrap_or(0);
        (self.mark)(self.x, width);
        self.push(unit);
    }
}

/// Walk `line` (its units as the caller gave them, prefixes and tabs included) in `format`: each
/// run of shown units to `run`, each underlined unit to `mark`; the line's width.
fn walk(
    dc: usize,
    line: &[u16],
    format: &Format,
    run: &mut dyn FnMut(i32, &[u16]),
    mark: &mut dyn FnMut(i32, i32),
) -> i32 {
    let mut walk = Walk {
        dc,
        buffer: [0; RUN],
        length: 0,
        x: 0,
        run,
        mark,
    };
    let mut at = 0;
    while at < line.len() {
        let unit = line[at];
        at += 1;
        if unit == PREFIX && format.prefixes() {
            match line.get(at) {
                Some(&PREFIX) => walk.push(PREFIX),
                Some(&next) => walk.underlined(next),
                // A prefix at the end prefixes nothing: it is not drawn.
                None => {}
            }
            at += 1;
            continue;
        }
        match (unit, format.tabs) {
            (TAB, Some(spacing)) => walk.tab(spacing),
            _ => walk.push(unit),
        }
    }
    walk.flush();
    walk.x
}

/// The width of `line` in `format`, nothing drawn.
fn width_of(dc: usize, line: &[u16], format: &Format) -> i32 {
    walk(dc, line, format, &mut |_, _| {}, &mut |_, _| {})
}

/// Whether `unit` is a place a line may break at (DT_WORDBREAK).
fn is_space(unit: u16) -> bool {
    unit == SPACE || unit == TAB
}

/// The line of `text` from `start`, in `format`, at most `limit` pixels wide when DT_WORDBREAK: its
/// end (its last unit's index plus one, a wrap's spaces left out), and where the next line
/// starts (the text's length once none does).
fn next_line(dc: usize, text: &[u16], start: usize, format: &Format, limit: i32) -> (usize, usize) {
    if format.has(DT_SINGLELINE) {
        return (text.len(), text.len());
    }
    let hard = text[start..]
        .iter()
        .position(|&unit| unit == CR || unit == LF)
        .map(|at| start + at);
    let (end, after) = match hard {
        None => (text.len(), text.len()),
        Some(at) if text[at] == CR && text.get(at + 1) == Some(&LF) => (at, at + 2),
        Some(at) => (at, at + 1),
    };
    if !format.has(DT_WORDBREAK) {
        return (end, after);
    }
    let mut fits = None;
    let mut at = start;
    loop {
        let word = (at..end).find(|&i| !is_space(text[i])).unwrap_or(end);
        if word == end {
            break;
        }
        let word_end = (word..end).find(|&i| is_space(text[i])).unwrap_or(end);
        let wide = width_of(dc, &text[start..word_end], format) > limit;
        if wide && fits.is_some() {
            break;
        }
        fits = Some(word_end);
        if wide {
            break;
        }
        at = word_end;
    }
    match fits {
        Some(wrap) if (wrap..end).any(|i| !is_space(text[i])) => {
            let next = (wrap..end).find(|&i| !is_space(text[i])).unwrap_or(end);
            (wrap, next)
        }
        _ => (end, after),
    }
}

/// The underline under a prefixed character at (`x`, `y`), `width` wide: a row of the text color,
/// clipped to `clip` when there is one.
fn underline(dc: usize, x: i32, y: i32, width: i32, clip: Option<&Rect>) {
    let mut line = Rect {
        left: x,
        top: y,
        right: x + width,
        bottom: y + 1,
    };
    if let Some(clip) = clip {
        line = Rect {
            left: line.left.max(clip.left),
            top: line.top.max(clip.top),
            right: line.right.min(clip.right),
            bottom: line.bottom.min(clip.bottom),
        };
    }
    let Some(brush) = imports::create_solid_brush(imports::text_color(dc)) else {
        return;
    };
    Brushed::new(dc).rect(brush, line, PATCOPY);
    imports::delete_object(brush);
}

/// DrawText's work: `text` laid out in `rect` by `format` (see the module notes), drawn unless
/// DT_CALCRECT; the answer, and the rectangle as DT_CALCRECT leaves it. 0 for a DC gdi32 refuses.
pub fn draw_text_in(dc: usize, text: &[u16], rect: Rect, format: u32) -> (i32, Rect) {
    let Some(metric) = imports::text_metrics(dc) else {
        return (0, rect);
    };
    let format = Format::new(format, &metric);
    let height = metric.height
        + if format.has(DT_EXTERNALLEADING) {
            metric.external_leading
        } else {
            0
        };
    let calc = format.has(DT_CALCRECT);
    let clip = (!format.has(DT_NOCLIP)).then_some(&rect);
    let options = if clip.is_some() { ETO_CLIPPED } else { 0 };
    let limit = rect.right - rect.left;
    let single = format.has(DT_SINGLELINE);
    let mut y = rect.top;
    if single && !calc {
        if format.has(DT_BOTTOM) {
            y = rect.bottom - height;
        } else if format.has(DT_VCENTER) {
            y = rect.top + (rect.bottom - rect.top - height) / 2;
        }
    }
    let mut widest = 0;
    let mut lines = 0;
    let mut start = 0;
    while start < text.len() {
        let (end, next) = next_line(dc, text, start, &format, limit);
        let line = &text[start..end];
        let width = width_of(dc, line, &format);
        widest = widest.max(width);
        if !calc {
            let x = if format.has(DT_RIGHT) {
                rect.right - width
            } else if format.has(DT_CENTER) {
                rect.left + (limit - width) / 2
            } else {
                rect.left
            };
            let shown = !format.has(DT_PREFIXONLY);
            let underlined = !format.has(DT_HIDEPREFIX);
            walk(
                dc,
                line,
                &format,
                &mut |at, units| {
                    if shown {
                        imports::ext_text_out(dc, x + at, y, options, clip, units);
                    }
                },
                &mut |at, width| {
                    if underlined {
                        underline(dc, x + at, y + metric.ascent + 1, width, clip);
                    }
                },
            );
        }
        y += height;
        lines += 1;
        start = next;
    }
    let total = lines * height;
    if calc {
        let bound = Rect {
            right: rect.left + widest,
            bottom: rect.top + total,
            ..rect
        };
        return (total, bound);
    }
    let answer = if single && lines > 0 && format.has(DT_VCENTER | DT_BOTTOM) {
        y - rect.top
    } else {
        total
    };
    (answer, rect)
}

/// DrawText's text as a slice: the caller's units when they are aligned, a copy on the process
/// heap otherwise (none when the heap has no room); `f` runs on them.
fn with_units<R>(units: InBuf<u16>, f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    if let Some(units) = units.aligned() {
        return Some(f(units));
    }
    let mut block = imports::HeapBlock::new(2 * units.len())?;
    let copy = &mut block.units_mut()[..units.len()];
    units.copy_to(copy);
    Some(f(copy))
}

/// DrawText's core over a wide text and the caller's RECT (written by DT_CALCRECT).
fn draw_text(dc: usize, text: &[u16], mut place: Out<Rect>, format: u32) -> i32 {
    let (answer, rect) = draw_text_in(dc, text, place.get(), format);
    if format & DT_CALCRECT != 0 {
        place.set(rect);
    }
    answer
}

/// DrawTextW: the text (`count` units, or NUL-terminated for a negative count) drawn in the
/// rectangle by the format (see the module notes); the text's height, or 0 for a DC gdi32 refuses
/// or no text.
///
/// # Safety
///
/// The caller's string and RECT (read, and written with DT_CALCRECT), as for the platform's.
#[unsafe(export_name = "f2k_export_DrawTextW")]
pub unsafe extern "system" fn draw_text_w(
    dc: usize,
    text: *const u16,
    count: i32,
    rect: *mut Rect,
    format: u32,
) -> i32 {
    // SAFETY: the caller's string (counted, or NUL-terminated) and RECT.
    let (units, place) = unsafe {
        let units = if count < 0 {
            InWStr::new(text).units()
        } else {
            InBuf::new(text, count as usize)
        };
        (units, Out::new(rect))
    };
    with_units(units, |units| draw_text(dc, units, place, format)).unwrap_or(0)
}

/// DrawTextA: the text (`count` bytes, or NUL-terminated for a negative count) converted to its
/// wide form, then DrawTextW's drawing.
///
/// # Safety
///
/// The caller's string and RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_DrawTextA")]
pub unsafe extern "system" fn draw_text_a(
    dc: usize,
    text: *const u8,
    count: i32,
    rect: *mut Rect,
    format: u32,
) -> i32 {
    // SAFETY: the caller's string (counted, or NUL-terminated) and RECT.
    let (bytes, place) = unsafe {
        let bytes = if count < 0 {
            InStr::new(text).bytes()
        } else {
            InBuf::new(text, count as usize).bytes()
        };
        (bytes, Out::new(rect))
    };
    crate::with_wide(bytes, |units| {
        draw_text(dc, &units[..units.len() - 1], place, format)
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;

    use super::*;
    use crate::imports::host::canvas::*;
    use crate::imports::host::DEBUG_PRINTS;

    const DC: usize = CANVAS_DC;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The default scheme's 3D colors, the paper, and what the tests paint with, as characters.
    /// COLOR_3DLIGHT and COLOR_3DFACE are one color in it ('L').
    const LEGEND: [(u32, char); 7] = [
        (PAPER, '.'),
        (0x00FF_FFFF, 'H'),
        (0x0080_8080, 'S'),
        (0x0040_4040, 'D'),
        (0x00C8_D0D4, 'L'),
        (0x0000_00FF, 'R'),
        (0x0000_0000, 'K'),
    ];

    fn picture(area: Rect) -> Vec<String> {
        canvas(|canvas| canvas.picture(area, &LEGEND))
    }

    /// The canvas DC's own brush is the white stock one, and no brush the call made is left.
    fn left_as_found() {
        canvas(|canvas| {
            assert_eq!(canvas.brush, stock_handle(WHITE_BRUSH).unwrap() as usize);
            assert!(canvas.brushes.is_empty(), "{:?}", canvas.brushes);
        });
    }

    fn fill(area: Rect, brush: usize) -> i32 {
        // SAFETY: the test's own RECT.
        unsafe { fill_rect(DC, &area, brush) }
    }

    fn edge(area: Rect, edge: u32, flags: u32) -> (u32, Rect) {
        let mut area = area;
        // SAFETY: the test's own RECT.
        let done = unsafe { draw_edge(DC, &mut area, edge, flags) };
        (done, area)
    }

    fn text(string: &str, area: Rect, format: u32) -> (i32, Rect) {
        let units: Vec<u16> = string.encode_utf16().collect();
        let mut area = area;
        // SAFETY: the test's own string and RECT.
        let answer =
            unsafe { draw_text_w(DC, units.as_ptr(), units.len() as i32, &mut area, format) };
        (answer, area)
    }

    fn drawn() -> Vec<(i32, i32, String)> {
        canvas(|canvas| {
            canvas
                .text
                .iter()
                .map(|call| (call.x, call.y, call.text.clone()))
                .collect()
        })
    }

    /// FillRect paints the rectangle, its right and bottom edges left, with a brush or a system
    /// color's (COLOR_* + 1), the DC's own brush put back; NULL, or a DC that is none, is 0.
    ///
    /// Pins: user32.FillRect
    #[test]
    fn fill_rect_paints_with_the_brush() {
        reset_canvas();
        let red = imports::create_solid_brush(0x0000_00FF).unwrap();
        assert_ne!(fill(rect(1, 1, 4, 3), red), 0);
        assert_ne!(fill(rect(4, 2, 6, 4), (COLOR_3DSHADOW + 1) as usize), 0);
        assert_eq!(
            picture(rect(0, 0, 7, 5)),
            [
                ".......", //
                ".RRR...", ".RRRSS.", "....SS.", ".......",
            ]
        );
        assert_eq!(fill(rect(0, 0, 2, 2), 0), 0, "no brush");
        // SAFETY: the test's own RECT.
        assert_eq!(unsafe { fill_rect(0x99, &rect(0, 0, 2, 2), red) }, 0);
        imports::delete_object(red);
        left_as_found();
    }

    /// FrameRect paints the one-pixel frame just inside the rectangle; a rectangle turned inside
    /// out draws nothing.
    ///
    /// Pins: user32.FrameRect
    #[test]
    fn frame_rect_paints_a_frame() {
        reset_canvas();
        let black = stock_handle(BLACK_BRUSH).unwrap() as usize;
        // SAFETY: the tests' own RECTs.
        unsafe {
            assert_ne!(frame_rect(DC, &rect(1, 1, 6, 5), black), 0);
            assert_ne!(frame_rect(DC, &rect(8, 1, 9, 3), black), 0);
            assert_ne!(frame_rect(DC, &rect(5, 4, 2, 2), black), 0);
            assert_ne!(
                frame_rect(DC, &rect(3, 0, 3, 5), black),
                0,
                "empty: nothing"
            );
        }
        assert_eq!(
            picture(rect(0, 0, 10, 6)),
            [
                "..........", //
                ".KKKKK..K.",
                ".K...K..K.",
                ".K...K....",
                ".KKKKK....",
                "..........",
            ]
        );
        left_as_found();
    }

    /// InvertRect inverts the rectangle's pixels: twice, they are as they were.
    ///
    /// Pins: user32.InvertRect
    #[test]
    fn invert_rect_inverts() {
        reset_canvas();
        // SAFETY: the test's own RECT.
        unsafe {
            assert_eq!(invert_rect(DC, &rect(1, 1, 3, 2)), 1);
            assert_eq!(canvas(|canvas| canvas.at(1, 1)), !PAPER & RGB_MASK);
            assert_eq!(canvas(|canvas| canvas.at(3, 1)), PAPER);
            assert_eq!(invert_rect(DC, &rect(1, 1, 3, 2)), 1);
            assert_eq!(invert_rect(0x99, &rect(1, 1, 3, 2)), 0);
        }
        assert!(picture(rect(0, 0, 8, 8))
            .iter()
            .all(|row| row == "........"));
    }

    /// DrawFocusRect inverts every other pixel of the frame just inside the rectangle, the
    /// checkerboard's from the DC's origin; drawn again, it is gone; the DC's colors and brush are
    /// as they were.
    ///
    /// Pins: user32.DrawFocusRect
    #[test]
    fn draw_focus_rect_is_a_dotted_xor_frame() {
        reset_canvas();
        canvas(|canvas| {
            canvas.text_color = 0x0000_00FF;
            canvas.bk_color = 0x0000_FF00;
        });
        // SAFETY: the test's own RECT.
        assert_eq!(unsafe { draw_focus_rect(DC, &rect(1, 1, 6, 5)) }, 1);
        let inverted = !PAPER & RGB_MASK;
        let legend = [(PAPER, '.'), (inverted, 'X')];
        assert_eq!(
            canvas(|canvas| canvas.picture(rect(0, 0, 7, 6), &legend)),
            [
                ".......", //
                ".X.X.X.", ".......", ".X...X.", "..X.X..", ".......",
            ]
        );
        assert_eq!(
            canvas(|canvas| (canvas.text_color, canvas.bk_color)),
            (0x0000_00FF, 0x0000_FF00)
        );
        // SAFETY: the test's own RECT.
        assert_eq!(unsafe { draw_focus_rect(DC, &rect(1, 1, 6, 5)) }, 1);
        assert!(canvas(|canvas| canvas
            .pixels
            .iter()
            .all(|&pixel| pixel == PAPER)));
        // SAFETY: the test's own RECTs.
        unsafe {
            assert_eq!(draw_focus_rect(DC, &rect(3, 3, 3, 9)), 1, "empty: nothing");
            assert_eq!(draw_focus_rect(0x99, &rect(1, 1, 6, 5)), 0);
        }
        left_as_found();
    }

    /// EDGE_RAISED: the outer border light above and left, dark-shadowed below and right, the
    /// inner one highlighted and shadowed; the bottom-right sides own the far corners; BF_MIDDLE
    /// fills the rest with the face color, BF_ADJUST hands it back.
    ///
    /// Pins: user32.DrawEdge
    #[test]
    fn a_raised_edge() {
        reset_canvas();
        let (done, inside) = edge(rect(1, 1, 7, 6), EDGE_RAISED, BF_RECT | BF_ADJUST);
        assert_eq!((done, inside), (1, rect(3, 3, 5, 4)));
        assert_eq!(
            picture(rect(0, 0, 8, 7)),
            [
                "........", //
                ".LLLLLD.", ".LHHHSD.", ".LH..SD.", ".LSSSSD.", ".DDDDDD.", "........",
            ]
        );
        let (_, untouched) = edge(rect(1, 1, 7, 6), EDGE_RAISED, BF_RECT | BF_MIDDLE);
        assert_eq!(untouched, rect(1, 1, 7, 6), "without BF_ADJUST");
        assert_eq!(picture(rect(1, 3, 7, 4)), ["LHLLSD"]);
        left_as_found();
    }

    /// EDGE_SUNKEN: shadowed above and left, highlighted below and right, the inner border dark
    /// above and light below; BF_SOFT swaps the borders' top-left colors (a push button's white
    /// outer edge).
    ///
    /// Pins: user32.DrawEdge
    #[test]
    fn a_sunken_edge_and_a_soft_one() {
        reset_canvas();
        edge(rect(0, 0, 6, 5), EDGE_SUNKEN, BF_RECT);
        assert_eq!(
            picture(rect(0, 0, 6, 5)),
            [
                "SSSSSH", //
                "SDDDLH", "SD..LH", "SLLLLH", "HHHHHH",
            ]
        );
        reset_canvas();
        edge(rect(0, 0, 6, 5), EDGE_RAISED, BF_RECT | BF_SOFT);
        assert_eq!(
            picture(rect(0, 0, 6, 5)),
            [
                "HHHHHD", //
                "HLLLSD", "HL..SD", "HSSSSD", "DDDDDD",
            ]
        );
        reset_canvas();
        edge(rect(0, 0, 6, 5), EDGE_ETCHED, BF_RECT);
        assert_eq!(picture(rect(0, 0, 6, 2)), ["SSSSSH", "SHHHSH"]);
        left_as_found();
    }

    /// The sides drawn are the flags': each border moves the rectangle in on those sides alone; a
    /// border missing leaves the other at the rectangle's edge; an empty rectangle draws nothing.
    ///
    /// Pins: user32.DrawEdge
    #[test]
    fn an_edge_on_some_sides() {
        reset_canvas();
        let (_, inside) = edge(
            rect(0, 0, 4, 3),
            BDR_RAISEDINNER,
            BF_LEFT | BF_TOP | BF_ADJUST,
        );
        assert_eq!(inside, rect(1, 1, 4, 3));
        assert_eq!(
            picture(rect(0, 0, 5, 4)),
            ["HHHH.", "H....", "H....", "....."]
        );
        reset_canvas();
        let (_, inside) = edge(rect(0, 0, 4, 3), EDGE_RAISED, BF_BOTTOM | BF_ADJUST);
        assert_eq!(inside, rect(0, 0, 4, 1));
        assert_eq!(picture(rect(0, 0, 4, 3)), ["....", "SSSS", "DDDD"]);
        reset_canvas();
        let (done, _) = edge(rect(3, 3, 3, 8), EDGE_RAISED, BF_RECT | BF_MIDDLE);
        assert_eq!(done, 1);
        assert!(canvas(|canvas| canvas
            .pixels
            .iter()
            .all(|&pixel| pixel == PAPER)));
        left_as_found();
    }

    /// BF_DIAGONAL goes to the stub routine: logged, FALSE.
    ///
    /// Pins: user32.DrawEdge
    #[test]
    fn a_diagonal_edge_is_a_stub() {
        reset_canvas();
        let (done, _) = edge(
            rect(0, 0, 4, 4),
            EDGE_RAISED,
            BF_DIAGONAL | BF_TOP | BF_LEFT,
        );
        assert_eq!(done, 0);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert!(
            printed.iter().any(|line| line.contains("DrawEdge")),
            "{printed:?}"
        );
    }

    /// A single line, by the alignments: the text's position in the rectangle, clipped to it, and
    /// the answer (the height, or the drawn text's bottom from the top for DT_VCENTER and
    /// DT_BOTTOM).
    ///
    /// Pins: user32.DrawTextW
    #[test]
    fn a_single_line_aligns_in_its_rectangle() {
        let area = rect(0, 0, 40, 30);
        let cases = [
            (DT_LEFT | DT_TOP, (0, 0), 16),
            (DT_CENTER | DT_VCENTER, (12, 7), 23),
            (DT_RIGHT | DT_BOTTOM, (24, 14), 30),
            (DT_CENTER, (12, 0), 16),
            (DT_RIGHT | DT_VCENTER, (24, 7), 23),
        ];
        for (format, (x, y), answer) in cases {
            reset_canvas();
            assert_eq!(
                text("Hi", area, DT_SINGLELINE | format).0,
                answer,
                "{format:#x}"
            );
            assert_eq!(drawn(), [(x, y, String::from("Hi"))], "{format:#x}");
            let call = canvas(|canvas| canvas.text[0].clone());
            assert_eq!((call.options, call.rect), (ETO_CLIPPED, Some(area)));
        }
        reset_canvas();
        let unclipped = text("Hi", rect(10, 20, 50, 50), DT_SINGLELINE | DT_NOCLIP);
        assert_eq!(unclipped.0, 16);
        let call = canvas(|canvas| canvas.text[0].clone());
        assert_eq!((call.x, call.y, call.options, call.rect), (10, 20, 0, None));
    }

    /// Lines break at CR LF, LF and CR, one below the other; a break at the end starts no line;
    /// DT_SINGLELINE keeps them on its one line; the vertical alignments are DT_SINGLELINE's
    /// alone.
    ///
    /// Pins: user32.DrawTextW
    #[test]
    fn lines_break_at_carriage_returns_and_line_feeds() {
        reset_canvas();
        let area = rect(0, 0, 40, 100);
        assert_eq!(
            text("ab\r\ncd\nef\rg\n", area, DT_CENTER | DT_VCENTER).0,
            64
        );
        assert_eq!(
            drawn(),
            [
                (12, 0, String::from("ab")),
                (12, 16, String::from("cd")),
                (12, 32, String::from("ef")),
                (16, 48, String::from("g")),
            ]
        );
        reset_canvas();
        assert_eq!(text("a\nb", area, DT_SINGLELINE).0, 16);
        assert_eq!(drawn(), [(0, 0, String::from("a\nb"))]);
        reset_canvas();
        assert_eq!(text("", area, DT_SINGLELINE | DT_VCENTER).0, 0, "no text");
        assert!(drawn().is_empty());
    }

    /// DT_WORDBREAK breaks before the word that would cross the right side, the spaces at the
    /// break not drawn; a word wider than the rectangle has its own line; DT_CALCRECT draws
    /// nothing and bounds the lines.
    ///
    /// Pins: user32.DrawTextW
    #[test]
    fn words_wrap_and_the_rectangle_is_calculated() {
        reset_canvas();
        let area = rect(0, 0, 48, 100);
        assert_eq!(text("aa bbb   cc", area, DT_WORDBREAK).0, 32);
        assert_eq!(
            drawn(),
            [(0, 0, String::from("aa bbb")), (0, 16, String::from("cc"))]
        );
        reset_canvas();
        let right = text("abcdefghij x", rect(0, 0, 40, 100), DT_WORDBREAK | DT_RIGHT);
        assert_eq!(right.0, 32);
        assert_eq!(
            drawn(),
            [
                (-40, 0, String::from("abcdefghij")),
                (32, 16, String::from("x"))
            ]
        );
        reset_canvas();
        let calc = DT_WORDBREAK | DT_CALCRECT;
        assert_eq!(
            text("aa bbb cc", rect(5, 5, 53, 100), calc),
            (32, rect(5, 5, 53, 37))
        );
        assert_eq!(
            text("abcdefghij x", rect(0, 0, 40, 10), calc),
            (32, rect(0, 0, 80, 32)),
            "widened to the long word"
        );
        assert_eq!(
            text("Hello", rect(3, 4, 10, 10), DT_SINGLELINE | DT_CALCRECT),
            (16, rect(3, 4, 43, 20))
        );
        assert!(drawn().is_empty(), "DT_CALCRECT draws nothing");
    }

    /// `&` underlines the character after it: a row of the text color on the second row below the
    /// baseline, as wide as the character, the `&` not drawn; `&&` is one `&`; a last `&` is
    /// nothing; DT_NOPREFIX draws them all, DT_HIDEPREFIX no underline, DT_PREFIXONLY the
    /// underline alone.
    ///
    /// Pins: user32.DrawTextW
    #[test]
    fn prefixes_underline_their_character() {
        reset_canvas();
        assert_eq!(text("Sa&ve", rect(2, 1, 40, 30), DT_SINGLELINE).0, 16);
        assert_eq!(
            drawn(),
            [(2, 1, String::from("Sa")), (18, 1, String::from("ve"))]
        );
        assert_eq!(picture(rect(17, 14, 27, 15)), [".KKKKKKKK."]);
        let unmarked = |row: &String| !row.contains('K');
        assert!(picture(rect(0, 13, 40, 14)).iter().all(unmarked));
        left_as_found();

        reset_canvas();
        text("a&&b&", rect(0, 0, 40, 30), DT_SINGLELINE);
        assert_eq!(drawn(), [(0, 0, String::from("a&b"))]);
        reset_canvas();
        text("&File", rect(0, 0, 40, 30), DT_SINGLELINE | DT_NOPREFIX);
        assert_eq!(drawn(), [(0, 0, String::from("&File"))]);
        assert!(picture(rect(0, 13, 40, 14)).iter().all(unmarked));
        reset_canvas();
        text("&File", rect(0, 0, 40, 30), DT_SINGLELINE | DT_HIDEPREFIX);
        assert_eq!(drawn(), [(0, 0, String::from("File"))]);
        assert!(picture(rect(0, 13, 40, 14)).iter().all(unmarked));
        reset_canvas();
        text("&File", rect(0, 0, 40, 30), DT_SINGLELINE | DT_PREFIXONLY);
        assert!(drawn().is_empty());
        assert_eq!(picture(rect(0, 13, 9, 14)), ["KKKKKKKK."]);
        reset_canvas();
        text("&File", rect(0, 0, 5, 30), DT_SINGLELINE);
        assert_eq!(
            picture(rect(0, 13, 9, 14)),
            ["KKKKK...."],
            "clipped to the rectangle"
        );
        left_as_found();
    }

    /// DT_EXPANDTABS moves a tab to the next stop, eight average widths apart (or DT_TABSTOP's
    /// count, its bits no flags then); without it, a tab is a character.
    ///
    /// Pins: user32.DrawTextW
    #[test]
    fn tabs_expand_to_their_stops() {
        reset_canvas();
        text(
            "a\tb\tc",
            rect(4, 0, 400, 30),
            DT_SINGLELINE | DT_EXPANDTABS,
        );
        assert_eq!(
            drawn(),
            [
                (4, 0, String::from("a")),
                (68, 0, String::from("b")),
                (132, 0, String::from("c")),
            ]
        );
        reset_canvas();
        let format = DT_SINGLELINE | DT_EXPANDTABS | DT_TABSTOP | (3 << 8);
        text("a\tb", rect(0, 0, 400, 30), format);
        assert_eq!(
            drawn(),
            [(0, 0, String::from("a")), (24, 0, String::from("b"))]
        );
        let clipped = canvas(|canvas| canvas.text[0].options);
        assert_eq!(clipped, ETO_CLIPPED, "the count's bits are no DT_NOCLIP");
        reset_canvas();
        text("a\tb", rect(0, 0, 400, 30), DT_SINGLELINE);
        assert_eq!(drawn(), [(0, 0, String::from("a\tb"))]);
    }

    /// DrawTextA converts its text; a negative count is a NUL-terminated string; a DC that is none
    /// draws nothing and answers 0.
    ///
    /// Pins: user32.DrawTextA, user32.DrawTextW
    #[test]
    fn the_narrow_form_and_the_terminated_strings() {
        reset_canvas();
        let mut area = rect(0, 0, 40, 30);
        let wide: Vec<u16> = "Yo\0".encode_utf16().collect();
        // SAFETY: the test's own strings and RECT.
        unsafe {
            let hi = c"Hi".as_ptr().cast();
            assert_eq!(draw_text_a(DC, hi, -1, &mut area, DT_SINGLELINE), 16);
            assert_eq!(
                draw_text_a(DC, c"Hello".as_ptr().cast(), 3, &mut area, 0),
                16
            );
            assert_eq!(draw_text_w(DC, wide.as_ptr(), -1, &mut area, 0), 16);
            assert_eq!(draw_text_w(0x99, wide.as_ptr(), -1, &mut area, 0), 0);
        }
        assert_eq!(
            drawn(),
            [
                (0, 0, String::from("Hi")),
                (0, 0, String::from("Hel")),
                (0, 0, String::from("Yo")),
            ]
        );
    }
}
