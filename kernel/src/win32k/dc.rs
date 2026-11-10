//! Device contexts: win32k's DC objects, and the services gdi32's DC, object, text and pixel calls
//! and user32's GetDC family come through; the drawing itself is the rasterizer's
//! ([`super::raster`]).
//!
//! A DC is an object of the object manager ([`crate::ob`]'s Dc type), its body a [`Dc`]: its
//! target, the screen; its origin, where its logical (0, 0) lands on the screen; its clipping
//! region, in screen coordinates, within the screen's extent when it was made (the framebuffer the
//! graphics mode set, empty before it is); its text and background colors and background mode; the
//! objects it has selected. Its creator's process holds it through a handle in its handle
//! table, as every object is held, so a DC closes with its process's other handles at its end, and
//! the teardown's leak sweep counts one left behind. (Windows 2000 keeps a DC in GDI's own handle
//! table, its attributes in user-mode memory gdi32 reads; here its state is the kernel's, and every
//! attribute gdi32 reads or writes is a service.)
//!
//! What the minimal subset serves:
//!
//! - the screen's DCs and the windows': gdi32's CreateDC of the display ([`open_dc`]) and user32's
//!   GetDC family of no window make a DC of the whole screen, its origin the screen's; GetDC and
//!   GetDCEx of a window ([`get_dc`], [`get_dc_ex`]) a DC of its client area, GetWindowDC
//!   ([`get_window_dc`]) and GetDCEx with DCX_WINDOW of its window rectangle, and BeginPaint
//!   ([`paint_dc`]) one of its client area clipped to the update region: the DC's origin is the
//!   area's top left, its clipping region the area (on the screen). A window's DC is not clipped by
//!   the windows above it or by its children, whatever WS_CLIPCHILDREN says: there are no visible
//!   regions yet;
//! - the coordinates a drawing service takes are logical, the DC's origin added (the mapping mode
//!   is MM_TEXT, its window and viewport origins zero);
//! - the stock objects as constant handles ([`rtl::gdi::stock_handle`]), which a DC selects by
//!   kind; brushes as objects and global brushes ([`super::brush`]), the DC keeping the selected
//!   brush's fill beside its handle; font objects ([`super::fonts`]), the DC keeping the selected
//!   font's object id beside its handle; no pens but the stock ones (the seam where they land: an
//!   object's handle carries its kind, [`rtl::gdi::object_handle`], and a selection of an object of
//!   another kind answers STATUS_OBJECT_TYPE_MISMATCH);
//! - the stock fonts are the built-in 8x16 one ([`super::font`]): ExtTextOutW draws its glyphs at
//!   (x, y) as their cells' top left, glyph pixels in the text color, the cells' other pixels in
//!   the background color when the background mode is OPAQUE (TRANSPARENT leaves them), every pixel
//!   clipped to the DC's clipping region (and to the rectangle, with ETO_CLIPPED); ETO_OPAQUE fills
//!   the rectangle with the background color first;
//! - a font object is realised against the TrueType faces loaded ([`super::fonts`]), the built-in
//!   font when no face answers it: the text, its metrics and its extent are then the face's, at its
//!   size, each glyph from the realised font's cache, (x, y) the cell's top left and the baseline
//!   its ascent below, clipped as the built-in font's;
//! - SetPixel and GetPixel through the framebuffer, clipped alike.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; a DC handle that names no DC is
//! STATUS_INVALID_HANDLE):
//!
//! - NtGdiOpenDCW(ptr Device, ptr<u32> Dc): a screen DC, for the primary display (a null device, or
//!   `\\.\DISPLAY1`);
//! - NtUserGetDC(handle Window, ptr<u32> Dc), NtUserGetDCEx(handle Window, handle Region, u32
//!   Flags, ptr<u32> Dc), NtUserGetWindowDC(handle Window, ptr<u32> Dc): the window's DC (the
//!   screen's for no window); STATUS_INVALID_HANDLE for a handle that names no window;
//! - NtGdiDeleteObjectApp(handle Object): a DC's, a brush's or a font's handle closed; a global
//!   object (a stock object, a global brush) is never deleted (the call succeeds);
//! - NtGdiGetStockObject(u32 Index, ptr<u32> Object): the stock object's handle;
//! - NtGdiSelectBrush, NtGdiSelectPen, NtGdiSelectFont(handle Dc, handle Object, ptr<u32>
//!   Previous): the object selected, the one it replaces answered (NtGdiSelectFont takes a font
//!   object's handle too); STATUS_OBJECT_TYPE_MISMATCH for an object of another kind,
//!   STATUS_INVALID_HANDLE for a handle that names none;
//! - NtGdiGetDCDword(handle Dc, u32 Index, ptr<u32> Value) and NtGdiGetAndSetDCDword(handle Dc, u32
//!   Index, u32 Value, ptr<u32> Previous): the text color, the background color, the background
//!   mode ([`rtl::gdi`]'s DC_ indexes);
//! - NtGdiExtTextOutW(handle Dc, i32 X, i32 Y, u32 Options, ptr Rect, ptr String, u32 Count, ptr
//!   Dx): the text drawn (`Dx`, when given, the advance of each character), and NtGdiEngTextOut,
//!   the engine's entry, the same;
//! - NtGdiGetTextMetricsW(handle Dc, ptr Metric) and NtGdiGetTextExtent(handle Dc, ptr String, u32
//!   Count, ptr Size): the font's TEXTMETRICW, a string's SIZE;
//! - NtGdiSetPixel(handle Dc, i32 X, i32 Y, u32 Color, ptr<u32> Set) and NtGdiGetPixel(handle Dc,
//!   i32 X, i32 Y, ptr<u32> Color): the color set, or read; CLR_INVALID for a pixel outside the
//!   clipping region.

use rtl::gdi::*;
use rtl::pod::Pod;

use super::brush::Fill;
use super::font;
use super::fonts::table::Realization;
use super::raster::{advanced, get_pixel_on, set_pixel_on, TextOut};
use crate::hw::vbe::Framebuffer;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// The access a DC's handle carries: STANDARD_RIGHTS_REQUIRED (a DC has no specific rights).
pub const DC_ACCESS: u32 = 0x000F_0000;

/// The characters a text service copies from the caller at a time, through buffers on the stack.
const CHUNK: usize = 64;

/// A DC's body: its target (the screen, the one there is) and its state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dc {
    /// Where the logical (0, 0) lands on the screen: the screen's own, or a window's area's top
    /// left. It is the brush origin too.
    pub origin: (i32, i32),
    /// The clipping region, in screen coordinates: the screen's extent when the DC was made (a
    /// window's area within it), empty before the graphics mode is set.
    pub clip: Rect,
    /// The text color, the background color (COLORREFs, as set) and the background mode.
    pub text_color: u32,
    pub bk_color: u32,
    pub bk_mode: u32,
    /// The objects selected, by kind: their handles (the stock pen; a stock font's, or a font
    /// object's).
    pub brush: u32,
    pub pen: u32,
    pub font: u32,
    /// What the selected brush paints.
    pub brush_fill: Fill,
    /// The font object selected, beside its handle: none for a stock font.
    pub font_object: Option<crate::ob::ObjectId>,
}

impl Dc {
    /// A record holding no DC (a pool's fresh record).
    pub const fn none() -> Self {
        Dc {
            origin: (0, 0),
            clip: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            text_color: 0,
            bk_color: 0,
            bk_mode: 0,
            brush: 0,
            pen: 0,
            font: 0,
            brush_fill: Fill::Null,
            font_object: None,
        }
    }

    /// A DC of a `width` by `height` screen, as a DC starts: black text on a white background,
    /// OPAQUE, the white brush, the black pen and the system font selected (the platform's
    /// defaults).
    pub fn screen(width: i32, height: i32) -> Self {
        let stock = |index| stock_handle(index).expect("a stock object");
        Dc {
            origin: (0, 0),
            clip: Rect {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            },
            text_color: DEFAULT_TEXT_COLOR,
            bk_color: DEFAULT_BK_COLOR,
            bk_mode: DEFAULT_BK_MODE,
            brush: stock(WHITE_BRUSH),
            pen: stock(BLACK_PEN),
            font: stock(SYSTEM_FONT),
            brush_fill: Fill::of_global(GlobalBrush::Stock(WHITE_BRUSH)),
            font_object: None,
        }
    }

    /// A DC of the area `area` (screen coordinates: a window's client area or rectangle) of a
    /// `width` by `height` screen, as a screen DC starts but for its origin, the area's top left,
    /// and its clipping region, the area on the screen.
    pub fn window(width: i32, height: i32, area: Rect) -> Self {
        let mut dc = Dc::screen(width, height);
        dc.origin = (area.left, area.top);
        dc.clip = super::raster::intersect(dc.clip, area);
        dc
    }

    /// The screen's point for the logical point (`x`, `y`).
    pub fn screen_point(&self, x: i32, y: i32) -> (i32, i32) {
        (
            x.saturating_add(self.origin.0),
            y.saturating_add(self.origin.1),
        )
    }

    /// The screen's rectangle for the logical rectangle `rect`.
    pub fn screen_rect(&self, rect: Rect) -> Rect {
        let (left, top) = self.screen_point(rect.left, rect.top);
        let (right, bottom) = self.screen_point(rect.right, rect.bottom);
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The attribute at `index` (the DC_ indexes); none for another index.
    pub fn attribute(&self, index: u32) -> Option<u32> {
        match index {
            DC_TEXT_COLOR => Some(self.text_color),
            DC_BK_COLOR => Some(self.bk_color),
            DC_BK_MODE => Some(self.bk_mode),
            _ => None,
        }
    }

    /// Set the attribute at `index` to `value`, answering the value it had; none, the DC
    /// untouched, for another index or a background mode that is neither TRANSPARENT nor OPAQUE.
    pub fn set_attribute(&mut self, index: u32, value: u32) -> Option<u32> {
        let field = match index {
            DC_TEXT_COLOR => &mut self.text_color,
            DC_BK_COLOR => &mut self.bk_color,
            DC_BK_MODE if matches!(value, TRANSPARENT | OPAQUE) => &mut self.bk_mode,
            _ => return None,
        };
        Some(core::mem::replace(field, value))
    }

    /// Select the stock object `handle` names, when it is of `kind` (OBJ_BRUSH, OBJ_PEN or
    /// OBJ_FONT), answering the one of its kind it replaces; none, the DC untouched, for a handle
    /// that names no stock object of that kind.
    pub fn select(&mut self, kind: u32, handle: u32) -> Option<u32> {
        let (index, found) = stock_object(handle)?;
        if found != kind {
            return None;
        }
        if kind == OBJ_BRUSH {
            return Some(self.select_brush(handle, Fill::of_global(GlobalBrush::Stock(index))));
        }
        let slot = match kind {
            OBJ_PEN => &mut self.pen,
            OBJ_FONT => {
                self.font_object = None;
                &mut self.font
            }
            _ => return None,
        };
        Some(core::mem::replace(slot, handle))
    }

    /// Select the brush `handle`, which paints `fill`, answering the brush it replaces.
    pub fn select_brush(&mut self, handle: u32, fill: Fill) -> u32 {
        self.brush_fill = fill;
        core::mem::replace(&mut self.brush, handle)
    }

    /// Select the font object `id`, whose handle is `handle`, answering the font it replaces (a
    /// stock font's handle or a font object's).
    pub fn select_font_object(&mut self, handle: u32, id: crate::ob::ObjectId) -> u32 {
        self.font_object = Some(id);
        core::mem::replace(&mut self.font, handle)
    }
}

// --- The services --------------------------------------------------------------------------------

/// NtGdiOpenDCW(Device, Dc): a screen DC for the primary display, its handle into `out`;
/// STATUS_INVALID_PARAMETER for another device.
pub fn open_dc(call: &mut NtCall, device: UserAddr, out: UserPtr<u32>) -> NtResult {
    if !device.is_null() && !names_primary_display(device)? {
        return Err(STATUS_INVALID_PARAMETER);
    }
    screen_dc(call, out)
}

/// GetDCEx's flag for a DC of the window rectangle rather than the client area.
pub const DCX_WINDOW: u32 = 0x0000_0001;

/// NtUserGetDC(Window, Dc): a DC of the window's client area (the screen's for no window).
pub fn get_dc(call: &mut NtCall, window: Handle, out: UserPtr<u32>) -> NtResult {
    window_dc(call, window, false, out)
}

/// NtUserGetDCEx(Window, Region, Flags, Dc): GetDC's DC, or GetWindowDC's with DCX_WINDOW (the
/// region and the other flags are not looked at: there are no visible regions to clip to yet).
pub fn get_dc_ex(
    call: &mut NtCall,
    window: Handle,
    _region: Handle,
    flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    window_dc(call, window, flags & DCX_WINDOW != 0, out)
}

/// NtUserGetWindowDC(Window, Dc): a DC of the window's rectangle, its non-client area included
/// (the screen's for no window).
pub fn get_window_dc(call: &mut NtCall, window: Handle, out: UserPtr<u32>) -> NtResult {
    window_dc(call, window, true, out)
}

/// NtGdiDeleteObjectApp(Object): a DC's, a brush's or a font's handle closed (the object goes with
/// it); a global object stays (it is never deleted: the call succeeds); STATUS_INVALID_HANDLE for
/// anything else.
pub fn delete_object(call: &mut NtCall, object: Handle) -> NtResult {
    if global_object_kind(object.raw()).is_some() {
        return Ok(STATUS_SUCCESS);
    }
    close_object(call, object)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetStockObject(Index, Object): the stock object's handle; STATUS_INVALID_PARAMETER for an
/// index that names none.
pub fn get_stock_object(_call: &mut NtCall, index: u32, out: UserPtr<u32>) -> NtResult {
    let handle = stock_handle(index).ok_or(STATUS_INVALID_PARAMETER)?;
    out.write(handle)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiSelectBrush(Dc, Brush, Previous): a global brush or a brush object (see
/// [`super::brush::fill_of`]).
pub fn select_brush(call: &mut NtCall, dc: Handle, object: Handle, out: UserPtr<u32>) -> NtResult {
    dc_of(call, dc)?;
    let fill = super::brush::fill_of(call, object)?;
    let previous = update_dc(call, dc, |dc| dc.select_brush(object.raw(), fill))?;
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiSelectPen(Dc, Pen, Previous).
pub fn select_pen(call: &mut NtCall, dc: Handle, object: Handle, out: UserPtr<u32>) -> NtResult {
    select(call, dc, OBJ_PEN, object, out)
}

/// NtGdiSelectFont(Dc, Font, Previous): a font object the calling process's `object` names (a
/// handle of the font kind: [`rtl::gdi::object_of`]), or a stock font (see [`select`]).
pub fn select_font(call: &mut NtCall, dc: Handle, object: Handle, out: UserPtr<u32>) -> NtResult {
    if !matches!(object_of(object.raw()), Some((OBJ_FONT, _))) {
        return select(call, dc, OBJ_FONT, object, out);
    }
    let id = super::fonts::font_object(object).ok_or(STATUS_INVALID_HANDLE)?;
    let previous = update_dc(call, dc, |dc| dc.select_font_object(object.raw(), id))?;
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
}

/// Select the stock `object` of `kind` into `dc`, the object it replaces into `out`;
/// STATUS_OBJECT_TYPE_MISMATCH for an object of another kind (a global one, or one the calling
/// process's handle names), STATUS_INVALID_HANDLE for a handle that names none.
fn select(call: &mut NtCall, dc: Handle, kind: u32, object: Handle, out: UserPtr<u32>) -> NtResult {
    let Some(previous) = update_dc(call, dc, |dc| dc.select(kind, object.raw()))? else {
        return Err(if names_object(call, object) {
            STATUS_OBJECT_TYPE_MISMATCH
        } else {
            STATUS_INVALID_HANDLE
        });
    };
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetDCDword(Dc, Index, Value): the attribute at `index`; STATUS_INVALID_PARAMETER for an
/// index that names none.
pub fn get_dc_dword(call: &mut NtCall, dc: Handle, index: u32, out: UserPtr<u32>) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let value = dc.attribute(index).ok_or(STATUS_INVALID_PARAMETER)?;
    out.write(value)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetAndSetDCDword(Dc, Index, Value, Previous): the attribute at `index` set, the value it
/// had into `out`; STATUS_INVALID_PARAMETER for an index that names none or a background mode
/// that is no mode.
pub fn get_and_set_dc_dword(
    call: &mut NtCall,
    dc: Handle,
    index: u32,
    value: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let previous = update_dc(call, dc, |dc| dc.set_attribute(index, value))?
        .ok_or(STATUS_INVALID_PARAMETER)?;
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiExtTextOutW(Dc, X, Y, Options, Rect, String, Count, Dx): see the module notes. The
/// rectangle and the string (and the advances) are read from the caller a chunk at a time, each
/// drawn before the next is read.
#[allow(clippy::too_many_arguments)]
pub fn ext_text_out_w(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    options: u32,
    rect: UserAddr,
    string: UserAddr,
    count: u32,
    dx: UserAddr,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let realization = super::fonts::realize_selected(call, &dc);
    let rect = if rect.is_null() {
        None
    } else {
        Some(dc.screen_rect(rect.cast::<Rect>().read()?))
    };
    let (x, y) = dc.screen_point(x, y);
    let text = TextOut::new(
        dc.clip,
        dc.text_color,
        dc.bk_color,
        dc.bk_mode == OPAQUE,
        y,
        options,
        rect,
    );
    with_screen(|screen| text.fill_background(screen));
    let mut units = [0u16; CHUNK];
    let mut advances = [0i32; CHUNK];
    let mut pen = x;
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(CHUNK);
        string
            .offset(2 * done as u32)
            .read_units(&mut units[..length])?;
        let advances = if dx.is_null() {
            None
        } else {
            dx.offset(4 * done as u32)
                .read(&mut advances.as_bytes_mut()[..4 * length])?;
            Some(&advances[..length])
        };
        let units = &units[..length];
        pen = match realization {
            Realization::BuiltIn { .. } => {
                with_screen(|screen| text.draw(screen, pen, units, advances))
                    .unwrap_or_else(|| advanced(pen, length, advances))
            }
            Realization::TrueType { key, .. } => with_screen(|screen| {
                super::fonts::draw_text(Some(screen), &text, key, pen, units, advances)
            })
            .unwrap_or_else(|| {
                super::fonts::draw_text::<ScreenMemory>(None, &text, key, pen, units, advances)
            }),
        };
        done += length;
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiEngTextOut: the text engine's entry, ExtTextOutW's drawing ([`ext_text_out_w`]).
#[allow(clippy::too_many_arguments)]
pub fn eng_text_out(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    options: u32,
    rect: UserAddr,
    string: UserAddr,
    count: u32,
    dx: UserAddr,
) -> NtResult {
    ext_text_out_w(call, dc, x, y, options, rect, string, count, dx)
}

/// NtGdiGetTextMetricsW(Dc, Metric): the font's TEXTMETRICW.
pub fn get_text_metrics_w(call: &mut NtCall, dc: Handle, metric: UserAddr) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let answer = match super::fonts::realize_selected(call, &dc) {
        Realization::BuiltIn { .. } => font::text_metric(),
        Realization::TrueType { key, char_set, .. } => {
            super::fonts::text_metric(key, char_set).ok_or(STATUS_INVALID_HANDLE)?
        }
    };
    metric.cast::<TextMetricW>().write(answer)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetTextExtent(Dc, String, Count, Size): the SIZE of `count` characters of the string (each
/// read: the built-in font's cells are all one width, but a string the caller cannot read is a
/// fault). In a TrueType font, the characters' advances side by side and the cell's height; no
/// characters, no height.
pub fn get_text_extent(
    call: &mut NtCall,
    dc: Handle,
    string: UserAddr,
    count: u32,
    size: UserAddr,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let realization = super::fonts::realize_selected(call, &dc);
    let mut units = [0u16; CHUNK];
    let mut width = 0i32;
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(CHUNK);
        string
            .offset(2 * done as u32)
            .read_units(&mut units[..length])?;
        if let Realization::TrueType { key, .. } = realization {
            width = width.saturating_add(super::fonts::text_width(key, &units[..length]));
        }
        done += length;
    }
    let (cx, cy) = match realization {
        Realization::BuiltIn { .. } => font::extent(count),
        Realization::TrueType { .. } if count == 0 => (0, 0),
        Realization::TrueType { key, char_set, .. } => {
            let metric = super::fonts::text_metric(key, char_set).ok_or(STATUS_INVALID_HANDLE)?;
            (width, metric.height)
        }
    };
    size.cast::<Size>().write(Size { cx, cy })?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiSetPixel(Dc, X, Y, Color, Set): the pixel set, the COLORREF set (or CLR_INVALID) into
/// `out`.
pub fn set_pixel(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    color: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let (x, y) = dc.screen_point(x, y);
    let set = with_screen(|screen| set_pixel_on(Some(screen), &dc.clip, x, y, color))
        .unwrap_or(CLR_INVALID);
    out.write(set)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetPixel(Dc, X, Y, Color): the pixel's COLORREF (or CLR_INVALID) into `out`.
pub fn get_pixel(call: &mut NtCall, dc: Handle, x: i32, y: i32, out: UserPtr<u32>) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let (x, y) = dc.screen_point(x, y);
    let color =
        with_screen(|screen| get_pixel_on(Some(screen), &dc.clip, x, y)).unwrap_or(CLR_INVALID);
    out.write(color)?;
    Ok(STATUS_SUCCESS)
}

/// Whether the NUL-terminated name at `at` is the primary display's (without regard to case).
fn names_primary_display(at: UserAddr) -> Result<bool, NtStatus> {
    let mut units = [0u16; rtl::display::CCHDEVICENAME];
    for (index, unit) in units.iter_mut().enumerate() {
        *unit = at.offset(2 * index as u32).cast::<u16>().read()?;
        if *unit == 0 {
            return Ok(super::display::is_primary_display(&units[..index]));
        }
    }
    Ok(false)
}

// --- The target's side: the objects and the screen ----------------------------------------------

/// The screen's pixel memory: the framebuffer's, on target.
#[cfg(target_arch = "x86")]
type ScreenMemory = crate::hw::vbe::trampoline::LfbMemory;

/// Run `f` against the screen, once the graphics mode is set; none before it.
#[cfg(target_arch = "x86")]
pub(super) fn with_screen<R>(f: impl FnOnce(&mut Framebuffer<ScreenMemory>) -> R) -> Option<R> {
    crate::hw::vbe::with_framebuffer(f)
}

/// The screen's extent, as a new DC's clipping region: empty before the graphics mode is set.
#[cfg(target_arch = "x86")]
fn screen_extent() -> (i32, i32) {
    with_screen(|screen| (screen.geometry.width as i32, screen.geometry.height as i32))
        .unwrap_or((0, 0))
}

/// A new screen DC, its handle in the calling process (not inheritable) into `out`;
/// STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the handle table is full.
#[cfg(target_arch = "x86")]
fn screen_dc(call: &mut NtCall, out: UserPtr<u32>) -> NtResult {
    let (width, height) = screen_extent();
    hand_out(call, Dc::screen(width, height), out)
}

/// A new DC of the window `window` names, of its rectangle when `whole` and of its client area
/// otherwise (the screen's for a null handle), its handle into `out` (see [`screen_dc`]);
/// STATUS_INVALID_HANDLE for a handle that names no window.
#[cfg(target_arch = "x86")]
fn window_dc(call: &mut NtCall, window: Handle, whole: bool, out: UserPtr<u32>) -> NtResult {
    if window.raw() == 0 {
        return screen_dc(call, out);
    }
    let area = crate::win32k::queue::with_manager(call.passive(), |m| {
        let id = m.windows.window_from_handle(window.raw())?;
        Some(if whole {
            m.windows.window_rect(id)
        } else {
            m.windows.client_rect(id)
        })
    })
    .ok_or(STATUS_INVALID_HANDLE)?;
    let area = Rect {
        left: area.left,
        top: area.top,
        right: area.right,
        bottom: area.bottom,
    };
    let (width, height) = screen_extent();
    hand_out(call, Dc::window(width, height, area), out)
}

/// A DC of state `dc` made, its handle into `out`; the DC closed again when `out` cannot be
/// written.
#[cfg(target_arch = "x86")]
fn hand_out(call: &mut NtCall, dc: Dc, out: UserPtr<u32>) -> NtResult {
    let handle = publish_dc(call, dc)?;
    if out.write(handle).is_err() {
        call.process().close_handle(handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// BeginPaint's DC: a DC of the window's client area `client` clipped to `clip` (both screen
/// coordinates: `clip` the part of the client area its update region covers), its handle in the
/// calling process (not inheritable); STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the
/// handle table is full.
#[cfg(target_arch = "x86")]
pub(super) fn paint_dc(call: &mut NtCall, client: Rect, clip: Rect) -> Result<u32, NtStatus> {
    let (width, height) = screen_extent();
    let mut dc = Dc::window(width, height, client);
    dc.clip = super::raster::intersect(dc.clip, clip);
    publish_dc(call, dc)
}

/// EndPaint's release of BeginPaint's DC: its handle closed; STATUS_INVALID_HANDLE when the handle
/// names no DC.
#[cfg(target_arch = "x86")]
pub(super) fn release_paint_dc(call: &mut NtCall, handle: u32) -> Result<(), NtStatus> {
    close_dc(call, Handle(handle))
}

/// A DC of state `dc` made, its handle in the calling process (not inheritable);
/// STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the handle table is full.
#[cfg(target_arch = "x86")]
fn publish_dc(call: &mut NtCall, dc: Dc) -> Result<u32, NtStatus> {
    let id = crate::ob::locked(|directory| directory.create_dc(dc))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    crate::ob::publish(call.process(), id, DC_ACCESS, false)
        .map(core::num::NonZeroU32::get)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

/// Close the calling process's handle `handle` when it names `kind`'s object;
/// STATUS_INVALID_HANDLE otherwise. (The look-up and the close are one step: a service runs masked
/// until its first wait, and neither waits.)
#[cfg(target_arch = "x86")]
fn close_kind(
    call: &mut NtCall,
    handle: Handle,
    kind: crate::ob::ObjectType,
) -> Result<(), NtStatus> {
    let process = call.process();
    let is_kind = process
        .lookup_handle(handle.raw())
        .and_then(|entry| entry.object_id())
        .is_some_and(|id| id.kind == kind);
    if is_kind && process.close_handle(handle.raw()) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// Close the calling process's handle `handle` when it names a DC; STATUS_INVALID_HANDLE
/// otherwise.
#[cfg(target_arch = "x86")]
fn close_dc(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
    close_kind(call, handle, crate::ob::ObjectType::Dc)
}

/// Close the calling process's handle when `handle` names a DC (its bare handle), a brush or a
/// font (its handle-table handle under the kind's bits: [`rtl::gdi::object_of`]), DeleteObject's;
/// STATUS_INVALID_HANDLE otherwise.
#[cfg(target_arch = "x86")]
fn close_object(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
    match object_of(handle.raw()) {
        Some((OBJ_BRUSH, table)) => close_kind(call, Handle(table), crate::ob::ObjectType::Brush),
        Some((OBJ_FONT, _)) => super::fonts::delete_font(call, handle),
        Some(_) => Err(STATUS_INVALID_HANDLE),
        None => close_dc(call, handle),
    }
}

/// Whether `handle` is a global object's or an object's of the calling process (one with its
/// kind's bits, or a DC's bare handle).
#[cfg(target_arch = "x86")]
fn names_object(call: &mut NtCall, handle: Handle) -> bool {
    let table = object_of(handle.raw()).map_or(handle.raw(), |(_, table)| table);
    global_object_kind(handle.raw()).is_some()
        || call
            .process()
            .lookup_handle(table)
            .and_then(|entry| entry.object_id())
            .is_some()
}

/// The DC `handle` names in the calling process, referenced for as long as the caller keeps the
/// reference, and its state as it is now.
#[cfg(target_arch = "x86")]
pub(super) fn dc_of(
    _call: &mut NtCall,
    handle: Handle,
) -> Result<(crate::ob::ObRef, Dc), NtStatus> {
    let reference = crate::ob::reference_by_handle(handle.raw(), Some(crate::ob::ObjectType::Dc))
        .ok_or(STATUS_INVALID_HANDLE)?;
    let dc = crate::ob::locked(|directory| directory.dc(reference.id()).copied())
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok((reference, dc))
}

/// Run `f` on the state of the DC `handle` names, in one hold of the directory.
#[cfg(target_arch = "x86")]
fn update_dc<R>(
    call: &mut NtCall,
    handle: Handle,
    f: impl FnOnce(&mut Dc) -> R,
) -> Result<R, NtStatus> {
    let (reference, _) = dc_of(call, handle)?;
    let result = crate::ob::locked(|directory| directory.dc(reference.id()).map(f))
        .ok_or(STATUS_INVALID_HANDLE);
    drop(reference);
    result
}

// The host builds have no processes and no screen: no handle names a DC, and nothing is drawn (the
// host tests drive the DC's state, the rasterizer and the pixels against fakes).

#[cfg(not(target_arch = "x86"))]
type ScreenMemory = NoScreen;

/// The host's screen memory: there is none.
#[cfg(not(target_arch = "x86"))]
pub struct NoScreen;

#[cfg(not(target_arch = "x86"))]
impl crate::hw::vbe::PixelMemory for NoScreen {
    fn store(&mut self, _: usize, _: u32) {}

    fn load(&mut self, _: usize) -> u32 {
        0
    }
}

#[cfg(not(target_arch = "x86"))]
pub(super) fn with_screen<R>(_: impl FnOnce(&mut Framebuffer<ScreenMemory>) -> R) -> Option<R> {
    None
}

#[cfg(not(target_arch = "x86"))]
fn screen_dc(_: &mut NtCall, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
fn window_dc(_: &mut NtCall, _: Handle, _: bool, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
fn close_object(_: &mut NtCall, _: Handle) -> Result<(), NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
fn names_object(_: &mut NtCall, handle: Handle) -> bool {
    global_object_kind(handle.raw()).is_some()
}

#[cfg(not(target_arch = "x86"))]
pub(super) fn dc_of(_: &mut NtCall, _: Handle) -> Result<((), Dc), NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
fn update_dc<R>(_: &mut NtCall, _: Handle, _: impl FnOnce(&mut Dc) -> R) -> Result<R, NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// A screen DC starts as the platform's: black on white, OPAQUE, the white brush, the black
    /// pen and the system font selected, clipped to the screen.
    #[test]
    fn a_screen_dc_starts_at_the_defaults() {
        let dc = Dc::screen(640, 480);
        assert_eq!(dc.clip, rect(0, 0, 640, 480));
        assert_eq!(
            (dc.text_color, dc.bk_color, dc.bk_mode),
            (0x00_0000, 0xFF_FFFF, OPAQUE)
        );
        assert_eq!(dc.brush, stock_handle(WHITE_BRUSH).unwrap());
        assert_eq!(dc.pen, stock_handle(BLACK_PEN).unwrap());
        assert_eq!(dc.font, stock_handle(SYSTEM_FONT).unwrap());
        assert_eq!(
            Dc::screen(0, 0).clip,
            rect(0, 0, 0, 0),
            "before the mode is set"
        );
    }

    /// The attributes answer their previous values, as the guidc capture's calls see them; a mode
    /// that is no mode and an index that is none leave the DC as it was.
    #[test]
    fn the_attributes_answer_their_previous_values() {
        let mut dc = Dc::screen(640, 480);
        assert_eq!(dc.set_attribute(DC_TEXT_COLOR, 0x00_00FF), Some(0x00_0000));
        assert_eq!(dc.set_attribute(DC_BK_COLOR, 0xFF_0000), Some(0xFF_FFFF));
        assert_eq!(dc.set_attribute(DC_BK_MODE, TRANSPARENT), Some(OPAQUE));
        assert_eq!(dc.set_attribute(DC_BK_MODE, OPAQUE), Some(TRANSPARENT));
        let before = dc;
        assert_eq!(dc.set_attribute(DC_BK_MODE, 3), None);
        assert_eq!(dc.set_attribute(DC_BK_MODE, 0), None);
        assert_eq!(dc.set_attribute(7, 1), None);
        assert_eq!(dc, before);
        assert_eq!(dc.attribute(DC_TEXT_COLOR), Some(0x00_00FF));
        assert_eq!(dc.attribute(DC_BK_COLOR), Some(0xFF_0000));
        assert_eq!(dc.attribute(DC_BK_MODE), Some(OPAQUE));
        assert_eq!(dc.attribute(3), None);
    }

    /// A window's DC: its origin the area's top left, its clipping region the area cut to the
    /// screen; the logical coordinates land at the origin.
    #[test]
    fn a_window_dc_draws_at_its_origin_clipped() {
        let dc = Dc::window(640, 480, rect(600, 30, 700, 80));
        assert_eq!(dc.origin, (600, 30));
        assert_eq!(dc.clip, rect(600, 30, 640, 80), "cut to the screen");
        assert_eq!(dc.screen_point(0, 0), (600, 30));
        assert_eq!(dc.screen_point(-5, 7), (595, 37));
        assert_eq!(dc.screen_rect(rect(1, 2, 3, 4)), rect(601, 32, 603, 34));
        assert_eq!(
            dc.brush,
            stock_handle(WHITE_BRUSH).unwrap(),
            "a DC's defaults"
        );
        let screen = Dc::screen(640, 480);
        assert_eq!(screen.origin, (0, 0));
        assert_eq!(screen.screen_point(3, 4), (3, 4));
        assert_eq!(
            Dc::window(640, 480, rect(-10, -10, -1, -1)).clip.right,
            -1,
            "off the screen: empty"
        );
    }

    /// Selecting a brush keeps its fill beside its handle: a stock brush's by its index, a brush
    /// object's or a global one's as given; the brush replaced is answered.
    #[test]
    fn a_selected_brush_keeps_its_fill() {
        let mut dc = Dc::screen(640, 480);
        let stock = |index| stock_handle(index).unwrap();
        assert_eq!(dc.brush_fill, Fill::Solid(0xFF_FFFF));
        assert_eq!(
            dc.select(OBJ_BRUSH, stock(BLACK_BRUSH)),
            Some(stock(WHITE_BRUSH))
        );
        assert_eq!(dc.brush_fill, Fill::Solid(0));
        assert_eq!(
            dc.select(OBJ_BRUSH, stock(NULL_BRUSH)),
            Some(stock(BLACK_BRUSH))
        );
        assert_eq!(dc.brush_fill, Fill::Null);
        assert_eq!(
            dc.select_brush(0x44, Fill::Solid(0x12_3456)),
            stock(NULL_BRUSH)
        );
        assert_eq!((dc.brush, dc.brush_fill), (0x44, Fill::Solid(0x12_3456)));
        let face = sys_color_brush(15).unwrap();
        assert_eq!(dc.select_brush(face, Fill::SysColor(15)), 0x44);
        assert_eq!(dc.select(OBJ_BRUSH, face), None, "not a stock object");
    }

    /// A stock object is selected over the one of its kind, which is answered; one of another
    /// kind, a palette, or a handle that is no stock object's is refused.
    #[test]
    fn stock_objects_select_by_kind() {
        let mut dc = Dc::screen(640, 480);
        let stock = |index| stock_handle(index).unwrap();
        assert_eq!(
            dc.select(OBJ_BRUSH, stock(WHITE_BRUSH)),
            Some(stock(WHITE_BRUSH))
        );
        assert_eq!(
            dc.select(OBJ_BRUSH, stock(BLACK_BRUSH)),
            Some(stock(WHITE_BRUSH))
        );
        assert_eq!(dc.brush, stock(BLACK_BRUSH));
        assert_eq!(dc.select(OBJ_PEN, stock(NULL_PEN)), Some(stock(BLACK_PEN)));
        assert_eq!(
            dc.select(OBJ_FONT, stock(ANSI_VAR_FONT)),
            Some(stock(SYSTEM_FONT))
        );
        let before = dc;
        assert_eq!(
            dc.select(OBJ_BRUSH, stock(BLACK_PEN)),
            None,
            "a pen is no brush"
        );
        assert_eq!(dc.select(OBJ_PAL, stock(DEFAULT_PALETTE)), None);
        assert_eq!(dc.select(OBJ_BRUSH, 0x7C), None, "a handle table's handle");
        assert_eq!(dc, before);
    }
}
