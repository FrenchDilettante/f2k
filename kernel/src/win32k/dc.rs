//! Device contexts: win32k's DC objects, and the services gdi32's DC, object, text and pixel calls
//! and user32's GetDC family come through; the drawing itself is the rasterizer's
//! ([`super::raster`]).
//!
//! A DC is an object of the object manager ([`crate::ob`]'s Dc type), its body a [`Dc`]: its
//! target, the screen or (a memory DC) its selected bitmap; its origin, where its logical (0, 0)
//! lands on the screen; its clipping
//! region, in screen coordinates, within the screen's extent when it was made (the framebuffer the
//! graphics mode set, empty before it is); its text and background colors and background mode; the
//! objects it has selected. Its creator's process holds it through an entry of the GDI handle
//! table ([`super::gdi`]), as Windows 2000 keeps a DC in GDI's own handle table, so its handle
//! names it in that process alone, and a DC goes with its process's other GDI objects at its end.
//! (Windows 2000 keeps a DC's attributes in user-mode memory gdi32 reads; here its state is the
//! kernel's, and every attribute gdi32 reads or writes is a service.)
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
//! - SetPixel and GetPixel through the framebuffer, clipped alike;
//! - memory DCs (CreateCompatibleDC's, [`create_compatible_dc`]): a DC that draws on the bitmap it
//!   holds, the default 1 by 1 monochrome one at first ([`super::bitmap`]), its origin (0, 0) and
//!   its clipping region the bitmap's extent; text, pixels and fills go to the bitmap's pixels as
//!   to the screen's, through the surface the DC draws on ([`super::bitmap::with_surface`]);
//! - the stretch mode and the brush origin, as attributes (SetStretchBltMode takes any value, as
//!   Windows 2000's does).
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; a DC handle that names no DC is
//! STATUS_INVALID_HANDLE):
//!
//! - NtGdiOpenDCW(ptr Device, ptr<u32> Dc): a screen DC, for the primary display (a null device, or
//!   `\\.\DISPLAY1`);
//! - NtGdiCreateCompatibleDC(handle Dc, ptr<u32> MemoryDc): a memory DC;
//! - NtUserGetDC(handle Window, ptr<u32> Dc), NtUserGetDCEx(handle Window, handle Region, u32
//!   Flags, ptr<u32> Dc), NtUserGetWindowDC(handle Window, ptr<u32> Dc): the window's DC (the
//!   screen's for no window); STATUS_INVALID_HANDLE for a handle that names no window;
//! - NtGdiDeleteObjectApp(handle Object): a DC's, a brush's, a font's or a bitmap's handle closed
//!   (a bitmap a DC holds is not: STATUS_CANNOT_DELETE); a global object (a stock object, a global
//!   brush, the default bitmap) is never deleted (the call succeeds);
//! - NtGdiGetStockObject(u32 Index, ptr<u32> Object): the stock object's handle;
//! - NtGdiSelectBrush, NtGdiSelectPen, NtGdiSelectFont(handle Dc, handle Object, ptr<u32>
//!   Previous): the object selected, the one it replaces answered (NtGdiSelectFont takes a font
//!   object's handle too); STATUS_OBJECT_TYPE_MISMATCH for an object of another kind,
//!   STATUS_INVALID_HANDLE for a handle that names none;
//! - NtGdiGetDCDword(handle Dc, u32 Index, ptr<u32> Value) and NtGdiGetAndSetDCDword(handle Dc, u32
//!   Index, u32 Value, ptr<u32> Previous): the text color, the background color, the background
//!   mode, the stretch mode, the brush origin's coordinates, and (read alone) the DC's kind, OBJ_DC
//!   or OBJ_MEMDC ([`rtl::gdi`]'s DC_ indexes);
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

use super::bitmap::with_surface;
use super::brush::Fill;
use super::font;
use super::fonts::table::Realization;
use super::raster::{advanced, get_pixel_on, set_pixel_on, Surface, TextOut};
use crate::hw::vbe::Framebuffer;
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

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
    /// Whether it is a memory DC (CreateCompatibleDC's): it draws on its selected bitmap, whose
    /// extent its clipping region is, rather than on the screen.
    pub memory: bool,
    /// The bitmap selected (a memory DC's: the default bitmap's handle, or a bitmap object's), and
    /// beside it the bitmap object (none for the default bitmap).
    pub bitmap: u32,
    pub bitmap_object: Option<crate::ob::ObjectId>,
    /// The stretch mode (SetStretchBltMode's value, as set: any value is taken).
    pub stretch_mode: u32,
    /// The brush origin, in the DC's logical coordinates (SetBrushOrgEx's).
    pub brush_org: (i32, i32),
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
            memory: false,
            bitmap: 0,
            bitmap_object: None,
            stretch_mode: 0,
            brush_org: (0, 0),
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
            memory: false,
            bitmap: DEFAULT_BITMAP,
            bitmap_object: None,
            stretch_mode: DEFAULT_STRETCH_MODE,
            brush_org: (0, 0),
        }
    }

    /// A memory DC, as CreateCompatibleDC makes one: a screen DC's defaults, holding the default
    /// bitmap (1 by 1), its clipping region that bitmap's extent.
    pub fn memory() -> Self {
        Dc {
            memory: true,
            ..Dc::screen(1, 1)
        }
    }

    /// Select the bitmap `handle` (its object `object`, none for the default bitmap) of `width`
    /// by `height` into a memory DC, its clipping region its extent; the bitmap it replaces
    /// answered.
    pub fn select_bitmap(
        &mut self,
        handle: u32,
        object: Option<crate::ob::ObjectId>,
        width: i32,
        height: i32,
    ) -> u32 {
        self.bitmap_object = object;
        self.clip = Rect {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        };
        core::mem::replace(&mut self.bitmap, handle)
    }

    /// The brush origin on the surface: the DC's origin and its brush origin.
    pub fn pattern_origin(&self) -> (i32, i32) {
        self.screen_point(self.brush_org.0, self.brush_org.1)
    }

    /// A DC of the area `area` (screen coordinates: a window's client area or rectangle) of a
    /// `width` by `height` screen, as a screen DC starts but for its origin, the area's top left,
    /// and its clipping region, the area on the screen.
    pub fn window(width: i32, height: i32, area: Rect) -> Self {
        let mut dc = Dc::screen(width, height);
        dc.origin = (area.left, area.top);
        dc.clip = dc.clip.intersect(area);
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
        rect.saturating_offset(self.origin.0, self.origin.1)
    }

    /// The attribute at `index` (the DC_ indexes); none for another index.
    pub fn attribute(&self, index: u32) -> Option<u32> {
        match index {
            DC_TEXT_COLOR => Some(self.text_color),
            DC_BK_COLOR => Some(self.bk_color),
            DC_BK_MODE => Some(self.bk_mode),
            DC_STRETCH_MODE => Some(self.stretch_mode),
            DC_BRUSH_ORG_X => Some(self.brush_org.0 as u32),
            DC_BRUSH_ORG_Y => Some(self.brush_org.1 as u32),
            DC_OBJECT_TYPE => Some(if self.memory {
                rtl::dib::OBJ_MEMDC
            } else {
                OBJ_DC
            }),
            _ => None,
        }
    }

    /// The object of `kind` (OBJ_BRUSH, OBJ_PEN or OBJ_FONT) selected; none for another kind.
    pub fn object(&self, kind: u32) -> Option<u32> {
        match kind {
            OBJ_BRUSH => Some(self.brush),
            OBJ_PEN => Some(self.pen),
            OBJ_FONT => Some(self.font),
            rtl::dib::OBJ_BITMAP => Some(self.bitmap),
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
            DC_STRETCH_MODE => &mut self.stretch_mode,
            DC_BRUSH_ORG_X => {
                return Some(core::mem::replace(&mut self.brush_org.0, value as i32) as u32)
            }
            DC_BRUSH_ORG_Y => {
                return Some(core::mem::replace(&mut self.brush_org.1, value as i32) as u32)
            }
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

/// NtGdiCreateCompatibleDC(Dc, MemoryDc): a memory DC (see [`Dc::memory`]), its handle into `out`;
/// the DC it is made compatible with (none: the screen) must be one (the screen is the one
/// device: every memory DC is the screen's).
pub fn create_compatible_dc(call: &mut NtCall, dc: Handle, out: UserPtr<u32>) -> NtResult {
    if dc.raw() != 0 {
        dc_of(call, dc)?;
    }
    hand_out(call, Dc::memory(), out)
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

/// NtGdiGetDCObject(Dc, ObjectType, Object): the brush, pen, font or bitmap selected
/// (GetCurrentObject); STATUS_INVALID_PARAMETER for another kind.
pub fn get_dc_object(call: &mut NtCall, dc: Handle, kind: u32, out: UserPtr<u32>) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let object = dc.object(kind).ok_or(STATUS_INVALID_PARAMETER)?;
    out.write(object)?;
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
    with_surface(&dc, |surface| text.fill_background(surface));
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
                with_surface(&dc, |surface| text.draw(surface, pen, units, advances))
                    .unwrap_or_else(|| advanced(pen, length, advances))
            }
            Realization::TrueType { key, .. } => with_surface(&dc, |surface| {
                super::fonts::draw_text(Some(surface), &text, key, pen, units, advances)
            })
            .unwrap_or_else(|| {
                super::fonts::draw_text::<dyn Surface>(None, &text, key, pen, units, advances)
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
    let set = with_surface(&dc, |surface| {
        set_pixel_on(Some(surface), &dc.clip, x, y, color)
    })
    .unwrap_or(CLR_INVALID);
    out.write(set)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetPixel(Dc, X, Y, Color): the pixel's COLORREF (or CLR_INVALID) into `out`.
pub fn get_pixel(call: &mut NtCall, dc: Handle, x: i32, y: i32, out: UserPtr<u32>) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let (x, y) = dc.screen_point(x, y);
    let color = with_surface(&dc, |surface| get_pixel_on(Some(surface), &dc.clip, x, y))
        .unwrap_or(CLR_INVALID);
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
        super::gdi::delete(handle, super::gdi::DC_KIND);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// BeginPaint's DC: a DC of the window's client area `client` clipped to `clip` (both screen
/// coordinates: `clip` the part of the client area its update region covers), its handle the
/// calling process's; STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the GDI table is full.
#[cfg(target_arch = "x86")]
pub(super) fn paint_dc(call: &mut NtCall, client: Rect, clip: Rect) -> Result<u32, NtStatus> {
    let (width, height) = screen_extent();
    let mut dc = Dc::window(width, height, client);
    dc.clip = dc.clip.intersect(clip);
    publish_dc(call, dc)
}

/// EndPaint's release of BeginPaint's DC: its handle closed; STATUS_INVALID_HANDLE when the handle
/// names no DC.
#[cfg(target_arch = "x86")]
pub(super) fn release_paint_dc(call: &mut NtCall, handle: u32) -> Result<(), NtStatus> {
    close_dc(call, Handle(handle))
}

/// A DC of state `dc` made, its GDI handle the calling process's ([`super::gdi`]);
/// STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the GDI table is full.
#[cfg(target_arch = "x86")]
fn publish_dc(_call: &mut NtCall, dc: Dc) -> Result<u32, NtStatus> {
    let id = crate::ob::locked(|directory| directory.create_dc(dc))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    super::gdi::insert(id).ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

/// Delete the calling process's DC `handle`; STATUS_INVALID_HANDLE when it names none.
#[cfg(target_arch = "x86")]
fn close_dc(_call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
    if super::gdi::delete(handle.raw(), super::gdi::DC_KIND) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// Delete the calling process's object `handle` names, a DC (its handle has no kind bits), a
/// brush, a font or a bitmap (its kind in its bits: [`rtl::gdi::object_of`]), DeleteObject's;
/// STATUS_INVALID_HANDLE otherwise.
#[cfg(target_arch = "x86")]
fn close_object(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
    match object_of(handle.raw()) {
        Some((OBJ_BRUSH, _)) if super::gdi::delete(handle.raw(), OBJ_BRUSH) => Ok(()),
        Some((OBJ_FONT, _)) => super::fonts::delete_font(call, handle),
        Some((rtl::dib::OBJ_BITMAP, _)) => super::bitmap::delete_bitmap(call, handle.raw()),
        Some(_) => Err(STATUS_INVALID_HANDLE),
        None => close_dc(call, handle),
    }
}

/// Whether `handle` is a global object's or an object's of the calling process (any kind).
#[cfg(target_arch = "x86")]
fn names_object(_call: &mut NtCall, handle: Handle) -> bool {
    global_object_kind(handle.raw()).is_some() || super::gdi::names(handle.raw())
}

/// The DC `handle` names in the calling process, referenced for as long as the caller keeps the
/// reference, and its state as it is now.
#[cfg(target_arch = "x86")]
pub(super) fn dc_of(
    _call: &mut NtCall,
    handle: Handle,
) -> Result<(crate::ob::ObRef, Dc), NtStatus> {
    let reference =
        super::gdi::reference(handle.raw(), super::gdi::DC_KIND).ok_or(STATUS_INVALID_HANDLE)?;
    let dc = crate::ob::locked(|directory| directory.dc(reference.id()).copied())
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok((reference, dc))
}

/// Run `f` on the state of the DC `handle` names, in one hold of the directory.
#[cfg(target_arch = "x86")]
pub(super) fn update_dc<R>(
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
fn hand_out(_: &mut NtCall, _: Dc, _: UserPtr<u32>) -> NtResult {
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
pub(super) fn update_dc<R>(
    _: &mut NtCall,
    _: Handle,
    _: impl FnOnce(&mut Dc) -> R,
) -> Result<R, NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen DC starts as the platform's: black on white, OPAQUE, the white brush, the black
    /// pen and the system font selected, clipped to the screen.
    #[test]
    fn a_screen_dc_starts_at_the_defaults() {
        let dc = Dc::screen(640, 480);
        assert_eq!(dc.clip, Rect::new(0, 0, 640, 480));
        assert_eq!(
            (dc.text_color, dc.bk_color, dc.bk_mode),
            (0x00_0000, 0xFF_FFFF, OPAQUE)
        );
        assert_eq!(dc.brush, stock_handle(WHITE_BRUSH).unwrap());
        assert_eq!(dc.pen, stock_handle(BLACK_PEN).unwrap());
        assert_eq!(dc.font, stock_handle(SYSTEM_FONT).unwrap());
        // GetCurrentObject's answers (controls `drawdc`); no object of another kind.
        assert_eq!(dc.object(OBJ_BRUSH), Some(dc.brush));
        assert_eq!(dc.object(OBJ_PEN), Some(dc.pen));
        assert_eq!(dc.object(OBJ_FONT), Some(dc.font));
        assert_eq!(dc.object(OBJ_DC), None);
        assert_eq!(
            Dc::screen(0, 0).clip,
            Rect::new(0, 0, 0, 0),
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
        assert_eq!(dc.attribute(9), None);
    }

    /// The bitmaps capture's attributes: the stretch mode starts BLACKONWHITE and takes any value
    /// (0 and 5 too); the brush origin starts at 0,0 and goes negative; the kind is a memory DC's
    /// or a screen DC's.
    #[test]
    fn the_stretch_mode_and_the_brush_origin() {
        let mut dc = Dc::memory();
        assert_eq!(dc.attribute(DC_STRETCH_MODE), Some(1));
        assert_eq!(dc.set_attribute(DC_STRETCH_MODE, 0), Some(1));
        assert_eq!(dc.set_attribute(DC_STRETCH_MODE, 5), Some(0));
        assert_eq!(dc.set_attribute(DC_BRUSH_ORG_X, 9), Some(0));
        assert_eq!(dc.set_attribute(DC_BRUSH_ORG_Y, -1i32 as u32), Some(0));
        assert_eq!(dc.attribute(DC_BRUSH_ORG_Y), Some(-1i32 as u32));
        assert_eq!(dc.pattern_origin(), (9, -1));
        assert_eq!(dc.attribute(DC_OBJECT_TYPE), Some(rtl::dib::OBJ_MEMDC));
        assert_eq!(Dc::screen(640, 480).attribute(DC_OBJECT_TYPE), Some(OBJ_DC));
        assert_eq!(dc.set_attribute(DC_OBJECT_TYPE, 3), None, "read alone");
    }

    /// A memory DC holds the default bitmap, its clipping region that bitmap's 1 by 1; a bitmap
    /// selected answers the one it replaces and makes its extent the clipping region.
    #[test]
    fn a_memory_dc_holds_its_bitmap() {
        let mut dc = Dc::memory();
        assert!(dc.memory);
        assert_eq!(dc.object(rtl::dib::OBJ_BITMAP), Some(DEFAULT_BITMAP));
        assert_eq!(dc.clip, Rect::new(0, 0, 1, 1));
        assert_eq!(dc.select_bitmap(0x7_0010, None, 16, 8), DEFAULT_BITMAP);
        assert_eq!(dc.clip, Rect::new(0, 0, 16, 8));
        assert_eq!(dc.select_bitmap(DEFAULT_BITMAP, None, 1, 1), 0x7_0010);
    }

    /// A window's DC: its origin the area's top left, its clipping region the area cut to the
    /// screen; the logical coordinates land at the origin.
    #[test]
    fn a_window_dc_draws_at_its_origin_clipped() {
        let dc = Dc::window(640, 480, Rect::new(600, 30, 700, 80));
        assert_eq!(dc.origin, (600, 30));
        assert_eq!(dc.clip, Rect::new(600, 30, 640, 80), "cut to the screen");
        assert_eq!(dc.screen_point(0, 0), (600, 30));
        assert_eq!(dc.screen_point(-5, 7), (595, 37));
        assert_eq!(
            dc.screen_rect(Rect::new(1, 2, 3, 4)),
            Rect::new(601, 32, 603, 34)
        );
        assert_eq!(
            dc.brush,
            stock_handle(WHITE_BRUSH).unwrap(),
            "a DC's defaults"
        );
        let screen = Dc::screen(640, 480);
        assert_eq!(screen.origin, (0, 0));
        assert_eq!(screen.screen_point(3, 4), (3, 4));
        assert_eq!(
            Dc::window(640, 480, Rect::new(-10, -10, -1, -1)).clip,
            Rect::new(0, 0, 0, 0),
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
        assert_eq!(
            dc.select(OBJ_BRUSH, 0x0102_007C),
            None,
            "a process object's handle"
        );
        assert_eq!(dc, before);
    }
}
