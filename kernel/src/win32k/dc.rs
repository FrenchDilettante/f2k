//! Device contexts: win32k's DC objects, and the services gdi32's DC, object, text and pixel calls
//! and user32's GetDC family come through; the drawing itself is the rasterizer's
//! ([`super::raster`]).
//!
//! A DC is an object of the object manager ([`crate::ob`]'s Dc type), its body a [`Dc`]: its
//! target, the screen or (a memory DC) its selected bitmap; its origin, where its logical (0, 0)
//! lands on the screen; its regions (see the clipping notes); its text and background colors and
//! background mode; the
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
//!   area's top left, its visible region the area on the screen (cut to the update region for
//!   BeginPaint's). A window's visible region is not cut by the windows above it or by its
//!   children, whatever WS_CLIPCHILDREN says: F2K does not yet work out windows' visible regions;
//! - the coordinates a drawing service takes are logical: the DC's page transform takes them to
//!   device coordinates ([`super::mapping`]: the mapping mode, the window's and viewport's origins
//!   and extents, attributes), and the DC's origin onto the surface ([`Dc::screen_point`], the one
//!   way every service's coordinates go). Sizes the drawing keeps in pixels (a pen's width, a
//!   font's height, ExtTextOut's advances) are not scaled;
//! - SaveDC's states ([`save_dc`], [`restore_dc`]): a copy of the whole DC (its objects,
//!   attributes, mapping, regions, current position, modes) saved as a DC object of its own,
//!   chained from the DC, restored relative (-1 the last) or absolute (its level), the states above
//!   it dropped;
//! - the stock objects as constant handles ([`rtl::gdi::stock_handle`]), which a DC selects by
//!   kind; brushes as objects and global brushes ([`super::brush`]), the DC keeping the selected
//!   brush's fill beside its handle; font objects ([`super::fonts`]), the DC keeping the selected
//!   font's object id beside its handle; the stock pens and pen objects ([`super::pen`]), the DC
//!   keeping a copy of the selected pen beside its handle (a selection of an object of another kind
//!   answers STATUS_OBJECT_TYPE_MISMATCH);
//! - the current position, the mix mode and the polygon fill mode, which the lines and shapes draw
//!   with ([`super::shape`]);
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
//!   its visible region the bitmap's extent; text, pixels and fills go to the bitmap's pixels as to
//!   the screen's, through the surface the DC draws on ([`super::bitmap::with_surface`]);
//! - the stretch mode and the brush origin, as attributes (SetStretchBltMode takes any value, as
//!   Windows 2000's does).
//!
//! # Clipping
//!
//! A DC clips as Windows 2000's does, through regions ([`super::region`]'s y-x banded rectangles,
//! each the DC's own block): its visible region (the surface's coordinates: the screen's extent,
//! a window's area on the screen, BeginPaint's cut to the update region, a memory DC's bitmap's
//! extent), its meta region and its clipping region (device coordinates, from the DC's origin;
//! none of either at first, and F2K serves no SetMetaRgn), and the final region they make, the
//! visible region within the other two, which the rasterizer clips every pixel of every drawing to
//! ([`super::raster::Clip`]). A service draws with a copy of the final region ([`DcState`]), never
//! with the DC's own blocks, which another thread's clipping call may give back meanwhile; the
//! DC's deletion gives its blocks back.
//!
//! The clipping calls work on the clipping region, a call that finds none starting from the DC's
//! extent (a mode over no clipping region is the mode over the whole DC: RGN_OR makes it the
//! extent, RGN_DIFF the extent less the region); their logical rectangles go to device
//! coordinates through the mapping, while SelectClipRgn's region is in device coordinates already.
//! Each answers the final region's complexity, as the regions capture shows, but IntersectClipRect,
//! which answers COMPLEXREGION whatever is left.
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
//! - NtGdiDeleteObjectApp(handle Object): a DC's, a brush's, a pen's, a font's or a bitmap's handle
//!   closed (a bitmap a DC holds is not: STATUS_CANNOT_DELETE); a global object (a stock object, a
//!   global brush, the default bitmap) is never deleted (the call succeeds);
//! - NtGdiGetStockObject(u32 Index, ptr<u32> Object): the stock object's handle;
//! - NtGdiSelectBrush, NtGdiSelectPen, NtGdiSelectFont(handle Dc, handle Object, ptr<u32>
//!   Previous): the object selected, the one it replaces answered (NtGdiSelectFont takes a font
//!   object's handle too); STATUS_OBJECT_TYPE_MISMATCH for an object of another kind,
//!   STATUS_INVALID_HANDLE for a handle that names none;
//! - NtGdiGetDCDword(handle Dc, u32 Index, ptr<u32> Value) and NtGdiGetAndSetDCDword(handle Dc, u32
//!   Index, u32 Value, ptr<u32> Previous): the text color, the background color, the background
//!   mode, the stretch mode, the brush origin's coordinates, the window origin's, the mix mode, the
//!   polygon fill mode, and (read alone) the DC's kind, OBJ_DC or OBJ_MEMDC ([`rtl::gdi`]'s DC_
//!   indexes);
//! - NtGdiExtTextOutW(handle Dc, i32 X, i32 Y, u32 Options, ptr Rect, ptr String, u32 Count, ptr
//!   Dx): the text drawn (`Dx`, when given, the advance of each character), and NtGdiEngTextOut,
//!   the engine's entry, the same;
//! - NtGdiGetTextMetricsW(handle Dc, ptr Metric) and NtGdiGetTextExtent(handle Dc, ptr String, u32
//!   Count, ptr Size): the font's TEXTMETRICW, a string's SIZE;
//! - NtGdiSetPixel(handle Dc, i32 X, i32 Y, u32 Color, ptr<u32> Set) and NtGdiGetPixel(handle Dc,
//!   i32 X, i32 Y, ptr<u32> Color): the color set, or read; CLR_INVALID for a pixel outside the
//!   final region;
//! - NtGdiExtSelectClipRgn(handle Dc, handle Region, u32 Mode, ptr<u32> Complexity),
//!   NtGdiIntersectClipRect and NtGdiExcludeClipRect(handle Dc, i32 Left, i32 Top, i32 Right, i32
//!   Bottom, ptr<u32> Complexity), NtGdiOffsetClipRgn(handle Dc, i32 X, i32 Y, ptr<u32>
//!   Complexity): the clipping region changed (see the clipping notes), the final region's
//!   complexity answered; STATUS_NO_MEMORY when the pool has no room (the clipping as it was);
//! - NtGdiGetAppClipBox(handle Dc, ptr Box, ptr<u32> Complexity): the final region's box in logical
//!   coordinates; NtGdiGetRandomRgn(handle Dc, handle Region, u32 Which, ptr<u32> Result): with
//!   CLIPRGN, the region made a copy of the clipping region (1), or 0 without one;
//! - NtGdiPtVisible(handle Dc, i32 X, i32 Y, ptr<u32> Visible) and NtGdiRectVisible(handle Dc, ptr
//!   Rect, ptr<u32> Visible): whether the logical point, or any of the rectangle, is inside the
//!   final region;
//! - NtGdiSaveDC(handle Dc, ptr<u32> Level) and NtGdiRestoreDC(handle Dc, i32 Level): the DC's
//!   state saved, its level answered; a saved state restored ([`restore_level`]: -1 the last),
//!   STATUS_INVALID_PARAMETER for a level that names none;
//! - NtGdiComputeXformCoefficients(handle Dc): MM_ISOTROPIC's adjustment, after gdi32 set an extent
//!   a coordinate at a time (the mapping's attributes are NtGdiGetAndSetDCDword's DC_ indexes, its
//!   points NtGdiGetDCPoint's, [`super::shape`]);
//! - NtGdiScaleViewportExtEx and NtGdiScaleWindowExtEx(handle Dc, i32 XNum, i32 XDenom, i32 YNum,
//!   i32 YDenom, ptr Previous, ptr<u32> Result): the extents scaled, 1 or 0 answered
//!   ([`scale_ext`]);
//! - NtGdiTransformPoints(handle Dc, ptr In, ptr Out, u32 Count, u32 Mode): LPtoDP's and DPtoLP's
//!   points, through the mapping.

use rtl::gdi::*;
use rtl::pod::Pod;
use rtl::user::{CS_CLASSDC, CS_OWNDC};

use super::bitmap::with_surface;
use super::brush::Fill;
use super::font;
use super::fonts::table::Realization;
use super::mapping::{Device, Mapping};
use super::raster::{advanced, get_pixel_on, set_pixel_on, Clip, Surface, TextOut};
use super::region::{ordered, OwnedRegion, Region};
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
    /// The DC's extent from its origin: the screen's, a window's area's, or a memory DC's
    /// bitmap's. With no clipping region, the region the clipping calls start from.
    pub extent: (i32, i32),
    /// The visible region, in the surface's coordinates (see the clipping notes): its extent on
    /// the screen (or the bitmap), BeginPaint's cut to the update region. Its own block.
    vis: Region,
    /// The meta region and the clipping region (SetMetaRgn's and SelectClipRgn's), in device
    /// coordinates (from the DC's origin), each its own block; none without one. F2K serves no
    /// SetMetaRgn: the meta region is always none.
    meta: Option<Region>,
    clip_rgn: Option<Region>,
    /// The final region every drawing is clipped to, in the surface's coordinates: the visible
    /// region within the meta and clipping regions; none when there is neither, the visible
    /// region itself. Its own block.
    rao: Option<Region>,
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
    /// The selected pen, a copy of it.
    pub pen_state: super::pen::Pen,
    /// The current position (MoveToEx's, LineTo's), logical.
    pub current: (i32, i32),
    /// The mix mode (SetROP2's) and the polygon fill mode (SetPolyFillMode's), as set: any value
    /// is taken.
    pub rop2: u32,
    pub fill_mode: u32,
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
    /// The brush origin, from the DC's origin (SetBrushOrgEx's, in device units: the window
    /// origin does not move it).
    pub brush_org: (i32, i32),
    /// The page transform: the mapping mode, the window's and the viewport's origins and extents
    /// ([`super::mapping`]), from the logical coordinates to the device's (from the DC's origin).
    pub mapping: Mapping,
    /// SaveDC's states: how many are saved, and the last one saved, a DC object of its own (the
    /// DC's reference on it; each saved state holds the one saved before it), as Windows 2000's
    /// SaveDC keeps a copy of the DC; none saved, none.
    pub saves: u32,
    pub saved: Option<crate::ob::ObjectId>,
    /// A saved state's: the DC it was saved from (none for a live DC). Its bitmap counts as that
    /// DC's selection, no other DC's.
    pub saved_by: Option<crate::ob::ObjectId>,
}

impl Dc {
    /// A record holding no DC (a pool's fresh record).
    pub const fn none() -> Self {
        Dc {
            origin: (0, 0),
            extent: (0, 0),
            vis: Region::none(),
            meta: None,
            clip_rgn: None,
            rao: None,
            text_color: 0,
            bk_color: 0,
            bk_mode: 0,
            brush: 0,
            pen: 0,
            font: 0,
            brush_fill: Fill::Null,
            pen_state: super::pen::Pen::none(),
            current: (0, 0),
            rop2: 0,
            fill_mode: 0,
            font_object: None,
            memory: false,
            bitmap: 0,
            bitmap_object: None,
            stretch_mode: 0,
            brush_org: (0, 0),
            mapping: Mapping::TEXT,
            saves: 0,
            saved: None,
            saved_by: None,
        }
    }

    /// A DC of a `width` by `height` screen, as a DC starts: black text on a white background,
    /// OPAQUE, the white brush, the black pen and the system font selected (the platform's
    /// defaults).
    pub fn screen(width: i32, height: i32) -> Self {
        let stock = |index| stock_handle(index).expect("a stock object");
        Dc {
            origin: (0, 0),
            extent: (width, height),
            vis: Region::rect(ordered(0, 0, width, height)),
            meta: None,
            clip_rgn: None,
            rao: None,
            text_color: DEFAULT_TEXT_COLOR,
            bk_color: DEFAULT_BK_COLOR,
            bk_mode: DEFAULT_BK_MODE,
            brush: stock(WHITE_BRUSH),
            pen: stock(BLACK_PEN),
            font: stock(SYSTEM_FONT),
            brush_fill: Fill::of_global(GlobalBrush::Stock(WHITE_BRUSH)),
            pen_state: super::pen::Pen::stock(BLACK_PEN),
            current: (0, 0),
            rop2: DEFAULT_ROP2,
            fill_mode: DEFAULT_POLY_FILL_MODE,
            font_object: None,
            memory: false,
            bitmap: DEFAULT_BITMAP,
            bitmap_object: None,
            stretch_mode: DEFAULT_STRETCH_MODE,
            brush_org: (0, 0),
            mapping: Mapping::TEXT,
            saves: 0,
            saved: None,
            saved_by: None,
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
        self.extent = (width, height);
        self.set_vis(OwnedRegion::rect(Rect::new(0, 0, width, height)));
        core::mem::replace(&mut self.bitmap, handle)
    }

    /// The brush origin on the surface: the DC's origin and its brush origin.
    pub fn pattern_origin(&self) -> (i32, i32) {
        (
            self.brush_org.0.saturating_add(self.origin.0),
            self.brush_org.1.saturating_add(self.origin.1),
        )
    }

    /// A DC of the area `area` (screen coordinates: a window's client area or rectangle) of a
    /// `width` by `height` screen, as a screen DC starts but for its origin, the area's top left,
    /// and its clipping region, the area on the screen.
    pub fn window(width: i32, height: i32, area: Rect) -> Self {
        let mut dc = Dc::screen(width, height);
        dc.origin = (area.left, area.top);
        dc.extent = (area.width(), area.height());
        let visible = Rect::new(0, 0, width, height).intersect(area);
        dc.set_vis(OwnedRegion::rect(visible));
        dc
    }

    /// The device point of the logical point (`x`, `y`), from the DC's origin: the page
    /// transform's ([`Mapping::to_device`]), the one every coordinate a service takes goes through.
    pub fn device_point(&self, x: i32, y: i32) -> (i32, i32) {
        self.mapping.to_device(x, y)
    }

    /// The surface's point (the screen's, or the bitmap's) for the logical point (`x`, `y`): its
    /// device point, from the DC's origin.
    pub fn screen_point(&self, x: i32, y: i32) -> (i32, i32) {
        let (x, y) = self.device_point(x, y);
        (
            x.saturating_add(self.origin.0),
            y.saturating_add(self.origin.1),
        )
    }

    /// The surface's rectangle for the logical rectangle `rect`: its corners' points, swapped in
    /// a direction the mapping flips (so an ordered rectangle stays one; MM_TEXT's is the
    /// rectangle moved).
    pub fn screen_rect(&self, rect: Rect) -> Rect {
        let (mut left, mut top) = self.screen_point(rect.left, rect.top);
        let (mut right, mut bottom) = self.screen_point(rect.right, rect.bottom);
        let (flip_x, flip_y) = self.mapping.flips();
        if flip_x {
            core::mem::swap(&mut left, &mut right);
        }
        if flip_y {
            core::mem::swap(&mut top, &mut bottom);
        }
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The surface's point and extent for a logical point and extent (a blit's): the point's, and
    /// the far corner's less it, its sign as the mapping makes it (a flipping mapping negates it).
    pub fn screen_span(&self, x: i32, y: i32, width: i32, height: i32) -> (i32, i32, i32, i32) {
        let (left, top) = self.screen_point(x, y);
        let (right, bottom) = self.screen_point(x.saturating_add(width), y.saturating_add(height));
        (
            left,
            top,
            right.saturating_sub(left),
            bottom.saturating_sub(top),
        )
    }

    /// A logical distance in device units (no origin): a round rectangle's corner, OffsetClipRgn's
    /// offset.
    pub fn device_distance(&self, dx: i32, dy: i32) -> (i32, i32) {
        self.mapping.distance_to_device(dx, dy)
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
            DC_WINDOW_ORG_X => Some(self.mapping.window_org.0 as u32),
            DC_WINDOW_ORG_Y => Some(self.mapping.window_org.1 as u32),
            DC_VIEWPORT_ORG_X => Some(self.mapping.viewport_org.0 as u32),
            DC_VIEWPORT_ORG_Y => Some(self.mapping.viewport_org.1 as u32),
            DC_WINDOW_EXT_X => Some(self.mapping.window_ext.0 as u32),
            DC_WINDOW_EXT_Y => Some(self.mapping.window_ext.1 as u32),
            DC_VIEWPORT_EXT_X => Some(self.mapping.viewport_ext.0 as u32),
            DC_VIEWPORT_EXT_Y => Some(self.mapping.viewport_ext.1 as u32),
            DC_MAP_MODE => Some(self.mapping.mode),
            DC_ROP2 => Some(self.rop2),
            DC_POLY_FILL_MODE => Some(self.fill_mode),
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
            DC_ROP2 => &mut self.rop2,
            DC_POLY_FILL_MODE => &mut self.fill_mode,
            DC_BRUSH_ORG_X => {
                return Some(core::mem::replace(&mut self.brush_org.0, value as i32) as u32)
            }
            DC_BRUSH_ORG_Y => {
                return Some(core::mem::replace(&mut self.brush_org.1, value as i32) as u32)
            }
            DC_WINDOW_ORG_X => {
                return Some(
                    core::mem::replace(&mut self.mapping.window_org.0, value as i32) as u32,
                )
            }
            DC_WINDOW_ORG_Y => {
                return Some(
                    core::mem::replace(&mut self.mapping.window_org.1, value as i32) as u32,
                )
            }
            DC_VIEWPORT_ORG_X => {
                return Some(
                    core::mem::replace(&mut self.mapping.viewport_org.0, value as i32) as u32,
                )
            }
            DC_VIEWPORT_ORG_Y => {
                return Some(
                    core::mem::replace(&mut self.mapping.viewport_org.1, value as i32) as u32,
                )
            }
            DC_WINDOW_EXT_X | DC_WINDOW_EXT_Y | DC_VIEWPORT_EXT_X | DC_VIEWPORT_EXT_Y => {
                let window = matches!(index, DC_WINDOW_EXT_X | DC_WINDOW_EXT_Y);
                let y = matches!(index, DC_WINDOW_EXT_Y | DC_VIEWPORT_EXT_Y);
                return self
                    .mapping
                    .set_ext_coordinate(window, y, value as i32)
                    .map(|previous| previous as u32);
            }
            DC_MAP_MODE => return self.mapping.set_mode(value, Device::display()),
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
            OBJ_PEN => {
                self.pen_state = super::pen::Pen::stock(index);
                &mut self.pen
            }
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

    /// Select the pen `handle`, which draws as `pen`, answering the pen it replaces.
    pub fn select_pen(&mut self, handle: u32, pen: super::pen::Pen) -> u32 {
        self.pen_state = pen;
        core::mem::replace(&mut self.pen, handle)
    }

    /// Select the font object `id`, whose handle is `handle`, answering the font it replaces (a
    /// stock font's handle or a font object's).
    pub fn select_font_object(&mut self, handle: u32, id: crate::ob::ObjectId) -> u32 {
        self.font_object = Some(id);
        core::mem::replace(&mut self.font, handle)
    }
}

// --- Clipping ------------------------------------------------------------------------------------

/// What a clipping call answers when the pool has no room for the region it makes (the DC's
/// clipping as it was).
pub const NO_ROOM: NtStatus = STATUS_NO_MEMORY;

impl Dc {
    /// The DC's extent as a region's rectangle, in device coordinates.
    fn device_extent(&self) -> Rect {
        Rect::new(0, 0, self.extent.0, self.extent.1)
    }

    /// The final region's body: the composed one, or the visible region.
    fn final_body(&self) -> &Region {
        self.rao.as_ref().unwrap_or(&self.vis)
    }

    /// The rectangles of one of the DC's own regions.
    fn rects_of(region: &Region) -> &[Rect] {
        // SAFETY: a DC's regions are its own blocks, read through the body that owns them (the
        // directory's, in its hold, or a test's): a DC handed out of the directory carries none
        // ([`DcState`]).
        unsafe { region.rects() }
    }

    /// The final region every drawing is clipped to (the surface's coordinates).
    pub fn final_region(&self) -> Clip<'_> {
        let body = self.final_body();
        Clip::new(Dc::rects_of(body), body.bounds)
    }

    /// A copy of the final region, its holder's own; none when the pool has no room.
    pub fn final_copy(&self) -> Option<OwnedRegion> {
        OwnedRegion::of_rects(Dc::rects_of(self.final_body()))
    }

    /// The clipping region's copy (device coordinates); none without one, or when the pool has
    /// no room (`Err`).
    pub fn clip_copy(&self) -> Result<Option<OwnedRegion>, NtStatus> {
        self.clip_rgn
            .as_ref()
            .map(|region| OwnedRegion::of_rects(Dc::rects_of(region)).ok_or(NO_ROOM))
            .transpose()
    }

    /// Give back the DC's regions' blocks, the DC left with empty ones: its deletion.
    pub fn release_regions(&mut self) {
        for region in [
            Some(core::mem::replace(&mut self.vis, Region::none())),
            self.meta.take(),
            self.clip_rgn.take(),
            self.rao.take(),
        ]
        .into_iter()
        .flatten()
        {
            super::region::release_storage(&region);
        }
    }

    /// Make `vis` the visible region (the old one's block given back) and compose the final
    /// region again.
    pub fn set_vis(&mut self, vis: OwnedRegion) -> bool {
        let old = core::mem::replace(&mut self.vis, vis.into_inner());
        super::region::release_storage(&old);
        self.compose()
    }

    /// Make `clip` the clipping region (device coordinates; none: no clipping region), the old
    /// one's block given back, and compose the final region again; the final region's complexity,
    /// or [`NO_ROOM`] (the clipping as it was).
    fn set_clip(&mut self, clip: Option<OwnedRegion>) -> Result<i32, NtStatus> {
        let old = core::mem::replace(&mut self.clip_rgn, clip.map(OwnedRegion::into_inner));
        if !self.compose() {
            let new = core::mem::replace(&mut self.clip_rgn, old);
            if let Some(new) = new {
                super::region::release_storage(&new);
            }
            self.compose();
            return Err(NO_ROOM);
        }
        if let Some(old) = old {
            super::region::release_storage(&old);
        }
        Ok(self.final_body().complexity())
    }

    /// The final region composed again: the visible region within the meta region and the
    /// clipping region (each moved from device coordinates to the surface's); false when the pool
    /// has no room, the final region then empty, so nothing is drawn outside the clipping asked.
    fn compose(&mut self) -> bool {
        if let Some(old) = self.rao.take() {
            super::region::release_storage(&old);
        }
        let mut answer: Option<OwnedRegion> = None;
        for limit in [self.meta.as_ref(), self.clip_rgn.as_ref()]
            .into_iter()
            .flatten()
        {
            let base = match &answer {
                Some(region) => region.rects(),
                None => Dc::rects_of(&self.vis),
            };
            let moved = OwnedRegion::moved(Dc::rects_of(limit), self.origin.0, self.origin.1);
            let Some(next) =
                moved.and_then(|moved| OwnedRegion::combined(base, moved.rects(), |a, b| a && b))
            else {
                self.rao = Some(Region::none());
                return false;
            };
            answer = Some(next);
        }
        self.rao = answer.map(OwnedRegion::into_inner);
        true
    }

    /// The device rectangle of the logical rectangle `rect`, its edges put in order.
    fn device_rect(&self, rect: Rect) -> Rect {
        let (left, top) = self.device_point(rect.left, rect.top);
        let (right, bottom) = self.device_point(rect.right, rect.bottom);
        Rect::new(
            left.min(right),
            top.min(bottom),
            left.max(right),
            top.max(bottom),
        )
    }

    /// ExtSelectClipRgn: the clipping region made what `mode` makes of it (with none, of the DC's
    /// extent) and `region` (device coordinates); RGN_COPY makes it a copy of `region`, or none
    /// for no region. The final region's complexity; STATUS_INVALID_PARAMETER for another mode or
    /// for no region in another mode (the clipping as it was).
    pub fn select_clip(&mut self, region: Option<&[Rect]>, mode: u32) -> Result<i32, NtStatus> {
        let keep = super::region::keeps(mode).ok_or(STATUS_INVALID_PARAMETER)?;
        let new = match region {
            None if mode == RGN_COPY => None,
            None => return Err(STATUS_INVALID_PARAMETER),
            Some(rects) if mode == RGN_COPY => Some(OwnedRegion::of_rects(rects).ok_or(NO_ROOM)?),
            Some(rects) => Some(self.combined_clip(rects, keep)?),
        };
        self.set_clip(new)
    }

    /// The clipping region (the DC's extent for none) combined with `rects` by `keep`.
    fn combined_clip(
        &self,
        rects: &[Rect],
        keep: fn(bool, bool) -> bool,
    ) -> Result<OwnedRegion, NtStatus> {
        let extent = self.device_extent();
        let current = match &self.clip_rgn {
            Some(region) => Dc::rects_of(region),
            None if extent.is_empty() => &[],
            None => core::slice::from_ref(&extent),
        };
        OwnedRegion::combined(current, rects, keep).ok_or(NO_ROOM)
    }

    /// IntersectClipRect: the clipping region (the DC's extent for none) cut to the logical
    /// rectangle `rect`. Windows 2000 answers COMPLEXREGION for what is left whatever its shape
    /// (the regions capture's IntersectClipRect of a rectangle within a rectangle), NULLREGION
    /// when nothing is.
    pub fn intersect_clip(&mut self, rect: Rect) -> Result<i32, NtStatus> {
        let rect = self.device_rect(rect);
        let cut: &[Rect] = if rect.is_empty() {
            &[]
        } else {
            core::slice::from_ref(&rect)
        };
        let new = self.combined_clip(cut, |a, b| a && b)?;
        let complexity = self.set_clip(Some(new))?;
        Ok(if complexity == NULLREGION {
            NULLREGION
        } else {
            COMPLEXREGION
        })
    }

    /// ExcludeClipRect: the logical rectangle `rect` taken out of the clipping region (the DC's
    /// extent for none); the final region's complexity.
    pub fn exclude_clip(&mut self, rect: Rect) -> Result<i32, NtStatus> {
        let rect = self.device_rect(rect);
        let cut: &[Rect] = if rect.is_empty() {
            &[]
        } else {
            core::slice::from_ref(&rect)
        };
        let new = self.combined_clip(cut, |a, b| a && !b)?;
        self.set_clip(Some(new))
    }

    /// OffsetClipRgn: the clipping region moved by (`dx`, `dy`) (logical units, scaled to device
    /// ones by the mapping); without one, nothing moves. The final region's complexity.
    pub fn offset_clip(&mut self, dx: i32, dy: i32) -> Result<i32, NtStatus> {
        let Some(clip) = &self.clip_rgn else {
            return Ok(self.final_body().complexity());
        };
        let (dx, dy) = self.device_distance(dx, dy);
        let moved = OwnedRegion::moved(Dc::rects_of(clip), dx, dy).ok_or(NO_ROOM)?;
        self.set_clip(Some(moved))
    }

    /// GetClipBox: the final region's complexity and box, in logical coordinates (its corners taken
    /// back through the mapping, put in order; the empty rectangle for an empty region).
    pub fn clip_box(&self) -> (i32, Rect) {
        let body = self.final_body();
        if body.count() == 0 {
            return (NULLREGION, Rect::EMPTY);
        }
        let device = body
            .bounds
            .saturating_offset_back(self.origin.0, self.origin.1);
        let (left, top) = self.mapping.to_logical(device.left, device.top);
        let (right, bottom) = self.mapping.to_logical(device.right, device.bottom);
        (
            body.complexity(),
            Rect::new(
                left.min(right),
                top.min(bottom),
                left.max(right),
                top.max(bottom),
            ),
        )
    }

    /// PtVisible: whether the logical point is inside the final region.
    pub fn point_visible(&self, x: i32, y: i32) -> bool {
        let (x, y) = self.screen_point(x, y);
        self.final_region().contains(x, y)
    }

    /// RectVisible: whether any pixel of the logical rectangle (its edges put in order) is inside
    /// the final region.
    pub fn rect_visible(&self, rect: Rect) -> bool {
        self.final_region().touches(self.screen_rect(rect))
    }
}

// --- SaveDC and RestoreDC -----------------------------------------------------------------------

impl Dc {
    /// SaveDC's copy of the DC: every attribute and object as it is, its regions copied into
    /// blocks of its own (the final region composed again); none when the pool has no room.
    pub fn saved_copy(&self) -> Option<Dc> {
        fn copied(region: Option<&Region>) -> Option<Option<OwnedRegion>> {
            match region {
                None => Some(None),
                Some(region) => OwnedRegion::of_rects(Dc::rects_of(region)).map(Some),
            }
        }
        let vis = copied(Some(&self.vis))??;
        let meta = copied(self.meta.as_ref())?;
        let clip = copied(self.clip_rgn.as_ref())?;
        let mut saved = Dc {
            vis: vis.into_inner(),
            meta: meta.map(OwnedRegion::into_inner),
            clip_rgn: clip.map(OwnedRegion::into_inner),
            rao: None,
            ..*self
        };
        if !saved.compose() {
            saved.release_regions();
            return None;
        }
        Some(saved)
    }

    /// RestoreDC's step: the DC made the saved state `saved` (whose regions it takes over), but for
    /// a screen's or a window's DC its visible region, origin and extent, which are the window's
    /// now (a memory DC's are its bitmap's, restored with it); its own regions given back. The
    /// saved states' chain is the caller's to set.
    pub fn restore_from(&mut self, saved: Dc) {
        let mut old = core::mem::replace(self, saved);
        if !self.memory {
            core::mem::swap(&mut self.vis, &mut old.vis);
            self.origin = old.origin;
            self.extent = old.extent;
        }
        self.saved_by = old.saved_by;
        old.release_regions();
        self.compose();
    }
}

/// The saved state RestoreDC(`level`) restores with `saves` states saved: its level (1 the first
/// saved), a negative `level` counting back from the last (-1); none for 0 or a level past either
/// end (ERROR_INVALID_PARAMETER, as the mapmode capture's RestoreDC(5), (0) and (-2) with one
/// saved, and RestoreDC(-1) with none).
pub fn restore_level(saves: u32, level: i32) -> Option<u32> {
    let target = if level < 0 {
        i64::from(saves) + i64::from(level) + 1
    } else {
        i64::from(level)
    };
    (level != 0 && (1..=i64::from(saves)).contains(&target)).then_some(target as u32)
}

/// A DC's state as a service draws with it, out of the directory: the DC's attributes, and a copy
/// of its final region, the holder's own (the DC's own regions are not in it: their blocks are
/// the directory's body's, which another thread's call may give back).
#[derive(Debug)]
pub struct DcState {
    dc: Dc,
    clip: OwnedRegion,
}

impl DcState {
    /// The state of the DC `dc` (read in the hold of the directory that holds it); none when the
    /// pool has no room for its final region's copy.
    pub fn of(dc: &Dc) -> Option<DcState> {
        let clip = dc.final_copy()?;
        let mut copy = *dc;
        copy.vis = Region::none();
        copy.meta = None;
        copy.clip_rgn = None;
        copy.rao = None;
        Some(DcState { dc: copy, clip })
    }

    /// The final region every drawing is clipped to (the surface's coordinates).
    pub fn clip(&self) -> Clip<'_> {
        self.clip.clip()
    }
}

impl core::ops::Deref for DcState {
    type Target = Dc;

    fn deref(&self) -> &Dc {
        &self.dc
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
/// GetDCEx's flag for a DC out of the DC cache.
pub const DCX_CACHE: u32 = 0x0000_0002;
/// GetDCEx's flag for the DC its window's class style picks (GetDC's and GetWindowDC's own).
pub const DCX_USESTYLE: u32 = 0x0001_0000;

/// Whether GetDCEx with `flags` has a DC to answer for a window whose class style is
/// `class_style`. Windows 2000's _GetDCEx takes a DC out of its cache for DCX_CACHE, and for
/// DCX_USESTYLE (which GetDC and GetWindowDC pass) when the class keeps no DC of its own; with
/// neither it answers the window's own or class DC (CS_OWNDC, CS_CLASSDC), and NULL for a window
/// whose class keeps none, with no error. So the guidc capture's GetDCEx(h, NULL, DCX_WINDOW)
/// answers NULL where GetWindowDC answers a DC, and WM_NCPAINT's documented GetDCEx(hwnd, hrgn,
/// DCX_WINDOW | DCX_INTERSECTRGN) needs DCX_CACHE added to work.
pub fn answers_dc(flags: u32, class_style: u32) -> bool {
    flags & (DCX_CACHE | DCX_USESTYLE) != 0 || class_style & (CS_OWNDC | CS_CLASSDC) != 0
}

/// NtUserGetDC(Window, Dc): a DC of the window's client area (the screen's for no window).
pub fn get_dc(call: &mut NtCall, window: Handle, out: UserPtr<u32>) -> NtResult {
    window_dc(call, window, false, out)
}

/// NtUserGetDCEx(Window, Region, Flags, Dc): GetDC's DC, or GetWindowDC's with DCX_WINDOW; 0 (and
/// success: Windows 2000 sets no error) for a window that has no DC for `flags` (see
/// [`answers_dc`]). The region and the clipping flags are not looked at: there are no visible
/// regions to clip to yet.
pub fn get_dc_ex(
    call: &mut NtCall,
    window: Handle,
    _region: Handle,
    flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    if window.raw() != 0 && !answers_dc(flags, class_style(call, window)?) {
        out.write(0)?;
        return Ok(STATUS_SUCCESS);
    }
    window_dc(call, window, flags & DCX_WINDOW != 0, out)
}

/// NtUserGetWindowDC(Window, Dc): a DC of the window's rectangle, its non-client area included
/// (the screen's for no window).
pub fn get_window_dc(call: &mut NtCall, window: Handle, out: UserPtr<u32>) -> NtResult {
    window_dc(call, window, true, out)
}

/// NtGdiDeleteObjectApp(Object): a DC's, a brush's, a font's, a bitmap's or a region's handle
/// closed (the object goes with it); a global object stays (it is never deleted: the call
/// succeeds); STATUS_INVALID_HANDLE for anything else.
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

/// NtGdiSelectPen(Dc, Pen, Previous): a stock pen or a pen object, either kind (see
/// [`super::pen::pen_of`]).
pub fn select_pen(call: &mut NtCall, dc: Handle, object: Handle, out: UserPtr<u32>) -> NtResult {
    dc_of(call, dc)?;
    let pen = super::pen::pen_of(call, object)?;
    let previous = update_dc(call, dc, |dc| dc.select_pen(object.raw(), pen))?;
    out.write(previous)?;
    Ok(STATUS_SUCCESS)
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
        dc.clip(),
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
        set_pixel_on(Some(surface), dc.clip(), x, y, color)
    })
    .unwrap_or(CLR_INVALID);
    out.write(set)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetPixel(Dc, X, Y, Color): the pixel's COLORREF (or CLR_INVALID) into `out`.
pub fn get_pixel(call: &mut NtCall, dc: Handle, x: i32, y: i32, out: UserPtr<u32>) -> NtResult {
    let (_reference, dc) = dc_of(call, dc)?;
    let (x, y) = dc.screen_point(x, y);
    let color = with_surface(&dc, |surface| get_pixel_on(Some(surface), dc.clip(), x, y))
        .unwrap_or(CLR_INVALID);
    out.write(color)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiExtSelectClipRgn(Dc, Region, Mode, Complexity): see [`Dc::select_clip`]; the region (a
/// null handle: none) is read as it is now, a copy kept (the caller may delete it).
pub fn ext_select_clip_rgn(
    call: &mut NtCall,
    dc: Handle,
    region: Handle,
    mode: u32,
    out: UserPtr<u32>,
) -> NtResult {
    dc_of(call, dc)?;
    let source = if region.raw() == 0 {
        None
    } else {
        Some(super::region::copy_of(call, region)?)
    };
    let rects = source.as_ref().map(OwnedRegion::rects);
    let complexity = update_dc(call, dc, |dc| dc.select_clip(rects, mode))??;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiIntersectClipRect(Dc, Left, Top, Right, Bottom, Complexity): see
/// [`Dc::intersect_clip`].
pub fn intersect_clip_rect(
    call: &mut NtCall,
    dc: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let rect = Rect::new(left, top, right, bottom);
    let complexity = update_dc(call, dc, |dc| dc.intersect_clip(rect))??;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiExcludeClipRect(Dc, Left, Top, Right, Bottom, Complexity): see [`Dc::exclude_clip`].
pub fn exclude_clip_rect(
    call: &mut NtCall,
    dc: Handle,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let rect = Rect::new(left, top, right, bottom);
    let complexity = update_dc(call, dc, |dc| dc.exclude_clip(rect))??;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiOffsetClipRgn(Dc, X, Y, Complexity): see [`Dc::offset_clip`].
pub fn offset_clip_rgn(
    call: &mut NtCall,
    dc: Handle,
    x: i32,
    y: i32,
    out: UserPtr<u32>,
) -> NtResult {
    let complexity = update_dc(call, dc, |dc| dc.offset_clip(x, y))??;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetAppClipBox(Dc, Box, Complexity): see [`Dc::clip_box`].
pub fn get_app_clip_box(
    call: &mut NtCall,
    dc: Handle,
    rect: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let (complexity, bounds) = update_dc(call, dc, |dc| dc.clip_box())?;
    rect.cast::<Rect>().write(bounds)?;
    out.write(complexity as u32)?;
    Ok(STATUS_SUCCESS)
}

/// GetRandomRgn's CLIPRGN: the clipping region.
pub const CLIPRGN: u32 = 1;

/// NtGdiGetRandomRgn(Dc, Region, Which, Result): with [`CLIPRGN`], the region made a copy of the
/// clipping region (device coordinates) and 1 answered, or 0 without one (the region untouched);
/// STATUS_INVALID_PARAMETER for another region kind.
pub fn get_random_rgn(
    call: &mut NtCall,
    dc: Handle,
    region: Handle,
    which: u32,
    out: UserPtr<u32>,
) -> NtResult {
    if which != CLIPRGN {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let clip = update_dc(call, dc, |dc| dc.clip_copy())??;
    let answer = match clip {
        Some(clip) => {
            super::region::assign(call, region, &clip)?;
            1
        }
        None => {
            super::region::copy_of(call, region)?;
            0
        }
    };
    out.write(answer)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiPtVisible(Dc, X, Y, Visible): see [`Dc::point_visible`].
pub fn pt_visible(call: &mut NtCall, dc: Handle, x: i32, y: i32, out: UserPtr<u32>) -> NtResult {
    let visible = update_dc(call, dc, |dc| dc.point_visible(x, y))?;
    out.write(visible as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiRectVisible(Dc, Rect, Visible): see [`Dc::rect_visible`].
pub fn rect_visible(call: &mut NtCall, dc: Handle, rect: UserAddr, out: UserPtr<u32>) -> NtResult {
    let rect = rect.cast::<Rect>().read()?;
    let visible = update_dc(call, dc, |dc| dc.rect_visible(rect))?;
    out.write(visible as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiSaveDC(Dc, Level): the DC's state saved (see the module notes), its level (how many are
/// saved now) into `out`; STATUS_NO_MEMORY when the pool has no room for its regions,
/// STATUS_INSUFFICIENT_RESOURCES when the DCs' pool is full.
pub fn save_dc(call: &mut NtCall, dc: Handle, out: UserPtr<u32>) -> NtResult {
    let level = save_state(call, dc)?;
    out.write(level)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiRestoreDC(Dc, Level): the saved state `level` names ([`restore_level`]) restored, the ones
/// saved after it dropped; STATUS_INVALID_PARAMETER for a level that names none.
pub fn restore_dc(call: &mut NtCall, dc: Handle, level: i32) -> NtResult {
    restore_state(call, dc, level)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiComputeXformCoefficients(Dc): the page transform made whole after gdi32 set an extent's
/// two coordinates one at a time: MM_ISOTROPIC's adjustment ([`Mapping::fix_isotropic`]).
pub fn compute_xform_coefficients(call: &mut NtCall, dc: Handle) -> NtResult {
    update_dc(call, dc, |dc| dc.mapping.fix_isotropic(Device::display()))?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiScaleViewportExtEx and NtGdiScaleWindowExtEx's work: the extents scaled
/// ([`Mapping::scale_viewport_ext`], [`Mapping::scale_window_ext`]), 1 or 0 into `out` (a failure
/// sets no error, as the mapmode capture's). The previous extents go into the SIZE at `previous`
/// (unless null): the viewport's always, the window's unless the scale fails in a mode that takes
/// it, as the capture's ScaleWindowExtEx(0/1) leaves its SIZE unwritten.
#[allow(clippy::too_many_arguments)]
fn scale_ext(
    call: &mut NtCall,
    dc: Handle,
    window: bool,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    previous: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let (old, scalable, scaled) = update_dc(call, dc, |dc| {
        let mapping = &mut dc.mapping;
        let old = if window {
            mapping.window_ext
        } else {
            mapping.viewport_ext
        };
        let scalable = mapping.scalable();
        let scaled = if window {
            mapping.scale_window_ext(x_num, x_den, y_num, y_den, Device::display())
        } else {
            mapping.scale_viewport_ext(x_num, x_den, y_num, y_den, Device::display())
        };
        (old, scalable, scaled)
    })?;
    if !previous.is_null() && (scaled || !window || !scalable) {
        previous.cast::<Size>().write(Size {
            cx: old.0,
            cy: old.1,
        })?;
    }
    out.write(scaled as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiScaleViewportExtEx(Dc, XNum, XDenom, YNum, YDenom, Previous, Result): see [`scale_ext`].
#[allow(clippy::too_many_arguments)]
pub fn scale_viewport_ext_ex(
    call: &mut NtCall,
    dc: Handle,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    previous: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    scale_ext(call, dc, false, x_num, x_den, y_num, y_den, previous, out)
}

/// NtGdiScaleWindowExtEx(Dc, XNum, XDenom, YNum, YDenom, Previous, Result): see [`scale_ext`].
#[allow(clippy::too_many_arguments)]
pub fn scale_window_ext_ex(
    call: &mut NtCall,
    dc: Handle,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    previous: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    scale_ext(call, dc, true, x_num, x_den, y_num, y_den, previous, out)
}

/// NtGdiTransformPoints(Dc, In, Out, Count, Mode): the `count` POINTs at `points_in` taken through
/// the DC's mapping, logical to device (XFP_LPTODP, LPtoDP's) or back (XFP_DPTOLP, DPtoLP's), into
/// the POINTs at `points_out` (the same memory, for gdi32's calls); STATUS_INVALID_PARAMETER for
/// another mode.
pub fn transform_points(
    call: &mut NtCall,
    dc: Handle,
    points_in: UserAddr,
    points_out: UserAddr,
    count: u32,
    mode: u32,
) -> NtResult {
    if !matches!(mode, XFP_LPTODP | XFP_DPTOLP) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_reference, state) = dc_of(call, dc)?;
    let mapping = state.mapping;
    let mut chunk = [Point::default(); CHUNK];
    let mut done = 0u32;
    while done < count {
        let length = (count - done).min(CHUNK as u32) as usize;
        points_in
            .offset(8 * done)
            .read(&mut chunk.as_bytes_mut()[..8 * length])?;
        for point in &mut chunk[..length] {
            let (x, y) = if mode == XFP_LPTODP {
                mapping.to_device(point.x, point.y)
            } else {
                mapping.to_logical(point.x, point.y)
            };
            *point = Point { x, y };
        }
        points_out
            .offset(8 * done)
            .write(&chunk.as_bytes()[..8 * length])?;
        done += length as u32;
    }
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

/// The class style of the window `window` names; STATUS_INVALID_HANDLE for a handle that names
/// none.
#[cfg(target_arch = "x86")]
fn class_style(call: &mut NtCall, window: Handle) -> Result<u32, NtStatus> {
    crate::win32k::queue::with_manager(call.passive(), |m| {
        m.windows.window_from_handle(window.raw())?;
        Some(
            m.windows
                .class_window(window.raw())
                .map_or(0, |w| m.classes.class_data(w.class).style),
        )
    })
    .ok_or(STATUS_INVALID_HANDLE)
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

/// BeginPaint's DC: a DC of the window's client area `client` (screen coordinates), its visible
/// region cut to `update` (the update region, client coordinates), its handle the calling
/// process's; STATUS_INSUFFICIENT_RESOURCES when the DCs' pool or the GDI table is full,
/// STATUS_NO_MEMORY when the pool has no room for the region.
#[cfg(target_arch = "x86")]
pub(super) fn paint_dc(
    call: &mut NtCall,
    client: Rect,
    update: &OwnedRegion,
) -> Result<u32, NtStatus> {
    let (width, height) = screen_extent();
    let mut dc = Dc::window(width, height, client);
    let painted = paint_vis(&dc, update).ok_or(STATUS_NO_MEMORY);
    let painted = match painted {
        Ok(painted) => painted,
        Err(status) => {
            dc.release_regions();
            return Err(status);
        }
    };
    if !dc.set_vis(painted) {
        dc.release_regions();
        return Err(STATUS_NO_MEMORY);
    }
    publish_dc(call, dc)
}

/// BeginPaint's visible region: the window DC's `dc` cut to the update region `update` (client
/// coordinates, moved to the screen's by the DC's origin); none when the pool has no room.
pub fn paint_vis(dc: &Dc, update: &OwnedRegion) -> Option<OwnedRegion> {
    let moved = OwnedRegion::moved(update.rects(), dc.origin.0, dc.origin.1)?;
    OwnedRegion::combined(Dc::rects_of(&dc.vis), moved.rects(), |a, b| a && b)
}

/// EndPaint's release of BeginPaint's DC: its handle closed; STATUS_INVALID_HANDLE when the handle
/// names no DC.
#[cfg(target_arch = "x86")]
pub(super) fn release_paint_dc(call: &mut NtCall, handle: u32) -> Result<(), NtStatus> {
    close_dc(call, Handle(handle))
}

/// A DC of state `dc` made, its GDI handle the calling process's ([`super::gdi`]);
/// STATUS_INSUFFICIENT_RESOURCES when the DCs' pool is full, the GDI table's refusal's status
/// (STATUS_NO_MEMORY: the process's quota, the table's ceiling) when it gives no handle.
#[cfg(target_arch = "x86")]
fn publish_dc(_call: &mut NtCall, mut dc: Dc) -> Result<u32, NtStatus> {
    let Some(id) = crate::ob::locked(|directory| directory.create_dc(dc)) else {
        dc.release_regions();
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    super::gdi::insert(id)
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
/// brush, a font, a bitmap or a region (its kind in its bits: [`rtl::gdi::object_of`]),
/// DeleteObject's; STATUS_INVALID_HANDLE otherwise.
#[cfg(target_arch = "x86")]
fn close_object(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
    match object_of(handle.raw()) {
        Some((OBJ_BRUSH, _)) if super::gdi::delete(handle.raw(), OBJ_BRUSH) => Ok(()),
        Some((OBJ_FONT, _)) => super::fonts::delete_font(call, handle),
        Some((rtl::dib::OBJ_BITMAP, _)) => super::bitmap::delete_bitmap(call, handle.raw()),
        Some((OBJ_REGION, _)) if super::gdi::delete(handle.raw(), OBJ_REGION) => Ok(()),
        Some((OBJ_PEN | OBJ_EXTPEN, _)) if super::pen::close_pen(call, handle.raw()) => Ok(()),
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
/// reference, and its state as it is now ([`DcState`]); STATUS_NO_MEMORY when the pool has no
/// room for its final region's copy.
#[cfg(target_arch = "x86")]
pub(super) fn dc_of(
    _call: &mut NtCall,
    handle: Handle,
) -> Result<(crate::ob::ObRef, DcState), NtStatus> {
    let reference =
        super::gdi::reference(handle.raw(), super::gdi::DC_KIND).ok_or(STATUS_INVALID_HANDLE)?;
    let dc = crate::ob::locked(|directory| directory.dc(reference.id()).map(|dc| DcState::of(dc)))
        .ok_or(STATUS_INVALID_HANDLE)?
        .ok_or(STATUS_NO_MEMORY)?;
    Ok((reference, dc))
}

/// SaveDC's work on the DC `handle` names: a copy of it made a DC object of its own, chained from
/// the DC (the DC's reference on it); the DC's level answered.
#[cfg(target_arch = "x86")]
fn save_state(call: &mut NtCall, handle: Handle) -> Result<u32, NtStatus> {
    let (reference, _) = dc_of(call, handle)?;
    let id = reference.id();
    crate::ob::locked(|directory| {
        let live = *directory.dc(id).ok_or(STATUS_INVALID_HANDLE)?;
        let mut copy = live.saved_copy().ok_or(STATUS_NO_MEMORY)?;
        copy.saved_by = Some(id);
        let Some(saved) = directory.create_dc(copy) else {
            copy.release_regions();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        let live = directory.dc(id).expect("a referenced DC lives");
        live.saved = Some(saved);
        live.saves += 1;
        Ok(live.saves)
    })
}

/// RestoreDC's work on the DC `handle` names: the states above the one `level` names dropped
/// (their objects released), that one's taken back into the DC and dropped too.
#[cfg(target_arch = "x86")]
fn restore_state(call: &mut NtCall, handle: Handle, level: i32) -> Result<(), NtStatus> {
    let (reference, _) = dc_of(call, handle)?;
    let id = reference.id();
    crate::ob::locked(|directory| {
        let live = *directory.dc(id).ok_or(STATUS_INVALID_HANDLE)?;
        let target = restore_level(live.saves, level).ok_or(STATUS_INVALID_PARAMETER)?;
        let mut top = live.saved;
        for _ in target..live.saves {
            let state = top.expect("a saved state per level");
            top = directory.dc(state).and_then(|state| state.saved.take());
            let followup = directory.dereference(state);
            debug_assert!(
                followup.is_none(),
                "a DC's deletion leaves nothing to finish"
            );
        }
        let state = top.expect("a saved state per level");
        let mut saved = core::mem::replace(
            directory.dc(state).expect("a saved state lives"),
            Dc::none(),
        );
        let followup = directory.dereference(state);
        debug_assert!(
            followup.is_none(),
            "a DC's deletion leaves nothing to finish"
        );
        let chain = saved.saved.take();
        let live = directory.dc(id).expect("a referenced DC lives");
        live.restore_from(saved);
        live.saved = chain;
        live.saves = target - 1;
        Ok(())
    })
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
fn class_style(_: &mut NtCall, _: Handle) -> Result<u32, NtStatus> {
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
fn save_state(_: &mut NtCall, _: Handle) -> Result<u32, NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
fn restore_state(_: &mut NtCall, _: Handle, _: i32) -> Result<(), NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
pub(super) fn dc_of(_: &mut NtCall, _: Handle) -> Result<((), DcState), NtStatus> {
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
    /// GetDCEx takes a DC from the cache for DCX_CACHE or DCX_USESTYLE; with neither, only a
    /// window whose class keeps its own DC has one: the guidc capture's GetDCEx(h, NULL,
    /// DCX_WINDOW) of a CS_HREDRAW | CS_VREDRAW class answers NULL.
    #[test]
    fn get_dc_ex_without_the_cache_needs_a_dc_of_the_class() {
        let redraw = 0x0001 | 0x0002;
        assert!(!answers_dc(DCX_WINDOW, redraw));
        assert!(!answers_dc(0, 0));
        assert!(answers_dc(DCX_WINDOW | DCX_CACHE, redraw));
        assert!(
            answers_dc(DCX_WINDOW | DCX_USESTYLE, redraw),
            "GetWindowDC's"
        );
        assert!(answers_dc(DCX_USESTYLE, 0), "GetDC's");
        assert!(answers_dc(DCX_WINDOW, CS_OWNDC));
        assert!(answers_dc(0, CS_CLASSDC));
    }

    #[test]
    fn a_screen_dc_starts_at_the_defaults() {
        let dc = Dc::screen(640, 480);
        assert_eq!(dc.final_region().bounds(), Rect::new(0, 0, 640, 480));
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
            Dc::screen(0, 0).final_region().bounds(),
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
        assert_eq!(dc.set_attribute(99, 1), None);
        assert_eq!(dc, before);
        assert_eq!(dc.attribute(DC_TEXT_COLOR), Some(0x00_00FF));
        assert_eq!(dc.attribute(DC_BK_COLOR), Some(0xFF_0000));
        assert_eq!(dc.attribute(DC_BK_MODE), Some(OPAQUE));
        assert_eq!(dc.attribute(99), None);
        // The mix mode and the fill mode take any value, as the shapes capture's SetROP2(17) and
        // SetPolyFillMode(3) do.
        assert_eq!(dc.set_attribute(DC_ROP2, 17), Some(R2_COPYPEN));
        assert_eq!(dc.attribute(DC_ROP2), Some(17));
        assert_eq!(dc.set_attribute(DC_POLY_FILL_MODE, 3), Some(ALTERNATE));
        assert_eq!(dc.attribute(DC_POLY_FILL_MODE), Some(3));
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

    /// The window origin moves the logical coordinates (the regions capture's FillRgn through
    /// the window origin -1,-1 paints one pixel right and down), not the brush origin.
    #[test]
    fn the_window_origin_moves_the_logical_coordinates() {
        let mut dc = Dc::window(640, 480, Rect::new(100, 50, 300, 250));
        assert_eq!(dc.set_attribute(DC_WINDOW_ORG_X, -1i32 as u32), Some(0));
        assert_eq!(dc.set_attribute(DC_WINDOW_ORG_Y, -1i32 as u32), Some(0));
        assert_eq!(dc.attribute(DC_WINDOW_ORG_X), Some(-1i32 as u32));
        assert_eq!(dc.screen_point(0, 0), (101, 51));
        assert_eq!(
            dc.screen_rect(Rect::new(0, 0, 6, 3)),
            Rect::new(101, 51, 107, 54)
        );
        assert_eq!(dc.pattern_origin(), (100, 50));
    }

    /// A memory DC holds the default bitmap, its clipping region that bitmap's 1 by 1; a bitmap
    /// selected answers the one it replaces and makes its extent the clipping region.
    #[test]
    fn a_memory_dc_holds_its_bitmap() {
        let mut dc = Dc::memory();
        assert!(dc.memory);
        assert_eq!(dc.object(rtl::dib::OBJ_BITMAP), Some(DEFAULT_BITMAP));
        assert_eq!(dc.final_region().bounds(), Rect::new(0, 0, 1, 1));
        assert_eq!(dc.select_bitmap(0x7_0010, None, 16, 8), DEFAULT_BITMAP);
        assert_eq!(dc.final_region().bounds(), Rect::new(0, 0, 16, 8));
        assert_eq!(dc.select_bitmap(DEFAULT_BITMAP, None, 1, 1), 0x7_0010);
    }

    /// A window's DC: its origin the area's top left, its clipping region the area cut to the
    /// screen; the logical coordinates land at the origin.
    #[test]
    fn a_window_dc_draws_at_its_origin_clipped() {
        let dc = Dc::window(640, 480, Rect::new(600, 30, 700, 80));
        assert_eq!(dc.origin, (600, 30));
        assert_eq!(
            dc.final_region().bounds(),
            Rect::new(600, 30, 640, 80),
            "cut to the screen"
        );
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
            Dc::window(640, 480, Rect::new(-10, -10, -1, -1))
                .final_region()
                .bounds(),
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

    /// A 16x12 memory DC, as the regions capture's canvas.
    fn canvas() -> Dc {
        let mut dc = Dc::memory();
        dc.select_bitmap(0x7_0010, None, 16, 12);
        dc
    }

    /// The final region's rectangles.
    fn final_rects(dc: &Dc) -> std::vec::Vec<Rect> {
        dc.final_region().rects_for_tests().to_vec()
    }

    /// The clipping region's rectangles (device coordinates), none without one.
    fn clip_rects(dc: &Dc) -> Option<std::vec::Vec<Rect>> {
        dc.clip_copy()
            .unwrap()
            .map(|region| region.rects().to_vec())
    }

    /// The regions capture's `clip` section: SelectClipRgn of a rectangle, IntersectClipRect
    /// (COMPLEXREGION whatever is left), ExcludeClipRect's hole, PtVisible and RectVisible,
    /// OffsetClipRgn, and SelectClipRgn(NULL) back to the canvas.
    #[test]
    fn the_capture_clip_section() {
        let mut dc = canvas();
        assert_eq!(clip_rects(&dc), None);
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(0, 0, 16, 12)));
        assert!(dc.point_visible(15, 11));
        assert!(!dc.point_visible(16, 0));
        assert!(!dc.point_visible(-1, 0));
        assert!(dc.rect_visible(Rect::new(14, 10, 20, 20)));
        assert!(!dc.rect_visible(Rect::new(16, 0, 20, 4)));

        let a = [Rect::new(2, 2, 10, 8)];
        assert_eq!(dc.select_clip(Some(&a), RGN_COPY), Ok(SIMPLEREGION));
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(2, 2, 10, 8)));
        assert_eq!(clip_rects(&dc), Some(a.to_vec()));

        assert_eq!(dc.intersect_clip(Rect::new(4, 0, 16, 6)), Ok(COMPLEXREGION));
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(4, 2, 10, 6)));

        assert_eq!(dc.exclude_clip(Rect::new(6, 3, 8, 5)), Ok(COMPLEXREGION));
        assert_eq!(dc.clip_box(), (COMPLEXREGION, Rect::new(4, 2, 10, 6)));
        let holed = [
            Rect::new(4, 2, 10, 3),
            Rect::new(4, 3, 6, 5),
            Rect::new(8, 3, 10, 5),
            Rect::new(4, 5, 10, 6),
        ];
        assert_eq!(clip_rects(&dc), Some(holed.to_vec()));
        assert_eq!(final_rects(&dc), holed.to_vec());
        assert!(!dc.point_visible(6, 3));
        assert!(dc.point_visible(5, 3));
        assert!(dc.point_visible(9, 5));
        assert!(!dc.rect_visible(Rect::new(6, 3, 8, 5)));
        assert!(dc.rect_visible(Rect::new(5, 3, 7, 4)));
        assert!(!dc.rect_visible(Rect::new(0, 0, 4, 12)));

        assert_eq!(dc.offset_clip(2, 3), Ok(COMPLEXREGION));
        assert_eq!(dc.clip_box(), (COMPLEXREGION, Rect::new(6, 5, 12, 9)));

        assert_eq!(dc.select_clip(None, RGN_COPY), Ok(SIMPLEREGION));
        assert_eq!(clip_rects(&dc), None);
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(0, 0, 16, 12)));
        assert_eq!(dc.offset_clip(1, 1), Ok(SIMPLEREGION));
        assert_eq!(clip_rects(&dc), None, "nothing to move");
        dc.release_regions();
    }

    /// The regions capture's `extclip` section: each mode over a clipping region; NULL in a mode
    /// that is not RGN_COPY fails, the clipping as it was; with no clipping region a mode works on
    /// the canvas; the window origin moves IntersectClipRect's rectangle, not GetClipRgn's.
    #[test]
    fn the_capture_extclip_section() {
        let mut dc = canvas();
        let (a, b) = ([Rect::new(2, 2, 10, 8)], [Rect::new(6, 5, 14, 11)]);
        let modes = [
            (RGN_AND, SIMPLEREGION, Rect::new(6, 5, 10, 8)),
            (RGN_OR, COMPLEXREGION, Rect::new(2, 2, 14, 11)),
            (RGN_XOR, COMPLEXREGION, Rect::new(2, 2, 14, 11)),
            (RGN_DIFF, COMPLEXREGION, Rect::new(2, 2, 10, 8)),
            (RGN_COPY, SIMPLEREGION, Rect::new(6, 5, 14, 11)),
        ];
        for (mode, complexity, bounds) in modes {
            dc.select_clip(Some(&a), RGN_COPY).unwrap();
            assert_eq!(
                dc.select_clip(Some(&b), mode),
                Ok(complexity),
                "mode {mode}"
            );
            assert_eq!(dc.clip_box(), (complexity, bounds), "mode {mode}");
        }
        dc.select_clip(Some(&a), RGN_COPY).unwrap();
        assert_eq!(dc.select_clip(None, RGN_AND), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(2, 2, 10, 8)));

        let none = |dc: &mut Dc, mode| {
            dc.select_clip(None, RGN_COPY).unwrap();
            dc.select_clip(Some(&b), mode).unwrap();
            dc.clip_box()
        };
        assert_eq!(
            none(&mut dc, RGN_AND),
            (SIMPLEREGION, Rect::new(6, 5, 14, 11))
        );
        assert_eq!(
            none(&mut dc, RGN_OR),
            (SIMPLEREGION, Rect::new(0, 0, 16, 12))
        );
        assert_eq!(
            none(&mut dc, RGN_DIFF),
            (COMPLEXREGION, Rect::new(0, 0, 16, 12))
        );
        assert_eq!(
            final_rects(&dc),
            [
                Rect::new(0, 0, 16, 5),
                Rect::new(0, 5, 6, 11),
                Rect::new(14, 5, 16, 11),
                Rect::new(0, 11, 16, 12),
            ]
        );

        dc.select_clip(None, RGN_COPY).unwrap();
        assert_eq!(dc.exclude_clip(Rect::new(4, 4, 8, 8)), Ok(COMPLEXREGION));
        assert_eq!(dc.clip_box(), (COMPLEXREGION, Rect::new(0, 0, 16, 12)));

        dc.select_clip(None, RGN_COPY).unwrap();
        dc.set_attribute(DC_WINDOW_ORG_X, 2);
        dc.set_attribute(DC_WINDOW_ORG_Y, 1);
        assert_eq!(dc.intersect_clip(Rect::new(2, 1, 6, 4)), Ok(COMPLEXREGION));
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(2, 1, 6, 4)));
        assert_eq!(clip_rects(&dc), Some(std::vec![Rect::new(0, 0, 4, 3)]));
        assert_eq!(final_rects(&dc), [Rect::new(0, 0, 4, 3)]);
        dc.release_regions();
    }

    /// A window DC's clipping region is in device coordinates, from its origin: the final region
    /// is it moved onto the screen, within the visible region.
    #[test]
    fn a_window_dcs_clipping_region_is_from_its_origin() {
        let mut dc = Dc::window(640, 480, Rect::new(600, 30, 700, 80));
        assert_eq!(dc.extent, (100, 50));
        assert_eq!(
            dc.select_clip(Some(&[Rect::new(30, 10, 60, 20)]), RGN_COPY),
            Ok(SIMPLEREGION)
        );
        assert_eq!(
            final_rects(&dc),
            [Rect::new(630, 40, 640, 50)],
            "cut to the screen"
        );
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(30, 10, 40, 20)));
        assert!(dc.point_visible(35, 15));
        assert!(!dc.point_visible(45, 15), "off the screen");
        dc.release_regions();
    }

    /// The mapmode capture's `drawing`: a doubling mapping scales a blit's rectangle, a flipped
    /// one negates its height from the far corner; the clipping calls' logical rectangles go
    /// through it, GetClipBox's box comes back through it, and OffsetClipRgn's offset scales.
    #[test]
    fn the_mapping_moves_every_coordinate() {
        let mut dc = canvas();
        dc.set_attribute(DC_MAP_MODE, rtl::gdi::MM_ANISOTROPIC);
        assert!(dc.mapping.set_window_ext(8, 6, Device::display()));
        assert!(dc.mapping.set_viewport_ext(16, 12, Device::display()));
        assert_eq!(dc.screen_span(1, 1, 3, 2), (2, 2, 6, 4));
        assert_eq!(
            dc.screen_rect(Rect::new(1, 1, 6, 5)),
            Rect::new(2, 2, 12, 10)
        );
        assert_eq!(dc.intersect_clip(Rect::new(1, 1, 4, 3)), Ok(COMPLEXREGION));
        assert_eq!(clip_rects(&dc), Some(std::vec![Rect::new(2, 2, 8, 6)]));
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(1, 1, 4, 3)));
        assert!(dc.point_visible(1, 1));
        assert!(!dc.point_visible(4, 1));
        assert_eq!(dc.offset_clip(1, 0), Ok(SIMPLEREGION));
        assert_eq!(clip_rects(&dc), Some(std::vec![Rect::new(4, 2, 10, 6)]));

        assert!(dc.mapping.set_viewport_ext(16, -12, Device::display()));
        dc.set_attribute(DC_VIEWPORT_ORG_Y, 12);
        assert_eq!(dc.screen_span(1, 1, 3, 2), (2, 10, 6, -4));
        assert_eq!(
            dc.screen_rect(Rect::new(1, 1, 4, 3)),
            Rect::new(2, 6, 8, 10),
            "an ordered rectangle stays one"
        );
        assert_eq!(dc.clip_box(), (SIMPLEREGION, Rect::new(2, 3, 5, 5)));
        dc.release_regions();
    }

    /// The mapping's attributes: the mode sets its extents; an extent's coordinate is taken only
    /// in a mode that takes extents, never 0.
    #[test]
    fn the_mapping_attributes() {
        let mut dc = Dc::memory();
        assert_eq!(dc.attribute(DC_MAP_MODE), Some(rtl::gdi::MM_TEXT));
        assert_eq!(
            dc.set_attribute(DC_WINDOW_EXT_X, 5),
            None,
            "MM_TEXT's are fixed"
        );
        assert_eq!(dc.set_attribute(DC_MAP_MODE, 9), None);
        assert_eq!(
            dc.set_attribute(DC_MAP_MODE, rtl::gdi::MM_ANISOTROPIC),
            Some(rtl::gdi::MM_TEXT)
        );
        assert_eq!(dc.set_attribute(DC_WINDOW_EXT_X, 5), Some(1));
        assert_eq!(dc.set_attribute(DC_VIEWPORT_EXT_Y, 0), None);
        assert_eq!(dc.set_attribute(DC_VIEWPORT_EXT_Y, -7i32 as u32), Some(1));
        assert_eq!(dc.attribute(DC_VIEWPORT_EXT_Y), Some(-7i32 as u32));
        assert_eq!(dc.set_attribute(DC_VIEWPORT_ORG_X, 3), Some(0));
        assert_eq!(dc.mapping.viewport_org, (3, 0));
        assert_eq!(dc.mapping.window_ext, (5, 1));
        dc.release_regions();
    }

    /// RestoreDC's levels, as the mapmode capture's `savedc` asks them: -1 the last, a positive
    /// level absolute; 0, and a level past either end, none.
    #[test]
    fn restore_levels() {
        assert_eq!(restore_level(3, -1), Some(3));
        assert_eq!(restore_level(2, -1), Some(2));
        assert_eq!(restore_level(3, 1), Some(1));
        assert_eq!(restore_level(0, -1), None);
        assert_eq!(restore_level(1, 5), None);
        assert_eq!(restore_level(1, 0), None);
        assert_eq!(restore_level(1, -2), None);
        assert_eq!(restore_level(1, 1), Some(1));
        assert_eq!(
            restore_level(u32::MAX, i32::MIN),
            Some(u32::MAX - 0x8000_0000 + 1)
        );
    }

    /// SaveDC's copy carries every attribute and a copy of the clipping region of its own; a
    /// restore takes them all back (a memory DC its visible region too, its bitmap's).
    #[test]
    fn a_saved_state_restores_the_whole_dc() {
        let mut dc = canvas();
        dc.select_clip(Some(&[Rect::new(2, 2, 10, 8)]), RGN_COPY)
            .unwrap();
        dc.set_attribute(DC_MAP_MODE, rtl::gdi::MM_ANISOTROPIC);
        dc.set_attribute(DC_WINDOW_ORG_X, 5);
        dc.set_attribute(DC_TEXT_COLOR, 0xFF);
        dc.set_attribute(DC_ROP2, 7);
        dc.current = (3, 4);
        let saved = dc.saved_copy().unwrap();
        assert_eq!(clip_rects(&saved), clip_rects(&dc));

        dc.select_clip(None, RGN_COPY).unwrap();
        dc.set_attribute(DC_MAP_MODE, rtl::gdi::MM_LOMETRIC);
        dc.set_attribute(DC_TEXT_COLOR, 0xFF00);
        dc.select_bitmap(0x7_0020, None, 2, 2);
        dc.current = (0, 0);
        assert_eq!(dc.final_region().bounds(), Rect::new(0, 0, 2, 2));

        dc.restore_from(saved);
        assert_eq!(dc.mapping.mode, rtl::gdi::MM_ANISOTROPIC);
        assert_eq!(dc.mapping.window_org, (5, 0));
        assert_eq!((dc.text_color, dc.rop2, dc.current), (0xFF, 7, (3, 4)));
        assert_eq!(dc.bitmap, 0x7_0010);
        assert_eq!(clip_rects(&dc), Some(std::vec![Rect::new(2, 2, 10, 8)]));
        assert_eq!(final_rects(&dc), [Rect::new(2, 2, 10, 8)]);
        dc.release_regions();

        // A window's DC keeps its visible region, which is the window's now.
        let mut window = Dc::window(640, 480, Rect::new(10, 20, 110, 70));
        let saved = window.saved_copy().unwrap();
        let painted = OwnedRegion::of_rects(&[Rect::new(10, 20, 20, 30)]).unwrap();
        assert!(window.set_vis(painted));
        window.restore_from(saved);
        assert_eq!(final_rects(&window), [Rect::new(10, 20, 20, 30)]);
        window.release_regions();
    }

    /// BeginPaint's visible region: the window's area cut to the update region (client
    /// coordinates), its pieces kept apart.
    #[test]
    fn a_paint_dcs_visible_region_is_the_update_region() {
        let mut dc = Dc::window(640, 480, Rect::new(10, 20, 110, 70));
        let update =
            OwnedRegion::of_rects(&[Rect::new(0, 0, 10, 10), Rect::new(50, 0, 60, 10)]).unwrap();
        let vis = paint_vis(&dc, &update).unwrap();
        assert!(dc.set_vis(vis));
        assert_eq!(
            final_rects(&dc),
            [Rect::new(10, 20, 20, 30), Rect::new(60, 20, 70, 30)]
        );
        assert_eq!(dc.clip_box(), (COMPLEXREGION, Rect::new(0, 0, 60, 10)));
        let state = DcState::of(&dc).unwrap();
        assert_eq!(state.clip().bounds(), Rect::new(10, 20, 70, 30));
        assert_eq!(
            state.final_region().bounds(),
            Rect::EMPTY,
            "the copy carries no region"
        );
        dc.release_regions();
    }
}
