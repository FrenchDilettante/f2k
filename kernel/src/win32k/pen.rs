//! Pens: win32k's pen objects, and what a DC draws its lines with.
//!
//! A pen is an object of the object manager ([`crate::ob`]'s Pen type), its body a [`Pen`]: its
//! style, width and color as GetObject answers them, and for an extended pen (ExtCreatePen's) its
//! brush and its user style's entries. Its creator's process holds it through an entry of the GDI
//! handle table ([`super::gdi`]), as a brush is held ([`super::brush`]); its handle carries OBJ_PEN
//! in its kind bits, or OBJ_EXTPEN for an extended pen, as Windows 2000's pens carry their type.
//!
//! A DC keeps a copy of the pen it has selected beside the pen's handle ([`super::dc::Dc`]), as it
//! keeps its brush's fill: a pen never changes, and one deleted while selected leaves the DC able
//! to draw.
//!
//! What a pen draws ([`Pen::stroke`], the rasterizer's [`super::stroke::Stroke`]), as the shapes
//! capture shows Windows 2000's:
//!
//! - a CreatePen pen of width 0 or 1 is cosmetic: one-pixel lines, its style's dashes in pixels
//!   (PS_DASH 18 on and 6 off, PS_DOT 3 and 3, PS_DASHDOT 9, 6, 3, 6, PS_DASHDOTDOT 9, 3, 3, 3, 3,
//!   3); PS_INSIDEFRAME draws as PS_SOLID; PS_NULL draws nothing;
//! - a wider CreatePen pen is geometric, with round end caps and joins, and solid whatever its
//!   style (the capture's PS_DASH and PS_DOT at width 3 are solid lines); PS_INSIDEFRAME keeps a
//!   figure's frame inside its box;
//! - an ExtCreatePen pen is cosmetic (width 1, a solid brush: its style's dashes as CreatePen's, a
//!   user style's entries three pixels each, PS_ALTERNATE every other pixel) or geometric (its end
//!   cap and join, its style's dashes in widths: PS_DASH 3 and 1, PS_DOT 1 and 1, PS_DASHDOT 3, 1,
//!   1, 1, PS_DASHDOTDOT 3, 1, 1, 1, 1, 1; a user style's entries in pixels).
//!
//! CreatePen takes any style and width: a style past PS_INSIDEFRAME is PS_SOLID, a negative width
//! its magnitude, and PS_NULL's LOGPEN answers width 1 and color 0. ExtCreatePen refuses
//! (STATUS_INVALID_PARAMETER, the capture's ERROR_INVALID_PARAMETER) a cosmetic pen wider than 1 or
//! of a brush other than solid, a type, cap, join or style that is none, PS_ALTERNATE on a
//! geometric pen, a user style of no entries or more than 16, and entries for another style.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtGdiCreatePen(i32 Style, i32 Width, u32 Color, ptr<u32> Pen): a pen, its handle (OBJ_PEN);
//! - NtGdiExtCreatePen(u32 Style, u32 Width, u32 BrushStyle, u32 Color, u32 Hatch, u32 Count, ptr
//!   Entries, ptr<u32> Pen): an extended pen of the LOGBRUSH's fields and `Count` style entries
//!   read from `Entries`, its handle (OBJ_EXTPEN).
//!
//! GetObject's answers ([`Pen::describe`]): a CreatePen pen's LOGPEN (16 bytes), an extended pen's
//! EXTLOGPEN (24 bytes and 4 an entry), each whole or not at all (0 for a buffer too short, no
//! error), their size for no buffer.

use rtl::dib::{BS_HATCHED, BS_NULL, BS_SOLID};
use rtl::gdi::*;
use rtl::pod::Pod;

use super::stroke::{Cap, Dashes, Join, Stroke};
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// A pen object's body, and the copy a DC keeps of the pen it has selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pen {
    /// The style as GetObject answers it: LOGPEN's lopnStyle, or EXTLOGPEN's elpPenStyle (its cap,
    /// join and type with it).
    pub style: u32,
    /// The width, in pixels (MM_TEXT's logical units).
    pub width: u32,
    /// The color, a COLORREF.
    pub color: u32,
    /// Whether it is an extended pen (ExtCreatePen's: OBJ_EXTPEN, an EXTLOGPEN).
    pub extended: bool,
    /// An extended pen's LOGBRUSH style and hatch.
    pub brush_style: u32,
    pub hatch: u32,
    /// A user style's entries (PS_USERSTYLE), `count` of them.
    pub count: u8,
    pub entries: [u32; MAX_STYLE_ENTRIES],
}

impl Pen {
    /// A record holding no pen (a pool's fresh record).
    pub const fn none() -> Self {
        Pen {
            style: PS_NULL,
            width: 1,
            color: 0,
            extended: false,
            brush_style: BS_SOLID,
            hatch: 0,
            count: 0,
            entries: [0; MAX_STYLE_ENTRIES],
        }
    }

    /// The stock pen `index` (BLACK_PEN, WHITE_PEN, NULL_PEN; DC_PEN black), as a DC draws with it.
    pub const fn stock(index: u32) -> Self {
        let color = match index {
            WHITE_PEN => 0x00FF_FFFF,
            _ => 0,
        };
        Pen {
            style: if index == NULL_PEN { PS_NULL } else { PS_SOLID },
            width: 0,
            color,
            ..Pen::none()
        }
    }

    /// CreatePen's pen of `style`, `width` and `color` (see the module notes).
    pub fn create(style: i32, width: i32, color: u32) -> Self {
        let style = match style as u32 {
            style @ PS_SOLID..=PS_INSIDEFRAME => style,
            _ => PS_SOLID,
        };
        let (width, color) = if style == PS_NULL {
            (1, 0)
        } else {
            (width.unsigned_abs(), color & RGB_MASK)
        };
        Pen {
            style,
            width,
            color,
            ..Pen::none()
        }
    }

    /// ExtCreatePen's pen (see the module notes); STATUS_INVALID_PARAMETER for one it refuses.
    pub fn extended(
        style: u32,
        width: u32,
        brush_style: u32,
        color: u32,
        hatch: u32,
        entries: &[u32],
    ) -> Result<Self, NtStatus> {
        let line = style & PS_STYLE_MASK;
        let cap = style & PS_ENDCAP_MASK;
        let join = style & PS_JOIN_MASK;
        let kind = style & PS_TYPE_MASK;
        let known = style & !(PS_STYLE_MASK | PS_ENDCAP_MASK | PS_JOIN_MASK | PS_TYPE_MASK) == 0
            && line <= PS_ALTERNATE
            && matches!(cap, PS_ENDCAP_ROUND | PS_ENDCAP_SQUARE | PS_ENDCAP_FLAT)
            && matches!(join, PS_JOIN_ROUND | PS_JOIN_BEVEL | PS_JOIN_MITER)
            && matches!(kind, PS_COSMETIC | PS_GEOMETRIC);
        let cosmetic_ok = kind != PS_COSMETIC || (width == 1 && brush_style == BS_SOLID);
        let alternate_ok = line != PS_ALTERNATE || kind == PS_COSMETIC;
        let entries_ok = if line == PS_USERSTYLE {
            (1..=MAX_STYLE_ENTRIES).contains(&entries.len())
        } else {
            entries.is_empty()
        };
        let brush_ok = matches!(brush_style, BS_SOLID | BS_NULL | BS_HATCHED);
        if !(known && cosmetic_ok && alternate_ok && entries_ok && brush_ok) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut pen = Pen {
            style,
            width,
            color: color & RGB_MASK,
            extended: true,
            brush_style,
            hatch,
            count: entries.len() as u8,
            ..Pen::none()
        };
        pen.entries[..entries.len()].copy_from_slice(entries);
        Ok(pen)
    }

    /// GetObject's answer, into `bytes`: its size (a LOGPEN's or an EXTLOGPEN's).
    pub fn describe(&self, bytes: &mut [u8; 96]) -> usize {
        if !self.extended {
            let log_pen = LogPen {
                style: self.style,
                width: Point {
                    x: self.width as i32,
                    y: 0,
                },
                color: self.color,
            };
            let answer = log_pen.as_bytes();
            bytes[..answer.len()].copy_from_slice(answer);
            return answer.len();
        }
        let header = ExtLogPenHeader {
            style: self.style,
            width: self.width,
            brush_style: self.brush_style,
            color: self.color,
            hatch: self.hatch,
            count: u32::from(self.count),
        };
        let head = header.as_bytes();
        bytes[..head.len()].copy_from_slice(head);
        let mut length = head.len();
        for entry in &self.entries[..self.count as usize] {
            bytes[length..length + 4].copy_from_slice(&entry.to_le_bytes());
            length += 4;
        }
        length
    }

    /// What the pen draws (see the module notes).
    pub fn stroke(&self) -> Stroke {
        let line = self.style & PS_STYLE_MASK;
        if line == PS_NULL || (self.extended && self.brush_style == BS_NULL) {
            return Stroke::Null;
        }
        let color = self.color;
        let geometric = if self.extended {
            self.style & PS_TYPE_MASK == PS_GEOMETRIC
        } else {
            self.width > 1
        };
        if !geometric {
            let dashes = match line {
                PS_DASH => Dashes::of(&[18, 6]),
                PS_DOT => Dashes::of(&[3, 3]),
                PS_DASHDOT => Dashes::of(&[9, 6, 3, 6]),
                PS_DASHDOTDOT => Dashes::of(&[9, 3, 3, 3, 3, 3]),
                PS_ALTERNATE => Dashes::of(&[1, 1]),
                PS_USERSTYLE => Dashes::scaled(&self.entries[..self.count as usize], 3),
                _ => Dashes::SOLID,
            };
            return Stroke::Cosmetic { color, dashes };
        }
        let width = self.width.max(1);
        if !self.extended {
            return Stroke::Geometric {
                color,
                width,
                cap: Cap::Round,
                join: Join::Round,
                dashes: Dashes::SOLID,
                inside_frame: line == PS_INSIDEFRAME,
            };
        }
        let dashes = match line {
            PS_DASH => Dashes::scaled(&[3, 1], width),
            PS_DOT => Dashes::scaled(&[1, 1], width),
            PS_DASHDOT => Dashes::scaled(&[3, 1, 1, 1], width),
            PS_DASHDOTDOT => Dashes::scaled(&[3, 1, 1, 1, 1, 1], width),
            PS_USERSTYLE => Dashes::scaled(&self.entries[..self.count as usize], 1),
            _ => Dashes::SOLID,
        };
        Stroke::Geometric {
            color,
            width,
            cap: match self.style & PS_ENDCAP_MASK {
                PS_ENDCAP_SQUARE => Cap::Square,
                PS_ENDCAP_FLAT => Cap::Flat,
                _ => Cap::Round,
            },
            join: match self.style & PS_JOIN_MASK {
                PS_JOIN_BEVEL => Join::Bevel,
                PS_JOIN_MITER => Join::Miter,
                _ => Join::Round,
            },
            dashes,
            inside_frame: line == PS_INSIDEFRAME,
        }
    }
}

// --- The services --------------------------------------------------------------------------------

/// NtGdiCreatePen(Style, Width, Color, Pen): see the module notes.
pub fn create_pen(
    call: &mut NtCall,
    style: i32,
    width: i32,
    color: u32,
    out: UserPtr<u32>,
) -> NtResult {
    hand_out(call, Pen::create(style, width, color), out)
}

/// NtGdiExtCreatePen(Style, Width, BrushStyle, Color, Hatch, Count, Entries, Pen): see the module
/// notes.
#[allow(clippy::too_many_arguments)]
pub fn ext_create_pen(
    call: &mut NtCall,
    style: u32,
    width: u32,
    brush_style: u32,
    color: u32,
    hatch: u32,
    count: u32,
    entries: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    if count as usize > MAX_STYLE_ENTRIES || (count != 0 && entries.is_null()) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut read = [0u32; MAX_STYLE_ENTRIES];
    if count != 0 {
        entries.read(&mut read.as_bytes_mut()[..4 * count as usize])?;
    }
    let pen = Pen::extended(
        style,
        width,
        brush_style,
        color,
        hatch,
        &read[..count as usize],
    )?;
    hand_out(call, pen, out)
}

/// A pen of state `pen` made, its handle into `out` (deleted again when `out` cannot be written).
fn hand_out(call: &mut NtCall, pen: Pen, out: UserPtr<u32>) -> NtResult {
    let handle = publish_pen(call, pen)?;
    if out.write(handle).is_err() {
        close_pen(call, handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// GetObject of the pen `object` names (NtGdiExtGetObjectW's, [`super::bitmap::ext_get_object_w`]):
/// its LOGPEN or EXTLOGPEN into `buffer` whole when `count` bytes hold it (0 written otherwise),
/// its size for no buffer; STATUS_INVALID_HANDLE for a handle that names no pen.
pub fn get_object(
    call: &mut NtCall,
    object: Handle,
    count: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let pen = pen_of(call, object)?;
    let mut bytes = [0u8; 96];
    let length = pen.describe(&mut bytes);
    let written = if buffer.is_null() {
        length
    } else if (count as usize) < length {
        0
    } else {
        buffer.write(&bytes[..length])?;
        length
    };
    out.write(written as u32)?;
    Ok(STATUS_SUCCESS)
}

/// The pen `handle` names: a stock pen, or the calling process's pen object (OBJ_PEN or
/// OBJ_EXTPEN); STATUS_OBJECT_TYPE_MISMATCH for another global object, STATUS_INVALID_HANDLE for a
/// handle that names no pen.
pub fn pen_of(call: &mut NtCall, handle: Handle) -> Result<Pen, NtStatus> {
    if let Some((index, kind)) = stock_object(handle.raw()) {
        return if kind == OBJ_PEN {
            Ok(Pen::stock(index))
        } else {
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        };
    }
    match object_of(handle.raw()) {
        Some((kind @ (OBJ_PEN | OBJ_EXTPEN), _)) => pen_object(call, handle, kind),
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None if global_object_kind(handle.raw()).is_some() => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None => Err(STATUS_INVALID_HANDLE),
    }
}

// --- The target's side: the objects --------------------------------------------------------------

/// A pen of state `pen` made, its GDI handle the calling process's (OBJ_PEN, or OBJ_EXTPEN for an
/// extended pen); STATUS_INSUFFICIENT_RESOURCES when the pool is full, the GDI table's refusal's
/// status (STATUS_NO_MEMORY: the process's quota, the table's ceiling) when it gives no handle.
#[cfg(target_arch = "x86")]
fn publish_pen(_call: &mut NtCall, pen: Pen) -> Result<u32, NtStatus> {
    let kind = if pen.extended { OBJ_EXTPEN } else { OBJ_PEN };
    let id = crate::ob::locked(|directory| directory.create_pen(pen))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    super::gdi::insert_as(id, kind)
}

/// Delete the calling process's pen `handle` (either kind); whether it named one.
#[cfg(target_arch = "x86")]
pub fn close_pen(_call: &mut NtCall, handle: u32) -> bool {
    match object_of(handle) {
        Some((kind @ (OBJ_PEN | OBJ_EXTPEN), _)) => super::gdi::delete(handle, kind),
        _ => false,
    }
}

/// The pen object the calling process's `handle` (of `kind`) names.
#[cfg(target_arch = "x86")]
fn pen_object(_call: &mut NtCall, handle: Handle, kind: u32) -> Result<Pen, NtStatus> {
    let reference = super::gdi::reference(handle.raw(), kind).ok_or(STATUS_INVALID_HANDLE)?;
    crate::ob::locked(|directory| directory.pen(reference.id()).copied())
        .ok_or(STATUS_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
fn publish_pen(_: &mut NtCall, _: Pen) -> Result<u32, NtStatus> {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[cfg(not(target_arch = "x86"))]
pub fn close_pen(_: &mut NtCall, _: u32) -> bool {
    false
}

#[cfg(not(target_arch = "x86"))]
fn pen_object(_: &mut NtCall, _: Handle, _: u32) -> Result<Pen, NtStatus> {
    Err(STATUS_INVALID_HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CreatePen's LOGPENs, as the capture's pens section prints them: each style kept, widths 0, 1
    /// and 3 kept; PS_NULL's width 1 and color 0; styles 7, 8 and 9 PS_SOLID; width -1 1.
    #[test]
    fn create_pen_normalizes_as_the_capture() {
        let blue = 0x00FF_0000;
        for style in 0..=6 {
            for width in [0, 1, 3] {
                let pen = Pen::create(style, width, blue);
                let mut bytes = [0u8; 96];
                assert_eq!(pen.describe(&mut bytes), 16);
                let expected = if style == PS_NULL as i32 {
                    (PS_NULL, 1, 0)
                } else {
                    (style as u32, width as u32, blue)
                };
                assert_eq!((pen.style, pen.width, pen.color), expected);
            }
        }
        for style in 7..=9 {
            assert_eq!(Pen::create(style, 1, blue).style, PS_SOLID);
        }
        assert_eq!(Pen::create(PS_SOLID as i32, -1, blue).width, 1);
    }

    /// ExtCreatePen's EXTLOGPENs and refusals, as the capture's extpen section shows them.
    #[test]
    fn ext_create_pen_validates_as_the_capture() {
        let pen = Pen::extended(PS_COSMETIC | PS_USERSTYLE, 1, BS_SOLID, 0, 0, &[3, 1]).unwrap();
        let mut bytes = [0u8; 96];
        assert_eq!(pen.describe(&mut bytes), 32);
        assert_eq!(&bytes[20..32], &[2, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0]);
        let flat = PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT;
        let pen = Pen::extended(flat, 3, BS_SOLID, 0, 0, &[]).unwrap();
        assert_eq!(pen.describe(&mut bytes), 24);
        assert_eq!(&bytes[0..4], &0x0001_0200u32.to_le_bytes());
        assert_eq!(
            Pen::extended(PS_COSMETIC | PS_SOLID, 2, BS_SOLID, 0, 0, &[]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            Pen::extended(PS_COSMETIC | PS_USERSTYLE, 1, BS_SOLID, 0, 0, &[]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            Pen::extended(PS_GEOMETRIC | PS_ALTERNATE, 3, BS_SOLID, 0, 0, &[]),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// A wide CreatePen pen draws solid with round caps and joins, whatever its style.
    #[test]
    fn wide_create_pens_are_solid_and_round() {
        let stroke = Pen::create(PS_DASH as i32, 3, 0).stroke();
        assert_eq!(
            stroke,
            Stroke::Geometric {
                color: 0,
                width: 3,
                cap: Cap::Round,
                join: Join::Round,
                dashes: Dashes::SOLID,
                inside_frame: false,
            }
        );
        assert_eq!(Pen::create(PS_NULL as i32, 3, 0).stroke(), Stroke::Null);
        assert!(matches!(
            Pen::create(PS_DOT as i32, 1, 0).stroke(),
            Stroke::Cosmetic { dashes, .. } if dashes == Dashes::of(&[3, 3])
        ));
    }
}
