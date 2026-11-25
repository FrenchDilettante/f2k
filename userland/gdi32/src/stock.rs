//! GetObject of the stock objects: what GetObjectW and GetObjectA answer for a handle
//! GetStockObject gave, from gdi32 alone (a stock object's description never changes, and the
//! handle names its index: rtl::gdi's `stock_object`).
//!
//! - A font's LOGFONTW (GetObjectA: its LOGFONTA, the face name converted), as a font object's is
//!   answered ([`crate::font`]): its first `size` bytes, their number; its whole size for no
//!   buffer.
//! - A pen's LOGPEN (16 bytes), a brush's LOGBRUSH (12) and the palette's entry count (a WORD, 2):
//!   the whole of it, its size; its size for no buffer; 0 for a buffer too small for it, the last
//!   error untouched (a solid brush's short buffer is answered alike, [`crate::font`]).
//!
//! The descriptions are Windows 2000's stock objects on an English system at 96 DPI. The brushes'
//! colors and DEFAULT_PALETTE's 20 entries follow from the objects themselves; the fonts' heights,
//! weights and faces are Windows 2000's as Wine's stock-font tests record them (SYSTEM_FONT and
//! DEVICE_DEFAULT_FONT the System font at 16, bold; DEFAULT_GUI_FONT "MS Shell Dlg" at -11;
//! ANSI_VAR_FONT MS Sans Serif and ANSI_FIXED_FONT Courier at 12). The rest is a prediction no
//! capture checks yet: the fonts' widths, character sets, pitches and families, OEM_FIXED_FONT's
//! Terminal and SYSTEM_FIXED_FONT's Fixedsys, the pens' width of 0, and the short buffers'
//! answers; a `stockobj` section of the bitmaps fixture, printing them all, waits for the real
//! machine's next capture. DC_BRUSH and DC_PEN, which F2K's GetStockObject names (Windows XP's),
//! describe as XP's defaults: a white brush, a black pen.

use rtl::dib::{LogBrush, BS_NULL, BS_SOLID};
use rtl::edge::OutBuf;
use rtl::gdi::*;
use rtl::pod::Pod;

use crate::imports;

/// LOGPEN, Windows 2000's (16 bytes): the style, the width (a POINT whose `y` is unused), the
/// color.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogPen {
    pub style: u32,
    pub width: [i32; 2],
    pub color: u32,
}

// SAFETY: integers, laid out with no padding; every bit pattern is a value.
unsafe impl Pod for LogPen {}

/// The pen styles the stock pens have: a solid line, no line.
pub const PS_SOLID: u32 = 0;
pub const PS_NULL: u32 = 5;

/// LOGFONT's character set of the OEM code page's fonts.
pub const OEM_CHARSET: u8 = 255;

/// The default palette's number of entries (the 20 static colors).
pub const DEFAULT_PALETTE_ENTRIES: u16 = 20;

/// What a stock object is described by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Description {
    Font(LogFontW),
    Pen(LogPen),
    Brush(LogBrush),
    /// The palette's number of entries.
    Palette(u16),
}

/// A stock font's LOGFONTW: every field not given 0 (the default precisions and quality, no
/// escapement, italic, underline or strike-out).
fn font(face: &str, height: i32, width: i32, weight: i32, char_set: u8, pitch: u8) -> LogFontW {
    let mut log_font = LogFontW::zeroed();
    log_font.height = height;
    log_font.width = width;
    log_font.weight = weight;
    log_font.char_set = char_set;
    log_font.pitch_and_family = pitch;
    for (unit, byte) in log_font.face_name.iter_mut().zip(face.bytes()) {
        *unit = u16::from(byte);
    }
    log_font
}

fn brush(style: u32, color: u32) -> Description {
    Description::Brush(LogBrush {
        style,
        color,
        hatch: 0,
    })
}

fn pen(style: u32, color: u32) -> Description {
    Description::Pen(LogPen {
        style,
        width: [0, 0],
        color,
    })
}

/// Stock object `index`'s description (see the module notes); none for an index that names no
/// stock object.
pub fn description(index: u32) -> Option<Description> {
    const SWISS: u8 = VARIABLE_PITCH | FF_SWISS;
    const MODERN: u8 = FIXED_PITCH | FF_MODERN;
    Some(match index {
        WHITE_BRUSH | DC_BRUSH => brush(BS_SOLID, 0xFF_FFFF),
        LTGRAY_BRUSH => brush(BS_SOLID, 0xC0_C0C0),
        GRAY_BRUSH => brush(BS_SOLID, 0x80_8080),
        DKGRAY_BRUSH => brush(BS_SOLID, 0x40_4040),
        BLACK_BRUSH => brush(BS_SOLID, 0),
        NULL_BRUSH => brush(BS_NULL, 0),
        WHITE_PEN => pen(PS_SOLID, 0xFF_FFFF),
        BLACK_PEN | DC_PEN => pen(PS_SOLID, 0),
        NULL_PEN => pen(PS_NULL, 0),
        OEM_FIXED_FONT => {
            Description::Font(font("Terminal", 12, 8, FW_NORMAL, OEM_CHARSET, MODERN))
        }
        ANSI_FIXED_FONT => {
            Description::Font(font("Courier", 12, 9, FW_NORMAL, ANSI_CHARSET, MODERN))
        }
        ANSI_VAR_FONT => {
            Description::Font(font("MS Sans Serif", 12, 9, FW_NORMAL, ANSI_CHARSET, SWISS))
        }
        SYSTEM_FONT | DEVICE_DEFAULT_FONT => {
            Description::Font(font("System", 16, 7, FW_BOLD, ANSI_CHARSET, SWISS))
        }
        SYSTEM_FIXED_FONT => {
            Description::Font(font("Fixedsys", 16, 8, FW_NORMAL, ANSI_CHARSET, MODERN))
        }
        DEFAULT_GUI_FONT => {
            Description::Font(font("MS Shell Dlg", -11, 0, FW_NORMAL, ANSI_CHARSET, SWISS))
        }
        DEFAULT_PALETTE => Description::Palette(DEFAULT_PALETTE_ENTRIES),
        _ => return None,
    })
}

/// GetObjectW (`narrow` false) and GetObjectA (true) of stock object `index`: its description into
/// `buffer` (see the module notes); 0 for an index that names none. `size` is not negative.
pub(crate) fn get_object(index: u32, size: i32, buffer: usize, narrow: bool) -> i32 {
    let narrow_font;
    let palette;
    let Some(description) = description(index) else {
        return 0;
    };
    let (bytes, whole): (&[u8], bool) = match &description {
        Description::Font(wide) if narrow => {
            narrow_font = narrow_log_font(wide, imports::unicode_to_multi_byte);
            (narrow_font.as_bytes(), false)
        }
        Description::Font(wide) => (wide.as_bytes(), false),
        Description::Pen(pen) => (pen.as_bytes(), true),
        Description::Brush(brush) => (brush.as_bytes(), true),
        Description::Palette(entries) => {
            palette = entries.to_le_bytes();
            (&palette[..], true)
        }
    };
    if buffer == 0 {
        return bytes.len() as i32;
    }
    let length = if whole {
        if (size as usize) < bytes.len() {
            return 0;
        }
        bytes.len()
    } else {
        bytes.len().min(size as usize)
    };
    // SAFETY: the caller's buffer of `size` bytes, at least `length`.
    let mut out = unsafe { OutBuf::new(buffer as *mut u8, length) };
    out.put(&bytes[..length]);
    length as i32
}

#[cfg(test)]
mod tests;
