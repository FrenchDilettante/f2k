//! GetObjectW and GetObjectA of every stock object against the host stand-ins: the sizes with no
//! buffer, the descriptions, the short and the long buffers, and a solid brush's short buffer
//! answered as a stock brush's is.

use std::vec;

use super::*;
use crate::bitmap::get_object_type;
use crate::brush::create_solid_brush;
use crate::dc::{delete_object, get_stock_object};
use crate::font::{get_object_a, get_object_w};
use crate::imports::host::{BRUSHES, LAST_ERROR};
use crate::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};

fn reset() {
    BRUSHES.with(|brushes| brushes.borrow_mut().clear());
    LAST_ERROR.with(|error| error.set(0xF2F2));
}

fn last_error() -> u32 {
    LAST_ERROR.with(|error| error.get())
}

fn stock(index: u32) -> usize {
    get_stock_object(index as i32)
}

/// GetObjectW of `object` into a buffer of `size` bytes filled with 0xCC: its answer and the
/// buffer.
fn wide(object: usize, size: usize) -> (i32, vec::Vec<u8>) {
    let mut buffer = vec![0xCCu8; size.max(1)];
    let answer = get_object_w(object, size as i32, buffer.as_mut_ptr() as usize);
    buffer.truncate(size);
    (answer, buffer)
}

/// GetObjectA, as [`wide`].
fn narrow(object: usize, size: usize) -> (i32, vec::Vec<u8>) {
    let mut buffer = vec![0xCCu8; size.max(1)];
    // SAFETY: the test's own buffer of `size` bytes.
    let answer = unsafe { get_object_a(object, size as i32, buffer.as_mut_ptr()) };
    buffer.truncate(size);
    (answer, buffer)
}

fn face_units(name: &str) -> [u16; LF_FACESIZE] {
    let mut units = [0u16; LF_FACESIZE];
    for (unit, byte) in units.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    units
}

/// With no buffer, each stock object answers its description's size: a font's LOGFONTW (92) or
/// LOGFONTA (60), a pen's LOGPEN (16), a brush's LOGBRUSH (12), the palette's WORD (2); and
/// GetObjectType its kind. The last error is untouched.
///
/// Pins: gdi32.GetObjectW, gdi32.GetObjectA, gdi32.GetObjectType
#[test]
fn every_stock_object_answers_its_size() {
    reset();
    for index in (0..=19).filter(|&index| index != 9) {
        let object = stock(index);
        let kind = stock_kind(index).unwrap();
        let (w, a) = match kind {
            OBJ_FONT => (92, 60),
            OBJ_PEN => (16, 16),
            OBJ_BRUSH => (12, 12),
            _ => (2, 2),
        };
        assert_eq!(get_object_w(object, 0, 0), w, "{index}");
        // SAFETY: no buffer.
        assert_eq!(unsafe { get_object_a(object, 0, core::ptr::null_mut()) }, a);
        assert_eq!(get_object_type(object), kind, "{index}");
    }
    assert_eq!(last_error(), 0xF2F2);
}

/// DEFAULT_GUI_FONT's LOGFONTW is "MS Shell Dlg" at -11, normal weight, as a dialog font is made
/// from it; its LOGFONTA the same, the face name narrow; SYSTEM_FONT's the bold System font at 16.
///
/// Pins: gdi32.GetObjectW, gdi32.GetObjectA
#[test]
fn the_stock_fonts_answer_their_logfonts() {
    reset();
    let (answer, bytes) = wide(stock(DEFAULT_GUI_FONT), size_of::<LogFontW>());
    assert_eq!(answer, 92);
    let gui = LogFontW::from_bytes(&bytes).unwrap();
    assert_eq!((gui.height, gui.width, gui.weight), (-11, 0, FW_NORMAL));
    assert_eq!((gui.char_set, gui.pitch_and_family), (ANSI_CHARSET, 0x22));
    assert_eq!(gui.face_name, face_units("MS Shell Dlg"));
    let (answer, bytes) = narrow(stock(DEFAULT_GUI_FONT), size_of::<LogFontA>());
    assert_eq!(answer, 60);
    let gui_a = LogFontA::from_bytes(&bytes).unwrap();
    assert_eq!((gui_a.height, gui_a.weight), (-11, FW_NORMAL));
    assert_eq!(&gui_a.face_name[..13], b"MS Shell Dlg\0");
    assert!(gui_a.face_name.iter().skip(12).all(|&byte| byte == 0));

    let (_, bytes) = wide(stock(SYSTEM_FONT), size_of::<LogFontW>());
    let system = LogFontW::from_bytes(&bytes).unwrap();
    assert_eq!(
        (system.height, system.width, system.weight),
        (16, 7, FW_BOLD)
    );
    assert_eq!(system.face_name, face_units("System"));
    let (_, bytes) = wide(stock(DEVICE_DEFAULT_FONT), size_of::<LogFontW>());
    assert_eq!(LogFontW::from_bytes(&bytes).unwrap(), system);
    let (_, bytes) = wide(stock(OEM_FIXED_FONT), size_of::<LogFontW>());
    let oem = LogFontW::from_bytes(&bytes).unwrap();
    assert_eq!((oem.char_set, oem.pitch_and_family), (OEM_CHARSET, 0x31));
    assert_eq!(oem.face_name, face_units("Terminal"));
    assert_eq!(last_error(), 0xF2F2);
}

/// The stock pens' LOGPENs, the brushes' LOGBRUSHes and the palette's 20 entries.
///
/// Pins: gdi32.GetObjectW, gdi32.GetObjectA
#[test]
fn the_stock_pens_brushes_and_palette_answer_their_descriptions() {
    reset();
    let pen_of = |index| {
        let (answer, bytes) = wide(stock(index), 16);
        assert_eq!(answer, 16);
        LogPen::from_bytes(&bytes).unwrap()
    };
    assert_eq!(
        pen_of(WHITE_PEN),
        LogPen {
            style: PS_SOLID,
            width: [0, 0],
            color: 0xFF_FFFF
        }
    );
    assert_eq!(pen_of(BLACK_PEN).color, 0);
    assert_eq!(pen_of(NULL_PEN).style, PS_NULL);
    let brush_of = |index| {
        let (answer, bytes) = narrow(stock(index), 12);
        assert_eq!(answer, 12);
        LogBrush::from_bytes(&bytes).unwrap()
    };
    let colors = [0xFF_FFFF, 0xC0_C0C0, 0x80_8080, 0x40_4040, 0];
    for (index, color) in (WHITE_BRUSH..=BLACK_BRUSH).zip(colors) {
        assert_eq!(
            brush_of(index),
            LogBrush {
                style: BS_SOLID,
                color,
                hatch: 0
            }
        );
    }
    assert_eq!(brush_of(NULL_BRUSH).style, BS_NULL);
    assert_eq!(wide(stock(DEFAULT_PALETTE), 2), (2, vec![20, 0]));
    assert_eq!(last_error(), 0xF2F2);
}

/// A font's buffer takes its first bytes, however few; a pen's, a brush's or the palette's too
/// small for it takes nothing (0, the last error untouched), and a larger one the description
/// alone. A negative size is refused.
///
/// Pins: gdi32.GetObjectW, gdi32.GetObjectA
#[test]
fn short_and_long_buffers() {
    reset();
    let (answer, bytes) = wide(stock(SYSTEM_FONT), 6);
    assert_eq!((answer, &bytes[..]), (6, &[16, 0, 0, 0, 7, 0][..]));
    let (answer, bytes) = narrow(stock(DEFAULT_GUI_FONT), 30);
    assert_eq!(answer, 30);
    assert_eq!(&bytes[28..], b"MS");
    let (answer, _) = wide(stock(ANSI_VAR_FONT), 200);
    assert_eq!(answer, 92, "a font's buffer past its LOGFONTW");
    assert_eq!(wide(stock(BLACK_PEN), 15), (0, vec![0xCC; 15]));
    assert_eq!(wide(stock(WHITE_BRUSH), 11), (0, vec![0xCC; 11]));
    assert_eq!(narrow(stock(DEFAULT_PALETTE), 1), (0, vec![0xCC]));
    assert_eq!(last_error(), 0xF2F2);
    let (answer, bytes) = wide(stock(WHITE_PEN), 20);
    assert_eq!(answer, 16);
    assert_eq!(&bytes[16..], &[0xCC; 4]);
    assert_eq!(wide(stock(GRAY_BRUSH), 16).0, 12);
    assert_eq!(get_object_w(stock(SYSTEM_FONT), -1, 0), 0);
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    reset();
    // SAFETY: no buffer.
    assert_eq!(
        unsafe { get_object_a(stock(BLACK_PEN), -1, core::ptr::null_mut()) },
        0
    );
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
}

/// A solid brush's LOGBRUSH is answered as a stock brush's: whole, or nothing for a short buffer;
/// a deleted brush fails with the service's error.
///
/// Pins: gdi32.GetObjectW, gdi32.GetObjectA
#[test]
fn a_solid_brush_answers_as_a_stock_brush() {
    reset();
    let brush = create_solid_brush(0x0012_3456);
    let (answer, bytes) = narrow(brush, 12);
    assert_eq!(answer, 12);
    assert_eq!(
        LogBrush::from_bytes(&bytes).unwrap(),
        LogBrush {
            style: BS_SOLID,
            color: 0x12_3456,
            hatch: 0
        }
    );
    assert_eq!(wide(brush, 8), (0, vec![0xCC; 8]));
    assert_eq!(get_object_w(brush, 0, 0), 12);
    assert_eq!(last_error(), 0xF2F2);
    assert_eq!(delete_object(brush), 1);
    assert_eq!(wide(brush, 8).0, 0);
    assert_eq!(last_error(), ERROR_INVALID_HANDLE);
}
