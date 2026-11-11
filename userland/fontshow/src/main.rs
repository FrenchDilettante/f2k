//! fontshow.exe: draws lines of text on the screen through gdi32's TextOutW, in each face the
//! system loads at its start from `\WINNT\Fonts` (Wine's Tahoma, Tahoma Bold, MS Sans Serif,
//! System and Marlett) at the sizes the user interface uses, and in the stock fonts, so the screen
//! can be looked at. It reports each font's face name, cell height and kind on its standard output,
//! and ends with 0 when every call succeeded and every face asked for by name was the face
//! expected, of the kind expected (a TrueType face, or a raster-style one, never the built-in font
//! standing in for it). Run under FiSH, which sets the graphics mode first.

#![no_std]
#![no_main]

exe::entry!(main);

/// A line's font: a stock font (GetStockObject's index), or a font made from a LOGFONT's height,
/// weight and face name.
#[derive(Clone, Copy)]
enum Font {
    Stock(i32),
    Made(i32, i32, &'static str),
}

/// The stock fonts the sheet draws in: SYSTEM_FONT, a DC's default, and DEFAULT_GUI_FONT.
const SYSTEM_FONT: i32 = 13;
const DEFAULT_GUI_FONT: i32 = 17;

/// What a face asked for by name must be: its name, as GetTextFaceW answers it, and whether it is
/// a TrueType face (a raster-style face is not).
const EXPECTED: [(&str, &str, bool); 6] = [
    ("Tahoma", "Tahoma", true),
    ("MS Shell Dlg 2", "MS Shell Dlg 2", true),
    ("MS Sans Serif", "MS Sans Serif", false),
    ("MS Shell Dlg", "MS Shell Dlg", false),
    ("System", "System", false),
    ("Marlett", "Marlett", true),
];

/// Each line: its font, its column and row, and its text. Marlett's line is its caption-button,
/// scroll-arrow and check-mark glyphs, by their character codes: '0' minimise, '1' maximise, '2'
/// restore, 'r' close, '3' to '6' the arrows left, right, up and down, 'a' the check mark (Marlett
/// has no space: each glyph is an em wide, which spaces them).
const LINES: [(Font, i32, i32, &str); 16] = [
    (
        Font::Stock(SYSTEM_FONT),
        8,
        8,
        "SYSTEM_FONT: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Stock(DEFAULT_GUI_FONT),
        8,
        30,
        "DEFAULT_GUI_FONT: OK   Cancel   Apply   Help   The quick brown fox jumps over the lazy dog.",
    ),
    (
        Font::Made(-11, 400, "Tahoma"),
        8,
        52,
        "Tahoma 8 pt (-11): The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Made(-13, 400, "Tahoma"),
        8,
        70,
        "Tahoma -13: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Made(-16, 400, "Tahoma"),
        8,
        90,
        "Tahoma -16: The quick brown fox jumps over the lazy dog.",
    ),
    (
        Font::Made(-24, 400, "Tahoma"),
        8,
        114,
        "Tahoma -24: Wg0@ Hij! The quick brown fox",
    ),
    (
        Font::Made(-11, 700, "Tahoma"),
        8,
        150,
        "Tahoma Bold 8 pt (-11, weight 700): File  Edit  View  Help  F2K caption",
    ),
    (
        Font::Made(-13, 700, "Tahoma"),
        8,
        168,
        "Tahoma Bold -13: The quick brown fox jumps over the lazy dog.",
    ),
    (
        Font::Made(-11, 400, "MS Shell Dlg 2"),
        8,
        190,
        "MS Shell Dlg 2 (-11): OK   Cancel   Apply   Help",
    ),
    (
        Font::Made(-11, 400, "MS Shell Dlg"),
        8,
        210,
        "MS Shell Dlg (-11): OK   Cancel   Apply   Help",
    ),
    (
        Font::Made(13, 400, "MS Sans Serif"),
        8,
        232,
        "MS Sans Serif 13: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Made(16, 400, "MS Sans Serif"),
        8,
        252,
        "MS Sans Serif 16: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Made(20, 400, "MS Sans Serif"),
        8,
        276,
        "MS Sans Serif 20: The quick brown fox jumps over the lazy dog.",
    ),
    (
        Font::Made(16, 700, "System"),
        8,
        306,
        "System 16: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        Font::Made(18, 700, "System"),
        8,
        330,
        "System 18: The quick brown fox jumps over the lazy dog.",
    ),
    (Font::Made(-16, 400, "Marlett"), 8, 362, "012r3456a"),
];

/// The longest line, in UTF-16 units with a terminator.
const ROOM: usize = 128;

#[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    fn CreateDCW(driver: *const u16, device: *const u16, output: *const u16, init: usize) -> usize;
    fn DeleteDC(dc: usize) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn CreateFontW(
        height: i32,
        width: i32,
        escapement: i32,
        orientation: i32,
        weight: i32,
        italic: u32,
        underline: u32,
        strike_out: u32,
        char_set: u32,
        out_precision: u32,
        clip_precision: u32,
        quality: u32,
        pitch_and_family: u32,
        face: *const u16,
    ) -> usize;
    fn GetStockObject(index: i32) -> usize;
    fn SelectObject(dc: usize, object: usize) -> usize;
    fn DeleteObject(object: usize) -> i32;
    fn TextOutW(dc: usize, x: i32, y: i32, text: *const u16, count: i32) -> i32;
    fn GetTextFaceW(dc: usize, count: i32, face: *mut u16) -> i32;
    fn GetTextMetricsW(dc: usize, metric: *mut [i32; 15]) -> i32;
}

/// `text`'s UTF-16 units and a terminator, in `units`: the units, the terminator left out.
fn wide<'a>(text: &str, units: &'a mut [u16; ROOM]) -> &'a [u16] {
    let mut length = 0;
    for unit in text.encode_utf16().take(ROOM - 1) {
        units[length] = unit;
        length += 1;
    }
    units[length] = 0;
    &units[..length]
}

/// The font a line asks for (a font object it made, or a stock font), and whether the line made
/// it; 0 when it could not be had.
fn font_of(font: Font) -> (usize, bool) {
    match font {
        // SAFETY: an index, no pointer.
        Font::Stock(index) => (unsafe { GetStockObject(index) }, false),
        Font::Made(height, weight, face) => {
            let mut face_units = [0u16; ROOM];
            wide(face, &mut face_units);
            // SAFETY: the face name is NUL-terminated; the rest are numbers.
            let made = unsafe {
                CreateFontW(
                    height,
                    0,
                    0,
                    0,
                    weight,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0,
                    0,
                    face_units.as_ptr(),
                )
            };
            (made, true)
        }
    }
}

fn main() -> u32 {
    let mut display = [0u16; ROOM];
    wide("DISPLAY", &mut display);
    // SAFETY: a NUL-terminated driver name; no device, output or initialization data.
    let dc = unsafe { CreateDCW(display.as_ptr(), core::ptr::null(), core::ptr::null(), 0) };
    if dc == 0 {
        let _ = exe::stderr().print(format_args!("fontshow: no screen DC\r\n"));
        return 1;
    }
    let mut ok = true;
    for (font, x, row, text) in LINES {
        let (handle, made) = font_of(font);
        if handle == 0 {
            ok = false;
            continue;
        }
        // SAFETY: the DC and the font are handles this program holds.
        let previous = unsafe { SelectObject(dc, handle) };
        let mut units = [0u16; ROOM];
        let line = wide(text, &mut units);
        // SAFETY: the DC is ours; the text holds `line.len()` units.
        ok &= unsafe { TextOutW(dc, x, row, line.as_ptr(), line.len() as i32) } != 0;
        let mut name = [0u16; 32];
        let mut metric = [0i32; 15];
        // SAFETY: the DC is ours; the buffers are ours, of the sizes given.
        let (length, _) = unsafe {
            (
                GetTextFaceW(dc, name.len() as i32, name.as_mut_ptr()),
                GetTextMetricsW(dc, &mut metric),
            )
        };
        let name = &name[..(length.max(1) as usize - 1).min(31)];
        let _ = exe::stdout().print(format_args!("fontshow: row {row}: face "));
        for &unit in name {
            let character = char::from_u32(unit as u32).unwrap_or('?');
            let _ = exe::stdout().print(format_args!("{character}"));
        }
        // TEXTMETRICW's tmPitchAndFamily, its byte 55: TMPF_TRUETYPE for a TrueType font. The
        // built-in font answers a weight of 0, a face of the system's its own.
        let truetype = (metric[13] >> 24) & 0x04 != 0;
        let weight = metric[7];
        let _ = exe::stdout().print(format_args!(
            ", tmHeight {}, tmAveCharWidth {}, tmWeight {weight}, TrueType {}\r\n",
            metric[0],
            metric[5],
            if truetype { "yes" } else { "no" }
        ));
        if let Font::Made(_, _, face) = font {
            let expected = EXPECTED.iter().find(|(asked, _, _)| *asked == face);
            if let Some(&(_, answered, kind)) = expected {
                let named = answered.encode_utf16().eq(name.iter().copied());
                if !named || truetype != kind || weight == 0 {
                    ok = false;
                }
            }
        }
        // SAFETY: the DC and the fonts are ours.
        unsafe {
            SelectObject(dc, previous);
            if made {
                DeleteObject(handle);
            }
        }
    }
    // SAFETY: the DC is ours.
    unsafe { DeleteDC(dc) };
    if ok {
        0
    } else {
        1
    }
}
