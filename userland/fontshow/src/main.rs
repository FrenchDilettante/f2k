//! fontshow.exe: draws lines of text on the screen through gdi32's TextOutW, in the built-in font
//! and in the TrueType Tahoma the system loads at its start (`\WINNT\Fonts\tahoma.ttf`) at several
//! sizes, bold, and through the dialog face "MS Shell Dlg 2", so the screen can be looked at. It
//! reports each font's face name and cell height on its standard output, and ends with 0 when every
//! call succeeded and Tahoma was Tahoma (a TrueType face, not the built-in font standing in for
//! it). Run under FiSH, which sets the graphics mode first.

#![no_std]
#![no_main]

exe::entry!(main);

/// What each line asks for: its LOGFONT height (0: the stock built-in font), its weight, its face
/// name, its row and its text.
const LINES: [(i32, i32, &str, i32, &str); 7] = [
    (
        0,
        400,
        "",
        8,
        "The built-in font: The quick brown fox jumps over the lazy dog.",
    ),
    (
        -11,
        400,
        "Tahoma",
        40,
        "Tahoma 8 pt (-11): The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        -13,
        400,
        "Tahoma",
        64,
        "Tahoma -13: The quick brown fox jumps over the lazy dog. 0123456789",
    ),
    (
        -16,
        400,
        "Tahoma",
        90,
        "Tahoma -16: The quick brown fox jumps over the lazy dog.",
    ),
    (
        -24,
        400,
        "Tahoma",
        120,
        "Tahoma -24: Wg0@ Hij! The quick brown fox",
    ),
    (
        -11,
        700,
        "Tahoma",
        160,
        "Tahoma 8 pt bold: File  Edit  View  Help  (synthesised emboldening)",
    ),
    (
        -11,
        400,
        "MS Shell Dlg 2",
        184,
        "MS Shell Dlg 2: OK   Cancel   Apply   Help",
    ),
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
    for (height, weight, face, row, text) in LINES {
        let mut face_units = [0u16; ROOM];
        wide(face, &mut face_units);
        let font = if height == 0 {
            0
        } else {
            // SAFETY: the face name is NUL-terminated; the rest are numbers.
            unsafe {
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
            }
        };
        if height != 0 && font == 0 {
            ok = false;
            continue;
        }
        // SAFETY: the DC and the font are this program's own handles.
        let previous = (font != 0).then(|| unsafe { SelectObject(dc, font) });
        let mut units = [0u16; ROOM];
        let line = wide(text, &mut units);
        // SAFETY: the DC is ours; the text holds `line.len()` units.
        ok &= unsafe { TextOutW(dc, 8, row, line.as_ptr(), line.len() as i32) } != 0;
        let mut name = [0u16; 32];
        let mut metric = [0i32; 15];
        // SAFETY: the DC is ours; the buffers are ours, of the sizes given.
        let (length, _) = unsafe {
            (
                GetTextFaceW(dc, name.len() as i32, name.as_mut_ptr()),
                GetTextMetricsW(dc, &mut metric),
            )
        };
        let shown = name[..(length.max(1) as usize - 1).min(31)]
            .iter()
            .map(|&unit| char::from_u32(unit as u32).unwrap_or('?'));
        let _ = exe::stdout().print(format_args!(
            "fontshow: lfHeight {height} lfWeight {weight}: face "
        ));
        for character in shown {
            let _ = exe::stdout().print(format_args!("{character}"));
        }
        // TEXTMETRICW's tmPitchAndFamily, its byte 55: TMPF_TRUETYPE for a TrueType font.
        let truetype = (metric[13] >> 24) & 0x04 != 0;
        let _ = exe::stdout().print(format_args!(
            ", tmHeight {}, TrueType {}\r\n",
            metric[0],
            if truetype { "yes" } else { "no" }
        ));
        let named = "Tahoma\0".encode_utf16().eq(name[..7].iter().copied());
        if face == "Tahoma" && (!named || !truetype) {
            ok = false;
        }
        if let Some(previous) = previous {
            // SAFETY: the DC and the fonts are ours.
            unsafe {
                SelectObject(dc, previous);
                DeleteObject(font);
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
