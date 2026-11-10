//! The font exports against the host stand-ins (crate::imports::host): the file looked for in the
//! Fonts directory first, the loads' last error, the font objects' LOGFONTs both ways, the face
//! names' counts as the ttfont capture shows them, the narrow ranges, metrics and enumerations.

use std::string::String;
use std::vec::Vec;

use super::*;
use crate::imports::host::{width_of, HostFonts, DC, FIRST_FONT, FONTS, LAST_ERROR};

fn reset() {
    FONTS.with(|fonts| *fonts.borrow_mut() = HostFonts::default());
    LAST_ERROR.with(|error| error.set(0xF2F2));
}

fn last_error() -> u32 {
    LAST_ERROR.with(|error| error.get())
}

fn fonts<R>(f: impl FnOnce(&HostFonts) -> R) -> R {
    FONTS.with(|fonts| f(&fonts.borrow()))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// The capture's load section: the private load twice (W and A), two removals and a third
/// refused; the missing file 0; the public load and its removals. Each looks in the Fonts
/// directory first and leaves its ERROR_FILE_NOT_FOUND; every open is closed.
#[test]
fn loads_look_in_the_fonts_directory_first() {
    reset();
    let file = wide("f2ktahom.ttf");
    // SAFETY: the tests' own names.
    unsafe {
        assert_eq!(add_font_resource_ex_w(file.as_ptr(), 0x10, 0), 1);
        assert_eq!(last_error(), 2);
        assert_eq!(
            add_font_resource_ex_a(c"f2ktahom.ttf".as_ptr().cast(), 0x10, 0),
            1
        );
        assert_eq!(
            remove_font_resource_ex_a(c"f2ktahom.ttf".as_ptr().cast(), 0x10, 0),
            1
        );
        assert_eq!(remove_font_resource_ex_w(file.as_ptr(), 0x10, 0), 1);
        LAST_ERROR.with(|error| error.set(0xF2F2));
        assert_eq!(remove_font_resource_ex_w(file.as_ptr(), 0x10, 0), 0);
        assert_eq!(
            last_error(),
            2,
            "the Fonts directory's look, not the removal"
        );
        assert_eq!(
            add_font_resource_ex_w(wide("f2knone.ttf").as_ptr(), 0x10, 0),
            0
        );
        assert_eq!(last_error(), 2);
        assert_eq!(add_font_resource_w(file.as_ptr()), 1);
        assert_eq!(fonts(|fonts| fonts.loads), [1, 0]);
        assert_eq!(remove_font_resource_w(file.as_ptr()), 1);
        assert_eq!(remove_font_resource_a(c"f2ktahom.ttf".as_ptr().cast()), 0);
        assert_eq!(add_font_resource_ex_w(file.as_ptr(), 0, 4), 0, "reserved");
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(add_font_resource_w(core::ptr::null()), 0);
        assert_eq!(add_font_resource_w(wide("C:\\x\\f2ktahom.ttf").as_ptr()), 0);
    }
    let opened = fonts(|fonts| fonts.opened.clone());
    assert_eq!(opened[0], "C:\\WINNT\\Fonts|f2ktahom.ttf");
    assert_eq!(opened[1], "|f2ktahom.ttf");
    assert_eq!(
        opened.last().unwrap(),
        "|C:\\x\\f2ktahom.ttf",
        "a path is looked for as named"
    );
    assert_eq!(fonts(|fonts| fonts.open), 0, "every open closed");
}

/// The font objects: CreateFontIndirectW's LOGFONTW as given; CreateFontIndirectA's,
/// CreateFontA's and CreateFontW's the same; GetObjectW's and GetObjectA's sizes (92 and 60) and
/// LOGFONTA.
#[test]
fn font_objects_keep_their_logfont() {
    reset();
    let mut lf = LogFontW::zeroed();
    lf.height = -11;
    lf.weight = 400;
    lf.char_set = DEFAULT_CHARSET;
    lf.face_name[..10].copy_from_slice(&wide("F2K Tahoma")[..10]);
    let first = create_font_indirect_w(&lf);
    assert_eq!(first, FIRST_FONT);
    let mut lfa = LogFontA::zeroed();
    lfa.height = -11;
    lfa.weight = 400;
    lfa.char_set = DEFAULT_CHARSET;
    lfa.face_name[..10].copy_from_slice(b"F2K Tahoma");
    // SAFETY: the tests' own structures and names.
    let made = unsafe {
        [
            create_font_indirect_a(&lfa),
            create_font_a(
                -11,
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                c"F2K Tahoma".as_ptr().cast(),
            ),
            create_font_w(
                -11,
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                wide("F2K Tahoma").as_ptr(),
            ),
        ]
    };
    for font in made {
        let mut got = LogFontW::zeroed();
        assert_eq!(
            get_object_w(font, 92, &mut got as *mut LogFontW as usize),
            92
        );
        assert_eq!(got, lf);
    }
    assert_eq!(get_object_w(first, 0, 0), 92);
    // SAFETY: the tests' own buffer, and none.
    unsafe {
        assert_eq!(get_object_a(first, 0, core::ptr::null_mut()), 60);
        let mut narrow = LogFontA::zeroed();
        assert_eq!(
            get_object_a(first, 60, &mut narrow as *mut LogFontA as *mut u8),
            60
        );
        assert_eq!(narrow, lfa);
    }
    assert_eq!(create_font_indirect_w(core::ptr::null()), 0);
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
}

/// The face name's counts, as the capture's create section shows them: W counts units with the
/// terminator, A counts bytes without it, A with no buffer W's count; a short buffer cut.
#[test]
fn face_names_count_as_the_capture() {
    reset();
    let mut lf = LogFontW::zeroed();
    lf.face_name[..10].copy_from_slice(&wide("F2K Tahoma")[..10]);
    let font = create_font_indirect_w(&lf);
    assert_ne!(crate::dc::select_object(DC, font), 0);
    let mut units = [0x23u16; 40];
    let mut bytes = [0x23u8; 40];
    assert_eq!(get_text_face_w(DC, 32, units.as_mut_ptr()), 11);
    assert_eq!(&units[..11], &wide("F2K Tahoma")[..]);
    // SAFETY: the tests' own buffers.
    unsafe {
        assert_eq!(get_text_face_a(DC, 32, bytes.as_mut_ptr()), 10);
        assert_eq!(&bytes[..11], b"F2K Tahoma\0");
        assert_eq!(get_text_face_a(DC, 0, core::ptr::null_mut()), 11);
        bytes.fill(b'#');
        assert_eq!(get_text_face_a(DC, 4, bytes.as_mut_ptr()), 3);
        assert_eq!(&bytes[..6], b"F2K\0##");
    }
    assert_eq!(get_text_face_w(DC, 0, core::ptr::null_mut()), 11);
    units.fill(u16::from(b'#'));
    assert_eq!(get_text_face_w(DC, 4, units.as_mut_ptr()), 4);
    assert_eq!(&units[..6], &[0x46, 0x32, 0x4B, 0, 0x23, 0x23]);
}

/// The narrow ranges reach the kernel as their wide characters (0x80 the euro sign); a range that
/// runs backwards or past a byte is refused.
#[test]
fn narrow_ranges_convert() {
    reset();
    let mut widths = [0i32; 3];
    assert_eq!(
        get_char_width32_a(DC, 0x7F, 0x81, widths.as_mut_ptr() as usize),
        1
    );
    assert_eq!(
        fonts(|fonts| fonts.characters.clone()),
        [0x7F, 0x20AC, 0x81]
    );
    assert_eq!(widths, [width_of(0x7F), width_of(0x20AC), width_of(0x81)]);
    assert_eq!(
        get_char_width32_w(DC, 0x30, 0x32, widths.as_mut_ptr() as usize),
        1
    );
    assert_eq!(widths, [width_of(0x30), width_of(0x31), width_of(0x32)]);
    let mut abc = [Abc::default(); 2];
    assert_eq!(
        get_char_abc_widths_a(DC, 0x41, 0x42, abc.as_mut_ptr() as usize),
        1
    );
    assert_eq!(
        abc[1],
        Abc {
            a: 1,
            b: width_of(0x42) as u32,
            c: -1
        }
    );
    assert_eq!(
        get_char_width32_a(DC, 0x41, 0x100, widths.as_mut_ptr() as usize),
        0
    );
    assert_eq!(
        get_char_width32_w(DC, 0x42, 0x41, widths.as_mut_ptr() as usize),
        0
    );
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
}

/// GetOutlineTextMetricsA: the structure 212 bytes, its names after it in the ANSI code page,
/// their offsets the narrow ones, its TEXTMETRICA as the capture's (0x1E to 0xFF).
#[test]
fn outline_metrics_convert() {
    reset();
    let wide_size = crate::imports::host::outline_metric().len() as u32;
    assert_eq!(get_outline_text_metrics_w(DC, 0, 0), wide_size);
    let size = 212 + 7 + 5 + 6 + 10;
    // SAFETY: the tests' own buffer, and none.
    unsafe {
        assert_eq!(
            get_outline_text_metrics_a(DC, 0, core::ptr::null_mut()),
            size
        );
        let mut buffer = [0u32; 64];
        let bytes = buffer.as_mut_ptr() as *mut u8;
        assert_eq!(get_outline_text_metrics_a(DC, size, bytes), size);
        let all = buffer.as_bytes();
        let metric = OutlineTextMetricA::from_bytes(all).unwrap();
        assert_eq!(metric.size, size);
        assert_eq!(
            (
                metric.text_metrics.first_char,
                metric.text_metrics.last_char
            ),
            (0x1E, 0xFF)
        );
        assert_eq!(metric.fields.em_square, 2048);
        let name = |offset: u32| {
            let rest = &all[offset as usize..];
            String::from_utf8(rest[..rest.iter().position(|&b| b == 0).unwrap()].to_vec()).unwrap()
        };
        assert_eq!(name(metric.fields.family_name), "Family");
        assert_eq!(name(metric.fields.face_name), "Face");
        assert_eq!(name(metric.fields.style_name), "Style");
        assert_eq!(name(metric.fields.full_name), "Full name");
    }
}

/// GetGlyphOutlineA converts its character; a matrix that is not the identity goes to the stub
/// routine; no GLYPHMETRICS is ERROR_INVALID_PARAMETER.
#[test]
fn glyph_outlines_check_their_arguments() {
    reset();
    let mut metrics = [0u32; 5];
    let at = metrics.as_mut_ptr() as usize;
    let identity = [0x0001_0000u32, 0, 0, 0x0001_0000];
    // SAFETY: the tests' own matrices and buffers.
    unsafe {
        assert_eq!(get_glyph_outline_a(DC, 0x80, 0, at, 0, 0, &identity), 32);
        assert_eq!(get_glyph_outline_w(DC, 0x41, 1, at, 0, 0, &identity), 32);
        assert_eq!(get_glyph_outline_a(DC, 7, 0x81, at, 0, 0, &identity), 32);
        assert_eq!(
            fonts(|fonts| fonts.glyphs.clone()),
            [(0x20AC, 0), (0x41, 1), (7, 0x81)]
        );
        assert_eq!(
            get_glyph_outline_w(DC, 0x41, 0, 0, 0, 0, &identity),
            GDI_ERROR
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        let doubled = [0x0002_0000u32, 0, 0, 0x0002_0000];
        assert_eq!(
            get_glyph_outline_w(DC, 0x41, 0, at, 0, 0, &doubled),
            GDI_ERROR
        );
        assert_eq!(
            get_glyph_outline_w(DC, 0x41, 2, at, 0, 0, &identity),
            GDI_ERROR,
            "GGO_NATIVE"
        );
        assert_eq!(last_error(), crate::stub::ERROR_CALL_NOT_IMPLEMENTED);
    }
}

std::thread_local! {
    static SEEN: core::cell::RefCell<Vec<(String, String, u8, u8)>> = const { core::cell::RefCell::new(Vec::new()) };
}

fn wide_text(units: &[u16]) -> String {
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    String::from_utf16(&units[..end]).unwrap()
}

fn narrow_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).unwrap()
}

unsafe extern "system" fn seen_w(
    log_font: *const u8,
    metric: *const u8,
    font_type: u32,
    value: isize,
) -> i32 {
    // SAFETY: the enumeration's structures.
    let (log_font, metric) = unsafe {
        (
            (log_font as *const EnumLogFontExW).read_unaligned(),
            (metric as *const NewTextMetricExW).read_unaligned(),
        )
    };
    assert_eq!(font_type, TRUETYPE_FONTTYPE);
    SEEN.with(|seen| {
        seen.borrow_mut().push((
            wide_text(&log_font.log_font.face_name),
            wide_text(&log_font.script),
            log_font.log_font.char_set,
            metric.metric.text_metric.char_set,
        ))
    });
    value as i32
}

unsafe extern "system" fn seen_a(
    log_font: *const u8,
    metric: *const u8,
    _font_type: u32,
    value: isize,
) -> i32 {
    // SAFETY: the enumeration's structures.
    let (log_font, metric) = unsafe {
        (
            (log_font as *const EnumLogFontExA).read_unaligned(),
            (metric as *const NewTextMetricExA).read_unaligned(),
        )
    };
    assert_eq!(
        (
            metric.metric.text_metric.first_char,
            metric.metric.text_metric.last_char
        ),
        (0x1E, 0xFF)
    );
    SEEN.with(|seen| {
        seen.borrow_mut().push((
            narrow_text(&log_font.log_font.face_name),
            narrow_text(&log_font.script),
            log_font.log_font.char_set,
            metric.metric.text_metric.char_set,
        ))
    });
    value as i32
}

fn seen() -> Vec<(String, String, u8, u8)> {
    SEEN.with(|seen| seen.take())
}

/// The enumerations: each face's records through the callback, converted for the narrow forms;
/// the callback's answer the call's, its 0 stopping it; 1 when nothing is enumerated; the face
/// name and the character set as the LOGFONT gives them, and EnumFontFamilies' each face once.
#[test]
fn enumerations_call_back() {
    reset();
    seen();
    let mut lf = LogFontW::zeroed();
    lf.char_set = DEFAULT_CHARSET;
    lf.face_name[..10].copy_from_slice(&wide("F2K Tahoma")[..10]);
    // SAFETY: the tests' own structures and callbacks.
    unsafe {
        assert_eq!(enum_font_families_ex_w(DC, &lf, Some(seen_w), 5, 0), 5);
        assert_eq!(
            seen(),
            [
                ("F2K Tahoma".into(), "Western".into(), 0, 0),
                ("F2K Tahoma".into(), "Cyrillic".into(), 204, 204)
            ]
        );
        assert_eq!(enum_font_families_ex_w(DC, &lf, Some(seen_w), 0, 0), 0);
        assert_eq!(seen().len(), 1, "stopped at the first");
        let mut lfa = LogFontA::zeroed();
        lfa.char_set = ANSI_CHARSET;
        lfa.face_name[..10].copy_from_slice(b"F2K Tahoma");
        assert_eq!(enum_font_families_ex_a(DC, &lfa, Some(seen_a), 1, 0), 1);
        assert_eq!(
            seen()[1],
            ("F2K Tahoma".into(), "Cyrillic".into(), 204, 204)
        );
        assert_eq!(
            enum_font_families_w(DC, wide("F2K Tahoma").as_ptr(), Some(seen_w), 1),
            1
        );
        assert_eq!(seen().len(), 1);
        assert_eq!(
            enum_font_families_a(DC, c"F2K No Such Face".as_ptr().cast(), Some(seen_a), 3),
            1
        );
        assert!(seen().is_empty());
        assert_eq!(enum_font_families_w(DC, core::ptr::null(), None, 1), 0);
    }
    assert_eq!(
        fonts(|fonts| fonts.enumerated.clone()),
        [
            ("F2K Tahoma".into(), DEFAULT_CHARSET, 0),
            ("F2K Tahoma".into(), DEFAULT_CHARSET, 0),
            ("F2K Tahoma".into(), ANSI_CHARSET, 0),
            ("F2K Tahoma".into(), DEFAULT_CHARSET, 1),
            ("F2K No Such Face".into(), DEFAULT_CHARSET, 1),
        ]
    );
}

/// GetFontData answers the kernel's answer, GDI_ERROR included, leaving the last error.
#[test]
fn font_data_answers_the_kernels() {
    reset();
    let mut buffer = [0u8; 8];
    assert_eq!(get_font_data(DC, 0x6461_6568, 0, 0, 0), 54);
    assert_eq!(
        get_font_data(DC, 0x6461_6568, 50, buffer.as_mut_ptr() as usize, 8),
        4
    );
    assert_eq!(buffer[..5], [0xAB, 0xAB, 0xAB, 0xAB, 0]);
    assert_eq!(
        get_font_data(DC, 0x6461_6568, 54, buffer.as_mut_ptr() as usize, 8),
        GDI_ERROR
    );
    assert_eq!(last_error(), 0xF2F2);
}
