//! The fonts against Windows 2000's answers on the fixtures' font (tests/gdi32/ttfont/output.txt):
//! the text a run draws, set against the capture's `pixels` section (TextOutW into a memory DC,
//! which F2K has not yet: the rows are checked here, on a fake screen); the extents of the
//! `widths` section; the enumeration's records; GetFontData's sizes; the outline metrics' layout.

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use rtl::gdi::{LogFontW, DEFAULT_CHARSET};

use super::table::{FileIdentity, FontTable, Key, Owner, Realization};
use super::*;
use crate::hw::vbe::{Framebuffer, Geometry, PixelMemory};

// The table's storage in the host tests is a vector (table.rs's tests give it its Storage).
type Table = FontTable<Vec<u8>>;

const FILE: FileIdentity = FileIdentity {
    parent_cluster: 2,
    index: 9,
};

fn repository_file(path: &str) -> Vec<u8> {
    let full = format!("{}/../{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read(&full).unwrap_or_else(|error| panic!("{full}: {error}"))
}

/// The lines of the capture's section `name`.
fn capture_section(name: &str) -> Vec<String> {
    let capture = String::from_utf8(repository_file("tests/gdi32/ttfont/output.txt")).unwrap();
    let start = format!("== {name}");
    capture
        .lines()
        .skip_while(|line| *line != start)
        .skip(1)
        .take_while(|line| !line.starts_with("<<<"))
        .map(String::from)
        .collect()
}

/// A table with the fixtures' font loaded for process 1.
fn table() -> std::boxed::Box<Table> {
    let mut table = std::boxed::Box::new(Table::new());
    table
        .add(
            repository_file("tests/gdi32/ttfont/f2ktahom.ttf"),
            FILE,
            Owner::Private(1),
        )
        .unwrap();
    table
}

fn key_for(table: &Table, height: i32, weight: i32) -> Key {
    let mut font = LogFontW::zeroed();
    font.height = height;
    font.weight = weight;
    font.char_set = DEFAULT_CHARSET;
    for (unit, byte) in font.face_name.iter_mut().zip("F2K Tahoma".encode_utf16()) {
        *unit = byte;
    }
    match table.map(&font, 1) {
        Realization::TrueType { key, .. } => key,
        other => panic!("{other:?}"),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// A screen's pixel memory: 32-bit pixels, packed.
struct Memory(Vec<u32>);

impl PixelMemory for Memory {
    fn store(&mut self, offset: usize, value: u32) {
        self.0[offset / 4] = value;
    }

    fn load(&mut self, offset: usize) -> u32 {
        self.0[offset / 4]
    }
}

const WHITE: u32 = 0x00FF_FFFF;

/// The capture's rows of the pixels section's text at `height`: '#' black, '.' white.
fn captured_rows(height: i32) -> Vec<String> {
    let heading = format!("-- lfHeight {height}, ");
    capture_section("pixels")
        .into_iter()
        .skip_while(|line| !line.starts_with(&heading))
        .skip_while(|line| !line.starts_with("row "))
        .take_while(|line| line.starts_with("row "))
        .map(|line| line.split_once(": ").unwrap().1.into())
        .collect()
}

/// "Wg0@ Hij!" drawn at (2, 2) in black, TRANSPARENT, on a white screen the capture's size, as the
/// capture's rows show it.
fn drawn_rows(table: &mut Table, height: i32, width: usize, rows: usize) -> Vec<String> {
    let mut screen = Framebuffer::new(Memory(vec![0; width * rows]), Geometry::packed(width, rows));
    screen.clear(WHITE);
    let key = key_for(table, height, 400);
    let cell = table.cell(key).unwrap();
    let clip = rtl::gdi::Rect {
        left: 0,
        top: 0,
        right: width as i32,
        bottom: rows as i32,
    };
    let text = TextOut::new(clip, 0, WHITE, false, 2, 0, None);
    let end = draw_run(
        table,
        Some(&mut screen),
        &text,
        key,
        cell,
        2,
        &wide("Wg0@ Hij!"),
        None,
    );
    assert_eq!(end - 2, extent(table, key, &wide("Wg0@ Hij!")));
    (0..rows)
        .map(|y| {
            (0..width)
                .map(|x| match screen.get_pixel(x, y) {
                    Some(0) => '#',
                    Some(WHITE) => '.',
                    _ => '?',
                })
                .collect()
        })
        .collect()
}

/// At lfHeight -11 the text is the 11-ppem strike's glyphs, placed as Windows 2000 placed them:
/// every pixel of the capture's rows.
#[test]
fn text_at_a_strikes_size_matches_the_capture() {
    let mut table = table();
    let captured = captured_rows(-11);
    assert_eq!(captured.len(), 18);
    assert_eq!(drawn_rows(&mut table, -11, 64, 18), captured);
}

/// At lfHeight -24, which no strike has, the outlines are scan-converted unhinted: the rows match
/// the capture but for the pixels the rasteriser's tests list ('0''s and '@''s, each a pixel
/// Windows leaves off), placed where the run draws those glyphs.
#[test]
fn text_from_outlines_matches_the_capture_but_for_the_known_pixels() {
    let mut table = table();
    let captured = captured_rows(-24);
    let ours = drawn_rows(&mut table, -24, 128, 34);
    let mut differing = Vec::new();
    for (y, (theirs, ours)) in captured.iter().zip(&ours).enumerate() {
        for (x, (a, b)) in theirs.chars().zip(ours.chars()).enumerate() {
            if a != b {
                differing.push((x, y, a, b));
            }
        }
    }
    // '0''s pixel (its black box's 8, 5) and '@''s (its 2, 15), each set by F2K and left by
    // Windows: the text's row is 2, the baseline 24 below it, the glyphs' tops 18 above that.
    assert_eq!(differing, [(46, 13, '.', '#'), (54, 23, '.', '#')]);
}

/// Under OPAQUE the run's cells are filled with the background, the glyphs drawn over them.
#[test]
fn an_opaque_run_fills_its_cells() {
    let mut table = table();
    let key = key_for(&table, -11, 400);
    let cell = table.cell(key).unwrap();
    let mut screen = Framebuffer::new(Memory(vec![0x12_3456; 40 * 20]), Geometry::packed(40, 20));
    let clip = rtl::gdi::Rect {
        left: 0,
        top: 0,
        right: 40,
        bottom: 20,
    };
    let text = TextOut::new(clip, 0, WHITE, true, 1, 0, None);
    let end = draw_run(
        &mut table,
        Some(&mut screen),
        &text,
        key,
        cell,
        3,
        &wide("ii"),
        None,
    );
    assert_eq!(end, 3 + 4, "two advances of 2");
    for y in 0..20 {
        for x in 0..40 {
            let pixel = screen.get_pixel(x, y).unwrap();
            let inside = (3..7).contains(&x) && (1..14).contains(&y);
            assert_eq!(pixel != 0x12_3456, inside, "({x}, {y})");
        }
    }
}

/// The text extents of the capture's widths section, at each height and both weights: the
/// characters' advances summed (U+4E00 the missing glyph's).
#[test]
fn extents_match_the_capture() {
    let mut table = table();
    let mut heading = None;
    let mut checked = 0;
    for line in capture_section("widths") {
        if let Some(rest) = line.strip_prefix("-- lfHeight ") {
            let (height, weight) = rest.split_once(", lfWeight ").unwrap();
            heading = Some((height.parse().unwrap(), weight.parse().unwrap()));
            continue;
        }
        let Some(rest) = line.strip_prefix("GetTextExtentPoint32W(L\"") else {
            continue;
        };
        let (text, rest) = rest.split_once("\", ").unwrap();
        let text = text.replace("<U+4E00>", "\u{4E00}");
        let field = |name: &str| -> i32 {
            let at = rest.find(&format!("{name}=")).unwrap() + name.len() + 1;
            rest[at..].split(' ').next().unwrap().parse().unwrap()
        };
        let (height, weight) = heading.unwrap();
        let key = key_for(&table, height, weight);
        let units = wide(&text);
        let cx = extent(&mut table, key, &units);
        assert_eq!(cx, field("cx"), "{height} {weight} {text:?}");
        let cy = if units.is_empty() {
            0
        } else {
            table.cell(key).unwrap().height
        };
        assert_eq!(cy, field("cy"), "{height} {weight} {text:?}");
        checked += 1;
    }
    assert_eq!(checked, 7 * 8);
}

/// The enumeration's records, as the capture's callbacks print them: five character sets for
/// DEFAULT_CHARSET, one for ANSI_CHARSET, one for the families' enumeration, none for a face no
/// font has.
#[test]
fn the_enumeration_matches_the_capture() {
    let table = table();
    let face = wide("F2K Tahoma");
    let all: Vec<FontEnumRecord> = (0..)
        .map_while(|index| enumerated(&table, 1, Some(&face), DEFAULT_CHARSET, false, index))
        .collect();
    let sets: Vec<(u8, String)> = all
        .iter()
        .map(|record| {
            let script = &record.log_font.script;
            let end = script.iter().position(|&unit| unit == 0).unwrap();
            (
                record.log_font.log_font.char_set,
                String::from_utf16(&script[..end]).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        sets,
        [
            (0, "Western".into()),
            (178, "Arabic".into()),
            (162, "Turkish".into()),
            (238, "Central European".into()),
            (204, "Cyrillic".into())
        ]
    );
    let first = all[0];
    let log_font = first.log_font.log_font;
    assert_eq!(
        (
            log_font.height,
            log_font.width,
            log_font.weight,
            log_font.out_precision,
            log_font.clip_precision,
            log_font.quality,
            log_font.pitch_and_family
        ),
        (39, 14, 400, 3, 2, 1, 0x22)
    );
    assert_eq!(log_font.face(), &face[..]);
    let metric = first.metric.metric;
    assert_eq!(
        (
            metric.text_metric.height,
            metric.text_metric.max_char_width,
            metric.text_metric.pitch_and_family,
            metric.flags,
            metric.size_em,
            metric.cell_height,
            metric.avg_width
        ),
        (39, 47, 0x27, 0x40, 2048, 2472, 910)
    );
    assert_eq!(all[1].metric.metric.text_metric.char_set, 178);
    assert_eq!(first.font_type, 4);
    assert!(enumerated(&table, 1, Some(&face), 0, false, 1).is_none());
    assert_eq!(
        enumerated(&table, 1, Some(&face), 0, false, 0)
            .map(|record| record.log_font.log_font.char_set),
        Some(0)
    );
    let families: Vec<_> = (0..)
        .map_while(|index| enumerated(&table, 1, Some(&face), DEFAULT_CHARSET, true, index))
        .collect();
    assert_eq!(families.len(), 1);
    assert!(enumerated(
        &table,
        1,
        Some(&wide("F2K No Such Face")),
        DEFAULT_CHARSET,
        false,
        0
    )
    .is_none());
    assert!(
        enumerated(&table, 2, None, DEFAULT_CHARSET, false, 0).is_none(),
        "another process's face"
    );
}

/// GetFontData's sizes and partial reads, as the capture's data section answers them.
#[test]
fn font_data_matches_the_capture() {
    let font = repository_file("tests/gdi32/ttfont/f2ktahom.ttf");
    let tag = |name: &[u8; 4]| u32::from_le_bytes(*name);
    assert_eq!(font_data(&font, tag(b"head"), 0).map(<[u8]>::len), Some(54));
    assert_eq!(
        font_data(&font, tag(b"EBDT"), 0).map(<[u8]>::len),
        Some(35_699)
    );
    assert_eq!(font_data(&font, 0, 0).map(<[u8]>::len), Some(143_612));
    for missing in [b"fpgm", b"prep", b"kern", b"hdmx"] {
        assert_eq!(font_data(&font, tag(missing), 0), None);
    }
    assert_eq!(font_data(&font, tag(b"head"), 50).map(<[u8]>::len), Some(4));
    assert_eq!(font_data(&font, tag(b"head"), 54), None);
    assert_eq!(font_data(&font, tag(b"head"), 100), None);
    assert_eq!(
        &font_data(&font, tag(b"hhea"), 4).unwrap()[..6],
        [0x08, 0x01, 0xFE, 0x59, 0, 0]
    );
}

/// OUTLINETEXTMETRICW's size and its names after it: 298 bytes, as the capture's.
#[test]
fn the_outline_metrics_lay_out_their_names() {
    let table = table();
    let key = key_for(&table, -11, 400);
    let (metric, names) = outline_metric(&table, key, 0).unwrap();
    assert_eq!(metric.size, 298);
    assert_eq!(metric.fields.family_name, 216);
    assert_eq!(metric.fields.face_name, 216 + 22);
    assert_eq!(metric.fields.style_name, 216 + 44);
    assert_eq!(metric.fields.full_name, 216 + 60);
    assert_eq!(names[2].units(), &wide("Regular")[..]);
    assert_eq!(metric.text_metrics, table.text_metric(key, 0).unwrap());
}

// --- The system's faces: Wine's five (fonts/), as the boot loads them ---------------------------

/// A table with the boot's five faces loaded, public.
fn system_table() -> std::boxed::Box<Table> {
    let mut table = std::boxed::Box::new(Table::new());
    for (index, path) in BOOT_FONTS.iter().enumerate() {
        let name = path.rsplit('\\').next().unwrap();
        let identity = FileIdentity {
            parent_cluster: 3,
            index: index as u32,
        };
        table
            .add(
                repository_file(&format!("fonts/{name}")),
                identity,
                Owner::Public,
            )
            .unwrap();
    }
    table
}

fn log_font(face: &str, height: i32, weight: i32) -> LogFontW {
    let mut font = LogFontW::zeroed();
    font.height = height;
    font.weight = weight;
    font.char_set = DEFAULT_CHARSET;
    for (unit, byte) in font.face_name.iter_mut().zip(face.encode_utf16()) {
        *unit = byte;
    }
    font
}

/// What `log_font` realises to: its key, the name GetTextFace answers, its face's style name.
fn realised(table: &Table, log_font: &LogFontW) -> (Key, String, String) {
    match table.map(log_font, 1) {
        Realization::TrueType { key, name, .. } => {
            let face = table.face(key.face).unwrap();
            (
                key,
                String::from_utf16(name.units()).unwrap(),
                String::from_utf16(face.style.units()).unwrap(),
            )
        }
        other => panic!("{other:?}"),
    }
}

/// The dialog base units of a realised font, as GetDialogBaseUnits and MapDialogRect compute them
/// from it: the 52 letters' extent over 26, plus one, halved; the cell's height.
fn base_units(table: &mut Table, key: Key) -> (i32, i32) {
    let letters = wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    let width = extent(table, key, &letters);
    ((width / 26 + 1) / 2, table.cell(key).unwrap().height)
}

/// The stock SYSTEM_FONT is the System face at its 16-pixel strike: the guidc capture's "Hello"
/// 34 wide and 16 high, an average of 7; its dialog base units 8 by 16, the dialog capture's for
/// a dialog with no font.
#[test]
fn the_system_font_is_the_system_face() {
    let mut table = system_table();
    let stock = mapper::stock_log_font(rtl::gdi::SYSTEM_FONT).unwrap();
    let (key, name, _) = realised(&table, &stock);
    assert_eq!((key.ppem, key.raster, key.bold), (16, true, false));
    assert_eq!(name, "System");
    assert_eq!(extent(&mut table, key, &wide("Hello")), 34);
    let metric = table.text_metric(key, 0).unwrap();
    assert_eq!((metric.height, metric.ave_char_width), (16, 7));
    assert_eq!(base_units(&mut table, key), (8, 16));
}

/// DEFAULT_GUI_FONT and a dialog's "MS Shell Dlg" at 8 points are MS Sans Serif at its 13-pixel
/// strike, the name answered as asked; its dialog base units 6 by 13, the dialog capture's.
/// "Microsoft Sans Serif" reaches the same face through its stand-in, and "MS Sans Serif" by its
/// own name.
#[test]
fn the_dialog_face_is_ms_sans_serif() {
    let mut table = system_table();
    let stock = mapper::stock_log_font(rtl::gdi::DEFAULT_GUI_FONT).unwrap();
    let (key, name, _) = realised(&table, &stock);
    assert_eq!((key.ppem, key.raster), (13, true));
    assert_eq!(name, "MS Shell Dlg");
    assert_eq!(base_units(&mut table, key), (6, 13));
    let face = table.face(key.face).unwrap();
    assert_eq!(face.family.units(), &wide("MS Sans Serif")[..]);
    let (stood_in, name, _) = realised(&table, &log_font("Microsoft Sans Serif", -11, 400));
    assert_eq!((stood_in, name.as_str()), (key, "Microsoft Sans Serif"));
    let (own, name, _) = realised(&table, &log_font("MS Sans Serif", 16, 400));
    assert_eq!((own.ppem, name.as_str()), (16, "MS Sans Serif"));
    let (var, _, _) = realised(
        &table,
        &mapper::stock_log_font(rtl::gdi::ANSI_VAR_FONT).unwrap(),
    );
    assert_eq!(var, key);
}

/// Tahoma asked bold is the Tahoma Bold face, not Tahoma emboldened; asked regular, Tahoma; a
/// bold request of MS Sans Serif, which has no bold face, is emboldened. The dialog face "MS
/// Shell Dlg 2" at 8 points is Tahoma's 11-pixel strike, its base units 6 by 13.
#[test]
fn a_bold_request_takes_the_bold_face() {
    let mut table = system_table();
    let (bold, name, style) = realised(&table, &log_font("Tahoma", -11, 700));
    assert_eq!(
        (bold.bold, name.as_str(), style.as_str()),
        (false, "Tahoma", "Bold")
    );
    let (regular, _, style) = realised(&table, &log_font("Tahoma", -11, 400));
    assert_eq!((regular.bold, style.as_str()), (false, "Regular"));
    assert_ne!(bold.face, regular.face);
    let (synthesised, _, _) = realised(&table, &log_font("MS Sans Serif", -11, 700));
    assert!(synthesised.bold);
    let (dialog, name, _) = realised(&table, &log_font("MS Shell Dlg 2", -11, 400));
    assert_eq!((dialog, name.as_str()), (regular, "MS Shell Dlg 2"));
    assert_eq!(base_units(&mut table, dialog), (6, 13));
}

/// Marlett by its name, a symbol face: its characters at U+F000 and up, as its codes are.
#[test]
fn marlett_is_found_by_its_name() {
    let mut table = system_table();
    let (key, name, _) = realised(&table, &log_font("Marlett", -13, 400));
    assert_eq!(
        (key.ppem, key.raster, name.as_str()),
        (13, false, "Marlett")
    );
    let mut glyphs = [0u16; 4];
    table
        .glyph_indices(key.face, &wide("rstu"), &mut glyphs)
        .unwrap();
    assert!(glyphs.iter().all(|&glyph| glyph != 0), "{glyphs:?}");
    assert!(extent(&mut table, key, &wide("r")) > 0);
}

/// A name no face has is the System face, the mapper's default; asked at a fixed pitch it is the
/// built-in font. Without a System face, it is the built-in font as before.
#[test]
fn an_unknown_name_is_the_system_face() {
    let table = system_table();
    for unknown in ["F2K No Such Face", ""] {
        let (key, name, _) = realised(&table, &log_font(unknown, 0, 0));
        assert_eq!((key.ppem, name.as_str()), (16, "System"));
    }
    let mut fixed = log_font("F2K No Such Face", 0, 0);
    fixed.pitch_and_family = rtl::gdi::FIXED_PITCH;
    assert_eq!(
        table.map(&fixed, 1),
        Realization::BuiltIn {
            name: FaceName::ascii("System")
        }
    );
    let tahoma_only = self::table();
    assert!(matches!(
        tahoma_only.map(&log_font("F2K No Such Face", 0, 0), 1),
        Realization::BuiltIn { .. }
    ));
}

/// A raster-style face draws its strike's glyphs: a character the face has no glyph for draws the
/// strike's missing glyph, not a blank from the empty outlines.
#[test]
fn a_raster_face_draws_its_strike_alone() {
    let mut table = system_table();
    let (key, _, _) = realised(&table, &log_font("System", 16, 0));
    let mut glyphs = [0u16; 2];
    table
        .glyph_indices(key.face, &wide("A\u{4E00}"), &mut glyphs)
        .unwrap();
    let a = table
        .with_glyph(key, glyphs[0], |metrics, bits| (*metrics, bits.len()))
        .unwrap();
    assert!(a.1 > 0, "the strike's 'A'");
    let missing = table
        .with_glyph(key, glyphs[1], |metrics, _| *metrics)
        .unwrap();
    let zero = table.with_glyph(key, 0, |metrics, _| *metrics).unwrap();
    assert_eq!(missing, zero);
    assert!(
        zero.black_box_y > 1,
        "the strike's missing glyph, not a blank"
    );
}

/// The enumeration reports a raster-style face as a raster font, once per strike for its name;
/// a family of two faces (Tahoma and Tahoma Bold) twice for its name; every family once for no
/// name.
#[test]
fn raster_faces_enumerate_as_raster_fonts() {
    let table = system_table();
    let system = wide("System");
    let sizes: Vec<(i32, u32)> = (0..)
        .map_while(|index| enumerated(&table, 1, Some(&system), 0, false, index))
        .map(|record| (record.log_font.log_font.height, record.font_type))
        .collect();
    assert_eq!(sizes, [(16, 1), (18, 1)]);
    let first = enumerated(&table, 1, Some(&system), 0, false, 0).unwrap();
    let log_font = first.log_font.log_font;
    assert_eq!(
        (
            log_font.width,
            log_font.weight,
            log_font.out_precision,
            log_font.pitch_and_family
        ),
        (7, 700, 1, 0x22)
    );
    assert_eq!(first.metric.metric.text_metric.pitch_and_family, 0x21);
    let tahoma = wide("Tahoma");
    let styles = (0..)
        .map_while(|index| enumerated(&table, 1, Some(&tahoma), DEFAULT_CHARSET, true, index))
        .count();
    assert_eq!(styles, 2);
    let families: Vec<String> = (0..)
        .map_while(|index| enumerated(&table, 1, None, DEFAULT_CHARSET, true, index))
        .map(|record| String::from_utf16(record.log_font.log_font.face()).unwrap())
        .collect();
    assert_eq!(families, ["Tahoma", "MS Sans Serif", "System", "Marlett"]);
}
