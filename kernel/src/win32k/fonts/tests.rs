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
