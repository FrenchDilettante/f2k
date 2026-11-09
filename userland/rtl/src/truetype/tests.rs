//! The reader against the repository's fonts: Wine's Tahoma (fonts/tahoma.ttf) and the fixtures'
//! renamed copy (tests/gdi32/ttfont/f2ktahom.ttf), read from the repository when the tests run, and
//! against Windows 2000's answers on the copy (tests/gdi32/ttfont/output.txt). Then malformed
//! files, which must give errors and never a panic.

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use super::glyf::{Outline, Point};
use super::scale::Scale;
use super::*;

/// A file of the repository, read when the test runs.
pub(super) fn repository_file(path: &str) -> Vec<u8> {
    let full = format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read(&full).unwrap_or_else(|error| panic!("{full}: {error}"))
}

/// The fixtures' copy, which the capture describes.
pub(super) fn fixture_font() -> Vec<u8> {
    repository_file("tests/gdi32/ttfont/f2ktahom.ttf")
}

/// Wine's Tahoma, as the owner fetched it.
fn wine_font() -> Vec<u8> {
    repository_file("fonts/tahoma.ttf")
}

/// The lines of the capture's section `name`.
pub(super) fn capture_section(name: &str) -> Vec<String> {
    let capture = String::from_utf8(repository_file("tests/gdi32/ttfont/output.txt")).unwrap();
    let start = format!("== {name}");
    capture
        .lines()
        .skip_while(|line| *line != start)
        .skip(1)
        .take_while(|line| !line.starts_with("== ") && !line.starts_with("<<<"))
        .map(String::from)
        .collect()
}

/// One GetGlyphOutlineW glyph of the capture's `glyphs` section: the LOGFONT height it was drawn
/// at, its character, its GLYPHMETRICS and its GGO_BITMAP rows (as the capture prints them: the
/// bytes that cover the black box's width, in hex).
#[derive(Debug)]
pub(super) struct CapturedGlyph {
    pub height: i32,
    pub character: u32,
    /// gmBlackBoxX, gmBlackBoxY, gmptGlyphOrigin.x, gmptGlyphOrigin.y, gmCellIncX.
    pub metrics: [i32; 5],
    /// GGO_BITMAP's size for a NULL buffer.
    pub size: u32,
    pub rows: Vec<String>,
}

/// The capture's GetGlyphOutlineW glyphs.
pub(super) fn captured_glyphs() -> Vec<CapturedGlyph> {
    let mut glyphs: Vec<CapturedGlyph> = Vec::new();
    let mut height = 0;
    for line in capture_section("glyphs") {
        let field = |name: &str| -> i32 {
            let at = line.find(&format!("{name}=")).unwrap() + name.len() + 1;
            let text: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            text.parse().unwrap()
        };
        if line.starts_with("-- GetGlyphOutlineA") {
            break;
        }
        if let Some(rest) = line.strip_prefix("-- lfHeight ") {
            height = rest.split(',').next().unwrap().parse().unwrap();
        } else if line.starts_with("U+") && line.contains("(GGO_METRICS)") {
            glyphs.push(CapturedGlyph {
                height,
                character: u32::from_str_radix(&line[2..6], 16).unwrap(),
                metrics: [0; 5],
                size: 0,
                rows: Vec::new(),
            });
        } else if line.contains("gmBlackBoxX=") {
            let origin = line.split("gmptGlyphOrigin=").nth(1).unwrap();
            let mut origin = origin.split(' ').next().unwrap().split(',');
            glyphs.last_mut().unwrap().metrics = [
                field("gmBlackBoxX"),
                field("gmBlackBoxY"),
                origin.next().unwrap().parse().unwrap(),
                origin.next().unwrap().parse().unwrap(),
                field("gmCellIncX"),
            ];
        } else if line.contains("(GGO_BITMAP, 0, NULL)") {
            glyphs.last_mut().unwrap().size = field("ret") as u32;
        } else if let Some(row) = line.strip_prefix("  row ") {
            let hex = row.split(": ").nth(1).unwrap();
            glyphs.last_mut().unwrap().rows.push(String::from(hex));
        }
    }
    glyphs
}

/// The CRC-32 (IEEE 802.3, reflected) the capture prints for each table.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A tag as the capture quotes it.
fn tag(name: &str) -> Tag {
    Tag::new(name.as_bytes().try_into().unwrap())
}

/// Every GetFontData line of the capture: each table's size and CRC-32, the tables the font
/// lacks, the whole file, and the partial reads (the bytes returned, and GDI_ERROR for an offset
/// at or past the table's end).
#[test]
fn every_table_matches_the_capture() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let mut checked = 0;
    for line in capture_section("data") {
        let Some(call) = line.strip_prefix("GetFontData(") else {
            continue;
        };
        if line.contains("stock SYSTEM_FONT") {
            continue;
        }
        let (table, call) = if let Some(rest) = call.strip_prefix("0 (the whole file), ") {
            (Some(font.data()), rest)
        } else {
            let name = &call[1..5];
            (font.table(tag(name)), &call[8..])
        };
        let mut arguments = call.split(", ");
        let offset: usize = arguments.next().unwrap().parse().unwrap();
        let buffer = arguments.next().unwrap();
        let ret = line
            .split("ret=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        if ret == "GDI_ERROR" {
            assert!(table.is_none_or(|table| offset >= table.len()), "{line}");
        } else {
            let ret: usize = ret.parse().unwrap();
            let table = table.unwrap_or_else(|| panic!("{line}"));
            if buffer == "NULL" {
                assert_eq!(table.len(), ret, "{line}");
            } else if let Some(crc) = line.split("crc32=0x").nth(1) {
                assert_eq!(table.len(), ret, "{line}");
                assert_eq!(
                    crc32(table),
                    u32::from_str_radix(crc, 16).unwrap(),
                    "{line}"
                );
            } else {
                let hex = line.split("buf=").nth(1).unwrap();
                let expected: Vec<u8> = (0..ret)
                    .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
                    .collect();
                assert_eq!(&table[offset..offset + ret], &expected[..], "{line}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 43);
}

/// Both files' tables sum to their directory's checksums, and each whole file to the head
/// table's magic sum.
#[test]
fn checksums_match() {
    for data in [fixture_font(), wine_font()] {
        let font = Font::new(&data).unwrap();
        assert_eq!(font.directory().len(), 20);
        for record in font.directory().records() {
            assert!(record.checksum_matches(&data).unwrap(), "{:?}", record.tag);
        }
        assert_eq!(directory::table_checksum(&data), 0xB1B0_AFBA);
    }
}

/// The headers, as the capture's outline text metrics and GetFontData's partial reads show
/// them.
#[test]
fn headers_read() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    assert_eq!(font.head.units_per_em, 2048);
    assert_eq!(font.head.lowest_rec_ppem, 8);
    assert_eq!(
        (
            font.head.x_min,
            font.head.y_min,
            font.head.x_max,
            font.head.y_max
        ),
        (-210, -850, 2754, 2389)
    );
    assert_eq!(font.head.index_to_loc_format, 0);
    assert_eq!(
        (font.hhea.ascender, font.hhea.descender, font.hhea.line_gap),
        (2049, -423, 0)
    );
    assert_eq!(font.hhea.number_of_h_metrics, 981);
    assert_eq!(font.glyph_count(), 988);
    assert_eq!(font.maxp.max_component_depth, 3);

    let os2 = font.os2().unwrap().unwrap();
    assert_eq!(os2.version, 2);
    assert_eq!(os2.panose, [2, 11, 6, 4, 3, 5, 4, 4, 2, 4]);
    assert_eq!((os2.fs_selection, os2.fs_type), (0x0040, 0));
    assert_eq!(os2.us_weight_class, 400);
    assert_eq!((os2.us_win_ascent, os2.us_win_descent), (2049, 423));
    assert_eq!(
        (
            os2.s_typo_ascender,
            os2.s_typo_descender,
            os2.s_typo_line_gap
        ),
        (1566, -423, 59)
    );
    assert_eq!(
        (os2.us_first_char_index, os2.us_last_char_index),
        (0x20, 0xFEFC)
    );
    assert_eq!((os2.sx_height, os2.s_cap_height), (1120, 1489));
    assert_eq!((os2.us_default_char, os2.us_break_char), (0, 0x20));
    assert_eq!(os2.x_avg_char_width, 910);

    let post = font.post().unwrap().unwrap();
    assert_eq!(post.version, 0x0002_0000);
    assert_eq!(post.italic_angle, 0);
    assert_eq!(
        (post.underline_position, post.underline_thickness),
        (-235, 130)
    );
    assert_eq!(post.is_fixed_pitch, 0);
}

/// The names Windows reads: the copy's are "F2K Tahoma", Wine's "Tahoma".
#[test]
fn names_read() {
    let utf16 = |data: &[u8], id| -> String {
        let font = Font::new(data).unwrap();
        let name = font.name().unwrap().unwrap();
        let record = name.windows_string(id).unwrap();
        assert!(record.is_utf16());
        char::decode_utf16(record.utf16())
            .map(Result::unwrap)
            .collect()
    };
    let (fixture, wine) = (fixture_font(), wine_font());
    assert_eq!(utf16(&fixture, name::NAME_FAMILY), "F2K Tahoma");
    assert_eq!(utf16(&fixture, name::NAME_FULL), "F2K Tahoma");
    assert_eq!(utf16(&fixture, name::NAME_SUBFAMILY), "Regular");
    assert_eq!(utf16(&fixture, name::NAME_POSTSCRIPT), "F2KTahoma");
    assert_eq!(utf16(&wine, name::NAME_FAMILY), "Tahoma");
    assert_eq!(utf16(&wine, name::NAME_POSTSCRIPT), "WineTahoma");
}

/// The capture's characters map to their glyphs through the Windows Unicode subtable (format 4),
/// and the Macintosh subtable (format 6) agrees on ASCII; U+4E00, which the font lacks, maps to
/// the missing glyph.
#[test]
fn cmap_maps_the_fixture_characters() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let cmap = font.cmap().unwrap();
    let unicode = cmap.unicode().unwrap().unwrap();
    assert_eq!(
        (unicode.platform_id, unicode.encoding_id, unicode.format()),
        (3, 1, 4)
    );
    let expected = [
        ('A', 36),
        ('g', 74),
        ('W', 58),
        ('i', 76),
        ('j', 77),
        ('y', 92),
        ('0', 19),
        ('@', 35),
        ('.', 17),
        (' ', 3),
        ('\u{E9}', 172),
        ('\u{416}', 322),
        ('\u{4E00}', 0),
    ];
    for (character, glyph) in expected {
        assert_eq!(unicode.glyph(character as u32), glyph, "{character:?}");
    }
    assert_eq!(unicode.glyph(0xFFFF), 0);
    assert_eq!(unicode.glyph(0x1_0000), 0);
    let mac = cmap.macintosh_roman().unwrap().unwrap();
    assert_eq!(mac.format(), 6);
    for code in 0x20..0x7F {
        assert_eq!(mac.glyph(code), unicode.glyph(code), "{code:#x}");
    }
}

/// The horizontal metrics: a full entry, and a glyph past the full entries, which takes the last
/// advance.
#[test]
fn horizontal_metrics_read() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let hmtx = font.hmtx().unwrap();
    let a = hmtx.metric(36).unwrap();
    assert_eq!((a.advance_width, a.left_side_bearing), (1229, -10));
    let last_full = hmtx.metric(980).unwrap();
    assert_eq!(
        hmtx.metric(987).unwrap().advance_width,
        last_full.advance_width
    );
    assert_eq!(hmtx.metric(988), None);
}

/// Every glyph's outline reads in font units, its points about its header's box; 'A' is
/// two contours, and 'é' resolves its two components.
#[test]
fn outlines_read() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let glyphs = font.glyphs().unwrap();
    let mut points = vec![Point::default(); 512];
    let mut ends = vec![0u16; 64];
    let mut outline = Outline::new(&mut points, &mut ends);
    let mut composites = 0;
    for glyph in 0..glyphs.len() {
        glyphs
            .outline(glyph, Scale::FontUnits, &mut outline)
            .unwrap();
        match glyphs.header(glyph).unwrap() {
            None => assert!(outline.is_empty(), "glyph {glyph}"),
            Some(header) => {
                composites += (header.number_of_contours < 0) as u32;
                let box_ = (
                    header.x_min as i32,
                    header.y_min as i32,
                    header.x_max as i32,
                    header.y_max as i32,
                );
                // The header's box is the curves' own extent: it holds every on-curve point,
                // and the control points' hull holds it; give or take a unit, as the font's tools
                // round some boxes (glyph 238's is a unit wider than its points both ways, and
                // composite 171's a unit taller than its components).
                let slack = 1;
                let (x0, y0, x1, y1) = outline.bounds().unwrap();
                assert!(
                    x0 <= box_.0 + slack
                        && y0 <= box_.1 + slack
                        && x1 >= box_.2 - slack
                        && y1 >= box_.3 - slack,
                    "glyph {glyph}"
                );
                for point in outline.points().iter().filter(|point| point.on_curve()) {
                    assert!(
                        (box_.0 - slack..=box_.2 + slack).contains(&point.x)
                            && (box_.1 - slack..=box_.3 + slack).contains(&point.y),
                        "glyph {glyph}"
                    );
                }
            }
        }
    }
    assert_eq!(composites, 535);

    glyphs.outline(36, Scale::FontUnits, &mut outline).unwrap();
    assert_eq!(outline.contour_ends().len(), 2);
    assert_eq!(outline.metrics_glyph(), 36);
    // 'é': 'e''s two contours and the acute's one.
    glyphs.outline(172, Scale::FontUnits, &mut outline).unwrap();
    assert_eq!(outline.contours().count(), 3);
    assert_eq!(
        outline.contours().map(<[Point]>::len).sum::<usize>(),
        outline.points().len()
    );
}

/// A buffer too small for a glyph is an error, and leaves the outline empty.
#[test]
fn a_small_buffer_is_refused() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let glyphs = font.glyphs().unwrap();
    let mut points = [Point::default(); 8];
    let mut ends = [0u16; 4];
    let mut outline = Outline::new(&mut points, &mut ends);
    assert_eq!(
        glyphs.outline(36, Scale::FontUnits, &mut outline),
        Err(Error::BufferTooSmall)
    );
    assert!(outline.is_empty() && outline.points().is_empty());
}

/// The per-size tables: no hdmx; gasp's three ranges; VDMX's 1:1 group.
#[test]
fn device_tables_read() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    assert!(font.hdmx().unwrap().is_none());
    let gasp = font.gasp().unwrap().unwrap();
    assert_eq!(gasp.behavior(8), Some(0));
    assert_eq!(gasp.behavior(11), Some(device::GASP_GRIDFIT));
    assert_eq!(
        gasp.behavior(24),
        Some(device::GASP_GRIDFIT | device::GASP_DOGRAY)
    );
    let vdmx = font.vdmx().unwrap().unwrap();
    let group = vdmx.group(1, 1).unwrap().unwrap();
    assert_eq!((group.start, group.end), (8, 255));
    let entry = |ppem| {
        let entry = group.entry(ppem).unwrap();
        (entry.y_max, entry.y_min)
    };
    assert_eq!(entry(11), (11, -2));
    assert_eq!(entry(13), (13, -3));
    assert_eq!(entry(16), (17, -4));
    assert_eq!(entry(24), (26, -6));
}

/// The strikes are the README's sizes, and the 11-ppem strike's glyphs are the bitmaps and
/// metrics Windows 2000's GetGlyphOutline gave at lfHeight -11 for every glyph the strike holds.
#[test]
fn strikes_match_the_capture() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let strikes = font.strikes().unwrap().unwrap();
    let ppems: Vec<u8> = strikes.all().map(|strike| strike.unwrap().ppem_x).collect();
    assert_eq!(ppems, [8, 9, 10, 11, 12, 13, 15, 16]);
    assert!(strikes.strike(14).unwrap().is_none());
    let strike = strikes.strike(11).unwrap().unwrap();
    assert_eq!(strike.flags, embedded::FLAG_HORIZONTAL_METRICS);
    assert_eq!((strike.hori.ascender, strike.hori.descender), (9, -2));
    let unicode = font.cmap().unwrap().unicode().unwrap().unwrap();
    let mut matched = 0;
    for captured in captured_glyphs().iter().filter(|glyph| glyph.height == -11) {
        let glyph = unicode.glyph(captured.character);
        let Some(image) = strike.glyph(glyph).unwrap() else {
            continue;
        };
        let m = image.metrics;
        assert_eq!(
            [
                m.width as i32,
                m.height as i32,
                m.bearing_x as i32,
                m.bearing_y as i32,
                m.advance as i32
            ],
            captured.metrics,
            "U+{:04X}",
            captured.character
        );
        for (y, row) in captured.rows.iter().enumerate() {
            let bits = u32::from_str_radix(row, 16).unwrap() << (32 - row.len() * 4);
            for x in 0..32 {
                assert_eq!(
                    image.pixel(x, y as u32),
                    bits & (0x8000_0000 >> x) != 0,
                    "U+{:04X} ({x}, {y})",
                    captured.character
                );
            }
        }
        matched += 1;
    }
    // Every captured glyph but the space and the missing glyph, which the strike leaves out.
    assert_eq!(matched, 11);
}

/// Reads everything a font file offers, through every reader: what a malformed file must survive.
/// Errors are fine; a panic is not.
pub(super) fn exercise(data: &[u8]) {
    let Ok(font) = Font::new(data) else {
        return;
    };
    for record in font.directory().records() {
        let _ = record.checksum_matches(data);
    }
    let _ = font.os2();
    let _ = font.post();
    if let Ok(Some(name)) = font.name() {
        for record in name.records() {
            let _ = record.utf16().count();
        }
        let _ = name.windows_string(name::NAME_FAMILY);
    }
    if let Ok(cmap) = font.cmap() {
        for subtable in [cmap.unicode(), cmap.macintosh_roman()] {
            if let Ok(Some(subtable)) = subtable {
                for code in (0..0x1_0100).step_by(13) {
                    let _ = subtable.glyph(code);
                }
            }
        }
    }
    if let Ok(hmtx) = font.hmtx() {
        for glyph in 0..=font.glyph_count() {
            let _ = hmtx.metric(glyph);
        }
    }
    if let Ok(Some(vdmx)) = font.vdmx() {
        if let Ok(Some(group)) = vdmx.group(1, 1) {
            let _ = group.entries().count();
        }
    }
    if let Ok(Some(gasp)) = font.gasp() {
        let _ = gasp.behavior(11);
    }
    if let Ok(Some(hdmx)) = font.hdmx() {
        let _ = hdmx.widths(11);
    }
    if let Ok(glyphs) = font.glyphs() {
        let mut points = vec![Point::default(); 256];
        let mut ends = vec![0u16; 32];
        let mut outline = Outline::new(&mut points, &mut ends);
        for glyph in 0..=glyphs.len() {
            let _ = glyphs.header(glyph);
            let _ = glyphs.outline(glyph, Scale::FontUnits, &mut outline);
            let _ = glyphs.outline(
                glyph,
                Scale::pixels(24, font.head.units_per_em),
                &mut outline,
            );
        }
    }
    if let Ok(Some(strikes)) = font.strikes() {
        for strike in strikes.all().flatten() {
            for glyph in 0..=font.glyph_count() {
                if let Ok(Some(image)) = strike.glyph(glyph) {
                    for y in 0..image.metrics.height as u32 {
                        for x in 0..image.metrics.width as u32 {
                            let _ = image.pixel(x, y);
                        }
                    }
                }
            }
        }
    }
}

/// A file cut short anywhere reads as errors: at every length through the directory, and at
/// lengths through the rest of the file.
#[test]
fn a_truncated_file_gives_errors() {
    let data = fixture_font();
    for length in (0..400).chain((400..data.len()).step_by(4093)) {
        exercise(&data[..length]);
        assert!(Font::new(&data[..length]).is_err() || length >= 400);
    }
    // Cut inside the glyph table, the directory's glyf record runs past the end.
    let glyf = Font::new(&data)
        .unwrap()
        .directory()
        .find(Tag::GLYF)
        .unwrap();
    let cut = &data[..glyf.offset as usize + 100];
    assert_eq!(Font::new(cut).err(), Some(Error::Truncated));
}

/// The file with the bytes at `at` replaced by `bytes`.
fn patched(data: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut patched = data.to_vec();
    patched[at..at + bytes.len()].copy_from_slice(bytes);
    patched
}

/// The offset of `tag`'s table in the file.
fn table_offset(data: &[u8], tag: Tag) -> usize {
    Font::new(data)
        .unwrap()
        .directory()
        .find(tag)
        .unwrap()
        .offset as usize
}

/// A composite that contains itself is refused as too deep; one that matches a point it lacks is
/// malformed.
#[test]
fn a_recursive_composite_is_refused() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let glyphs = font.glyphs().unwrap();
    let e_acute = glyphs.data(172).unwrap();
    assert!(i16::from_be_bytes([e_acute[0], e_acute[1]]) < 0);
    // The glyph's first component record: its flags, then the component's glyph index.
    let at = e_acute.as_ptr() as usize - data.as_ptr() as usize + 12;
    let recursive = patched(&data, at, &172u16.to_be_bytes());
    let font = Font::new(&recursive).unwrap();
    let mut points = vec![Point::default(); 4096];
    let mut ends = vec![0u16; 512];
    let mut outline = Outline::new(&mut points, &mut ends);
    assert_eq!(
        font.glyphs()
            .unwrap()
            .outline(172, Scale::FontUnits, &mut outline),
        Err(Error::CompositeTooDeep)
    );
    assert!(outline.is_empty());

    // The first component placed by matching points: the composite's point 0 (it has none yet)
    // to the component's.
    let flags = u16::from_be_bytes([data[at - 2], data[at - 1]]) & !0x0002;
    let matching = patched(&data, at - 2, &flags.to_be_bytes());
    let font = Font::new(&matching).unwrap();
    assert_eq!(
        font.glyphs()
            .unwrap()
            .outline(172, Scale::FontUnits, &mut outline),
        Err(Error::Malformed)
    );
}

/// Offsets past the end: a loca entry past the glyph table, a cmap subtable past the table, a
/// strike's index subtable past the location table.
#[test]
fn offsets_past_the_end_give_errors() {
    let data = fixture_font();
    let mut points = vec![Point::default(); 512];
    let mut ends = vec![0u16; 64];
    let mut outline = Outline::new(&mut points, &mut ends);

    // loca's short offsets are halved: glyph 36's end past the glyph table.
    let loca = table_offset(&data, Tag::LOCA);
    let bad = patched(&data, loca + 37 * 2, &0xFFFFu16.to_be_bytes());
    let font = Font::new(&bad).unwrap();
    assert_eq!(
        font.glyphs()
            .unwrap()
            .outline(36, Scale::FontUnits, &mut outline),
        Err(Error::Truncated)
    );
    // And glyph 37's start before its end: offsets that run backwards.
    assert_eq!(
        font.glyphs()
            .unwrap()
            .outline(37, Scale::FontUnits, &mut outline),
        Err(Error::Malformed)
    );

    // The cmap's third encoding record (Windows Unicode) pointing past the table.
    let cmap = table_offset(&data, Tag::CMAP);
    let bad = patched(&data, cmap + 4 + 2 * 8 + 4, &0x0001_0000u32.to_be_bytes());
    let font = Font::new(&bad).unwrap();
    assert_eq!(
        font.cmap().unwrap().subtable(3, 1).err(),
        Some(Error::Truncated)
    );

    // The 11-ppem strike's index subtable array past the location table.
    let eblc = table_offset(&data, Tag::EBLC);
    let bad = patched(&data, eblc + 8 + 3 * 48, &0x00FF_0000u32.to_be_bytes());
    let font = Font::new(&bad).unwrap();
    let strikes = font.strikes().unwrap().unwrap();
    assert_eq!(strikes.strike(11).err(), Some(Error::Truncated));
}

/// A small deterministic generator for the corruption test.
pub(super) struct XorShift(pub u32);

impl XorShift {
    pub fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

/// Bytes overwritten at random inside the tables the reader reads give errors or odd glyphs, never
/// a panic.
#[test]
fn corrupt_tables_never_panic() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let tables: Vec<_> = [
        Tag::HEAD,
        Tag::HHEA,
        Tag::MAXP,
        Tag::OS2,
        Tag::NAME,
        Tag::CMAP,
        Tag::HMTX,
        Tag::LOCA,
        Tag::GLYF,
        Tag::VDMX,
        Tag::GASP,
        Tag::EBLC,
        Tag::EBDT,
    ]
    .iter()
    .map(|&tag| font.directory().find(tag).unwrap())
    .collect();
    let mut random = XorShift(0x2468_ACE1);
    for _ in 0..60 {
        let mut corrupt = data.clone();
        let table = tables[random.next() as usize % tables.len()];
        for _ in 0..1 + random.next() % 16 {
            let at = table.offset as usize + random.next() as usize % table.length as usize;
            corrupt[at] = random.next() as u8;
        }
        exercise(&corrupt);
    }
}

/// The tag's text, for the messages.
#[test]
fn tags_print_as_text() {
    assert_eq!(format!("{:?}", Tag::OS2), "'OS/2'");
    assert_eq!(
        String::from_utf8(Tag::CMAP.bytes().to_vec()).unwrap(),
        "cmap"
    );
}
