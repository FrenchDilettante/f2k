//! GetGlyphOutline's answers and the scan converter against Windows 2000's (the ttfont capture's
//! `glyphs` and `widths` sections), on the fixtures' font read from the repository; then shapes
//! made to show dropout control, and malformed fonts.

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use super::glyf::{Outline, Point, ON_CURVE};
use super::glyph::{self, Options, Rendered, Source, Workspace};
use super::raster::{self, Crossing, Dropout, Target};
use super::tests::{capture_section, captured_glyphs, fixture_font, CapturedGlyph, XorShift};
use super::*;

/// The pixels where the unhinted rasteriser and Windows 2000 part: (lfHeight, character, x, y in
/// the black box), each a pixel Windows leaves off. In both, the pixel's centre lies inside the
/// outline the font's points draw, by less than a 200th of a pixel: Windows' own arithmetic puts
/// it on the other side.
const MISMATCHES: [(i32, u32, usize, usize); 2] = [
    // '0''s counter, its right side: the curve crosses the row at x 607.8 (26.6), left of the
    // centre at 608.
    (-24, 0x30, 8, 5),
    // '@''s outer contour, its lower left: the curve crosses the row at x 287.97, left of the
    // centre at 288.
    (-24, 0x40, 2, 15),
];

/// Renders `glyph` into a fresh buffer, with a workspace enough for any of the font's glyphs: the
/// rendering asked for its size first, as GetGlyphOutline's callers do.
fn render(font: &Font, glyph: u16, options: &Options) -> Result<(Rendered, Vec<u8>), Error> {
    let mut points = vec![Point::default(); 512];
    let mut ends = vec![0u16; 64];
    let mut crossings = vec![Crossing::default(); 256];
    let mut workspace = Workspace {
        points: &mut points,
        contour_ends: &mut ends,
        crossings: &mut crossings,
    };
    let sized = glyph::render(font, glyph, options, &mut workspace, &mut [])?;
    let mut bits = vec![0xEE; sized.size.max(1)];
    let rendered = glyph::render(font, glyph, options, &mut workspace, &mut bits)?;
    assert_eq!(sized, rendered);
    bits.truncate(rendered.size);
    Ok((rendered, bits))
}

/// A bitmap's rows as the capture prints them: the bytes that cover the black box's width, in
/// hex.
fn rows(width: u32, bits: &[u8]) -> Vec<String> {
    let stride = glyph::stride(width);
    bits.chunks(stride.max(1))
        .map(|row| {
            row[..(width as usize).div_ceil(8)]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect()
        })
        .collect()
}

/// The pixels (x, y) where two bitmaps, as rows of hex, differ.
fn differences(ours: &[String], theirs: &[String]) -> Vec<(usize, usize)> {
    let mut differences = Vec::new();
    for (y, (ours, theirs)) in ours.iter().zip(theirs).enumerate() {
        let bits =
            u32::from_str_radix(ours, 16).unwrap() ^ u32::from_str_radix(theirs, 16).unwrap();
        let width = ours.len() * 4;
        for x in 0..width {
            if bits & (1 << (width - 1 - x)) != 0 {
                differences.push((x, y));
            }
        }
    }
    differences
}

/// The glyph a captured character maps to.
fn glyph_of(font: &Font, character: u32) -> u16 {
    font.cmap()
        .unwrap()
        .unicode()
        .unwrap()
        .unwrap()
        .glyph(character)
}

/// The metrics as the capture lists them.
fn listed(rendered: &Rendered) -> [i32; 5] {
    let metrics = rendered.metrics;
    [
        metrics.black_box_x as i32,
        metrics.black_box_y as i32,
        metrics.origin_x,
        metrics.origin_y,
        metrics.cell_inc_x as i32,
    ]
}

/// The capture's text metrics at each height (weight 400) are the font's tables scaled to its
/// ppem and rounded to whole pixels: the ascent and descent OS/2's Windows pair (not VDMX's
/// entries, which give 17 and 4 at 16 ppem where Windows answered 16 and 3), the internal leading
/// what the cell holds beyond the em, the average width OS/2's, the widest the head box's width.
#[test]
fn text_metrics_follow_the_tables() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let os2 = font.os2().unwrap().unwrap();
    let mut height = None;
    let mut checked = 0;
    for line in capture_section("metrics") {
        if let Some(rest) = line.strip_prefix("-- lfHeight ") {
            let mut fields = rest.split(", lfWeight ");
            let (value, weight) = (fields.next().unwrap(), fields.next().unwrap());
            height = (weight == "400").then(|| value.parse::<i32>().unwrap());
            continue;
        }
        let Some(height) = height.filter(|_| line.starts_with("  tmHeight=")) else {
            continue;
        };
        let field = |name: &str| -> i32 {
            let at = line.find(&format!(" {name}=")).unwrap() + name.len() + 2;
            line[at..].split(' ').next().unwrap().parse().unwrap()
        };
        let ppem = glyph::ppem_for_height(&font, height).unwrap();
        let scale = scale::Scale::pixels(ppem, font.head.units_per_em);
        let pixels = |units: i32| scale::round_pixel(scale.apply(units));
        let ascent = pixels(os2.us_win_ascent as i32);
        let descent = pixels(os2.us_win_descent as i32);
        let name = format!("lfHeight {height}");
        assert_eq!(field("tmAscent"), ascent, "{name}");
        assert_eq!(field("tmDescent"), descent, "{name}");
        assert_eq!(field("tmHeight"), ascent + descent, "{name}");
        assert_eq!(
            field("tmInternalLeading"),
            ascent + descent - ppem as i32,
            "{name}"
        );
        assert_eq!(
            field("tmAveCharWidth"),
            pixels(os2.x_avg_char_width as i32),
            "{name}"
        );
        let widest = font.head.x_max as i32 - font.head.x_min as i32;
        assert_eq!(field("tmMaxCharWidth"), pixels(widest), "{name}");
        checked += 1;
    }
    // Five heights, GetTextMetricsW's line and GetTextMetricsA's.
    assert_eq!(checked, 10);
}

/// The LOGFONT heights map to the ppems the capture's metrics show: -11 and -24 are em heights;
/// +16 is a cell height, whose metrics in the capture are -13's.
#[test]
fn heights_make_ppems() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    for (height, ppem) in [(-11, 11), (-13, 13), (-16, 16), (-24, 24), (16, 13), (0, 0)] {
        assert_eq!(
            glyph::ppem_for_height(&font, height).unwrap(),
            ppem,
            "{height}"
        );
    }
}

/// Every glyph of the capture's `glyphs` section: its GLYPHMETRICS and its bitmap's size exactly,
/// its rows exactly but for the known pixels (each of which must still differ). At lfHeight -11
/// the strike answers, but for the space and the missing glyph, which it leaves out; at -24, which
/// no strike has, the outline does.
#[test]
fn glyphs_match_the_capture() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let captured = captured_glyphs();
    assert_eq!(captured.len(), 26);
    for glyph in &captured {
        let CapturedGlyph {
            height, character, ..
        } = *glyph;
        let ppem = glyph::ppem_for_height(&font, height).unwrap();
        let (rendered, bits) =
            render(&font, glyph_of(&font, character), &Options::new(ppem)).unwrap();
        let name = format!("lfHeight {height} U+{character:04X}");
        let from_strike = height == -11 && character != 0x20 && character != 0x4E00;
        let source = if from_strike {
            Source::Strike
        } else {
            Source::Outline
        };
        assert_eq!(rendered.source, source, "{name}");
        assert_eq!(listed(&rendered), glyph.metrics, "{name}");
        assert_eq!(rendered.size as u32, glyph.size, "{name}");
        let ours = rows(rendered.metrics.black_box_x, &bits);
        assert_eq!(ours.len(), glyph.rows.len(), "{name}");
        let expected: Vec<(usize, usize)> = MISMATCHES
            .iter()
            .filter(|known| known.0 == height && known.1 == character)
            .map(|known| (known.2, known.3))
            .collect();
        assert_eq!(differences(&ours, &glyph.rows), expected, "{name}");
    }
}

/// The capture's -11 glyphs are the strike's: the same glyphs from their outlines differ from what
/// Windows 2000 answered.
#[test]
fn the_strike_answers_at_its_size() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let outlines = Options {
        use_strikes: false,
        ..Options::new(11)
    };
    let mut differing = 0;
    for glyph in captured_glyphs().iter().filter(|glyph| glyph.height == -11) {
        let (rendered, bits) = render(&font, glyph_of(&font, glyph.character), &outlines).unwrap();
        assert_eq!(rendered.source, Source::Outline);
        if listed(&rendered) != glyph.metrics
            || rows(rendered.metrics.black_box_x, &bits) != glyph.rows
        {
            differing += 1;
        }
    }
    assert!(differing >= 8, "{differing}");
}

/// GetCharWidth32W's widths in the capture's `widths` section are the glyphs' cell increments, at
/// the strikes' sizes and at 24 ppem's outlines alike.
#[test]
fn cell_increments_match_the_widths() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let mut height = None;
    let mut checked = 0;
    let mut wide = false;
    for line in capture_section("widths") {
        if let Some(rest) = line.strip_prefix("-- lfHeight ") {
            let mut fields = rest.split(", lfWeight ");
            let (value, weight) = (fields.next().unwrap(), fields.next().unwrap());
            height = (weight == "400").then(|| value.parse::<i32>().unwrap());
        } else if line.starts_with("GetCharWidth32") {
            wide = line.starts_with("GetCharWidth32W");
        } else if let (Some(height), true, Some(row)) = (height, wide, line.strip_prefix("  0x")) {
            if !line.contains(": ") || line.split(' ').count() < 8 {
                continue;
            }
            let (first, widths) = row.split_once(": ").unwrap();
            let first = u32::from_str_radix(first, 16).unwrap();
            let ppem = glyph::ppem_for_height(&font, height).unwrap();
            for (index, width) in widths.split(' ').enumerate() {
                let character = first + index as u32;
                let (rendered, _) =
                    render(&font, glyph_of(&font, character), &Options::new(ppem)).unwrap();
                assert_eq!(
                    rendered.metrics.cell_inc_x as i32,
                    width.parse::<i32>().unwrap(),
                    "lfHeight {height} {character:#x}"
                );
                checked += 1;
            }
        }
    }
    // 0x20 to 0x7E at five heights.
    assert_eq!(checked, 95 * 5);
}

/// The missing glyph at 11 ppem: its top stroke, thinner than a pixel and between two rows'
/// centres, vanishes without dropout control (as Windows 2000 draws it, this font having no
/// control-value program) and comes back with it, on the row below the stroke's middle.
#[test]
fn dropout_control_keeps_a_thin_stroke() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let draw = |dropout| {
        let options = Options {
            dropout,
            ..Options::new(11)
        };
        let (rendered, bits) = render(&font, 0, &options).unwrap();
        rows(rendered.metrics.black_box_x, &bits)
    };
    let missing = captured_glyphs()
        .into_iter()
        .find(|glyph| glyph.height == -11 && glyph.character == 0x4E00)
        .unwrap();
    assert_eq!(draw(None), missing.rows);
    assert_eq!(draw(Some(Dropout::Off)), missing.rows);
    for dropout in [Dropout::Simple, Dropout::Smart] {
        let rows = draw(Some(dropout));
        assert_eq!(rows[0], "FF80", "{dropout:?}");
        assert_eq!(rows[1..], missing.rows[1..], "{dropout:?}");
    }
}

/// A rectangle's contour, in 26.6 units.
fn rectangle(left: i32, bottom: i32, right: i32, top: i32) -> [Point; 4] {
    let corner = |x, y| Point {
        x,
        y,
        flags: ON_CURVE,
    };
    [
        corner(left, bottom),
        corner(left, top),
        corner(right, top),
        corner(right, bottom),
    ]
}

/// Scan-converts `contours` into a bitmap of `width` by `height` pixels from the origin up, as
/// rows from the top in bits.
fn scan(contours: &[&[Point]], width: u32, height: u32, dropout: Dropout) -> Vec<String> {
    let mut points = [Point::default(); 32];
    let mut ends = [0u16; 8];
    let mut outline = Outline::new(&mut points, &mut ends);
    for contour in contours {
        outline.push_contour(contour).unwrap();
    }
    let stride = glyph::stride(width);
    let mut bits = vec![0u8; stride * height as usize];
    let mut target = Target {
        bits: &mut bits,
        stride,
        width,
        height,
        left: 0,
        top: height as i32,
    };
    let mut crossings = [Crossing::default(); 16];
    raster::fill(&outline, &mut target, dropout, &mut crossings).unwrap();
    bits.chunks(stride)
        .map(|row| {
            (0..width as usize)
                .map(|x| {
                    if row[x / 8] & (0x80 >> (x % 8)) != 0 {
                        '#'
                    } else {
                        '.'
                    }
                })
                .collect()
        })
        .collect()
}

/// A bar between two rows' centres, from y 0.8 to 1.4 pixels: no pixel without dropout control;
/// the lower row under rule 3; the upper row, nearer its middle (1.1), under rule 5.
#[test]
fn dropout_rules_choose_their_pixel() {
    let bar = rectangle(13, 51, 243, 90);
    assert_eq!(scan(&[&bar], 4, 2, Dropout::Off), ["....", "...."]);
    assert_eq!(scan(&[&bar], 4, 2, Dropout::Simple), ["....", "####"]);
    assert_eq!(scan(&[&bar], 4, 2, Dropout::Smart), ["####", "...."]);
    // A stem between two columns' centres, from x 0.8 to 1.4: the left column, or the right.
    let stem = rectangle(51, 13, 90, 243);
    assert_eq!(
        scan(&[&stem], 2, 4, Dropout::Simple),
        ["#.", "#.", "#.", "#."]
    );
    assert_eq!(
        scan(&[&stem], 2, 4, Dropout::Smart),
        [".#", ".#", ".#", ".#"]
    );
}

/// Rules 1 and 2: a pixel is on when its centre is inside, or on an edge (here the square's
/// bottom-left corner is the first pixel's centre, and its top and right edges pass through the
/// third row's and column's centres). Under the nonzero winding rule a hole wound against its
/// contour is left out, and a square wound with it fills the part of the hole it covers.
#[test]
fn centres_inside_or_on_the_outline_are_on() {
    let square = rectangle(32, 32, 160, 160);
    assert_eq!(
        scan(&[&square], 4, 4, Dropout::Off),
        ["....", "###.", "###.", "###."]
    );
    // A square with a hole wound the other way, and a square over the hole's lower right wound
    // with the outer one (winding 1 over the hole, 2 beside it).
    let outer = rectangle(0, 0, 256, 256);
    let mut hole = rectangle(64, 64, 192, 192);
    hole.reverse();
    assert_eq!(
        scan(&[&outer, &hole], 4, 4, Dropout::Off),
        ["####", "#..#", "#..#", "####"]
    );
    let overlap = rectangle(128, 0, 256, 128);
    assert_eq!(
        scan(&[&outer, &hole, &overlap], 4, 4, Dropout::Off),
        ["####", "#..#", "#.##", "####"]
    );
}

/// A buffer too small for the bitmap, an outline's points or a scan line's crossings is an error.
#[test]
fn small_buffers_are_refused() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let (mut points, mut ends, mut crossings) = (
        vec![Point::default(); 512],
        vec![0u16; 64],
        vec![Crossing::default(); 256],
    );
    let options = Options::new(24);
    let at_ = glyph_of(&font, 0x40);
    let mut workspace = Workspace {
        points: &mut points,
        contour_ends: &mut ends,
        crossings: &mut crossings,
    };
    let mut small = [0u8; 8];
    assert_eq!(
        glyph::render(&font, at_, &options, &mut workspace, &mut small),
        Err(Error::BufferTooSmall)
    );
    let mut bits = [0u8; 84];
    let mut few_crossings = [Crossing::default(); 2];
    let mut workspace = Workspace {
        points: &mut points,
        contour_ends: &mut ends,
        crossings: &mut few_crossings,
    };
    assert_eq!(
        glyph::render(&font, at_, &options, &mut workspace, &mut bits),
        Err(Error::BufferTooSmall)
    );
    let mut few_points = [Point::default(); 16];
    let mut workspace = Workspace {
        points: &mut few_points,
        contour_ends: &mut ends,
        crossings: &mut crossings,
    };
    assert_eq!(
        glyph::render(&font, at_, &options, &mut workspace, &mut bits),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        glyph::render(
            &font,
            font.glyph_count(),
            &options,
            &mut workspace,
            &mut bits
        ),
        Err(Error::BadGlyph)
    );
}

/// Every glyph renders at the sizes from 1 to 20 ppem and at a few larger ones, from its strike
/// and from its outline, into exactly its black box's rows.
#[test]
fn every_glyph_renders() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    for ppem in (1..=20).chain([24, 32, 100]) {
        for use_strikes in [true, false] {
            let options = Options {
                use_strikes,
                ..Options::new(ppem)
            };
            for glyph in 0..font.glyph_count() {
                let (rendered, bits) = render(&font, glyph, &options).unwrap();
                let metrics = rendered.metrics;
                assert_eq!(
                    bits.len(),
                    glyph::stride(metrics.black_box_x)
                        * metrics.black_box_y as usize
                        * (rendered.size != 0) as usize
                );
            }
        }
    }
}

/// Corrupt fonts render as errors or odd glyphs, never a panic.
#[test]
fn corrupt_fonts_never_panic() {
    let data = fixture_font();
    let font = Font::new(&data).unwrap();
    let tables: Vec<_> = [
        Tag::GLYF,
        Tag::LOCA,
        Tag::EBLC,
        Tag::EBDT,
        Tag::HMTX,
        Tag::OS2,
    ]
    .iter()
    .map(|&tag| font.directory().find(tag).unwrap())
    .collect();
    let mut random = XorShift(0x1357_9BDF);
    for _ in 0..12 {
        let mut corrupt = data.clone();
        let table = tables[random.next() as usize % tables.len()];
        for _ in 0..1 + random.next() % 32 {
            let at = table.offset as usize + random.next() as usize % table.length as usize;
            corrupt[at] = random.next() as u8;
        }
        let Ok(font) = Font::new(&corrupt) else {
            continue;
        };
        for ppem in [11, 24] {
            let _ = glyph::ppem_for_height(&font, ppem);
            for glyph in 0..font.glyph_count() {
                let _ = render(&font, glyph, &Options::new(ppem as u16));
            }
        }
    }
}
