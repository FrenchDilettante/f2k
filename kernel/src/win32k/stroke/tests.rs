//! The rasterizer against the shapes capture (tests/gdi32/shapes/output.txt): each figure the
//! fixture draws, drawn here into a 32-bit surface the fixture's size and printed as its rows of
//! letters, must read as the real machine's.

use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

use rtl::dib::BS_SOLID;
use rtl::gdi::*;

use super::*;
use crate::win32k::pen::Pen;
use crate::win32k::raster::{screen_rgb, FormatKey};
use crate::win32k::region::{polygon, rect_buf, Crossing, MOST_POINTS};

/// A 32-bit top-down DIB section's pixels, as the fixture's canvas.
struct Board {
    width: i32,
    height: i32,
    pixels: Vec<u32>,
}

impl Surface for Board {
    fn extent(&self) -> (i32, i32) {
        (self.width, self.height)
    }

    fn format(&self) -> FormatKey {
        FormatKey {
            bpp: 32,
            masks: [0x00FF_0000, 0x0000_FF00, 0x0000_00FF],
            table: 0,
        }
    }

    fn load(&mut self, x: i32, y: i32) -> u32 {
        self.pixels[(y * self.width + x) as usize]
    }

    fn store(&mut self, x: i32, y: i32, pixel: u32) {
        self.pixels[(y * self.width + x) as usize] = pixel;
    }

    fn rgb(&self, pixel: u32) -> u32 {
        pixel & 0x00FF_FFFF
    }

    fn pixel(&self, rgb: u32) -> u32 {
        rgb & 0x00FF_FFFF
    }
}

const WHITE: u32 = 0x00FF_FFFF;
const RED_BRUSH: u32 = 0x0000_00FF;

impl Board {
    fn new(width: i32, height: i32) -> Board {
        Board {
            width,
            height,
            pixels: std::vec![WHITE; (width * height) as usize],
        }
    }

    /// The rows as the fixture prints them.
    fn rows(&self) -> Vec<String> {
        (0..self.height)
            .map(|y| {
                (0..self.width)
                    .map(
                        |x| match self.pixels[(y * self.width + x) as usize] & 0xFF_FFFF {
                            0x00_0000 => '#',
                            0xFF_FFFF => '.',
                            0xFF_0000 => 'R',
                            0x00_FF00 => 'G',
                            0x00_00FF => 'B',
                            _ => '?',
                        },
                    )
                    .collect()
            })
            .collect()
    }

    /// `f` run with a painter over the whole board in R2_COPYPEN.
    fn paint(&mut self, f: impl FnOnce(&mut Painter<'_, Board>)) {
        let whole = Rect::new(0, 0, self.width, self.height);
        let mut painter = Painter {
            surface: self,
            clip: Clip::rect(&whole),
            mode: R2_COPYPEN,
        };
        f(&mut painter);
    }

    /// A line along `points` with `pen`.
    fn polyline(&mut self, pen: &Pen, points: &[(i32, i32)]) {
        let path: Vec<Fx> = points.iter().map(|&(x, y)| Fx::pixel(x, y)).collect();
        let mut kept = std::vec![Fx::default(); path.len()];
        let count = dedup(&path, false, &mut kept);
        let stroke = pen.stroke();
        let ink = screen_rgb(pen.color);
        self.paint(|painter| {
            assert!(draw(
                painter,
                &stroke,
                ink,
                None,
                &kept[..count],
                false,
                Interior::None,
                None
            ))
        });
    }

    /// A polygon of `points` with `pen` and the red brush (none: the null brush), under `winding`.
    fn polygon(&mut self, pen: &Pen, brush: bool, points: &[(i32, i32)], winding: bool) {
        let corners: Vec<Point> = points.iter().map(|&(x, y)| Point { x, y }).collect();
        let mut rects = rect_buf();
        let mut crossings = SmallBuf::<Crossing, 32>::new(Crossing::default(), MOST_POINTS);
        let counts = [corners.len() as u32];
        assert!(polygon(
            &corners,
            &counts,
            winding,
            &mut rects,
            &mut crossings
        ));
        let path: Vec<Fx> = points.iter().map(|&(x, y)| Fx::pixel(x, y)).collect();
        let mut kept = std::vec![Fx::default(); path.len()];
        let count = dedup(&path, true, &mut kept);
        let stroke = pen.stroke();
        let ink = screen_rgb(pen.color);
        let red = Ink::Pixel(screen_rgb(RED_BRUSH));
        self.paint(|painter| {
            draw(
                painter,
                &stroke,
                ink,
                None,
                &kept[..count],
                true,
                Interior::Rects(rects.as_slice()),
                brush.then_some(&red),
            );
        });
    }

    fn shape(&mut self, pen: &Pen, brush: bool, shape: Shape, rect: (i32, i32, i32, i32)) {
        let stroke = pen.stroke();
        let ink = screen_rgb(pen.color);
        let red = Ink::Pixel(screen_rgb(RED_BRUSH));
        self.paint(|painter| {
            assert!(draw_shape(
                painter,
                &stroke,
                ink,
                None,
                shape,
                rect,
                brush.then_some(&red)
            ))
        });
    }
}

/// The capture's letter grids, by the line printed before each (its title).
fn capture() -> HashMap<String, Vec<String>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/gdi32/shapes/output.txt"
    );
    let text = std::fs::read_to_string(path).expect("the shapes capture");
    let mut grids = HashMap::new();
    let mut title = String::new();
    let mut rows: Vec<String> = Vec::new();
    for line in text.lines() {
        let row = line
            .strip_prefix("  row ")
            .and_then(|rest| rest.split_once(": "))
            .map(|(_, row)| row)
            .filter(|row| row.chars().all(|c| "#.RGB?".contains(c)));
        match row {
            Some(row) => rows.push(row.into()),
            None => {
                if !rows.is_empty() {
                    grids.insert(title.clone(), core::mem::take(&mut rows));
                }
                title = line.into();
            }
        }
    }
    grids
}

fn expect(grids: &HashMap<String, Vec<String>>, title: &str, board: &Board) {
    let expected = grids
        .get(title)
        .unwrap_or_else(|| panic!("no grid {title:?}"));
    let got = board.rows();
    if &got != expected {
        let mut report = std::format!("{title}\n");
        for (got, expected) in got.iter().zip(expected) {
            let mark = if got == expected { "" } else { " <<" };
            report += &std::format!("  {got}  {expected}{mark}\n");
        }
        panic!("{report}");
    }
}

const BLACK: u32 = 0;

fn black_pen() -> Pen {
    Pen::stock(BLACK_PEN)
}

/// Each CreatePen style at width 1, and four at width 3 (the pens section).
#[test]
fn the_pens_section_draws_as_the_capture() {
    let grids = capture();
    let mut board = Board::new(32, 7);
    for style in 0..=6 {
        board.polyline(&Pen::create(style, 1, BLACK), &[(0, style), (32, style)]);
    }
    expect(
        &grids,
        "-- each style at width 1, black, from x 0 to 32 on row i",
        &board,
    );
    let mut board = Board::new(32, 17);
    for (index, style) in [PS_SOLID, PS_DASH, PS_DOT, PS_INSIDEFRAME]
        .into_iter()
        .enumerate()
    {
        let y = 2 + 4 * index as i32;
        board.polyline(&Pen::create(style as i32, 3, BLACK), &[(2, y), (30, y)]);
    }
    expect(
        &grids,
        "-- PS_SOLID, PS_DASH, PS_DOT and PS_INSIDEFRAME at width 3, black, from x 2 to 30 on rows 2, 6, 10 and 14",
        &board,
    );
}

/// ExtCreatePen's eight pens, and the width-5 corner under each join (the extpen section).
#[test]
fn the_extpen_section_draws_as_the_capture() {
    let grids = capture();
    let pens = [
        (PS_COSMETIC | PS_SOLID, 1, &[][..]),
        (PS_COSMETIC | PS_ALTERNATE, 1, &[]),
        (PS_COSMETIC | PS_USERSTYLE, 1, &[3, 1]),
        (PS_COSMETIC | PS_DOT, 1, &[]),
        (PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT, 3, &[]),
        (PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_SQUARE, 3, &[]),
        (PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND, 3, &[]),
        (PS_GEOMETRIC | PS_DASH | PS_ENDCAP_FLAT, 2, &[]),
    ];
    let mut board = Board::new(20, 40);
    for (index, (style, width, entries)) in pens.into_iter().enumerate() {
        let pen = Pen::extended(style, width, BS_SOLID, BLACK, 0, entries).unwrap();
        let y = 2 + 5 * index as i32;
        board.polyline(&pen, &[(4, y), (16, y)]);
    }
    expect(
        &grids,
        "-- each pen above, in order, from x 4 to 16 on rows 2, 7, 12, ...",
        &board,
    );
    let titles = [
        "ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_MITER, 5): non-NULL yes err=-",
        "ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_BEVEL, 5): non-NULL yes err=-",
        "ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_ROUND, 5): non-NULL yes err=-",
    ];
    // The corners' grids follow their Polyline lines, which all read alike: take them in order.
    let corners: Vec<Vec<String>> = {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/gdi32/shapes/output.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        titles
            .iter()
            .map(|title| {
                let after = &text[text.find(title).unwrap()..];
                after
                    .lines()
                    .skip(2)
                    .take(15)
                    .map(|line| line.split_once(": ").unwrap().1.into())
                    .collect()
            })
            .collect()
    };
    for (join, expected) in [PS_JOIN_MITER, PS_JOIN_BEVEL, PS_JOIN_ROUND]
        .into_iter()
        .zip(corners)
    {
        let style = PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | join;
        let pen = Pen::extended(style, 5, BS_SOLID, BLACK, 0, &[]).unwrap();
        let mut board = Board::new(15, 15);
        board.polyline(&pen, &[(2, 12), (7, 3), (12, 12)]);
        assert_eq!(board.rows(), expected, "join {join:#x}");
    }
}

/// MoveToEx and LineTo's lines, the diagonals both ways (the lines section).
#[test]
fn the_lines_section_draws_as_the_capture() {
    let grids = capture();
    let pen = black_pen();
    let mut board = Board::new(12, 8);
    board.polyline(&pen, &[(1, 1), (6, 1), (6, 5)]);
    board.polyline(&pen, &[(9, 3), (10, 3)]);
    board.polyline(&pen, &[(9, 6), (9, 6)]);
    board.polyline(&pen, &[(2, 7), (2, 3)]);
    expect(
        &grids,
        "MoveToEx(2, 7) LineTo(2, 3): rets 1 1 err=-",
        &board,
    );
    for (from, to) in [
        ((0, 0), (9, 4)),
        ((9, 4), (0, 0)),
        ((0, 0), (3, 9)),
        ((3, 9), (0, 0)),
        ((6, 6), (1, 1)),
        ((1, 1), (6, 6)),
    ] {
        let size = match from.0.max(to.0) {
            9 => (10, 5),
            3 => (5, 10),
            _ => (7, 7),
        };
        let mut board = Board::new(size.0, size.1);
        board.polyline(&pen, &[from, to]);
        let title = std::format!(
            "MoveToEx({}, {}) LineTo({}, {}): rets 1 1 err=-",
            from.0,
            from.1,
            to.0,
            to.1
        );
        expect(&grids, &title, &board);
    }
}

/// Polyline, and Polygon under both fill modes and with the null pen and brush (the poly
/// section).
#[test]
fn the_poly_section_draws_as_the_capture() {
    let grids = capture();
    let pen = black_pen();
    let mut board = Board::new(11, 10);
    board.polyline(&pen, &[(1, 8), (3, 1), (6, 8), (9, 1)]);
    expect(
        &grids,
        "Polyline(1,8 3,1 6,8 9,1): ret=1 err=- the current position still 0,9: yes",
        &board,
    );
    let star = [(6, 0), (10, 11), (0, 4), (12, 4), (2, 11)];
    for (winding, title) in [
        (
            false,
            "Polygon(6,0 10,11 0,4 12,4 2,11) under ALTERNATE: ret=1 err=-",
        ),
        (true, "Polygon(the same) under WINDING: ret=1 err=-"),
    ] {
        let mut board = Board::new(13, 12);
        board.polygon(&pen, true, &star, winding);
        expect(&grids, title, &board);
    }
    let triangle = [(1, 1), (10, 1), (1, 8)];
    let mut board = Board::new(13, 12);
    board.polygon(&Pen::stock(NULL_PEN), true, &triangle, false);
    expect(
        &grids,
        "Polygon(1,1 10,1 1,8) with the null pen: ret=1 err=-",
        &board,
    );
    let mut board = Board::new(13, 12);
    board.polygon(&pen, false, &triangle, false);
    expect(
        &grids,
        "Polygon(the same) with the null brush: ret=1 err=-",
        &board,
    );
    let mut board = Board::new(13, 12);
    board.polygon(&pen, true, &triangle[..2], false);
    expect(
        &grids,
        "Polygon of two points (1,1 10,1): ret=1 err=-",
        &board,
    );
}

/// Rectangle, Ellipse and RoundRect with the black pen, the null pen and the null brush, and with
/// width-3 PS_SOLID and PS_INSIDEFRAME pens (the shapes section). The null pen's ellipse and
/// rounded rectangle are left out: F2K's fill of them is not yet Windows 2000's (see
/// [`draw_shape`]).
#[test]
fn the_shapes_section_draws_as_the_capture() {
    let grids = capture();
    let black = black_pen();
    let null = Pen::stock(NULL_PEN);
    let solid3 = Pen::create(PS_SOLID as i32, 3, BLACK);
    let frame3 = Pen::create(PS_INSIDEFRAME as i32, 3, BLACK);
    use Shape::*;
    let cases: [(&str, Shape, (i32, i32, i32, i32), &Pen, bool); 17] = [
        (
            "Rectangle(1, 1, 8, 6): ret=1 err=-",
            Rectangle,
            (1, 1, 8, 6),
            &black,
            true,
        ),
        (
            "Rectangle(8, 6, 1, 1), reversed: ret=1 err=-",
            Rectangle,
            (8, 6, 1, 1),
            &black,
            true,
        ),
        (
            "Rectangle(1, 1, 8, 6) with the null pen: ret=1 err=-",
            Rectangle,
            (1, 1, 8, 6),
            &null,
            true,
        ),
        (
            "Rectangle(1, 1, 8, 6) with the null brush: ret=1 err=-",
            Rectangle,
            (1, 1, 8, 6),
            &black,
            false,
        ),
        (
            "Rectangle(1, 1, 2, 2), 1x1: ret=1 err=-",
            Rectangle,
            (1, 1, 2, 2),
            &black,
            true,
        ),
        (
            "Rectangle(1, 1, 3, 3), 2x2: ret=1 err=-",
            Rectangle,
            (1, 1, 3, 3),
            &black,
            true,
        ),
        (
            "Rectangle(3, 1, 3, 6), 0 wide: ret=1 err=-",
            Rectangle,
            (3, 1, 3, 6),
            &black,
            true,
        ),
        (
            "Ellipse(1, 1, 13, 9): ret=1 err=-",
            Ellipse,
            (1, 1, 13, 9),
            &black,
            true,
        ),
        (
            "Ellipse(1, 1, 5, 5), small: ret=1 err=-",
            Ellipse,
            (1, 1, 5, 5),
            &black,
            true,
        ),
        (
            "Ellipse(1, 1, 13, 9) with the null brush: ret=1 err=-",
            Ellipse,
            (1, 1, 13, 9),
            &black,
            false,
        ),
        (
            "RoundRect(1, 1, 13, 9, 4, 4): ret=1 err=-",
            RoundRect(4, 4),
            (1, 1, 13, 9),
            &black,
            true,
        ),
        (
            "RoundRect(1, 1, 13, 9, 0, 0): ret=1 err=-",
            RoundRect(0, 0),
            (1, 1, 13, 9),
            &black,
            true,
        ),
        (
            "RoundRect(1, 1, 13, 9, 20, 20), corners larger than itself: ret=1 err=-",
            RoundRect(20, 20),
            (1, 1, 13, 9),
            &black,
            true,
        ),
        (
            "Rectangle(2, 2, 12, 8) with the PS_SOLID width-3 pen: ret=1 err=-",
            Rectangle,
            (2, 2, 12, 8),
            &solid3,
            true,
        ),
        (
            "Rectangle(2, 2, 12, 8) with the PS_INSIDEFRAME width-3 pen: ret=1 err=-",
            Rectangle,
            (2, 2, 12, 8),
            &frame3,
            true,
        ),
        (
            "Ellipse(2, 2, 12, 8) with the PS_SOLID width-3 pen: ret=1 err=-",
            Ellipse,
            (2, 2, 12, 8),
            &solid3,
            true,
        ),
        (
            "Ellipse(2, 2, 12, 8) with the PS_INSIDEFRAME width-3 pen: ret=1 err=-",
            Ellipse,
            (2, 2, 12, 8),
            &frame3,
            true,
        ),
    ];
    for (title, shape, rect, pen, brush) in cases {
        let mut board = Board::new(14, 10);
        board.shape(pen, brush, shape, rect);
        expect(&grids, title, &board);
    }
}

/// The mix modes on a Rectangle: a green pen and a blue brush under R2_XORPEN over red and white,
/// each pixel touched once (the rop2 section's last figure).
#[test]
fn a_rectangle_under_xor_touches_each_pixel_once() {
    let mut board = Board::new(8, 3);
    for (index, pixel) in board.pixels.iter_mut().enumerate() {
        *pixel = if index % 8 < 4 { 0x00FF_0000 } else { WHITE };
    }
    let green = Pen::create(PS_SOLID as i32, 1, 0x0000_FF00);
    let whole = Rect::new(0, 0, 8, 3);
    let mut painter = Painter {
        surface: &mut board,
        clip: Clip::rect(&whole),
        mode: R2_XORPEN,
    };
    let blue = Ink::Pixel(screen_rgb(0x00FF_0000));
    draw_shape(
        &mut painter,
        &green.stroke(),
        screen_rgb(green.color),
        None,
        Shape::Rectangle,
        (0, 0, 8, 3),
        Some(&blue),
    );
    let (yellow, magenta) = (0x00FF_FF00, 0x00FF_00FF);
    let rows = [
        [
            yellow, yellow, yellow, yellow, magenta, magenta, magenta, magenta,
        ],
        [
            yellow, magenta, magenta, magenta, yellow, yellow, yellow, magenta,
        ],
        [
            yellow, yellow, yellow, yellow, magenta, magenta, magenta, magenta,
        ],
    ];
    for (y, row) in rows.iter().enumerate() {
        assert_eq!(&board.pixels[8 * y..8 * y + 8], row, "row {y}");
    }
}

/// Drawing is clipped to the clipping region: a line across two rectangles' gap lights nothing in
/// it.
#[test]
fn drawing_is_clipped() {
    let mut board = Board::new(10, 3);
    let rects = [Rect::new(0, 0, 3, 3), Rect::new(6, 0, 10, 3)];
    let mut painter = Painter {
        surface: &mut board,
        clip: Clip::new(&rects, Rect::new(0, 0, 10, 3)),
        mode: R2_COPYPEN,
    };
    let path = [Fx::pixel(0, 1), Fx::pixel(10, 1)];
    draw(
        &mut painter,
        &black_pen().stroke(),
        0,
        None,
        &path,
        false,
        Interior::None,
        None,
    );
    assert_eq!(board.rows()[1], "###...####");
}
