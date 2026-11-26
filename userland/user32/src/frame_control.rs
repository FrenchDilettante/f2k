//! DrawFrameControl: the caption buttons (DFC_CAPTION), which the non-client area draws its own
//! with ([`draw_caption_in`]).
//!
//! A caption button is a raised edge, soft (COLOR_3DHILIGHT outside above and to the left,
//! COLOR_3DLIGHT inside it; COLOR_3DDKSHADOW and COLOR_3DSHADOW below and to the right), its middle
//! COLOR_3DFACE, and a glyph in COLOR_BTNTEXT. Pushed (DFCS_PUSHED), the edge is sunken, as soft
//! (COLOR_3DDKSHADOW outside above and to the left, COLOR_3DSHADOW inside it), and the glyph moves
//! a pixel down and to the right. Inactive (DFCS_INACTIVE), the glyph is grayed: drawn in
//! COLOR_3DHILIGHT a pixel down and to the right, then in COLOR_3DSHADOW over that.
//!
//! Windows 2000 draws the glyphs from Marlett (close `r`, minimize `0`, maximize `1`, restore `2`,
//! help `s`); F2K draws them as the pixels Windows 2000's Marlett gives in a caption button of the
//! standard scheme's (SM_CXSIZE - 2 by SM_CYSIZE - 4: 16 by 14), each at its own place in the
//! button ([`Shape`]). The close, minimize and maximize glyphs, the edge and the grayed glyph are
//! measured off a capture of calc.exe on the real machine (its maximize button disabled); the
//! restore and help glyphs, and the pushed edge, are Windows 2000's known shapes, not yet
//! captured. In a rectangle of another size, the glyph keeps its place relative to the standard
//! button centered in it, clipped to the rectangle (Windows 2000 scales Marlett to the rectangle
//! instead: not done yet).
//!
//! The other kinds (DFC_BUTTON, DFC_MENU, DFC_SCROLL, DFC_POPUPMENU) go to the stub routine.
//! DFCS_FLAT and DFCS_MONO draw the edge as DrawEdge's BF_FLAT and BF_MONO do (as 3D);
//! DFCS_ADJUSTRECT leaves the rectangle as it is.

use rtl::display::{COLOR_3DHILIGHT, COLOR_3DSHADOW, COLOR_BTNTEXT};
use rtl::edge::In;
use rtl::gdi::Rect;

use crate::draw::{self, BF_FLAT, BF_MIDDLE, BF_MONO, BF_RECT, BF_SOFT, EDGE_RAISED, EDGE_SUNKEN};

/// DrawFrameControl's kinds (winuser.h's DFC_*).
pub const DFC_CAPTION: u32 = 1;
pub const DFC_MENU: u32 = 2;
pub const DFC_SCROLL: u32 = 3;
pub const DFC_BUTTON: u32 = 4;
pub const DFC_POPUPMENU: u32 = 5;

/// DFC_CAPTION's parts (winuser.h's DFCS_CAPTION*): the state's low byte.
pub const DFCS_CAPTIONCLOSE: u32 = 0x0000;
pub const DFCS_CAPTIONMIN: u32 = 0x0001;
pub const DFCS_CAPTIONMAX: u32 = 0x0002;
pub const DFCS_CAPTIONRESTORE: u32 = 0x0003;
pub const DFCS_CAPTIONHELP: u32 = 0x0004;

/// DrawFrameControl's states (winuser.h's DFCS_*).
pub const DFCS_INACTIVE: u32 = 0x0100;
pub const DFCS_PUSHED: u32 = 0x0200;
pub const DFCS_FLAT: u32 = 0x4000;
pub const DFCS_MONO: u32 = 0x8000;

/// The standard caption button the glyphs' places are measured in: SM_CXSIZE - 2 by SM_CYSIZE - 4.
pub const BUTTON_WIDTH: i32 = rtl::nonclient::SIZE - 2;
pub const BUTTON_HEIGHT: i32 = rtl::nonclient::SIZE - 4;

/// A glyph's pixels and their place: `#` for ink, in rows of equal width, the first row's first
/// pixel `at` from the standard button's top left.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub at: (i32, i32),
    pub rows: &'static [&'static [u8]],
}

/// Marlett's `r`: two diagonal strokes two pixels wide, 8 by 7 (measured).
const CLOSE: Shape = Shape {
    at: (4, 3),
    rows: &[
        b"##....##",
        b".##..##.",
        b"..####..",
        b"...##...",
        b"..####..",
        b".##..##.",
        b"##....##",
    ],
};

/// Marlett's `0`: a bar 6 by 2 near the button's bottom (measured).
const MINIMIZE: Shape = Shape {
    at: (4, 9),
    rows: &[b"######", b"######"],
};

/// Marlett's `1`: a box 9 by 9, its top two pixels thick (measured, grayed).
const MAXIMIZE: Shape = Shape {
    at: (3, 2),
    rows: &[
        b"#########",
        b"#########",
        b"#.......#",
        b"#.......#",
        b"#.......#",
        b"#.......#",
        b"#.......#",
        b"#.......#",
        b"#########",
    ],
};

/// Marlett's `2`: two boxes 6 by 6, their tops two pixels thick, the front one down and to the
/// left (Windows 2000's known shape, at the maximize box's place: not captured).
const RESTORE: Shape = Shape {
    at: (3, 2),
    rows: &[
        b"..######",
        b"..######",
        b"..#....#",
        b"######.#",
        b"######.#",
        b"#....###",
        b"#....#..",
        b"#....#..",
        b"######..",
    ],
};

/// Marlett's `s`: a question mark 6 by 9 (Windows 2000's known shape, centered as the close
/// glyph is: not captured).
const HELP: Shape = Shape {
    at: (5, 2),
    rows: &[
        b".####.", b"##..##", b"##..##", b"...##.", b"..##..", b"..##..", b"......", b"..##..",
        b"..##..",
    ],
};

/// The glyph of a DFC_CAPTION part (the state's low byte); none for another value.
pub fn caption_shape(part: u32) -> Option<Shape> {
    match part {
        DFCS_CAPTIONCLOSE => Some(CLOSE),
        DFCS_CAPTIONMIN => Some(MINIMIZE),
        DFCS_CAPTIONMAX => Some(MAXIMIZE),
        DFCS_CAPTIONRESTORE => Some(RESTORE),
        DFCS_CAPTIONHELP => Some(HELP),
        _ => None,
    }
}

/// DFC_CAPTION's work: the button `state` names (its part and its DFCS_* states) drawn in `rect`
/// (see the module notes); whether it was (FALSE for a part that is none, nothing drawn).
pub fn draw_caption_in(dc: usize, rect: Rect, state: u32) -> bool {
    let Some(shape) = caption_shape(state & 0xFF) else {
        return false;
    };
    let pushed = state & DFCS_PUSHED != 0;
    let edge = if pushed { EDGE_SUNKEN } else { EDGE_RAISED };
    let mut flags = BF_RECT | BF_SOFT | BF_MIDDLE;
    if state & DFCS_FLAT != 0 {
        flags |= BF_FLAT;
    }
    if state & DFCS_MONO != 0 {
        flags |= BF_MONO;
    }
    let (_, mut done) = draw::draw_edge_in(dc, rect, edge, flags);
    let shift = pushed as i32;
    let left = rect.left + (rect.right - rect.left - BUTTON_WIDTH) / 2 + shift;
    let top = rect.top + (rect.bottom - rect.top - BUTTON_HEIGHT) / 2 + shift;
    let layers: &[(i32, u32)] = if state & DFCS_INACTIVE != 0 {
        &[(1, COLOR_3DHILIGHT), (0, COLOR_3DSHADOW)]
    } else {
        &[(0, COLOR_BTNTEXT)]
    };
    for &(offset, color) in layers {
        done &= draw_shape(
            dc,
            &shape,
            left + offset,
            top + offset,
            rect,
            color as usize + 1,
        );
    }
    done
}

/// `shape`'s ink painted with `brush`, the standard button's top left at (`left`, `top`), clipped
/// to `clip`; whether gdi32 painted every run.
fn draw_shape(dc: usize, shape: &Shape, left: i32, top: i32, clip: Rect, brush: usize) -> bool {
    let mut done = true;
    for (y, row) in shape.rows.iter().enumerate() {
        let y = top + shape.at.1 + y as i32;
        if y < clip.top || y >= clip.bottom {
            continue;
        }
        let mut x = 0;
        while x < row.len() {
            if row[x] != b'#' {
                x += 1;
                continue;
            }
            let start = x;
            while x < row.len() && row[x] == b'#' {
                x += 1;
            }
            let run = Rect {
                left: (left + shape.at.0 + start as i32).max(clip.left),
                top: y,
                right: (left + shape.at.0 + x as i32).min(clip.right),
                bottom: y + 1,
            };
            if run.left < run.right {
                done &= draw::fill(dc, run, brush);
            }
        }
    }
    done
}

/// DrawFrameControl: the control `kind` names drawn in the rectangle, in `state`; TRUE, or FALSE
/// for a part that is none or a DC gdi32 refuses. Only DFC_CAPTION is drawn (see the module
/// notes); the other kinds go to the stub routine.
///
/// # Safety
///
/// The caller's RECT, read, as for the platform's.
#[unsafe(export_name = "f2k_export_DrawFrameControl")]
pub unsafe extern "system" fn draw_frame_control(
    dc: usize,
    rect: *mut Rect,
    kind: u32,
    state: u32,
) -> u32 {
    if kind != DFC_CAPTION {
        let args = [dc as u64, rect as u64, kind as u64, state as u64];
        let reason = match kind {
            DFC_MENU | DFC_POPUPMENU => "menu glyphs not yet implemented",
            DFC_SCROLL => "scroll bar arrows and size grips not yet implemented",
            DFC_BUTTON => "push buttons, check boxes and radio buttons not yet implemented",
            _ => "no such kind",
        };
        // SAFETY: the arguments as DrawFrameControl's kinds read them.
        return unsafe { crate::stub::stubbed(&crate::spec::DrawFrameControl, reason, &args) };
    }
    // SAFETY: the caller's RECT.
    let rect = unsafe { In::new(rect.cast_const()) }.read();
    draw_caption_in(dc, rect, state) as u32
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;

    use super::*;
    use crate::imports::host::canvas::*;

    const DC: usize = CANVAS_DC;

    /// The default scheme's 3D colors and the text's, as characters, as the capture's maps read:
    /// COLOR_3DHILIGHT 'W', COLOR_3DFACE and COLOR_3DLIGHT '.', COLOR_3DSHADOW 'G',
    /// COLOR_3DDKSHADOW 'D', COLOR_BTNTEXT '#'.
    const LEGEND: [(u32, char); 6] = [
        (PAPER, '~'),
        (0x00FF_FFFF, 'W'),
        (0x0080_8080, 'G'),
        (0x0040_4040, 'D'),
        (0x00C8_D0D4, '.'),
        (0x0000_0000, '#'),
    ];

    const BUTTON: Rect = Rect {
        left: 1,
        top: 1,
        right: 1 + BUTTON_WIDTH,
        bottom: 1 + BUTTON_HEIGHT,
    };

    /// The standard button drawn in `state` through DrawFrameControl, and its pixels.
    fn button(state: u32) -> Vec<String> {
        reset_canvas();
        let mut rect = BUTTON;
        // SAFETY: the test's own RECT.
        assert_eq!(
            unsafe { draw_frame_control(DC, &mut rect, DFC_CAPTION, state) },
            1
        );
        canvas(|canvas| canvas.picture(BUTTON, &LEGEND))
    }

    /// The minimize, maximize (inactive) and close buttons are the capture's pixels: calc.exe's
    /// caption on Windows 2000, its maximize button disabled.
    ///
    /// Pins: user32.DrawFrameControl
    #[test]
    fn the_captured_buttons() {
        assert_eq!(
            button(DFCS_CAPTIONMIN),
            [
                "WWWWWWWWWWWWWWWD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W.............GD",
                "W...######....GD",
                "W...######....GD",
                "W.............GD",
                "WGGGGGGGGGGGGGGD",
                "DDDDDDDDDDDDDDDD",
            ]
        );
        assert_eq!(
            button(DFCS_CAPTIONMAX | DFCS_INACTIVE),
            [
                "WWWWWWWWWWWWWWWD",
                "W.............GD",
                "W..GGGGGGGGG..GD",
                "W..GGGGGGGGGW.GD",
                "W..GWWWWWWWGW.GD",
                "W..GW......GW.GD",
                "W..GW......GW.GD",
                "W..GW......GW.GD",
                "W..GW......GW.GD",
                "W..GW......GW.GD",
                "W..GGGGGGGGGW.GD",
                "W...WWWWWWWWW.GD",
                "WGGGGGGGGGGGGGGD",
                "DDDDDDDDDDDDDDDD",
            ]
        );
        assert_eq!(
            button(DFCS_CAPTIONCLOSE),
            [
                "WWWWWWWWWWWWWWWD",
                "W.............GD",
                "W.............GD",
                "W...##....##..GD",
                "W....##..##...GD",
                "W.....####....GD",
                "W......##.....GD",
                "W.....####....GD",
                "W....##..##...GD",
                "W...##....##..GD",
                "W.............GD",
                "W.............GD",
                "WGGGGGGGGGGGGGGD",
                "DDDDDDDDDDDDDDDD",
            ]
        );
    }

    /// Pushed, the edge is sunken (soft: the dark shadow outside above and to the left) and the
    /// glyph a pixel down and to the right; the restore and help glyphs.
    ///
    /// Pins: user32.DrawFrameControl
    #[test]
    fn pushed_restore_and_help() {
        assert_eq!(
            button(DFCS_CAPTIONCLOSE | DFCS_PUSHED),
            [
                "DDDDDDDDDDDDDDDW",
                "DGGGGGGGGGGGGG.W",
                "DG.............W",
                "DG.............W",
                "DG...##....##..W",
                "DG....##..##...W",
                "DG.....####....W",
                "DG......##.....W",
                "DG.....####....W",
                "DG....##..##...W",
                "DG...##....##..W",
                "DG.............W",
                "D..............W",
                "WWWWWWWWWWWWWWWW",
            ]
        );
        assert_eq!(
            button(DFCS_CAPTIONRESTORE),
            [
                "WWWWWWWWWWWWWWWD",
                "W.............GD",
                "W....######...GD",
                "W....######...GD",
                "W....#....#...GD",
                "W..######.#...GD",
                "W..######.#...GD",
                "W..#....###...GD",
                "W..#....#.....GD",
                "W..#....#.....GD",
                "W..######.....GD",
                "W.............GD",
                "WGGGGGGGGGGGGGGD",
                "DDDDDDDDDDDDDDDD",
            ]
        );
        assert_eq!(
            button(DFCS_CAPTIONHELP),
            [
                "WWWWWWWWWWWWWWWD",
                "W.............GD",
                "W.....####....GD",
                "W....##..##...GD",
                "W....##..##...GD",
                "W.......##....GD",
                "W......##.....GD",
                "W......##.....GD",
                "W.............GD",
                "W......##.....GD",
                "W......##.....GD",
                "W.............GD",
                "WGGGGGGGGGGGGGGD",
                "DDDDDDDDDDDDDDDD",
            ]
        );
    }

    /// A part that is none draws nothing and is FALSE; another kind goes to the stub routine.
    ///
    /// Pins: user32.DrawFrameControl
    #[test]
    fn other_parts_and_kinds() {
        reset_canvas();
        let mut rect = BUTTON;
        // SAFETY: the test's own RECT.
        assert_eq!(
            unsafe { draw_frame_control(DC, &mut rect, DFC_CAPTION, 9) },
            0
        );
        assert!(canvas(|canvas| canvas
            .pixels
            .iter()
            .all(|&pixel| pixel == PAPER)));
        // SAFETY: as above.
        assert_eq!(
            unsafe { draw_frame_control(DC, &mut rect, DFC_BUTTON, 0) },
            0
        );
        assert!(canvas(|canvas| canvas
            .pixels
            .iter()
            .all(|&pixel| pixel == PAPER)));
    }
}
