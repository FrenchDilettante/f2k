//! drawdemo: a sample sheet of user32's drawing calls in a window, for a screenshot compared by
//! eye with Windows 2000 drawing the same. The program (src/main.rs) makes the calls; this library
//! lays the sheet out, host-tested: where each sample goes in the window's client area, and with
//! which edges, flags and text.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// RECT, as user32 and gdi32 take it: its right and bottom edges outside it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// The rectangle from (`left`, `top`) to (`right`, `bottom`).
pub const fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
    Rect {
        left,
        top,
        right,
        bottom,
    }
}

impl Rect {
    /// Whether `inner` lies within this rectangle.
    pub fn holds(&self, inner: &Rect) -> bool {
        inner.left >= self.left
            && inner.top >= self.top
            && inner.right <= self.right
            && inner.bottom <= self.bottom
    }

    /// Whether this rectangle and `other` share a pixel.
    pub fn meets(&self, other: &Rect) -> bool {
        self.left < other.right
            && other.left < self.right
            && self.top < other.bottom
            && other.top < self.bottom
    }
}

/// The window: a popup (no border, no caption: its client area is its rectangle) at this screen
/// position and size.
pub const WINDOW: Rect = rect(20, 20, 620, 460);

/// The client area, in client coordinates.
pub const CLIENT: Rect = rect(0, 0, WINDOW.right - WINDOW.left, WINDOW.bottom - WINDOW.top);

/// DrawEdge's borders and flags the sheet uses (winuser.h).
pub const EDGE_RAISED: u32 = 0x0005;
pub const EDGE_SUNKEN: u32 = 0x000A;
pub const EDGE_ETCHED: u32 = 0x0006;
pub const EDGE_BUMP: u32 = 0x0009;
pub const BF_RECT: u32 = 0x000F;
pub const BF_MIDDLE: u32 = 0x0800;
pub const BF_SOFT: u32 = 0x1000;
pub const BF_ADJUST: u32 = 0x2000;

/// DrawText's format flags the sheet uses (winuser.h).
pub const DT_LEFT: u32 = 0x0000;
pub const DT_TOP: u32 = 0x0000;
pub const DT_CENTER: u32 = 0x0001;
pub const DT_RIGHT: u32 = 0x0002;
pub const DT_VCENTER: u32 = 0x0004;
pub const DT_BOTTOM: u32 = 0x0008;
pub const DT_WORDBREAK: u32 = 0x0010;
pub const DT_SINGLELINE: u32 = 0x0020;
pub const DT_EXPANDTABS: u32 = 0x0040;
pub const DT_CALCRECT: u32 = 0x0400;

/// One edge sample: its box, its label (`&` a mnemonic), its border and its extra flags (every
/// box is BF_RECT, BF_MIDDLE and BF_ADJUST, its label centered in what the border leaves).
pub struct EdgeSample {
    pub area: Rect,
    pub label: &'static [u8],
    pub edge: u32,
    pub flags: u32,
}

/// The top row: the four edges, and a soft raised one (a push button's face).
pub const EDGES: [EdgeSample; 5] = [
    EdgeSample {
        area: rect(10, 10, 110, 50),
        label: b"Raised",
        edge: EDGE_RAISED,
        flags: 0,
    },
    EdgeSample {
        area: rect(120, 10, 220, 50),
        label: b"Sunken",
        edge: EDGE_SUNKEN,
        flags: 0,
    },
    EdgeSample {
        area: rect(230, 10, 330, 50),
        label: b"Etched",
        edge: EDGE_ETCHED,
        flags: 0,
    },
    EdgeSample {
        area: rect(340, 10, 440, 50),
        label: b"Bump",
        edge: EDGE_BUMP,
        flags: 0,
    },
    EdgeSample {
        area: rect(450, 10, 550, 50),
        label: b"&Soft",
        edge: EDGE_RAISED,
        flags: BF_SOFT,
    },
];

/// The fills: three solid brushes' (red, green, blue COLORREFs), a band inverted across them,
/// and two frames, a black brush's and the shadow color's inside it.
pub const FILLS: [(Rect, u32); 3] = [
    (rect(10, 70, 70, 130), 0x0000_00FF),
    (rect(80, 70, 140, 130), 0x0000_FF00),
    (rect(150, 70, 210, 130), 0x00FF_0000),
];
pub const INVERTED: Rect = rect(20, 90, 200, 110);
pub const FRAME: Rect = rect(220, 70, 300, 130);
pub const INNER_FRAME: Rect = rect(225, 75, 295, 125);

/// The focus rectangles around their labels: BeginPaint's DC's, and GetDC's (the window's DC
/// outside the paint).
pub const FOCUS: Rect = rect(320, 80, 440, 120);
pub const GETDC_FOCUS: Rect = rect(460, 80, 580, 120);

/// DrawText's alignments: three single lines in one framed box.
pub const ALIGNED: Rect = rect(10, 150, 290, 260);
pub const ALIGNMENTS: [(&[u8], u32); 3] = [
    (b"Top left", DT_LEFT | DT_TOP),
    (b"Centered", DT_CENTER | DT_VCENTER),
    (b"Bottom right", DT_RIGHT | DT_BOTTOM),
];

/// A paragraph DT_WORDBREAK wraps, in a sunken box with the window color inside, its text inset.
pub const WRAPPED: Rect = rect(300, 150, 590, 260);
pub const PARAGRAPH: &[u8] =
    b"DrawText breaks this paragraph at the spaces before a word that would cross the box's right \
      side. A &mnemonic is underlined.";

/// Tabs DT_EXPANDTABS expands, two lines in a sunken box.
pub const TABBED: Rect = rect(10, 280, 290, 330);
pub const TABS: &[u8] = b"Name\tValue\tMore\r\nx\t1\t&Tab";

/// DT_CALCRECT's rectangle for a line, framed, the line drawn in it.
pub const CALCULATED_AT: Rect = rect(310, 290, 590, 330);
pub const CALCULATED: &[u8] = b"DT_CALCRECT bounds this";

/// A dialog's buttons: the default one framed black with the focus inside, and a plain one.
pub const DEFAULT_BUTTON: Rect = rect(400, 380, 480, 410);
pub const BUTTON: Rect = rect(500, 380, 580, 410);

/// Every sample's area, to check the layout.
pub fn areas() -> impl Iterator<Item = Rect> {
    EDGES
        .iter()
        .map(|sample| sample.area)
        .chain(FILLS.iter().map(|&(area, _)| area))
        .chain([
            FRAME,
            FOCUS,
            GETDC_FOCUS,
            ALIGNED,
            WRAPPED,
            TABBED,
            CALCULATED_AT,
            DEFAULT_BUTTON,
            BUTTON,
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window fits a 640x480 screen; every sample lies in the client area, apart from every
    /// other; the band and the inner frame lie within what they cross.
    #[test]
    fn the_samples_fit_apart() {
        assert!(rect(0, 0, 640, 480).holds(&WINDOW));
        let areas: std::vec::Vec<Rect> = areas().collect();
        for (index, area) in areas.iter().enumerate() {
            assert!(CLIENT.holds(area), "{area:?}");
            for other in &areas[index + 1..] {
                assert!(!area.meets(other), "{area:?} and {other:?}");
            }
        }
        assert!(rect(10, 70, 210, 130).holds(&INVERTED));
        assert!(FRAME.holds(&INNER_FRAME));
    }
}
