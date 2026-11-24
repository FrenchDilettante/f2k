//! The system bitmaps (winuser.h's OBM_*, under OEMRESOURCE) that LoadBitmap and LoadImage give
//! with no module: Windows 2000 keeps them as user32's own resources, which F2K's user32 has none
//! of, so each is held here as the rows the bitmaps capture (tests/gdi32/bitmaps, `obm`) prints of
//! it, one character a pixel, and handed to the loader as the packed DIB a resource would be.
//!
//! The characters are the capture's shades: `#` black, `+` dark gray (0x808080), `-` light gray
//! (0xC0C0C0), `.` white. The capture prints any other color as `?`, naming only the first; the
//! colored pixels of OBM_CLOSE (the window flag, twice) are written here as `r` red (the first,
//! 0xFF0000, as captured), `g` green, `b` blue and `y` yellow, the flag's four colors by its
//! panes, their exact places within the `?` pixels not captured.
//!
//! OBM_CHECK is a monochrome DIB (black and white), loaded as a monochrome bitmap as the capture
//! shows (its depth not the screen's); the others are 4-bit DIBs, loaded at the screen's format.

use rtl::dib::{dword_stride, quad_of_rgb, set_packed, table_size, BitmapInfoHeader, HEADER_SIZE};
use rtl::pod::Pod;

/// The system bitmaps held (winuser.h's OBM_*).
pub const OBM_CLOSE: u16 = 32754;
pub const OBM_UPARROW: u16 = 32753;
pub const OBM_DNARROW: u16 = 32752;
pub const OBM_RGARROW: u16 = 32751;
pub const OBM_LFARROW: u16 = 32750;
pub const OBM_CHECK: u16 = 32760;
pub const OBM_CHECKBOXES: u16 = 32759;

/// A system bitmap: its rows, and whether it is monochrome.
pub struct Art {
    rows: &'static [&'static str],
    mono: bool,
}

/// The colors of the 4-bit bitmaps' table, by the characters standing for them.
const COLORS: [(u8, u32); 8] = [
    (b'#', 0x000000),
    (b'+', 0x808080),
    (b'-', 0xC0C0C0),
    (b'.', 0xFFFFFF),
    (b'r', 0xFF0000),
    (b'g', 0x00FF00),
    (b'b', 0x0000FF),
    (b'y', 0xFFFF00),
];

/// The system bitmap `id`; none for one F2K does not hold.
pub fn find(id: u16) -> Option<&'static Art> {
    match id {
        OBM_CHECK => Some(&CHECK),
        OBM_CLOSE => Some(&CLOSE),
        OBM_CHECKBOXES => Some(&CHECKBOXES),
        OBM_UPARROW => Some(&UPARROW),
        OBM_DNARROW => Some(&DNARROW),
        OBM_LFARROW => Some(&LFARROW),
        OBM_RGARROW => Some(&RGARROW),
        _ => None,
    }
}

impl Art {
    pub fn width(&self) -> i32 {
        self.rows[0].len() as i32
    }

    pub fn height(&self) -> i32 {
        self.rows.len() as i32
    }

    fn bpp(&self) -> u32 {
        if self.mono {
            1
        } else {
            4
        }
    }

    /// The size of its packed DIB: header, table, rows.
    pub fn packed_size(&self) -> usize {
        let bpp = self.bpp();
        HEADER_SIZE as usize
            + 4 * table_size(bpp)
            + dword_stride(self.width(), bpp) as usize * self.height() as usize
    }

    /// Its packed DIB (bottom-up, as a resource's) written to `out`, [`Art::packed_size`] bytes
    /// of zeroes.
    pub fn write_packed(&self, out: &mut [u8]) {
        let bpp = self.bpp();
        let header = BitmapInfoHeader {
            size: HEADER_SIZE,
            width: self.width(),
            height: self.height(),
            planes: 1,
            bit_count: bpp as u16,
            ..BitmapInfoHeader::default()
        };
        out[..HEADER_SIZE as usize].copy_from_slice(header.as_bytes());
        let table = &mut out[HEADER_SIZE as usize..HEADER_SIZE as usize + 4 * table_size(bpp)];
        let (quads, _) = table.as_chunks_mut::<4>();
        if self.mono {
            quads[0] = quad_of_rgb(0x000000);
            quads[1] = quad_of_rgb(0xFFFFFF);
        } else {
            for (quad, &(_, rgb)) in quads.iter_mut().zip(COLORS.iter()) {
                *quad = quad_of_rgb(rgb);
            }
        }
        let start = HEADER_SIZE as usize + 4 * table_size(bpp);
        let stride = dword_stride(self.width(), bpp) as usize;
        for (y, row) in self.rows.iter().enumerate() {
            let stored = self.rows.len() - 1 - y;
            let into = &mut out[start + stride * stored..start + stride * (stored + 1)];
            for (x, &c) in row.as_bytes().iter().enumerate() {
                let index = if self.mono {
                    (c == b'.') as u32
                } else {
                    COLORS.iter().position(|&(k, _)| k == c).unwrap_or(0) as u32
                };
                set_packed(into, x, bpp, index);
            }
        }
    }
}

static CHECK: Art = Art {
    mono: true,
    rows: &[
        ".............",
        ".............",
        ".............",
        "........#....",
        ".......##....",
        "..#...###....",
        "..##.###.....",
        "..#####......",
        "...###.......",
        "....#........",
        ".............",
        ".............",
        ".............",
    ],
};

static CLOSE: Art = Art {
    mono: false,
    rows: &[
        "----------------------------------------",
        "----------------------------------------",
        "----------------------------------------",
        "-----------####----------------####-----",
        "---------########------------########---",
        "--#-----###r##g###----#-----###r##g###--",
        "--#-#-####rr##gg##----#-#-####rr##gg##--",
        "----######rr##gg##------######rr##gg##--",
        "--r-----##r####g##----r-----##r####g##--",
        "--r-r-rr##########----r-r-rr##########--",
        "----bbbb###b##y###------bbbb###b##y###--",
        "--b-----##bb##yy##----b-----##bb##yy##--",
        "--b-b-bb##bb##yy##----b-b-bb##bb##yy##--",
        "----bbbb##b####y##------bbbb##b####y##--",
        "--#-----##########----#-----##########--",
        "--#-#-#####----###----#-#-#####----###--",
        "----#####--------#------#####--------#--",
        "----------------------------------------",
        "----------------------------------------",
        "----------------------------------------",
        "----------------------------------------",
        "----------------------------------------",
    ],
};

static CHECKBOXES: Art = Art {
    mono: false,
    rows: &[
        "++++++++++++.++++++++++++.++++++++++++.++++++++++++.",
        "+++++++++++-.+++++++++++-.+++++++++++-.+++++++++++-.",
        "++.........-.++.........-.++----------.++----------.",
        "++.........-.++.......#.-.++----------.++-------#--.",
        "++.........-.++......##.-.++----------.++------##--.",
        "++.........-.++.#...###.-.++----------.++-#---###--.",
        "++.........-.++.##.###..-.++----------.++-##-###---.",
        "++.........-.++.#####...-.++----------.++-#####----.",
        "++.........-.++..###....-.++----------.++--###-----.",
        "++.........-.++...#.....-.++----------.++---#------.",
        "++.........-.++.........-.++----------.++----------.",
        "+-----------.+-----------.+-----------.+-----------.",
        "....................................................",
        ".....++++.........++++.........++++.........++++....",
        "...++++++++.....++++++++.....++++++++.....++++++++..",
        "..+++....++....+++....++....+++----++....+++----++..",
        "..++......-....++......-....++-------....++-------..",
        ".++........-..++...##...-..++---------..++---##----.",
        ".++........-..++..####..-..++---------..++--####---.",
        ".++........-..++..####..-..++---------..++--####---.",
        ".++........-..++...##...-..++---------..++---##----.",
        "..++......-....++......-....++-------....++-------..",
        "..+--....--....+--....--....+--------....+--------..",
        ".....----.........----.........----.........----....",
        "....................................................",
        "....................................................",
        "#####++++####++++++++++++.++++++++++++.++++++++++++.",
        "###++++++++##+++++++++++-.+++++++++++-.+++++++++++-.",
        "##+++----++.#++----------.++.-.-.-.-.-.++----------.",
        "##++-------.#++----------.++-.-.-.-+--.++-------+--.",
        "#++---++----.++----------.++.-.-.-++.-.++------++--.",
        "#++--++++---.++----------.++-+-.-+++--.++-+---+++--.",
        "#++--++++---.++----------.++.++-+++-.-.++-++-+++---.",
        "#++---++----.++----------.++-+++++-.--.++-+++++----.",
        "##++-------.#++----------.++.-+++-.-.-.++--+++-----.",
        "##+--------.#++----------.++-.-+-.-.--.++---+------.",
        "###..----..##++----------.++.-.-.-.-.-.++----------.",
        "#####....####+-----------.+-----------.+-----------.",
        "#############.......................................",
    ],
};

static UPARROW: Art = Art {
    mono: false,
    rows: &[
        "---------------+",
        "-.............++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.-----#------++",
        "-.----###-----++",
        "-.---#####----++",
        "-.--#######---++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-+++++++++++++++",
        "++++++++++++++++",
    ],
};

static DNARROW: Art = Art {
    mono: false,
    rows: &[
        "---------------+",
        "-.............++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.--#######---++",
        "-.---#####----++",
        "-.----###-----++",
        "-.-----#------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-+++++++++++++++",
        "++++++++++++++++",
    ],
};

static LFARROW: Art = Art {
    mono: false,
    rows: &[
        "---------------+",
        "-.............++",
        "-.------------++",
        "-.------------++",
        "-.------#-----++",
        "-.-----##-----++",
        "-.----###-----++",
        "-.---####-----++",
        "-.----###-----++",
        "-.-----##-----++",
        "-.------#-----++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-+++++++++++++++",
        "++++++++++++++++",
    ],
};

static RGARROW: Art = Art {
    mono: false,
    rows: &[
        "---------------+",
        "-.............++",
        "-.------------++",
        "-.------------++",
        "-.----#-------++",
        "-.----##------++",
        "-.----###-----++",
        "-.----####----++",
        "-.----###-----++",
        "-.----##------++",
        "-.----#-------++",
        "-.------------++",
        "-.------------++",
        "-.------------++",
        "-+++++++++++++++",
        "++++++++++++++++",
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The bitmaps capture's `obm` block: each held bitmap's rows, the colored characters `?`.
    #[test]
    fn the_rows_are_the_capture() {
        let capture = include_str!("../../../tests/gdi32/bitmaps/output.txt");
        let block = &capture[capture.find("== obm").unwrap()..];
        let held = [
            ("OBM_CHECK", OBM_CHECK),
            ("OBM_CLOSE", OBM_CLOSE),
            ("OBM_CHECKBOXES", OBM_CHECKBOXES),
            ("OBM_UPARROW", OBM_UPARROW),
            ("OBM_DNARROW", OBM_DNARROW),
            ("OBM_LFARROW", OBM_LFARROW),
            ("OBM_RGARROW", OBM_RGARROW),
        ];
        for (name, id) in held {
            let art = find(id).unwrap();
            let start = block
                .find(&std::format!("LoadBitmapW(NULL, {name}):"))
                .unwrap();
            let lines: std::vec::Vec<&str> = block[start..].lines().skip(3).collect();
            for (y, row) in art.rows.iter().enumerate() {
                let shown: std::string::String = row
                    .chars()
                    .map(|c| if "rgby".contains(c) { '?' } else { c })
                    .collect();
                assert_eq!(lines[y].trim(), shown, "{name} row {y}");
                assert_eq!(row.len(), art.width() as usize, "{name} row {y}");
            }
        }
    }

    /// A packed DIB of a held bitmap parses back to its rows (bottom-up).
    #[test]
    fn the_packed_dib_holds_the_rows() {
        let art = find(OBM_UPARROW).unwrap();
        let mut data = std::vec![0u8; art.packed_size()];
        art.write_packed(&mut data);
        let header = BitmapInfoHeader::from_bytes(&data[..40]).unwrap();
        assert_eq!((header.width, header.height, header.bit_count), (16, 16, 4));
        // The top row, stored last: fifteen light grays (index 2) and a dark gray (1).
        let last = &data[data.len() - 8..];
        assert_eq!(last, [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x21]);
    }
}
