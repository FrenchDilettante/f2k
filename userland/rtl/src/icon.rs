//! Icons' and cursors' shared shapes: what win32k's cursor and icon services and user32's
//! LoadIcon agree on. A group icon resource's directory, the public GRPICONDIR and GRPICONDIRENTRY
//! ([`GroupEntry`]), the pick LookupIconIdFromDirectoryEx makes among its images ([`best_entry`]),
//! an RT_ICON image's header, the public BITMAPINFOHEADER ([`image_size`]), and what F2K's
//! NtUserSetCursorIconData hands the window manager about an image ([`CursorData`]).

use core::mem::size_of;

use crate::pod::Pod;

/// The resource types: a cursor's image, an icon's image, a group icon's directory.
pub const RT_CURSOR: u16 = 1;
pub const RT_ICON: u16 = 3;
pub const RT_GROUP_ICON: u16 = 14;

/// The size LoadIcon asks for, SM_CXICON by SM_CYICON (Windows 2000's 32 by 32), which LoadCursor's
/// SM_CXCURSOR by SM_CYCURSOR is too.
pub const ICON_SIZE: i32 = 32;

/// The stock cursors' resource ids (winuser.h's IDC_*), in the order the boot makes them.
pub const STOCK_CURSORS: [u16; 16] = [
    32512, // IDC_ARROW
    32513, // IDC_IBEAM
    32514, // IDC_WAIT
    32515, // IDC_CROSS
    32516, // IDC_UPARROW
    32640, // IDC_SIZE
    32641, // IDC_ICON
    32642, // IDC_SIZENWSE
    32643, // IDC_SIZENESW
    32644, // IDC_SIZEWE
    32645, // IDC_SIZENS
    32646, // IDC_SIZEALL
    32648, // IDC_NO
    32649, // IDC_HAND
    32650, // IDC_APPSTARTING
    32651, // IDC_HELP
];

/// The stock icons' resource ids (winuser.h's IDI_*: IDI_APPLICATION, IDI_HAND, IDI_QUESTION,
/// IDI_EXCLAMATION, IDI_ASTERISK, IDI_WINLOGO; IDI_ERROR, IDI_WARNING and IDI_INFORMATION are
/// IDI_HAND's, IDI_EXCLAMATION's and IDI_ASTERISK's), in the order the boot makes them.
pub const STOCK_ICONS: [u16; 6] = [32512, 32513, 32514, 32515, 32516, 32517];

/// GRPICONDIRENTRY (14 bytes, packed): one image of a group icon, its RT_ICON resource's id last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupEntry {
    /// The image's width and height in pixels (0 stands for 256), its colors (0 for 256 or more).
    pub width: u8,
    pub height: u8,
    pub colors: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes: u32,
    /// nID: its RT_ICON resource's number.
    pub id: u16,
}

impl GroupEntry {
    /// The entries a group icon's data lists (after GRPICONDIR's three words: idReserved, idType,
    /// idCount), as far as the data holds them.
    pub fn entries(data: &[u8]) -> impl Iterator<Item = GroupEntry> + '_ {
        let count = data
            .get(4..6)
            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize);
        let (entries, _) = data.get(6..).unwrap_or(&[]).as_chunks::<14>();
        entries.iter().take(count).map(|b| GroupEntry {
            width: b[0],
            height: b[1],
            colors: b[2],
            planes: u16::from_le_bytes([b[4], b[5]]),
            bit_count: u16::from_le_bytes([b[6], b[7]]),
            bytes: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            id: u16::from_le_bytes([b[12], b[13]]),
        })
    }

    /// The image's width and height, 0 read as 256.
    pub fn size(&self) -> (i32, i32) {
        let side = |v: u8| if v == 0 { 256 } else { i32::from(v) };
        (side(self.width), side(self.height))
    }

    /// Its bits per pixel: the planes times the bit count when the entry gives them, else what its
    /// color count needs.
    pub fn bits(&self) -> u32 {
        let bits = u32::from(self.planes.max(1)) * u32::from(self.bit_count);
        if bits != 0 {
            return bits;
        }
        match self.colors {
            0 => 8,
            c if c <= 2 => 1,
            c if c <= 16 => 4,
            _ => 8,
        }
    }
}

/// The image of a group icon LookupIconIdFromDirectoryEx picks for a `cx` by `cy` icon on a
/// display of `display_bits` bits per pixel: the closest in size (the sum of the differences of
/// the sides), among those the deepest that the display shows as it is (no more bits than it
/// has), else the shallowest deeper one; the first of equals. None for a directory of no images.
///
/// Windows 2000 documents the pick as the best fit for the size and the display's colors; the
/// order of the two tests and the ties are assumptions.
pub fn best_entry(data: &[u8], cx: i32, cy: i32, display_bits: u32) -> Option<GroupEntry> {
    let score = |entry: &GroupEntry| {
        let (w, h) = entry.size();
        let distance = (w - cx).unsigned_abs() + (h - cy).unsigned_abs();
        let bits = entry.bits();
        let depth = if bits <= display_bits {
            display_bits - bits
        } else {
            0x100 + bits
        };
        (distance, depth)
    };
    let mut best: Option<GroupEntry> = None;
    for entry in GroupEntry::entries(data) {
        if best.is_none_or(|b| score(&entry) < score(&b)) {
            best = Some(entry);
        }
    }
    best
}

/// An RT_ICON image's size, from its BITMAPINFOHEADER: biWidth by half biHeight (the height
/// counts the color image and the mask); none for data too short for the header.
pub fn image_size(data: &[u8]) -> Option<(i32, i32)> {
    let word = |at: usize| {
        data.get(at..at + 4)
            .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let header = word(0)?;
    if header < 12 {
        return None;
    }
    Some((word(4)?, word(8)? / 2))
}

/// What NtUserSetCursorIconData (F2K's argument list) hands the window manager about a cursor or
/// icon: its kind, its size and hot spot, and what it was loaded from (the module and the
/// resource, the group's data address, which names it in the module, for a shared one; none for
/// one made from bits).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CursorData {
    /// A boolean: an icon (a cursor otherwise).
    pub is_icon: u32,
    pub width: i32,
    pub height: i32,
    pub hotspot_x: i32,
    pub hotspot_y: i32,
    pub bits_per_pixel: u32,
    pub module: u32,
    pub resource: u32,
    /// A boolean: LR_SHARED, the one image of its resource and size that LoadIcon answers.
    pub shared: u32,
}

const _: () = assert!(size_of::<CursorData>() == 36);

// SAFETY: nine 32-bit integers.
unsafe impl Pod for CursorData {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    fn directory(images: &[(u8, u8, u8, u16, u16)]) -> Vec<u8> {
        let mut data = std::vec![0, 0, 1, 0];
        data.extend_from_slice(&(images.len() as u16).to_le_bytes());
        for &(w, h, colors, bits, id) in images {
            data.extend_from_slice(&[w, h, colors, 0]);
            data.extend_from_slice(&1u16.to_le_bytes());
            data.extend_from_slice(&bits.to_le_bytes());
            data.extend_from_slice(&744u32.to_le_bytes());
            data.extend_from_slice(&id.to_le_bytes());
        }
        data
    }

    /// The closest size first, then the deepest color the display shows.
    #[test]
    fn the_pick_is_the_closest_size_then_the_display_depth() {
        let data = directory(&[
            (16, 16, 16, 4, 1),
            (32, 32, 16, 4, 2),
            (32, 32, 0, 8, 3),
            (48, 48, 0, 8, 4),
        ]);
        assert_eq!(best_entry(&data, 32, 32, 8).map(|e| e.id), Some(3));
        assert_eq!(best_entry(&data, 32, 32, 4).map(|e| e.id), Some(2));
        assert_eq!(best_entry(&data, 16, 16, 32).map(|e| e.id), Some(1));
        assert_eq!(best_entry(&directory(&[]), 32, 32, 8), None);
        let deep = directory(&[(32, 32, 0, 32, 5), (32, 32, 0, 8, 6)]);
        assert_eq!(best_entry(&deep, 32, 32, 16).map(|e| e.id), Some(6));
    }

    /// A BITMAPINFOHEADER's height counts the mask.
    #[test]
    fn image_sizes_halve_the_height() {
        let mut header = std::vec![0u8; 40];
        header[0] = 40;
        header[4] = 32;
        header[8] = 64;
        assert_eq!(image_size(&header), Some((32, 32)));
        assert_eq!(image_size(&header[..8]), None);
    }
}
