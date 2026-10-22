//! The keyboard layout: the data that turns a key into its virtual key and its character, and the
//! walk over that data.
//!
//! A layout is data only ([`Layout`]): which virtual keys are modifiers and the bits each
//! contributes, which modifier combination selects which character column (and which select none),
//! the scan-code tables (base, E0-prefixed, E1-prefixed), the virtual-key conversions some modifier
//! or toggle states apply, and one character row per virtual key — its caps-lock columns, its dead
//! columns, and a UTF-16 unit per column. The producer ([`super::input`]) owns everything that is
//! not layout-shaped (the byte decode, the key-down set, the toggles and the lights, the
//! control-key state) and asks the layout only through [`Layout::modifier_bits`] and
//! [`Layout::translate`], so a second layout is another constant and nothing else.
//!
//! Columns 0 to 3 mean the same in every layout — no modifier, Shift, Ctrl, Shift+Ctrl — so rows
//! can be shared between layouts and layered: a layout's rows are an ordered list of tables, the
//! first one holding a virtual key answering for it. Extra columns (an AltGr pair, say) start at
//! 4. US, the one shipped instance, fills the first four.

/// The modifier bits a layout's shift states read.
pub const SHIFT: u8 = 1 << 0;
pub const CTRL: u8 = 1 << 1;
pub const ALT: u8 = 1 << 2;

/// The toggle bits: the producer owns them; every layout reads the same three.
pub const CAPS_LOCK: u8 = 1 << 0;
pub const NUM_LOCK: u8 = 1 << 1;
pub const SCROLL_LOCK: u8 = 1 << 2;

/// The most character columns a layout may use (columns 0-3 are every layout's base four).
pub const COLUMNS: usize = 8;
/// A shift state that selects no column: no character, the virtual key still reports.
pub const NO_COLUMN: u8 = 0xFF;
/// A column that produces no character (a noncharacter, so no real entry collides with it).
pub const NO: char = '\u{FFFF}';

/// The virtual keys the shipped tables name: the public Win32 values.
pub const VK_CANCEL: u8 = 0x03;
pub const VK_BACK: u8 = 0x08;
pub const VK_TAB: u8 = 0x09;
pub const VK_CLEAR: u8 = 0x0C;
pub const VK_RETURN: u8 = 0x0D;
/// The generic modifier keys: what a record names for either side's key.
pub const VK_SHIFT: u8 = 0x10;
pub const VK_CONTROL: u8 = 0x11;
pub const VK_MENU: u8 = 0x12;
pub const VK_PAUSE: u8 = 0x13;
pub const VK_CAPITAL: u8 = 0x14;
pub const VK_ESCAPE: u8 = 0x1B;
pub const VK_SPACE: u8 = 0x20;
pub const VK_PRIOR: u8 = 0x21;
pub const VK_NEXT: u8 = 0x22;
pub const VK_END: u8 = 0x23;
pub const VK_HOME: u8 = 0x24;
pub const VK_LEFT: u8 = 0x25;
pub const VK_UP: u8 = 0x26;
pub const VK_RIGHT: u8 = 0x27;
pub const VK_DOWN: u8 = 0x28;
pub const VK_SNAPSHOT: u8 = 0x2C;
pub const VK_INSERT: u8 = 0x2D;
pub const VK_DELETE: u8 = 0x2E;
pub const VK_LWIN: u8 = 0x5B;
pub const VK_RWIN: u8 = 0x5C;
pub const VK_APPS: u8 = 0x5D;
pub const VK_NUMPAD0: u8 = 0x60;
pub const VK_NUMPAD1: u8 = 0x61;
pub const VK_NUMPAD2: u8 = 0x62;
pub const VK_NUMPAD3: u8 = 0x63;
pub const VK_NUMPAD4: u8 = 0x64;
pub const VK_NUMPAD5: u8 = 0x65;
pub const VK_NUMPAD6: u8 = 0x66;
pub const VK_NUMPAD7: u8 = 0x67;
pub const VK_NUMPAD8: u8 = 0x68;
pub const VK_NUMPAD9: u8 = 0x69;
pub const VK_MULTIPLY: u8 = 0x6A;
pub const VK_ADD: u8 = 0x6B;
pub const VK_SUBTRACT: u8 = 0x6D;
pub const VK_DECIMAL: u8 = 0x6E;
pub const VK_DIVIDE: u8 = 0x6F;
pub const VK_F1: u8 = 0x70;
pub const VK_F2: u8 = 0x71;
pub const VK_F3: u8 = 0x72;
pub const VK_F4: u8 = 0x73;
pub const VK_F5: u8 = 0x74;
pub const VK_F6: u8 = 0x75;
pub const VK_F7: u8 = 0x76;
pub const VK_F8: u8 = 0x77;
pub const VK_F9: u8 = 0x78;
pub const VK_F10: u8 = 0x79;
pub const VK_F11: u8 = 0x7A;
pub const VK_F12: u8 = 0x7B;
pub const VK_NUMLOCK: u8 = 0x90;
pub const VK_SCROLL: u8 = 0x91;
pub const VK_LSHIFT: u8 = 0xA0;
pub const VK_RSHIFT: u8 = 0xA1;
pub const VK_LCONTROL: u8 = 0xA2;
pub const VK_RCONTROL: u8 = 0xA3;
pub const VK_LMENU: u8 = 0xA4;
pub const VK_RMENU: u8 = 0xA5;
pub const VK_OEM_1: u8 = 0xBA;
pub const VK_OEM_PLUS: u8 = 0xBB;
pub const VK_OEM_COMMA: u8 = 0xBC;
pub const VK_OEM_MINUS: u8 = 0xBD;
pub const VK_OEM_PERIOD: u8 = 0xBE;
pub const VK_OEM_2: u8 = 0xBF;
pub const VK_OEM_3: u8 = 0xC0;
pub const VK_OEM_4: u8 = 0xDB;
pub const VK_OEM_5: u8 = 0xDC;
pub const VK_OEM_6: u8 = 0xDD;
pub const VK_OEM_7: u8 = 0xDE;
pub const VK_OEM_102: u8 = 0xE2;

/// A column's bit, in a row's caps or dead mask.
pub const fn col(column: u8) -> u8 {
    1 << column
}

/// The columns caps lock applies to on a letter: the plain pair.
pub const LETTER_CAPS: u8 = col(0) | col(1);

/// Where a key's make code came from: the base table, or after the E0 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Base,
    E0,
}

/// A condition over the live bits: each pair is (mask, value), holding when bits & mask == value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct When {
    pub mods: (u8, u8),
    pub toggles: (u8, u8),
}

/// A condition pair that always holds.
pub const ANY: (u8, u8) = (0, 0);

/// A virtual-key rewrite: the scan table's `vk` reports as `to` when `when` holds, for keys from
/// `origin` (any origin if none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conversion {
    pub vk: u8,
    pub origin: Option<Origin>,
    pub when: When,
    pub to: u8,
}

/// One virtual key's characters, a UTF-16 unit per column ([`NO`]'s unit where there is none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub vk: u8,
    /// The columns caps lock applies to: it flips SHIFT before the column is read.
    pub caps: u8,
    /// The columns that are dead keys; the column holds the dead character itself.
    pub dead: u8,
    pub chars: [u16; COLUMNS],
}

/// A keyboard layout: data only, walked by the producer.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub name: &'static str,
    /// Which virtual keys are modifiers, and the bits each contributes (the left and right keys,
    /// individually).
    pub modifiers: &'static [(u8, u8)],
    /// The column each modifier-bit combination selects, indexed by the bits ([`NO_COLUMN`]: no
    /// character).
    pub states: &'static [u8],
    /// The virtual key of each base make code (0: not a key, the code is dropped).
    pub scan: &'static [u8; 0x80],
    /// The virtual keys of the E0-prefixed make codes (one not listed is dropped).
    pub scan_e0: &'static [(u8, u8)],
    /// The virtual keys of the E1-prefixed sequences, by the make code after the prefix.
    pub scan_e1: &'static [(u8, u8)],
    /// The rewrites, tried in order: the first that holds applies.
    pub conversions: &'static [Conversion],
    /// The character rows, searched in order: the first table holding the virtual key answers.
    pub rows: &'static [&'static [Row]],
    /// The compositions a dead key starts: (dead character, next character, composed). None
    /// shipped: composition is a later slice's.
    pub dead_keys: &'static [(u16, u16, u16)],
}

/// A row from its characters, column 0 first; columns not given produce none.
pub const fn row(vk: u8, caps: u8, cols: &[char]) -> Row {
    assert!(cols.len() <= COLUMNS);
    let mut chars = [NO as u16; COLUMNS];
    let mut index = 0;
    while index < cols.len() {
        // One UTF-16 unit per column: a key that produces more is a later seam.
        assert!(cols[index] as u32 <= 0xFFFF);
        chars[index] = cols[index] as u16;
        index += 1;
    }
    Row {
        vk,
        caps,
        dead: 0,
        chars,
    }
}

/// A letter key: its two cases, its control character from the virtual key (Ctrl+A 0x01 to Ctrl+Z
/// 0x1A), caps lock on the plain pair.
pub const fn letter(vk: u8, lower: char, upper: char) -> Row {
    row(vk, LETTER_CAPS, &[lower, upper, (vk - 0x40) as char])
}

/// A base scan table with some make codes' virtual keys replaced: (make code, virtual key) pairs.
pub const fn patch(base: [u8; 0x80], patches: &[(u8, u8)]) -> [u8; 0x80] {
    let mut table = base;
    let mut index = 0;
    while index < patches.len() {
        table[patches[index].0 as usize] = patches[index].1;
        index += 1;
    }
    table
}

impl Layout {
    /// The modifier bits the live key-down set holds.
    pub fn modifier_bits(&self, is_down: impl Fn(u8) -> bool) -> u8 {
        self.modifiers
            .iter()
            .filter(|&&(vk, _)| is_down(vk))
            .fold(0, |bits, &(_, bit)| bits | bit)
    }

    /// The virtual key an E0-prefixed make code reports; none for a code the table does not list.
    pub fn e0_key(&self, make: u8) -> Option<u8> {
        lookup(self.scan_e0, make)
    }

    /// The virtual key an E1-prefixed sequence reports, by its first make code.
    pub fn e1_key(&self, make: u8) -> Option<u8> {
        lookup(self.scan_e1, make)
    }

    /// The reported virtual key and character of a key from `origin` whose scan table gives `vk`,
    /// under the live modifier and toggle bits (character 0: none).
    pub fn translate(&self, origin: Origin, vk: u8, mods: u8, toggles: u8) -> (u8, u16) {
        let vk = self.convert(origin, vk, mods, toggles);
        let Some(row) = self.row(vk) else {
            return (vk, 0);
        };
        let mut column = self.column(mods);
        if toggles & CAPS_LOCK != 0 && column != NO_COLUMN && row.caps & col(column) != 0 {
            column = self.column(mods ^ SHIFT);
        }
        if column == NO_COLUMN {
            return (vk, 0);
        }
        if row.dead & col(column) != 0 {
            // A dead key: the compose step goes here — hold the character, and combine it with the
            // next key's through `dead_keys`. No shipped layout has one; until then the dead
            // character reports as itself.
        }
        match row.chars[column as usize] {
            unit if unit == NO as u16 => (vk, 0),
            unit => (vk, unit),
        }
    }

    /// The column a modifier combination selects; [`NO_COLUMN`] for one the table leaves out or
    /// maps past the row's width.
    fn column(&self, mods: u8) -> u8 {
        match self.states.get(mods as usize) {
            Some(&column) if (column as usize) < COLUMNS => column,
            _ => NO_COLUMN,
        }
    }

    /// The virtual key after the first conversion that holds.
    fn convert(&self, origin: Origin, vk: u8, mods: u8, toggles: u8) -> u8 {
        let holds = |(mask, value): (u8, u8), bits: u8| bits & mask == value;
        self.conversions
            .iter()
            .find(|conversion| {
                conversion.vk == vk
                    && conversion.origin.is_none_or(|from| from == origin)
                    && holds(conversion.when.mods, mods)
                    && holds(conversion.when.toggles, toggles)
            })
            .map_or(vk, |conversion| conversion.to)
    }

    /// The first row holding `vk`, across the layered tables.
    fn row(&self, vk: u8) -> Option<&Row> {
        self.rows
            .iter()
            .flat_map(|table| table.iter())
            .find(|row| row.vk == vk)
    }
}

/// The value a (key, value) table pairs with `key`.
fn lookup(table: &[(u8, u8)], key: u8) -> Option<u8> {
    table
        .iter()
        .find(|&&(entry, _)| entry == key)
        .map(|&(_, value)| value)
}

// --- US: the shipped instance -------------------------------------------------------------------

/// The US keyboard: Shift, Ctrl and Alt from either side; Alt in any combination selects no
/// character (the record still carries the virtual key).
pub const US: Layout = Layout {
    name: "US",
    modifiers: &[
        (VK_LSHIFT, SHIFT),
        (VK_RSHIFT, SHIFT),
        (VK_LCONTROL, CTRL),
        (VK_RCONTROL, CTRL),
        (VK_LMENU, ALT),
        (VK_RMENU, ALT),
    ],
    //       none shift ctrl shift+ctrl | every state with Alt
    states: &[0, 1, 2, 3, NO_COLUMN, NO_COLUMN, NO_COLUMN, NO_COLUMN],
    scan: &US_SCAN,
    scan_e0: &US_SCAN_E0,
    scan_e1: &[(0x1D, VK_PAUSE)],
    conversions: &PC_CONVERSIONS,
    rows: &[&US_ROWS, &COMMON_ROWS],
    dead_keys: &[],
};

/// The US base scan table: set 1's make codes, as the controller's translation delivers them.
pub const US_SCAN: [u8; 0x80] = patch(
    [0; 0x80],
    &[
        (0x01, VK_ESCAPE),
        (0x02, b'1'),
        (0x03, b'2'),
        (0x04, b'3'),
        (0x05, b'4'),
        (0x06, b'5'),
        (0x07, b'6'),
        (0x08, b'7'),
        (0x09, b'8'),
        (0x0A, b'9'),
        (0x0B, b'0'),
        (0x0C, VK_OEM_MINUS),
        (0x0D, VK_OEM_PLUS),
        (0x0E, VK_BACK),
        (0x0F, VK_TAB),
        (0x10, b'Q'),
        (0x11, b'W'),
        (0x12, b'E'),
        (0x13, b'R'),
        (0x14, b'T'),
        (0x15, b'Y'),
        (0x16, b'U'),
        (0x17, b'I'),
        (0x18, b'O'),
        (0x19, b'P'),
        (0x1A, VK_OEM_4),
        (0x1B, VK_OEM_6),
        (0x1C, VK_RETURN),
        (0x1D, VK_LCONTROL),
        (0x1E, b'A'),
        (0x1F, b'S'),
        (0x20, b'D'),
        (0x21, b'F'),
        (0x22, b'G'),
        (0x23, b'H'),
        (0x24, b'J'),
        (0x25, b'K'),
        (0x26, b'L'),
        (0x27, VK_OEM_1),
        (0x28, VK_OEM_7),
        (0x29, VK_OEM_3),
        (0x2A, VK_LSHIFT),
        (0x2B, VK_OEM_5),
        (0x2C, b'Z'),
        (0x2D, b'X'),
        (0x2E, b'C'),
        (0x2F, b'V'),
        (0x30, b'B'),
        (0x31, b'N'),
        (0x32, b'M'),
        (0x33, VK_OEM_COMMA),
        (0x34, VK_OEM_PERIOD),
        (0x35, VK_OEM_2),
        (0x36, VK_RSHIFT),
        (0x37, VK_MULTIPLY),
        (0x38, VK_LMENU),
        (0x39, VK_SPACE),
        (0x3A, VK_CAPITAL),
        (0x3B, VK_F1),
        (0x3C, VK_F2),
        (0x3D, VK_F3),
        (0x3E, VK_F4),
        (0x3F, VK_F5),
        (0x40, VK_F6),
        (0x41, VK_F7),
        (0x42, VK_F8),
        (0x43, VK_F9),
        (0x44, VK_F10),
        (0x45, VK_NUMLOCK),
        (0x46, VK_SCROLL),
        (0x47, VK_HOME),
        (0x48, VK_UP),
        (0x49, VK_PRIOR),
        (0x4A, VK_SUBTRACT),
        (0x4B, VK_LEFT),
        (0x4C, VK_CLEAR),
        (0x4D, VK_RIGHT),
        (0x4E, VK_ADD),
        (0x4F, VK_END),
        (0x50, VK_DOWN),
        (0x51, VK_NEXT),
        (0x52, VK_INSERT),
        (0x53, VK_DELETE),
        (0x54, VK_SNAPSHOT),
        (0x56, VK_OEM_102),
        (0x57, VK_F11),
        (0x58, VK_F12),
    ],
);

/// The US E0-prefixed keys: the right-hand modifiers, the keypad's Enter and Divide, Print Screen,
/// the gray navigation block, and the Windows and application keys.
pub const US_SCAN_E0: [(u8, u8); 18] = [
    (0x1C, VK_RETURN),
    (0x1D, VK_RCONTROL),
    (0x35, VK_DIVIDE),
    (0x37, VK_SNAPSHOT),
    (0x38, VK_RMENU),
    (0x47, VK_HOME),
    (0x48, VK_UP),
    (0x49, VK_PRIOR),
    (0x4B, VK_LEFT),
    (0x4D, VK_RIGHT),
    (0x4F, VK_END),
    (0x50, VK_DOWN),
    (0x51, VK_NEXT),
    (0x52, VK_INSERT),
    (0x53, VK_DELETE),
    (0x5B, VK_LWIN),
    (0x5C, VK_RWIN),
    (0x5D, VK_APPS),
];

/// The rewrites every PC layout shares: Ctrl turns Num Lock into Pause and Scroll Lock into Break,
/// Shift turns Print Screen into the keypad's multiply; with Num Lock on, the keypad's base keys
/// report its digits and decimal point (the gray block's E0 keys stay navigation keys).
pub const PC_CONVERSIONS: [Conversion; 14] = [
    Conversion {
        vk: VK_NUMLOCK,
        origin: None,
        when: When {
            mods: (CTRL, CTRL),
            toggles: ANY,
        },
        to: VK_PAUSE,
    },
    Conversion {
        vk: VK_SCROLL,
        origin: None,
        when: When {
            mods: (CTRL, CTRL),
            toggles: ANY,
        },
        to: VK_CANCEL,
    },
    Conversion {
        vk: VK_SNAPSHOT,
        origin: None,
        when: When {
            mods: (SHIFT, SHIFT),
            toggles: ANY,
        },
        to: VK_MULTIPLY,
    },
    numpad(VK_INSERT, VK_NUMPAD0),
    numpad(VK_END, VK_NUMPAD1),
    numpad(VK_DOWN, VK_NUMPAD2),
    numpad(VK_NEXT, VK_NUMPAD3),
    numpad(VK_LEFT, VK_NUMPAD4),
    numpad(VK_CLEAR, VK_NUMPAD5),
    numpad(VK_RIGHT, VK_NUMPAD6),
    numpad(VK_HOME, VK_NUMPAD7),
    numpad(VK_UP, VK_NUMPAD8),
    numpad(VK_PRIOR, VK_NUMPAD9),
    numpad(VK_DELETE, VK_DECIMAL),
];

/// A keypad key: its digit with Num Lock on, from the base table only.
const fn numpad(vk: u8, to: u8) -> Conversion {
    Conversion {
        vk,
        origin: Some(Origin::Base),
        when: When {
            mods: ANY,
            toggles: (NUM_LOCK, NUM_LOCK),
        },
        to,
    }
}

/// The US printing keys: the digits and punctuation, then the letters.
pub const US_ROWS: [Row; 47] = [
    row(VK_OEM_3, 0, &['`', '~']),
    row(b'1', 0, &['1', '!']),
    row(b'2', 0, &['2', '@', NO, '\0']),
    row(b'3', 0, &['3', '#']),
    row(b'4', 0, &['4', '$']),
    row(b'5', 0, &['5', '%']),
    row(b'6', 0, &['6', '^', NO, '\x1e']),
    row(b'7', 0, &['7', '&']),
    row(b'8', 0, &['8', '*']),
    row(b'9', 0, &['9', '(']),
    row(b'0', 0, &['0', ')']),
    row(VK_OEM_MINUS, 0, &['-', '_', NO, '\x1f']),
    row(VK_OEM_PLUS, 0, &['=', '+']),
    row(VK_OEM_4, 0, &['[', '{', '\x1b']),
    row(VK_OEM_6, 0, &[']', '}', '\x1d']),
    row(VK_OEM_5, 0, &['\\', '|', '\x1c']),
    row(VK_OEM_1, 0, &[';', ':']),
    row(VK_OEM_7, 0, &['\'', '"']),
    row(VK_OEM_COMMA, 0, &[',', '<']),
    row(VK_OEM_PERIOD, 0, &['.', '>']),
    row(VK_OEM_2, 0, &['/', '?']),
    letter(b'A', 'a', 'A'),
    letter(b'B', 'b', 'B'),
    letter(b'C', 'c', 'C'),
    letter(b'D', 'd', 'D'),
    letter(b'E', 'e', 'E'),
    letter(b'F', 'f', 'F'),
    letter(b'G', 'g', 'G'),
    letter(b'H', 'h', 'H'),
    letter(b'I', 'i', 'I'),
    letter(b'J', 'j', 'J'),
    letter(b'K', 'k', 'K'),
    letter(b'L', 'l', 'L'),
    letter(b'M', 'm', 'M'),
    letter(b'N', 'n', 'N'),
    letter(b'O', 'o', 'O'),
    letter(b'P', 'p', 'P'),
    letter(b'Q', 'q', 'Q'),
    letter(b'R', 'r', 'R'),
    letter(b'S', 's', 'S'),
    letter(b'T', 't', 'T'),
    letter(b'U', 'u', 'U'),
    letter(b'V', 'v', 'V'),
    letter(b'W', 'w', 'W'),
    letter(b'X', 'x', 'X'),
    letter(b'Y', 'y', 'Y'),
    letter(b'Z', 'z', 'Z'),
];

/// The rows every layout shares: the whitespace and editing keys, Escape, and the keypad's
/// characters.
pub const COMMON_ROWS: [Row; 20] = [
    // TODO: the Ctrl columns of Tab, Enter, Backspace, Space and Escape are capture-pending: the
    // plain characters stand until a real machine's records rule them.
    row(VK_SPACE, 0, &[' ', ' ', ' ', ' ']),
    row(VK_TAB, 0, &['\t', '\t']),
    row(VK_RETURN, 0, &['\r', '\r']),
    row(VK_BACK, 0, &['\x08', '\x08']),
    row(VK_ESCAPE, 0, &['\x1b', '\x1b']),
    row(VK_NUMPAD0, 0, &['0', '0', '0']),
    row(VK_NUMPAD1, 0, &['1', '1', '1']),
    row(VK_NUMPAD2, 0, &['2', '2', '2']),
    row(VK_NUMPAD3, 0, &['3', '3', '3']),
    row(VK_NUMPAD4, 0, &['4', '4', '4']),
    row(VK_NUMPAD5, 0, &['5', '5', '5']),
    row(VK_NUMPAD6, 0, &['6', '6', '6']),
    row(VK_NUMPAD7, 0, &['7', '7', '7']),
    row(VK_NUMPAD8, 0, &['8', '8', '8']),
    row(VK_NUMPAD9, 0, &['9', '9', '9']),
    row(VK_DECIMAL, 0, &['.', '.', '.', '.']),
    row(VK_MULTIPLY, 0, &['*', '*', '*', '*']),
    row(VK_ADD, 0, &['+', '+', '+', '+']),
    row(VK_SUBTRACT, 0, &['-', '-', '-', '-']),
    row(VK_DIVIDE, 0, &['/', '/', '/', '/']),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Right Alt as AltGr, as a layout with an AltGr column enters it: right Alt contributes Ctrl
    /// and Alt, and Ctrl+Alt selects columns 4 and 5.
    const ALTGR_MODIFIERS: &[(u8, u8)] = &[
        (VK_LSHIFT, SHIFT),
        (VK_RSHIFT, SHIFT),
        (VK_LCONTROL, CTRL),
        (VK_RCONTROL, CTRL),
        (VK_LMENU, ALT),
        (VK_RMENU, CTRL | ALT),
    ];
    //                      none shift ctrl s+ctrl alt        s+alt      altgr s+altgr
    const ALTGR_STATES: &[u8] = &[0, 1, 2, 3, NO_COLUMN, NO_COLUMN, 4, 5];

    fn us(vk: u8, mods: u8, toggles: u8) -> (u8, u16) {
        US.translate(Origin::Base, vk, mods, toggles)
    }

    fn unit(c: char) -> u16 {
        c as u16
    }

    #[test]
    fn the_base_table_names_every_key_of_the_us_keyboard() {
        let pairs = [
            (0x01, VK_ESCAPE),
            (0x02, b'1'),
            (0x0B, b'0'),
            (0x0E, VK_BACK),
            (0x10, b'Q'),
            (0x19, b'P'),
            (0x1C, VK_RETURN),
            (0x1D, VK_LCONTROL),
            (0x1E, b'A'),
            (0x26, b'L'),
            (0x2A, VK_LSHIFT),
            (0x2C, b'Z'),
            (0x32, b'M'),
            (0x36, VK_RSHIFT),
            (0x37, VK_MULTIPLY),
            (0x38, VK_LMENU),
            (0x3A, VK_CAPITAL),
            (0x3B, VK_F1),
            (0x44, VK_F10),
            (0x45, VK_NUMLOCK),
            (0x46, VK_SCROLL),
            (0x4C, VK_CLEAR),
            (0x53, VK_DELETE),
            (0x54, VK_SNAPSHOT),
            (0x56, VK_OEM_102),
            (0x57, VK_F11),
            (0x58, VK_F12),
        ];
        for (make, vk) in pairs {
            assert_eq!(US.scan[make as usize], vk, "{make:#04x}");
        }
        for make in [0x00, 0x55, 0x59, 0x7F] {
            assert_eq!(US.scan[make], 0, "{make:#04x}: not a key");
        }
        assert_eq!(US.e0_key(0x1D), Some(VK_RCONTROL));
        assert_eq!(US.e0_key(0x38), Some(VK_RMENU));
        assert_eq!(US.e0_key(0x1C), Some(VK_RETURN));
        assert_eq!(US.e0_key(0x4D), Some(VK_RIGHT));
        assert_eq!(US.e0_key(0x5D), Some(VK_APPS));
        assert_eq!(US.e0_key(0x4C), None, "the gray block has no centre key");
        assert_eq!(US.e1_key(0x1D), Some(VK_PAUSE));
    }

    /// Num Lock resolves the keypad's base keys, not the gray block's E0 ones; Ctrl and Shift
    /// rewrite their keys whatever the toggles.
    #[test]
    fn the_conversions_follow_the_modifiers_and_num_lock() {
        let pad = [
            (VK_INSERT, VK_NUMPAD0, '0'),
            (VK_END, VK_NUMPAD1, '1'),
            (VK_CLEAR, VK_NUMPAD5, '5'),
            (VK_PRIOR, VK_NUMPAD9, '9'),
            (VK_DELETE, VK_DECIMAL, '.'),
        ];
        for (navigation, digit, character) in pad {
            assert_eq!(us(navigation, 0, NUM_LOCK), (digit, unit(character)));
            assert_eq!(us(navigation, 0, 0), (navigation, 0), "Num Lock off");
            assert_eq!(
                US.translate(Origin::E0, navigation, 0, NUM_LOCK),
                (navigation, 0),
                "the gray block"
            );
        }
        assert_eq!(us(VK_NUMLOCK, CTRL, 0), (VK_PAUSE, 0));
        assert_eq!(us(VK_NUMLOCK, 0, 0), (VK_NUMLOCK, 0));
        assert_eq!(us(VK_SCROLL, CTRL, 0), (VK_CANCEL, 0));
        assert_eq!(us(VK_SNAPSHOT, SHIFT, 0), (VK_MULTIPLY, unit('*')));
        assert_eq!(
            US.translate(Origin::E0, VK_SNAPSHOT, 0, 0),
            (VK_SNAPSHOT, 0)
        );
        assert_eq!(us(VK_MULTIPLY, 0, 0), (VK_MULTIPLY, unit('*')));
        assert_eq!(us(VK_MULTIPLY, CTRL, 0), (VK_MULTIPLY, unit('*')));
        assert_eq!(us(VK_CLEAR, CTRL, NUM_LOCK), (VK_NUMPAD5, unit('5')));
        assert_eq!(
            us(VK_CLEAR, SHIFT | CTRL, NUM_LOCK).1,
            0,
            "the digits have no Shift+Ctrl column"
        );
        assert_eq!(
            US.translate(Origin::E0, VK_DIVIDE, CTRL, 0),
            (VK_DIVIDE, unit('/'))
        );
        assert_eq!(
            US.translate(Origin::E0, VK_DIVIDE, 0, 0),
            (VK_DIVIDE, unit('/'))
        );
    }

    #[test]
    fn the_shift_states_select_the_columns() {
        assert_eq!(us(b'A', 0, 0), (b'A', unit('a')));
        assert_eq!(us(b'A', SHIFT, 0), (b'A', unit('A')));
        assert_eq!(us(b'C', CTRL, 0), (b'C', 0x03));
        assert_eq!(us(b'Q', CTRL, 0), (b'Q', 0x11));
        assert_eq!(us(b'Z', CTRL, 0), (b'Z', 0x1A));
        assert_eq!(us(b'A', SHIFT | CTRL, 0), (b'A', 0), "no Shift+Ctrl column");
        for alt in [ALT, ALT | SHIFT, ALT | CTRL, ALT | CTRL | SHIFT] {
            assert_eq!(us(b'A', alt, 0), (b'A', 0), "Alt: no character");
            assert_eq!(us(VK_SPACE, alt, 0), (VK_SPACE, 0));
        }
        assert_eq!(us(b'1', 0, 0), (b'1', unit('1')));
        assert_eq!(us(b'1', SHIFT, 0), (b'1', unit('!')));
        assert_eq!(us(b'1', CTRL, 0), (b'1', 0));
        assert_eq!(us(VK_F1, 0, 0), (VK_F1, 0), "no row");
    }

    #[test]
    fn the_oem_keys_carry_their_specials() {
        assert_eq!(us(VK_OEM_3, SHIFT, 0).1, unit('~'));
        assert_eq!(us(b'2', SHIFT, 0).1, unit('@'));
        assert_eq!(us(b'2', SHIFT | CTRL, 0).1, 0);
        assert_eq!(us(b'6', SHIFT | CTRL, 0).1, 0x1E);
        assert_eq!(us(VK_OEM_MINUS, SHIFT | CTRL, 0).1, 0x1F);
        assert_eq!(us(VK_OEM_MINUS, SHIFT, 0).1, unit('_'));
        assert_eq!(us(VK_OEM_4, CTRL, 0).1, 0x1B);
        assert_eq!(us(VK_OEM_6, CTRL, 0).1, 0x1D);
        assert_eq!(us(VK_OEM_5, CTRL, 0).1, 0x1C);
        assert_eq!(us(VK_OEM_5, SHIFT, 0).1, unit('|'));
        assert_eq!(us(VK_OEM_7, SHIFT, 0).1, unit('"'));
        assert_eq!(us(VK_OEM_2, SHIFT, 0).1, unit('?'));
        assert_eq!(us(VK_SPACE, CTRL | SHIFT, 0).1, 0x20);
        assert_eq!(us(VK_RETURN, 0, 0).1, 0x0D);
        assert_eq!(us(VK_TAB, SHIFT, 0).1, 0x09);
        assert_eq!(us(VK_BACK, 0, 0).1, 0x08);
        assert_eq!(us(VK_ESCAPE, 0, 0).1, 0x1B);
    }

    /// Caps lock flips the letters' shift, only with no Ctrl and no Alt; never a digit's.
    #[test]
    fn caps_lock_flips_the_letters_only() {
        assert_eq!(us(b'A', 0, CAPS_LOCK).1, unit('A'));
        assert_eq!(us(b'A', SHIFT, CAPS_LOCK).1, unit('a'));
        assert_eq!(us(b'A', CTRL, CAPS_LOCK).1, 0x01);
        assert_eq!(us(b'A', ALT, CAPS_LOCK).1, 0);
        assert_eq!(us(b'1', 0, CAPS_LOCK).1, unit('1'));
        assert_eq!(us(VK_OEM_1, 0, CAPS_LOCK).1, unit(';'));
    }

    /// The modifier bits come from the live key-down set, either side's key giving its bit.
    #[test]
    fn the_modifier_bits_come_from_the_down_set() {
        assert_eq!(US.modifier_bits(|vk| vk == VK_RSHIFT), SHIFT);
        assert_eq!(
            US.modifier_bits(|vk| vk == VK_LCONTROL || vk == VK_RMENU),
            CTRL | ALT
        );
        assert_eq!(US.modifier_bits(|vk| vk == b'A'), 0);
    }

    /// The synthetic layout: an AltGr column, caps lock on the AltGr pair, left Alt alone giving no
    /// character, a dead column reporting its character, a toggle-dependent conversion — shapes US
    /// cannot reach, walked by the same code, through the producer too.
    #[test]
    fn a_second_layout_is_data() {
        use crate::console::input::{
            Producer,
            CAPSLOCK_ON,
            ENHANCED_KEY,
            LEFT_ALT_PRESSED,
            RIGHT_ALT_PRESSED,
        };

        const ROWS: [Row; 2] = [
            Row {
                caps: LETTER_CAPS | col(4) | col(5),
                ..row(b'E', 0, &['e', 'E', '\x05', NO, '€', 'Ę'])
            },
            Row {
                dead: col(4),
                ..row(VK_OEM_7, 0, &['\'', '"', NO, NO, '´'])
            },
        ];
        static SYNTHETIC: Layout = Layout {
            name: "synthetic",
            modifiers: ALTGR_MODIFIERS,
            states: ALTGR_STATES,
            rows: &[&ROWS],
            conversions: &[Conversion {
                vk: b'E',
                origin: None,
                when: When {
                    mods: ANY,
                    toggles: (SCROLL_LOCK, SCROLL_LOCK),
                },
                to: VK_OEM_7,
            }],
            ..US
        };
        let altgr = CTRL | ALT;
        let walk = |vk, mods, toggles| SYNTHETIC.translate(Origin::Base, vk, mods, toggles);
        assert_eq!(walk(b'E', altgr, 0), (b'E', unit('€')));
        assert_eq!(walk(b'E', altgr | SHIFT, 0), (b'E', unit('Ę')));
        assert_eq!(
            walk(b'E', altgr, CAPS_LOCK),
            (b'E', unit('Ę')),
            "caps on AltGr"
        );
        assert_eq!(walk(b'E', 0, CAPS_LOCK), (b'E', unit('E')));
        assert_eq!(walk(b'E', CTRL, CAPS_LOCK), (b'E', 0x05));
        assert_eq!(walk(b'E', ALT, 0), (b'E', 0), "left Alt alone: none");
        assert_eq!(walk(VK_OEM_7, altgr, 0), (VK_OEM_7, unit('´')), "dead");
        assert_eq!(walk(b'E', 0, SCROLL_LOCK), (VK_OEM_7, unit('\'')));
        assert_eq!(walk(b'A', 0, 0), (b'A', 0), "no row: none");

        // Bytes in, records out: right Alt (E0 38) is AltGr, left Alt (38) is not.
        let mut producer = Producer::new(&SYNTHETIC);
        let mut records = std::vec::Vec::new();
        for byte in [0xE0, 0x38, 0x12, 0x92, 0xE0, 0xB8, 0x38, 0x12, 0x92, 0xB8] {
            producer.event(byte, &mut (), &mut |record| records.push(record));
        }
        let shape: std::vec::Vec<_> = records
            .iter()
            .map(|r| {
                (
                    r.key_down,
                    r.virtual_key_code as u8,
                    r.char,
                    r.control_key_state,
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (1, VK_MENU, 0, RIGHT_ALT_PRESSED | ENHANCED_KEY),
                (1, b'E', unit('€'), RIGHT_ALT_PRESSED),
                (0, b'E', 0, RIGHT_ALT_PRESSED),
                (0, VK_MENU, 0, ENHANCED_KEY),
                (1, VK_MENU, 0, LEFT_ALT_PRESSED),
                (1, b'E', 0, LEFT_ALT_PRESSED),
                (0, b'E', 0, LEFT_ALT_PRESSED),
                (0, VK_MENU, 0, 0),
            ]
        );
        // Caps lock reaches the AltGr pair through the producer too.
        records.clear();
        for byte in [0x3A, 0xBA, 0xE0, 0x38, 0x12] {
            producer.event(byte, &mut (), &mut |record| records.push(record));
        }
        let last = records.last().unwrap();
        assert_eq!(
            (last.char, last.control_key_state),
            (unit('Ę'), RIGHT_ALT_PRESSED | CAPSLOCK_ON)
        );
    }

    /// Layering: a layout that moves one key's virtual key and overrides one row lists only those;
    /// the US rows answer for everything else, and a row keyed by virtual key follows its key.
    #[test]
    fn rows_layer_and_follow_their_keys() {
        const MOVED: [u8; 0x80] = patch(US_SCAN, &[(0x56, VK_OEM_5), (0x2B, 0)]);
        const OVERRIDES: [Row; 1] = [row(b'2', 0, &['2', '"', NO, '\0'])];
        static LAYERED: Layout = Layout {
            name: "layered",
            scan: &MOVED,
            rows: &[&OVERRIDES, &US_ROWS, &COMMON_ROWS],
            ..US
        };
        let walk = |make: u8, mods| {
            let vk = LAYERED.scan[make as usize];
            LAYERED.translate(Origin::Base, vk, mods, 0)
        };
        assert_eq!(walk(0x03, SHIFT), (b'2', unit('"')), "the override");
        assert_eq!(walk(0x03, 0), (b'2', unit('2')));
        assert_eq!(walk(0x1E, SHIFT), (b'A', unit('A')), "the US rows");
        assert_eq!(walk(0x39, 0), (VK_SPACE, unit(' ')), "the common rows");
        assert_eq!(walk(0x56, 0), (VK_OEM_5, unit('\\')), "the moved key's row");
        assert_eq!(walk(0x56, CTRL), (VK_OEM_5, 0x1C));
        assert_eq!(LAYERED.scan[0x2B], 0, "its old code is no key");
        assert_eq!(US.scan[0x56], VK_OEM_102, "US itself is unchanged");
    }

    /// Columns 0-3 mean the same in every layout: the shared rows read through a six-column state
    /// table give US's characters there.
    #[test]
    fn the_base_columns_are_every_layouts() {
        static SIX: Layout = Layout {
            name: "six columns",
            modifiers: ALTGR_MODIFIERS,
            states: ALTGR_STATES,
            ..US
        };
        for row in COMMON_ROWS.iter().chain(US_ROWS.iter()) {
            for mods in [0, SHIFT, CTRL, SHIFT | CTRL] {
                for toggles in [0, CAPS_LOCK] {
                    assert_eq!(
                        SIX.translate(Origin::Base, row.vk, mods, toggles),
                        US.translate(Origin::Base, row.vk, mods, toggles),
                        "{:#04x} {mods:#x} {toggles:#x}",
                        row.vk
                    );
                }
            }
        }
    }
}
