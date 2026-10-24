//! The console's input side: the key-event producer that turns the keyboard controller's bytes
//! into KEY_EVENT_RECORDs, and the input buffer the records wait in for the console's readers.
//!
//! The producer is fed one byte at a time ([`Producer::event`]) — the original PC/XT-compatible
//! scan codes the keyboard controller delivers with its translation on: a make code per key, the
//! same code with bit 7 set for its break, 0xE0 before an extended key, 0xE1 before Pause's
//! three-byte sequence. It owns the decode, the key-down set (per virtual key, the left and right
//! modifiers apart), the three toggles (caps, num and scroll lock, and the lights that show them),
//! and the control-key state each record carries. What a key means — its virtual key and its
//! character — is the layout's ([`super::layout`]), which the producer holds by reference and asks
//! nothing else of.
//!
//! Each physical press is one keydown record and one keyup record, each with a repeat count of 1;
//! a key the keyboard repeats while held gives further keydowns. The input buffer
//! ([`InputBuffer`]) folds a keydown repeating the one before it into that record's repeat count.
//! Characters are UTF-16 units, as the layout produces them: nothing on the input path narrows to
//! a code page.

use super::layout::{
    Layout,
    Origin,
    CAPS_LOCK,
    NUM_LOCK,
    SCROLL_LOCK,
    VK_CAPITAL,
    VK_CONTROL,
    VK_LCONTROL,
    VK_LMENU,
    VK_LSHIFT,
    VK_MENU,
    VK_NUMLOCK,
    VK_RCONTROL,
    VK_RMENU,
    VK_RSHIFT,
    VK_SCROLL,
    VK_SHIFT,
};

/// INPUT_RECORD's EventType for a key event.
pub const KEY_EVENT: u16 = 0x1;

/// The control-key state bits a KEY_EVENT_RECORD carries (dwControlKeyState).
pub const RIGHT_ALT_PRESSED: u32 = 0x1;
pub const LEFT_ALT_PRESSED: u32 = 0x2;
pub const RIGHT_CTRL_PRESSED: u32 = 0x4;
pub const LEFT_CTRL_PRESSED: u32 = 0x8;
pub const SHIFT_PRESSED: u32 = 0x10;
pub const NUMLOCK_ON: u32 = 0x20;
pub const SCROLLLOCK_ON: u32 = 0x40;
pub const CAPSLOCK_ON: u32 = 0x80;
pub const ENHANCED_KEY: u32 = 0x100;

/// The toggles a fresh boot reports: every light off.
// TODO: the initial caps/num/scroll state a fresh boot reports is capture-pending: the real
// machine's records rule it; this constant is the one place to change.
pub const BOOT_TOGGLES: u8 = 0;

/// KEY_EVENT_RECORD: one key going down or up, as the public ABI lays it out (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyEventRecord {
    /// bKeyDown: a BOOL, nonzero for a keydown.
    pub key_down: u32,
    pub repeat_count: u16,
    pub virtual_key_code: u16,
    /// The un-prefixed make code; ENHANCED_KEY in the control-key state carries an E0 prefix.
    pub virtual_scan_code: u16,
    /// uChar: the character's UTF-16 unit, 0 for none.
    pub char: u16,
    pub control_key_state: u32,
}

const _: () = assert!(core::mem::size_of::<KeyEventRecord>() == 16);

/// INPUT_RECORD: an event's type, then the event (20 bytes: the union is 16, after a padded
/// word). Only key events have a producer here; another type a client writes (WriteConsoleInput)
/// keeps its event's 16 bytes in the key event's fields, as they lie in the union.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputRecord {
    pub event_type: u16,
    pub key: KeyEventRecord,
}

/// An INPUT_RECORD's size in the client's buffer.
pub const INPUT_RECORD_BYTES: usize = 20;

const _: () = assert!(core::mem::size_of::<InputRecord>() == INPUT_RECORD_BYTES);

impl InputRecord {
    /// A key event's record.
    pub const fn key(key: KeyEventRecord) -> Self {
        InputRecord {
            event_type: KEY_EVENT,
            key,
        }
    }

    /// The record's bytes, as the client's INPUT_RECORD array holds them (the padding zero).
    pub fn bytes(&self) -> [u8; INPUT_RECORD_BYTES] {
        let mut bytes = [0u8; INPUT_RECORD_BYTES];
        let key = &self.key;
        bytes[0..2].copy_from_slice(&self.event_type.to_le_bytes());
        bytes[4..8].copy_from_slice(&key.key_down.to_le_bytes());
        bytes[8..10].copy_from_slice(&key.repeat_count.to_le_bytes());
        bytes[10..12].copy_from_slice(&key.virtual_key_code.to_le_bytes());
        bytes[12..14].copy_from_slice(&key.virtual_scan_code.to_le_bytes());
        bytes[14..16].copy_from_slice(&key.char.to_le_bytes());
        bytes[16..20].copy_from_slice(&key.control_key_state.to_le_bytes());
        bytes
    }

    /// The record a client's INPUT_RECORD holds (the padding ignored).
    pub fn from_bytes(bytes: &[u8; INPUT_RECORD_BYTES]) -> Self {
        let half = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        InputRecord {
            event_type: half(0),
            key: KeyEventRecord {
                key_down: word(4),
                repeat_count: half(8),
                virtual_key_code: half(10),
                virtual_scan_code: half(12),
                char: half(14),
                control_key_state: word(16),
            },
        }
    }

    /// Whether the record is a key's going down.
    pub fn is_key_down(&self) -> bool {
        self.event_type == KEY_EVENT && self.key.key_down != 0
    }
}

/// The keyboard's lights, as the producer reaches them: the device that shows the toggles.
pub trait Lights {
    /// Show `toggles` ([`CAPS_LOCK`], [`NUM_LOCK`], [`SCROLL_LOCK`]).
    fn set(&mut self, toggles: u8);
}

/// No lights at all.
impl Lights for () {
    fn set(&mut self, _toggles: u8) {}
}

/// The prefix the next byte completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prefix {
    None,
    E0,
    /// E1, waiting for the sequence's first make code.
    E1,
    /// E1 and its first make code, waiting for the trailing byte.
    E1Then(u8),
}

/// The key-event producer: the controller's bytes in, key event records out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Producer {
    layout: &'static Layout,
    prefix: Prefix,
    /// The key-down set: one bit per virtual key, as the scan tables give it (before any
    /// conversion: the physical key).
    down: [u32; 8],
    toggles: u8,
}

impl Producer {
    /// A fresh producer over `layout`: no key down, the boot's toggles.
    pub const fn new(layout: &'static Layout) -> Self {
        Producer {
            layout,
            prefix: Prefix::None,
            down: [0; 8],
            toggles: BOOT_TOGGLES,
        }
    }

    /// The layout the producer walks.
    pub fn layout(&self) -> &'static Layout {
        self.layout
    }

    /// The live toggles ([`CAPS_LOCK`], [`NUM_LOCK`], [`SCROLL_LOCK`]).
    pub fn toggles(&self) -> u8 {
        self.toggles
    }

    /// Whether the key with scan-table virtual key `vk` is down.
    pub fn is_down(&self, vk: u8) -> bool {
        self.down[vk as usize / 32] & (1 << (vk % 32)) != 0
    }

    /// Take one controller byte: a byte that completes a key's event hands its record to `sink`;
    /// a toggle key's make shows the new toggles on `lights`. The keyboard's overrun report (0x00),
    /// the fake shifts it wraps extended keys in (E0 2A, E0 36, and their breaks), and codes no
    /// table names are dropped.
    pub fn event(
        &mut self,
        byte: u8,
        lights: &mut impl Lights,
        sink: &mut impl FnMut(KeyEventRecord),
    ) {
        let prefix = core::mem::replace(&mut self.prefix, Prefix::None);
        let make = byte & 0x7F;
        let down = byte & 0x80 == 0;
        match (prefix, byte) {
            // Pause: E1 1D 45 (its break E1 9D C5) is one key, reported with the trailing byte's
            // code; that byte is not Num Lock.
            (Prefix::E1, first) => self.prefix = Prefix::E1Then(first),
            (Prefix::E1Then(first), _) => {
                if let Some(vk) = self.layout.e1_key(first & 0x7F) {
                    let down = first & 0x80 == 0;
                    self.key(Origin::Base, vk, make, down, lights, sink);
                }
            }
            (_, 0xE0) => self.prefix = Prefix::E0,
            (_, 0xE1) => self.prefix = Prefix::E1,
            (_, 0x00) => {}
            (Prefix::E0, _) if make == 0x2A || make == 0x36 => {}
            (Prefix::E0, _) => {
                // An extended code the table does not name would be a flag-only event: dropped.
                if let Some(vk) = self.layout.e0_key(make) {
                    self.key(Origin::E0, vk, make, down, lights, sink);
                }
            }
            (Prefix::None, _) => match self.layout.scan[make as usize] {
                0 => {}
                vk => self.key(Origin::Base, vk, make, down, lights, sink),
            },
        }
    }

    /// One key's event: the key-down set and the toggles updated, then its record.
    fn key(
        &mut self,
        origin: Origin,
        vk: u8,
        scan: u8,
        down: bool,
        lights: &mut impl Lights,
        sink: &mut impl FnMut(KeyEventRecord),
    ) {
        let repeat = self.is_down(vk);
        let bit = 1 << (vk % 32);
        if down {
            self.down[vk as usize / 32] |= bit;
        } else {
            self.down[vk as usize / 32] &= !bit;
        }
        let mods = self.layout.modifier_bits(|vk| self.is_down(vk));
        let (reported, char) = self.layout.translate(origin, vk, mods, self.toggles);
        // A toggle flips on its key's first make, not on the keyboard's repeats nor on a break.
        let toggle = match reported {
            VK_CAPITAL => CAPS_LOCK,
            VK_NUMLOCK => NUM_LOCK,
            VK_SCROLL => SCROLL_LOCK,
            _ => 0,
        };
        if down && !repeat && toggle != 0 {
            self.toggles ^= toggle;
            lights.set(self.toggles);
        }
        sink(KeyEventRecord {
            key_down: down.into(),
            repeat_count: 1,
            virtual_key_code: record_key(reported).into(),
            virtual_scan_code: scan.into(),
            char: if down { char } else { 0 },
            control_key_state: self.control_key_state(origin == Origin::E0),
        });
    }

    /// The control-key state the live key-down set and toggles give: from the physical keys, never
    /// from the layout's modifier bits.
    // TODO: the control-key state an AltGr press reports (a synthesized LEFT_CTRL_PRESSED beside
    // RIGHT_ALT_PRESSED, or not) is capture-pending; unreachable on US, whose right Alt is Alt.
    fn control_key_state(&self, enhanced: bool) -> u32 {
        let keys = [
            (VK_RMENU, RIGHT_ALT_PRESSED),
            (VK_LMENU, LEFT_ALT_PRESSED),
            (VK_RCONTROL, RIGHT_CTRL_PRESSED),
            (VK_LCONTROL, LEFT_CTRL_PRESSED),
            (VK_LSHIFT, SHIFT_PRESSED),
            (VK_RSHIFT, SHIFT_PRESSED),
        ];
        let toggles = [
            (NUM_LOCK, NUMLOCK_ON),
            (SCROLL_LOCK, SCROLLLOCK_ON),
            (CAPS_LOCK, CAPSLOCK_ON),
        ];
        let pressed = keys
            .iter()
            .filter(|&&(vk, _)| self.is_down(vk))
            .fold(0, |state, &(_, bit)| state | bit);
        let on = toggles
            .iter()
            .filter(|&&(toggle, _)| self.toggles & toggle != 0)
            .fold(0, |state, &(_, bit)| state | bit);
        pressed | on | if enhanced { ENHANCED_KEY } else { 0 }
    }
}

/// The virtual key a record names: a modifier without its side. Only the key-state queries tell the
/// left and right modifier keys apart by virtual key; a console record names the generic Shift,
/// Ctrl or Alt key, and its control-key state says which side is down.
fn record_key(vk: u8) -> u8 {
    match vk {
        VK_LSHIFT | VK_RSHIFT => VK_SHIFT,
        VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
        VK_LMENU | VK_RMENU => VK_MENU,
        other => other,
    }
}

/// How many records the input buffer holds.
pub const INPUT_BUFFER_RECORDS: usize = 128;

/// The hook the input buffer consults for each record before it is kept: true keeps it.
pub type Filter = fn(&KeyEventRecord) -> bool;

/// The default filter: every record is kept.
pub fn keep_everything(_record: &KeyEventRecord) -> bool {
    true
}

/// What an append did with its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Append {
    /// Stored in a slot of its own.
    Stored,
    /// Folded into the last record, whose repeat count it raised.
    Coalesced,
    /// Refused by the filter.
    Filtered,
    /// Lost: the buffer is full.
    Dropped,
}

/// The console's input buffer: a ring of records, oldest first.
#[derive(Clone, Debug)]
pub struct InputBuffer {
    records: [InputRecord; INPUT_BUFFER_RECORDS],
    /// The oldest record's slot, and how many there are.
    first: usize,
    count: usize,
    filter: Filter,
}

impl InputBuffer {
    /// An empty buffer that keeps every record.
    pub const fn new() -> Self {
        InputBuffer {
            records: [InputRecord::key(KeyEventRecord {
                key_down: 0,
                repeat_count: 0,
                virtual_key_code: 0,
                virtual_scan_code: 0,
                char: 0,
                control_key_state: 0,
            }); INPUT_BUFFER_RECORDS],
            first: 0,
            count: 0,
            filter: keep_everything,
        }
    }

    /// How many records wait.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The `index`th waiting record, oldest first.
    pub fn get(&self, index: usize) -> Option<&InputRecord> {
        (index < self.count).then(|| &self.records[(self.first + index) % INPUT_BUFFER_RECORDS])
    }

    /// Consult `filter` for every record appended from now on.
    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = filter;
    }

    /// Append a key event: the filter first, then a keydown that repeats the last waiting record
    /// (a keydown of the same scan code, character and control-key state) raises that record's
    /// repeat count instead of taking a slot; anything else takes the next slot, if there is one.
    pub fn append(&mut self, key: KeyEventRecord) -> Append {
        if !(self.filter)(&key) {
            return Append::Filtered;
        }
        if key.key_down != 0 && self.count != 0 {
            let last = (self.first + self.count - 1) % INPUT_BUFFER_RECORDS;
            let held = &mut self.records[last].key;
            if held.key_down != 0
                && held.virtual_scan_code == key.virtual_scan_code
                && held.char == key.char
                && held.control_key_state == key.control_key_state
            {
                if let Some(count) = held.repeat_count.checked_add(key.repeat_count) {
                    held.repeat_count = count;
                    return Append::Coalesced;
                }
            }
        }
        if self.count == INPUT_BUFFER_RECORDS {
            return Append::Dropped;
        }
        self.records[(self.first + self.count) % INPUT_BUFFER_RECORDS] = InputRecord::key(key);
        self.count += 1;
        Append::Stored
    }

    /// Add a record a client wrote (WriteConsoleInput) as it is: no filter, no folding into the
    /// last record; false (nothing added) when the buffer is full.
    pub fn push(&mut self, record: InputRecord) -> bool {
        if self.count == INPUT_BUFFER_RECORDS {
            return false;
        }
        self.records[(self.first + self.count) % INPUT_BUFFER_RECORDS] = record;
        self.count += 1;
        true
    }

    /// Take the oldest record out of the buffer; none when it is empty.
    pub fn pop(&mut self) -> Option<InputRecord> {
        let record = *self.get(0)?;
        self.remove(1);
        Some(record)
    }

    /// The last waiting record, as the latest append left it.
    pub fn last(&self) -> Option<&InputRecord> {
        self.count.checked_sub(1).and_then(|index| self.get(index))
    }

    /// Remove up to `count` records, oldest first; how many were removed.
    pub fn remove(&mut self, count: usize) -> usize {
        let removed = count.min(self.count);
        self.first = (self.first + removed) % INPUT_BUFFER_RECORDS;
        self.count -= removed;
        removed
    }

    /// Empty the buffer.
    pub fn flush(&mut self) {
        self.first = 0;
        self.count = 0;
    }
}

impl Default for InputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Two buffers are equal when the same records wait in them, through the same filter.
impl PartialEq for InputBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count
            && core::ptr::fn_addr_eq(self.filter, other.filter)
            && (0..self.count).all(|index| self.get(index) == other.get(index))
    }
}

impl Eq for InputBuffer {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::console::layout::{
        US,
        VK_CANCEL,
        VK_CLEAR,
        VK_DECIMAL,
        VK_LEFT,
        VK_NUMPAD5,
        VK_PAUSE,
        VK_RETURN,
        VK_RIGHT,
    };

    /// Lights that keep every state they were asked to show.
    #[derive(Default)]
    struct Shown(Vec<u8>);

    impl Lights for Shown {
        fn set(&mut self, toggles: u8) {
            self.0.push(toggles);
        }
    }

    /// A producer over US, fed bytes, keeping its records and the lights it set.
    struct Feed {
        producer: Producer,
        lights: Shown,
        records: Vec<KeyEventRecord>,
    }

    impl Feed {
        fn new() -> Self {
            Feed {
                producer: Producer::new(&US),
                lights: Shown::default(),
                records: Vec::new(),
            }
        }

        /// Feed `bytes`; the records they completed.
        fn bytes(&mut self, bytes: &[u8]) -> Vec<KeyEventRecord> {
            let mut records = Vec::new();
            for &byte in bytes {
                self.producer
                    .event(byte, &mut self.lights, &mut |record| records.push(record));
            }
            self.records.extend(&records);
            records
        }

        /// (down, virtual key, scan, character, control-key state) of each record `bytes` complete.
        fn shape(&mut self, bytes: &[u8]) -> Vec<(bool, u16, u16, u16, u32)> {
            self.bytes(bytes)
                .iter()
                .map(|r| {
                    (
                        r.key_down != 0,
                        r.virtual_key_code,
                        r.virtual_scan_code,
                        r.char,
                        r.control_key_state,
                    )
                })
                .collect()
        }
    }

    fn key(down: bool, vk: u8, scan: u16, char: u16, state: u32) -> KeyEventRecord {
        KeyEventRecord {
            key_down: down.into(),
            repeat_count: 1,
            virtual_key_code: vk.into(),
            virtual_scan_code: scan,
            char,
            control_key_state: state,
        }
    }

    /// One keydown and one keyup per press, each counted once; the keydown carries the character,
    /// the keyup none.
    #[test]
    fn a_press_is_one_keydown_and_one_keyup() {
        let mut feed = Feed::new();
        assert_eq!(
            feed.bytes(&[0x1E, 0x9E]),
            [
                key(true, b'A', 0x1E, 'a' as u16, 0),
                key(false, b'A', 0x1E, 0, 0)
            ]
        );
        assert_eq!(
            feed.shape(&[0x3B, 0xBB]),
            [(true, 0x70, 0x3B, 0, 0), (false, 0x70, 0x3B, 0, 0)],
            "a key with no character"
        );
    }

    /// The control-key state is the live one: a shift's own keydown has it, its keyup not; the
    /// keys between see it.
    #[test]
    fn the_control_key_state_is_the_live_one() {
        let mut feed = Feed::new();
        assert_eq!(
            feed.shape(&[0x2A, 0x1E, 0x9E, 0xAA]),
            [
                (true, 0x10, 0x2A, 0, SHIFT_PRESSED),
                (true, b'A'.into(), 0x1E, 'A' as u16, SHIFT_PRESSED),
                (false, b'A'.into(), 0x1E, 0, SHIFT_PRESSED),
                (false, 0x10, 0x2A, 0, 0),
            ]
        );
        assert_eq!(
            feed.shape(&[0x1D, 0x2E, 0xAE, 0x9D]),
            [
                (true, 0x11, 0x1D, 0, LEFT_CTRL_PRESSED),
                (true, b'C'.into(), 0x2E, 0x03, LEFT_CTRL_PRESSED),
                (false, b'C'.into(), 0x2E, 0, LEFT_CTRL_PRESSED),
                (false, 0x11, 0x1D, 0, 0),
            ],
            "Ctrl+C is a record like any other"
        );
        // Right Ctrl and both Alts track apart in the state, under the generic virtual keys; Alt
        // gives no character.
        assert_eq!(
            feed.shape(&[0xE0, 0x1D, 0x38, 0x1E])
                .iter()
                .map(|r| (r.1, r.3, r.4))
                .collect::<Vec<_>>(),
            [
                (0x11, 0, RIGHT_CTRL_PRESSED | ENHANCED_KEY),
                (0x12, 0, RIGHT_CTRL_PRESSED | LEFT_ALT_PRESSED),
                (b'A'.into(), 0, RIGHT_CTRL_PRESSED | LEFT_ALT_PRESSED),
            ]
        );
    }

    /// E0 marks the extended keys: the record's scan is the un-prefixed code, ENHANCED_KEY its
    /// flag. Keypad Enter and Enter share a virtual key.
    #[test]
    fn extended_keys_carry_the_enhanced_bit() {
        let mut feed = Feed::new();
        assert_eq!(
            feed.shape(&[0xE0, 0x4D, 0xE0, 0xCD]),
            [
                (true, VK_RIGHT.into(), 0x4D, 0, ENHANCED_KEY),
                (false, VK_RIGHT.into(), 0x4D, 0, ENHANCED_KEY)
            ]
        );
        assert_eq!(
            feed.shape(&[0xE0, 0x1C, 0x1C]),
            [
                (true, VK_RETURN.into(), 0x1C, 0x0D, ENHANCED_KEY),
                (true, VK_RETURN.into(), 0x1C, 0x0D, 0)
            ]
        );
    }

    /// The overrun report, the fake shifts around extended keys, codes no table names, and E0
    /// codes the E0 table does not name are dropped; the prefix applies to one byte only.
    #[test]
    fn noise_is_dropped() {
        let mut feed = Feed::new();
        assert!(feed.bytes(&[0x00, 0xFF]).is_empty());
        assert!(feed.bytes(&[0x55, 0xD5, 0x7F]).is_empty());
        assert!(feed
            .bytes(&[0xE0, 0x2A, 0xE0, 0xAA, 0xE0, 0x36, 0xE0, 0xB6])
            .is_empty());
        assert!(feed.bytes(&[0xE0, 0x4C, 0xE0, 0x10]).is_empty());
        // Print Screen as the keyboard wraps it: only E0 37 is a key.
        assert_eq!(
            feed.shape(&[0xE0, 0x2A, 0xE0, 0x37, 0xE0, 0xB7, 0xE0, 0xAA]),
            [
                (true, 0x2C, 0x37, 0, ENHANCED_KEY),
                (false, 0x2C, 0x37, 0, ENHANCED_KEY)
            ]
        );
        assert_eq!(
            feed.shape(&[0xE0, 0x4B, 0x4B]),
            [
                (true, VK_LEFT.into(), 0x4B, 0, ENHANCED_KEY),
                (true, VK_LEFT.into(), 0x4B, 0, 0)
            ],
            "the keypad's own 4 after the gray one"
        );
        assert!(
            !feed.producer.is_down(0xA0),
            "no fake shift reached the down set"
        );
    }

    /// Pause: E1 1D 45 is one keydown, E1 9D C5 one keyup, scan 0x45 — neither byte 0x45 is Num
    /// Lock.
    #[test]
    fn pause_is_one_key() {
        let mut feed = Feed::new();
        assert_eq!(
            feed.shape(&[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5]),
            [
                (true, VK_PAUSE.into(), 0x45, 0, 0),
                (false, VK_PAUSE.into(), 0x45, 0, 0)
            ]
        );
        assert_eq!(feed.producer.toggles(), 0);
        assert!(feed.lights.0.is_empty());
        assert!(!feed.producer.is_down(0x1D) && !feed.producer.is_down(0xA2));
    }

    /// A toggle flips on its key's first make — not on the keyboard's repeats, not on a break —
    /// and each flip shows on the lights.
    #[test]
    fn toggles_flip_once_per_press_and_light() {
        let mut feed = Feed::new();
        let caps = feed.shape(&[0x3A, 0x3A, 0xBA]);
        assert_eq!(
            caps,
            [
                (true, 0x14, 0x3A, 0, CAPSLOCK_ON),
                (true, 0x14, 0x3A, 0, CAPSLOCK_ON),
                (false, 0x14, 0x3A, 0, CAPSLOCK_ON)
            ]
        );
        assert_eq!(feed.lights.0, [CAPS_LOCK]);
        assert_eq!(feed.shape(&[0x1E])[0].3, 'A' as u16);
        feed.bytes(&[0x9E, 0x45, 0xC5, 0x46, 0xC6]);
        assert_eq!(
            feed.lights.0,
            [
                CAPS_LOCK,
                CAPS_LOCK | NUM_LOCK,
                CAPS_LOCK | NUM_LOCK | SCROLL_LOCK
            ]
        );
        assert_eq!(
            feed.shape(&[0x1E])[0].4,
            CAPSLOCK_ON | NUMLOCK_ON | SCROLLLOCK_ON
        );
        feed.bytes(&[0x9E, 0x3A, 0xBA]);
        assert_eq!(feed.producer.toggles(), NUM_LOCK | SCROLL_LOCK);
        assert_eq!(feed.shape(&[0x1E])[0].3, 'a' as u16, "caps off again");
    }

    /// Num Lock resolves the keypad: on, its digits; off, its navigation keys.
    #[test]
    fn num_lock_resolves_the_keypad() {
        let mut feed = Feed::new();
        assert_eq!(
            feed.shape(&[0x4C, 0xCC]),
            [
                (true, VK_CLEAR.into(), 0x4C, 0, 0),
                (false, VK_CLEAR.into(), 0x4C, 0, 0)
            ]
        );
        feed.bytes(&[0x45, 0xC5]);
        assert_eq!(
            feed.shape(&[0x4C, 0xCC, 0x53]),
            [
                (true, VK_NUMPAD5.into(), 0x4C, '5' as u16, NUMLOCK_ON),
                (false, VK_NUMPAD5.into(), 0x4C, 0, NUMLOCK_ON),
                (true, VK_DECIMAL.into(), 0x53, '.' as u16, NUMLOCK_ON)
            ]
        );
    }

    /// Ctrl turns Num Lock into Pause (no toggle) and Scroll Lock into Break.
    #[test]
    fn ctrl_converts_the_lock_keys() {
        let mut feed = Feed::new();
        let shape = feed.shape(&[0x1D, 0x45, 0xC5, 0x46, 0xC6, 0x9D]);
        assert_eq!(
            shape.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
            [
                (true, 0x11),
                (true, VK_PAUSE.into()),
                (false, VK_PAUSE.into()),
                (true, VK_CANCEL.into()),
                (false, VK_CANCEL.into()),
                (false, 0x11)
            ]
        );
        assert_eq!(feed.producer.toggles(), 0);
    }

    fn down(scan: u16, char: u16) -> KeyEventRecord {
        key(true, b'A', scan, char, 0)
    }

    /// A keydown repeating the last waiting keydown raises its count; a keyup, a different key or
    /// state, or a keydown after a keyup takes a slot.
    #[test]
    fn the_buffer_coalesces_repeats() {
        let mut buffer = InputBuffer::new();
        assert_eq!(buffer.append(down(0x1E, 0x61)), Append::Stored);
        assert_eq!(buffer.append(down(0x1E, 0x61)), Append::Coalesced);
        assert_eq!(buffer.append(down(0x1E, 0x61)), Append::Coalesced);
        assert_eq!(buffer.count(), 1);
        assert_eq!(buffer.last().unwrap().key.repeat_count, 3);
        let up = key(false, b'A', 0x1E, 0, 0);
        assert_eq!(buffer.append(up), Append::Stored);
        assert_eq!(buffer.append(up), Append::Stored, "a keyup never merges");
        assert_eq!(buffer.append(down(0x1E, 0x61)), Append::Stored);
        let shifted = KeyEventRecord {
            control_key_state: SHIFT_PRESSED,
            ..down(0x1E, 0x41)
        };
        assert_eq!(buffer.append(shifted), Append::Stored);
        assert_eq!(
            buffer.append(KeyEventRecord {
                char: 0x61,
                ..shifted
            }),
            Append::Stored
        );
        assert_eq!(buffer.append(down(0x30, 0x62)), Append::Stored);
        assert_eq!(buffer.count(), 7);
        let first = buffer.get(0).unwrap();
        assert_eq!(first.event_type, KEY_EVENT);
        assert_eq!(buffer.get(7), None);
    }

    /// Reads take from the front, as many as asked and there are; a full buffer drops what comes.
    #[test]
    fn the_buffer_is_a_ring() {
        let mut buffer = InputBuffer::new();
        for scan in 0..3 {
            buffer.append(down(scan, 0));
        }
        assert_eq!(buffer.remove(2), 2);
        assert_eq!(buffer.count(), 1);
        assert_eq!(buffer.get(0).unwrap().key.virtual_scan_code, 2);
        assert_eq!(buffer.remove(5), 1);
        assert_eq!(buffer.remove(5), 0, "empty: none");
        for scan in 0..INPUT_BUFFER_RECORDS as u16 {
            assert_eq!(buffer.append(down(scan, 0)), Append::Stored);
        }
        assert_eq!(buffer.append(down(999, 0)), Append::Dropped);
        assert_eq!(
            buffer.append(down(INPUT_BUFFER_RECORDS as u16 - 1, 0)),
            Append::Coalesced,
            "a repeat still counts in a full buffer"
        );
        assert_eq!(buffer.count(), INPUT_BUFFER_RECORDS);
        assert_eq!(buffer.remove(1), 1);
        assert_eq!(buffer.append(down(500, 0)), Append::Stored);
        assert_eq!(buffer.last().unwrap().key.virtual_scan_code, 500);
        assert_eq!(buffer.get(0).unwrap().key.virtual_scan_code, 1);
        buffer.flush();
        assert_eq!((buffer.count(), buffer.last()), (0, None));
        assert_eq!(buffer, InputBuffer::new());
    }

    /// The filter seam: a refused record never reaches the buffer, nor coalesces.
    #[test]
    fn the_filter_decides_what_is_kept() {
        fn no_ctrl_c(record: &KeyEventRecord) -> bool {
            record.char != 0x03
        }
        let mut buffer = InputBuffer::new();
        assert!(keep_everything(&down(0x2E, 0x03)));
        buffer.set_filter(no_ctrl_c);
        assert_eq!(buffer.append(down(0x2E, 0x03)), Append::Filtered);
        assert_eq!(buffer.append(down(0x1E, 0x61)), Append::Stored);
        assert_eq!(buffer.count(), 1);
        assert_ne!(buffer, InputBuffer::new());
    }

    /// The record's bytes are INPUT_RECORD's: the type, its padding, then KEY_EVENT_RECORD.
    #[test]
    fn the_record_bytes_are_the_abis() {
        let record = InputRecord::key(KeyEventRecord {
            key_down: 1,
            repeat_count: 2,
            virtual_key_code: 0x41,
            virtual_scan_code: 0x1E,
            char: 0x0161,
            control_key_state: 0x0000_0190,
        });
        assert_eq!(
            record.bytes(),
            [1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0x41, 0, 0x1E, 0, 0x61, 0x01, 0x90, 0x01, 0, 0]
        );
        // The fields sit where the bytes put them.
        use core::mem::offset_of;
        assert_eq!(offset_of!(InputRecord, key), 4);
        assert_eq!(
            [
                offset_of!(KeyEventRecord, repeat_count),
                offset_of!(KeyEventRecord, virtual_key_code),
                offset_of!(KeyEventRecord, virtual_scan_code),
                offset_of!(KeyEventRecord, char),
                offset_of!(KeyEventRecord, control_key_state),
            ],
            [4, 6, 8, 10, 12]
        );
    }
}
