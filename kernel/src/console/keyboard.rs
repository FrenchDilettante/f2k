//! The keyboard decoder: scancode set 1 bytes in, console key events out.
//!
//! The 8042 controller translates the keyboard's own codes into set 1, so a key arrives as a make
//! code (bit 7 clear) or a break code (bit 7 set), optionally after an 0xE0 prefix that marks the
//! enhanced keys (the separate navigation block, the right-hand modifiers, keypad Enter and
//! slash). Pause sends the six-byte 0xE1 sequence and no break; Print Screen and the navigation
//! block wrap themselves in fake shift codes (0xE0 0x2A and friends) that are dropped.
//!
//! An event carries what a console input record does: down or up, the virtual-key code, the set 1
//! scan code, the UTF-16 character the key produces under the US layout (0 for none), and the
//! control-key state (modifiers, lock toggles, the enhanced-key flag) as it stands after the key.
//! Shift, Control and Alt report the generic virtual keys (VK_SHIFT, VK_CONTROL, VK_MENU); left and
//! right are told apart by the state bits and the enhanced flag.
//!
//! Character rules: letters follow Shift XOR Caps Lock; the other printing keys follow Shift; the
//! keypad digits print while Num Lock XOR Shift is on and act as navigation keys otherwise.
//! Control with a letter gives its control code (Ctrl+A is 0x01), with [ \ ] gives 0x1B-0x1D, with
//! Enter gives line feed and with Backspace gives 0x7F; Control with anything else, and Control
//! with Alt, give no character; Alt alone leaves the character as it is. A key's up event carries
//! the same character as its down event would.
//!
//! Quirk: the lock LEDs are not driven, and the Control/Alt character rules and Pause's scan code
//! are the layout as read, not yet pinned by a real-machine capture.

/// Control-key state bits (the console input record's).
pub const RIGHT_ALT_PRESSED: u32 = 0x0001;
pub const LEFT_ALT_PRESSED: u32 = 0x0002;
pub const RIGHT_CTRL_PRESSED: u32 = 0x0004;
pub const LEFT_CTRL_PRESSED: u32 = 0x0008;
pub const SHIFT_PRESSED: u32 = 0x0010;
pub const NUMLOCK_ON: u32 = 0x0020;
pub const SCROLLLOCK_ON: u32 = 0x0040;
pub const CAPSLOCK_ON: u32 = 0x0080;
pub const ENHANCED_KEY: u32 = 0x0100;

const CTRL_PRESSED: u32 = LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED;
const ALT_PRESSED: u32 = LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED;
const LOCKS: u32 = NUMLOCK_ON | SCROLLLOCK_ON | CAPSLOCK_ON;

/// Virtual-key codes.
pub const VK_BACK: u16 = 0x08;
pub const VK_TAB: u16 = 0x09;
pub const VK_CLEAR: u16 = 0x0C;
pub const VK_RETURN: u16 = 0x0D;
pub const VK_SHIFT: u16 = 0x10;
pub const VK_CONTROL: u16 = 0x11;
pub const VK_MENU: u16 = 0x12;
pub const VK_PAUSE: u16 = 0x13;
pub const VK_CAPITAL: u16 = 0x14;
pub const VK_ESCAPE: u16 = 0x1B;
pub const VK_SPACE: u16 = 0x20;
pub const VK_PRIOR: u16 = 0x21;
pub const VK_NEXT: u16 = 0x22;
pub const VK_END: u16 = 0x23;
pub const VK_HOME: u16 = 0x24;
pub const VK_LEFT: u16 = 0x25;
pub const VK_UP: u16 = 0x26;
pub const VK_RIGHT: u16 = 0x27;
pub const VK_DOWN: u16 = 0x28;
pub const VK_SNAPSHOT: u16 = 0x2C;
pub const VK_INSERT: u16 = 0x2D;
pub const VK_DELETE: u16 = 0x2E;
pub const VK_LWIN: u16 = 0x5B;
pub const VK_RWIN: u16 = 0x5C;
pub const VK_APPS: u16 = 0x5D;
pub const VK_NUMPAD0: u16 = 0x60;
pub const VK_MULTIPLY: u16 = 0x6A;
pub const VK_ADD: u16 = 0x6B;
pub const VK_SUBTRACT: u16 = 0x6D;
pub const VK_DECIMAL: u16 = 0x6E;
pub const VK_DIVIDE: u16 = 0x6F;
pub const VK_F1: u16 = 0x70;
pub const VK_F11: u16 = 0x7A;
pub const VK_F12: u16 = 0x7B;
pub const VK_NUMLOCK: u16 = 0x90;
pub const VK_SCROLL: u16 = 0x91;
pub const VK_OEM_1: u16 = 0xBA;
pub const VK_OEM_PLUS: u16 = 0xBB;
pub const VK_OEM_COMMA: u16 = 0xBC;
pub const VK_OEM_MINUS: u16 = 0xBD;
pub const VK_OEM_PERIOD: u16 = 0xBE;
pub const VK_OEM_2: u16 = 0xBF;
pub const VK_OEM_3: u16 = 0xC0;
pub const VK_OEM_4: u16 = 0xDB;
pub const VK_OEM_5: u16 = 0xDC;
pub const VK_OEM_6: u16 = 0xDD;
pub const VK_OEM_7: u16 = 0xDE;
pub const VK_OEM_102: u16 = 0xE2;

/// Set 1 make codes the decoder treats specially.
const SC_LCTRL: u8 = 0x1D;
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_LALT: u8 = 0x38;
const SC_CAPS: u8 = 0x3A;
const SC_NUMLOCK: u8 = 0x45;
const SC_SCROLL: u8 = 0x46;

const PREFIX_E0: u8 = 0xE0;
const PREFIX_E1: u8 = 0xE1;
const BREAK: u8 = 0x80;

/// The bytes Pause sends after its 0xE1 prefix.
const PAUSE_TAIL: [u8; 5] = [0x1D, 0x45, 0xE1, 0x9D, 0xC5];

/// One key event (see the module doc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyEvent {
    pub key_down: bool,
    pub virtual_key: u16,
    pub scan_code: u16,
    pub character: u16,
    pub control_state: u32,
}

/// What a plain (unprefixed) make code is.
#[derive(Clone, Copy)]
enum Plain {
    /// A key with a character: its virtual key, the character, and the shifted character.
    Printing(u16, u8, u8),
    /// A letter: its virtual key is its uppercase character.
    Letter(u8),
    /// A key without a character of its own.
    Silent(u16),
    /// A keypad key that is a digit (or the decimal point) under Num Lock and a navigation key
    /// otherwise: the digit's virtual key and character, the navigation virtual key.
    Keypad(u16, u8, u16),
}

/// The US layout's unprefixed make codes.
fn plain(code: u8) -> Option<Plain> {
    use Plain::*;
    Some(match code {
        0x01 => Printing(VK_ESCAPE, 0x1B, 0x1B),
        0x02..=0x0A => {
            let digit = b'1' + (code - 0x02);
            Printing(digit as u16, digit, b"!@#$%^&*("[(code - 0x02) as usize])
        }
        0x0B => Printing(b'0' as u16, b'0', b')'),
        0x0C => Printing(VK_OEM_MINUS, b'-', b'_'),
        0x0D => Printing(VK_OEM_PLUS, b'=', b'+'),
        0x0E => Printing(VK_BACK, 0x08, 0x08),
        0x0F => Printing(VK_TAB, b'\t', b'\t'),
        0x10..=0x19 => Letter(b"QWERTYUIOP"[(code - 0x10) as usize]),
        0x1A => Printing(VK_OEM_4, b'[', b'{'),
        0x1B => Printing(VK_OEM_6, b']', b'}'),
        0x1C => Printing(VK_RETURN, b'\r', b'\r'),
        SC_LCTRL => Silent(VK_CONTROL),
        0x1E..=0x26 => Letter(b"ASDFGHJKL"[(code - 0x1E) as usize]),
        0x27 => Printing(VK_OEM_1, b';', b':'),
        0x28 => Printing(VK_OEM_7, b'\'', b'"'),
        0x29 => Printing(VK_OEM_3, b'`', b'~'),
        SC_LSHIFT | SC_RSHIFT => Silent(VK_SHIFT),
        0x2B => Printing(VK_OEM_5, b'\\', b'|'),
        0x2C..=0x32 => Letter(b"ZXCVBNM"[(code - 0x2C) as usize]),
        0x33 => Printing(VK_OEM_COMMA, b',', b'<'),
        0x34 => Printing(VK_OEM_PERIOD, b'.', b'>'),
        0x35 => Printing(VK_OEM_2, b'/', b'?'),
        0x37 => Printing(VK_MULTIPLY, b'*', b'*'),
        SC_LALT => Silent(VK_MENU),
        0x39 => Printing(VK_SPACE, b' ', b' '),
        SC_CAPS => Silent(VK_CAPITAL),
        0x3B..=0x44 => Silent(VK_F1 + (code - 0x3B) as u16),
        SC_NUMLOCK => Silent(VK_NUMLOCK),
        SC_SCROLL => Silent(VK_SCROLL),
        0x47 => Keypad(VK_NUMPAD0 + 7, b'7', VK_HOME),
        0x48 => Keypad(VK_NUMPAD0 + 8, b'8', VK_UP),
        0x49 => Keypad(VK_NUMPAD0 + 9, b'9', VK_PRIOR),
        0x4A => Printing(VK_SUBTRACT, b'-', b'-'),
        0x4B => Keypad(VK_NUMPAD0 + 4, b'4', VK_LEFT),
        0x4C => Keypad(VK_NUMPAD0 + 5, b'5', VK_CLEAR),
        0x4D => Keypad(VK_NUMPAD0 + 6, b'6', VK_RIGHT),
        0x4E => Printing(VK_ADD, b'+', b'+'),
        0x4F => Keypad(VK_NUMPAD0 + 1, b'1', VK_END),
        0x50 => Keypad(VK_NUMPAD0 + 2, b'2', VK_DOWN),
        0x51 => Keypad(VK_NUMPAD0 + 3, b'3', VK_NEXT),
        0x52 => Keypad(VK_NUMPAD0, b'0', VK_INSERT),
        0x53 => Keypad(VK_DECIMAL, b'.', VK_DELETE),
        0x56 => Printing(VK_OEM_102, b'\\', b'|'),
        0x57 => Silent(VK_F11),
        0x58 => Silent(VK_F12),
        _ => return None,
    })
}

/// The US layout's 0xE0-prefixed make codes: the virtual key and the character (0 for none).
fn enhanced(code: u8) -> Option<(u16, u8)> {
    Some(match code {
        0x1C => (VK_RETURN, b'\r'),
        SC_LCTRL => (VK_CONTROL, 0),
        0x35 => (VK_DIVIDE, b'/'),
        0x37 => (VK_SNAPSHOT, 0),
        SC_LALT => (VK_MENU, 0),
        0x47 => (VK_HOME, 0),
        0x48 => (VK_UP, 0),
        0x49 => (VK_PRIOR, 0),
        0x4B => (VK_LEFT, 0),
        0x4D => (VK_RIGHT, 0),
        0x4F => (VK_END, 0),
        0x50 => (VK_DOWN, 0),
        0x51 => (VK_NEXT, 0),
        0x52 => (VK_INSERT, 0),
        0x53 => (VK_DELETE, 0),
        0x5B => (VK_LWIN, 0),
        0x5C => (VK_RWIN, 0),
        0x5D => (VK_APPS, 0),
        _ => return None,
    })
}

/// Where the decoder is in a multi-byte sequence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Prefix {
    None,
    E0,
    /// Inside Pause's sequence: how many of its tail bytes have arrived.
    Pause(usize),
}

/// The decoder (see the module doc): the sequence position, the modifier and lock state, and which
/// lock keys are held (a held lock key's typematic repeats must not toggle it again).
pub struct Decoder {
    prefix: Prefix,
    state: u32,
    shift_left: bool,
    shift_right: bool,
    locks_held: u8,
}

impl Decoder {
    /// A decoder with no modifiers held and the lock toggles `locks` (a mask of the `*_ON` bits).
    pub const fn new(locks: u32) -> Self {
        Self {
            prefix: Prefix::None,
            state: locks & LOCKS,
            shift_left: false,
            shift_right: false,
            locks_held: 0,
        }
    }

    /// Feed one byte from the controller; a completed key comes back as its event.
    pub fn feed(&mut self, byte: u8) -> Option<KeyEvent> {
        match self.prefix {
            Prefix::Pause(seen) => {
                // Anything off the script abandons the sequence.
                if byte != PAUSE_TAIL[seen] {
                    self.prefix = Prefix::None;
                    return None;
                }
                if seen + 1 < PAUSE_TAIL.len() {
                    self.prefix = Prefix::Pause(seen + 1);
                    return None;
                }
                self.prefix = Prefix::None;
                Some(KeyEvent {
                    key_down: true,
                    virtual_key: VK_PAUSE,
                    scan_code: SC_NUMLOCK as u16,
                    character: 0,
                    control_state: self.state,
                })
            }
            Prefix::E0 => {
                self.prefix = Prefix::None;
                self.enhanced_key(byte & !BREAK, byte & BREAK == 0)
            }
            Prefix::None => match byte {
                PREFIX_E0 => {
                    self.prefix = Prefix::E0;
                    None
                }
                PREFIX_E1 => {
                    self.prefix = Prefix::Pause(0);
                    None
                }
                _ => self.plain_key(byte & !BREAK, byte & BREAK == 0),
            },
        }
    }

    fn plain_key(&mut self, code: u8, down: bool) -> Option<KeyEvent> {
        let key = plain(code)?;
        match code {
            SC_LSHIFT => self.shift_left = down,
            SC_RSHIFT => self.shift_right = down,
            SC_LCTRL => set(&mut self.state, LEFT_CTRL_PRESSED, down),
            SC_LALT => set(&mut self.state, LEFT_ALT_PRESSED, down),
            SC_CAPS => self.toggle(0, CAPSLOCK_ON, down),
            SC_NUMLOCK => self.toggle(1, NUMLOCK_ON, down),
            SC_SCROLL => self.toggle(2, SCROLLLOCK_ON, down),
            _ => {}
        }
        set(
            &mut self.state,
            SHIFT_PRESSED,
            self.shift_left || self.shift_right,
        );
        let shifted = self.state & SHIFT_PRESSED != 0;
        let (virtual_key, character) = match key {
            Plain::Printing(vk, normal, shifted_char) => (
                vk,
                self.with_control(vk, if shifted { shifted_char } else { normal }),
            ),
            Plain::Letter(upper) => {
                let caps = self.state & CAPSLOCK_ON != 0;
                let character = if shifted != caps {
                    upper
                } else {
                    upper.to_ascii_lowercase()
                };
                (upper as u16, self.with_control(upper as u16, character))
            }
            Plain::Silent(vk) => (vk, 0),
            Plain::Keypad(digit_vk, digit, navigation_vk) => {
                if (self.state & NUMLOCK_ON != 0) != shifted {
                    (digit_vk, digit)
                } else {
                    (navigation_vk, 0)
                }
            }
        };
        Some(KeyEvent {
            key_down: down,
            virtual_key,
            scan_code: code as u16,
            character: character as u16,
            control_state: self.state,
        })
    }

    fn enhanced_key(&mut self, code: u8, down: bool) -> Option<KeyEvent> {
        // The fake shifts the navigation block and Print Screen wrap themselves in.
        if code == SC_LSHIFT || code == SC_RSHIFT {
            return None;
        }
        let (virtual_key, character) = enhanced(code)?;
        match code {
            SC_LCTRL => set(&mut self.state, RIGHT_CTRL_PRESSED, down),
            SC_LALT => set(&mut self.state, RIGHT_ALT_PRESSED, down),
            _ => {}
        }
        let character = self.with_control(virtual_key, character);
        Some(KeyEvent {
            key_down: down,
            virtual_key,
            scan_code: code as u16,
            character: character as u16,
            control_state: self.state | ENHANCED_KEY,
        })
    }

    /// Toggle lock `bit` on a press that is not a repeat; `index` names the lock's held flag.
    fn toggle(&mut self, index: u8, bit: u32, down: bool) {
        let held = self.locks_held & (1 << index) != 0;
        if down && !held {
            self.state ^= bit;
        }
        if down {
            self.locks_held |= 1 << index;
        } else {
            self.locks_held &= !(1 << index);
        }
    }

    /// The character a key gives under the Control/Alt rules (see the module doc).
    fn with_control(&self, virtual_key: u16, character: u8) -> u8 {
        let ctrl = self.state & CTRL_PRESSED != 0;
        let alt = self.state & ALT_PRESSED != 0;
        if !ctrl {
            return character;
        }
        if alt {
            return 0;
        }
        match virtual_key {
            0x41..=0x5A => virtual_key as u8 - 0x40,
            VK_OEM_4 => 0x1B,
            VK_OEM_5 => 0x1C,
            VK_OEM_6 => 0x1D,
            VK_RETURN => b'\n',
            VK_BACK => 0x7F,
            _ => 0,
        }
    }
}

fn set(state: &mut u32, bit: u32, on: bool) {
    if on {
        *state |= bit;
    } else {
        *state &= !bit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `bytes`, collecting the events.
    fn feed(decoder: &mut Decoder, bytes: &[u8]) -> Vec<KeyEvent> {
        bytes.iter().filter_map(|&b| decoder.feed(b)).collect()
    }

    fn event(down: bool, vk: u16, scan: u16, character: u8, state: u32) -> KeyEvent {
        KeyEvent {
            key_down: down,
            virtual_key: vk,
            scan_code: scan,
            character: character as u16,
            control_state: state,
        }
    }

    #[test]
    fn a_letter_goes_down_and_up() {
        let mut decoder = Decoder::new(0);
        assert_eq!(
            feed(&mut decoder, &[0x23, 0xA3]),
            vec![
                event(true, 0x48, 0x23, b'h', 0),
                event(false, 0x48, 0x23, b'h', 0)
            ]
        );
    }

    #[test]
    fn shift_capitalises_and_reports_itself() {
        let mut decoder = Decoder::new(0);
        assert_eq!(
            feed(&mut decoder, &[0x2A, 0x1E, 0x9E, 0xAA]),
            vec![
                event(true, VK_SHIFT, 0x2A, 0, SHIFT_PRESSED),
                event(true, 0x41, 0x1E, b'A', SHIFT_PRESSED),
                event(false, 0x41, 0x1E, b'A', SHIFT_PRESSED),
                event(false, VK_SHIFT, 0x2A, 0, 0),
            ]
        );
    }

    #[test]
    fn either_shift_holds_the_state() {
        let mut decoder = Decoder::new(0);
        feed(&mut decoder, &[0x2A, 0x36, 0xAA]);
        assert_eq!(decoder.state, SHIFT_PRESSED);
        feed(&mut decoder, &[0xB6]);
        assert_eq!(decoder.state, 0);
    }

    #[test]
    fn shifted_printing_keys_use_the_us_layout() {
        let mut decoder = Decoder::new(0);
        let typed: Vec<u8> = [
            0x02, 0x0B, 0x0C, 0x0D, 0x1A, 0x1B, 0x27, 0x28, 0x29, 0x2B, 0x33,
        ]
        .iter()
        .flat_map(|&code| feed(&mut decoder, &[0x2A, code, code | 0x80, 0xAA]))
        .filter(|e| e.key_down && e.character != 0)
        .map(|e| e.character as u8)
        .collect();
        assert_eq!(typed, b"!)_+{}:\"~|<");
    }

    #[test]
    fn unshifted_row_types_as_written() {
        let mut decoder = Decoder::new(0);
        let codes = [
            0x29, 0x02, 0x03, 0x0B, 0x0C, 0x0D, 0x10, 0x1A, 0x1B, 0x2B, 0x27, 0x28, 0x35,
        ];
        let typed: Vec<u8> = codes
            .iter()
            .filter_map(|&code| decoder.feed(code))
            .map(|e| e.character as u8)
            .collect();
        assert_eq!(typed, b"`120-=q[]\\;'/");
    }

    #[test]
    fn caps_lock_toggles_once_per_press_and_inverts_shift_for_letters_only() {
        let mut decoder = Decoder::new(0);
        // Press with two typematic repeats, then release: one toggle.
        feed(&mut decoder, &[0x3A, 0x3A, 0x3A, 0xBA]);
        assert_eq!(decoder.state, CAPSLOCK_ON);
        let letter = decoder.feed(0x1E).unwrap();
        assert_eq!(letter.character, b'A' as u16);
        assert_eq!(letter.control_state, CAPSLOCK_ON);
        let digit = decoder.feed(0x02).unwrap();
        assert_eq!(digit.character, b'1' as u16);
        // Shift with Caps Lock: lowercase.
        let shifted = feed(&mut decoder, &[0x2A, 0x1E]);
        assert_eq!(shifted[1].character, b'a' as u16);
        // A second press turns it off.
        feed(&mut decoder, &[0xAA, 0x3A, 0xBA]);
        assert_eq!(decoder.state, 0);
    }

    #[test]
    fn initial_locks_come_from_the_constructor() {
        let decoder = Decoder::new(NUMLOCK_ON | 0x0010);
        assert_eq!(decoder.state, NUMLOCK_ON, "only lock bits are taken");
    }

    #[test]
    fn the_keypad_follows_num_lock_xor_shift() {
        let mut decoder = Decoder::new(NUMLOCK_ON);
        assert_eq!(
            decoder.feed(0x47),
            Some(event(true, VK_NUMPAD0 + 7, 0x47, b'7', NUMLOCK_ON))
        );
        assert_eq!(
            decoder.feed(0x53),
            Some(event(true, VK_DECIMAL, 0x53, b'.', NUMLOCK_ON))
        );
        let mut decoder = Decoder::new(0);
        assert_eq!(decoder.feed(0x47), Some(event(true, VK_HOME, 0x47, 0, 0)));
        // Shift inverts.
        let shifted = feed(&mut decoder, &[0x2A, 0x47]);
        assert_eq!(shifted[1].character, b'7' as u16);
        // The operators ignore Num Lock.
        assert_eq!(decoder.feed(0x4E).unwrap().character, b'+' as u16);
    }

    #[test]
    fn enhanced_keys_carry_the_flag() {
        let mut decoder = Decoder::new(NUMLOCK_ON);
        assert_eq!(
            feed(&mut decoder, &[0xE0, 0x48, 0xE0, 0xC8]),
            vec![
                event(true, VK_UP, 0x48, 0, NUMLOCK_ON | ENHANCED_KEY),
                event(false, VK_UP, 0x48, 0, NUMLOCK_ON | ENHANCED_KEY),
            ]
        );
        assert_eq!(
            feed(&mut decoder, &[0xE0, 0x1C]),
            vec![event(
                true,
                VK_RETURN,
                0x1C,
                b'\r',
                NUMLOCK_ON | ENHANCED_KEY
            )]
        );
        assert_eq!(
            feed(&mut decoder, &[0xE0, 0x35]),
            vec![event(
                true,
                VK_DIVIDE,
                0x35,
                b'/',
                NUMLOCK_ON | ENHANCED_KEY
            )]
        );
    }

    #[test]
    fn fake_shifts_around_navigation_keys_are_dropped() {
        // Insert with Num Lock on, as the keyboard sends it: a fake left-shift break first.
        let mut decoder = Decoder::new(NUMLOCK_ON);
        let events = feed(
            &mut decoder,
            &[0xE0, 0xAA, 0xE0, 0x52, 0xE0, 0xD2, 0xE0, 0x2A],
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].virtual_key, VK_INSERT);
        assert_eq!(decoder.state, NUMLOCK_ON);
        // Print Screen.
        let events = feed(&mut decoder, &[0xE0, 0x2A, 0xE0, 0x37]);
        assert_eq!(
            events,
            vec![event(true, VK_SNAPSHOT, 0x37, 0, NUMLOCK_ON | ENHANCED_KEY)]
        );
    }

    #[test]
    fn right_hand_modifiers_set_their_own_bits() {
        let mut decoder = Decoder::new(0);
        let events = feed(&mut decoder, &[0xE0, 0x1D, 0xE0, 0x38]);
        assert_eq!(
            events,
            vec![
                event(true, VK_CONTROL, 0x1D, 0, RIGHT_CTRL_PRESSED | ENHANCED_KEY),
                event(
                    true,
                    VK_MENU,
                    0x38,
                    0,
                    RIGHT_CTRL_PRESSED | RIGHT_ALT_PRESSED | ENHANCED_KEY
                ),
            ]
        );
        feed(&mut decoder, &[0xE0, 0x9D, 0xE0, 0xB8]);
        assert_eq!(decoder.state, 0);
        feed(&mut decoder, &[0x1D, 0x38]);
        assert_eq!(decoder.state, LEFT_CTRL_PRESSED | LEFT_ALT_PRESSED);
    }

    #[test]
    fn control_gives_control_codes() {
        let mut decoder = Decoder::new(0);
        decoder.feed(0x1D);
        let codes: Vec<u16> = [0x2E, 0x1E, 0x2C, 0x1A, 0x2B, 0x1B, 0x1C, 0x0E, 0x02]
            .iter()
            .map(|&code| decoder.feed(code).unwrap().character)
            .collect();
        // Ctrl+C, A, Z, [, \, ], Enter, Backspace, 1.
        assert_eq!(
            codes,
            vec![0x03, 0x01, 0x1A, 0x1B, 0x1C, 0x1D, 0x0A, 0x7F, 0]
        );
        // With Alt as well: nothing.
        decoder.feed(0x38);
        assert_eq!(decoder.feed(0x2E).unwrap().character, 0);
    }

    #[test]
    fn alt_alone_keeps_the_character() {
        let mut decoder = Decoder::new(0);
        let events = feed(&mut decoder, &[0x38, 0x23]);
        assert_eq!(events[1], event(true, 0x48, 0x23, b'h', LEFT_ALT_PRESSED));
    }

    #[test]
    fn pause_is_one_down_event() {
        let mut decoder = Decoder::new(0);
        let events = feed(&mut decoder, &[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5]);
        assert_eq!(events, vec![event(true, VK_PAUSE, 0x45, 0, 0)]);
        // An interrupted sequence is abandoned; the next key decodes normally.
        let events = feed(&mut decoder, &[0xE1, 0x1D, 0x23]);
        assert_eq!(events, vec![]);
        assert_eq!(decoder.feed(0x23).unwrap().character, b'h' as u16);
    }

    #[test]
    fn function_and_silent_keys_have_no_character() {
        let mut decoder = Decoder::new(0);
        assert_eq!(decoder.feed(0x3B), Some(event(true, VK_F1, 0x3B, 0, 0)));
        assert_eq!(decoder.feed(0x44), Some(event(true, VK_F1 + 9, 0x44, 0, 0)));
        assert_eq!(decoder.feed(0x57), Some(event(true, VK_F11, 0x57, 0, 0)));
        assert_eq!(decoder.feed(0x58), Some(event(true, VK_F12, 0x58, 0, 0)));
    }

    #[test]
    fn unknown_codes_are_dropped() {
        let mut decoder = Decoder::new(0);
        assert_eq!(feed(&mut decoder, &[0x59, 0x7F, 0xE0, 0x10]), vec![]);
        // The decoder is not left inside a prefix.
        assert_eq!(decoder.feed(0x23).unwrap().character, b'h' as u16);
    }

    #[test]
    fn enter_space_tab_backspace_escape() {
        let mut decoder = Decoder::new(0);
        let typed: Vec<(u16, u16)> = [0x1C, 0x39, 0x0F, 0x0E, 0x01]
            .iter()
            .map(|&code| {
                let e = decoder.feed(code).unwrap();
                (e.virtual_key, e.character)
            })
            .collect();
        assert_eq!(
            typed,
            vec![
                (VK_RETURN, 0x0D),
                (VK_SPACE, 0x20),
                (VK_TAB, 0x09),
                (VK_BACK, 0x08),
                (VK_ESCAPE, 0x1B)
            ]
        );
    }
}
