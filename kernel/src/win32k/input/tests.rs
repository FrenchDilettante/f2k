//! The input path's host tests: the keyinput fixture's sections, as its procedure records them
//! (each case's expected records are the capture's), the keyboard's bytes, the key states, and the
//! window a key message is bound to as it is read.

use rtl::user::{INPUT_KEYBOARD, WM_USER};

use super::*;
use crate::win32k::class;
use crate::win32k::focus::{active_window, focus_window, set_focus, set_foreground_window};
use crate::win32k::queue::rig::{
    all,
    deliver,
    manager,
    msg_of,
    popup,
    read as read_queue,
    thread,
    window_at,
};
use crate::win32k::queue::{end_sent, take, Filter, QueuePump, Taken};
use crate::win32k::window::{Hwnd, WindowManager, WS_CHILD, WS_VISIBLE};

const DOWN: u32 = 0;
const UP: u32 = KEYEVENTF_KEYUP;
const EXT: u32 = KEYEVENTF_EXTENDEDKEY;

/// What the keyinput fixture's procedure records of a message: the message, wParam, lParam, and
/// the down bits of Shift, Ctrl, Alt and the message's own key (none for a character), as
/// GetKeyState reads them inside the procedure.
type Record = (u32, u32, u32, bool, bool, bool, Option<bool>);

/// The keyinput fixture's window: a popup of its own thread, the foreground and focus window.
struct Rig {
    m: &'static mut WindowManager,
    atom: class::Atom,
    t: ThreadId,
    window: Hwnd,
}

impl Rig {
    fn new() -> Rig {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x40);
        let window = popup(m, atom, t);
        let id = m.windows.window_from_handle(window).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        assert!(set_foreground_window(
            windows,
            classes,
            t,
            id,
            &mut QueuePump
        ));
        set_focus(windows, classes, t, Some(id), &mut QueuePump);
        let mut rig = Rig { m, atom, t, window };
        rig.pump();
        assert_eq!(focus_window(&rig.m.windows, t), Some(id));
        rig
    }

    /// The fixture's loop: every message read out (the sent ones answered), each key-down
    /// translated, each key and character message recorded with the thread's key state.
    fn pump(&mut self) -> Vec<Record> {
        let mut got = Vec::new();
        loop {
            match read_queue(self.m, self.t, &all(), 0) {
                Taken::Sent(_) => assert!(end_sent(&mut self.m.windows, self.t, 0)),
                Taken::Message(msg) => {
                    let keys = self.m.windows.thread(self.t).keys;
                    let key = matches!(
                        msg.message,
                        WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP
                    );
                    if key || matches!(msg.message, WM_CHAR | WM_SYSCHAR) {
                        got.push((
                            msg.message,
                            msg.wparam,
                            msg.lparam as u32,
                            keys.key_state(VK_SHIFT) & 0x8000 != 0,
                            keys.key_state(VK_CONTROL) & 0x8000 != 0,
                            keys.key_state(VK_MENU) & 0x8000 != 0,
                            key.then(|| keys.key_state(msg.wparam as u8) & 0x8000 != 0),
                        ));
                    }
                    translate(&mut self.m.windows, self.t, &msg, 0).unwrap();
                }
                Taken::Nothing { .. } => return got,
            }
        }
    }

    /// SendInput of the strokes (virtual key, scan code, flags), nothing read.
    fn type_ahead(&mut self, strokes: &[(u16, u16, u32)]) {
        for &(vk, scan, flags) in strokes {
            let input = Input {
                kind: INPUT_KEYBOARD,
                vk,
                scan,
                flags,
                ..Input::default()
            };
            let stroke = Keystroke::of_input(&input, &self.m.windows.input.keys).unwrap();
            key_event(&mut self.m.windows, stroke, 0);
        }
    }

    /// SendInput of the strokes, then the fixture's loop.
    fn send(&mut self, strokes: &[(u16, u16, u32)]) -> Vec<Record> {
        self.type_ahead(strokes);
        self.pump()
    }

    /// A visible child window of the popup's, at `x`: the typeahead section's A and B.
    fn child(&mut self, x: i32) -> Hwnd {
        let child = window_at(
            self.m,
            self.atom,
            self.t,
            WS_CHILD | WS_VISIBLE,
            self.window,
            x,
            10,
            60,
            40,
        );
        self.pump();
        child
    }

    /// SetFocus: the focus moved to the window `hwnd` (0: taken away), the messages it sent
    /// delivered.
    fn focus(&mut self, hwnd: Hwnd) {
        let target = (hwnd != 0).then(|| self.m.windows.window_from_handle(hwnd).unwrap());
        let WindowManager {
            windows, classes, ..
        } = &mut *self.m;
        set_focus(windows, classes, self.t, target, &mut QueuePump);
        deliver(self.m, self.t);
    }

    /// The fixture's loop, each key and character message read noted with its window.
    fn reads(&mut self) -> Vec<(u32, Hwnd)> {
        let mut got = Vec::new();
        loop {
            match read_queue(self.m, self.t, &all(), 0) {
                Taken::Sent(_) => assert!(end_sent(&mut self.m.windows, self.t, 0)),
                Taken::Message(msg) => {
                    if matches!(
                        msg.message,
                        WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP | WM_CHAR | WM_SYSCHAR
                    ) {
                        got.push((msg.message, msg.hwnd));
                    }
                    translate(&mut self.m.windows, self.t, &msg, 0).unwrap();
                }
                Taken::Nothing { .. } => return got,
            }
        }
    }

    /// One read with a filter for the window `hwnd` (0: any) and the range `min` to `max`, taking
    /// out what it finds (not translated): its message and window.
    fn read_filtered(&mut self, hwnd: Hwnd, min: u32, max: u32) -> Option<(u32, Hwnd)> {
        let filter = Filter::new(hwnd, min, max, 0);
        match take(&mut self.m.windows, self.t, &filter, true, 0).unwrap() {
            Taken::Message(msg) => Some((msg.message, msg.hwnd)),
            _ => None,
        }
    }

    /// The keyboard's bytes, then the fixture's loop.
    fn type_bytes(&mut self, bytes: &[u8]) -> Vec<Record> {
        for &byte in bytes {
            key_byte(&mut self.m.windows, byte, 0);
        }
        self.pump()
    }
}

/// A key message's record, as the capture prints it.
fn key(message: u32, wparam: u32, lparam: u32, mods: (bool, bool, bool), down: bool) -> Record {
    (message, wparam, lparam, mods.0, mods.1, mods.2, Some(down))
}

/// A character message's record.
fn chr(message: u32, wparam: u32, lparam: u32, mods: (bool, bool, bool)) -> Record {
    (message, wparam, lparam, mods.0, mods.1, mods.2, None)
}

const NONE: (bool, bool, bool) = (false, false, false);
const SHIFTED: (bool, bool, bool) = (true, false, false);
const CTRLED: (bool, bool, bool) = (false, true, false);
const ALTED: (bool, bool, bool) = (false, false, true);

/// A plain key's press and release, as the capture records it: WM_KEYDOWN, its character,
/// WM_KEYUP.
fn plain(vk: u32, scan: u32, character: u32) -> Vec<Record> {
    let lparam = 1 | scan << 16;
    std::vec![
        key(WM_KEYDOWN, vk, lparam, NONE, true),
        chr(WM_CHAR, character, lparam, NONE),
        key(WM_KEYUP, vk, lparam | 0xC000_0000, NONE, false),
    ]
}

/// The letters section: 'A', Shift+A, '2'.
#[test]
fn letters_and_shift() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.send(&[(0x41, 0x1E, DOWN), (0x41, 0x1E, UP)]),
        plain(0x41, 0x1E, 0x61)
    );
    assert_eq!(
        rig.send(&[
            (0x10, 0x2A, DOWN),
            (0x41, 0x1E, DOWN),
            (0x41, 0x1E, UP),
            (0x10, 0x2A, UP),
        ]),
        [
            key(WM_KEYDOWN, 0x10, 0x002A_0001, SHIFTED, true),
            key(WM_KEYDOWN, 0x41, 0x001E_0001, SHIFTED, true),
            chr(WM_CHAR, 0x41, 0x001E_0001, SHIFTED),
            key(WM_KEYUP, 0x41, 0xC01E_0001, SHIFTED, false),
            key(WM_KEYUP, 0x10, 0xC02A_0001, NONE, false),
        ]
    );
    assert_eq!(
        rig.send(&[(0x32, 0x03, DOWN), (0x32, 0x03, UP)]),
        plain(0x32, 0x03, 0x32)
    );
}

/// The symbols section: Shift+'=' is '+', and the keypad's operators make theirs, the divide
/// extended.
#[test]
fn symbols_and_the_keypad() {
    let mut rig = Rig::new();
    let shift_equals = rig.send(&[
        (0x10, 0x2A, DOWN),
        (0xBB, 0x0D, DOWN),
        (0xBB, 0x0D, UP),
        (0x10, 0x2A, UP),
    ]);
    assert_eq!(shift_equals[2], chr(WM_CHAR, 0x2B, 0x000D_0001, SHIFTED));
    for (vk, scan, character) in [
        (0xBB, 0x0D, 0x3D),
        (0xBE, 0x34, 0x2E),
        (0x6B, 0x4E, 0x2B),
        (0x6D, 0x4A, 0x2D),
        (0x6A, 0x37, 0x2A),
        (0x6E, 0x53, 0x2E),
    ] {
        assert_eq!(
            rig.send(&[(vk, scan, DOWN), (vk, scan, UP)]),
            plain(u32::from(vk), u32::from(scan), character)
        );
    }
    assert_eq!(
        rig.send(&[(0x6F, 0x35, DOWN | EXT), (0x6F, 0x35, UP | EXT)]),
        [
            key(WM_KEYDOWN, 0x6F, 0x0135_0001, NONE, true),
            chr(WM_CHAR, 0x2F, 0x0135_0001, NONE),
            key(WM_KEYUP, 0x6F, 0xC135_0001, NONE, false),
        ]
    );
}

/// The control section: Enter, Escape, Backspace and Tab make their control characters, and
/// Ctrl+C makes 3.
#[test]
fn control_characters() {
    let mut rig = Rig::new();
    for (vk, scan) in [(0x0D, 0x1C), (0x1B, 0x01), (0x08, 0x0E), (0x09, 0x0F)] {
        assert_eq!(
            rig.send(&[(vk, scan, DOWN), (vk, scan, UP)]),
            plain(u32::from(vk), u32::from(scan), u32::from(vk))
        );
    }
    assert_eq!(
        rig.send(&[
            (0x11, 0x1D, DOWN),
            (0x43, 0x2E, DOWN),
            (0x43, 0x2E, UP),
            (0x11, 0x1D, UP),
        ]),
        [
            key(WM_KEYDOWN, 0x11, 0x001D_0001, CTRLED, true),
            key(WM_KEYDOWN, 0x43, 0x002E_0001, CTRLED, true),
            chr(WM_CHAR, 0x03, 0x002E_0001, CTRLED),
            key(WM_KEYUP, 0x43, 0xC02E_0001, CTRLED, false),
            key(WM_KEYUP, 0x11, 0xC01D_0001, NONE, false),
        ]
    );
}

/// The alt section: Alt+F is system keys and WM_SYSCHAR 'f', Alt's release after it a WM_KEYUP;
/// Alt alone is WM_SYSKEYDOWN and WM_SYSKEYUP.
#[test]
fn alt_makes_system_keys() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.send(&[
            (0x12, 0x38, DOWN),
            (0x46, 0x21, DOWN),
            (0x46, 0x21, UP),
            (0x12, 0x38, UP),
        ]),
        [
            key(WM_SYSKEYDOWN, 0x12, 0x2038_0001, ALTED, true),
            key(WM_SYSKEYDOWN, 0x46, 0x2021_0001, ALTED, true),
            chr(WM_SYSCHAR, 0x66, 0x2021_0001, ALTED),
            key(WM_SYSKEYUP, 0x46, 0xE021_0001, ALTED, false),
            key(WM_KEYUP, 0x12, 0xC038_0001, NONE, false),
        ]
    );
    assert_eq!(
        rig.send(&[(0x12, 0x38, DOWN), (0x12, 0x38, UP)]),
        [
            key(WM_SYSKEYDOWN, 0x12, 0x2038_0001, ALTED, true),
            key(WM_SYSKEYUP, 0x12, 0xC038_0001, NONE, false),
        ]
    );
}

/// The extended section: the arrows and Delete carry the extended bit and make no character.
#[test]
fn extended_keys() {
    let mut rig = Rig::new();
    for (vk, scan) in [
        (0x25, 0x4B),
        (0x27, 0x4D),
        (0x26, 0x48),
        (0x28, 0x50),
        (0x2E, 0x53),
    ] {
        let lparam = 0x0100_0001 | u32::from(scan) << 16;
        assert_eq!(
            rig.send(&[(vk, scan, DOWN | EXT), (vk, scan, UP | EXT)]),
            [
                key(WM_KEYDOWN, u32::from(vk), lparam, NONE, true),
                key(WM_KEYUP, u32::from(vk), lparam | 0xC000_0000, NONE, false),
            ]
        );
    }
}

/// The scancode section: a scan code alone names 'A' through the layout; a virtual key with no
/// scan code keeps 0 in lParam.
#[test]
fn scan_codes_and_virtual_keys() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.send(&[
            (0, 0x1E, DOWN | KEYEVENTF_SCANCODE),
            (0, 0x1E, UP | KEYEVENTF_SCANCODE)
        ]),
        plain(0x41, 0x1E, 0x61)
    );
    assert_eq!(
        rig.send(&[(0x41, 0, DOWN), (0x41, 0, UP)]),
        plain(0x41, 0, 0x61)
    );
}

/// The repeat section: a key down twice before its release is one WM_KEYDOWN counted 2, its
/// character counted 2 too.
#[test]
fn a_repeated_key_folds_into_one_message() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.send(&[(0x42, 0x30, DOWN), (0x42, 0x30, DOWN), (0x42, 0x30, UP)]),
        [
            key(WM_KEYDOWN, 0x42, 0x0030_0002, NONE, true),
            chr(WM_CHAR, 0x62, 0x0030_0002, NONE),
            key(WM_KEYUP, 0x42, 0xC030_0001, NONE, false),
        ]
    );
}

/// The keyboard's bytes take the same path: Shift+A as the controller sends it, an extended arrow,
/// Caps Lock, whose toggle the character and the lights follow, and the right Ctrl.
#[test]
fn the_keyboards_bytes_reach_the_window() {
    let mut rig = Rig::new();
    assert_eq!(
        rig.type_bytes(&[0x2A, 0x1E, 0x9E, 0xAA]),
        [
            key(WM_KEYDOWN, 0x10, 0x002A_0001, SHIFTED, true),
            key(WM_KEYDOWN, 0x41, 0x001E_0001, SHIFTED, true),
            chr(WM_CHAR, 0x41, 0x001E_0001, SHIFTED),
            key(WM_KEYUP, 0x41, 0xC01E_0001, SHIFTED, false),
            key(WM_KEYUP, 0x10, 0xC02A_0001, NONE, false),
        ]
    );
    assert_eq!(
        rig.type_bytes(&[0xE0, 0x4B, 0xE0, 0xCB]),
        [
            key(WM_KEYDOWN, 0x25, 0x014B_0001, NONE, true),
            key(WM_KEYUP, 0x25, 0xC14B_0001, NONE, false),
        ]
    );
    assert_eq!(key_byte(&mut rig.m.windows, 0x3A, 0), Some(CAPS_LOCK));
    assert_eq!(key_byte(&mut rig.m.windows, 0xBA, 0), None);
    rig.pump();
    assert!(rig.m.windows.thread(rig.t).keys.is_toggled(VK_CAPITAL));
    assert_eq!(
        rig.type_bytes(&[0x1E, 0x9E])[1],
        chr(WM_CHAR, 0x41, 0x001E_0001, NONE)
    );
    let right = rig.type_bytes(&[0xE0, 0x1D, 0xE0, 0x9D]);
    assert_eq!(right[0], key(WM_KEYDOWN, 0x11, 0x011D_0001, CTRLED, true));
    assert!(!rig.m.windows.input.keys.is_down(VK_RCONTROL));
}

/// The thread's key state is its last read's: the system's moves at once, the thread's as it
/// reads.
#[test]
fn the_threads_state_follows_its_reads() {
    let mut rig = Rig::new();
    let input = Input {
        kind: INPUT_KEYBOARD,
        vk: 0x10,
        scan: 0x2A,
        ..Input::default()
    };
    let stroke = Keystroke::of_input(&input, &rig.m.windows.input.keys).unwrap();
    key_event(&mut rig.m.windows, stroke, 0);
    assert!(rig.m.windows.input.keys.is_down(VK_SHIFT));
    assert!(rig.m.windows.input.keys.is_down(VK_LSHIFT));
    assert!(!rig.m.windows.thread(rig.t).keys.is_down(VK_SHIFT));
    assert_eq!(rig.m.windows.input.async_key_state(VK_SHIFT), 0x8001);
    assert_eq!(
        rig.m.windows.input.async_key_state(VK_SHIFT),
        0x8000,
        "the press is told once"
    );
    rig.pump();
    let keys = rig.m.windows.thread(rig.t).keys;
    assert_eq!(
        keys.key_state(VK_SHIFT),
        0xFF81,
        "down, toggled by its first press"
    );
    assert!(keys.is_down(VK_LSHIFT) && !keys.is_down(VK_RSHIFT));
    assert_eq!(keys.byte(VK_SHIFT), 0x81);
    assert_eq!(
        keys.modifiers(),
        Modifiers {
            shift: true,
            control: false,
            alt: false
        }
    );
}

/// SetKeyboardState's bytes are the thread's state: TranslateMessage and the accelerators read
/// them.
#[test]
fn set_bytes_are_the_threads_state() {
    let mut rig = Rig::new();
    let keys = &mut rig.m.windows.thread_mut(rig.t).keys;
    keys.set_byte(VK_CONTROL, 0x80);
    keys.set_byte(VK_CAPITAL, 0x01);
    assert_eq!(keys.key_state(VK_CONTROL), 0xFF80);
    assert_eq!(
        keys.modifiers(),
        Modifiers {
            shift: false,
            control: true,
            alt: false
        }
    );
    let down = Msg {
        hwnd: rig.window,
        message: WM_KEYDOWN,
        wparam: 0x5A,
        lparam: 0x002C_0001,
        ..Msg::default()
    };
    assert!(translate(&mut rig.m.windows, rig.t, &down, 0).unwrap());
    assert_eq!(rig.pump(), [chr(WM_CHAR, 0x1A, 0x002C_0001, CTRLED)]);
    rig.m.windows.thread_mut(rig.t).keys.set_byte(VK_CONTROL, 0);
    assert!(translate(&mut rig.m.windows, rig.t, &down, 0).unwrap());
    assert_eq!(rig.pump()[0].1, 0x5A, "Caps Lock: the capital");
    let other = Msg {
        message: WM_USER,
        ..down
    };
    assert!(!translate(&mut rig.m.windows, rig.t, &other, 0).unwrap());
    let f1 = Msg {
        wparam: 0x70,
        ..down
    };
    assert!(
        !translate(&mut rig.m.windows, rig.t, &f1, 0).unwrap(),
        "no character"
    );
}

/// A character SendInput carries (KEYEVENTF_UNICODE) is a VK_PACKET whose TranslateMessage posts
/// the character.
#[test]
fn a_unicode_event_carries_its_character() {
    let mut rig = Rig::new();
    let got = rig.send(&[
        (0, 0x00E9, KEYEVENTF_UNICODE),
        (0, 0x00E9, KEYEVENTF_UNICODE | UP),
    ]);
    assert_eq!(got[0].1, 0x00E9_00E7);
    assert_eq!((got[1].0, got[1].1), (WM_CHAR, 0xE9));
}

/// With no focus window the keystrokes go to the active window as system keys; with no GUI
/// foreground, nowhere, and the keyboard's bytes go to the console.
#[test]
fn no_focus_makes_system_keys() {
    let mut rig = Rig::new();
    rig.m.windows.thread_mut(rig.t).focus = None;
    let got = rig.send(&[(0x41, 0x1E, DOWN), (0x41, 0x1E, UP)]);
    assert_eq!(got[0].0, WM_SYSKEYDOWN);
    assert_eq!(got[0].2, 0x001E_0001, "no context bit: Alt is up");
    assert_eq!(got[2].0, WM_SYSKEYUP);
    publish(&rig.m.windows);
    assert!(takes_keyboard());
    rig.m.windows.foreground_thread = None;
    publish(&rig.m.windows);
    assert!(!takes_keyboard());
    assert!(rig.send(&[(0x41, 0x1E, DOWN), (0x41, 0x1E, UP)]).is_empty());
}

// --- The window a key message is bound to: keyinput's typeahead section -------------------------

/// 'X' pressed and released.
const KEY_X: [(u16, u16, u32); 2] = [(0x58, 0x2D, DOWN), (0x58, 0x2D, UP)];

/// The first and last key messages: a filter's range over them all.
const WM_KEYFIRST: u32 = 0x0100;
const WM_KEYLAST: u32 = 0x0108;

/// Keys typed with the focus on A and read once it has moved to B go to B: the window is the
/// focus window as the thread reads, not as the key went down.
#[test]
fn a_key_goes_to_the_focus_window_of_its_read() {
    let mut rig = Rig::new();
    let (a, b) = (rig.child(10), rig.child(80));
    rig.focus(a);
    rig.type_ahead(&KEY_X);
    rig.focus(b);
    assert_eq!(rig.reads(), [(WM_KEYDOWN, b), (WM_CHAR, b), (WM_KEYUP, b)]);
}

/// A peek that leaves the message binds it for that read alone: once the focus moves, the read
/// that takes it out binds it again.
#[test]
fn a_peek_binds_the_key_for_itself_alone() {
    let mut rig = Rig::new();
    let (a, b) = (rig.child(10), rig.child(80));
    rig.focus(a);
    rig.type_ahead(&KEY_X);
    let filter = Filter::new(0, WM_KEYFIRST, WM_KEYLAST, 0);
    let peeked = msg_of(take(&mut rig.m.windows, rig.t, &filter, false, 0).unwrap());
    assert_eq!((peeked.message, peeked.hwnd), (WM_KEYDOWN, a));
    assert!(
        !rig.m.windows.thread(rig.t).keys.is_down(0x58),
        "a peek leaves the key state"
    );
    rig.focus(b);
    assert_eq!(rig.reads(), [(WM_KEYDOWN, b), (WM_CHAR, b), (WM_KEYUP, b)]);
}

/// A read filtered by window judges the bound window: A's finds nothing once the focus is on B,
/// B's finds the key.
#[test]
fn the_window_filter_sees_the_bound_window() {
    let mut rig = Rig::new();
    let (a, b) = (rig.child(10), rig.child(80));
    rig.focus(a);
    rig.type_ahead(&KEY_X);
    rig.focus(b);
    assert_eq!(rig.read_filtered(a, WM_KEYFIRST, WM_KEYLAST), None);
    assert_eq!(
        rig.read_filtered(b, WM_KEYFIRST, WM_KEYLAST),
        Some((WM_KEYDOWN, b))
    );
    assert!(rig.m.windows.thread(rig.t).keys.is_down(0x58));
    assert_eq!(rig.reads(), [(WM_KEYUP, b)]);
}

/// With the focus taken away before the read, the keys go to the active window as system keys,
/// and a read filtered by message judges the system key: WM_KEYDOWN's range finds nothing.
#[test]
fn a_key_read_with_no_focus_is_a_system_key_of_the_active_window() {
    let mut rig = Rig::new();
    let a = rig.child(10);
    rig.focus(a);
    rig.type_ahead(&KEY_X);
    rig.focus(0);
    assert_eq!(rig.read_filtered(0, WM_KEYDOWN, WM_KEYDOWN), None);
    assert_eq!(
        rig.read_filtered(0, WM_SYSKEYDOWN, WM_SYSKEYDOWN),
        Some((WM_SYSKEYDOWN, rig.window))
    );
    assert_eq!(rig.reads(), [(WM_SYSKEYUP, rig.window)]);

    rig.type_ahead(&KEY_X);
    assert_eq!(
        rig.reads(),
        [
            (WM_SYSKEYDOWN, rig.window),
            (WM_SYSCHAR, rig.window),
            (WM_SYSKEYUP, rig.window)
        ]
    );
}

/// Keys typed with no focus and read once the focus is given are the focus window's plain keys.
#[test]
fn a_key_typed_with_no_focus_goes_to_the_window_focused_before_the_read() {
    let mut rig = Rig::new();
    let a = rig.child(10);
    rig.focus(0);
    rig.type_ahead(&KEY_X);
    rig.focus(a);
    assert_eq!(rig.reads(), [(WM_KEYDOWN, a), (WM_CHAR, a), (WM_KEYUP, a)]);
}

/// The focus window destroyed before the read: its keys go where the focus went, the parent, and
/// none is lost with the window.
#[test]
fn a_key_outlives_the_focus_window_it_was_typed_into() {
    let mut rig = Rig::new();
    let a = rig.child(10);
    rig.focus(a);
    rig.type_ahead(&KEY_X);
    let WindowManager {
        windows, classes, ..
    } = &mut *rig.m;
    windows
        .destroy_window_handle(classes, rig.t, a, &mut QueuePump)
        .unwrap();
    let parent = rig.m.windows.window_from_handle(rig.window);
    assert_eq!(focus_window(&rig.m.windows, rig.t), parent);
    assert_eq!(
        rig.reads(),
        [
            (WM_KEYDOWN, rig.window),
            (WM_CHAR, rig.window),
            (WM_KEYUP, rig.window)
        ]
    );
}

/// A key message read while the thread has neither a focus window nor an active window is
/// discarded, its key state still moving: no key stays down for the thread.
#[test]
fn a_key_with_no_window_to_go_to_is_discarded() {
    let mut rig = Rig::new();
    rig.type_ahead(&[(0x58, 0x2D, DOWN)]);
    assert_eq!(
        rig.read_filtered(0, WM_KEYDOWN, WM_KEYDOWN),
        Some((WM_KEYDOWN, rig.window))
    );
    assert!(rig.m.windows.thread(rig.t).keys.is_down(0x58));
    rig.type_ahead(&[(0x58, 0x2D, UP)]);
    let thread = rig.m.windows.thread_mut(rig.t);
    thread.focus = None;
    thread.active = None;
    assert_eq!(active_window(&rig.m.windows, rig.t), None);
    assert!(rig.reads().is_empty());
    assert!(!rig.m.windows.thread(rig.t).keys.is_down(0x58));
}
