//! The mouse's host tests: the mousein fixture's sections as its procedure records them (each
//! case's expected records are the capture's), the absolute coordinates' scale, the moves the input
//! path posts and folds, the reads' conversions (the hit-test codes, the client points, the
//! double-click), the capture and where the messages go.

use rtl::nonclient::HTCAPTION;
use rtl::user::{
    MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MOVE,
    WM_CAPTURECHANGED,
    WM_NCLBUTTONDOWN,
    WM_NCMOUSEMOVE,
    WS_OVERLAPPEDWINDOW,
};

use super::*;
use crate::win32k::focus::{set_capture, set_foreground_window};
use crate::win32k::queue::rig::{manager, read, thread, window_at};
use crate::win32k::queue::{end_sent, keep_prepared, QueueSession, Taken};
use crate::win32k::window::WindowManager;

/// The rig's screen: the boot desktop's.
const SCREEN: Rect = Rect {
    left: 0,
    top: 0,
    right: 640,
    bottom: 480,
};

/// The mousein fixture's window: a visible overlapped window of its own thread, centred, 320x240,
/// the foreground window, with a visible child (its button) at client (16, 16), 80x28.
struct Rig {
    m: &'static mut WindowManager,
    t: ThreadId,
    window: Hwnd,
    button: Hwnd,
    /// The hit-test code the window's procedure answers in its non-client area (its client area's
    /// is HTCLIENT), as the fixture's DefWindowProc would on its caption.
    frame_hit: u32,
}

impl Rig {
    fn new() -> Rig {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x40);
        let window = window_at(
            m,
            atom,
            t,
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            0,
            160,
            120,
            320,
            240,
        );
        let button = window_at(m, atom, t, WS_CHILD | WS_VISIBLE, window, 16, 16, 80, 28);
        let id = m.windows.window_from_handle(window).unwrap();
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        assert!(set_foreground_window(
            &mut QueueSession::new(windows, classes),
            t,
            id
        ));
        let mut rig = Rig {
            m,
            t,
            window,
            button,
            frame_hit: HTCAPTION,
        };
        rig.pump();
        rig
    }

    fn id(&self, hwnd: Hwnd) -> WindowId {
        self.m.windows.window_from_handle(hwnd).unwrap()
    }

    /// A client point of the window `hwnd` on the screen.
    fn screen(&self, hwnd: Hwnd, x: i32, y: i32) -> Point {
        let client = self.m.windows.client_rect(self.id(hwnd));
        Point {
            x: client.left + x,
            y: client.top + y,
        }
    }

    /// The window's client area's size.
    fn client_size(&self) -> (i32, i32) {
        let client = self.m.windows.client_rect(self.id(self.window));
        (client.width(), client.height())
    }

    /// The fixture's loop: every message read out, each mouse message's window asked where the
    /// point is (its procedure answering HTCLIENT in its client area, `frame_hit` elsewhere), the
    /// sent ones answered (the paint left); the mouse messages the window's procedure (not its
    /// button's) receives.
    fn pump(&mut self) -> Vec<Msg> {
        let mut got = Vec::new();
        // No paint: the windows show, and nothing here validates them.
        let input = crate::win32k::queue::Filter::new(
            0,
            0,
            0,
            rtl::user::PM_QS_INPUT | rtl::user::PM_QS_SENDMESSAGE | rtl::user::PM_QS_POSTMESSAGE,
        );
        loop {
            match read(self.m, self.t, &input, 0) {
                Taken::Sent(_) => assert!(end_sent(&mut self.m.windows, self.t, 0)),
                Taken::Prepare {
                    entry,
                    window,
                    pt,
                    captured,
                } => {
                    let hit = if captured {
                        HTCLIENT
                    } else if self.m.windows.client_rect(window).contains(pt.x, pt.y) {
                        HTCLIENT
                    } else {
                        self.frame_hit
                    };
                    let p = prepared(&self.m.windows, &self.m.classes, window, pt, hit);
                    keep_prepared(&mut self.m.windows, self.t, entry, p);
                }
                Taken::Mouse(read) => {
                    if read.msg.hwnd == self.window {
                        got.push(read.msg);
                    }
                }
                Taken::Message(_) => {}
                Taken::Nothing { .. } => return got,
            }
        }
    }

    /// SetCursorPos to the window's client point, its move read away.
    fn place(&mut self, x: i32, y: i32) {
        let pt = self.screen(self.window, x, y);
        set_cursor_pos(&mut self.m.windows, pt.x, pt.y, SCREEN, 0);
        self.pump();
    }

    /// SendInput's events, nothing read.
    fn inject(&mut self, events: &[MouseInput]) {
        for event in events {
            mouse_event(&mut self.m.windows, event, SCREEN, 0);
        }
    }

    /// An absolute move to the window's client point, as the fixture normalises it.
    fn move_to(&self, x: i32, y: i32) -> MouseInput {
        let pt = self.screen(self.window, x, y);
        MouseInput {
            dx: normalise(pt.x, SCREEN.width()),
            dy: normalise(pt.y, SCREEN.height()),
            flags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
            ..MouseInput::default()
        }
    }

    /// SetCapture to `hwnd` (0: ReleaseCapture), the WM_CAPTURECHANGED it sent delivered: the
    /// window that had the capture, and the (window, lParam) of the WM_CAPTURECHANGED sent.
    fn capture(&mut self, hwnd: Hwnd) -> (Hwnd, Vec<(Hwnd, u32)>) {
        let target = (hwnd != 0).then(|| self.id(hwnd));
        let WindowManager {
            windows, classes, ..
        } = &mut *self.m;
        let previous = set_capture(&mut QueueSession::new(windows, classes), self.t, target);
        let previous = previous.map_or(0, |w| self.m.windows.handle_of(w));
        let mut changed = Vec::new();
        let only_sent = crate::win32k::queue::Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
        while let Taken::Sent(id) = read(self.m, self.t, &only_sent, 0) {
            let head = crate::win32k::queue::head_of(&self.m.windows, id).unwrap();
            if head.msg.message == WM_CAPTURECHANGED {
                changed.push((head.msg.hwnd, head.msg.lparam as u32));
            }
            assert!(end_sent(&mut self.m.windows, self.t, 0));
        }
        (previous, changed)
    }
}

/// A screen coordinate as the fixture sends it: the middle of the pixel's interval of 0-65535.
fn normalise(v: i32, size: i32) -> i32 {
    ((2 * v + 1) * 32768) / size
}

/// A button event of SendInput's.
fn button(flags: u32) -> MouseInput {
    MouseInput {
        flags,
        ..MouseInput::default()
    }
}

/// A record as the fixture prints it: the message, wParam and the client point.
fn record(msg: &Msg) -> (u32, u32, i32, i32) {
    (
        msg.message,
        msg.wparam,
        i32::from(msg.lparam as u16 as i16),
        i32::from((msg.lparam >> 16) as u16 as i16),
    )
}

/// The fixture's normalised coordinates come back to the pixel they name, at every width.
#[test]
fn absolute_moves_land_on_the_pixel_sent() {
    for width in [640, 800, 1024, 1280, 1600] {
        let screen = Rect {
            left: 0,
            top: 0,
            right: width,
            bottom: 480,
        };
        for x in 0..width {
            assert_eq!(absolute(normalise(x, width), 0, screen).x, x, "{width}");
        }
    }
    assert_eq!(absolute(65535, 65535, SCREEN), Point { x: 639, y: 479 });
    assert_eq!(
        clamp(Point { x: -5, y: 900 }, SCREEN),
        Point { x: 0, y: 479 }
    );
}

/// The move section: one absolute move to the client area's centre, from the start point, is one
/// WM_MOUSEMOVE there with no flags, and the cursor is there.
#[test]
fn the_move_section() {
    let mut rig = Rig::new();
    let (w, h) = rig.client_size();
    rig.place(w * 3 / 4, h * 3 / 4);
    let event = rig.move_to(w / 2, h / 2);
    rig.inject(&[event]);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(got, [(WM_MOUSEMOVE, 0, w / 2, h / 2)]);
    assert_eq!(
        position(&rig.m.windows, SCREEN),
        rig.screen(rig.window, w / 2, h / 2)
    );
}

/// The click section after the move section: the move to where the move section's event left the
/// cursor posts nothing (SetCursorPos took it away and back meanwhile), the press and the release
/// come with MK_LBUTTON and none.
#[test]
fn the_click_section_follows_the_move_section() {
    let mut rig = Rig::new();
    let (w, h) = rig.client_size();
    rig.place(w * 3 / 4, h * 3 / 4);
    let centre = rig.move_to(w / 2, h / 2);
    rig.inject(&[centre]);
    rig.pump();
    // The click section's own start.
    rig.place(w * 3 / 4, h * 3 / 4);
    rig.inject(&[
        centre,
        button(MOUSEEVENTF_LEFTDOWN),
        button(MOUSEEVENTF_LEFTUP),
    ]);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(
        got,
        [
            (WM_LBUTTONDOWN, MK_LBUTTON, w / 2, h / 2),
            (WM_LBUTTONUP, 0, w / 2, h / 2),
        ]
    );
}

/// A press where the input path did not leave the cursor posts the move first; a move by the
/// input path to the same place again posts nothing.
#[test]
fn a_press_elsewhere_moves_first() {
    let mut rig = Rig::new();
    let (w, h) = rig.client_size();
    rig.place(w / 4, h / 4);
    rig.inject(&[button(MOUSEEVENTF_LEFTDOWN), button(MOUSEEVENTF_LEFTUP)]);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(
        got,
        [
            (WM_MOUSEMOVE, 0, w / 4, h / 4),
            (WM_LBUTTONDOWN, MK_LBUTTON, w / 4, h / 4),
            (WM_LBUTTONUP, 0, w / 4, h / 4),
        ]
    );
    let again = rig.move_to(w / 4, h / 4);
    rig.inject(&[again]);
    assert_eq!(rig.pump(), []);
}

/// Moves the thread has not read fold into the last: one WM_MOUSEMOVE, at the last place.
#[test]
fn unread_moves_fold() {
    let mut rig = Rig::new();
    let events = [
        rig.move_to(110, 100),
        rig.move_to(120, 120),
        rig.move_to(130, 125),
    ];
    rig.inject(&events);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(got, [(WM_MOUSEMOVE, 0, 130, 125)]);
}

/// The capture section's first half: SetCapture onto the window, the button, the window again,
/// then ReleaseCapture; each answers the window that had it, and the window losing it is sent
/// WM_CAPTURECHANGED naming the window gaining it.
#[test]
fn the_capture_moves_between_the_window_and_its_button() {
    let mut rig = Rig::new();
    let (window, button) = (rig.window, rig.button);
    assert_eq!(rig.capture(window), (0, vec![]));
    assert_eq!(rig.capture(button), (window, vec![(window, button)]));
    assert_eq!(rig.capture(window), (button, vec![(button, window)]));
    assert_eq!(rig.capture(0), (window, vec![(window, 0)]));
    assert_eq!(capture_of(&rig.m.windows, rig.t), None);
}

/// The capture section's second half: the window holding the capture, a press at the start point
/// (the cursor put there by SetCursorPos), a move onto the caption and the release there are the
/// window's client messages, the caption's point outside its client area.
#[test]
fn the_capture_section_drags_onto_the_caption() {
    let mut rig = Rig::new();
    let (w, h) = rig.client_size();
    // The click section left the cursor at the centre.
    rig.place(w * 3 / 4, h * 3 / 4);
    let centre = rig.move_to(w / 2, h / 2);
    rig.inject(&[centre]);
    rig.pump();
    rig.place(w * 3 / 4, h * 3 / 4);
    let window = rig.window;
    rig.capture(window);
    let rect = rig.m.windows.window_rect(rig.id(window));
    let client = rig.m.windows.client_rect(rig.id(window));
    let caption = Point {
        x: (rect.left + rect.right) / 2 - client.left,
        y: rect.top + 4 + 9 - client.top,
    };
    let onto = rig.move_to(caption.x, caption.y);
    rig.inject(&[
        button(MOUSEEVENTF_LEFTDOWN),
        onto,
        button(MOUSEEVENTF_LEFTUP),
    ]);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(
        got,
        [
            (WM_MOUSEMOVE, 0, w * 3 / 4, h * 3 / 4),
            (WM_LBUTTONDOWN, MK_LBUTTON, w * 3 / 4, h * 3 / 4),
            (WM_MOUSEMOVE, MK_LBUTTON, caption.x, caption.y),
            (WM_LBUTTONUP, 0, caption.x, caption.y),
        ]
    );
    assert!(caption.y < 0);
    assert_eq!(capture_of(&rig.m.windows, rig.t), Some(rig.id(window)));
}

/// Without the capture, a point on the caption is the non-client message, wParam the code and
/// lParam the screen point.
#[test]
fn the_caption_has_the_non_client_messages() {
    let mut rig = Rig::new();
    let rect = rig.m.windows.window_rect(rig.id(rig.window));
    let at = Point {
        x: (rect.left + rect.right) / 2,
        y: rect.top + 10,
    };
    rig.inject(&[
        MouseInput {
            dx: normalise(at.x, 640),
            dy: normalise(at.y, 480),
            flags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN,
            ..MouseInput::default()
        },
        button(MOUSEEVENTF_LEFTUP),
    ]);
    let got: Vec<_> = rig.pump().iter().map(record).collect();
    assert_eq!(
        got,
        [
            (WM_NCMOUSEMOVE, HTCAPTION, at.x, at.y),
            (WM_NCLBUTTONDOWN, HTCAPTION, at.x, at.y),
            (WM_NCLBUTTONDOWN + 1, HTCAPTION, at.x, at.y),
        ]
    );
}

/// The button section: the press over the button goes to the button, not its parent; the
/// thread's key state follows the button's messages as they are read.
#[test]
fn the_button_has_its_press() {
    let mut rig = Rig::new();
    let event = rig.move_to(16 + 40, 16 + 14);
    let button_id = rig.id(rig.button);
    assert_eq!(
        target(&rig.m.windows, rig.screen(rig.window, 56, 30)),
        Some(button_id)
    );
    rig.inject(&[event, button(MOUSEEVENTF_LEFTDOWN)]);
    assert_eq!(rig.pump(), []);
    assert!(rig.m.windows.thread(rig.t).keys.is_down(VK_LBUTTON as u8));
    rig.inject(&[button(MOUSEEVENTF_LEFTUP)]);
    rig.pump();
    assert!(!rig.m.windows.thread(rig.t).keys.is_down(VK_LBUTTON as u8));
}

/// A disabled child's point goes to its parent; a hidden one's too.
#[test]
fn a_disabled_child_gives_way_to_its_parent() {
    let mut rig = Rig::new();
    let at = rig.screen(rig.window, 56, 30);
    let button_id = rig.id(rig.button);
    rig.m.windows.set_disabled(button_id, true);
    assert_eq!(target(&rig.m.windows, at), Some(rig.id(rig.window)));
    rig.m.windows.set_disabled(button_id, false);
    rig.m.windows.set_visible_for_tests(button_id, false);
    assert_eq!(target(&rig.m.windows, at), Some(rig.id(rig.window)));
    assert_eq!(target(&rig.m.windows, Point { x: 5, y: 5 }), None);
}

/// A second press of the same button on the same window, soon and near enough, is a double-click
/// for a class with CS_DBLCLKS or out of the client area; the third starts over.
#[test]
fn a_quick_second_press_is_a_double_click() {
    let rig = Rig::new();
    let window = rig.id(rig.window);
    let pt = rig.screen(rig.window, 50, 50);
    let msg = Msg {
        hwnd: rig.window,
        message: WM_LBUTTONDOWN,
        wparam: MK_LBUTTON,
        lparam: 0,
        time: 1000,
        pt,
    };
    let first = Click {
        message: WM_LBUTTONDOWN,
        hwnd: rig.window,
        time: 800,
        pt: Point {
            x: pt.x - 1,
            y: pt.y + 1,
        },
    };
    let mut prepared = Prepared {
        hwnd: rig.window,
        pt,
        hit: HTCLIENT,
        dblclks: true,
    };
    let convert_with =
        |prepared: &Prepared, click| convert(&rig.m.windows, window, &msg, prepared, click).1;
    assert_eq!(convert_with(&prepared, Some(first)), WM_LBUTTONDBLCLK);
    assert_eq!(convert_with(&prepared, None), WM_LBUTTONDOWN);
    let late = Click { time: 400, ..first };
    assert_eq!(convert_with(&prepared, Some(late)), WM_LBUTTONDOWN);
    let far = Click {
        pt: Point {
            x: pt.x - 3,
            y: pt.y,
        },
        ..first
    };
    assert_eq!(convert_with(&prepared, Some(far)), WM_LBUTTONDOWN);
    prepared.dblclks = false;
    assert_eq!(convert_with(&prepared, Some(first)), WM_LBUTTONDOWN);
    prepared.hit = HTCAPTION;
    let (nc, client) = convert(&rig.m.windows, window, &msg, &prepared, Some(first));
    assert_eq!(
        (nc.message, client),
        (WM_NCLBUTTONDOWN + 2, WM_LBUTTONDBLCLK)
    );
    assert_eq!(
        next_click(Some(first), WM_LBUTTONDBLCLK, rig.window, 1000, pt),
        None
    );
}

/// The MK_ flags follow the system's key state: the buttons, Shift and Ctrl.
#[test]
fn the_flags_follow_the_key_state() {
    let mut keys = KeyState::EMPTY;
    assert_eq!(mk_flags(&keys), 0);
    keys.press(VK_LBUTTON as u8, true);
    keys.press(VK_MBUTTON as u8, true);
    keys.press(rtl::console::layout::VK_LSHIFT, true);
    assert_eq!(mk_flags(&keys), MK_LBUTTON | MK_MBUTTON | MK_SHIFT);
}

/// A relative move is doubled past the threshold, and the cursor stays on the screen.
#[test]
fn relative_moves_accelerate_and_stay_on_the_screen() {
    let mut rig = Rig::new();
    rig.place(0, 0);
    let start = position(&rig.m.windows, SCREEN);
    let by = |dx, dy| MouseInput {
        dx,
        dy,
        flags: MOUSEEVENTF_MOVE,
        ..MouseInput::default()
    };
    rig.inject(&[by(5, -3)]);
    assert_eq!(
        position(&rig.m.windows, SCREEN),
        Point {
            x: start.x + 5,
            y: start.y - 3
        }
    );
    rig.inject(&[by(10, 0)]);
    assert_eq!(position(&rig.m.windows, SCREEN).x, start.x + 25);
    rig.inject(&[by(-5000, 5000)]);
    assert_eq!(position(&rig.m.windows, SCREEN), Point { x: 0, y: 479 });
}
