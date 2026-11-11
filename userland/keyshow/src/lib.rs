//! keyshow: a window that prints the keyboard messages it receives. The program (src/main.rs)
//! makes the calls; this library names the messages and lays their lines out, host-tested.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The keyboard messages a window receives (winuser.h).
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;

/// The character that ends keyshow: Escape's.
pub const ESCAPE: u32 = 0x1B;

/// The line keyshow prints once its window is the foreground and focus window: keys typed from
/// then on reach it.
pub const READY: &str = "keyshow: ready";

/// The line keyshow prints when its window could not be made the foreground window.
pub const NOT_FOREGROUND: &str = "keyshow: the window is not the foreground window";

/// keyshow's exit codes: 0 once Escape ended it; 1 when its window could not be made or made the
/// foreground window.
pub const NO_WINDOW: u32 = 1;

/// A keyboard message's name; none for another message.
pub fn name(message: u32) -> Option<&'static str> {
    Some(match message {
        WM_KEYDOWN => "WM_KEYDOWN",
        WM_KEYUP => "WM_KEYUP",
        WM_CHAR => "WM_CHAR",
        WM_SYSKEYDOWN => "WM_SYSKEYDOWN",
        WM_SYSKEYUP => "WM_SYSKEYUP",
        WM_SYSCHAR => "WM_SYSCHAR",
        _ => return None,
    })
}

/// A keyboard message's line: its name, wParam and lParam, in the keyinput fixture's form.
pub struct Line {
    pub name: &'static str,
    pub wparam: u32,
    pub lparam: u32,
}

impl Line {
    /// The line of a keyboard message; none for another message.
    pub fn of(message: u32, wparam: u32, lparam: u32) -> Option<Line> {
        name(message).map(|name| Line {
            name,
            wparam,
            lparam,
        })
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} wParam=0x{:04X} lParam=0x{:08X}",
            self.name, self.wparam, self.lparam
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_message_prints_its_name_and_parameters() {
        let line = Line::of(WM_KEYUP, 0x41, 0xC01E_0001).unwrap();
        assert_eq!(
            std::format!("{line}"),
            "WM_KEYUP wParam=0x0041 lParam=0xC01E0001"
        );
        let line = Line::of(WM_SYSCHAR, 0x66, 0x2021_0001).unwrap();
        assert_eq!(
            std::format!("{line}"),
            "WM_SYSCHAR wParam=0x0066 lParam=0x20210001"
        );
        assert!(Line::of(0x000F, 0, 0).is_none(), "WM_PAINT is no key's");
    }
}
