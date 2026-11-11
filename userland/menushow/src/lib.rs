//! menushow: a top-level window with a caption, a border and calc's menu bar, driven by the
//! keyboard through the default window procedure's menu loop. The program (src/main.rs) makes the
//! calls; this library holds the menu it builds and lays out the lines it prints, host-tested.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The messages menushow reads (winuser.h).
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_MENUSELECT: u32 = 0x011F;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_ENTERMENULOOP: u32 = 0x0211;
pub const WM_EXITMENULOOP: u32 = 0x0212;

/// The window's styles: calc's (a caption, its system menu and minimize box, a fixed frame).
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const STYLE: u32 = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;

/// The menu's commands.
pub const ID_COPY: u16 = 300;
pub const ID_PASTE: u16 = 301;
pub const ID_STANDARD: u16 = 303;
pub const ID_SCIENTIFIC: u16 = 304;
pub const ID_GROUPING: u16 = 305;
pub const ID_TOPICS: u16 = 310;
pub const ID_ABOUT: u16 = 311;

/// AppendMenu's flags (winuser.h).
pub const MF_STRING: u32 = 0x0000;
pub const MF_GRAYED: u32 = 0x0001;
pub const MF_CHECKED: u32 = 0x0008;
pub const MF_POPUP: u32 = 0x0010;
pub const MF_SEPARATOR: u32 = 0x0800;

/// One item of a popup: its flags, its command, its text (with its accelerator after a tab).
pub type Item = (u32, u16, &'static str);

/// The menu bar: calc's Edit, View and Help, each a popup of its items. Paste is grayed, so the
/// sheet shows a grayed item; Standard is checked, as calc's radio item is at its start.
pub const MENU: [(&str, &[Item]); 3] = [
    (
        "&Edit",
        &[
            (MF_STRING, ID_COPY, "&Copy\tCtrl+C"),
            (MF_STRING | MF_GRAYED, ID_PASTE, "&Paste\tCtrl+V"),
        ],
    ),
    (
        "&View",
        &[
            (MF_STRING | MF_CHECKED, ID_STANDARD, "S&tandard"),
            (MF_STRING, ID_SCIENTIFIC, "&Scientific"),
            (MF_SEPARATOR, 0, ""),
            (MF_STRING, ID_GROUPING, "Digit &grouping"),
        ],
    ),
    (
        "&Help",
        &[
            (MF_STRING, ID_TOPICS, "&Help Topics"),
            (MF_SEPARATOR, 0, ""),
            (MF_STRING, ID_ABOUT, "&About Calculator"),
        ],
    ),
];

/// The line menushow prints once its window shows, painted: keys typed from then on reach it.
pub const READY: &str = "menushow: ready";
/// The line it prints when a command has been taken and the window is painted again.
pub const SETTLED: &str = "menushow: settled";

/// menushow's exit codes: 0 once its window is closed; 1 when it could not be made.
pub const NO_WINDOW: u32 = 1;

/// What a menu handle is, as a line names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuName {
    Bar,
    /// The popup at this position of the bar.
    Popup(usize),
    Null,
    Other,
}

impl fmt::Display for MenuName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MenuName::Bar => write!(f, "the bar"),
            MenuName::Popup(index) => {
                let name = MENU.get(*index).map_or("?", |(name, _)| name);
                write!(f, "{}", name.trim_start_matches('&'))
            }
            MenuName::Null => write!(f, "NULL"),
            MenuName::Other => write!(f, "another menu"),
        }
    }
}

/// The line of a menu message the window received: the message, its parameters as numbers, the
/// menu it names by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuLine {
    pub message: u32,
    pub wparam: u32,
    pub lparam: u32,
    pub menu: MenuName,
}

impl fmt::Display for MenuLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (low, high) = (self.wparam & 0xFFFF, self.wparam >> 16);
        match self.message {
            WM_SYSCOMMAND => write!(
                f,
                "WM_SYSCOMMAND 0x{:04X} lParam={}",
                self.wparam, self.lparam
            ),
            WM_ENTERMENULOOP => write!(f, "WM_ENTERMENULOOP {}", self.wparam),
            WM_EXITMENULOOP => write!(f, "WM_EXITMENULOOP {}", self.wparam),
            WM_INITMENU => write!(f, "WM_INITMENU {}", self.menu),
            WM_INITMENUPOPUP => write!(
                f,
                "WM_INITMENUPOPUP {} position {} system {}",
                self.menu,
                self.lparam & 0xFFFF,
                self.lparam >> 16
            ),
            WM_UNINITMENUPOPUP => write!(f, "WM_UNINITMENUPOPUP {}", self.menu),
            WM_MENUSELECT => write!(f, "WM_MENUSELECT {low} flags 0x{high:04X} {}", self.menu),
            WM_COMMAND => write!(f, "WM_COMMAND id={low} code={high}"),
            WM_ENTERIDLE => write!(f, "WM_ENTERIDLE {}", self.wparam),
            message => write!(f, "message 0x{message:04X}"),
        }
    }
}

/// Whether menushow prints a line for `message`.
pub fn is_menu_message(message: u32) -> bool {
    matches!(
        message,
        WM_SYSCOMMAND
            | WM_ENTERMENULOOP
            | WM_EXITMENULOOP
            | WM_INITMENU
            | WM_INITMENUPOPUP
            | WM_UNINITMENUPOPUP
            | WM_MENUSELECT
            | WM_COMMAND
            | WM_ENTERIDLE
    )
}

/// Which of `message`'s parameters is a menu handle: wParam's (WM_INITMENU, WM_INITMENUPOPUP,
/// WM_UNINITMENUPOPUP), lParam's (WM_MENUSELECT), or none.
pub fn menu_parameter(message: u32, wparam: u32, lparam: u32) -> Option<u32> {
    match message {
        WM_INITMENU | WM_INITMENUPOPUP | WM_UNINITMENUPOPUP => Some(wparam),
        WM_MENUSELECT => Some(lparam),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines read as tests/core/test_nonclient.py expects them.
    #[test]
    fn the_lines_read_as_documented() {
        let line = |message, wparam, lparam, menu| {
            MenuLine {
                message,
                wparam,
                lparam,
                menu,
            }
            .to_string()
        };
        assert_eq!(
            line(WM_SYSCOMMAND, 0xF100, 0, MenuName::Null),
            "WM_SYSCOMMAND 0xF100 lParam=0"
        );
        assert_eq!(
            line(WM_MENUSELECT, 0x0090_0001, 0, MenuName::Bar),
            "WM_MENUSELECT 1 flags 0x0090 the bar"
        );
        assert_eq!(
            line(WM_INITMENUPOPUP, 0, 1, MenuName::Popup(1)),
            "WM_INITMENUPOPUP View position 1 system 0"
        );
        assert_eq!(
            line(WM_COMMAND, u32::from(ID_SCIENTIFIC), 0, MenuName::Null),
            "WM_COMMAND id=304 code=0"
        );
        assert_eq!(menu_parameter(WM_MENUSELECT, 1, 2), Some(2));
        assert!(!is_menu_message(WM_TIMER));
    }
}
