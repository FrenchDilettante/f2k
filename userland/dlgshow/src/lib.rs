//! dlgshow: a dialog with push, default, check, radio and group-box buttons and static text, driven
//! by the keyboard through IsDialogMessageW. The program (src/main.rs) makes the calls; this
//! library builds the dialog's template and lays out the lines it prints, host-tested.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The messages and keys dlgshow reads (winuser.h).
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_INITDIALOG: u32 = 0x0110;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_CLOSE: u32 = 0x0010;

/// The dialog's controls' ids.
pub const ID_OK: u16 = 1;
pub const ID_CANCEL: u16 = 2;
pub const ID_KEEP: u16 = 101;
pub const ID_STANDARD: u16 = 103;
pub const ID_SCIENTIFIC: u16 = 104;

/// The line dlgshow prints once its dialog shows, painted, with the focus: keys typed from then on
/// reach it.
pub const READY: &str = "dlgshow: ready";

/// dlgshow's exit codes: 0 once OK or Cancel ended it; 1 when its dialog could not be made.
pub const NO_DIALOG: u32 = 1;

/// The styles of the dialog and its controls (winuser.h).
const WS_POPUP: u32 = 0x8000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_GROUP: u32 = 0x0002_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const DS_SETFONT: u32 = 0x0040;
const DS_MODALFRAME: u32 = 0x0080;
const DS_CENTER: u32 = 0x0800;
const BS_PUSHBUTTON: u32 = 0x0;
const BS_DEFPUSHBUTTON: u32 = 0x1;
const BS_AUTOCHECKBOX: u32 = 0x3;
const BS_GROUPBOX: u32 = 0x7;
const BS_AUTORADIOBUTTON: u32 = 0x9;
const SS_LEFT: u32 = 0x00;
const SS_ETCHEDHORZ: u32 = 0x10;

/// The predefined classes' ordinals.
const BUTTON: u16 = 0x80;
const STATIC: u16 = 0x82;

/// The controls, in tab order: style, rectangle in dialog units, id, class, text.
const CONTROLS: [(u32, [i16; 4], u16, u16, &str); 8] = [
    (
        SS_LEFT | WS_GROUP,
        [8, 8, 164, 10],
        0xFFFF,
        STATIC,
        "Choose the options and press OK.",
    ),
    (
        BS_DEFPUSHBUTTON | WS_TABSTOP | WS_GROUP,
        [122, 26, 50, 14],
        ID_OK,
        BUTTON,
        "OK",
    ),
    (
        BS_PUSHBUTTON | WS_TABSTOP,
        [122, 44, 50, 14],
        ID_CANCEL,
        BUTTON,
        "Cancel",
    ),
    (
        BS_AUTOCHECKBOX | WS_TABSTOP | WS_GROUP,
        [8, 26, 104, 10],
        ID_KEEP,
        BUTTON,
        "&Keep the window",
    ),
    (
        BS_GROUPBOX | WS_GROUP,
        [8, 40, 104, 46],
        102,
        BUTTON,
        "Mode",
    ),
    (
        BS_AUTORADIOBUTTON | WS_TABSTOP | WS_GROUP,
        [16, 52, 80, 10],
        ID_STANDARD,
        BUTTON,
        "&Standard",
    ),
    (
        BS_AUTORADIOBUTTON,
        [16, 66, 80, 10],
        ID_SCIENTIFIC,
        BUTTON,
        "S&cientific",
    ),
    (
        SS_ETCHEDHORZ | WS_GROUP,
        [8, 92, 164, 2],
        0xFFFF,
        STATIC,
        "",
    ),
];

/// The dialog's template: a DLGTEMPLATE in the dialog font ("MS Shell Dlg" 8), its controls each
/// on a DWORD boundary, written into `out` as its 16-bit words; how many it took (none when `out`
/// is too short).
pub fn template(out: &mut [u16]) -> Option<usize> {
    let mut words = Words { out, at: 0 };
    let style =
        WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT | DS_CENTER;
    words.dword(style);
    words.dword(0);
    words.word(CONTROLS.len() as u16);
    for value in [0, 0, 180, 104] {
        words.word(value);
    }
    words.word(0);
    words.word(0);
    words.text("F2K dialog");
    words.word(8);
    words.text("MS Shell Dlg");
    for (style, rect, id, class, text) in CONTROLS {
        if !words.at.is_multiple_of(2) {
            words.word(0);
        }
        words.dword(WS_CHILD | WS_VISIBLE | style);
        words.dword(0);
        for value in rect {
            words.word(value as u16);
        }
        words.word(id);
        words.word(0xFFFF);
        words.word(class);
        words.text(text);
        words.word(0);
    }
    (words.at <= words.out.len()).then_some(words.at)
}

/// A template's words being written.
struct Words<'a> {
    out: &'a mut [u16],
    at: usize,
}

impl Words<'_> {
    fn word(&mut self, value: u16) {
        if let Some(slot) = self.out.get_mut(self.at) {
            *slot = value;
        }
        self.at += 1;
    }

    fn dword(&mut self, value: u32) {
        self.word(value as u16);
        self.word((value >> 16) as u16);
    }

    fn text(&mut self, text: &str) {
        for unit in text.encode_utf16() {
            self.word(unit);
        }
        self.word(0);
    }
}

/// The control with the focus, as a line prints it: its id, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Focus(pub Option<i32>);

impl fmt::Display for Focus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(id) => write!(f, "focus {id}"),
            None => write!(f, "focus none"),
        }
    }
}

/// The line of a key the dialog took: the key's virtual-key code and the focus after it.
pub struct KeyLine {
    pub key: u32,
    pub focus: Focus,
}

impl fmt::Display for KeyLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key 0x{:02X}: {}", self.key, self.focus)
    }
}

/// The line of a command the dialog's procedure received: the id and the notification code.
pub struct CommandLine {
    pub id: u32,
    pub code: u32,
}

impl fmt::Display for CommandLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WM_COMMAND id={} code={}", self.id, self.code)
    }
}

/// The line dlgshow ends with: the button that ended it and the options' states.
pub struct EndLine {
    pub ok: bool,
    pub keep: u32,
    pub scientific: u32,
}

impl fmt::Display for EndLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dlgshow: {}, keep {}, mode {}",
            if self.ok { "OK" } else { "Cancel" },
            self.keep,
            if self.scientific != 0 {
                "scientific"
            } else {
                "standard"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The template's header and its first control lie where DLGTEMPLATE's layout puts them.
    #[test]
    fn the_template_is_a_dlgtemplate() {
        let mut words = [0u16; 512];
        let length = template(&mut words).unwrap();
        assert!(length < 512);
        assert_eq!(words[4], CONTROLS.len() as u16);
        assert_eq!(&words[5..9], &[0, 0, 180, 104]);
        let title: std::vec::Vec<u16> = "F2K dialog".encode_utf16().collect();
        assert_eq!(&words[11..11 + title.len()], &title[..]);
        assert!(template(&mut [0u16; 16]).is_none());
    }

    #[test]
    fn the_lines_read_as_documented() {
        let key = KeyLine {
            key: 0x09,
            focus: Focus(Some(2)),
        };
        assert_eq!(std::format!("{key}"), "key 0x09: focus 2");
        let command = CommandLine { id: 101, code: 0 };
        assert_eq!(std::format!("{command}"), "WM_COMMAND id=101 code=0");
        let end = EndLine {
            ok: true,
            keep: 1,
            scientific: 0,
        };
        assert_eq!(std::format!("{end}"), "dlgshow: OK, keep 1, mode standard");
    }
}
