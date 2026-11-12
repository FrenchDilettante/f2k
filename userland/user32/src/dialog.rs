//! The dialog manager: dialogs made from DIALOG and DIALOGEX templates (CreateDialogParam,
//! CreateDialogIndirectParamW, DialogBoxParam and its modal loop, EndDialog), the dialog class's
//! procedure (DefDlgProc), the calls on a dialog's controls (the GetDlgItem family), the dialog
//! base units (GetDialogBaseUnits, MapDialogRect) and the keyboard interface (IsDialogMessage), as
//! Windows 2000's user32 runs them, client-side, over its window calls.
//!
//! A template is read as its public layout gives it ([`Reader`]): the DLGTEMPLATE or DLGTEMPLATEEX
//! header (the styles, the control count, the rectangle in dialog units, the menu, the class, the
//! title and, with DS_SETFONT, the font), then each DLGITEMTEMPLATE(EX) on a DWORD boundary (the
//! styles, the rectangle, the id, the class, the title, the creation data). A resource's template
//! is its RT_DIALOG data; an indirect one the caller's memory.
//!
//! A dialog is a window of the class the template names, by default the dialog class (#32770,
//! registered in every process: [`crate::class::register_system_classes`]), whose procedure is
//! DefDlgProcW, or DefDlgProcA for a narrow caller's dialog. The window manager marks it a dialog
//! (NtUserSetWindowFNID), and its DLGWINDOWEXTRA extra bytes hold the dialog's state: the public
//! DWL_MSGRESULT, DWL_DLGPROC and DWL_USER, then the dialog manager's own (the control the focus
//! goes back to, EndDialog's result, the flags, the default button's id, the dialog's font and its
//! base units). DWL_DLGPROC reads and writes through GetWindowLong and SetWindowLong in the
//! caller's form, as a window procedure does ([`dialog_procedure`]).
//!
//! The dialog base units are the dialog font's: the average width of the 52 letters A-Z and a-z,
//! rounded as the documentation's formula rounds it, and the font's height; a dialog with no font
//! has the system font's, GetDialogBaseUnits'. A dialog unit is a quarter of the width unit and an
//! eighth of the height unit. A control's rectangle maps its four numbers each on its own (the x,
//! the y, the width and the height), as the dialog capture's positions show Windows 2000's do.
//!
//! The window manager has no non-client area yet: a dialog's window rectangle is its client area,
//! the template's size mapped.

use rtl::edge::{In, OutBuf};
use rtl::gdi::{LogFontW, Rect, DEFAULT_CHARSET, FW_NORMAL, SYSTEM_FONT};
use rtl::user::*;
use rtl::window::{WindowData, FNID_DIALOG, QUERY_WINDOW_EXTRA, WINDOW_DIALOG};

use crate::imports::{self, Creation, ResourceName};
use crate::procedure::{self, Procedure};
use crate::{answered, failed, focus, message, window};

// --- The public numbers (winuser.h) --------------------------------------------------------------

/// The dialog's extra bytes: DWL_MSGRESULT, DWL_DLGPROC and DWL_USER, and the dialog manager's.
pub const DWL_MSGRESULT: i32 = 0;
pub const DWL_DLGPROC: i32 = 4;
pub const DWL_USER: i32 = 8;
pub const DLGWINDOWEXTRA: i32 = 30;

/// The messages the dialog manager sends and answers.
pub const WM_NEXTDLGCTL: u32 = 0x0028;
pub const WM_SETFONT: u32 = 0x0030;
pub const WM_GETFONT: u32 = 0x0031;
pub const WM_QUERYDRAGICON: u32 = 0x0037;
pub const WM_COMPAREITEM: u32 = 0x0039;
pub const WM_VKEYTOITEM: u32 = 0x002E;
pub const WM_CHARTOITEM: u32 = 0x002F;
pub const WM_GETDLGCODE: u32 = 0x0087;
pub const WM_INITDIALOG: u32 = 0x0110;
pub const WM_COMMAND: u32 = 0x0111;
pub const DM_GETDEFID: u32 = WM_USER;
pub const DM_SETDEFID: u32 = WM_USER + 1;
pub const DM_REPOSITION: u32 = WM_USER + 2;

/// DM_GETDEFID's high word when the dialog has a default button.
pub const DC_HASDEFID: u32 = 0x534B;

/// WM_GETDLGCODE's answers: what a control wants of the keyboard and what kind of control it is.
pub const DLGC_WANTARROWS: u32 = 0x0001;
pub const DLGC_WANTTAB: u32 = 0x0002;
pub const DLGC_WANTALLKEYS: u32 = 0x0004;
pub const DLGC_HASSETSEL: u32 = 0x0008;
pub const DLGC_WANTMESSAGE: u32 = 0x0004;
pub const DLGC_DEFPUSHBUTTON: u32 = 0x0010;
pub const DLGC_UNDEFPUSHBUTTON: u32 = 0x0020;
pub const DLGC_RADIOBUTTON: u32 = 0x0040;
pub const DLGC_WANTCHARS: u32 = 0x0080;
pub const DLGC_STATIC: u32 = 0x0100;
pub const DLGC_BUTTON: u32 = 0x2000;

/// A button's notification of a click (WM_COMMAND's high word).
pub const BN_CLICKED: u32 = 0;

/// The dialog box command ids.
pub const IDOK: u32 = 1;
pub const IDCANCEL: u32 = 2;

/// The window styles the dialog manager reads and sets.
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_DISABLED: u32 = 0x0800_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_GROUP: u32 = 0x0002_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_CONTROLPARENT: u32 = 0x0001_0000;

/// The dialog styles (winuser.h's DS_*).
pub const DS_ABSALIGN: u32 = 0x0001;
pub const DS_SYSMODAL: u32 = 0x0002;
pub const DS_3DLOOK: u32 = 0x0004;
pub const DS_FIXEDSYS: u32 = 0x0008;
pub const DS_NOFAILCREATE: u32 = 0x0010;
pub const DS_SETFONT: u32 = 0x0040;
pub const DS_MODALFRAME: u32 = 0x0080;
pub const DS_CONTROL: u32 = 0x0400;
pub const DS_CENTER: u32 = 0x0800;
pub const DS_CENTERMOUSE: u32 = 0x1000;
pub const DS_CONTEXTHELP: u32 = 0x2000;

/// The virtual keys the keyboard interface handles.
const VK_TAB: u32 = 0x09;
const VK_RETURN: u32 = 0x0D;
const VK_SHIFT: i32 = 0x10;
const VK_ESCAPE: u32 = 0x1B;
const VK_LEFT: u32 = 0x25;
const VK_UP: u32 = 0x26;
const VK_RIGHT: u32 = 0x27;
const VK_DOWN: u32 = 0x28;

/// ShowWindow's command for a dialog shown.
const SW_SHOWNORMAL: i32 = 1;

/// The errors of the dialog calls (winerror.h).
const ERROR_INVALID_DATA: u32 = 13;
pub const ERROR_WINDOW_NOT_DIALOG: u32 = 1420;
pub const ERROR_CONTROL_ID_NOT_FOUND: u32 = 1421;

/// RT_DIALOG: a dialog template resource.
const RT_DIALOG: u16 = 5;

/// The resolution dialog fonts' point sizes become pixels at: F2K's display's, and the captures'
/// (96 DPI, the Small Fonts setting).
const LOGPIXELSY: i32 = 96;

// --- The dialog's own extra bytes ----------------------------------------------------------------

/// The dialog manager's part of the extra bytes, after DWL_USER: the control the focus goes back
/// to when the dialog is activated again, EndDialog's result, the flags (a WORD), the default
/// button's id (a WORD), the dialog's font, and its base units (a WORD: the width unit in the low
/// byte, the height unit in the high one; 0 for the system font's).
const FOCUS_SAVE: i32 = 12;
const RESULT: i32 = 16;
const FLAGS: i32 = 20;
const DEFAULT_ID: i32 = 22;
const FONT: i32 = 24;
const UNITS: i32 = 28;

/// The flags: EndDialog was called; the dialog procedure takes the narrow forms of the messages;
/// the default button's id is set.
const ENDED: u16 = 0x0001;
const ANSI_PROC: u16 = 0x0002;
const HAS_DEFAULT: u16 = 0x0008;

/// A 32-bit value of `window`'s extra bytes at `offset` (0 when it cannot be read).
fn read_long(window: usize, offset: i32) -> u32 {
    let mut value = 0u32;
    let _ = imports::query_window(window, QUERY_WINDOW_EXTRA | offset as u32, &mut value);
    value
}

/// A 16-bit value of `window`'s extra bytes at `offset` (0 when it cannot be read).
fn read_word(window: usize, offset: i32) -> u16 {
    let mut value = 0u16;
    let _ = imports::query_window(window, QUERY_WINDOW_EXTRA | offset as u32, &mut value);
    value
}

/// `window`'s extra bytes at `offset` set to a 32-bit value; the value they held.
fn write_long(window: usize, offset: i32, value: u32) -> u32 {
    imports::set_window_long(window, offset, value, false).map_or(0, |(previous, _)| previous)
}

/// `window`'s extra bytes at `offset` set to a 16-bit value.
fn write_word(window: usize, offset: i32, value: u16) {
    let _ = imports::set_window_word(window, offset, value);
}

/// The dialog's flags changed: `set` set, `clear` cleared.
fn change_flags(dialog: usize, set: u16, clear: u16) {
    let flags = read_word(dialog, FLAGS);
    write_word(dialog, FLAGS, (flags | set) & !clear);
}

/// Whether `window` is a dialog (the dialog manager marked it so).
pub fn is_dialog(window: usize) -> bool {
    window::window_data(window).is_ok_and(|data| data.flags & WINDOW_DIALOG != 0)
}

/// The dialogs of the process, as the dialog manager keeps them beside their extra bytes: each
/// one's handle, its procedure's address and form, and the font the dialog manager made for it.
/// The window manager frees a window before the messages of its destruction reach its procedure
/// (it calls no user-mode code: they are delivered once its service returns), so DefDlgProc's
/// WM_DESTROY and WM_NCDESTROY find the dialog procedure and the font here, as Windows 2000's
/// user32 finds them in its own dialog structure. A record goes at WM_NCDESTROY.
mod kept {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// How many dialogs a process keeps at once; past them a dialog's destruction messages do not
    /// reach its procedure.
    const KEPT: usize = 64;

    struct Kept {
        window: AtomicU32,
        proc: AtomicU32,
        /// The procedure's form (bit 0) and the font's ownership (bit 1).
        flags: AtomicU32,
        font: AtomicU32,
    }

    static DIALOGS: [Kept; KEPT] = [const {
        Kept {
            window: AtomicU32::new(0),
            proc: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            font: AtomicU32::new(0),
        }
    }; KEPT];

    fn find(window: u32) -> Option<&'static Kept> {
        DIALOGS
            .iter()
            .find(|kept| kept.window.load(Ordering::Acquire) == window)
    }

    /// The dialog `window`'s record set (made when it has none).
    pub fn keep(window: usize, proc: u32, ansi: bool, font: u32) {
        let window = window as u32;
        let record = find(window).or_else(|| {
            DIALOGS.iter().find(|kept| {
                kept.window
                    .compare_exchange(0, window, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            })
        });
        if let Some(record) = record {
            record.proc.store(proc, Ordering::Release);
            record
                .flags
                .store(ansi as u32 | ((font != 0) as u32) << 1, Ordering::Release);
            record.font.store(font, Ordering::Release);
        }
    }

    /// The dialog `window`'s procedure and form, as kept.
    pub fn procedure(window: usize) -> Option<(u32, bool)> {
        let record = find(window as u32)?;
        Some((
            record.proc.load(Ordering::Acquire),
            record.flags.load(Ordering::Acquire) & 1 != 0,
        ))
    }

    /// The dialog `window`'s procedure changed in its record.
    pub fn set_procedure(window: usize, proc: u32, ansi: bool) {
        if let Some(record) = find(window as u32) {
            record.proc.store(proc, Ordering::Release);
            let flags = record.flags.load(Ordering::Acquire) & !1;
            record.flags.store(flags | ansi as u32, Ordering::Release);
        }
    }

    /// The dialog `window`'s record dropped: the font the dialog manager made for it, when it did.
    pub fn forget(window: usize) -> Option<u32> {
        let record = find(window as u32)?;
        let owned = record.flags.load(Ordering::Acquire) & 2 != 0;
        let font = record.font.load(Ordering::Acquire);
        record.window.store(0, Ordering::Release);
        (owned && font != 0).then_some(font)
    }
}

/// The dialog procedure of the dialog `window` (its address 0 for none yet), in its own form; none
/// for a window that is no dialog, or none at all (GetWindowLong's DWL_DLGPROC).
pub fn dialog_procedure(window: usize) -> Option<Procedure> {
    let data = window::window_data(window).ok()?;
    (data.flags & WINDOW_DIALOG != 0).then(|| Procedure {
        address: read_long(window, DWL_DLGPROC),
        ansi: read_word(window, FLAGS) & ANSI_PROC != 0,
    })
}

/// DefDlgProc's dialog procedure for `window`: [`dialog_procedure`]'s, or, for a dialog the window
/// manager has freed already, the one the dialog manager kept (its destruction's messages).
fn procedure_for_messages(window: usize) -> Option<Procedure> {
    match window::window_data(window) {
        Ok(_) => dialog_procedure(window),
        Err(_) => kept::procedure(window).map(|(address, ansi)| Procedure { address, ansi }),
    }
}

/// The dialog `window`'s procedure set to `proc` (SetWindowLong's DWL_DLGPROC), the one it had
/// answered; none for a window that is no dialog.
pub fn set_dialog_procedure(window: usize, proc: Procedure) -> Option<Procedure> {
    if !is_dialog(window) {
        return None;
    }
    let previous = dialog_procedure(window)?;
    write_long(window, DWL_DLGPROC, proc.address);
    if proc.ansi {
        change_flags(window, ANSI_PROC, 0);
    } else {
        change_flags(window, 0, ANSI_PROC);
    }
    kept::set_procedure(window, proc.address, proc.ansi);
    Some(previous)
}

// --- Dialog units --------------------------------------------------------------------------------

/// MulDiv: `value` times `numerator` over `denominator`, rounded half away from zero; -1 for a
/// zero denominator.
pub fn mul_div(value: i32, numerator: i32, denominator: i32) -> i32 {
    if denominator == 0 {
        return -1;
    }
    let product = i64::from(value) * i64::from(numerator);
    let (product, denominator) = if denominator < 0 {
        (-product, -i64::from(denominator))
    } else {
        (product, i64::from(denominator))
    };
    let half = denominator / 2;
    let quotient = if product >= 0 {
        (product + half) / denominator
    } else {
        -((-product + half) / denominator)
    };
    quotient as i32
}

/// The 52 letters whose average width is the width unit.
const LETTERS: [u16; 52] = {
    let mut letters = [0u16; 52];
    let mut at = 0;
    while at < 26 {
        letters[at] = b'A' as u16 + at as u16;
        letters[26 + at] = b'a' as u16 + at as u16;
        at += 1;
    }
    letters
};

/// The base units of `font` (none: the system font) as the documentation's formula gives them:
/// the 52 letters' extent `cx` makes the width unit (cx / 26 + 1) / 2, the font's height the
/// height unit; none when the screen's DC cannot measure.
fn font_units(font: Option<usize>) -> Option<(i32, i32)> {
    let dc = crate::dc::get_dc(0);
    if dc == 0 {
        return None;
    }
    let font = font.unwrap_or_else(|| imports::stock_object(SYSTEM_FONT));
    let previous = imports::select_object(dc, font);
    let units = measured_units(dc);
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(0, dc);
    units
}

/// The base units of the font selected into `dc` ([`font_units`]'s formula); none when gdi32
/// cannot measure.
fn measured_units(dc: usize) -> Option<(i32, i32)> {
    let width = imports::text_width(dc, &LETTERS)?;
    let metrics = imports::text_metrics(dc)?;
    Some(((width / 26 + 1) / 2, metrics.height))
}

/// The base units of the font selected into `dc`; the system font's when it cannot be measured.
pub fn units_in(dc: usize) -> (i32, i32) {
    measured_units(dc).unwrap_or_else(system_units)
}

/// The system font's base units, measured once.
fn system_units() -> (i32, i32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static UNITS: AtomicU32 = AtomicU32::new(0);
    let known = UNITS.load(Ordering::Relaxed);
    if known != 0 {
        return ((known & 0xFFFF) as i32, (known >> 16) as i32);
    }
    let (x, y) = font_units(None).unwrap_or((8, 16));
    UNITS.store((x as u32 & 0xFFFF) | (y as u32) << 16, Ordering::Relaxed);
    (x, y)
}

/// The base units of the dialog `dialog`: its font's, the system font's for none.
fn dialog_units(dialog: usize) -> (i32, i32) {
    match read_word(dialog, UNITS) {
        0 => system_units(),
        units => (i32::from(units & 0xFF), i32::from(units >> 8)),
    }
}

/// GetDialogBaseUnits: the system font's base units, the width in the low word and the height in
/// the high word.
#[unsafe(export_name = "f2k_export_GetDialogBaseUnits")]
pub extern "system" fn get_dialog_base_units() -> i32 {
    let (x, y) = system_units();
    ((y as u32) << 16 | (x as u32 & 0xFFFF)) as i32
}

/// MapDialogRect: the caller's rectangle in the dialog's units mapped to pixels, each side on its
/// own; TRUE, or FALSE with 1400 for a handle naming no window, 1420 for a window that is no
/// dialog.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_MapDialogRect")]
pub unsafe extern "system" fn map_dialog_rect(dialog: usize, rect: *mut Rect) -> u32 {
    let Some(data) = answered(window::window_data(dialog)) else {
        return 0;
    };
    if data.flags & WINDOW_DIALOG == 0 {
        return failed(ERROR_WINDOW_NOT_DIALOG).unwrap_or(0);
    }
    // SAFETY: the caller's RECT.
    let mut rect = unsafe { crate::Out::new(rect) };
    let (x, y) = dialog_units(dialog);
    let r = rect.get();
    rect.set(Rect {
        left: mul_div(r.left, x, 4),
        top: mul_div(r.top, y, 8),
        right: mul_div(r.right, x, 4),
        bottom: mul_div(r.bottom, y, 8),
    });
    1
}

// --- Templates -----------------------------------------------------------------------------------

/// A name field of a template (sz_Or_Ord): none, an ordinal, or a string of the given length,
/// copied NUL-terminated into the caller's buffer (cut to it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    None,
    Ordinal(u16),
    Text(usize),
}

/// A template's bytes read in order: `read` answers the byte at an offset (none past a resource's
/// end), `base` is the template's address (its DWORD boundaries are the address's).
pub struct Reader<'a> {
    read: &'a dyn Fn(usize) -> Option<u8>,
    base: usize,
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(read: &'a dyn Fn(usize) -> Option<u8>, base: usize) -> Self {
        Reader { read, base, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = (self.read)(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn word(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.byte()?, self.byte()?]))
    }

    fn dword(&mut self) -> Option<u32> {
        Some(u32::from(self.word()?) | u32::from(self.word()?) << 16)
    }

    fn short(&mut self) -> Option<i32> {
        Some(i32::from(self.word()? as i16))
    }

    /// The next DWORD boundary.
    fn align(&mut self) {
        let address = self.base.wrapping_add(self.at);
        self.at += (4 - address % 4) % 4;
    }

    /// A NUL-terminated string, starting with the unit `first`, into `out`: its length.
    fn string(&mut self, first: u16, out: &mut [u16]) -> Option<usize> {
        let mut length = 0;
        let mut unit = first;
        while unit != 0 {
            if length + 1 < out.len() {
                out[length] = unit;
                length += 1;
            }
            unit = self.word()?;
        }
        if let Some(end) = out.get_mut(length) {
            *end = 0;
        }
        Some(length)
    }

    /// A name field into `out`.
    fn field(&mut self, out: &mut [u16]) -> Option<Field> {
        match self.word()? {
            0 => {
                out[0] = 0;
                Some(Field::None)
            }
            0xFFFF => Some(Field::Ordinal(self.word()?)),
            first => Some(Field::Text(self.string(first, out)?)),
        }
    }
}

/// A template's font: its point size, weight, italic flag and character set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontSpec {
    pub points: u16,
    pub weight: u16,
    pub italic: u8,
    pub charset: u8,
}

/// A template's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub extended: bool,
    pub style: u32,
    pub ex_style: u32,
    pub count: u16,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub menu: Field,
    pub class: Field,
    pub title: Field,
    pub font: Option<FontSpec>,
}

/// The strings of a header, copied.
pub struct HeaderNames {
    pub menu: [u16; 64],
    pub class: [u16; 128],
    pub title: [u16; 256],
    pub face: [u16; 32],
}

impl Default for HeaderNames {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderNames {
    pub const fn new() -> Self {
        HeaderNames {
            menu: [0; 64],
            class: [0; 128],
            title: [0; 256],
            face: [0; 32],
        }
    }
}

/// A template's control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub style: u32,
    pub ex_style: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub id: u32,
    pub class: Field,
    pub title: Field,
    /// The address of the creation data (its WORD size first), 0 for none.
    pub data: usize,
}

/// The strings of a control, copied.
pub struct ItemNames {
    pub class: [u16; 128],
    pub title: [u16; 256],
}

impl Default for ItemNames {
    fn default() -> Self {
        Self::new()
    }
}

impl ItemNames {
    pub const fn new() -> Self {
        ItemNames {
            class: [0; 128],
            title: [0; 256],
        }
    }
}

/// The header DLGTEMPLATEEX's first DWORD holds: dlgVer 1 and the signature 0xFFFF.
const EXTENDED_SIGNATURE: u32 = 0xFFFF_0001;

/// The template's header, its strings into `names`; none for a template cut short.
pub fn read_header(reader: &mut Reader, names: &mut HeaderNames) -> Option<Header> {
    let first = reader.dword()?;
    let extended = first == EXTENDED_SIGNATURE;
    let (ex_style, style) = if extended {
        let _help = reader.dword()?;
        let ex_style = reader.dword()?;
        (ex_style, reader.dword()?)
    } else {
        (reader.dword()?, first)
    };
    let count = reader.word()?;
    let (x, y, cx, cy) = (
        reader.short()?,
        reader.short()?,
        reader.short()?,
        reader.short()?,
    );
    let menu = reader.field(&mut names.menu)?;
    let class = reader.field(&mut names.class)?;
    let title = reader.field(&mut names.title)?;
    let font = if style & DS_SETFONT != 0 {
        let points = reader.word()?;
        let (weight, italic, charset) = if extended {
            (reader.word()?, reader.byte()?, reader.byte()?)
        } else {
            (FW_NORMAL as u16, 0, DEFAULT_CHARSET)
        };
        let first = reader.word()?;
        reader.string(first, &mut names.face)?;
        Some(FontSpec {
            points,
            weight,
            italic,
            charset,
        })
    } else {
        None
    };
    Some(Header {
        extended,
        style,
        ex_style,
        count,
        x,
        y,
        cx,
        cy,
        menu,
        class,
        title,
        font,
    })
}

/// The template's next control, on its DWORD boundary, its strings into `names`; none for a
/// template cut short.
pub fn read_item(reader: &mut Reader, extended: bool, names: &mut ItemNames) -> Option<Item> {
    reader.align();
    let (ex_style, style) = if extended {
        let _help = reader.dword()?;
        let ex_style = reader.dword()?;
        (ex_style, reader.dword()?)
    } else {
        let style = reader.dword()?;
        (reader.dword()?, style)
    };
    let (x, y, cx, cy) = (
        reader.short()?,
        reader.short()?,
        reader.short()?,
        reader.short()?,
    );
    let id = if extended {
        reader.dword()?
    } else {
        u32::from(reader.word()?)
    };
    let class = reader.field(&mut names.class)?;
    let title = reader.field(&mut names.title)?;
    let size = reader.word()?;
    let data = if size == 0 {
        0
    } else {
        reader.base.wrapping_add(reader.at - 2)
    };
    reader.at += usize::from(size);
    Some(Item {
        style,
        ex_style,
        x,
        y,
        cx,
        cy,
        id,
        class,
        title,
        data,
    })
}

/// The predefined control classes' names, by their ordinals 0x80 to 0x85, NUL-terminated.
fn predefined_class(ordinal: u16) -> Option<&'static [u16]> {
    const BUTTON: [u16; 7] = names::<7>("Button");
    const EDIT: [u16; 5] = names::<5>("Edit");
    const STATIC: [u16; 7] = names::<7>("Static");
    const LISTBOX: [u16; 8] = names::<8>("ListBox");
    const SCROLLBAR: [u16; 10] = names::<10>("ScrollBar");
    const COMBOBOX: [u16; 9] = names::<9>("ComboBox");
    Some(match ordinal {
        0x80 => &BUTTON,
        0x81 => &EDIT,
        0x82 => &STATIC,
        0x83 => &LISTBOX,
        0x84 => &SCROLLBAR,
        0x85 => &COMBOBOX,
        _ => return None,
    })
}

/// `text`'s units, NUL-terminated, in an array of `N` (its length plus one).
const fn names<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    let mut out = [0u16; N];
    let mut at = 0;
    while at < bytes.len() {
        out[at] = bytes[at] as u16;
        at += 1;
    }
    out
}

// --- Creation ------------------------------------------------------------------------------------

/// What a dialog is made for: the module its template, class and menu are the module's of, the
/// owner, the dialog procedure, WM_INITDIALOG's lParam, and whether its creator called the narrow
/// form (its window and controls then the narrow caller's).
#[derive(Clone, Copy)]
pub struct Request {
    pub instance: usize,
    pub owner: usize,
    pub proc: Procedure,
    pub param: i32,
    pub ansi: bool,
    /// The call the dialog is made for, as a line about it names it.
    pub call: Call,
}

/// The export a dialog is made through and its arguments (at most five, in order): what a line
/// about a case of the dialog F2K does not handle yet names.
#[derive(Clone, Copy)]
pub struct Call {
    pub entry: &'static rtl::stub::Entry,
    pub args: [u64; 5],
}

impl Call {
    /// The dialog export `entry`'s call: its five arguments (a name or template, an address).
    pub fn of(
        entry: &'static rtl::stub::Entry,
        instance: usize,
        name: usize,
        owner: usize,
        proc: usize,
        param: i32,
    ) -> Self {
        Call {
            entry,
            args: [
                instance as u64,
                name as u64,
                owner as u64,
                proc as u64,
                param as u32 as u64,
            ],
        }
    }

    /// The call's line, `reason` the case F2K does not handle yet.
    pub fn unhandled(&self, reason: impl core::fmt::Display) {
        // SAFETY: the dialog exports' arguments, no string among their kinds (a template's name
        // is a pointer's); or MessageBox's, whose strings are the caller's, which the call has
        // read, and which the line reads only where their pages can be read.
        unsafe { crate::stub::unhandled(self.entry, reason, &self.args) };
    }
}

/// The dialog styles the dialog manager does not handle yet (their effect missing): each one, and
/// what it does on Windows 2000.
const UNHANDLED_DIALOG_STYLES: [(u32, &str); 3] = [
    (DS_SYSMODAL, "DS_SYSMODAL (a system-modal, topmost dialog)"),
    (
        DS_CENTERMOUSE,
        "DS_CENTERMOUSE (the dialog centred on the mouse)",
    ),
    (DS_CONTEXTHELP, "DS_CONTEXTHELP (the caption's help button)"),
];

/// The dialog styles' cases logged in this process.
static DIALOG_STYLES_LOGGED: rtl::stub::Logged<8> = rtl::stub::Logged::new();

/// SS_ICON (a Static's type), and the message that gives it its icon.
const SS_ICON: u32 = 0x0003;
const SS_BITMAP: u32 = 0x000E;
const SS_TYPEMASK: u32 = 0x001F;
const STM_SETICON: u32 = 0x0170;

/// The dialog a template describes, made: the window, its controls, WM_SETFONT and WM_INITDIALOG
/// sent, the focus to the control WM_INITDIALOG named when it answered TRUE, shown when the
/// template asks for WS_VISIBLE and `show` lets it; its handle, or none with the last error
/// (ERROR_INVALID_DATA for a template cut short, the creation's error for a window refused, the
/// part made destroyed).
pub fn create(reader: &mut Reader, request: Request, show: bool) -> Option<usize> {
    let mut names = HeaderNames::new();
    let Some(header) = read_header(reader, &mut names) else {
        return failed(ERROR_INVALID_DATA);
    };
    log_unhandled_styles(&header, &request.call);

    // The font, and the units it gives (the system font's when there is none).
    let font = header.font.and_then(|spec| {
        let mut font = LogFontW {
            height: -mul_div(i32::from(spec.points), LOGPIXELSY, 72),
            width: 0,
            escapement: 0,
            orientation: 0,
            weight: i32::from(spec.weight),
            italic: spec.italic,
            underline: 0,
            strike_out: 0,
            char_set: spec.charset,
            out_precision: 0,
            clip_precision: 0,
            quality: 0,
            pitch_and_family: 0,
            face_name: [0; rtl::gdi::LF_FACESIZE],
        };
        let face = &names.face[..rtl::cstr::nul_len(&names.face)];
        let length = face.len().min(rtl::gdi::LF_FACESIZE - 1);
        font.face_name[..length].copy_from_slice(&face[..length]);
        imports::create_font(&font)
    });
    let (ux, uy) = match font {
        Some(font) => font_units(Some(font)).unwrap_or_else(system_units),
        None => system_units(),
    };

    // The dialog's styles: 4.0's 3D look, a modal frame's extended style, the control parent.
    let mut style = (header.style | DS_3DLOOK) & !WS_VISIBLE;
    let mut ex_style = header.ex_style | WS_EX_CONTROLPARENT;
    if style & DS_MODALFRAME != 0 {
        ex_style |= WS_EX_DLGMODALFRAME;
    }
    if style & DS_CONTROL != 0 {
        style &= !(WS_CAPTION | WS_SYSMENU);
    }

    // Its place: dialog units from the owner's client area (the screen's with DS_ABSALIGN or no
    // owner), centered with DS_CENTER. The template's rectangle is the client area: the window
    // rectangle is the frame around it (AdjustWindowRectEx's, a menu bar's room included), so a
    // dialog's window starts its frame's width up and left of the template's place (an
    // assumption: the documentation places the dialog, not which of its rectangles). A template
    // coordinate of 0x8000 is CW_USEDEFAULT: the marker goes to the window creation as it is
    // (the kernel places a tiled window at the cascade, or the startup info's place), not
    // converted to pixels.
    const TEMPLATE_USEDEFAULT: i32 = -32768; // 0x8000
    let default_x = header.x == TEMPLATE_USEDEFAULT;
    let default_y = header.y == TEMPLATE_USEDEFAULT;
    let client = Rect {
        left: if default_x { 0 } else { mul_div(header.x, ux, 4) },
        top: if default_y { 0 } else { mul_div(header.y, uy, 8) },
        right: if default_x { 0 } else { mul_div(header.x, ux, 4) } + mul_div(header.cx, ux, 4),
        bottom: if default_y { 0 } else { mul_div(header.y, uy, 8) } + mul_div(header.cy, uy, 8),
    };
    let has_menu = !matches!(header.menu, Field::None);
    let outer = rtl::nonclient::Frame::of(style, ex_style, has_menu).window(client);
    let cx = outer.right - outer.left;
    let cy = outer.bottom - outer.top;
    let (mut x, mut y) = (outer.left, outer.top);
    if style & DS_CENTER != 0 {
        x = (crate::display::get_system_metrics(0) - cx) / 2;
        y = (crate::display::get_system_metrics(1) - cy) / 2;
    } else if request.owner != 0 && style & (WS_CHILD | DS_ABSALIGN) == 0 {
        if let Some(origin) = client_origin(request.owner) {
            x += origin.0;
            y += origin.1;
        }
    }
    if default_x && style & DS_CENTER == 0 {
        x = 0x8000_0000u32 as i32; // CW_USEDEFAULT
        if default_y {
            y = 0x8000; // the kernel's second marker: both default, shown at the cascade
        }
    }

    let class = match header.class {
        Field::None => usize::from(crate::class::DIALOG_CLASS_ATOM),
        Field::Ordinal(atom) => usize::from(atom),
        Field::Text(_) => names.class.as_ptr() as usize,
    };
    let menu = match header.menu {
        Field::None => 0,
        // SAFETY: a number in a pointer's place, or this function's own NUL-terminated string.
        Field::Ordinal(id) => unsafe {
            crate::menu::load_menu_w(request.instance, id as usize as *const u16)
        },
        // SAFETY: as above.
        Field::Text(_) => unsafe {
            crate::menu::load_menu_w(request.instance, names.menu.as_ptr())
        },
    };
    let title = match header.title {
        Field::Text(_) => names.title.as_ptr() as usize,
        _ => 0,
    };
    let created = window::create_or_missing(&Creation {
        ex_style: ex_style
            | if request.ansi {
                window::ANSI_CREATOR
            } else {
                0
            },
        class,
        name: title,
        style,
        x,
        y,
        cx,
        cy,
        parent: request.owner,
        menu,
        instance: request.instance,
        param: 0,
        version: window::EXPECTED_VERSION,
    });
    let dialog = match created {
        Ok(dialog) => dialog,
        Err(missing) => {
            if let Some((_, what)) = missing {
                request.call.unhandled(format_args!(
                    "the dialog's own class could not be made: {what} is not yet implemented"
                ));
            }
            if let Some(font) = font {
                imports::delete_object(font);
            }
            return None;
        }
    };

    // The dialog's state: the mark, the procedure, the font and its units.
    let _ = imports::set_window_fnid(dialog, FNID_DIALOG);
    write_long(dialog, DWL_DLGPROC, request.proc.address);
    let mut flags = 0;
    if request.proc.ansi {
        flags |= ANSI_PROC;
    }
    if let Some(font) = font {
        write_long(dialog, FONT, font as u32);
        write_word(dialog, UNITS, (ux as u16 & 0xFF) | (uy as u16) << 8);
    }
    write_word(dialog, FLAGS, flags);
    kept::keep(
        dialog,
        request.proc.address,
        request.proc.ansi,
        font.map_or(0, |font| font as u32),
    );
    if let Some(font) = font {
        let _ = message::send(dialog, WM_SETFONT, font as u32, 0);
    }

    // The controls, in the template's order (each made at the bottom of the z-order).
    let mut item_names = ItemNames::new();
    for _ in 0..header.count {
        let Some(item) = read_item(reader, header.extended, &mut item_names) else {
            window::destroy_window(dialog);
            return failed(ERROR_INVALID_DATA);
        };
        let control = match create_control(dialog, &item, &item_names, request, (ux, uy)) {
            Ok(control) => control,
            Err(missing) => {
                let no_fail = header.style & DS_NOFAILCREATE != 0;
                match missing {
                    Some((name, what)) => {
                        let kept = if no_fail {
                            " (DS_NOFAILCREATE, which keeps the dialog, is not yet implemented)"
                        } else {
                            ""
                        };
                        request.call.unhandled(format_args!(
                            "the dialog's control {} of class {name} could not be made, so the \
                             dialog fails{kept}: {what} is not yet implemented",
                            item.id
                        ));
                    }
                    // Windows 2000 keeps a DS_NOFAILCREATE dialog whose control fails; F2K's
                    // fails with it.
                    None if no_fail => request.call.unhandled(format_args!(
                        "the dialog's control {} could not be made, so the dialog fails: \
                         DS_NOFAILCREATE, which keeps the dialog, is not yet implemented",
                        item.id
                    )),
                    None => {}
                }
                window::destroy_window(dialog);
                return None;
            }
        };
        if let Some(font) = font {
            let _ = message::send(control, WM_SETFONT, font as u32, 0);
        }
        if read_word(dialog, FLAGS) & HAS_DEFAULT == 0
            && dialog_code(control, 0) & DLGC_DEFPUSHBUTTON != 0
        {
            write_word(dialog, DEFAULT_ID, item.id as u16);
            change_flags(dialog, HAS_DEFAULT, 0);
        }
    }

    // WM_INITDIALOG, wParam the first control the focus may go to.
    let first = next_tab_item(dialog, 0, false);
    let answer = message::send(dialog, WM_INITDIALOG, first as u32, request.param).unwrap_or(0);
    if !window::is_window_alive(dialog) {
        return None;
    }
    if answer != 0 && first != 0 && read_word(dialog, FLAGS) & ENDED == 0 {
        set_dialog_focus(dialog, first);
    }
    if show && header.style & WS_VISIBLE != 0 && read_word(dialog, FLAGS) & ENDED == 0 {
        window::show_window(dialog, SW_SHOWNORMAL);
    }
    Some(dialog)
}

/// The dialog styles of `header` the dialog manager does not handle yet, logged for `call` (each
/// once per process): the [`UNHANDLED_DIALOG_STYLES`], and DS_FIXEDSYS without a font of the
/// template's (the fixed system font in the system font's place).
fn log_unhandled_styles(header: &Header, call: &Call) {
    for &(style, what) in &UNHANDLED_DIALOG_STYLES {
        if header.style & style != 0 && DIALOG_STYLES_LOGGED.first(style) {
            call.unhandled(format_args!("{what} is not yet implemented"));
        }
    }
    if header.style & (DS_FIXEDSYS | DS_SETFONT) == DS_FIXEDSYS
        && DIALOG_STYLES_LOGGED.first(DS_FIXEDSYS)
    {
        call.unhandled("DS_FIXEDSYS (the fixed system font) is not yet implemented");
    }
}

/// The screen coordinates of `window`'s client area's origin.
fn client_origin(window: usize) -> Option<(i32, i32)> {
    let mut point = Point { x: 0, y: 0 };
    // SAFETY: a POINT of this function's own.
    (unsafe { window::client_to_screen(window, &mut point) } != 0).then_some((point.x, point.y))
}

/// One of the dialog's controls made from its template's item: its handle; or, with the creation's
/// error, the system class F2K does not register yet that the control named, when it did (see
/// [`window::create_or_missing`]).
fn create_control(
    dialog: usize,
    item: &Item,
    names: &ItemNames,
    request: Request,
    (ux, uy): (i32, i32),
) -> Result<usize, Option<(&'static str, &'static str)>> {
    let class = match item.class {
        Field::Ordinal(ordinal) => match predefined_class(ordinal) {
            Some(name) => name.as_ptr() as usize,
            None => usize::from(ordinal),
        },
        Field::Text(_) => names.class.as_ptr() as usize,
        Field::None => return failed(ERROR_INVALID_DATA).ok_or(None),
    };
    let title = match item.title {
        Field::Text(_) => names.title.as_ptr() as usize,
        _ => 0,
    };
    let control = window::create_or_missing(&Creation {
        ex_style: item.ex_style
            | WS_EX_NOPARENTNOTIFY
            | if request.ansi {
                window::ANSI_CREATOR
            } else {
                0
            },
        class,
        name: title,
        style: item.style,
        x: mul_div(item.x, ux, 4),
        y: mul_div(item.y, uy, 8),
        cx: mul_div(item.cx, ux, 4),
        cy: mul_div(item.cy, uy, 8),
        parent: dialog,
        menu: item.id as usize,
        instance: request.instance,
        param: item.data,
        version: window::EXPECTED_VERSION,
    })?;
    // A Static icon's title is the number of its icon resource.
    let static_class = matches!(item.class, Field::Ordinal(0x82));
    match item.title {
        Field::Ordinal(id) if item.style & SS_TYPEMASK == SS_ICON => {
            // SAFETY: a number in a pointer's place.
            let icon =
                unsafe { crate::icon::load_icon_w(request.instance, id as usize as *const u16) };
            if icon != 0 {
                let _ = message::send(control, STM_SETICON, icon as u32, 0);
            }
        }
        Field::Ordinal(id) if static_class && item.style & SS_TYPEMASK == SS_BITMAP => {
            request.call.unhandled(format_args!(
                "the dialog's control {} names bitmap resource {id}: SS_BITMAP statics' bitmaps \
                 are not yet loaded",
                item.id
            ));
        }
        Field::Text(_) if static_class && item.style & SS_TYPEMASK == SS_ICON => {
            request.call.unhandled(format_args!(
                "the dialog's control {} names its icon by name: icons named by a string are not \
                 yet loaded for an SS_ICON static",
                item.id
            ));
        }
        _ => {}
    }
    Ok(control)
}

/// The dialog template resource `name` of the module `instance`: its data; none with kernel32's
/// last error when the module has none.
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn template_resource(instance: usize, name: ResourceName) -> Option<&'static [u8]> {
    // SAFETY: the caller's contract.
    let found = unsafe { imports::find_named_resource(instance, RT_DIALOG, name) }?;
    imports::resource_data(instance, found)
}

/// A dialog made from the resource `name`: its handle, or 0 with the last error.
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn create_from_resource(name: ResourceName, request: Request) -> usize {
    // SAFETY: the caller's contract.
    let Some(data) = (unsafe { template_resource(request.instance, name) }) else {
        return 0;
    };
    let read = |at: usize| data.get(at).copied();
    let mut reader = Reader::new(&read, data.as_ptr() as usize);
    create(&mut reader, request, true).unwrap_or(0)
}

/// CreateDialogParamW: the modeless dialog the module's template resource `name` describes,
/// `proc` its dialog procedure, `param` WM_INITDIALOG's lParam; its handle, or NULL with the last
/// error (ERROR_RESOURCE_NAME_NOT_FOUND for a template the module does not have).
///
/// # Safety
///
/// `name` is a resource number or a NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_CreateDialogParamW")]
pub unsafe extern "system" fn create_dialog_param_w(
    instance: usize,
    name: *const u16,
    owner: usize,
    proc: usize,
    param: i32,
) -> usize {
    let request = Request {
        instance,
        owner,
        proc: Procedure {
            address: proc as u32,
            ansi: false,
        },
        param,
        ansi: false,
        call: Call::of(
            &crate::spec::CreateDialogParamW,
            instance,
            name as usize,
            owner,
            proc,
            param,
        ),
    };
    // SAFETY: the caller's contract.
    unsafe { create_from_resource(ResourceName::Wide(name as usize), request) }
}

/// CreateDialogParamA: CreateDialogParamW's, the name an ANSI string or a number, the dialog and
/// its procedure the narrow caller's.
///
/// # Safety
///
/// As CreateDialogParamW's, the string ANSI.
#[unsafe(export_name = "f2k_export_CreateDialogParamA")]
pub unsafe extern "system" fn create_dialog_param_a(
    instance: usize,
    name: *const u8,
    owner: usize,
    proc: usize,
    param: i32,
) -> usize {
    let request = Request {
        instance,
        owner,
        proc: Procedure {
            address: proc as u32,
            ansi: true,
        },
        param,
        ansi: true,
        call: Call::of(
            &crate::spec::CreateDialogParamA,
            instance,
            name as usize,
            owner,
            proc,
            param,
        ),
    };
    // SAFETY: the caller's contract.
    unsafe { create_from_resource(ResourceName::Narrow(name as usize), request) }
}

/// CreateDialogIndirectParamW: the modeless dialog the template in the caller's memory describes.
///
/// # Safety
///
/// `template` is a DLGTEMPLATE or DLGTEMPLATEEX the call may read whole, DWORD-aligned, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_CreateDialogIndirectParamW")]
pub unsafe extern "system" fn create_dialog_indirect_param_w(
    instance: usize,
    template: *const u8,
    owner: usize,
    proc: usize,
    param: i32,
) -> usize {
    // SAFETY: the caller's template, which the reader reads only as far as its own structure goes.
    let read = |at: usize| Some(unsafe { template.add(at).read() });
    let mut reader = Reader::new(&read, template as usize);
    let request = Request {
        instance,
        owner,
        proc: Procedure {
            address: proc as u32,
            ansi: false,
        },
        param,
        ansi: false,
        call: Call::of(
            &crate::spec::CreateDialogIndirectParamW,
            instance,
            template as usize,
            owner,
            proc,
            param,
        ),
    };
    create(&mut reader, request, true).unwrap_or(0)
}

// --- Modal dialogs -------------------------------------------------------------------------------

/// The modal loop over the dialog `dialog`, its owner `owner` disabled meanwhile: the calling
/// thread's messages read and handed to IsDialogMessage (the others translated and dispatched)
/// until EndDialog; the dialog shown the first time the queue is found empty (so a command the
/// dialog posted itself in WM_INITDIALOG reaches it before it shows, as the dialog capture's
/// does). WM_QUIT ends the loop and is posted again for the caller's own loop. The dialog is
/// destroyed after it; EndDialog's result is the answer.
pub fn run_modal(dialog: usize, owner: usize) -> i32 {
    let disabled = owner != 0 && focus::is_window_enabled(owner) != 0;
    if disabled {
        focus::enable_window(owner, 0);
    }
    let mut shown = false;
    let mut msg = Msg::default();
    while window::is_window_alive(dialog) && read_word(dialog, FLAGS) & ENDED == 0 {
        if !shown && !message::queue_holds_message() {
            shown = true;
            window::show_window(dialog, SW_SHOWNORMAL);
            continue;
        }
        match message::next_message(&mut msg) {
            Some(true) => {}
            Some(false) => {
                message::post_quit_message(msg.wparam as i32);
                break;
            }
            None => break,
        }
        if !is_dialog_message(dialog, &msg, false) {
            message::translate(&msg);
            message::dispatch(&msg, false);
        }
    }
    let result = read_long(dialog, RESULT) as i32;
    if disabled {
        focus::enable_window(owner, 1);
    }
    window::destroy_window(dialog);
    result
}

/// A modal dialog made from the resource `name` and run: EndDialog's result, or -1 with the last
/// error when it could not be made.
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn modal_from_resource(name: ResourceName, request: Request) -> i32 {
    // SAFETY: the caller's contract.
    let Some(data) = (unsafe { template_resource(request.instance, name) }) else {
        return -1;
    };
    let read = |at: usize| data.get(at).copied();
    let mut reader = Reader::new(&read, data.as_ptr() as usize);
    match create(&mut reader, request, false) {
        Some(dialog) => run_modal(dialog, request.owner),
        None => -1,
    }
}

/// DialogBoxParamW: the modal dialog the module's template resource `name` describes, run until
/// EndDialog: its result, or -1 with the last error when it could not be made.
///
/// # Safety
///
/// `name` is a resource number or a NUL-terminated UTF-16 string, as for the platform's.
#[unsafe(export_name = "f2k_export_DialogBoxParamW")]
pub unsafe extern "system" fn dialog_box_param_w(
    instance: usize,
    name: *const u16,
    owner: usize,
    proc: usize,
    param: i32,
) -> i32 {
    let request = Request {
        instance,
        owner,
        proc: Procedure {
            address: proc as u32,
            ansi: false,
        },
        param,
        ansi: false,
        call: Call::of(
            &crate::spec::DialogBoxParamW,
            instance,
            name as usize,
            owner,
            proc,
            param,
        ),
    };
    // SAFETY: the caller's contract.
    unsafe { modal_from_resource(ResourceName::Wide(name as usize), request) }
}

/// DialogBoxParamA: DialogBoxParamW's, the name an ANSI string or a number, the dialog and its
/// procedure the narrow caller's.
///
/// # Safety
///
/// As DialogBoxParamW's, the string ANSI.
#[unsafe(export_name = "f2k_export_DialogBoxParamA")]
pub unsafe extern "system" fn dialog_box_param_a(
    instance: usize,
    name: *const u8,
    owner: usize,
    proc: usize,
    param: i32,
) -> i32 {
    let request = Request {
        instance,
        owner,
        proc: Procedure {
            address: proc as u32,
            ansi: true,
        },
        param,
        ansi: true,
        call: Call::of(
            &crate::spec::DialogBoxParamA,
            instance,
            name as usize,
            owner,
            proc,
            param,
        ),
    };
    // SAFETY: the caller's contract.
    unsafe { modal_from_resource(ResourceName::Narrow(name as usize), request) }
}

/// EndDialog: the dialog's end asked for, `result` what its DialogBox answers; the modal loop ends
/// once the message it is handling returns (a WM_NULL posted wakes a loop waiting for one). TRUE,
/// or FALSE with 1400 for a handle naming no window, 1420 for a window that is no dialog.
#[unsafe(export_name = "f2k_export_EndDialog")]
pub extern "system" fn end_dialog(dialog: usize, result: i32) -> u32 {
    let Some(data) = answered(window::window_data(dialog)) else {
        return 0;
    };
    if data.flags & WINDOW_DIALOG == 0 {
        return failed(ERROR_WINDOW_NOT_DIALOG).unwrap_or(0);
    }
    write_long(dialog, RESULT, result as u32);
    change_flags(dialog, ENDED, 0);
    let _ = imports::post_message(dialog, WM_NULL, 0, 0);
    1
}

// --- DefDlgProc ----------------------------------------------------------------------------------

/// Whether the dialog procedure's own answer to `message` is the message's (DefDlgProc answers it
/// as it is), rather than TRUE for "handled" with the answer in DWL_MSGRESULT.
fn answers_directly(message: u32) -> bool {
    matches!(
        message,
        WM_INITDIALOG
            | WM_COMPAREITEM
            | WM_VKEYTOITEM
            | WM_CHARTOITEM
            | WM_QUERYDRAGICON
            | message::WM_CTLCOLORMSGBOX..=message::WM_CTLCOLORSTATIC
    )
}

/// DefDlgProc's core, for a message of the narrow (`ansi`) or wide form: the dialog procedure
/// called first (translated when it takes the other form); its nonzero answer handled the message
/// (the answer itself for the messages that answer directly, DWL_MSGRESULT for the others). A
/// message it left (FALSE) gets the dialog's default: WM_ERASEBKGND the client area in the
/// WM_CTLCOLORDLG brush, WM_ACTIVATE the focus saved or brought back, WM_SETFOCUS the focus to the
/// saved control or the first one, WM_CLOSE IDCANCEL posted, DM_GETDEFID and DM_SETDEFID the
/// default button, WM_NEXTDLGCTL the focus moved, WM_GETFONT the dialog's font; the rest the
/// default window procedure's. WM_NCDESTROY deletes the font the dialog manager made.
fn default_dialog(dialog: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    if let Some(proc) = procedure_for_messages(dialog).filter(|proc| proc.address != 0) {
        let answer = procedure::call(proc, ansi, dialog as u32, message, wparam, lparam);
        if message == WM_NCDESTROY {
            release_font(dialog);
        }
        if answer != 0 {
            if answers_directly(message) {
                return answer;
            }
            return if window::is_window_alive(dialog) {
                read_long(dialog, DWL_MSGRESULT) as i32
            } else {
                0
            };
        }
        if !window::is_window_alive(dialog) {
            return 0;
        }
    } else if message == WM_NCDESTROY {
        release_font(dialog);
    }
    match message {
        WM_ERASEBKGND => {
            let dc = wparam as usize;
            let brush =
                message::send(dialog, message::WM_CTLCOLORDLG, wparam, dialog as i32).unwrap_or(0);
            if let Some(client) = window::client_rect(dialog) {
                crate::draw::fill(dc, client, brush as usize);
            }
            1
        }
        WM_ACTIVATE => {
            if wparam & 0xFFFF == WA_INACTIVE {
                save_focus(dialog);
            } else if restore_focus(dialog) {
                return 0;
            }
            message::default_procedure(dialog, message, wparam, lparam, ansi)
        }
        WM_SETFOCUS => {
            if !restore_focus(dialog) {
                let first = next_tab_item(dialog, 0, false);
                if first != 0 {
                    set_dialog_focus(dialog, first);
                }
            }
            0
        }
        WM_CLOSE => {
            let cancel = child_by_id(dialog, IDCANCEL);
            if cancel == 0 || focus::is_window_enabled(cancel) != 0 {
                let _ = imports::post_message(
                    dialog,
                    WM_COMMAND,
                    BN_CLICKED << 16 | IDCANCEL,
                    cancel as i32,
                );
            }
            0
        }
        DM_GETDEFID => {
            if read_word(dialog, FLAGS) & HAS_DEFAULT != 0 {
                (DC_HASDEFID << 16 | u32::from(read_word(dialog, DEFAULT_ID))) as i32
            } else {
                0
            }
        }
        DM_SETDEFID => {
            write_word(dialog, DEFAULT_ID, wparam as u16);
            change_flags(dialog, HAS_DEFAULT, 0);
            let focus = focus::get_focus();
            check_default_button(
                dialog,
                if is_descendant(dialog, focus) {
                    focus
                } else {
                    0
                },
            );
            1
        }
        DM_REPOSITION => 0,
        WM_NEXTDLGCTL => {
            let target = if lparam & 0xFFFF != 0 {
                wparam as usize
            } else {
                next_tab_item(dialog, focus::get_focus(), wparam != 0)
            };
            if target != 0 {
                set_dialog_focus(dialog, target);
            }
            0
        }
        WM_GETFONT => read_long(dialog, FONT) as i32,
        _ => message::default_procedure(dialog, message, wparam, lparam, ansi),
    }
}

/// The dialog's record dropped and the font the dialog manager made for it deleted (at its
/// WM_NCDESTROY).
fn release_font(dialog: usize) {
    if let Some(font) = kept::forget(dialog) {
        imports::delete_object(font as usize);
    }
}

/// The dialog's focus control kept for its next activation (its WM_ACTIVATE going inactive).
fn save_focus(dialog: usize) {
    let focus = focus::get_focus();
    if focus != 0 && is_descendant(dialog, focus) {
        write_long(dialog, FOCUS_SAVE, focus as u32);
    }
}

/// The focus back to the control the dialog kept, when it still is one of its enabled controls;
/// whether it went.
fn restore_focus(dialog: usize) -> bool {
    let saved = read_long(dialog, FOCUS_SAVE) as usize;
    if saved == 0 || !is_descendant(dialog, saved) || focus::is_window_enabled(saved) == 0 {
        return false;
    }
    focus::set_focus(saved);
    true
}

/// DefDlgProcA: the dialog class's procedure for a narrow message.
#[unsafe(export_name = "f2k_export_DefDlgProcA")]
pub extern "system" fn def_dlg_proc_a(
    dialog: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_dialog(dialog, message, wparam, lparam, true)
}

/// DefDlgProcW: the dialog class's procedure for a wide message.
#[unsafe(export_name = "f2k_export_DefDlgProcW")]
pub extern "system" fn def_dlg_proc_w(
    dialog: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    default_dialog(dialog, message, wparam, lparam, false)
}

// --- The controls --------------------------------------------------------------------------------

/// Whether `window` is `ancestor` or below it, up its chain of parents; the last error untouched.
pub fn is_descendant(ancestor: usize, window: usize) -> bool {
    let mut current = window;
    for _ in 0..64 {
        if current == 0 {
            return false;
        }
        if current == ancestor {
            return true;
        }
        let Some(style) = window::style_of(current) else {
            return false;
        };
        if style & WS_CHILD == 0 {
            return false;
        }
        current = window::links(current).map_or(0, |links| links.parent as usize);
    }
    false
}

/// The control's WM_GETDLGCODE answer (`msg` the address of the MSG asked about, 0 for none).
pub fn dialog_code(control: usize, msg: usize) -> u32 {
    message::send(control, WM_GETDLGCODE, 0, msg as i32).unwrap_or(0) as u32
}

/// The dialog's child with the id `id`, 0 for none; the last error untouched.
pub fn child_by_id(dialog: usize, id: u32) -> usize {
    window::children(dialog)
        .find(|&child| window::window_data(child).is_ok_and(|data| data.id == id))
        .unwrap_or(0)
}

/// How many controls the walks take: a dialog's children past these are not visited.
const MOST_CONTROLS: usize = 256;

/// The dialog's children, from the top of the z-order, into `out`: how many.
fn child_list(dialog: usize, out: &mut [usize; MOST_CONTROLS]) -> usize {
    let mut count = 0;
    for child in window::children(dialog).take(MOST_CONTROLS) {
        out[count] = child;
        count += 1;
    }
    count
}

/// Whether a control may take the focus: its style visible, enabled and, for `tab`, a tab stop.
fn takes_focus(control: usize, tab: bool) -> bool {
    let wanted = WS_VISIBLE | if tab { WS_TABSTOP } else { 0 };
    window::style_of(control).is_some_and(|style| style & (wanted | WS_DISABLED) == wanted)
}

/// GetNextDlgTabItem's walk: the control after `from` (before it with `previous`) in the dialog's
/// z-order that is a visible, enabled tab stop, round the end; the first one from the top (the
/// last with `previous`) for no `from`; `from` itself when no other is one, 0 when no control is.
pub fn next_tab_item(dialog: usize, from: usize, previous: bool) -> usize {
    let mut children = [0usize; MOST_CONTROLS];
    let count = child_list(dialog, &mut children);
    if count == 0 {
        return 0;
    }
    let start = children[..count].iter().position(|&child| child == from);
    for step in 1..=count {
        let index = match (start, previous) {
            (Some(at), false) => (at + step) % count,
            (Some(at), true) => (at + count - step % count) % count,
            (None, false) => step - 1,
            (None, true) => count - step,
        };
        if takes_focus(children[index], true) {
            return children[index];
        }
    }
    if start.is_some() {
        from
    } else {
        0
    }
}

/// GetNextDlgGroupItem's walk: within `from`'s group (from the control with WS_GROUP at or before
/// it to the next one with WS_GROUP), the visible, enabled control after it (before it with
/// `previous`), round the group's end; `from` itself when there is no other.
pub fn next_group_item(dialog: usize, from: usize, previous: bool) -> usize {
    let mut children = [0usize; MOST_CONTROLS];
    let count = child_list(dialog, &mut children);
    let Some(at) = children[..count].iter().position(|&child| child == from) else {
        return from;
    };
    let group = |child: usize| window::style_of(child).is_some_and(|style| style & WS_GROUP != 0);
    let first = (0..=at)
        .rev()
        .find(|&index| group(children[index]))
        .unwrap_or(0);
    let end = (at + 1..count)
        .find(|&index| group(children[index]))
        .unwrap_or(count);
    let size = end - first;
    for step in 1..size {
        let offset = at - first;
        let index = first
            + if previous {
                (offset + size - step) % size
            } else {
                (offset + step) % size
            };
        if takes_focus(children[index], false) {
            return children[index];
        }
    }
    from
}

/// The control after `from` in its group, round the group's end, whatever its state (an automatic
/// radio button's walk over the buttons it unchecks); `from` itself when it is alone.
pub fn next_group_item_any(parent: usize, from: usize) -> usize {
    let mut children = [0usize; MOST_CONTROLS];
    let count = child_list(parent, &mut children);
    let Some(at) = children[..count].iter().position(|&child| child == from) else {
        return from;
    };
    let group = |child: usize| window::style_of(child).is_some_and(|style| style & WS_GROUP != 0);
    let first = (0..=at)
        .rev()
        .find(|&index| group(children[index]))
        .unwrap_or(0);
    let end = (at + 1..count)
        .find(|&index| group(children[index]))
        .unwrap_or(count);
    let next = if at + 1 < end { at + 1 } else { first };
    children[next]
}

/// The focus moved to `control` by the dialog manager (DlgSetFocus): a control that keeps a
/// selection (DLGC_HASSETSEL: an edit) has all its text selected first, as Windows 2000's dialog
/// manager selects it, then the focus set, the control kept for the dialog's next activation, and
/// the default push button's look moved with it.
pub fn set_dialog_focus(dialog: usize, control: usize) {
    if dialog_code(control, 0) & DLGC_HASSETSEL != 0 {
        let _ = message::send(control, crate::edit::EM_SETSEL, 0, -1);
    }
    focus::set_focus(control);
    if focus::get_focus() == control {
        write_long(dialog, FOCUS_SAVE, control as u32);
    }
    check_default_button(dialog, control);
}

/// BM_SETSTYLE and the push buttons' styles (button.rs's).
const BM_SETSTYLE: u32 = 0x00F4;
const BS_PUSHBUTTON: u32 = 0x0000;
const BS_DEFPUSHBUTTON: u32 = 0x0001;

/// The default push button's look where the focus is: a push button with the focus looks the
/// default (Enter presses it), and otherwise the dialog's default button does; every other push
/// button looks a plain one. DM_GETDEFID's id does not change.
fn check_default_button(dialog: usize, focus: usize) {
    let push = |control: usize| {
        control != 0 && dialog_code(control, 0) & (DLGC_DEFPUSHBUTTON | DLGC_UNDEFPUSHBUTTON) != 0
    };
    let target = if push(focus) {
        focus
    } else if read_word(dialog, FLAGS) & HAS_DEFAULT != 0 {
        let default = child_by_id(dialog, u32::from(read_word(dialog, DEFAULT_ID)));
        if push(default) {
            default
        } else {
            0
        }
    } else {
        0
    };
    for child in window::children(dialog) {
        let code = dialog_code(child, 0);
        if child == target && code & DLGC_UNDEFPUSHBUTTON != 0 {
            let _ = message::send(child, BM_SETSTYLE, BS_DEFPUSHBUTTON, 1);
        } else if child != target && code & DLGC_DEFPUSHBUTTON != 0 {
            let _ = message::send(child, BM_SETSTYLE, BS_PUSHBUTTON, 1);
        }
    }
}

// --- The GetDlgItem family -----------------------------------------------------------------------

/// GetDlgItem: the dialog's control with the id `id`; NULL with 1400 for a handle naming no window,
/// 1421 for no control of that id.
#[unsafe(export_name = "f2k_export_GetDlgItem")]
pub extern "system" fn get_dlg_item(dialog: usize, id: i32) -> usize {
    if answered(window::links(dialog)).is_none() {
        return 0;
    }
    match child_by_id(dialog, id as u32) {
        0 => failed(ERROR_CONTROL_ID_NOT_FOUND).unwrap_or(0),
        control => control,
    }
}

/// GetDlgCtrlID: the window's id (GWL_ID: a control's id; a top-level window's menu, 0 for a
/// dialog); 0 with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_GetDlgCtrlID")]
pub extern "system" fn get_dlg_ctrl_id(window: usize) -> i32 {
    answered(window::window_data(window)).map_or(0, |data: WindowData| data.id as i32)
}

/// SetDlgItemTextW: the control's text set (SetWindowTextW); TRUE, or FALSE with the last error
/// (1421 for no control of that id).
#[unsafe(export_name = "f2k_export_SetDlgItemTextW")]
pub extern "system" fn set_dlg_item_text_w(dialog: usize, id: i32, text: *const u16) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => 0,
        control => window::set_window_text_w(control, text as usize),
    }
}

/// SetDlgItemTextA: SetDlgItemTextW's, the text narrow.
#[unsafe(export_name = "f2k_export_SetDlgItemTextA")]
pub extern "system" fn set_dlg_item_text_a(dialog: usize, id: i32, text: *const u8) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => 0,
        control => window::set_window_text_a(control, text as usize),
    }
}

/// GetDlgItemTextW: the control's text into the caller's buffer of `max` units (GetWindowTextW):
/// the units copied; 0 with the last error for no control of that id, the buffer's first unit a
/// terminator when it has room.
///
/// # Safety
///
/// `buffer` holds `max` units the call may write, as for the platform's.
#[unsafe(export_name = "f2k_export_GetDlgItemTextW")]
pub unsafe extern "system" fn get_dlg_item_text_w(
    dialog: usize,
    id: i32,
    buffer: *mut u16,
    max: i32,
) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => {
            if max > 0 {
                // SAFETY: the caller's buffer of `max` units.
                unsafe { OutBuf::new(buffer, max as usize) }.set(0, 0);
            }
            0
        }
        // SAFETY: the caller's contract.
        control => unsafe { window::get_window_text_w(control, buffer, max) as u32 },
    }
}

/// GetDlgItemTextA: GetDlgItemTextW's, into a buffer of `max` bytes, the text narrow.
///
/// # Safety
///
/// `buffer` holds `max` bytes the call may write, as for the platform's.
#[unsafe(export_name = "f2k_export_GetDlgItemTextA")]
pub unsafe extern "system" fn get_dlg_item_text_a(
    dialog: usize,
    id: i32,
    buffer: *mut u8,
    max: i32,
) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => {
            if max > 0 {
                // SAFETY: the caller's buffer of `max` bytes.
                unsafe { OutBuf::new(buffer, max as usize) }.set(0, 0);
            }
            0
        }
        // SAFETY: the caller's contract.
        control => unsafe { window::get_window_text_a(control, buffer, max) as u32 },
    }
}

/// SendDlgItemMessageW: the message sent to the control, its answer; 0 with the last error for no
/// control of that id.
#[unsafe(export_name = "f2k_export_SendDlgItemMessageW")]
pub extern "system" fn send_dlg_item_message_w(
    dialog: usize,
    id: i32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    match get_dlg_item(dialog, id) {
        0 => 0,
        control => message::send_message_w(control, message, wparam, lparam),
    }
}

/// SetDlgItemInt: the control's text set to `value` in decimal, signed (a minus sign for a
/// negative value) or unsigned; TRUE, or FALSE with the last error for no control of that id.
#[unsafe(export_name = "f2k_export_SetDlgItemInt")]
pub extern "system" fn set_dlg_item_int(dialog: usize, id: i32, value: u32, signed: u32) -> u32 {
    let mut units = [0u16; 12];
    format_int(value, signed != 0, &mut units);
    set_dlg_item_text_w(dialog, id, units.as_ptr())
}

/// `value` in decimal into `out`, NUL-terminated.
fn format_int(value: u32, signed: bool, out: &mut [u16; 12]) {
    let negative = signed && (value as i32) < 0;
    let mut magnitude = if negative {
        (value as i32).unsigned_abs()
    } else {
        value
    };
    let mut digits = [0u16; 10];
    let mut count = 0;
    loop {
        digits[count] = b'0' as u16 + (magnitude % 10) as u16;
        count += 1;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    let mut at = 0;
    if negative {
        out[0] = b'-' as u16;
        at = 1;
    }
    for index in (0..count).rev() {
        out[at] = digits[index];
        at += 1;
    }
    out[at] = 0;
}

/// GetDlgItemInt's reading of a text, as the dialog capture shows Windows 2000's: leading spaces
/// passed over; a minus sign for a signed reading; the decimal digits; anything after them (a
/// space too) leaves the value read but untranslated. No digits, a value past 32 bits, or a signed
/// value past the positive range is 0, untranslated; a signed negative value past -2147483647 is
/// read but untranslated. The answer is the value and whether it translated.
pub fn parse_int(text: &[u16], signed: bool) -> (u32, bool) {
    let mut at = 0;
    while text.get(at) == Some(&(b' ' as u16)) {
        at += 1;
    }
    let negative = signed && text.get(at) == Some(&(b'-' as u16));
    if negative {
        at += 1;
    }
    let start = at;
    let mut magnitude = 0u64;
    while let Some(&unit) = text.get(at) {
        let digit = u64::from(unit).wrapping_sub(u64::from(b'0'));
        if digit > 9 {
            break;
        }
        magnitude = magnitude * 10 + digit;
        if magnitude > u64::from(u32::MAX) {
            return (0, false);
        }
        at += 1;
    }
    if at == start {
        return (0, false);
    }
    let whole = at == text.len();
    if !signed {
        return (magnitude as u32, whole);
    }
    if !negative {
        return if magnitude > 0x7FFF_FFFF {
            (0, false)
        } else {
            (magnitude as u32, whole)
        };
    }
    if magnitude > 0x8000_0000 {
        return (0, false);
    }
    (
        (magnitude as u32).wrapping_neg(),
        whole && magnitude <= 0x7FFF_FFFF,
    )
}

/// GetDlgItemInt: the control's text read as a decimal integer ([`parse_int`]), whether it
/// translated into the caller's BOOL (when there is one); 0, untranslated, with the last error
/// for no control of that id.
///
/// # Safety
///
/// `translated` is the caller's BOOL or null, as for the platform's.
#[unsafe(export_name = "f2k_export_GetDlgItemInt")]
pub unsafe extern "system" fn get_dlg_item_int(
    dialog: usize,
    id: i32,
    translated: *mut u32,
    signed: u32,
) -> u32 {
    // SAFETY: the caller's BOOL, or null.
    let mut translated = unsafe { crate::Out::optional(translated) };
    if let Some(translated) = translated.as_mut() {
        translated.set(0);
    }
    let control = get_dlg_item(dialog, id);
    if control == 0 {
        return 0;
    }
    let mut units = [0u16; 64];
    // SAFETY: a buffer of this function's own, of its length.
    let length = unsafe { window::get_window_text_w(control, units.as_mut_ptr(), 64) }.max(0);
    let (value, ok) = parse_int(&units[..length as usize], signed != 0);
    if let Some(translated) = translated.as_mut() {
        translated.set(ok as u32);
    }
    value
}

/// BM_SETCHECK and BM_GETCHECK (button.rs's).
const BM_GETCHECK: u32 = 0x00F0;
const BM_SETCHECK: u32 = 0x00F1;

/// CheckDlgButton: the control sent BM_SETCHECK with `check`; TRUE (whatever the control does with
/// it), or FALSE with the last error for no control of that id.
#[unsafe(export_name = "f2k_export_CheckDlgButton")]
pub extern "system" fn check_dlg_button(dialog: usize, id: i32, check: u32) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => 0,
        control => {
            let _ = message::send(control, BM_SETCHECK, check, 0);
            1
        }
    }
}

/// IsDlgButtonChecked: the control's BM_GETCHECK answer (0 from a control that is no check box or
/// radio button); 0 with the last error for no control of that id.
#[unsafe(export_name = "f2k_export_IsDlgButtonChecked")]
pub extern "system" fn is_dlg_button_checked(dialog: usize, id: i32) -> u32 {
    match get_dlg_item(dialog, id) {
        0 => 0,
        control => message::send(control, BM_GETCHECK, 0, 0).unwrap_or(0) as u32,
    }
}

/// CheckRadioButton: every control of the dialog whose id is from `first` to `last` checked when
/// its id is `check`, unchecked otherwise (an id outside the range is left alone, and so is a
/// range whose first id is past its last); TRUE, or FALSE with 1400 for a handle naming no window.
#[unsafe(export_name = "f2k_export_CheckRadioButton")]
pub extern "system" fn check_radio_button(dialog: usize, first: i32, last: i32, check: i32) -> u32 {
    if answered(window::links(dialog)).is_none() {
        return 0;
    }
    for control in window::children(dialog) {
        let Ok(data) = window::window_data(control) else {
            continue;
        };
        let id = data.id as i32;
        if id >= first && id <= last {
            let _ = message::send(control, BM_SETCHECK, (id == check) as u32, 0);
        }
    }
    1
}

// --- IsDialogMessage -----------------------------------------------------------------------------

/// IsDialogMessage's core, for a message of the narrow (`ansi`) or wide form: a message for
/// another window than the dialog and its controls is left (FALSE). The others are the dialog's:
/// unless the control the key goes to wants it (WM_GETDLGCODE), Tab and Shift+Tab move the focus
/// through the tab stops, the arrow keys through the group, Enter presses the push button with the
/// focus or the default button (WM_COMMAND to the dialog, the button's id and handle; IDOK when
/// the dialog has none), Esc presses IDCANCEL, and a character presses the control whose text has
/// it as its mnemonic; any other message is translated and dispatched. TRUE.
pub fn is_dialog_message(dialog: usize, msg: &Msg, ansi: bool) -> bool {
    let target = msg.hwnd as usize;
    if dialog == 0 || (target != dialog && !is_descendant(dialog, target)) {
        return false;
    }
    let handled = match msg.message {
        WM_KEYDOWN => key_down(dialog, msg),
        WM_CHAR | WM_SYSCHAR => character(dialog, msg),
        _ => false,
    };
    if !handled {
        message::translate(msg);
        message::dispatch(msg, ansi);
    }
    true
}

/// IsDialogMessage's WM_KEYDOWN: whether the dialog handled the key.
fn key_down(dialog: usize, msg: &Msg) -> bool {
    let code = dialog_code(msg.hwnd as usize, msg as *const Msg as usize);
    if code & (DLGC_WANTALLKEYS | DLGC_WANTMESSAGE) != 0 {
        return false;
    }
    let focus = focus::get_focus();
    match msg.wparam {
        VK_TAB if code & DLGC_WANTTAB == 0 => {
            let back = crate::keyboard::get_key_state(VK_SHIFT) < 0;
            let next = next_tab_item(dialog, focus, back);
            if next != 0 {
                set_dialog_focus(dialog, next);
            }
            true
        }
        VK_LEFT | VK_UP | VK_RIGHT | VK_DOWN if code & DLGC_WANTARROWS == 0 => {
            if focus != 0 && is_descendant(dialog, focus) && focus != dialog {
                let back = matches!(msg.wparam, VK_LEFT | VK_UP);
                let next = next_group_item(dialog, focus, back);
                if next != focus {
                    set_dialog_focus(dialog, next);
                }
            }
            true
        }
        VK_RETURN => {
            let pushed = focus != 0
                && focus != dialog
                && is_descendant(dialog, focus)
                && dialog_code(focus, 0) & (DLGC_DEFPUSHBUTTON | DLGC_UNDEFPUSHBUTTON) != 0;
            let (id, control) = if pushed {
                (get_dlg_ctrl_id_quiet(focus), focus)
            } else {
                let default = message::send(dialog, DM_GETDEFID, 0, 0).unwrap_or(0) as u32;
                let id = if default >> 16 == DC_HASDEFID {
                    default & 0xFFFF
                } else {
                    IDOK
                };
                (id, child_by_id(dialog, id))
            };
            press(dialog, id, control);
            true
        }
        VK_ESCAPE => {
            press(dialog, IDCANCEL, child_by_id(dialog, IDCANCEL));
            true
        }
        _ => false,
    }
}

/// A control's id, the last error untouched.
fn get_dlg_ctrl_id_quiet(control: usize) -> u32 {
    window::window_data(control).map_or(0, |data| data.id)
}

/// The command `id` of the button `control` (0 for none) sent to the dialog, as a click of it
/// notifies; a disabled button beeps instead.
fn press(dialog: usize, id: u32, control: usize) {
    if control != 0 && focus::is_window_enabled(control) == 0 {
        // SAFETY: no pointers.
        unsafe { crate::sound::message_beep(0) };
        return;
    }
    let _ = message::send(
        dialog,
        WM_COMMAND,
        BN_CLICKED << 16 | (id & 0xFFFF),
        control as i32,
    );
}

/// BM_CLICK (button.rs's).
const BM_CLICK: u32 = 0x00F5;

/// IsDialogMessage's WM_CHAR and WM_SYSCHAR: whether the dialog handled the character (a control
/// that wants characters gets them; Tab, Enter and Esc are the keys' own; a mnemonic presses its
/// control: a button clicked, a static's next control focused, another control focused).
fn character(dialog: usize, msg: &Msg) -> bool {
    let code = dialog_code(msg.hwnd as usize, msg as *const Msg as usize);
    if msg.message == WM_CHAR {
        if code & (DLGC_WANTCHARS | DLGC_WANTALLKEYS) != 0 {
            return false;
        }
        if matches!(msg.wparam, 0x09 | 0x0D | 0x1B) {
            return true;
        }
    }
    let wanted = rtl::cp1252::map_case(msg.wparam as u16, true);
    let mut children = [0usize; MOST_CONTROLS];
    let count = child_list(dialog, &mut children);
    for &control in &children[..count] {
        if !takes_focus(control, false) || mnemonic(control) != Some(wanted) {
            continue;
        }
        let kind = dialog_code(control, 0);
        if kind & DLGC_STATIC != 0 {
            let next = next_tab_item(dialog, control, false);
            if next != 0 && next != control {
                set_dialog_focus(dialog, next);
            }
        } else if kind & DLGC_BUTTON != 0 {
            let _ = message::send(control, BM_CLICK, 0, 0);
        } else {
            set_dialog_focus(dialog, control);
        }
        return true;
    }
    false
}

/// The character after the first single `&` of the control's text, its case folded to upper.
fn mnemonic(control: usize) -> Option<u16> {
    let text = message::window_text(control)?;
    let text = text.as_slice();
    let mut at = 0;
    while at + 1 < text.len() {
        if text[at] == u16::from(b'&') {
            if text[at + 1] != u16::from(b'&') {
                return Some(rtl::cp1252::map_case(text[at + 1], true));
            }
            at += 1;
        }
        at += 1;
    }
    None
}

/// IsDialogMessageW: [`is_dialog_message`] for a wide message.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_IsDialogMessageW")]
pub unsafe extern "system" fn is_dialog_message_w(dialog: usize, msg: *const Msg) -> u32 {
    // SAFETY: the caller's MSG.
    let msg = unsafe { In::new(msg) }.read();
    is_dialog_message(dialog, &msg, false) as u32
}

/// IsDialogMessageA: [`is_dialog_message`] for a narrow message.
///
/// # Safety
///
/// The caller's MSG, as for the platform's.
#[unsafe(export_name = "f2k_export_IsDialogMessageA")]
pub unsafe extern "system" fn is_dialog_message_a(dialog: usize, msg: *const Msg) -> u32 {
    // SAFETY: the caller's MSG.
    let msg = unsafe { In::new(msg) }.read();
    is_dialog_message(dialog, &msg, true) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MulDiv rounds half away from zero.
    #[test]
    fn mul_div_rounds_half_away_from_zero() {
        assert_eq!(mul_div(44, 13, 8), 72);
        assert_eq!(mul_div(58, 13, 8), 94);
        assert_eq!(mul_div(-3, 1, 2), -2);
        assert_eq!(mul_div(3, 1, -2), -2);
        assert_eq!(mul_div(1, 1, 0), -1);
    }

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// GetDlgItemInt's readings, as the dialog capture's ints block shows them.
    #[test]
    fn integers_read_as_captured() {
        let cases: &[(&str, (u32, bool), (u32, bool))] = &[
            ("123", (123, true), (123, true)),
            ("-42", ((-42i32) as u32, true), (0, false)),
            ("+5", (0, false), (0, false)),
            ("  7", (7, true), (7, true)),
            ("7  ", (7, false), (7, false)),
            ("12abc", (12, false), (12, false)),
            ("abc", (0, false), (0, false)),
            ("", (0, false), (0, false)),
            ("2147483647", (2147483647, true), (2147483647, true)),
            ("2147483648", (0, false), (2147483648, true)),
            ("-2147483648", (0x8000_0000, false), (0, false)),
            ("4294967295", (0, false), (4294967295, true)),
            ("4294967296", (0, false), (0, false)),
            ("0x10", (0, false), (0, false)),
        ];
        for &(text, signed, unsigned) in cases {
            assert_eq!(parse_int(&units(text), true), signed, "{text} signed");
            assert_eq!(parse_int(&units(text), false), unsigned, "{text} unsigned");
        }
    }

    /// SetDlgItemInt's text, signed and unsigned.
    #[test]
    fn integers_format_in_decimal() {
        let text = |value: u32, signed: bool| {
            let mut out = [0u16; 12];
            format_int(value, signed, &mut out);
            String::from_utf16(&out[..rtl::cstr::nul_len(&out)]).unwrap()
        };
        assert_eq!(text(-42i32 as u32, true), "-42");
        assert_eq!(text(-42i32 as u32, false), "4294967254");
        assert_eq!(text(0, true), "0");
        assert_eq!(text(0x8000_0000, true), "-2147483648");
    }

    /// A DIALOG template and a DIALOGEX one read back as written.
    #[test]
    fn templates_read_their_layouts() {
        let mut words: std::vec::Vec<u16> = std::vec::Vec::new();
        let dword = |words: &mut std::vec::Vec<u16>, value: u32| {
            words.push(value as u16);
            words.push((value >> 16) as u16);
        };
        // DIALOG: style with DS_SETFONT, no ex style, one control.
        dword(&mut words, 0x80C8_00C0);
        dword(&mut words, 0);
        words.extend([1, 20, 20, 200, 110, 0, 0]);
        words.extend(units("Title"));
        words.push(0);
        words.push(8);
        words.extend(units("MS Shell Dlg"));
        words.push(0);
        while words.len() % 2 != 0 {
            words.push(0);
        }
        dword(&mut words, 0x5001_0001);
        dword(&mut words, 0);
        words.extend([140, 8, 50, 14, 1, 0xFFFF, 0x80]);
        words.extend(units("OK"));
        words.extend([0, 0]);
        let bytes: std::vec::Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let read = |at: usize| bytes.get(at).copied();
        let mut reader = Reader::new(&read, 0);
        let mut names = HeaderNames::new();
        let header = read_header(&mut reader, &mut names).unwrap();
        assert!(!header.extended);
        assert_eq!((header.count, header.cx, header.cy), (1, 200, 110));
        assert_eq!(header.title, Field::Text(5));
        assert_eq!(header.font.unwrap().points, 8);
        assert_eq!(&names.face[..12], &units("MS Shell Dlg")[..]);
        let mut item_names = ItemNames::new();
        let item = read_item(&mut reader, false, &mut item_names).unwrap();
        assert_eq!((item.id, item.x, item.cx), (1, 140, 50));
        assert_eq!(item.class, Field::Ordinal(0x80));
        assert_eq!(item.title, Field::Text(2));
        assert_eq!(item.data, 0);
    }

    /// A control of a system class F2K does not register yet fails the dialog, and the call's line
    /// says which control, of which class, and why.
    #[test]
    fn a_missing_control_class_fails_the_dialog_with_its_line() {
        use crate::class::{register_class_w, WndClass};
        use crate::imports::host::{procedure, DEBUG_PRINTS};
        fn plain(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
            message::default_procedure(window as usize, message, wparam, lparam, false)
        }
        // The dialog's own class, the test's (the system classes are registered once per
        // process, in another test's thread's host window manager).
        let class_name: std::vec::Vec<u16> = "F2KDlgTest\0".encode_utf16().collect();
        let class = WndClass {
            wnd_proc: procedure(plain) as usize,
            cb_wnd_extra: DLGWINDOWEXTRA,
            instance: 0x40_0000,
            class_name: class_name.as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSW of the test's own.
        assert_ne!(unsafe { register_class_w(&class) }, 0);
        let mut words: std::vec::Vec<u16> = std::vec::Vec::new();
        let dword = |words: &mut std::vec::Vec<u16>, value: u32| {
            words.push(value as u16);
            words.push((value >> 16) as u16);
        };
        // DIALOG: WS_POPUP, no font, menu or title, the class above; one ListBox control, id 7.
        dword(&mut words, WS_POPUP);
        dword(&mut words, 0);
        words.extend([1, 0, 0, 100, 50, 0]);
        words.extend_from_slice(&class_name);
        words.push(0);
        if words.len() % 2 != 0 {
            words.push(0);
        }
        dword(&mut words, WS_CHILD | WS_VISIBLE);
        dword(&mut words, 0);
        words.extend([0, 0, 50, 14, 7, 0xFFFF, 0x83, 0, 0]);
        // DWORD-aligned, as a template is.
        let template: std::vec::Vec<u32> = words
            .chunks(2)
            .map(|pair| u32::from(pair[0]) | u32::from(*pair.get(1).unwrap_or(&0)) << 16)
            .collect();
        DEBUG_PRINTS.with(|prints| prints.borrow_mut().clear());
        // SAFETY: the template above, whole.
        let dialog =
            unsafe { create_dialog_indirect_param_w(0x40_0000, template.as_ptr().cast(), 0, 0, 0) };
        assert_eq!(dialog, 0);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        let expected = std::format!(
            "stub user32.CreateDialogIndirectParamW(hInstance=0x400000, lpTemplate=0x{:08X}, \
             hWndParent=0, lpDialogFunc=NULL, dwInitParam=0): the dialog's control 7 of class \
             ListBox could not be made, so the dialog fails: the ListBox control class is not yet \
             implemented\n",
            template.as_ptr() as usize
        );
        assert_eq!(printed, [expected]);
    }

    /// A template coordinate of 0x8000 is CW_USEDEFAULT: the marker goes to the window creation as
    /// it is, not converted from dialog units (which would place the dialog tens of thousands of
    /// pixels out). With both coordinates default, y keeps the second marker word as it is.
    #[test]
    fn a_template_default_place_goes_to_the_creation_as_cw_usedefault() {
        use crate::class::SYSTEM_CLASSES_WANTED;
        use crate::imports::host::wm;
        SYSTEM_CLASSES_WANTED.with(|wanted| wanted.set(true));
        let mut words: std::vec::Vec<u16> = std::vec::Vec::new();
        let dword = |words: &mut std::vec::Vec<u16>, value: u32| {
            words.push(value as u16);
            words.push((value >> 16) as u16);
        };
        // DIALOG: WS_POPUP, no menu, the dialog class (#32770), no title, no controls; placed at
        // 0x8000, 0x8000 (both CW_USEDEFAULT), 100x50 dialog units.
        dword(&mut words, WS_POPUP);
        dword(&mut words, 0);
        words.extend([0, 0x8000, 0x8000, 100, 50, 0, 0xFFFF, 0x8002, 0]);
        // DWORD-aligned, as a template is.
        let template: std::vec::Vec<u32> = words
            .chunks(2)
            .map(|pair| u32::from(pair[0]) | u32::from(*pair.get(1).unwrap_or(&0)) << 16)
            .collect();
        // SAFETY: the template above, whole.
        let dialog =
            unsafe { create_dialog_indirect_param_w(0x40_0000, template.as_ptr().cast(), 0, 0, 0) };
        assert_ne!(dialog, 0);
        let rect = wm(|wm| {
            wm.windows
                .iter()
                .find(|w| w.handle as usize == dialog)
                .unwrap()
                .rect
        });
        // CW_USEDEFAULT's x reaches the creation as i32::MIN, which the host places at the origin
        // (as the kernel does, at the cascade); converted from dialog units it would be
        // 0x8000 * 8 / 4 = 65536 pixels out.
        assert_eq!((rect.left, rect.top), (0, 0));
    }
}
