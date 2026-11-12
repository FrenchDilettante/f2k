//! MessageBoxW and MessageBoxA: a modal dialog of the dialog class built from a template in memory,
//! as Windows 2000's user32 builds its message boxes, run by the dialog manager's modal loop
//! ([`dialog::run_modal`]).
//!
//! The box's template ([`build`]) holds its push buttons, in the order the MB_ type lists them,
//! then the icon (an SS_ICON static) when an MB_ICON flag asks for one, then the text (an SS_LEFT
//! static with no prefix, id 0xFFFF). The dialog capture's boxes show that order and Windows 2000's
//! one quirk: MB_OK's lone button "OK" has the id IDCANCEL, so Esc and the box's close end it, and
//! its answer is IDOK. The default button (MB_DEFBUTTON1 to 4) is a BS_DEFPUSHBUTTON and has the
//! focus. A command reaches the box's procedure for a button the box has, enabled: it ends the box
//! with its id; a command for a button it has not is ignored, GetDlgItem's 1421 left as the last
//! error (as the capture's MB_OK box shows when IDOK is posted to it).
//!
//! The layout is the box's own, in dialog units of the dialog font: the text measured with
//! DrawText (wrapped at five eighths of the screen's width), the icon 32 pixels square at its left,
//! the buttons 50 by 14 units in a row below, centred, the box centred on the screen (DS_CENTER).
//! The icon is a seam: its static holds the stock icon, which nothing draws yet.

use rtl::edge::InStr;
use rtl::gdi::{LogFontW, Rect, DEFAULT_CHARSET, FW_NORMAL};

use crate::dialog::{self, Call, Reader, Request, IDCANCEL, IDOK, WM_COMMAND, WM_INITDIALOG};
use crate::procedure::Procedure;
use crate::{draw, focus, imports, window};

/// The MB_ flags (winuser.h): the buttons, the icon, the default button, the box topmost.
const MB_TYPEMASK: u32 = 0x0000_000F;
const MB_ICONMASK: u32 = 0x0000_00F0;
const MB_DEFMASK: u32 = 0x0000_0F00;
const MB_TOPMOST: u32 = 0x0004_0000;
const MB_OK: u32 = 0;

/// The MB_ type the box does not handle yet: Cancel, Try Again and Continue.
const MB_CANCELTRYCONTINUE: u32 = 0x0000_0006;

/// The MB_ flags the box does not handle yet (their effect missing): each flag, and what it does
/// on Windows 2000.
const UNHANDLED_FLAGS: [(u32, &str); 5] = [
    (0x0000_1000, "MB_SYSTEMMODAL (a topmost box)"),
    (
        0x0000_2000,
        "MB_TASKMODAL (the thread's top-level windows disabled)",
    ),
    (0x0000_4000, "MB_HELP (a Help button)"),
    (0x0008_0000, "MB_RIGHT (the text right-aligned)"),
    (0x0010_0000, "MB_RTLREADING (right-to-left reading order)"),
];

/// The MB_ cases logged in this process, and a text cut short ([`LONG_TEXT`]).
static FLAGS_LOGGED: rtl::stub::Logged<12> = rtl::stub::Logged::new();

/// The most characters of its text the box shows, and the key of the case of a longer text.
const MOST_TEXT: usize = 1024;
const LONG_TEXT: u32 = 0x8000_0000;

/// The MB_ type and flags of `kind` the box does not handle yet, logged for `call` (each once per
/// process).
fn log_unhandled_flags(kind: u32, call: &Call) {
    if kind & MB_TYPEMASK == MB_CANCELTRYCONTINUE && FLAGS_LOGGED.first(MB_CANCELTRYCONTINUE) {
        call.unhandled(
            "MB_CANCELTRYCONTINUE (Cancel, Try Again, Continue) is not yet implemented: an OK box \
             is shown",
        );
    }
    for &(flag, what) in &UNHANDLED_FLAGS {
        if kind & flag != 0 && FLAGS_LOGGED.first(flag) {
            call.unhandled(format_args!("{what} is not yet implemented"));
        }
    }
}

/// The button ids beyond IDOK and IDCANCEL.
const IDABORT: u32 = 3;
const IDRETRY: u32 = 4;
const IDIGNORE: u32 = 5;
const IDYES: u32 = 6;
const IDNO: u32 = 7;

/// The icon static's id (an assumption: Windows 2000's is not public).
const ICON_ID: u16 = 20;
/// The text static's id: 0xFFFF, as the dialog capture shows.
const TEXT_ID: u16 = 0xFFFF;

/// The styles of the box and its controls.
const WS_POPUP: u32 = 0x8000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_GROUP: u32 = 0x0002_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const WS_EX_TOPMOST: u32 = 0x0000_0008;
const BS_PUSHBUTTON: u32 = 0x0;
const BS_DEFPUSHBUTTON: u32 = 0x1;
const SS_LEFT: u32 = 0x00;
const SS_ICON: u32 = 0x03;
const SS_NOPREFIX: u32 = 0x80;

/// The stock icons an MB_ICON flag shows (IDI_HAND, IDI_QUESTION, IDI_EXCLAMATION,
/// IDI_ASTERISK), by the flag's nibble.
fn icon_of(kind: u32) -> Option<u16> {
    match (kind & MB_ICONMASK) >> 4 {
        1 => Some(32513),
        2 => Some(32514),
        3 => Some(32515),
        4 => Some(32516),
        _ => None,
    }
}

/// The buttons of an MB_ type: their texts and ids, in order.
fn buttons(kind: u32) -> &'static [(&'static str, u32)] {
    match kind & MB_TYPEMASK {
        1 => &[("OK", IDOK), ("Cancel", IDCANCEL)],
        2 => &[
            ("&Abort", IDABORT),
            ("&Retry", IDRETRY),
            ("&Ignore", IDIGNORE),
        ],
        3 => &[("&Yes", IDYES), ("&No", IDNO), ("Cancel", IDCANCEL)],
        4 => &[("&Yes", IDYES), ("&No", IDNO)],
        5 => &[("&Retry", IDRETRY), ("Cancel", IDCANCEL)],
        _ => &[("OK", IDCANCEL)],
    }
}

/// The box's dialog font: the dialogs' "MS Shell Dlg" at 8 points.
const FACE: &str = "MS Shell Dlg";
const POINTS: u16 = 8;

/// A template under construction, in a buffer of DWORDs (a template is DWORD-aligned).
struct Template {
    words: [u16; 2048],
    at: usize,
}

impl Template {
    fn word(&mut self, value: u16) {
        if self.at < self.words.len() {
            self.words[self.at] = value;
        }
        self.at += 1;
    }

    fn dword(&mut self, value: u32) {
        self.word(value as u16);
        self.word((value >> 16) as u16);
    }

    fn text(&mut self, units: &[u16]) {
        for &unit in units {
            self.word(unit);
        }
        self.word(0);
    }

    fn str(&mut self, text: &str) {
        for unit in text.encode_utf16() {
            self.word(unit);
        }
        self.word(0);
    }

    fn align(&mut self) {
        if !self.at.is_multiple_of(2) {
            self.word(0);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn item(&mut self, style: u32, rect: (i32, i32, i32, i32), id: u16, class: u16, title: Title) {
        self.align();
        self.dword(style);
        self.dword(0);
        for value in [rect.0, rect.1, rect.2, rect.3] {
            self.word(value as i16 as u16);
        }
        self.word(id);
        self.word(0xFFFF);
        self.word(class);
        match title {
            Title::Str(text) => self.str(text),
            Title::Units(units) => self.text(units),
            Title::Ordinal(id) => {
                self.word(0xFFFF);
                self.word(id);
            }
        }
        self.word(0);
    }

    fn bytes(&self) -> impl Fn(usize) -> Option<u8> + '_ {
        move |at: usize| {
            let word = *self.words.get(at / 2)?;
            (at / 2 < self.at).then_some(word.to_le_bytes()[at % 2])
        }
    }
}

/// A control's title in the template.
enum Title<'a> {
    Str(&'static str),
    Units(&'a [u16]),
    Ordinal(u16),
}

/// The box's text measured in the dialog font: its size in pixels, wrapped at `wrap` pixels; and
/// the font's base units. None when the screen's DC cannot measure.
fn measure(text: &[u16], wrap: i32) -> ((i32, i32), (i32, i32)) {
    let mut face = [0u16; rtl::gdi::LF_FACESIZE];
    for (unit, out) in FACE.encode_utf16().zip(face.iter_mut()) {
        *out = unit;
    }
    let font = LogFontW {
        height: -dialog::mul_div(i32::from(POINTS), 96, 72),
        width: 0,
        escapement: 0,
        orientation: 0,
        weight: FW_NORMAL,
        italic: 0,
        underline: 0,
        strike_out: 0,
        char_set: DEFAULT_CHARSET,
        out_precision: 0,
        clip_precision: 0,
        quality: 0,
        pitch_and_family: 0,
        face_name: face,
    };
    let font = imports::create_font(&font);
    let dc = crate::dc::get_dc(0);
    let previous = font.and_then(|font| imports::select_object(dc, font));
    let units = dialog::units_in(dc);
    let rect = Rect {
        left: 0,
        top: 0,
        right: wrap,
        bottom: 0,
    };
    let (_, used) = draw::draw_text_in(
        dc,
        text,
        rect,
        draw::DT_CALCRECT | draw::DT_WORDBREAK | draw::DT_EXPANDTABS | draw::DT_NOPREFIX,
    );
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(0, dc);
    if let Some(font) = font {
        imports::delete_object(font);
    }
    ((used.right - used.left, used.bottom - used.top), units)
}

/// The box's template for `text`, `caption` and the MB_ `kind`, built into `template`.
fn build(template: &mut Template, text: &[u16], caption: &[u16], kind: u32) {
    let wrap = crate::display::get_system_metrics(0) * 5 / 8;
    let ((width, height), (ux, uy)) = measure(text, wrap);
    let du_x = |pixels: i32| (pixels * 4 + ux - 1) / ux.max(1);
    let du_y = |pixels: i32| (pixels * 8 + uy - 1) / uy.max(1);
    let margin = 7;
    let icon = icon_of(kind);
    let (icon_cx, icon_cy) = if icon.is_some() {
        (du_x(32), du_y(32))
    } else {
        (0, 0)
    };
    let text_x = margin + if icon.is_some() { icon_cx + margin } else { 0 };
    let text_cx = du_x(width).max(1);
    let text_cy = du_y(height).max(8);
    let list = buttons(kind);
    let (button_cx, button_cy, gap) = (50, 14, 4);
    let row = list.len() as i32 * button_cx + (list.len() as i32 - 1) * gap;
    let cx = (text_x + text_cx + margin).max(row + 2 * margin);
    let top = margin + text_cy.max(icon_cy) + margin;
    let cy = top + button_cy + margin;
    let default = ((kind & MB_DEFMASK) >> 8) as usize;
    let default = if default < list.len() { default } else { 0 };
    let count = list.len() + 1 + icon.is_some() as usize;

    template.dword(
        WS_POPUP
            | WS_CAPTION
            | WS_SYSMENU
            | dialog::DS_MODALFRAME
            | dialog::DS_SETFONT
            | dialog::DS_CENTER,
    );
    template.dword(if kind & MB_TOPMOST != 0 {
        WS_EX_TOPMOST
    } else {
        0
    });
    template.word(count as u16);
    for value in [0, 0, cx, cy] {
        template.word(value as i16 as u16);
    }
    template.word(0);
    template.word(0);
    template.text(caption);
    template.word(POINTS);
    template.str(FACE);

    let mut x = (cx - row) / 2;
    for (index, &(label, id)) in list.iter().enumerate() {
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | if index == 0 { WS_GROUP } else { 0 }
            | if index == default {
                BS_DEFPUSHBUTTON
            } else {
                BS_PUSHBUTTON
            };
        template.item(
            style,
            (x, top, button_cx, button_cy),
            id as u16,
            0x80,
            Title::Str(label),
        );
        x += button_cx + gap;
    }
    if let Some(icon) = icon {
        template.item(
            WS_CHILD | WS_VISIBLE | SS_ICON,
            (margin, margin, icon_cx, icon_cy),
            ICON_ID,
            0x82,
            Title::Ordinal(icon),
        );
    }
    template.item(
        WS_CHILD | WS_VISIBLE | WS_GROUP | SS_LEFT | SS_NOPREFIX,
        (text_x, margin, text_cx, text_cy),
        TEXT_ID,
        0x82,
        Title::Units(text),
    );
}

/// The box's dialog procedure: WM_INITDIALOG keeps the MB_ type (DWL_USER) and gives the default
/// button the focus; a command for one of its enabled buttons ends it (MB_OK's IDCANCEL as IDOK).
extern "system" fn box_procedure(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    match message {
        WM_INITDIALOG => {
            window::set_window_long_w(window, dialog::DWL_USER, lparam);
            for child in window::children(window) {
                if dialog::dialog_code(child, 0) & dialog::DLGC_DEFPUSHBUTTON != 0 {
                    dialog::set_dialog_focus(window, child);
                    break;
                }
            }
            if let Some(icon) = icon_of(lparam as u32) {
                let control = dialog::child_by_id(window, u32::from(ICON_ID));
                let handle = crate::class::stock(icon, rtl::icon::RT_ICON);
                if control != 0 && handle != 0 {
                    let _ = crate::message::send(
                        control,
                        crate::static_control::STM_SETICON,
                        handle as u32,
                        0,
                    );
                }
            }
            0
        }
        WM_COMMAND => {
            let id = wparam & 0xFFFF;
            if !(IDOK..=IDNO).contains(&id) {
                return 0;
            }
            let button = dialog::get_dlg_item(window, id as i32);
            if button == 0 || focus::is_window_enabled(button) == 0 {
                return 1;
            }
            let kind = window::get_window_long_w(window, dialog::DWL_USER) as u32;
            let result = if id == IDCANCEL && kind & MB_TYPEMASK == MB_OK {
                IDOK
            } else {
                id
            };
            dialog::end_dialog(window, result as i32);
            1
        }
        _ => 0,
    }
}

/// The address the box procedure is registered under: its own on the target, a stand-in's number
/// in the host tests.
fn box_procedure_address() -> u32 {
    #[cfg(not(test))]
    {
        box_procedure as *const () as usize as u32
    }
    #[cfg(test)]
    {
        fn host(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
            box_procedure(window as usize, message, wparam, lparam)
        }
        crate::imports::host::procedure(host)
    }
}

/// MessageBox's core, for `call`: the box made and run; the id of the button that ended it, 0
/// with the last error when it could not be made.
fn message_box(owner: usize, text: &[u16], caption: &[u16], kind: u32, call: Call) -> i32 {
    log_unhandled_flags(kind, &call);
    let mut template = Template {
        words: [0; 2048],
        at: 0,
    };
    if text.len() > MOST_TEXT && FLAGS_LOGGED.first(LONG_TEXT) {
        call.unhandled(format_args!(
            "a text longer than {MOST_TEXT} characters is not yet implemented: it is cut there"
        ));
    }
    let text = &text[..text.len().min(MOST_TEXT)];
    build(&mut template, text, caption, kind);
    if template.at > template.words.len() {
        call.unhandled(
            "a box whose template outgrows 4096 bytes (a long caption) is not yet implemented",
        );
        return 0;
    }
    let read = template.bytes();
    let mut reader = Reader::new(&read, template.words.as_ptr() as usize);
    let request = Request {
        instance: 0,
        owner,
        proc: Procedure {
            address: box_procedure_address(),
            ansi: false,
        },
        param: kind as i32,
        ansi: false,
        call,
    };
    match dialog::create(&mut reader, request, false) {
        Some(dialog) => dialog::run_modal(dialog, owner),
        None => 0,
    }
}

/// The caption a box without one has.
const ERROR_CAPTION: [u16; 6] = [
    b'E' as u16,
    b'r' as u16,
    b'r' as u16,
    b'o' as u16,
    b'r' as u16,
    0,
];

/// MessageBoxW: a modal box showing `text` under `caption` (NULL: "Error") with the buttons and
/// icon the MB_ `kind` asks for; the id of the button that ended it, 0 with the last error when
/// the box could not be made.
///
/// # Safety
///
/// `text` and `caption` are NUL-terminated strings or null, as for the platform's.
#[unsafe(export_name = "f2k_export_MessageBoxW")]
pub unsafe extern "system" fn message_box_w(
    owner: usize,
    text: *const u16,
    caption: *const u16,
    kind: u32,
) -> i32 {
    let (text_arg, caption_arg) = (text as usize, caption as usize);
    // SAFETY: the caller's strings, or null.
    let (text, caption) = unsafe {
        (
            rtl::edge::InWStr::optional(text),
            rtl::edge::InWStr::optional(caption),
        )
    };
    let mut text_units = [0u16; 1024];
    let text_length = text.map_or(0, |text| {
        let units = text.units();
        let length = units.len().min(text_units.len());
        for (index, out) in text_units[..length].iter_mut().enumerate() {
            *out = units.get(index);
        }
        length
    });
    let mut caption_units = [0u16; 256];
    let caption_length = match caption {
        Some(caption) => {
            let units = caption.units();
            let length = units.len().min(caption_units.len());
            for (index, out) in caption_units[..length].iter_mut().enumerate() {
                *out = units.get(index);
            }
            length
        }
        None => {
            caption_units[..5].copy_from_slice(&ERROR_CAPTION[..5]);
            5
        }
    };
    let call = Call {
        entry: &crate::spec::MessageBoxW,
        args: [
            owner as u64,
            text_arg as u64,
            caption_arg as u64,
            u64::from(kind),
            0,
        ],
    };
    message_box(
        owner,
        &text_units[..text_length],
        &caption_units[..caption_length],
        kind,
        call,
    )
}

/// MessageBoxA: MessageBoxW's, the text and the caption converted from the ANSI code page.
///
/// # Safety
///
/// As MessageBoxW's, the strings ANSI.
#[unsafe(export_name = "f2k_export_MessageBoxA")]
pub unsafe extern "system" fn message_box_a(
    owner: usize,
    text: *const u8,
    caption: *const u8,
    kind: u32,
) -> i32 {
    let (text_arg, caption_arg) = (text as usize, caption as usize);
    // SAFETY: the caller's strings, or null.
    let (text, caption) = unsafe { (InStr::optional(text), InStr::optional(caption)) };
    let text = text.map_or(&[][..], |text| text.bytes());
    let mut text_units = [0u16; 1024];
    let length = text.len().min(text_units.len() - 1);
    let text_length = imports::multi_byte_to_unicode(&mut text_units[..length], &text[..length]);
    let mut caption_units = [0u16; 256];
    let caption_length = match caption {
        Some(caption) => {
            let bytes = caption.bytes();
            let length = bytes.len().min(caption_units.len() - 1);
            imports::multi_byte_to_unicode(&mut caption_units[..length], &bytes[..length])
        }
        None => {
            caption_units[..5].copy_from_slice(&ERROR_CAPTION[..5]);
            5
        }
    };
    let call = Call {
        entry: &crate::spec::MessageBoxA,
        args: [
            owner as u64,
            text_arg as u64,
            caption_arg as u64,
            u64::from(kind),
            0,
        ],
    };
    message_box(
        owner,
        &text_units[..text_length],
        &caption_units[..caption_length],
        kind,
        call,
    )
}
