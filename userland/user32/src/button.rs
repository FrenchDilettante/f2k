//! The Button control: the class user32 registers in every process
//! ([`crate::class::register_system_classes`]), its procedure here in its two forms
//! ([`button_proc_w`], [`button_proc_a`]), as Windows 2000's user32 runs it.
//!
//! A button's state lives in its extra bytes ([`BUTTON_EXTRA`]: F2K's layout, Windows 2000's
//! being its own): its check state, pushed and focus bits (BM_GETSTATE's answer), and the font
//! WM_SETFONT gave it. Its behaviour, as the controls capture shows Windows 2000's:
//!
//! - BM_SETCHECK checks a check box or a radio button (any nonzero state is checked, but a
//!   three-state box keeps BST_INDETERMINATE), never another kind, and notifies nothing; an auto
//!   radio button checked so leaves its group as it is;
//! - BM_CLICK pushes the button and lets it go: the focus to it (a disabled one keeps none), an
//!   automatic check box toggled, an automatic three-state box stepped, an automatic radio button
//!   checked and its group's others unchecked, and BN_CLICKED sent to the parent, disabled or not;
//! - Space pushes it and its release clicks it, as BM_CLICK;
//! - a radio button the focus reaches unchecked, other than by a click, is clicked (the dialog
//!   capture's Tab into an auto radio group sends its BN_CLICKED);
//! - BM_SETSTYLE sets the style's low word; BM_SETSTATE the pushed bit;
//! - WM_GETDLGCODE: DLGC_BUTTON with DLGC_DEFPUSHBUTTON, DLGC_UNDEFPUSHBUTTON or DLGC_RADIOBUTTON
//!   by kind, a group box DLGC_STATIC.
//!
//! It paints with the drawing calls in the system colors, as Windows 2000's classic look draws:
//! a push button's face raised with BF_SOFT (sunken when pushed), the default one framed in black;
//! a check box's sunken white box and its check mark; a radio button's sunken round box and its
//! dot; a group box's etched frame under its text; the focus as a dotted rectangle. Windows 2000
//! draws the check and radio marks from bitmaps; F2K draws them pixel run by pixel run (a
//! deviation in look only).

use rtl::gdi::{Rect, TRANSPARENT};
use rtl::user::*;
use rtl::window::{WindowLinks, GWL_STYLE};

use crate::dialog::{self, BN_CLICKED, DLGC_BUTTON, DLGC_DEFPUSHBUTTON, DLGC_RADIOBUTTON};
use crate::dialog::{DLGC_STATIC, DLGC_UNDEFPUSHBUTTON, WM_COMMAND, WM_GETDLGCODE, WM_GETFONT};
use crate::dialog::{WM_SETFONT, WS_CHILD, WS_DISABLED};
use crate::draw::{self, BF_RECT, BF_SOFT, DT_CENTER, DT_LEFT, DT_SINGLELINE, DT_VCENTER};
use crate::{focus, imports, message, paint, window};

/// The button messages (winuser.h's BM_*).
pub const BM_GETCHECK: u32 = 0x00F0;
pub const BM_SETCHECK: u32 = 0x00F1;
pub const BM_GETSTATE: u32 = 0x00F2;
pub const BM_SETSTATE: u32 = 0x00F3;
pub const BM_SETSTYLE: u32 = 0x00F4;
pub const BM_CLICK: u32 = 0x00F5;

/// The button kinds (the style's low four bits, winuser.h's BS_*).
pub const BS_PUSHBUTTON: u32 = 0x0;
pub const BS_DEFPUSHBUTTON: u32 = 0x1;
pub const BS_CHECKBOX: u32 = 0x2;
pub const BS_AUTOCHECKBOX: u32 = 0x3;
pub const BS_RADIOBUTTON: u32 = 0x4;
pub const BS_3STATE: u32 = 0x5;
pub const BS_AUTO3STATE: u32 = 0x6;
pub const BS_GROUPBOX: u32 = 0x7;
pub const BS_AUTORADIOBUTTON: u32 = 0x9;
const BS_TYPEMASK: u32 = 0xF;

/// BM_GETSTATE's bits: the check state, pushed, the focus.
pub const BST_CHECKMASK: u32 = 0x0003;
pub const BST_PUSHED: u32 = 0x0004;
pub const BST_FOCUS: u32 = 0x0008;
/// The button is being clicked (BM_CLICK, Space): its WM_SETFOCUS clicks nothing.
const CLICKING: u32 = 0x0100;

/// A button's extra bytes: its state, then its font.
pub const BUTTON_EXTRA: i32 = 8;
const STATE: i32 = 0;
const FONT: i32 = 4;

/// The keys a button takes.
const VK_SPACE: u32 = 0x20;

/// The system colors a button paints in (winuser.h's COLOR_*).
const COLOR_WINDOW: u32 = 5;
const COLOR_WINDOWFRAME: u32 = 6;
const COLOR_WINDOWTEXT: u32 = 8;
const COLOR_3DFACE: u32 = 15;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_GRAYTEXT: u32 = 17;
const COLOR_BTNTEXT: u32 = 18;
const COLOR_3DHILIGHT: u32 = 20;
const COLOR_3DDKSHADOW: u32 = 21;
const COLOR_3DLIGHT: u32 = 22;

fn read(window: usize, offset: i32) -> u32 {
    let mut value = 0u32;
    let _ = imports::query_window(
        window,
        rtl::window::QUERY_WINDOW_EXTRA | offset as u32,
        &mut value,
    );
    value
}

fn write(window: usize, offset: i32, value: u32) {
    let _ = imports::set_window_long(window, offset, value, false);
}

fn style(window: usize) -> u32 {
    window::style_of(window).unwrap_or(0)
}

fn kind(window: usize) -> u32 {
    style(window) & BS_TYPEMASK
}

/// Whether the button's kind has a check state.
fn checkable(kind: u32) -> bool {
    matches!(
        kind,
        BS_CHECKBOX
            | BS_AUTOCHECKBOX
            | BS_RADIOBUTTON
            | BS_3STATE
            | BS_AUTO3STATE
            | BS_AUTORADIOBUTTON
    )
}

fn radio(kind: u32) -> bool {
    matches!(kind, BS_RADIOBUTTON | BS_AUTORADIOBUTTON)
}

/// The button's state changed: `set` set, `clear` cleared, the button redrawn when it shows.
fn change(window: usize, set: u32, clear: u32) {
    let state = read(window, STATE);
    let changed = (state | set) & !clear;
    if changed != state {
        write(window, STATE, changed);
        let _ = imports::invalidate_rect(window, 0, false);
    }
}

/// The check state set (redrawn when it changes).
fn set_check(window: usize, check: u32) {
    change(window, check & BST_CHECKMASK, BST_CHECKMASK & !check);
}

/// The click of the button: its automatic check state moved, then BN_CLICKED to its parent.
fn activate(window: usize) {
    let state = read(window, STATE);
    let check = state & BST_CHECKMASK;
    match kind(window) {
        BS_AUTOCHECKBOX => set_check(window, (check == 0) as u32),
        BS_AUTO3STATE => set_check(window, (check + 1) % 3),
        BS_AUTORADIOBUTTON => {
            set_check(window, 1);
            uncheck_group(window);
        }
        _ => {}
    }
    notify(window, BN_CLICKED);
}

/// The other radio buttons of the button's group unchecked.
fn uncheck_group(window: usize) {
    let parent = parent_of(window);
    if parent == 0 {
        return;
    }
    let mut current = window;
    for _ in 0..256 {
        current = dialog::next_group_item_any(parent, current);
        if current == window || current == 0 {
            break;
        }
        if dialog::dialog_code(current, 0) & DLGC_RADIOBUTTON != 0 {
            let _ = message::send(current, BM_SETCHECK, 0, 0);
        }
    }
}

/// The button's parent, 0 for a top-level button.
fn parent_of(window: usize) -> usize {
    if style(window) & WS_CHILD == 0 {
        return 0;
    }
    window::links(window).map_or(0, |links: WindowLinks| links.parent as usize)
}

/// The notification `code` sent to the button's parent (WM_COMMAND: its id and the code, the
/// button's handle).
fn notify(window: usize, code: u32) {
    let parent = parent_of(window);
    if parent == 0 {
        return;
    }
    let id = window::window_data(window).map_or(0, |data| data.id);
    let _ = message::send(
        parent,
        WM_COMMAND,
        code << 16 | (id & 0xFFFF),
        window as i32,
    );
}

/// BM_CLICK: pushed, the focus taken, let go, clicked.
fn click(window: usize) {
    change(window, BST_PUSHED | CLICKING, 0);
    focus::set_focus(window);
    change(window, 0, BST_PUSHED | CLICKING);
    activate(window);
}

/// The button's procedure, for a message of the narrow (`ansi`) or wide form.
fn button(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        WM_GETDLGCODE => {
            (match kind(window) {
                BS_PUSHBUTTON => DLGC_BUTTON | DLGC_UNDEFPUSHBUTTON,
                BS_DEFPUSHBUTTON => DLGC_BUTTON | DLGC_DEFPUSHBUTTON,
                BS_RADIOBUTTON | BS_AUTORADIOBUTTON => DLGC_BUTTON | DLGC_RADIOBUTTON,
                BS_GROUPBOX => DLGC_STATIC,
                _ => DLGC_BUTTON,
            }) as i32
        }
        BM_GETCHECK => {
            if checkable(kind(window)) {
                (read(window, STATE) & BST_CHECKMASK) as i32
            } else {
                0
            }
        }
        BM_SETCHECK => {
            let kind = kind(window);
            if checkable(kind) {
                let check = match kind {
                    BS_3STATE | BS_AUTO3STATE => wparam.min(2),
                    _ => (wparam != 0) as u32,
                };
                set_check(window, check);
            }
            0
        }
        BM_GETSTATE => (read(window, STATE) & (BST_CHECKMASK | BST_PUSHED | BST_FOCUS)) as i32,
        BM_SETSTATE => {
            if wparam != 0 {
                change(window, BST_PUSHED, 0);
            } else {
                change(window, 0, BST_PUSHED);
            }
            0
        }
        BM_SETSTYLE => {
            let style = style(window);
            let changed = (style & 0xFFFF_0000) | (wparam & 0xFFFF);
            if changed != style {
                window::set_window_long_w(window, GWL_STYLE, changed as i32);
            }
            if lparam != 0 {
                let _ = imports::invalidate_rect(window, 0, false);
            }
            0
        }
        BM_CLICK => {
            click(window);
            0
        }
        WM_SETFOCUS => {
            change(window, BST_FOCUS, 0);
            let state = read(window, STATE);
            if radio(kind(window)) && state & (BST_CHECKMASK | CLICKING) == 0 {
                activate(window);
            }
            0
        }
        WM_KILLFOCUS => {
            change(window, 0, BST_FOCUS | BST_PUSHED);
            0
        }
        WM_KEYDOWN if wparam == VK_SPACE => {
            change(window, BST_PUSHED | CLICKING, 0);
            0
        }
        WM_KEYUP if wparam == VK_SPACE => {
            if read(window, STATE) & BST_PUSHED != 0 {
                change(window, 0, BST_PUSHED | CLICKING);
                activate(window);
            }
            0
        }
        WM_SETFONT => {
            write(window, FONT, wparam);
            if lparam != 0 {
                let _ = imports::invalidate_rect(window, 0, false);
            }
            0
        }
        WM_GETFONT => read(window, FONT) as i32,
        WM_SETTEXT => {
            let answer = message::default_procedure(window, message, wparam, lparam, ansi);
            let _ = imports::invalidate_rect(window, 0, false);
            answer
        }
        WM_ENABLE => {
            let _ = imports::invalidate_rect(window, 0, false);
            0
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            if let Some(painting) = paint::Painting::begin(window) {
                draw_button(window, painting.dc());
            }
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// ButtonWndProcW: the Button class's procedure for a wide message.
pub extern "system" fn button_proc_w(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    button(window, message, wparam, lparam, false)
}

/// ButtonWndProcA: the Button class's procedure for a narrow message.
pub extern "system" fn button_proc_a(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    button(window, message, wparam, lparam, true)
}

// --- Painting ------------------------------------------------------------------------------------

/// COLOR_* + 1: a system color as a fill's brush.
fn color(index: u32) -> usize {
    index as usize + 1
}

/// A rectangle `inset` pixels inside `rect` on every side.
fn inset(rect: Rect, by: i32) -> Rect {
    Rect {
        left: rect.left + by,
        top: rect.top + by,
        right: rect.right - by,
        bottom: rect.bottom - by,
    }
}

/// The button drawn into `dc`, its font selected for the text.
fn draw_button(window: usize, dc: usize) {
    let Some(client) = window::client_rect(window) else {
        return;
    };
    let font = read(window, FONT);
    let previous = (font != 0)
        .then(|| imports::select_object(dc, font as usize))
        .flatten();
    let parent = parent_of(window);
    let brush = if parent != 0 {
        message::send(parent, message::WM_CTLCOLORBTN, dc as u32, window as i32).unwrap_or(0)
            as usize
    } else {
        0
    };
    let brush = if brush == 0 {
        color(COLOR_3DFACE)
    } else {
        brush
    };
    imports::set_bk_mode(dc, TRANSPARENT);
    let state = read(window, STATE);
    let disabled = style(window) & WS_DISABLED != 0;
    let text = message::window_text(window).unwrap_or_default();
    let text = text.as_slice();
    let text_color = crate::display::get_sys_color(if disabled {
        COLOR_GRAYTEXT
    } else {
        COLOR_BTNTEXT
    } as i32);
    imports::set_text_color(dc, text_color);
    match kind(window) {
        BS_PUSHBUTTON | BS_DEFPUSHBUTTON => {
            draw::fill(dc, client, color(COLOR_3DFACE));
            let mut face = client;
            if kind(window) == BS_DEFPUSHBUTTON {
                draw::frame_in(dc, face, color(COLOR_WINDOWFRAME));
                face = inset(face, 1);
            }
            let mut label = face;
            if state & BST_PUSHED != 0 {
                draw::frame_in(dc, face, color(COLOR_3DSHADOW));
                label.left += 1;
                label.top += 1;
            } else {
                draw::draw_edge_in(dc, face, draw::EDGE_RAISED, BF_RECT | BF_SOFT);
            }
            draw::draw_text_in(dc, text, label, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if state & BST_FOCUS != 0 {
                draw::focus_rect_in(dc, inset(face, 3));
            }
        }
        BS_GROUPBOX => {
            draw::fill(dc, client, brush);
            let height = imports::text_metrics(dc).map_or(16, |metrics| metrics.height);
            let frame = Rect {
                top: client.top + height / 2,
                ..client
            };
            draw::draw_edge_in(dc, frame, draw::EDGE_ETCHED, BF_RECT);
            if !text.is_empty() {
                let width = imports::text_width(dc, text).unwrap_or(0);
                let label = Rect {
                    left: client.left + 8,
                    top: client.top,
                    right: (client.left + 8 + width + 4).min(client.right),
                    bottom: client.top + height,
                };
                draw::fill(dc, label, brush);
                let label = Rect {
                    left: label.left + 2,
                    ..label
                };
                draw::draw_text_in(dc, text, label, DT_LEFT | DT_SINGLELINE);
            }
        }
        kind => {
            draw::fill(dc, client, brush);
            let size = 13;
            let top = client.top + (client.bottom - client.top - size) / 2;
            let mark = Rect {
                left: client.left,
                top,
                right: client.left + size,
                bottom: top + size,
            };
            let pushed_or_disabled = state & BST_PUSHED != 0 || disabled;
            let check = state & BST_CHECKMASK;
            if radio(kind) {
                draw_radio(dc, mark, check != 0, pushed_or_disabled);
            } else {
                draw_check_box(dc, mark, check, pushed_or_disabled);
            }
            let label = Rect {
                left: client.left + size + 4,
                ..client
            };
            let (_, used) = draw::draw_text_in(
                dc,
                text,
                label,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | draw::DT_CALCRECT,
            );
            draw::draw_text_in(dc, text, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            if state & BST_FOCUS != 0 && !text.is_empty() {
                let height = used.bottom - used.top;
                let top = label.top + (label.bottom - label.top - height) / 2;
                let around = Rect {
                    left: label.left - 1,
                    top: top - 1,
                    right: (label.left + used.right - used.left + 1).min(client.right),
                    bottom: (top + height + 1).min(client.bottom),
                };
                draw::focus_rect_in(dc, around);
            }
        }
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

/// A row of `width` pixels at (`x`, `y`) in the system color `index`.
fn run(dc: usize, x: i32, y: i32, width: i32, index: u32) {
    let rect = Rect {
        left: x,
        top: y,
        right: x + width,
        bottom: y + 1,
    };
    draw::fill(dc, rect, color(index));
}

/// A check box's box in `mark` (13 by 13): sunken, white inside (the face's color when pushed or
/// disabled), its check mark for a checked state, a gray one for an indeterminate one.
fn draw_check_box(dc: usize, mark: Rect, check: u32, dimmed: bool) {
    let (inner, _) = draw::draw_edge_in(dc, mark, draw::EDGE_SUNKEN, BF_RECT);
    draw::fill(
        dc,
        inner,
        color(if dimmed || check == 2 {
            COLOR_3DFACE
        } else {
            COLOR_WINDOW
        }),
    );
    if check == 0 {
        return;
    }
    let ink = if check == 2 || dimmed {
        COLOR_3DSHADOW
    } else {
        COLOR_WINDOWTEXT
    };
    // The check mark: seven columns, each three pixels high, down to the third and up again.
    let (x, y) = (inner.left + 1, inner.top + 1);
    for (column, top) in [2, 3, 4, 3, 2, 1, 0].into_iter().enumerate() {
        for row in 0..3 {
            run(dc, x + column as i32, y + top + row, 1, ink);
        }
    }
}

/// A radio button's round box in the top left of `mark` (12 by 12), as Windows 2000's classic
/// look colors it: its outer ring 3D shadow above and highlight below, its inner ring dark shadow
/// and light, white inside (the face's color when pushed or disabled), and its dot when checked.
fn draw_radio(dc: usize, mark: Rect, checked: bool, dimmed: bool) {
    const SHAPE: [&[u8; 12]; 12] = [
        b"....SSSS....",
        b"..SSDDDDSS..",
        b".SDDWWWWDDH.",
        b".SDWWWWWWLH.",
        b"SDWWWWWWWWLH",
        b"SDWWWWWWWWLH",
        b"SDWWWWWWWWLH",
        b"SDWWWWWWWWLH",
        b".SDWWWWWWLH.",
        b".HLLWWWWLLH.",
        b"..HHLLLLHH..",
        b"....HHHH....",
    ];
    let inside = if dimmed { COLOR_3DFACE } else { COLOR_WINDOW };
    for (y, row) in SHAPE.iter().enumerate() {
        let mut x = 0;
        while x < 12 {
            let pixel = row[x];
            let mut end = x + 1;
            while end < 12 && row[end] == pixel {
                end += 1;
            }
            let index = match pixel {
                b'S' => Some(COLOR_3DSHADOW),
                b'D' => Some(COLOR_3DDKSHADOW),
                b'H' => Some(COLOR_3DHILIGHT),
                b'L' => Some(COLOR_3DLIGHT),
                b'W' => Some(inside),
                _ => None,
            };
            if let Some(index) = index {
                run(
                    dc,
                    mark.left + x as i32,
                    mark.top + y as i32,
                    (end - x) as i32,
                    index,
                );
            }
            x = end;
        }
    }
    if checked {
        let ink = if dimmed {
            COLOR_3DSHADOW
        } else {
            COLOR_WINDOWTEXT
        };
        for (row, (from, width)) in [(5, 2), (4, 4), (4, 4), (5, 2)].into_iter().enumerate() {
            run(dc, mark.left + from, mark.top + 4 + row as i32, width, ink);
        }
    }
}
