//! The Static control: the class user32 registers in every process
//! ([`crate::class::register_system_classes`]), its procedure here in its two forms
//! ([`static_proc_w`], [`static_proc_a`]), as Windows 2000's user32 runs it.
//!
//! A static's extra bytes ([`STATIC_EXTRA`]: F2K's layout) hold its image (an SS_ICON static's
//! icon) and the font WM_SETFONT gave it. As the controls capture shows Windows 2000's:
//!
//! - WM_GETDLGCODE is DLGC_STATIC for every kind;
//! - a text static's WM_SETTEXT sets its text and redraws it; a frame's, a rectangle's or an etched
//!   line's is refused (FALSE), the text it was made with kept;
//! - STM_SETICON and STM_SETIMAGE (IMAGE_ICON) give an SS_ICON static its icon, answer the one it
//!   had and size it to the icon (SM_CXICON by SM_CYICON); STM_GETICON and STM_GETIMAGE
//!   (IMAGE_ICON) answer it; another kind of static has no icon (STM_SETICON answers NULL and keeps
//!   none); STM_GETIMAGE for a bitmap answers NULL.
//!
//! It paints in the colors its parent's WM_CTLCOLORSTATIC gives: its text through DrawText
//! (SS_LEFT, SS_CENTER and SS_RIGHT wrapped at words, SS_LEFTNOWORDWRAP not, SS_SIMPLE on one line,
//! SS_NOPREFIX with no mnemonic underline, SS_CENTERIMAGE on one line centred vertically, gray when
//! disabled); SS_SUNKEN is WS_EX_STATICEDGE's sunken edge, given at the creation; its rectangles
//! and frames in the 3D colors (black: COLOR_3DDKSHADOW, gray: COLOR_3DSHADOW, white:
//! COLOR_3DHILIGHT); its etched lines and frame with DrawEdge. An icon is not drawn: win32k's icon
//! records hold no bits yet (the seam the icons left), so an SS_ICON static paints its background
//! alone. Its WM_NCHITTEST is HTTRANSPARENT unless SS_NOTIFY; an SS_NOTIFY static sends its
//! parent STN_CLICKED at WM_LBUTTONDOWN and STN_DBLCLK at WM_LBUTTONDBLCLK.

use rtl::display::{
    COLOR_3DDKSHADOW,
    COLOR_3DFACE,
    COLOR_3DHILIGHT,
    COLOR_3DSHADOW,
    COLOR_GRAYTEXT,
    COLOR_WINDOWTEXT,
    SM_CXICON,
    SM_CYICON,
};
use rtl::gdi::TRANSPARENT;
use rtl::user::*;
use rtl::window::{
    WindowLinks,
    GWL_EXSTYLE,
    QUERY_WINDOW_EXTRA,
    SWP_FRAMECHANGED,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOZORDER,
};

use crate::dialog::DLGC_STATIC;
use crate::draw::{self, BF_LEFT, BF_RECT, BF_TOP};
use crate::{imports, message, paint, window};

/// The notifications an SS_NOTIFY static sends (winuser.h's STN_*).
const STN_CLICKED: u32 = 0;
const STN_DBLCLK: u32 = 1;

/// A static's extra bytes: its image, then its font.
pub const STATIC_EXTRA: i32 = 8;
const IMAGE: i32 = 0;
const FONT: i32 = 4;

fn read(window: usize, offset: i32) -> u32 {
    let mut value = 0u32;
    let _ = imports::query_window(window, QUERY_WINDOW_EXTRA | offset as u32, &mut value);
    value
}

fn write(window: usize, offset: i32, value: u32) -> u32 {
    imports::set_window_long(window, offset, value, false).map_or(0, |(previous, _)| previous)
}

fn style_of(window: usize) -> u32 {
    window::style_of(window).unwrap_or(0)
}

fn kind(window: usize) -> u32 {
    window::style_of(window).unwrap_or(0) & SS_TYPEMASK
}

/// The static kinds the procedure does not draw yet (drawn as a text static), and what Windows
/// 2000 draws for each.
const UNDRAWN_KINDS: [(u32, &str); 4] = [
    (SS_USERITEM, "SS_USERITEM statics"),
    (
        SS_OWNERDRAW,
        "SS_OWNERDRAW statics (WM_DRAWITEM to the parent)",
    ),
    (SS_BITMAP, "SS_BITMAP statics (a bitmap)"),
    (
        SS_ENHMETAFILE,
        "SS_ENHMETAFILE statics (an enhanced metafile)",
    ),
];

/// The style bits of a text static the procedure does not draw yet, and what each does.
const UNDRAWN_STYLES: [(u32, &str); 1] =
    [(0x2000, "SS_EDITCONTROL (an edit control's line breaks)")];

/// The ellipsis styles (one field of two bits), and what each does.
const ELLIPSES: [(u32, &str); 3] = [
    (
        0x4000,
        "SS_ENDELLIPSIS (the text's end cut with an ellipsis)",
    ),
    (
        0x8000,
        "SS_PATHELLIPSIS (a path's middle cut with an ellipsis)",
    ),
    (
        0xC000,
        "SS_WORDELLIPSIS (the text cut at a word with an ellipsis)",
    ),
];

/// The cases logged in this process: a kind, a style bit, a message.
static LOGGED: rtl::stub::Logged<16> = rtl::stub::Logged::new();

/// The cases of the static's paint the procedure does not draw yet, logged for the message it is
/// handling (each once per process): its kind, its style bits, an SS_ICON static's icon (win32k's
/// icon records hold no bits yet).
fn log_undrawn(window: usize, call: (usize, u32, u32, i32)) {
    let style = window::style_of(window).unwrap_or(0);
    let kind = style & SS_TYPEMASK;
    let log = |key: u32, reason: &dyn core::fmt::Display| {
        crate::stub::message_once(&LOGGED, key, &crate::stub::STATIC_PROC, reason, call);
    };
    if let Some(&(_, what)) = UNDRAWN_KINDS.iter().find(|&&(undrawn, _)| undrawn == kind) {
        log(
            kind,
            &format_args!("{what} are not yet drawn: the static is drawn as text"),
        );
    }
    if kind == SS_ICON && read(window, IMAGE) != 0 {
        log(
            SS_ICON,
            &"an SS_ICON static's icon is not yet drawn: icons hold no bits yet",
        );
    }
    if textless(kind) || matches!(kind, SS_ICON | SS_BITMAP | SS_ENHMETAFILE) {
        return;
    }
    let ellipsis = ELLIPSES
        .iter()
        .find(|&&(field, _)| style & SS_ELLIPSISMASK == field);
    for &(bit, what) in UNDRAWN_STYLES.iter().chain(ellipsis) {
        if style & bit == bit {
            log(bit, &format_args!("{what} is not yet drawn"));
        }
    }
}

/// Whether the static's kind shows no text: the rectangles, the frames, the etched lines.
fn textless(kind: u32) -> bool {
    matches!(
        kind,
        SS_BLACKRECT..=SS_WHITEFRAME | SS_ETCHEDHORZ | SS_ETCHEDVERT | SS_ETCHEDFRAME
    )
}

/// An SS_ICON static's icon set: the one it had answered, the static sized to the icon.
fn set_icon(window: usize, icon: u32) -> i32 {
    let previous = write(window, IMAGE, icon);
    if icon != 0 {
        let cx = crate::display::get_system_metrics(SM_CXICON);
        let cy = crate::display::get_system_metrics(SM_CYICON);
        window::set_window_pos(
            window,
            0,
            0,
            0,
            cx,
            cy,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
    let _ = imports::invalidate_rect(window, 0, true);
    previous as i32
}

/// The static's procedure, for a message of the narrow (`ansi`) or wide form.
fn static_control(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        WM_NCCREATE => {
            let answer = message::default_procedure(window, message, wparam, lparam, ansi);
            sunken_edge(window);
            answer
        }
        WM_GETDLGCODE => DLGC_STATIC as i32,
        // A static lets the mouse through to the window under it unless SS_NOTIFY asks for its
        // clicks (controls `edges`: WindowFromPoint finds a plain static's parent).
        WM_NCHITTEST if style_of(window) & SS_NOTIFY == 0 => -1,
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK if style_of(window) & SS_NOTIFY != 0 => {
            notify(
                window,
                if message == WM_LBUTTONDOWN {
                    STN_CLICKED
                } else {
                    STN_DBLCLK
                },
            );
            0
        }
        STM_GETICON => match kind(window) {
            SS_ICON => read(window, IMAGE) as i32,
            _ => 0,
        },
        STM_SETICON => match kind(window) {
            SS_ICON => set_icon(window, wparam),
            _ => 0,
        },
        STM_GETIMAGE => match (kind(window), wparam) {
            (SS_ICON, IMAGE_ICON | IMAGE_CURSOR) => read(window, IMAGE) as i32,
            _ => 0,
        },
        STM_SETIMAGE => match (kind(window), wparam) {
            (SS_ICON, IMAGE_ICON | IMAGE_CURSOR) => set_icon(window, lparam as u32),
            (SS_BITMAP, IMAGE_BITMAP) | (SS_ENHMETAFILE, IMAGE_ENHMETAFILE) => {
                crate::stub::message_once(
                    &LOGGED,
                    message,
                    &crate::stub::STATIC_PROC,
                    "a static's bitmap or enhanced metafile (STM_SETIMAGE) is not yet kept",
                    (window, message, wparam, lparam),
                );
                0
            }
            _ => 0,
        },
        WM_SETTEXT => {
            if textless(kind(window)) {
                return 0;
            }
            let answer = message::default_procedure(window, message, wparam, lparam, ansi);
            let _ = imports::invalidate_rect(window, 0, true);
            answer
        }
        WM_SETFONT => {
            write(window, FONT, wparam);
            if lparam != 0 {
                let _ = imports::invalidate_rect(window, 0, true);
            }
            0
        }
        WM_GETFONT => read(window, FONT) as i32,
        WM_ENABLE => {
            let _ = imports::invalidate_rect(window, 0, true);
            0
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            log_undrawn(window, (window, message, wparam, lparam));
            if let Some(painting) = paint::Painting::begin(window) {
                draw_static(window, painting.dc());
            }
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// The static's parent, 0 for a top-level static.
fn parent_of(window: usize) -> usize {
    if style_of(window) & WS_CHILD == 0 {
        return 0;
    }
    window::links(window).map_or(0, |links: WindowLinks| links.parent as usize)
}

/// The notification `code` sent to the static's parent (WM_COMMAND: its id and the code, the
/// static's handle).
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

/// SS_SUNKEN made WS_EX_STATICEDGE, as Windows 2000's static does at its creation (controls
/// `edges`: the ex style reads 0x20000, a 1-pixel sunken edge). F2K's window manager has computed
/// the client area by the time WM_NCCREATE reaches the procedure, so the frame is taken again
/// (SWP_FRAMECHANGED).
fn sunken_edge(window: usize) {
    let Ok(info) = window::window_info(window) else {
        return;
    };
    if info.style & SS_SUNKEN == 0 || info.ex_style & WS_EX_STATICEDGE != 0 {
        return;
    }
    let _ = imports::set_window_long(window, GWL_EXSTYLE, info.ex_style | WS_EX_STATICEDGE, false);
    let _ = imports::set_window_pos(
        window,
        0,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
    );
}

/// StaticWndProcW: the Static class's procedure for a wide message.
pub extern "system" fn static_proc_w(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    static_control(window, message, wparam, lparam, false)
}

/// StaticWndProcA: the Static class's procedure for a narrow message.
pub extern "system" fn static_proc_a(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    static_control(window, message, wparam, lparam, true)
}

/// The static drawn into `dc`.
fn draw_static(window: usize, dc: usize) {
    let Some(client) = window::client_rect(window) else {
        return;
    };
    let style = window::style_of(window).unwrap_or(0);
    let solid = |index: u32| index as usize + 1;
    match style & SS_TYPEMASK {
        SS_BLACKRECT => {
            draw::fill(dc, client, solid(COLOR_3DDKSHADOW));
        }
        SS_GRAYRECT => {
            draw::fill(dc, client, solid(COLOR_3DSHADOW));
        }
        SS_WHITERECT => {
            draw::fill(dc, client, solid(COLOR_3DHILIGHT));
        }
        SS_BLACKFRAME => {
            draw::frame_in(dc, client, solid(COLOR_3DDKSHADOW));
        }
        SS_GRAYFRAME => {
            draw::frame_in(dc, client, solid(COLOR_3DSHADOW));
        }
        SS_WHITEFRAME => {
            draw::frame_in(dc, client, solid(COLOR_3DHILIGHT));
        }
        SS_ETCHEDHORZ => {
            draw::draw_edge_in(dc, client, draw::EDGE_ETCHED, BF_TOP);
        }
        SS_ETCHEDVERT => {
            draw::draw_edge_in(dc, client, draw::EDGE_ETCHED, BF_LEFT);
        }
        SS_ETCHEDFRAME => {
            draw::draw_edge_in(dc, client, draw::EDGE_ETCHED, BF_RECT);
        }
        kind => {
            let parent = parent_of(window);
            let brush = if parent != 0 {
                message::send(parent, WM_CTLCOLORSTATIC, dc as u32, window as i32).unwrap_or(0)
                    as usize
            } else {
                0
            };
            draw::fill(
                dc,
                client,
                if brush == 0 {
                    solid(COLOR_3DFACE)
                } else {
                    brush
                },
            );
            if kind == SS_ICON {
                return;
            }
            let format = match kind {
                SS_CENTER => draw::DT_CENTER | draw::DT_WORDBREAK | draw::DT_EXPANDTABS,
                SS_RIGHT => draw::DT_RIGHT | draw::DT_WORDBREAK | draw::DT_EXPANDTABS,
                SS_SIMPLE => draw::DT_LEFT | draw::DT_SINGLELINE,
                SS_LEFTNOWORDWRAP => draw::DT_LEFT | draw::DT_EXPANDTABS,
                _ => draw::DT_LEFT | draw::DT_WORDBREAK | draw::DT_EXPANDTABS,
            } | if style & SS_NOPREFIX != 0 {
                draw::DT_NOPREFIX
            } else {
                0
            };
            // SS_CENTERIMAGE centres one line (controls `centred`: DEFAULT_GUI_FONT's 13-pixel line
            // starts 8 rows down a 30-pixel client).
            let format = if style & SS_CENTERIMAGE != 0 {
                (format & !draw::DT_WORDBREAK) | draw::DT_SINGLELINE | draw::DT_VCENTER
            } else {
                format
            };
            let font = read(window, FONT);
            let previous = (font != 0)
                .then(|| imports::select_object(dc, font as usize))
                .flatten();
            imports::set_bk_mode(dc, TRANSPARENT);
            if style & WS_DISABLED != 0 {
                imports::set_text_color(dc, crate::display::get_sys_color(COLOR_GRAYTEXT as i32));
            } else if brush == 0 {
                imports::set_text_color(dc, crate::display::get_sys_color(COLOR_WINDOWTEXT as i32));
            }
            let text = message::window_text(window).unwrap_or_default();
            draw::draw_text_in(dc, text.as_slice(), client, format);
            if let Some(previous) = previous {
                imports::select_object(dc, previous);
            }
        }
    }
}
