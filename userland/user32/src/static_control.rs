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
//! SS_NOPREFIX with no mnemonic underline, gray when disabled); its rectangles and frames in the
//! 3D colors (black: COLOR_3DDKSHADOW, gray: COLOR_3DSHADOW, white: COLOR_3DHILIGHT); its etched
//! lines and frame with DrawEdge. An icon is not drawn: win32k's icon records hold no bits yet
//! (the seam the icons left), so an SS_ICON static paints its background alone.

use rtl::gdi::TRANSPARENT;
use rtl::user::*;
use rtl::window::{WindowLinks, QUERY_WINDOW_EXTRA};

use crate::dialog::{DLGC_STATIC, WM_GETDLGCODE, WM_GETFONT, WM_SETFONT, WS_CHILD, WS_DISABLED};
use crate::draw::{self, BF_LEFT, BF_RECT, BF_TOP};
use crate::{imports, message, paint, window};

/// The static messages (winuser.h's STM_*).
pub const STM_SETICON: u32 = 0x0170;
pub const STM_GETICON: u32 = 0x0171;
pub const STM_SETIMAGE: u32 = 0x0172;
pub const STM_GETIMAGE: u32 = 0x0173;

/// STM_SETIMAGE's and STM_GETIMAGE's image kinds.
const IMAGE_ICON: u32 = 1;
const IMAGE_CURSOR: u32 = 2;

/// The static kinds (the style's low five bits, winuser.h's SS_*).
const SS_CENTER: u32 = 0x01;
const SS_RIGHT: u32 = 0x02;
const SS_ICON: u32 = 0x03;
const SS_BLACKRECT: u32 = 0x04;
const SS_GRAYRECT: u32 = 0x05;
const SS_WHITERECT: u32 = 0x06;
const SS_BLACKFRAME: u32 = 0x07;
const SS_GRAYFRAME: u32 = 0x08;
const SS_WHITEFRAME: u32 = 0x09;
const SS_SIMPLE: u32 = 0x0B;
const SS_LEFTNOWORDWRAP: u32 = 0x0C;
const SS_ETCHEDHORZ: u32 = 0x10;
const SS_ETCHEDVERT: u32 = 0x11;
const SS_ETCHEDFRAME: u32 = 0x12;
const SS_TYPEMASK: u32 = 0x1F;
const SS_NOPREFIX: u32 = 0x80;

/// A static's extra bytes: its image, then its font.
pub const STATIC_EXTRA: i32 = 8;
const IMAGE: i32 = 0;
const FONT: i32 = 4;

/// The system colors a static paints in (winuser.h's COLOR_*).
const COLOR_3DFACE: u32 = 15;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_GRAYTEXT: u32 = 17;
const COLOR_WINDOWTEXT: u32 = 8;
const COLOR_3DHILIGHT: u32 = 20;
const COLOR_3DDKSHADOW: u32 = 21;

/// GetSystemMetrics' icon size.
const SM_CXICON: i32 = 11;
const SM_CYICON: i32 = 12;

/// SetWindowPos's flags for a size alone.
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;

fn read(window: usize, offset: i32) -> u32 {
    let mut value = 0u32;
    let _ = imports::query_window(window, QUERY_WINDOW_EXTRA | offset as u32, &mut value);
    value
}

fn write(window: usize, offset: i32, value: u32) -> u32 {
    imports::set_window_long(window, offset, value, false).map_or(0, |(previous, _)| previous)
}

fn kind(window: usize) -> u32 {
    window::style_of(window).unwrap_or(0) & SS_TYPEMASK
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
        WM_GETDLGCODE => DLGC_STATIC as i32,
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
            if let Some(painting) = paint::Painting::begin(window) {
                draw_static(window, painting.dc());
            }
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
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
            let parent = if style & WS_CHILD != 0 {
                window::links(window).map_or(0, |links: WindowLinks| links.parent as usize)
            } else {
                0
            };
            let brush = if parent != 0 {
                message::send(parent, message::WM_CTLCOLORSTATIC, dc as u32, window as i32)
                    .unwrap_or(0) as usize
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
