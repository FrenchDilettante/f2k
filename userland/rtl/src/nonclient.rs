//! The non-client area's shared geometry: what win32k and user32 agree a window's frame, caption
//! and menu bar are. Windows 2000 computes them in win32k alone and hands user32 the answers; F2K's
//! win32k cannot call a window procedure back (its sends are queued, see win32k's queue), so the
//! default procedure's share runs in user32 and both sides compute from the same rules here.
//!
//! - The metrics are the standard scheme's at 96 dpi ([`BORDER`], [`DLG_FRAME`], [`FRAME`],
//!   [`EDGE`], [`CAPTION`], [`MENU`], [`SIZE`]...): the guidisp capture's SM_CYCAPTION and
//!   SM_CXFRAME, the others from the scheme's published values.
//! - A window's frame comes from its styles ([`Frame::of`]): a sizing border (WS_THICKFRAME), else
//!   a dialog frame (WS_DLGFRAME, which WS_CAPTION holds, or WS_EX_DLGMODALFRAME), else a thin
//!   border (WS_BORDER); a client edge inside it (WS_EX_CLIENTEDGE, and WS_EX_STATICEDGE's thin
//!   one); a caption for WS_CAPTION (a tool window's small one); a menu bar for a window that is
//!   not a child and has a menu. The menu bar is one row: F2K does not wrap a bar too narrow for
//!   its items onto more rows, as Windows does.
//! - The client rectangle is the window's less the frame ([`Frame::client`]: the default
//!   procedure's WM_NCCALCSIZE answer); AdjustWindowRectEx is its inverse ([`Frame::window`]).
//! - The caption's parts ([`Caption`]): the system menu's box at its left (a window with WS_SYSMENU
//!   that is neither a tool window nor a dialog frame), the buttons from its right — the close
//!   button, then the maximize and minimize buttons side by side when either box is asked for, or
//!   the help button with WS_EX_CONTEXTHELP — and the text between.
//! - WM_NCHITTEST's default answer ([`hit_test`]), in screen coordinates as the message carries
//!   them: nowhere outside the window; the sizing codes on a sizing border (a corner's within
//!   [`CORNER`] of it along either side), HTBORDER on another border; the caption's parts; the menu
//!   bar; HTBORDER on the client edge; the client area.

use crate::gdi::Rect;

/// The window styles the frame reads (winuser.h's WS_*).
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_WINDOWEDGE: u32 = 0x0000_0100;
pub const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
pub const WS_EX_CONTEXTHELP: u32 = 0x0000_0400;
pub const WS_EX_STATICEDGE: u32 = 0x0002_0000;

/// The standard scheme's metrics at 96 dpi, as GetSystemMetrics answers them.
///
/// SM_CXBORDER and SM_CYBORDER: a thin border.
pub const BORDER: i32 = 1;
/// SM_CXDLGFRAME (SM_CXFIXEDFRAME) and its Y: a dialog frame, its 3D edge and a pixel of face.
pub const DLG_FRAME: i32 = 3;
/// SM_CXFRAME (SM_CXSIZEFRAME) and its Y: a sizing border (the guidisp capture's).
pub const FRAME: i32 = 4;
/// SM_CXEDGE and SM_CYEDGE: a 3D edge.
pub const EDGE: i32 = 2;
/// SM_CYCAPTION: the caption's height, its bar and the line under it (the guidisp capture's).
pub const CAPTION: i32 = 19;
/// SM_CYSMCAPTION: a tool window's caption.
pub const SM_CAPTION: i32 = 16;
/// SM_CYMENU: the menu bar's height, a row of items and the line under it.
pub const MENU: i32 = 19;
/// SM_CXSIZE and SM_CYSIZE: a caption button's cell.
pub const SIZE: i32 = 18;
/// SM_CXSMSIZE and SM_CYSMSIZE: a tool window's caption button's cell.
pub const SM_SIZE_X: i32 = 12;
pub const SM_SIZE_Y: i32 = 15;
/// SM_CXMENUSIZE and SM_CYMENUSIZE: a menu bar button's cell.
pub const MENU_SIZE: i32 = 18;
/// SM_CXMENUCHECK and SM_CYMENUCHECK: a menu check mark's cell.
pub const MENU_CHECK: i32 = 13;
/// SM_CXSMICON and SM_CYSMICON: a small icon, the caption's.
pub const SM_ICON: i32 = 16;
/// SM_CXMIN and SM_CYMIN, SM_CXMINTRACK and SM_CYMINTRACK: the smallest window.
pub const MIN_X: i32 = 112;
pub const MIN_Y: i32 = 27;

/// How far along a sizing border a corner's code reaches from the corner: a caption button's cell
/// and the border (an assumption: no public document gives it).
pub const CORNER: i32 = SIZE + FRAME;

/// WM_NCHITTEST's answers (winuser.h's HT*).
pub const HTERROR: u32 = -2i32 as u32;
pub const HTNOWHERE: u32 = 0;
pub const HTCLIENT: u32 = 1;
pub const HTCAPTION: u32 = 2;
pub const HTSYSMENU: u32 = 3;
pub const HTMENU: u32 = 5;
pub const HTMINBUTTON: u32 = 8;
pub const HTMAXBUTTON: u32 = 9;
pub const HTLEFT: u32 = 10;
pub const HTRIGHT: u32 = 11;
pub const HTTOP: u32 = 12;
pub const HTTOPLEFT: u32 = 13;
pub const HTTOPRIGHT: u32 = 14;
pub const HTBOTTOM: u32 = 15;
pub const HTBOTTOMLEFT: u32 = 16;
pub const HTBOTTOMRIGHT: u32 = 17;
pub const HTBORDER: u32 = 18;
pub const HTCLOSE: u32 = 20;
pub const HTHELP: u32 = 21;

/// The kinds of border a frame has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Border {
    None,
    /// WS_BORDER: a line of COLOR_WINDOWFRAME.
    Thin,
    /// A dialog frame: a raised 3D edge and a pixel of the face.
    Dialog,
    /// WS_THICKFRAME: a raised 3D edge and two pixels of the border color.
    Sizing,
}

/// A window's non-client parts, their widths in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub border: Border,
    /// The border's width, on every side.
    pub border_width: i32,
    /// The client edge's width inside the border (WS_EX_CLIENTEDGE's 3D edge, WS_EX_STATICEDGE's
    /// line, or both), on every side.
    pub edge: i32,
    /// The caption's height (0 for none), the line under it included.
    pub caption: i32,
    /// The menu bar's height (0 for none), the line under it included.
    pub menu: i32,
}

impl Frame {
    /// The frame of a window of `style` and `ex_style`, with a menu bar when `menu`. A child has no
    /// menu bar whatever `menu` says; AdjustWindowRectEx, which takes the caller's word, reads
    /// [`Frame::of_styles`] instead.
    pub fn of(style: u32, ex_style: u32, menu: bool) -> Frame {
        Frame::of_styles(style, ex_style, menu && style & WS_CHILD == 0)
    }

    /// The frame `style` and `ex_style` give, with a menu bar when `menu`, a child's too.
    pub fn of_styles(style: u32, ex_style: u32, menu: bool) -> Frame {
        let (border, border_width) = if style & WS_THICKFRAME != 0 {
            (Border::Sizing, FRAME)
        } else if style & WS_DLGFRAME != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
            (Border::Dialog, DLG_FRAME)
        } else if style & WS_BORDER != 0 {
            (Border::Thin, BORDER)
        } else {
            (Border::None, 0)
        };
        let mut edge = 0;
        if ex_style & WS_EX_CLIENTEDGE != 0 {
            edge += EDGE;
        }
        if ex_style & WS_EX_STATICEDGE != 0 {
            edge += BORDER;
        }
        let caption = if style & WS_CAPTION != WS_CAPTION {
            0
        } else if ex_style & WS_EX_TOOLWINDOW != 0 {
            SM_CAPTION
        } else {
            CAPTION
        };
        Frame {
            border,
            border_width,
            edge,
            caption,
            menu: if menu { MENU } else { 0 },
        }
    }

    /// The client rectangle of a window at `window`: the window's less the frame, never inside
    /// out (an edge that would cross the opposite one stops at it).
    pub fn client(&self, window: Rect) -> Rect {
        let side = self.border_width + self.edge;
        let left = window.left + side;
        let top = window.top + self.border_width + self.caption + self.menu + self.edge;
        let right = (window.right - side).max(left);
        let bottom = (window.bottom - side).max(top);
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The window rectangle of a window whose client rectangle is `client`: AdjustWindowRectEx.
    pub fn window(&self, client: Rect) -> Rect {
        let side = self.border_width + self.edge;
        Rect {
            left: client.left - side,
            top: client.top - self.border_width - self.caption - self.menu - self.edge,
            right: client.right + side,
            bottom: client.bottom + side,
        }
    }

    /// The caption's bar in a window at `window` (the line under it left out); none without one.
    pub fn caption_bar(&self, window: Rect) -> Option<Rect> {
        (self.caption > 0).then(|| Rect {
            left: window.left + self.border_width,
            top: window.top + self.border_width,
            right: window.right - self.border_width,
            bottom: window.top + self.border_width + self.caption - 1,
        })
    }

    /// The menu bar in a window at `window`, the line under it included; none without one.
    pub fn menu_bar(&self, window: Rect) -> Option<Rect> {
        (self.menu > 0).then(|| {
            let top = window.top + self.border_width + self.caption;
            Rect {
                left: window.left + self.border_width,
                top,
                right: window.right - self.border_width,
                bottom: top + self.menu,
            }
        })
    }
}

/// A caption's button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Close,
    Maximize,
    Minimize,
    Help,
}

impl Button {
    /// The button's WM_NCHITTEST answer.
    pub fn hit(self) -> u32 {
        match self {
            Button::Close => HTCLOSE,
            Button::Maximize => HTMAXBUTTON,
            Button::Minimize => HTMINBUTTON,
            Button::Help => HTHELP,
        }
    }
}

/// A caption's parts, in the coordinates of the window rectangle it was laid out in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caption {
    /// The caption's bar.
    pub bar: Rect,
    /// The system menu's box, where the small icon is drawn; none without one.
    pub system_menu: Option<Rect>,
    /// The buttons, right to left, and whether each is enabled (a maximize or minimize button
    /// whose box the style lacks is drawn disabled beside the other).
    pub buttons: [Option<(Button, Rect, bool)>; 3],
    /// Where the text goes.
    pub text: Rect,
}

impl Caption {
    /// The caption of a window of `style` and `ex_style` at `window`; none without a caption.
    pub fn of(style: u32, ex_style: u32, window: Rect) -> Option<Caption> {
        let frame = Frame::of_styles(style, ex_style, false);
        let bar = frame.caption_bar(window)?;
        let tool = ex_style & WS_EX_TOOLWINDOW != 0;
        let system = style & WS_SYSMENU != 0;
        let (cx, cy) = if tool {
            (SM_SIZE_X - 2, SM_SIZE_Y - 4)
        } else {
            (SIZE - 2, SIZE - 4)
        };
        let top = bar.top + (bar.bottom - bar.top - cy) / 2;
        let button = |right: i32| Rect {
            left: right - cx,
            top,
            right,
            bottom: top + cy,
        };
        let mut buttons = [None; 3];
        let mut leftmost = bar.right;
        if system {
            let close = button(bar.right - 2);
            buttons[0] = Some((Button::Close, close, true));
            leftmost = close.left;
            if !tool && style & (WS_MINIMIZEBOX | WS_MAXIMIZEBOX) != 0 {
                let maximize = button(close.left - 2);
                let minimize = button(maximize.left);
                buttons[1] = Some((Button::Maximize, maximize, style & WS_MAXIMIZEBOX != 0));
                buttons[2] = Some((Button::Minimize, minimize, style & WS_MINIMIZEBOX != 0));
                leftmost = minimize.left;
            } else if !tool && ex_style & WS_EX_CONTEXTHELP != 0 {
                let help = button(close.left - 2);
                buttons[1] = Some((Button::Help, help, true));
                leftmost = help.left;
            }
        }
        let system_menu =
            (system && !tool && ex_style & WS_EX_DLGMODALFRAME == 0).then_some(Rect {
                left: bar.left,
                top: bar.top,
                right: bar.left + SIZE,
                bottom: bar.bottom,
            });
        let text_left = match system_menu {
            Some(icon) => icon.right + 1,
            None => bar.left + 3,
        };
        Some(Caption {
            bar,
            system_menu,
            buttons,
            text: Rect {
                left: text_left,
                top: bar.top,
                right: (leftmost - 2).max(text_left),
                bottom: bar.bottom,
            },
        })
    }
}

/// Whether `point` is in `rect`.
fn contains(rect: Rect, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

/// WM_NCHITTEST's default answer for the point (`x`, `y`) and a window of `style` and `ex_style` at
/// `window`, with a menu bar when `menu`, all in the same coordinates (the screen's).
pub fn hit_test(style: u32, ex_style: u32, menu: bool, window: Rect, x: i32, y: i32) -> u32 {
    if !contains(window, x, y) {
        return HTNOWHERE;
    }
    let frame = Frame::of(style, ex_style, menu);
    let inner = Rect {
        left: window.left + frame.border_width,
        top: window.top + frame.border_width,
        right: window.right - frame.border_width,
        bottom: window.bottom - frame.border_width,
    };
    if !contains(inner, x, y) {
        if frame.border != Border::Sizing {
            return HTBORDER;
        }
        let near_left = x < window.left + CORNER;
        let near_right = x >= window.right - CORNER;
        let near_top = y < window.top + CORNER;
        let near_bottom = y >= window.bottom - CORNER;
        return if x < inner.left {
            if near_top {
                HTTOPLEFT
            } else if near_bottom {
                HTBOTTOMLEFT
            } else {
                HTLEFT
            }
        } else if x >= inner.right {
            if near_top {
                HTTOPRIGHT
            } else if near_bottom {
                HTBOTTOMRIGHT
            } else {
                HTRIGHT
            }
        } else if y < inner.top {
            if near_left {
                HTTOPLEFT
            } else if near_right {
                HTTOPRIGHT
            } else {
                HTTOP
            }
        } else if near_left {
            HTBOTTOMLEFT
        } else if near_right {
            HTBOTTOMRIGHT
        } else {
            HTBOTTOM
        };
    }
    if frame.caption > 0 && y < inner.top + frame.caption {
        let Some(caption) = Caption::of(style, ex_style, window) else {
            return HTCAPTION;
        };
        for (button, rect, _) in caption.buttons.iter().flatten() {
            if contains(*rect, x, y) {
                return button.hit();
            }
        }
        return match caption.system_menu {
            Some(icon) if x < icon.right => HTSYSMENU,
            _ => HTCAPTION,
        };
    }
    if frame.menu > 0 && y < inner.top + frame.caption + frame.menu {
        return HTMENU;
    }
    if contains(frame.client(window), x, y) {
        HTCLIENT
    } else {
        HTBORDER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVERLAPPED_WINDOW: u32 =
        WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// AdjustWindowRectEx's widely published answers for the standard scheme: an overlapped
    /// window's 4-pixel border and 19-pixel caption, the menu bar's 19 more; and the coords
    /// capture's: a thin border's pixel, a captioned window's fixed frame.
    #[test]
    fn the_frames_of_the_common_styles() {
        let client = rect(0, 0, 100, 100);
        let adjust = |style, ex, menu| Frame::of_styles(style, ex, menu).window(client);
        assert_eq!(adjust(OVERLAPPED_WINDOW, 0, false), rect(-4, -23, 104, 104));
        assert_eq!(adjust(OVERLAPPED_WINDOW, 0, true), rect(-4, -42, 104, 104));
        assert_eq!(adjust(WS_BORDER, 0, false), rect(-1, -1, 101, 101));
        assert_eq!(adjust(WS_CAPTION, 0, false), rect(-3, -22, 103, 103));
        assert_eq!(
            adjust(WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME, false),
            rect(-3, -22, 103, 103)
        );
        assert_eq!(
            adjust(WS_CHILD, WS_EX_CLIENTEDGE, false),
            rect(-2, -2, 102, 102)
        );
        assert_eq!(adjust(0, 0, false), client);
        let frame = Frame::of(OVERLAPPED_WINDOW, 0, true);
        assert_eq!(frame.client(frame.window(client)), client);
        assert_eq!(Frame::of(WS_CHILD | WS_BORDER, 0, true).menu, 0);
    }

    /// The mousein capture's answers on a 320x240 overlapped window.
    #[test]
    fn the_hit_test_as_captured() {
        let w = rect(160, 120, 480, 360);
        let hit = |x, y| hit_test(OVERLAPPED_WINDOW, 0, false, w, x, y);
        let caption_y = w.top + FRAME + CAPTION / 2;
        assert_eq!(hit(320, caption_y), HTCAPTION);
        assert_eq!(hit(w.left + FRAME + SIZE / 2, caption_y), HTSYSMENU);
        assert_eq!(hit(w.right - FRAME - 2 - SIZE / 2, caption_y), HTCLOSE);
        assert_eq!(hit(320, w.top + 1), HTTOP);
        assert_eq!(hit(w.left + 1, 240), HTLEFT);
        assert_eq!(hit(w.right - 2, 240), HTRIGHT);
        assert_eq!(hit(320, w.bottom - 2), HTBOTTOM);
        assert_eq!(hit(w.left + 1, w.top + 1), HTTOPLEFT);
        assert_eq!(hit(w.right - 2, w.bottom - 2), HTBOTTOMRIGHT);
        assert_eq!(hit(320, 240), HTCLIENT);
        assert_eq!(hit(w.left - 10, 240), HTNOWHERE);
        assert_eq!(hit(w.right + 10, 240), HTNOWHERE);
    }

    /// The caption's buttons from the right, the menu bar under the caption, a dialog frame's
    /// border.
    #[test]
    fn the_buttons_the_menu_bar_and_a_dialog_frame() {
        let w = rect(0, 0, 300, 200);
        let caption = Caption::of(OVERLAPPED_WINDOW, 0, w).unwrap();
        let close = caption.buttons[0].unwrap();
        assert_eq!(close.1, rect(278, 6, 294, 20));
        assert_eq!(caption.buttons[1].unwrap().1.right, 276);
        assert_eq!(caption.buttons[2].unwrap().1.right, 260);
        let calc = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let calc_caption = Caption::of(calc, 0, w).unwrap();
        assert!(!calc_caption.buttons[1].unwrap().2, "no maximize box");
        assert_eq!(hit_test(calc, 0, true, w, 150, 3 + 19 + 5), HTMENU);
        assert_eq!(hit_test(calc, 0, true, w, 1, 100), HTBORDER);
        assert_eq!(hit_test(calc, 0, true, w, 150, 3 + 19 + 19), HTCLIENT);
        let dialog = Caption::of(WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME, w).unwrap();
        assert!(dialog.system_menu.is_none());
        assert!(dialog.buttons[1].is_none());
    }
}
