//! The non-client area: AdjustWindowRect and AdjustWindowRectEx, and the default window
//! procedure's WM_NCCALCSIZE, WM_NCHITTEST, WM_NCPAINT and WM_NCACTIVATE, over the frame
//! rtl::nonclient computes from a window's styles (win32k computes the same frame for the client
//! rectangles it keeps).
//!
//! Windows 2000 answers these in win32k (its xxxDefWindowProc), which calls the window procedures
//! back as it draws; F2K's win32k calls no user-mode code, so the default procedure's share runs
//! here, client-side, as the dialog manager's does, and draws through gdi32 into a DC of the whole
//! window (GetWindowDC), its coordinates the window's own.
//!
//! The frame is drawn in the classic look's system colors:
//! - a thin border (WS_BORDER) in COLOR_WINDOWFRAME;
//! - a dialog frame as a raised 3D edge and a pixel of COLOR_3DFACE;
//! - a sizing border as a raised 3D edge and two pixels of COLOR_ACTIVEBORDER (COLOR_INACTIVEBORDER
//!   for an inactive window);
//! - a client edge (WS_EX_CLIENTEDGE) sunken, a static edge (WS_EX_STATICEDGE) as its outer half.
//!
//! The caption's bar is a gradient from COLOR_ACTIVECAPTION on the left to
//! COLOR_GRADIENTACTIVECAPTION on the right (the inactive pair for an inactive window: Windows
//! 2000's default has gradient captions), drawn in bands of [`GRADIENT_BAND`] pixels; the line
//! under it is COLOR_3DFACE. Its text is the window's, in the caption font (Tahoma bold, 8 points)
//! and COLOR_CAPTIONTEXT (COLOR_INACTIVECAPTIONTEXT), left-aligned after the system menu's box,
//! clipped before the buttons. The box shows no icon: F2K's icons hold no bits yet. The buttons are
//! raised faces with Marlett's glyphs (close `r`, minimize `0`, maximize `1`, help `s`), a disabled
//! one's glyph embossed; on a disk without Marlett the glyphs are drawn as pixel shapes of their
//! own. Without the system's fonts the caption font is whatever the font mapper stands in (the
//! built-in 8x16 font), which fits the bar.
//!
//! A window's caption is drawn active when it is the foreground window, or the owner of the menu
//! loop running on the thread; WM_NCACTIVATE draws it as its wParam says.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::edge::Out;
use rtl::gdi::{LogFontW, Rect, LF_FACESIZE, SYMBOL_CHARSET, TRANSPARENT};
use rtl::nonclient::{Border, Button, Caption, Frame};

use crate::draw::{
    self,
    BDR_SUNKENOUTER,
    BF_MIDDLE,
    BF_RECT,
    BF_SOFT,
    DT_CENTER,
    DT_LEFT,
    DT_NOPREFIX,
    DT_SINGLELINE,
    DT_VCENTER,
    EDGE_RAISED,
    EDGE_SUNKEN,
};
use crate::{imports, menubar, message, window};

/// The non-client messages the default procedure answers (winuser.h's WM_*).
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCPAINT: u32 = 0x0085;
pub const WM_NCACTIVATE: u32 = 0x0086;

/// The system colors the frame is drawn in (winuser.h's COLOR_*).
const COLOR_ACTIVECAPTION: u32 = 2;
const COLOR_INACTIVECAPTION: u32 = 3;
const COLOR_WINDOWFRAME: u32 = 6;
const COLOR_CAPTIONTEXT: u32 = 9;
const COLOR_ACTIVEBORDER: u32 = 10;
const COLOR_INACTIVEBORDER: u32 = 11;
const COLOR_3DFACE: u32 = 15;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_BTNTEXT: u32 = 18;
const COLOR_INACTIVECAPTIONTEXT: u32 = 19;
const COLOR_3DHILIGHT: u32 = 20;
const COLOR_GRADIENTACTIVECAPTION: u32 = 27;
const COLOR_GRADIENTINACTIVECAPTION: u32 = 28;

/// The width of the caption gradient's bands, in pixels.
pub const GRADIENT_BAND: i32 = 4;

/// What the default procedure reads of a window to draw and answer its non-client area.
#[derive(Clone, Copy, Debug)]
pub struct Framed {
    pub handle: usize,
    pub style: u32,
    pub ex_style: u32,
    /// The window's rectangle, in screen coordinates.
    pub rect: Rect,
    /// Its menu bar's menu (0 for none: a child's id is no menu).
    pub menu: usize,
}

impl Framed {
    /// The window `handle` names; none for a handle naming no window (the last error untouched).
    pub fn of(handle: usize) -> Option<Framed> {
        let info = window::window_info(handle).ok()?;
        let menu = if info.style & rtl::nonclient::WS_CHILD != 0 {
            0
        } else {
            menu_quiet(handle)
        };
        Some(Framed {
            handle,
            style: info.style,
            ex_style: info.ex_style,
            rect: info.window,
            menu,
        })
    }

    /// The frame its styles and its menu give.
    pub fn frame(&self) -> Frame {
        Frame::of(self.style, self.ex_style, self.menu != 0)
    }

    /// Its rectangle in its own coordinates, as a DC of the whole window draws it.
    pub fn local(&self) -> Rect {
        Rect {
            left: 0,
            top: 0,
            right: self.rect.right - self.rect.left,
            bottom: self.rect.bottom - self.rect.top,
        }
    }
}

/// The window's menu, as GetMenu answers it, the last error untouched.
fn menu_quiet(window: usize) -> usize {
    let mut menu = 0u32;
    imports::query_window(window, rtl::window::QUERY_WINDOW_MENU, &mut menu)
        .map_or(0, |()| menu as usize)
}

// --- AdjustWindowRect ----------------------------------------------------------------------------

/// AdjustWindowRectEx: the client rectangle in the caller's RECT made the window rectangle a
/// window of `style` and `ex_style` (with a menu bar when `menu`) has around it; TRUE. The menu is
/// the caller's word, a child's too; WS_VSCROLL and WS_HSCROLL are not taken into account, as the
/// documentation says.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_AdjustWindowRectEx")]
pub unsafe extern "system" fn adjust_window_rect_ex(
    rect: *mut Rect,
    style: u32,
    menu: i32,
    ex_style: u32,
) -> i32 {
    // SAFETY: the caller's RECT.
    let mut rect = unsafe { Out::new(rect) };
    rect.set(Frame::of_styles(style, ex_style, menu != 0).window(rect.get()));
    1
}

/// AdjustWindowRect: AdjustWindowRectEx's, with no extended style.
///
/// # Safety
///
/// The caller's RECT, as for the platform's.
#[unsafe(export_name = "f2k_export_AdjustWindowRect")]
pub unsafe extern "system" fn adjust_window_rect(rect: *mut Rect, style: u32, menu: i32) -> i32 {
    // SAFETY: the caller's RECT, as the platform's AdjustWindowRect hands it on.
    unsafe { adjust_window_rect_ex(rect, style, menu, 0) }
}

// --- The default procedure's answers -------------------------------------------------------------

/// The default procedure's WM_NCCALCSIZE: the rectangle lParam points at made the client rectangle
/// the window's frame leaves inside it; 0. With wParam TRUE, lParam is an NCCALCSIZE_PARAMS, whose
/// first member is that rectangle (the new window rectangle), the others left as they are. The
/// rectangle is the caller's, in whatever coordinates it chose.
pub fn calc_size(window: usize, _wparam: u32, lparam: i32) -> i32 {
    if lparam != 0 {
        // SAFETY: WM_NCCALCSIZE's lParam as its sender hands it over: a RECT, or an
        // NCCALCSIZE_PARAMS whose first member is the RECT written.
        calc_into(window, unsafe { Out::new(lparam as usize as *mut Rect) });
    }
    0
}

/// WM_NCCALCSIZE's work: `rect` made the client rectangle `window`'s frame leaves inside it.
fn calc_into(window: usize, mut rect: Out<'_, Rect>) {
    if let Some(framed) = Framed::of(window) {
        rect.set(framed.frame().client(rect.get()));
    }
}

/// The default procedure's WM_NCHITTEST: what lies under the screen point lParam carries (its low
/// word x, its high word y, both signed).
pub fn hit_test(window: usize, lparam: i32) -> i32 {
    let Some(framed) = Framed::of(window) else {
        return rtl::nonclient::HTNOWHERE as i32;
    };
    let x = lparam as i16 as i32;
    let y = (lparam >> 16) as i16 as i32;
    rtl::nonclient::hit_test(
        framed.style,
        framed.ex_style,
        framed.menu != 0,
        framed.rect,
        x,
        y,
    ) as i32
}

/// Whether the window's caption is drawn active: it is the foreground window, or the menu loop
/// running on the thread is its.
fn is_active(window: usize) -> bool {
    imports::foreground_window().is_ok_and(|foreground| foreground as usize == window)
        || menubar::loop_owner() == window
}

/// The scroll bars a window's styles ask for, which the frame has no part for yet (neither drawn
/// nor taken from the client area), and what each is.
const SCROLL_BARS: [(u32, &str); 2] = [
    (0x0020_0000, "WS_VSCROLL (the window's vertical scroll bar)"),
    (
        0x0010_0000,
        "WS_HSCROLL (the window's horizontal scroll bar)",
    ),
];

/// The scroll bars logged in this process.
static SCROLL_BARS_LOGGED: rtl::stub::Logged<2> = rtl::stub::Logged::new();

/// The default procedure's WM_NCPAINT: the window's whole frame painted (whatever region wParam
/// names), its caption as its activation has it; 0. A scroll bar its styles ask for is logged for
/// `entry` (DefWindowProc's, with the message's `call`), once per process: it is not drawn yet.
pub fn paint(window: usize, entry: &rtl::stub::Entry, call: (usize, u32, u32, i32)) -> i32 {
    if let Some(framed) = Framed::of(window) {
        for &(bit, what) in &SCROLL_BARS {
            if framed.style & bit != 0 {
                crate::stub::message_once(
                    &SCROLL_BARS_LOGGED,
                    bit,
                    entry,
                    format_args!(
                        "{what} is not yet implemented: neither drawn nor taken from the client \
                         area"
                    ),
                    call,
                );
            }
        }
        if crate::window::is_window_visible(window) != 0 {
            paint_frame(&framed, is_active(window), true);
        }
    }
    0
}

/// The default procedure's WM_NCACTIVATE: the caption redrawn active or inactive as wParam says
/// (kept active while the window's menu loop runs); TRUE, the change goes on.
pub fn activate(window: usize, wparam: u32) -> i32 {
    if let Some(framed) = Framed::of(window) {
        if crate::window::is_window_visible(window) != 0 && framed.frame().caption > 0 {
            let active = wparam != 0 || menubar::loop_owner() == window;
            paint_frame(&framed, active, false);
        }
    }
    1
}

/// The caption of `window` redrawn as it stands (its text changed).
pub fn redraw_caption(window: usize) {
    if let Some(framed) = Framed::of(window) {
        if crate::window::is_window_visible(window) != 0 && framed.frame().caption > 0 {
            paint_frame(&framed, is_active(window), false);
        }
    }
}

/// The frame of `framed` drawn into a DC of the whole window: the borders and the edges, the
/// caption (`active` or not), and with `whole` the menu bar too.
fn paint_frame(framed: &Framed, active: bool, whole: bool) {
    let Ok(dc) = imports::get_window_dc(framed.handle) else {
        return;
    };
    let dc = dc as usize;
    let frame = framed.frame();
    let local = framed.local();
    if whole {
        draw_borders(dc, local, &frame, active);
    }
    if let Some(caption) = Caption::of(framed.style, framed.ex_style, local) {
        draw_caption(dc, framed.handle, &caption, active);
        let line = Rect {
            top: caption.bar.bottom,
            bottom: caption.bar.bottom + 1,
            ..caption.bar
        };
        draw::fill(dc, line, color(COLOR_3DFACE));
    }
    if whole {
        if let Some(bar) = frame.menu_bar(local) {
            menubar::draw_bar(dc, framed.menu, bar, menubar::bar_selection(framed.handle));
        }
    }
    let _ = imports::close(dc);
}

/// A system color as a fill's brush (its index plus one).
pub fn color(index: u32) -> usize {
    index as usize + 1
}

/// `rect` moved in by `by` on every side.
pub fn inset(rect: Rect, by: i32) -> Rect {
    Rect {
        left: rect.left + by,
        top: rect.top + by,
        right: rect.right - by,
        bottom: rect.bottom - by,
    }
}

/// The borders of a frame in a window at `local`, and its client edge.
fn draw_borders(dc: usize, local: Rect, frame: &Frame, active: bool) {
    let mut inside = local;
    match frame.border {
        Border::None => {}
        Border::Thin => {
            draw::frame_in(dc, inside, color(COLOR_WINDOWFRAME));
            inside = inset(inside, 1);
        }
        Border::Dialog | Border::Sizing => {
            let (rest, _) = draw::draw_edge_in(dc, inside, EDGE_RAISED, BF_RECT);
            inside = rest;
            let fill = if frame.border == Border::Dialog {
                COLOR_3DFACE
            } else if active {
                COLOR_ACTIVEBORDER
            } else {
                COLOR_INACTIVEBORDER
            };
            for _ in 2..frame.border_width {
                draw::frame_in(dc, inside, color(fill));
                inside = inset(inside, 1);
            }
        }
    }
    if frame.edge > 0 {
        let mut edge = inside;
        edge.top += frame.caption + frame.menu;
        let mut width = frame.edge;
        if width >= 2 {
            let (rest, _) = draw::draw_edge_in(dc, edge, EDGE_SUNKEN, BF_RECT);
            edge = rest;
            width -= 2;
        }
        if width > 0 {
            draw::draw_edge_in(dc, edge, BDR_SUNKENOUTER, BF_RECT);
        }
    }
}

/// The caption's bar of `window`: its gradient, its text and its buttons.
fn draw_caption(dc: usize, window: usize, caption: &Caption, active: bool) {
    let (from, to, text) = if active {
        (
            COLOR_ACTIVECAPTION,
            COLOR_GRADIENTACTIVECAPTION,
            COLOR_CAPTIONTEXT,
        )
    } else {
        (
            COLOR_INACTIVECAPTION,
            COLOR_GRADIENTINACTIVECAPTION,
            COLOR_INACTIVECAPTIONTEXT,
        )
    };
    gradient(
        dc,
        caption.bar,
        crate::display::get_sys_color(from as i32),
        crate::display::get_sys_color(to as i32),
    );
    let title = message::window_text(window).unwrap_or_default();
    let font = caption_font();
    let previous = (font != 0)
        .then(|| imports::select_object(dc, font))
        .flatten();
    imports::set_bk_mode(dc, TRANSPARENT);
    imports::set_text_color(dc, crate::display::get_sys_color(text as i32));
    draw::draw_text_in(
        dc,
        title.as_slice(),
        caption.text,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
    );
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    for (button, rect, enabled) in caption.buttons.iter().flatten() {
        draw_caption_button(dc, *button, *rect, *enabled);
    }
}

/// A gradient across `rect` from `from` on its left to `to` on its right (COLORREFs), in bands.
fn gradient(dc: usize, rect: Rect, from: u32, to: u32) {
    let width = (rect.right - rect.left).max(1);
    let channel = |color: u32, shift: u32| ((color >> shift) & 0xFF) as i32;
    let mut x = rect.left;
    while x < rect.right {
        let right = (x + GRADIENT_BAND).min(rect.right);
        let at = x - rect.left;
        let mix = |shift: u32| {
            let a = channel(from, shift);
            let b = channel(to, shift);
            (a + (b - a) * at / width) as u32
        };
        let color = mix(0) | mix(8) << 8 | mix(16) << 16;
        if let Some(brush) = imports::create_solid_brush(color) {
            draw::fill(
                dc,
                Rect {
                    left: x,
                    right,
                    ..rect
                },
                brush,
            );
            imports::delete_object(brush);
        }
        x = right;
    }
}

/// A caption button's face and glyph in `rect`; a disabled one's glyph embossed.
fn draw_caption_button(dc: usize, button: Button, rect: Rect, enabled: bool) {
    let (face, _) = draw::draw_edge_in(dc, rect, EDGE_RAISED, BF_RECT | BF_SOFT | BF_MIDDLE);
    let glyph = match button {
        Button::Close => Glyph::Close,
        Button::Minimize => Glyph::Minimize,
        Button::Maximize => Glyph::Maximize,
        Button::Help => Glyph::Help,
    };
    draw_glyph(dc, glyph, face, enabled, COLOR_BTNTEXT);
}

// --- The glyphs ----------------------------------------------------------------------------------

/// The glyphs the frame and the menus draw: Marlett's characters, or pixel shapes of their own
/// on a disk without Marlett.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    Close,
    Minimize,
    Maximize,
    Help,
    /// A menu item's check mark.
    Check,
    /// A radio item's bullet.
    Bullet,
    /// A popup item's arrow.
    Arrow,
}

impl Glyph {
    /// Its Marlett character.
    fn marlett(self) -> u16 {
        u16::from(match self {
            Glyph::Close => b'r',
            Glyph::Minimize => b'0',
            Glyph::Maximize => b'1',
            Glyph::Help => b's',
            Glyph::Check => b'a',
            Glyph::Bullet => b'h',
            Glyph::Arrow => b'8',
        })
    }

    /// Its own pixel shape, `#` for ink: rows of equal width.
    fn shape(self) -> &'static [&'static [u8]] {
        match self {
            Glyph::Close => &[
                b"##....##",
                b".##..##.",
                b"..####..",
                b"...##...",
                b"..####..",
                b".##..##.",
                b"##....##",
            ],
            Glyph::Minimize => &[
                b"......", b"......", b"......", b"......", b"######", b"######",
            ],
            Glyph::Maximize => &[
                b"#########",
                b"#########",
                b"#.......#",
                b"#.......#",
                b"#.......#",
                b"#.......#",
                b"#.......#",
                b"#########",
            ],
            Glyph::Help => &[
                b".####.", b"##..##", b"....##", b"...##.", b"..##..", b"..##..", b"......",
                b"..##..",
            ],
            Glyph::Check => &[
                b"......#", b".....##", b"#...###", b"##.###.", b"#####..", b".###...", b"..#....",
            ],
            Glyph::Bullet => &[b".##.", b"####", b"####", b".##."],
            Glyph::Arrow => &[
                b"#...", b"##..", b"###.", b"####", b"###.", b"##..", b"#...",
            ],
        }
    }
}

/// Marlett at the glyphs' size: its handle once made, 1 when it is not on the disk (the mapper
/// stood another face in), 0 before the first try.
static MARLETT: AtomicU32 = AtomicU32::new(0);
/// The caption and menu fonts, once made (0 before).
static CAPTION_FONT: AtomicU32 = AtomicU32::new(0);
static MENU_FONT: AtomicU32 = AtomicU32::new(0);

/// A font of `face` at `height` (negative: its em) and `weight`, in `char_set`.
fn make_font(face: &str, height: i32, weight: i32, char_set: u8) -> Option<usize> {
    let mut font = LogFontW {
        height,
        width: 0,
        escapement: 0,
        orientation: 0,
        weight,
        italic: 0,
        underline: 0,
        strike_out: 0,
        char_set,
        out_precision: 0,
        clip_precision: 0,
        quality: 0,
        pitch_and_family: 0,
        face_name: [0; LF_FACESIZE],
    };
    for (unit, byte) in font.face_name.iter_mut().zip(face.bytes()) {
        *unit = u16::from(byte);
    }
    imports::create_font(&font)
}

/// The font kept in `cell`, made by `make` the first time.
fn kept(cell: &AtomicU32, make: impl FnOnce() -> Option<usize>) -> usize {
    match cell.load(Ordering::Acquire) {
        0 => {
            let font = make().unwrap_or(0) as u32;
            match cell.compare_exchange(0, font, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => font as usize,
                Err(other) => {
                    if font != 0 {
                        imports::delete_object(font as usize);
                    }
                    other as usize
                }
            }
        }
        font => font as usize,
    }
}

/// The caption font: Tahoma, bold, 8 points at 96 dpi (the standard scheme's).
pub fn caption_font() -> usize {
    kept(&CAPTION_FONT, || make_font("Tahoma", -11, 700, 0))
}

/// The menu font: Tahoma, 8 points at 96 dpi (the standard scheme's).
pub fn menu_font() -> usize {
    kept(&MENU_FONT, || make_font("Tahoma", -11, 400, 0))
}

/// Marlett, when the disk has it, selected into `dc`: the DC's font before; none without Marlett
/// (nothing selected).
fn select_marlett(dc: usize) -> Option<usize> {
    match MARLETT.load(Ordering::Acquire) {
        1 => None,
        0 => {
            let Some(font) = make_font("Marlett", -13, 400, SYMBOL_CHARSET) else {
                MARLETT.store(1, Ordering::Release);
                return None;
            };
            let previous = imports::select_object(dc, font)?;
            let symbol =
                imports::text_metrics(dc).is_some_and(|metric| metric.char_set == SYMBOL_CHARSET);
            if !symbol {
                imports::select_object(dc, previous);
                imports::delete_object(font);
                MARLETT.store(1, Ordering::Release);
                return None;
            }
            if MARLETT
                .compare_exchange(0, font as u32, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                imports::select_object(dc, previous);
                imports::delete_object(font);
                return select_marlett(dc);
            }
            Some(previous)
        }
        font => imports::select_object(dc, font as usize),
    }
}

/// `glyph` centered in `rect`, in the system color `ink`; a disabled one embossed (COLOR_3DHILIGHT
/// a pixel down and right, COLOR_3DSHADOW over it).
pub fn draw_glyph(dc: usize, glyph: Glyph, rect: Rect, enabled: bool, ink: u32) {
    let layers: &[(i32, u32)] = if enabled {
        &[(0, ink)]
    } else {
        &[(1, COLOR_3DHILIGHT), (0, COLOR_3DSHADOW)]
    };
    if let Some(previous) = select_marlett(dc) {
        imports::set_bk_mode(dc, TRANSPARENT);
        let character = [glyph.marlett()];
        for &(offset, index) in layers {
            imports::set_text_color(dc, crate::display::get_sys_color(index as i32));
            let at = Rect {
                left: rect.left + offset,
                top: rect.top + offset,
                right: rect.right + offset,
                bottom: rect.bottom + offset,
            };
            draw::draw_text_in(
                dc,
                &character,
                at,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
        }
        imports::select_object(dc, previous);
        return;
    }
    let shape = glyph.shape();
    let height = shape.len() as i32;
    let width = shape.first().map_or(0, |row| row.len()) as i32;
    let left = rect.left + (rect.right - rect.left - width) / 2;
    let top = rect.top + (rect.bottom - rect.top - height) / 2;
    for &(offset, index) in layers {
        for (y, row) in shape.iter().enumerate() {
            let mut x = 0;
            while x < row.len() {
                if row[x] != b'#' {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < row.len() && row[x] == b'#' {
                    x += 1;
                }
                let run = Rect {
                    left: left + start as i32 + offset,
                    top: top + y as i32 + offset,
                    right: left + x as i32 + offset,
                    bottom: top + y as i32 + 1 + offset,
                };
                draw::fill(dc, run, color(index));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::procedure;
    use crate::window::create_window_ex_a;

    fn plain(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        crate::message::def_window_proc_a(window as usize, message, wparam, lparam)
    }

    fn framed(style: u32) -> usize {
        let class = WndClass {
            wnd_proc: procedure(plain) as usize,
            class_name: c"F2KFramed".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the test's own, and its name.
        unsafe {
            register_class_a(&class);
            create_window_ex_a(
                0,
                c"F2KFramed".as_ptr().cast(),
                core::ptr::null(),
                style,
                100,
                80,
                300,
                200,
                0,
                0,
                0,
                0,
            )
        }
    }

    /// AdjustWindowRectEx adds the frame, the caption and the menu bar: the standard scheme's
    /// overlapped window, a dialog frame, nothing for a bare popup.
    ///
    /// Pins: user32.AdjustWindowRectEx, user32.AdjustWindowRect
    #[test]
    fn adjust_adds_the_frame() {
        let client = Rect {
            left: 0,
            top: 0,
            right: 100,
            bottom: 50,
        };
        let mut rect = client;
        // SAFETY: the test's own RECT.
        assert_eq!(
            unsafe { adjust_window_rect_ex(&mut rect, 0x00CF_0000, 1, 0) },
            1
        );
        assert_eq!(
            rect,
            Rect {
                left: -4,
                top: -42,
                right: 104,
                bottom: 54
            }
        );
        let mut rect = client;
        // SAFETY: as above.
        unsafe { adjust_window_rect(&mut rect, 0x8000_0000, 0) };
        assert_eq!(rect, client);
    }

    /// WM_NCCALCSIZE takes the frame off the rectangle it is given; WM_NCHITTEST through
    /// DefWindowProc answers the caption, the client area and nowhere.
    ///
    /// Pins: user32.DefWindowProcA
    #[test]
    fn the_default_answers() {
        let window = framed(0x00CF_0000);
        let mut rect = Rect {
            left: 0,
            top: 0,
            right: 100,
            bottom: 50,
        };
        calc_into(window, Out::from(&mut rect));
        assert_eq!(
            rect,
            Rect {
                left: 4,
                top: 23,
                right: 96,
                bottom: 46
            }
        );
        let at = |x: i32, y: i32| (y << 16) | (x & 0xFFFF);
        assert_eq!(plain(window as u32, WM_NCHITTEST, 0, at(250, 90)), 2);
        assert_eq!(plain(window as u32, WM_NCHITTEST, 0, at(250, 200)), 1);
        assert_eq!(plain(window as u32, WM_NCHITTEST, 0, at(10, 10)), 0);
    }
}
