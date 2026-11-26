//! Scroll bars: SetScrollInfo and GetScrollInfo, SetScrollPos and GetScrollPos, SetScrollRange and
//! GetScrollRange, ShowScrollBar, EnableScrollBar, ScrollWindowEx and ScrollWindow; and the
//! ScrollBar control ([`scroll_bar_proc_w`], [`scroll_bar_proc_a`]), the class user32 registers in
//! every process ([`crate::class::register_system_classes`]).
//!
//! A window's own bars (SB_HORZ, SB_VERT) are win32k's: their changes go through its services
//! ([`imports`]: NtUserSetScrollInfo, NtUserShowScrollBar, NtUserEnableScrollBar), and the reads
//! through NtUserQueryWindow's QUERY_WINDOW_SCROLL_BARS, as Windows 2000's user32 reads the
//! window's SBINFO from the desktop's heap. The rules are rtl::scroll's (see the kernel's scroll
//! notes). The bars are drawn here, in the window's non-client area ([`draw_window_bars`]): by the
//! default procedure's WM_NCPAINT, and again after a call that changed them asks a redraw.
//!
//! SB_CTL names a ScrollBar control, whose bar is its own: each call sends the control its SBM_*
//! message, as Windows 2000's does (SetScrollInfo's redraw asked only of a visible control), and
//! answers as the scroll capture shows: GetScrollInfo, GetScrollRange and ShowScrollBar answer TRUE
//! whatever the window answered (a window that is no ScrollBar leaves the caller's structure as it
//! was), SetScrollRange TRUE once its range passes, SetScrollPos and SetScrollInfo the control's
//! answer.
//!
//! The errors are the capture's: a handle naming no window is 1400; a bar there is none of 87; a
//! window's bar read from a window with none ERROR_NO_SCROLLBARS (GetScrollRange answering TRUE
//! with a range of 0 to 0 even so); SetScrollRange of a range wider than MAXLONG
//! ERROR_INVALID_SCROLLBAR_RANGE; GetScrollInfo of a SCROLLINFO whose cbSize is neither of its
//! sizes, or whose mask names nothing, answers FALSE with no error.
//!
//! The control ([`scroll_bar`]) keeps its bar and its disabled arrows in its extra bytes
//! ([`SCROLLBAR_EXTRA`], F2K's layout of Windows 2000's SBWND): a vertical bar with SBS_VERT, a
//! horizontal one without, made with a range of 0 to 0. Its SBM_SETSCROLLINFO, SBM_SETPOS and
//! SBM_SETRANGE set it by the rules a window's bar follows (SBM_SETPOS and SBM_SETRANGE answering
//! the old position); a set asked to redraw takes the caret off the control and puts it back (the
//! control's own, when it has the focus: Windows 2000's ShowCaret and HideCaret, which leave
//! ERROR_ACCESS_DENIED on a thread with no caret, as the capture's sets do) and, when the control
//! is visible, enables it, or disables it as a window for a bar with nothing to scroll and
//! SIF_DISABLENOSCROLL ([`enable_control`]), then draws it. A control never hides itself. Its
//! WM_ENABLE enables or disables both its arrows.
//!
//! Neither the window's bars nor the control track the mouse or the keyboard yet: a click or a key
//! on the control is logged once, and nothing sends WM_HSCROLL or WM_VSCROLL. ScrollWindowEx's
//! hrgnUpdate is not filled (F2K's gdi32 has no region objects yet): it is logged once.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::edge::{In, InBuf, Out, OutBuf};
use rtl::gdi::Rect;
use rtl::nonclient::Frame;
use rtl::pod::Pod;
use rtl::scroll::*;
use rtl::user::{
    WM_ENABLE,
    WM_ERASEBKGND,
    WM_KEYDOWN,
    WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN,
    WM_PAINT,
    WS_DISABLED,
};
use rtl::window::{QUERY_WINDOW_EXTRA, QUERY_WINDOW_SCROLL_BARS};
use rtl::winerror::ERROR_INVALID_SCROLLBAR_RANGE;

use crate::draw::{self, BF_MIDDLE, BF_RECT, EDGE_RAISED};
use crate::{answered, failed, imports, message, paint, spec, window, ERROR_INVALID_PARAMETER};

/// A ScrollBar control's extra bytes: its disabled arrows, then its bar (min, max, page, pos).
pub const SCROLLBAR_EXTRA: i32 = 20;
const FLAGS: i32 = 0;
const MIN: i32 = 4;
const MAX: i32 = 8;
const PAGE: i32 = 12;
const POS: i32 = 16;

/// The ScrollBar class's atom in this process, once registered (0 before).
pub static SCROLLBAR_ATOM: AtomicU32 = AtomicU32::new(0);

/// The system colors a bar is drawn in (winuser.h's COLOR_*).
const COLOR_SCROLLBAR: u32 = 0;
const COLOR_BTNTEXT: u32 = 18;
const COLOR_3DFACE: u32 = 15;
const COLOR_3DSHADOW: u32 = 16;
const COLOR_3DHILIGHT: u32 = 20;

/// ShowWindow's commands ShowScrollBar gives a control.
const SW_HIDE: i32 = 0;
const SW_SHOWNORMAL: i32 = 1;

/// The cases logged in this process: the control's input, ScrollWindowEx's region.
static LOGGED: rtl::stub::Logged<4> = rtl::stub::Logged::new();

/// The control's procedure, as its log lines name it.
const SCROLLBAR_PROC: rtl::stub::Entry = crate::stub::procedure("ScrollBarWndProc");

// --- The caller's SCROLLINFO ---------------------------------------------------------------------

/// The first `size` bytes of the caller's SCROLLINFO at `at` (24 or 28), the rest zero.
///
/// # Safety
///
/// `at` is the caller's structure, `size` bytes of it readable.
unsafe fn read_info(at: *const ScrollInfo, size: usize) -> ScrollInfo {
    let mut info = ScrollInfo::default();
    // SAFETY: the caller's contract.
    unsafe { InBuf::new(at as *const u8, size) }.copy_to(&mut info.as_bytes_mut()[..size]);
    info
}

/// The first `size` bytes of `info` written into the caller's SCROLLINFO at `at`.
///
/// # Safety
///
/// `at` is the caller's structure, `size` bytes of it writable.
unsafe fn write_info(at: *mut ScrollInfo, info: &ScrollInfo, size: usize) {
    // SAFETY: the caller's contract.
    unsafe { OutBuf::new(at as *mut u8, size) }.put(&info.as_bytes()[..size]);
}

/// The size of the caller's SCROLLINFO its cbSize gives (24 or 28); none for another.
fn info_size(cb_size: u32) -> Option<usize> {
    match cb_size {
        SCROLLINFO_SIZE | SCROLLINFO_SIZE_V1 => Some(cb_size as usize),
        _ => None,
    }
}

/// Whether `window` names a window; 1400 made the last error when not.
fn valid(window: usize) -> bool {
    answered(window::window_info(window)).is_some()
}

/// The window's own bars; ERROR_NO_SCROLLBARS (as a status) for a window with none.
pub fn window_bars(window: usize) -> Result<ScrollBars, rtl::status::NtStatus> {
    let mut bars = ScrollBars::default();
    imports::query_window(window, QUERY_WINDOW_SCROLL_BARS, &mut bars)?;
    Ok(bars)
}

// --- The exports ---------------------------------------------------------------------------------

/// GetScrollInfo: the members the caller's SCROLLINFO's mask names, of the bar `bar` names; see
/// the module notes.
///
/// # Safety
///
/// The caller's SCROLLINFO, as for the platform's.
#[unsafe(export_name = "f2k_export_GetScrollInfo")]
pub unsafe extern "system" fn get_scroll_info(
    window: usize,
    bar: i32,
    info: *mut ScrollInfo,
) -> u32 {
    // SAFETY: the caller's structure, its size read first.
    let Some(size) = info_size(unsafe { In::new(info as *const u32) }.read()) else {
        return 0;
    };
    if !valid(window) {
        return 0;
    }
    match bar {
        SB_CTL => {
            let _ = message::send(window, SBM_GETSCROLLINFO, 0, info as usize as i32);
            1
        }
        SB_HORZ | SB_VERT => {
            let Some(bars) = answered(window_bars(window)) else {
                return 0;
            };
            // SAFETY: the caller's structure, `size` bytes of it.
            let mut local = unsafe { read_info(info, size) };
            if !get_parms(bars.bar(bar), &mut local) {
                return 0;
            }
            // SAFETY: as above.
            unsafe { write_info(info, &local, size) };
            1
        }
        _ => failed::<()>(ERROR_INVALID_PARAMETER).is_some() as u32,
    }
}

/// SetScrollInfo: the caller's SCROLLINFO set on the bar `bar` names, redrawn with `redraw`; the
/// position after (see the module notes). Its cbSize is not checked, as Windows 2000's is not.
///
/// # Safety
///
/// The caller's SCROLLINFO, as for the platform's.
#[unsafe(export_name = "f2k_export_SetScrollInfo")]
pub unsafe extern "system" fn set_scroll_info(
    window: usize,
    bar: i32,
    info: *const ScrollInfo,
    redraw: u32,
) -> i32 {
    // SAFETY: the caller's structure, read without its nTrackPos (which a set never reads).
    let info = unsafe { read_info(info, SCROLLINFO_SIZE_V1 as usize) };
    set_info(window, bar, info, redraw != 0)
}

/// SetScrollInfo's work, over a copy of the caller's structure: a control's sent
/// SBM_SETSCROLLINFO (its redraw asked only when it is visible), a window's bar set by win32k and
/// redrawn when asked.
fn set_info(window: usize, bar: i32, mut info: ScrollInfo, redraw: bool) -> i32 {
    if bar == SB_CTL {
        if !valid(window) {
            return 0;
        }
        let redraw = redraw && window::is_window_visible(window) != 0;
        return message::send(
            window,
            SBM_SETSCROLLINFO,
            redraw as u32,
            &mut info as *mut ScrollInfo as usize as i32,
        )
        .unwrap_or(0);
    }
    let Some(answer) = answered(imports::set_scroll_info(window, bar, &info, redraw)) else {
        return 0;
    };
    if redraw {
        draw_window_bars(window);
    }
    answer
}

/// SetScrollPos: the bar's position set (clamped as SetScrollInfo's), redrawn with `redraw`; the
/// position before.
#[unsafe(export_name = "f2k_export_SetScrollPos")]
pub extern "system" fn set_scroll_pos(window: usize, bar: i32, pos: i32, redraw: u32) -> i32 {
    let info = ScrollInfo {
        cb_size: SCROLLINFO_SIZE,
        mask: SIF_POS | SIF_RETURNOLDPOS,
        pos,
        ..ScrollInfo::default()
    };
    set_info(window, bar, info, redraw != 0)
}

/// SetScrollRange: the bar's range set (the page kept, the position clamped), redrawn with
/// `redraw`; TRUE, FALSE with ERROR_INVALID_SCROLLBAR_RANGE for a range wider than MAXLONG (an
/// inverted one included).
#[unsafe(export_name = "f2k_export_SetScrollRange")]
pub extern "system" fn set_scroll_range(
    window: usize,
    bar: i32,
    min: i32,
    max: i32,
    redraw: u32,
) -> u32 {
    if (max as u32).wrapping_sub(min as u32) > i32::MAX as u32 {
        return failed::<()>(ERROR_INVALID_SCROLLBAR_RANGE).is_some() as u32;
    }
    let info = ScrollInfo {
        cb_size: SCROLLINFO_SIZE,
        mask: SIF_RANGE,
        min,
        max,
        ..ScrollInfo::default()
    };
    set_info(window, bar, info, redraw != 0);
    1
}

/// GetScrollPos: the bar's position (a control's SBM_GETPOS answer); 0 with the last error for a
/// window or bar there is none of.
#[unsafe(export_name = "f2k_export_GetScrollPos")]
pub extern "system" fn get_scroll_pos(window: usize, bar: i32) -> i32 {
    if !valid(window) {
        return 0;
    }
    match bar {
        SB_CTL => message::send(window, SBM_GETPOS, 0, 0).unwrap_or(0),
        SB_HORZ | SB_VERT => answered(window_bars(window)).map_or(0, |bars| bars.bar(bar).pos),
        _ => failed::<()>(ERROR_INVALID_PARAMETER).map_or(0, |()| 0),
    }
}

/// GetScrollRange: the bar's range into the caller's two integers (a control's SBM_GETRANGE
/// writes them); TRUE, a range of 0 to 0 and ERROR_NO_SCROLLBARS for a window with no bars.
///
/// # Safety
///
/// The caller's integers, as for the platform's.
#[unsafe(export_name = "f2k_export_GetScrollRange")]
pub unsafe extern "system" fn get_scroll_range(
    window: usize,
    bar: i32,
    min: *mut i32,
    max: *mut i32,
) -> u32 {
    if !valid(window) {
        return 0;
    }
    let (low, high) = match bar {
        SB_CTL => {
            let _ = message::send(
                window,
                SBM_GETRANGE,
                min as usize as u32,
                max as usize as i32,
            );
            return 1;
        }
        SB_HORZ | SB_VERT => match answered(window_bars(window)) {
            Some(bars) => (bars.bar(bar).min, bars.bar(bar).max),
            None => (0, 0),
        },
        _ => return failed::<()>(ERROR_INVALID_PARAMETER).is_some() as u32,
    };
    // SAFETY: the caller's integers.
    unsafe {
        if let Some(mut min) = Out::optional(min) {
            min.set(low);
        }
        if let Some(mut max) = Out::optional(max) {
            max.set(high);
        }
    }
    1
}

/// ShowScrollBar: a window's bars `bar` shown or hidden (the frame taken again), a control shown
/// or hidden as a window (SB_CTL); TRUE, FALSE with the last error for a window or bar there is
/// none of.
#[unsafe(export_name = "f2k_export_ShowScrollBar")]
pub extern "system" fn show_scroll_bar(window: usize, bar: i32, show: u32) -> u32 {
    if bar == SB_CTL {
        if !valid(window) {
            return 0;
        }
        window::show_window(window, if show != 0 { SW_SHOWNORMAL } else { SW_HIDE });
        return 1;
    }
    let answer = imports::show_scroll_bar(window, bar, show != 0);
    answered(answer).is_some() as u32
}

/// EnableScrollBar: the arrows of a window's bars `bar` enabled or disabled (whether they changed,
/// the bars redrawn when they did), or a control's ([`enable_control`]); FALSE with 1400 for a
/// handle naming no window.
#[unsafe(export_name = "f2k_export_EnableScrollBar")]
pub extern "system" fn enable_scroll_bar(window: usize, bar: u32, arrows: u32) -> u32 {
    if bar as i32 == SB_CTL {
        if !valid(window) {
            return 0;
        }
        return enable_control(window, arrows);
    }
    let Some(changed) = answered(imports::enable_scroll_bar(window, bar as i32, arrows)) else {
        return 0;
    };
    if changed {
        draw_window_bars(window);
    }
    changed as u32
}

/// EnableScrollBar of a control (Windows 2000's xxxEnableScrollBar for SB_CTL,
/// [`control_enable`]): both arrows disabled disables the control as a window, both enabled again
/// enables it, answering whether its state changed as Windows 2000 does — the window's WS_DISABLED
/// as its style's state byte holds it (8) when the window was enabled, TRUE when it is enabled
/// now; one arrow goes through SBM_ENABLE_ARROWS, whose answer is the call's. A window that is no
/// ScrollBar has no arrows disabled.
pub fn enable_control(window: usize, arrows: u32) -> u32 {
    match control_enable(control_flags(window), arrows) {
        ControlEnable::Unchanged => 0,
        ControlEnable::Window(enable) => {
            let was_disabled = crate::focus::enable_window(window, enable as u32) != 0;
            let disabled = window::style_of(window).unwrap_or(0) & WS_DISABLED;
            if was_disabled {
                (disabled == 0) as u32
            } else {
                disabled >> 24
            }
        }
        ControlEnable::Arrows => {
            message::send(window, SBM_ENABLE_ARROWS, arrows, 0).unwrap_or(0) as u32
        }
    }
}

/// ScrollWindowEx: `window`'s client area scrolled by `dx` and `dy` (see the kernel's scroll
/// notes), the uncovered box into the caller's RECT; the uncovered region's complexity, ERROR with
/// 1400 for a handle naming no window.
///
/// # Safety
///
/// The caller's rectangles, as for the platform's.
#[unsafe(export_name = "f2k_export_ScrollWindowEx")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn scroll_window_ex(
    window: usize,
    dx: i32,
    dy: i32,
    scroll: *const Rect,
    clip: *const Rect,
    region: usize,
    update: *mut Rect,
    flags: u32,
) -> i32 {
    let answer = imports::scroll_window_ex(window, dx, dy, scroll as usize, clip as usize, flags);
    let Some((complexity, bounds)) = answered(answer) else {
        return ERROR;
    };
    // SAFETY: the caller's RECT.
    if let Some(mut update) = unsafe { Out::optional(update) } {
        update.set(bounds);
    }
    if region != 0 {
        let args = [
            window as u64,
            dx as u64,
            dy as u64,
            scroll as u64,
            clip as u64,
            region as u64,
            update as u64,
            u64::from(flags),
        ];
        // SAFETY: the arguments as ScrollWindowEx's kinds read them: handles, numbers and
        // pointers, none read as strings.
        unsafe {
            crate::stub::unhandled_once(
                &LOGGED,
                0,
                &spec::ScrollWindowEx,
                "hrgnUpdate is not yet filled: there are no region objects",
                &args,
            )
        };
    }
    complexity
}

/// ScrollWindow: ScrollWindowEx's, invalidating and erasing what it uncovers, the children
/// scrolled along with no scroll rectangle; whether it scrolled.
///
/// # Safety
///
/// The caller's rectangles, as for the platform's.
#[unsafe(export_name = "f2k_export_ScrollWindow")]
pub unsafe extern "system" fn scroll_window(
    window: usize,
    dx: i32,
    dy: i32,
    scroll: *const Rect,
    clip: *const Rect,
) -> u32 {
    let children = if scroll.is_null() {
        SW_SCROLLCHILDREN
    } else {
        0
    };
    let flags = SW_INVALIDATE | SW_ERASE | children;
    // SAFETY: the caller's rectangles, handed on.
    let answer = unsafe {
        scroll_window_ex(
            window,
            dx,
            dy,
            scroll,
            clip,
            0,
            core::ptr::null_mut(),
            flags,
        )
    };
    (answer != ERROR) as u32
}

// --- Drawing -------------------------------------------------------------------------------------

/// A system color's brush (its index plus one).
fn color(index: u32) -> usize {
    index as usize + 1
}

/// The bar of parameters `data` drawn into `dc` at `rect`, `vertical` or not, its arrows
/// `disabled` (ESB_DISABLE_LTUP, ESB_DISABLE_RTDN) or the whole bar `inactive`: an arrow button
/// at each end, the track between them and the thumb on it ([`Layout`]).
pub fn draw_bar(
    dc: usize,
    rect: Rect,
    vertical: bool,
    data: &ScrollData,
    disabled: u32,
    inactive: bool,
) {
    let disabled = if inactive { ESB_DISABLE_BOTH } else { disabled };
    let layout = Layout::of(rect, vertical, data, disabled != ESB_DISABLE_BOTH);
    draw::fill(dc, layout.track, color(COLOR_SCROLLBAR));
    let (start, end) = if vertical {
        (Arrow::Up, Arrow::Down)
    } else {
        (Arrow::Left, Arrow::Right)
    };
    draw_arrow(dc, layout.start, start, disabled & ESB_DISABLE_LTUP != 0);
    draw_arrow(dc, layout.end, end, disabled & ESB_DISABLE_RTDN != 0);
    if let Some(thumb) = layout.thumb {
        draw::draw_edge_in(dc, thumb, EDGE_RAISED, BF_RECT | BF_MIDDLE);
    }
}

/// Which way an arrow points.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arrow {
    Up,
    Down,
    Left,
    Right,
}

/// An arrow button: a raised face with the arrow's triangle in its middle, grayed (embossed) when
/// `disabled`.
fn draw_arrow(dc: usize, rect: Rect, arrow: Arrow, disabled: bool) {
    if rect.is_empty() {
        return;
    }
    let (inner, _) = draw::draw_edge_in(dc, rect, EDGE_RAISED, BF_RECT | BF_MIDDLE);
    // A triangle of `size` rows, the widest 2 * size - 1 pixels, centred in the face.
    let size = (inner.width().min(inner.height()) / 3).max(1);
    let cx = inner.left + inner.width() / 2;
    let cy = inner.top + inner.height() / 2;
    let triangle = |dc: usize, dx: i32, dy: i32, brush: usize| {
        let lead = size / 2;
        for row in 0..size {
            // The row's distance from the point, and the row's half-width.
            let (along, half) = (row - lead, row);
            let rect = match arrow {
                Arrow::Up => Rect::new(cx - half, cy + along, cx + half + 1, cy + along + 1),
                Arrow::Down => Rect::new(cx - half, cy - along, cx + half + 1, cy - along + 1),
                Arrow::Left => Rect::new(cx + along, cy - half, cx + along + 1, cy + half + 1),
                Arrow::Right => Rect::new(cx - along, cy - half, cx - along + 1, cy + half + 1),
            };
            draw::fill(dc, rect.offset(dx, dy), brush);
        }
    };
    if disabled {
        triangle(dc, 1, 1, color(COLOR_3DHILIGHT));
        triangle(dc, 0, 0, color(COLOR_3DSHADOW));
    } else {
        triangle(dc, 0, 0, color(COLOR_BTNTEXT));
    }
}

/// A window's own bars drawn in its non-client area, as its styles show them, with the square
/// between two bars in the face color, when the window is visible; nothing for a window with no
/// bars shown.
pub fn draw_window_bars(window: usize) {
    if window::is_window_visible(window) == 0 {
        return;
    }
    let Some(framed) = crate::nonclient::Framed::of(window) else {
        return;
    };
    let frame = framed.frame();
    let local = framed.local();
    let (vertical, horizontal) = frame.scroll_bars(local);
    if vertical.is_none() && horizontal.is_none() {
        return;
    }
    let Ok(dc) = imports::get_window_dc(window) else {
        return;
    };
    let dc = dc as usize;
    draw_frame_bars(dc, window, &frame, local);
    let _ = imports::delete_dc(dc);
}

/// The bars of `frame` (a window's, at `local`) drawn into `dc`, a DC of the whole window.
pub fn draw_frame_bars(dc: usize, window: usize, frame: &Frame, local: Rect) {
    let (vertical, horizontal) = frame.scroll_bars(local);
    let bars = window_bars(window).unwrap_or(ScrollBars::WINDOW);
    let inactive = window::style_of(window).unwrap_or(0) & WS_DISABLED != 0;
    if let Some(rect) = vertical {
        draw_bar(dc, rect, true, &bars.vert, bars.disabled(SB_VERT), inactive);
    }
    if let Some(rect) = horizontal {
        draw_bar(
            dc,
            rect,
            false,
            &bars.horz,
            bars.disabled(SB_HORZ),
            inactive,
        );
    }
    if let (Some(vertical), Some(horizontal)) = (vertical, horizontal) {
        let corner = Rect::new(
            vertical.left,
            horizontal.top,
            vertical.right,
            horizontal.bottom,
        );
        draw::fill(dc, corner, color(COLOR_3DFACE));
    }
}

// --- The ScrollBar control -----------------------------------------------------------------------

fn read(window: usize, offset: i32) -> u32 {
    let mut value = 0u32;
    let _ = imports::query_window(window, QUERY_WINDOW_EXTRA | offset as u32, &mut value);
    value
}

fn write(window: usize, offset: i32, value: u32) {
    let _ = imports::set_window_long(window, offset, value, false);
}

/// Whether `window` is a ScrollBar control: a window of user32's ScrollBar class.
fn is_scroll_bar(window: usize) -> bool {
    let atom = SCROLLBAR_ATOM.load(Ordering::Relaxed);
    atom != 0
        && window::window_info(window).is_ok_and(|info| u32::from(info.atom_window_type) == atom)
}

/// The control's disabled arrows; none for a window that is no ScrollBar.
fn control_flags(window: usize) -> u32 {
    if is_scroll_bar(window) {
        read(window, FLAGS)
    } else {
        0
    }
}

/// The control's bar.
fn control_data(window: usize) -> ScrollData {
    ScrollData {
        min: read(window, MIN) as i32,
        max: read(window, MAX) as i32,
        page: read(window, PAGE) as i32,
        pos: read(window, POS) as i32,
    }
}

/// The control's bar stored, what changed of it.
fn store_data(window: usize, old: &ScrollData, data: &ScrollData) {
    for (offset, before, after) in [
        (MIN, old.min, data.min),
        (MAX, old.max, data.max),
        (PAGE, old.page, data.page),
        (POS, old.pos, data.pos),
    ] {
        if before != after {
            write(window, offset, after as u32);
        }
    }
}

/// SBM_ENABLE_ARROWS (Windows 2000's xxxEnableSBCtlArrows): the control's arrows enabled or
/// disabled, the control redrawn when they changed; whether they did.
fn enable_arrows_message(window: usize, arrows: u32) -> bool {
    let (flags, changed) = control_arrows(read(window, FLAGS), arrows);
    if changed {
        write(window, FLAGS, flags);
        if window::is_window_visible(window) != 0 {
            let _ = imports::invalidate_rect(window, 0, true);
        }
    }
    changed
}

/// The control's set (SBM_SETSCROLLINFO, SBM_SETPOS, SBM_SETRANGE, SBM_SETRANGEREDRAW): `info`
/// set on its bar, redrawn with `redraw` (see the module notes); the set's answer.
fn set_control(window: usize, info: &ScrollInfo, redraw: bool) -> i32 {
    let old = control_data(window);
    let mut data = old;
    let set = set_parms(&mut data, info);
    store_data(window, &old, &data);
    if !redraw {
        return set.result;
    }
    crate::caret::show_or_hide(window, false);
    if window::is_window_visible(window) != 0 {
        let scrollable = set.scrollable.unwrap_or(true);
        let enable = scrollable || info.mask & SIF_DISABLENOSCROLL == 0;
        enable_control(
            window,
            if enable {
                ESB_ENABLE_BOTH
            } else {
                ESB_DISABLE_BOTH
            },
        );
        if let Ok(dc) = imports::get_dc(window) {
            draw_control(window, dc as usize);
            let _ = imports::delete_dc(dc as usize);
        }
    }
    crate::caret::show_or_hide(window, true);
    set.result
}

/// The control drawn into `dc`, a DC of its client area.
fn draw_control(window: usize, dc: usize) {
    let Some(client) = window::client_rect(window) else {
        return;
    };
    let style = window::style_of(window).unwrap_or(0);
    draw_bar(
        dc,
        client,
        style & SBS_VERT != 0,
        &control_data(window),
        read(window, FLAGS),
        style & WS_DISABLED != 0,
    );
}

/// The control's procedure, for a message of the narrow (`ansi`) or wide form: see the module
/// notes.
pub fn scroll_bar(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        WM_ENABLE => {
            let arrows = if wparam != 0 {
                ESB_ENABLE_BOTH
            } else {
                ESB_DISABLE_BOTH
            };
            enable_arrows_message(window, arrows);
            0
        }
        SBM_ENABLE_ARROWS => enable_arrows_message(window, wparam) as i32,
        SBM_GETPOS => read(window, POS) as i32,
        SBM_GETRANGE => {
            let data = control_data(window);
            // SAFETY: SBM_GETRANGE's parameters: the caller's two integers, either null.
            unsafe {
                if let Some(mut min) = Out::optional(wparam as usize as *mut i32) {
                    min.set(data.min);
                }
                if let Some(mut max) = Out::optional(lparam as usize as *mut i32) {
                    max.set(data.max);
                }
            }
            ((data.max as u32) << 16 | (data.min as u32 & 0xFFFF)) as i32
        }
        SBM_SETPOS => {
            let info = ScrollInfo {
                cb_size: SCROLLINFO_SIZE,
                mask: SIF_POS | SIF_RETURNOLDPOS,
                pos: wparam as i32,
                ..ScrollInfo::default()
            };
            set_control(window, &info, lparam != 0)
        }
        SBM_SETRANGE | SBM_SETRANGEREDRAW => {
            let info = ScrollInfo {
                cb_size: SCROLLINFO_SIZE,
                mask: SIF_RANGE | SIF_RETURNOLDPOS,
                min: wparam as i32,
                max: lparam,
                ..ScrollInfo::default()
            };
            set_control(window, &info, message == SBM_SETRANGEREDRAW)
        }
        SBM_SETSCROLLINFO => {
            if lparam == 0 {
                return 0;
            }
            // SAFETY: SBM_SETSCROLLINFO's lParam: the sender's SCROLLINFO, read without its
            // nTrackPos.
            let info = unsafe {
                read_info(
                    lparam as usize as *const ScrollInfo,
                    SCROLLINFO_SIZE_V1 as usize,
                )
            };
            set_control(window, &info, wparam != 0)
        }
        SBM_GETSCROLLINFO => {
            if lparam == 0 {
                return 0;
            }
            let at = lparam as usize as *mut ScrollInfo;
            // SAFETY: SBM_GETSCROLLINFO's lParam: the sender's SCROLLINFO, its size read first.
            let size = info_size(unsafe { In::new(at as *const u32) }.read())
                .unwrap_or(SCROLLINFO_SIZE as usize);
            // SAFETY: as above, `size` bytes of it.
            let mut local = unsafe { read_info(at, size) };
            let answer = get_parms(&control_data(window), &mut local);
            // SAFETY: as above.
            unsafe { write_info(at, &local, size) };
            answer as i32
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            if let Some(painting) = paint::Painting::begin(window) {
                draw_control(window, painting.dc());
            }
            0
        }
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK | WM_KEYDOWN => {
            crate::stub::message_once(
                &LOGGED,
                1,
                &SCROLLBAR_PROC,
                "a scroll bar's mouse and keyboard tracking (WM_HSCROLL, WM_VSCROLL to its \
                 parent) is not yet implemented",
                (window, message, wparam, lparam),
            );
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// ScrollBarWndProcW: the ScrollBar class's procedure for a wide message.
pub extern "system" fn scroll_bar_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    scroll_bar(window, message, wparam, lparam, false)
}

/// ScrollBarWndProcA: the ScrollBar class's procedure for a narrow message.
pub extern "system" fn scroll_bar_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    scroll_bar(window, message, wparam, lparam, true)
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WS_HSCROLL, WS_VSCROLL};
    use rtl::winerror::ERROR_NO_SCROLLBARS;

    use super::*;
    use crate::class::SYSTEM_CLASSES_WANTED;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xDEAD));
    }

    /// A window of user32's class `class`, `style`, 200x150.
    fn window_of(class: &str, style: u32) -> usize {
        SYSTEM_CLASSES_WANTED.with(|wanted| wanted.set(true));
        let class = wide(&format!("{class}\0"));
        let window = crate::window::create_window_ex_w(
            0,
            class.as_ptr(),
            core::ptr::null(),
            style,
            40,
            40,
            200,
            150,
            0,
            0,
            0,
            0,
        );
        assert_ne!(window, 0);
        window
    }

    fn info(mask: u32) -> ScrollInfo {
        ScrollInfo {
            cb_size: SCROLLINFO_SIZE,
            mask,
            min: -7,
            max: -7,
            page: 7,
            pos: -7,
            track_pos: -7,
        }
    }

    fn get(window: usize, bar: i32, info: &mut ScrollInfo) -> u32 {
        // SAFETY: a local structure.
        unsafe { get_scroll_info(window, bar, info) }
    }

    fn set(window: usize, bar: i32, info: &ScrollInfo) -> i32 {
        // SAFETY: a local structure.
        unsafe { set_scroll_info(window, bar, info, 0) }
    }

    /// GetScrollInfo: a cbSize of neither size and a mask naming nothing answer FALSE with no
    /// error; a bar there is none of is 87, no window 1400, a window with no bars 1447; a window
    /// made with bars reads 0 to 100.
    ///
    /// Pins: user32.GetScrollInfo
    #[test]
    fn get_scroll_info_checks_its_arguments() {
        let barred = window_of("Static", WS_VSCROLL | WS_HSCROLL);
        let mut out = ScrollInfo {
            cb_size: 0,
            ..info(SIF_ALL)
        };
        arm();
        assert_eq!(get(barred, SB_VERT, &mut out), 0);
        assert_eq!((last_error(), out.min), (0xDEAD, -7));
        let mut out = info(SIF_ALL);
        assert_eq!(get(barred, SB_VERT, &mut out), 1);
        assert_eq!(
            (out.min, out.max, out.page, out.pos, out.track_pos),
            (0, 100, 0, 0, 0)
        );
        let mut out = info(0);
        assert_eq!(get(barred, SB_HORZ, &mut out), 0);
        assert_eq!((last_error(), out.min), (0xDEAD, -7));
        let mut out = info(SIF_ALL);
        assert_eq!(get(barred, SB_BOTH, &mut out), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(get(0, SB_VERT, &mut out), 0);
        assert_eq!(last_error(), 1400);
        let plain = window_of("Static", 0);
        assert_eq!(get(plain, SB_VERT, &mut out), 0);
        assert_eq!(last_error(), ERROR_NO_SCROLLBARS);
        assert_eq!(out.min, -7);
    }

    /// SetScrollInfo, SetScrollPos and SetScrollRange on a window's bar: the clamped position,
    /// SetScrollPos's old one, SetScrollRange's MAXLONG check; GetScrollRange of a window with no
    /// bars answers TRUE and 0 to 0 with ERROR_NO_SCROLLBARS.
    ///
    /// Pins: user32.SetScrollInfo, user32.SetScrollPos, user32.SetScrollRange,
    /// user32.GetScrollPos, user32.GetScrollRange
    #[test]
    fn a_windows_bar_set_and_read() {
        let w = window_of("Static", WS_VSCROLL | WS_HSCROLL);
        let all = ScrollInfo {
            min: 0,
            max: 99,
            page: 10,
            pos: 95,
            ..info(SIF_ALL)
        };
        assert_eq!(set(w, SB_VERT, &all), 90);
        assert_eq!(set_scroll_pos(w, SB_VERT, 20, 0), 90);
        assert_eq!(get_scroll_pos(w, SB_VERT), 20);
        arm();
        assert_eq!(set_scroll_range(w, SB_VERT, 10, 5, 0), 0);
        assert_eq!(last_error(), ERROR_INVALID_SCROLLBAR_RANGE);
        assert_eq!(set_scroll_range(w, SB_VERT, -1, i32::MAX, 0), 0);
        assert_eq!(set_scroll_range(w, SB_VERT, 0, i32::MAX, 0), 1);
        let (mut low, mut high) = (-7, -7);
        // SAFETY: two locals.
        assert_eq!(
            unsafe { get_scroll_range(w, SB_VERT, &mut low, &mut high) },
            1
        );
        assert_eq!((low, high), (0, i32::MAX));
        let plain = window_of("Static", 0);
        arm();
        // SAFETY: as above.
        assert_eq!(
            unsafe { get_scroll_range(plain, SB_VERT, &mut low, &mut high) },
            1
        );
        assert_eq!((low, high, last_error()), (0, 0, ERROR_NO_SCROLLBARS));
        assert_eq!(get_scroll_pos(plain, SB_VERT), 0);
        assert_eq!(set_scroll_pos(plain, SB_VERT, 5, 0), 0);
        assert_eq!(last_error(), ERROR_NO_SCROLLBARS);
        assert_eq!(get_scroll_pos(w, 7), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// The ScrollBar control's messages: made with a range of 0 to 0; SBM_SETRANGE and SBM_SETPOS
    /// answer the old position, the new one clamped; SBM_GETRANGE answers MAKELONG(min, max);
    /// GetScrollPos and GetScrollRange of SB_CTL ask the control.
    ///
    /// Pins: user32.SendMessageW, user32.GetScrollPos, user32.GetScrollRange
    #[test]
    fn the_controls_messages() {
        let c = window_of("ScrollBar", 0);
        assert!(is_scroll_bar(c));
        assert_eq!(control_data(c), ScrollData::CONTROL);
        assert_eq!(message::send(c, SBM_SETRANGE, 5, 25), Some(0));
        assert_eq!(message::send(c, SBM_GETRANGE, 0, 0), Some(0x0019_0005));
        assert_eq!(message::send(c, SBM_SETPOS, 30, 0), Some(5));
        assert_eq!(message::send(c, SBM_GETPOS, 0, 0), Some(25));
        assert_eq!(message::send(c, SBM_SETPOS, 10, 0), Some(25));
        assert_eq!(get_scroll_pos(c, SB_CTL), 10);
        assert_eq!(get_scroll_pos(c, SB_VERT), 0);
        assert_eq!(last_error(), ERROR_NO_SCROLLBARS);
        // A window that is no ScrollBar answers SB_CTL's messages as the default does.
        let plain = window_of("Static", 0);
        assert!(!is_scroll_bar(plain));
        assert_eq!(get_scroll_pos(plain, SB_CTL), 0);
    }

    /// EnableScrollBar of a control: both arrows disable it as a window (WS_DISABLED's state byte,
    /// 8, answered), again nothing; both enabled enable it (TRUE); one arrow is the arrows'
    /// message; SBM_ENABLE_ARROWS answers whether they changed. A window that is no ScrollBar is
    /// disabled as one with its arrows enabled.
    ///
    /// Pins: user32.EnableScrollBar
    #[test]
    fn enable_scroll_bar_on_a_control() {
        let c = window_of("ScrollBar", SBS_VERT);
        assert_eq!(enable_scroll_bar(c, SB_CTL as u32, ESB_DISABLE_BOTH), 8);
        assert_eq!(crate::focus::is_window_enabled(c), 0);
        assert_eq!(
            read(c, FLAGS),
            ESB_DISABLE_BOTH,
            "WM_ENABLE took the arrows"
        );
        assert_eq!(enable_scroll_bar(c, SB_CTL as u32, ESB_DISABLE_BOTH), 0);
        assert_eq!(enable_scroll_bar(c, SB_CTL as u32, ESB_ENABLE_BOTH), 1);
        assert_eq!(crate::focus::is_window_enabled(c), 1);
        assert_eq!(enable_scroll_bar(c, SB_CTL as u32, ESB_DISABLE_LTUP), 1);
        assert_eq!(crate::focus::is_window_enabled(c), 1);
        assert_eq!(
            message::send(c, SBM_ENABLE_ARROWS, ESB_ENABLE_BOTH, 0),
            Some(1)
        );
        assert_eq!(
            message::send(c, SBM_ENABLE_ARROWS, ESB_ENABLE_BOTH, 0),
            Some(0)
        );
        let plain = window_of("Static", 0);
        assert_eq!(enable_scroll_bar(plain, SB_CTL as u32, ESB_DISABLE_BOTH), 8);
        assert_eq!(enable_scroll_bar(0, SB_VERT as u32, ESB_DISABLE_BOTH), 0);
        assert_eq!(last_error(), 1400);
    }
}
