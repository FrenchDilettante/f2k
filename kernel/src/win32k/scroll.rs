//! Scroll bars: a window's own bars (WS_HSCROLL and WS_VSCROLL, drawn in its non-client area),
//! their parameters and arrows, and ScrollWindowEx; the services user32's scroll calls come
//! through.
//!
//! A window's bars are Windows 2000's SBINFO ([`rtl::scroll::ScrollBars`]: the arrows' disabled
//! bits, the horizontal bar, the vertical one), which Windows 2000 allocates with a window made
//! with either style, or when a call first gives it a bar, and keeps for the window's life
//! (pwnd->pSBInfo). F2K keeps every window's in one table ([`WindowBars`]), each entry naming its
//! window by id, as the properties' table does ([`super::prop`]): a window made with WS_HSCROLL
//! or WS_VSCROLL that has no entry yet has a window's bars as they are made (0 to 100, no page,
//! at 0), its entry made the first time a call changes them; a destroyed window's entry is found
//! by nothing (its id carries the record's generation), and a full table takes such entries back.
//! A window whose style lost both bits before any call reached its bars has none, where Windows
//! 2000's kept the ones its creation made.
//!
//! The rules (Windows 2000's xxxSetScrollBar, xxxShowScrollBar, xxxEnableWndSBArrows and
//! xxxScrollWindowEx, as the scroll capture shows them):
//!
//! - SetScrollInfo sets the bar's parameters ([`rtl::scroll::set_parms`]); a window with no bars
//!   takes them only from a call with SIF_RANGE (ERROR_NO_SCROLLBARS otherwise). A call that
//!   changes nothing (without SIF_DISABLENOSCROLL) answers the position and does nothing else. A
//!   bar that the call leaves with nothing to scroll is hidden (its style bit cleared), one with
//!   something to scroll shown, the frame taken again (SetWindowPos's SWP_FRAMECHANGED, shown
//!   window or not); with SIF_DISABLENOSCROLL a shown bar stays and its arrows are disabled (or
//!   enabled when it has something to scroll), a hidden one stays hidden. A bar's arrows are left
//!   as they are otherwise: a range to scroll does not enable them again.
//! - ShowScrollBar sets or clears the bars' style bits, giving the window bars as it shows one, and
//!   takes the frame again when a bit changed; the bars' parameters stay.
//! - EnableScrollBar sets the arrows' bits ([`rtl::scroll::enable_arrows`]), a window with no bars
//!   given them unless the call enables both arrows (which changes nothing); it answers whether the
//!   bits changed, hidden bar or not.
//! - ScrollWindowEx moves the bits of the window's client area on the screen
//!   ([`rtl::scroll::scroll_area`]: the scroll rectangle moved, kept inside the clip rectangle),
//!   offsets the children the scroll rectangle reaches with SW_SCROLLCHILDREN (all of them with
//!   none), and with SW_INVALIDATE adds what it uncovered to the update region (SW_ERASE asking it
//!   erased); it answers the uncovered region's complexity and box. A hidden window scrolls
//!   nothing: NULLREGION and an empty box.
//!
//! The bars are drawn by user32 (the default procedure's WM_NCPAINT, and the calls that redraw
//! them), which reads them through NtUserQueryWindow ([`rtl::window::QUERY_WINDOW_SCROLL_BARS`]),
//! as Windows 2000's user32 reads pwnd->pSBInfo from the desktop's heap mapped into its process.
//! The ScrollBar control's bar is user32's own (its window's extra bytes): SB_CTL never reaches
//! these services. ScrollWindowEx's region (hrgnUpdate) is not filled here: F2K's GDI has no
//! region objects yet.
//!
//! The services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserSetScrollInfo (0x1202)(handle Window, i32 Bar, ptr Info, bool Redraw, ptr<u32> Result):
//!   the SCROLLINFO set, the answer into `Result`;
//! - NtUserShowScrollBar (0x1217)(handle Window, i32 Bar, bool Show);
//! - NtUserEnableScrollBar (0x1165)(handle Window, u32 Bar, u32 Arrows, ptr<u32> Result): whether
//!   the arrows changed into `Result`;
//! - NtUserScrollWindowEx (0x11DF)(handle Window, i32 Dx, i32 Dy, ptr Scroll, ptr Clip, u32 Flags,
//!   ptr Update, ptr<u32> Result): the uncovered box into `Update` (when not null), its complexity
//!   into `Result`.

use rtl::gdi::Rect;
use rtl::scroll::{
    enable_arrows,
    scroll_area,
    set_parms,
    ScrollArea,
    ScrollBars,
    ScrollInfo,
    ESB_DISABLE_BOTH,
    ESB_ENABLE_BOTH,
    SB_BOTH,
    SB_HORZ,
    SB_VERT,
    SIF_DISABLENOSCROLL,
    SIF_RANGE,
    SW_ERASE,
    SW_INVALIDATE,
    SW_SCROLLCHILDREN,
};
use rtl::user::{WS_HSCROLL, WS_VSCROLL};
use rtl::winerror::{
    ERROR_INVALID_PARAMETER,
    ERROR_INVALID_WINDOW_HANDLE,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_NO_SCROLLBARS,
};

use super::window::{Hwnd, WindowId, Windows, WINDOWS};
use crate::status::*;

/// Why a scroll bar call failed: the Win32 error code (winerror.h) the decision reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// ERROR_NOT_ENOUGH_MEMORY (8): the table is full of live windows' bars.
    NoMemory,
    /// ERROR_INVALID_PARAMETER (87): a bar there is none of.
    InvalidParameter,
    /// ERROR_INVALID_WINDOW_HANDLE (1400): the handle names no live window.
    InvalidWindowHandle,
    /// ERROR_NO_SCROLLBARS (1447): the window has no bars to read or set.
    NoScrollBars,
}

impl Failure {
    /// The Win32 error code the decision reports.
    pub const fn code(self) -> u32 {
        match self {
            Failure::NoMemory => ERROR_NOT_ENOUGH_MEMORY,
            Failure::InvalidParameter => ERROR_INVALID_PARAMETER,
            Failure::InvalidWindowHandle => ERROR_INVALID_WINDOW_HANDLE,
            Failure::NoScrollBars => ERROR_NO_SCROLLBARS,
        }
    }

    /// The NTSTATUS the service answers: the Win32 error itself in a FACILITY_NTWIN32 status
    /// (see [`super::window::Failure::status`]).
    pub const fn status(self) -> NtStatus {
        NtStatus::from_win32(self.code())
    }
}

/// One window's bars: its window and its SBINFO.
#[derive(Clone, Copy)]
struct Entry {
    /// The window the bars are; none for a free entry.
    window: Option<WindowId>,
    bars: ScrollBars,
}

impl Entry {
    const FREE: Self = Entry {
        window: None,
        bars: ScrollBars::WINDOW,
    };
}

/// The windows' bars, every window's in one table (see the module notes).
pub struct WindowBars {
    entries: [Entry; WINDOWS],
}

impl WindowBars {
    /// Write an empty table at `bars`, entry by entry (by value it would pass through the stack).
    ///
    /// # Safety
    ///
    /// `bars` is valid for writes, aligned, and the table's final address; its previous contents
    /// are overwritten, not dropped.
    pub unsafe fn write_empty(bars: *mut WindowBars) {
        // SAFETY: the caller's contract; every entry is written.
        unsafe {
            let entries = core::ptr::addr_of_mut!((*bars).entries) as *mut Entry;
            for index in 0..WINDOWS {
                entries.add(index).write(Entry::FREE);
            }
        }
    }

    fn find(&self, window: WindowId) -> Option<usize> {
        self.entries.iter().position(|e| e.window == Some(window))
    }

    /// The bars of `window` (whose style is `style`): its entry's, a window's bars as made when it
    /// has none but its style asks for a bar; none otherwise.
    pub fn bars(&self, window: WindowId, style: u32) -> Option<ScrollBars> {
        match self.find(window) {
            Some(at) => Some(self.entries[at].bars),
            None if style & (WS_HSCROLL | WS_VSCROLL) != 0 => Some(ScrollBars::WINDOW),
            None => None,
        }
    }

    /// Whether `window` has bars (see [`WindowBars::bars`]).
    pub fn has(&self, window: WindowId, style: u32) -> bool {
        self.bars(window, style).is_some()
    }

    /// The entry of `window`, made with a window's bars as made when it has none; a full table
    /// first takes back the entries of the windows `is_live` says are gone, NoMemory when it is
    /// still full.
    pub fn make(
        &mut self,
        window: WindowId,
        is_live: impl Fn(WindowId) -> bool,
    ) -> Result<&mut ScrollBars, Failure> {
        let at = match self.find(window) {
            Some(at) => at,
            None => {
                let free = |entries: &[Entry]| entries.iter().position(|e| e.window.is_none());
                let at = match free(&self.entries) {
                    Some(at) => at,
                    None => {
                        for entry in self.entries.iter_mut() {
                            if entry.window.is_some_and(|w| !is_live(w)) {
                                *entry = Entry::FREE;
                            }
                        }
                        free(&self.entries).ok_or(Failure::NoMemory)?
                    }
                };
                self.entries[at] = Entry {
                    window: Some(window),
                    bars: ScrollBars::WINDOW,
                };
                at
            }
        };
        Ok(&mut self.entries[at].bars)
    }
}

/// The style bit of the bar `bar` names: WS_HSCROLL for SB_HORZ, WS_VSCROLL for any other.
fn style_bit(bar: i32) -> u32 {
    if bar == SB_HORZ {
        WS_HSCROLL
    } else {
        WS_VSCROLL
    }
}

/// What a decision leaves the service to do: the window's frame to take again
/// (SWP_FRAMECHANGED), its handle.
pub type Reframe = Option<Hwnd>;

/// SetScrollInfo's decision for a window's bar `bar` (SB_HORZ, SB_VERT; SB_BOTH and the rest set
/// the vertical bar, as Windows 2000's): see the module notes. The answer (the position, the old
/// one with SIF_RETURNOLDPOS), and the frame to take again when a bar was shown or hidden.
pub fn set_bar_info(
    windows: &mut Windows,
    table: &mut WindowBars,
    handle: Hwnd,
    bar: i32,
    info: &ScrollInfo,
) -> Result<(i32, Reframe), Failure> {
    let id = windows
        .window_from_handle(handle)
        .ok_or(Failure::InvalidWindowHandle)?;
    let style = windows.window_style(id);
    let bit = style_bit(bar);
    let shown = style & bit != 0;
    if info.mask & SIF_RANGE == 0 && !table.has(id, style) {
        return Err(Failure::NoScrollBars);
    }
    let is_live = |w| windows.is_live(w);
    let bars = table.make(id, is_live)?;
    let set = set_parms(bars.bar_mut(bar), info);
    if !set.changed && info.mask & SIF_DISABLENOSCROLL == 0 {
        return Ok((set.result, None));
    }
    let scrollable = set.scrollable.unwrap_or(shown);
    let bar = if bar == SB_HORZ { SB_HORZ } else { SB_VERT };
    if info.mask & SIF_DISABLENOSCROLL != 0 {
        if shown {
            let arrows = if scrollable {
                ESB_ENABLE_BOTH
            } else {
                ESB_DISABLE_BOTH
            };
            bars.flags = enable_arrows(bars.flags, bar, arrows).0;
        }
        return Ok((set.result, None));
    }
    if scrollable == shown {
        return Ok((set.result, None));
    }
    windows.set_scroll_styles(id, bit, scrollable);
    Ok((set.result, Some(handle)))
}

/// ShowScrollBar's decision for a window's bars `bar` (SB_HORZ, SB_VERT, SB_BOTH; another is
/// InvalidParameter): see the module notes. The frame to take again when a style bit changed.
pub fn show_bars(
    windows: &mut Windows,
    table: &mut WindowBars,
    handle: Hwnd,
    bar: i32,
    show: bool,
) -> Result<Reframe, Failure> {
    let id = windows
        .window_from_handle(handle)
        .ok_or(Failure::InvalidWindowHandle)?;
    let bits = match bar {
        SB_HORZ => WS_HSCROLL,
        SB_VERT => WS_VSCROLL,
        SB_BOTH => WS_HSCROLL | WS_VSCROLL,
        _ => return Err(Failure::InvalidParameter),
    };
    let style = windows.window_style(id);
    let changed = if show {
        // The bars as the style had them, before the style grows them.
        if !table.has(id, style) {
            let is_live = |w| windows.is_live(w);
            table.make(id, is_live)?;
        }
        style & bits != bits
    } else {
        if style & bits != 0 && table.has(id, style) {
            // The bars as the style made them, kept once the style loses them.
            let is_live = |w| windows.is_live(w);
            table.make(id, is_live)?;
        }
        style & bits != 0
    };
    if !changed {
        return Ok(None);
    }
    windows.set_scroll_styles(id, bits, show);
    Ok(Some(handle))
}

/// EnableScrollBar's decision for a window's bars `bar` (SB_HORZ, SB_VERT, SB_BOTH): whether the
/// arrows' bits changed (see the module notes).
pub fn enable_bar_arrows(
    windows: &Windows,
    table: &mut WindowBars,
    handle: Hwnd,
    bar: i32,
    arrows: u32,
) -> Result<bool, Failure> {
    let id = windows
        .window_from_handle(handle)
        .ok_or(Failure::InvalidWindowHandle)?;
    if !table.has(id, windows.window_style(id)) && arrows == ESB_ENABLE_BOTH {
        return Ok(false);
    }
    let is_live = |w| windows.is_live(w);
    let bars = table.make(id, is_live)?;
    let (flags, changed) = enable_arrows(bars.flags, bar, arrows);
    bars.flags = flags;
    Ok(changed)
}

/// The window's bars as NtUserQueryWindow answers them; NoScrollBars for a window with none.
pub fn query_scroll_bars(
    windows: &Windows,
    table: &WindowBars,
    window: WindowId,
) -> Result<ScrollBars, Failure> {
    table
        .bars(window, windows.window_style(window))
        .ok_or(Failure::NoScrollBars)
}

/// ScrollWindowEx's decision, its blit and its children's moves left to the service: the area
/// (client coordinates) and the window's client rectangle on the screen; none for a hidden window,
/// which scrolls nothing. With SW_INVALIDATE the uncovered parts are added to the update region
/// here (SW_ERASE asking them erased).
pub fn scroll_window(
    windows: &mut Windows,
    handle: Hwnd,
    dx: i32,
    dy: i32,
    scroll: Option<Rect>,
    clip: Option<Rect>,
    flags: u32,
) -> Result<Option<(ScrollArea, Rect)>, Failure> {
    let id = windows
        .window_from_handle(handle)
        .ok_or(Failure::InvalidWindowHandle)?;
    if !super::paint::is_shown(windows, id) {
        return Ok(None);
    }
    let client = windows.client_rect(id);
    let local = Rect::new(0, 0, client.width(), client.height());
    let area = scroll_area(local, scroll, clip, dx, dy);
    if flags & SW_INVALIDATE != 0 {
        for part in area.parts() {
            super::paint::invalidate(windows, id, Some(*part), flags & SW_ERASE != 0);
        }
    }
    Ok(Some((area, client)))
}

/// The children of `handle` SW_SCROLLCHILDREN moves: each one's handle and its new place in the
/// window's client coordinates, every child with no scroll rectangle (`scroll` none), else those
/// whose rectangles it reaches. At most `N`; the rest stay.
pub fn children_to_scroll<const N: usize>(
    windows: &Windows,
    handle: Hwnd,
    dx: i32,
    dy: i32,
    scroll: Option<Rect>,
) -> rtl::array_vec::ArrayVec<(Hwnd, i32, i32), N> {
    let mut out = rtl::array_vec::ArrayVec::new();
    let Some(id) = windows.window_from_handle(handle) else {
        return out;
    };
    let client = windows.client_rect(id);
    let reach = scroll.map(|r| r.saturating_offset(client.left, client.top));
    let mut at = windows.first_child(id);
    while let Some(child) = at {
        at = windows.next_sibling(child);
        let rect = windows.window_rect(child);
        if reach.is_some_and(|r| r.intersect(rect).is_empty()) {
            continue;
        }
        let x = rect.left - client.left + dx;
        let y = rect.top - client.top + dy;
        if out.try_push((windows.handle_of(child), x, y)).is_err() {
            break;
        }
    }
    out
}

/// SW_SCROLLCHILDREN's flag test, for the service.
pub fn scrolls_children(flags: u32) -> bool {
    flags & SW_SCROLLCHILDREN != 0
}

// --- The services
// --------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use rtl::scroll::NULLREGION;

    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::blit::{blit, Blit, Source};
    use crate::win32k::queue::{with_manager, with_session};
    use crate::win32k::window::{
        Session,
        SWP_FRAMECHANGED,
        SWP_NOACTIVATE,
        SWP_NOMOVE,
        SWP_NOREDRAW,
        SWP_NOSIZE,
        SWP_NOZORDER,
    };
    use crate::win32k::winsta::gui_thread;

    /// BitBlt's plain copy (wingdi.h's SRCCOPY).
    const SRCCOPY: u32 = 0x00CC_0020;

    /// How many children one ScrollWindowEx moves.
    const CHILDREN: usize = 64;

    /// The frame of `handle` taken again (Windows 2000's xxxRedrawFrame): its WM_NCCALCSIZE and
    /// position messages queued for its thread.
    fn reframe(s: &mut dyn Session, handle: Hwnd) {
        let _ = Windows::set_window_pos_handle(
            s,
            handle,
            0,
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        );
    }

    /// NtUserSetScrollInfo(Window, Bar, Info, Redraw, Result): see [`set_bar_info`]. The
    /// redraw is user32's (it draws the bars).
    pub fn set_scroll_info(
        call: &mut NtCall,
        window: Handle,
        bar: i32,
        info: UserAddr,
        _redraw: bool,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let info = info.cast::<ScrollInfo>().read()?;
        let answer = with_session(call.passive(), |s| {
            let m = s.manager();
            let (answer, reframed) =
                set_bar_info(&mut m.windows, &mut m.scroll_bars, window.raw(), bar, &info)?;
            if let Some(handle) = reframed {
                reframe(s, handle);
            }
            Ok::<_, Failure>(answer)
        })
        .map_err(Failure::status)?;
        result.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserShowScrollBar(Window, Bar, Show): see [`show_bars`].
    pub fn show_scroll_bar(call: &mut NtCall, window: Handle, bar: i32, show: bool) -> NtResult {
        gui_thread(call)?;
        with_session(call.passive(), |s| {
            let m = s.manager();
            let reframed = show_bars(&mut m.windows, &mut m.scroll_bars, window.raw(), bar, show)?;
            if let Some(handle) = reframed {
                reframe(s, handle);
            }
            Ok::<_, Failure>(())
        })
        .map_err(Failure::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserEnableScrollBar(Window, Bar, Arrows, Result): see [`enable_bar_arrows`].
    pub fn enable_scroll_bar(
        call: &mut NtCall,
        window: Handle,
        bar: u32,
        arrows: u32,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let changed = with_manager(call.passive(), |m| {
            enable_bar_arrows(
                &m.windows,
                &mut m.scroll_bars,
                window.raw(),
                bar as i32,
                arrows,
            )
        })
        .map_err(Failure::status)?;
        result.write(changed as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// The rectangle a caller's pointer names; none for a null pointer.
    fn read_rect(rect: UserAddr) -> Result<Option<Rect>, NtStatus> {
        if rect.is_null() {
            return Ok(None);
        }
        Ok(Some(rect.cast::<Rect>().read()?))
    }

    /// The bits of `client` (the window's client area on the screen) the scroll keeps in view
    /// moved by (`dx`, `dy`) to `destination` (client coordinates): a screen-to-screen blit.
    fn move_bits(client: Rect, destination: Rect, dx: i32, dy: i32) {
        if destination.is_empty() {
            return;
        }
        let at = destination.saturating_offset(client.left, client.top);
        let job = Blit {
            x: at.left,
            y: at.top,
            width: at.width(),
            height: at.height(),
            source_x: at.left - dx,
            source_y: at.top - dy,
            source_width: at.width(),
            source_height: at.height(),
            clip: client,
            rop: SRCCOPY,
            mode: 0,
            text: 0,
            background: 0,
            source_background: 0,
        };
        crate::win32k::dc::with_screen(|screen| blit(screen, Source::Same, None, &job));
    }

    /// NtUserScrollWindowEx(Window, Dx, Dy, Scroll, Clip, Flags, Update, Result): see
    /// [`scroll_window`]; the bits moved, then the children, then the uncovered region invalidated.
    #[allow(clippy::too_many_arguments)]
    pub fn scroll_window_ex(
        call: &mut NtCall,
        window: Handle,
        dx: i32,
        dy: i32,
        scroll: UserAddr,
        clip: UserAddr,
        flags: u32,
        update: UserAddr,
        result: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let scroll = read_rect(scroll)?;
        let clip = read_rect(clip)?;
        let (complexity, bounds) = with_session(call.passive(), |s| {
            let m = s.manager();
            let handle = window.raw();
            // The bits move first, while the update region is still the one they had.
            if let Some(id) = m.windows.window_from_handle(handle) {
                if crate::win32k::paint::is_shown(&m.windows, id) {
                    let client = m.windows.client_rect(id);
                    let local = Rect::new(0, 0, client.width(), client.height());
                    let area = scroll_area(local, scroll, clip, dx, dy);
                    move_bits(client, area.destination, dx, dy);
                }
            }
            if scrolls_children(flags) {
                let children = children_to_scroll::<CHILDREN>(&m.windows, handle, dx, dy, scroll);
                for &(child, x, y) in children.iter() {
                    let _ = Windows::set_window_pos_handle(
                        s,
                        child,
                        0,
                        x,
                        y,
                        0,
                        0,
                        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW,
                    );
                }
            }
            let m = s.manager();
            let answer = super::scroll_window(&mut m.windows, handle, dx, dy, scroll, clip, flags)?;
            Ok::<_, Failure>(match answer {
                Some((area, _)) => (area.complexity, area.bounds),
                None => (NULLREGION, Rect::EMPTY),
            })
        })
        .map_err(Failure::status)?;
        if !update.is_null() {
            update.cast::<Rect>().write(bounds)?;
        }
        result.write(complexity as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// QUERY_WINDOW_SCROLL_BARS: the window's bars ([`query_scroll_bars`]), copied out once the
    /// window manager's lock is let go.
    pub fn query_window_scroll_bars(
        call: &mut NtCall,
        window: Handle,
        information: UserAddr,
    ) -> NtResult {
        let bars = with_manager(call.passive(), |m| {
            let id = m
                .windows
                .window_from_handle(window.raw())
                .ok_or(STATUS_INVALID_HANDLE)?;
            query_scroll_bars(&m.windows, &m.scroll_bars, id).map_err(Failure::status)
        })?;
        information.cast::<ScrollBars>().write(bars)?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the decisions themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    pub fn set_scroll_info(
        _: &mut NtCall,
        _: Handle,
        _: i32,
        _: UserAddr,
        _: bool,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn show_scroll_bar(_: &mut NtCall, _: Handle, _: i32, _: bool) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn enable_scroll_bar(
        _: &mut NtCall,
        _: Handle,
        _: u32,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn scroll_window_ex(
        _: &mut NtCall,
        _: Handle,
        _: i32,
        _: i32,
        _: UserAddr,
        _: UserAddr,
        _: u32,
        _: UserAddr,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(target_arch = "x86")]
pub use services::query_window_scroll_bars;
pub use services::{enable_scroll_bar, scroll_window_ex, set_scroll_info, show_scroll_bar};

#[cfg(test)]
mod tests {
    use rtl::scroll::{
        ScrollData,
        COMPLEXREGION,
        ESB_DISABLE_LTUP,
        NULLREGION,
        SIF_ALL,
        SIF_PAGE,
        SIF_POS,
        SIMPLEREGION,
    };
    use rtl::user::{WS_CHILD, WS_POPUP, WS_VISIBLE};

    use super::*;
    use crate::win32k::queue::rig::*;
    use crate::win32k::queue::QueueSession;
    use crate::win32k::window::WindowManager;

    fn info(mask: u32, min: i32, max: i32, page: u32, pos: i32) -> ScrollInfo {
        ScrollInfo {
            cb_size: 28,
            mask,
            min,
            max,
            page,
            pos,
            track_pos: 0,
        }
    }

    fn set(m: &mut WindowManager, h: Hwnd, bar: i32, info: ScrollInfo) -> Result<i32, Failure> {
        let (answer, reframe) = set_bar_info(&mut m.windows, &mut m.scroll_bars, h, bar, &info)?;
        if let Some(handle) = reframe {
            take_frame(m, handle);
        }
        Ok(answer)
    }

    fn take_frame(m: &mut WindowManager, handle: Hwnd) {
        use crate::win32k::window::{
            SWP_FRAMECHANGED,
            SWP_NOACTIVATE,
            SWP_NOMOVE,
            SWP_NOSIZE,
            SWP_NOZORDER,
        };
        Windows::set_window_pos_handle(
            &mut QueueSession::new(&mut m.windows, &mut m.classes),
            handle,
            0,
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        )
        .unwrap();
    }

    fn bars(m: &WindowManager, h: Hwnd) -> Result<ScrollBars, Failure> {
        let id = m.windows.window_from_handle(h).unwrap();
        query_scroll_bars(&m.windows, &m.scroll_bars, id)
    }

    fn style(m: &WindowManager, h: Hwnd) -> u32 {
        m.windows
            .window_style(m.windows.window_from_handle(h).unwrap())
    }

    /// The client area's width and height against the window's.
    fn shrink(m: &WindowManager, h: Hwnd) -> (i32, i32) {
        let id = m.windows.window_from_handle(h).unwrap();
        let (w, c) = (m.windows.window_rect(id), m.windows.client_rect(id));
        (w.width() - c.width(), w.height() - c.height())
    }

    /// A window made with both bars has them as made (0 to 100) before any call; a range the page
    /// covers hides a bar and takes the frame again, a range to scroll shows it.
    #[test]
    fn a_bar_hides_and_shows_with_its_range() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(
            m,
            atom,
            t,
            WS_POPUP | WS_VSCROLL | WS_HSCROLL,
            0,
            40,
            40,
            200,
            150,
        );
        assert_eq!(bars(m, h).unwrap(), ScrollBars::WINDOW);
        assert_eq!(shrink(m, h), (16, 16));
        assert_eq!(
            set(
                m,
                h,
                SB_VERT,
                info(SIF_RANGE | SIF_PAGE | SIF_POS, 0, 9, 10, 0)
            ),
            Ok(0)
        );
        assert_eq!(style(m, h) & (WS_VSCROLL | WS_HSCROLL), WS_HSCROLL);
        assert_eq!(shrink(m, h), (0, 16));
        // SIF_DISABLENOSCROLL keeps a hidden bar hidden.
        let keep = info(SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL, 0, 9, 10, 0);
        assert_eq!(set(m, h, SB_VERT, keep), Ok(0));
        assert_eq!(style(m, h) & WS_VSCROLL, 0);
        assert_eq!(
            set(m, h, SB_VERT, info(SIF_RANGE | SIF_PAGE, 0, 99, 10, 0)),
            Ok(0)
        );
        assert_eq!(shrink(m, h), (16, 16));
        // ... and a shown one shown, its arrows disabled; the same range again changes nothing.
        let none = info(SIF_RANGE | SIF_DISABLENOSCROLL, 0, 0, 0, 0);
        assert_eq!(set(m, h, SB_VERT, none), Ok(0));
        assert_eq!(style(m, h) & WS_VSCROLL, WS_VSCROLL);
        assert_eq!(bars(m, h).unwrap().disabled(SB_VERT), ESB_DISABLE_BOTH);
        assert_eq!(set(m, h, SB_VERT, info(SIF_RANGE, 0, 0, 0, 0)), Ok(0));
        assert_eq!(style(m, h) & WS_VSCROLL, WS_VSCROLL);
        assert_eq!(
            bars(m, h).unwrap().vert,
            ScrollData {
                min: 0,
                max: 0,
                page: 1,
                pos: 0
            }
        );
        // SB_BOTH sets the vertical bar.
        set(m, h, SB_VERT, info(SIF_RANGE | SIF_PAGE, 0, 99, 10, 0)).unwrap();
        assert_eq!(set(m, h, SB_BOTH, info(SIF_POS, 0, 0, 0, 5)), Ok(5));
        assert_eq!(bars(m, h).unwrap().vert.pos, 5);
    }

    /// A window made without bars has none (ERROR_NO_SCROLLBARS) until a call with SIF_RANGE gives
    /// it them; the bar that has something to scroll shows.
    #[test]
    fn a_window_without_bars_takes_them_from_a_range() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 40, 40, 200, 150);
        assert_eq!(bars(m, h), Err(Failure::NoScrollBars));
        assert_eq!(
            set(m, h, SB_VERT, info(SIF_POS, 0, 0, 0, 5)),
            Err(Failure::NoScrollBars)
        );
        assert_eq!(set(m, h, SB_VERT, info(SIF_ALL, 0, 99, 10, 30)), Ok(30));
        assert_eq!(style(m, h) & (WS_VSCROLL | WS_HSCROLL), WS_VSCROLL);
        assert_eq!(shrink(m, h), (16, 0));
        assert_eq!(
            set(m, h, SB_HORZ, info(SIF_RANGE | SIF_PAGE, 0, 9, 10, 0)),
            Ok(0)
        );
        assert_eq!(style(m, h) & WS_HSCROLL, 0);
        assert_eq!(
            set(m, h, SB_HORZ, info(SIF_RANGE | SIF_PAGE, 0, 49, 10, 0)),
            Ok(0)
        );
        assert_eq!(shrink(m, h), (16, 16));
        assert_eq!(
            set(m, 0x1234, SB_VERT, info(SIF_POS, 0, 0, 0, 5)),
            Err(Failure::InvalidWindowHandle)
        );
    }

    /// ShowScrollBar sets and clears the style bits, keeps the parameters, gives a window without
    /// bars them, and refuses a bar there is none of.
    #[test]
    fn show_keeps_the_parameters() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(
            m,
            atom,
            t,
            WS_POPUP | WS_VSCROLL | WS_HSCROLL,
            0,
            40,
            40,
            200,
            150,
        );
        set(
            m,
            h,
            SB_VERT,
            info(SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 30),
        )
        .unwrap();
        let show = |m: &mut WindowManager, bar, on| {
            let reframe = show_bars(&mut m.windows, &mut m.scroll_bars, h, bar, on)?;
            if let Some(handle) = reframe {
                take_frame(m, handle);
            }
            Ok::<_, Failure>(reframe.is_some())
        };
        assert_eq!(show(m, SB_VERT, false), Ok(true));
        assert_eq!(show(m, SB_VERT, false), Ok(false));
        assert_eq!(shrink(m, h), (0, 16));
        assert_eq!(bars(m, h).unwrap().vert.pos, 30);
        assert_eq!(show(m, SB_BOTH, false), Ok(true));
        assert_eq!(shrink(m, h), (0, 0));
        assert_eq!(
            bars(m, h).unwrap().vert.pos,
            30,
            "kept once the style lost both"
        );
        assert_eq!(show(m, SB_BOTH, true), Ok(true));
        assert_eq!(shrink(m, h), (16, 16));
        assert_eq!(show(m, 7, true), Err(Failure::InvalidParameter));
        let plain = window_at(m, atom, t, WS_POPUP, 0, 40, 40, 200, 150);
        assert_eq!(
            show_bars(&mut m.windows, &mut m.scroll_bars, plain, SB_VERT, true)
                .map(|r| r.is_some()),
            Ok(true)
        );
        assert_eq!(bars(m, plain).unwrap().vert, ScrollData::WINDOW);
    }

    /// EnableScrollBar answers whether the arrows changed; a window without bars takes them from
    /// a call that disables an arrow.
    #[test]
    fn enable_answers_a_change() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP | WS_VSCROLL, 0, 40, 40, 200, 150);
        let enable = |m: &mut WindowManager, h, bar, arrows| {
            enable_bar_arrows(&m.windows, &mut m.scroll_bars, h, bar, arrows)
        };
        assert_eq!(enable(m, h, SB_VERT, ESB_DISABLE_BOTH), Ok(true));
        assert_eq!(enable(m, h, SB_VERT, ESB_DISABLE_BOTH), Ok(false));
        assert_eq!(enable(m, h, SB_VERT, ESB_ENABLE_BOTH), Ok(true));
        assert_eq!(enable(m, h, SB_HORZ, ESB_DISABLE_LTUP), Ok(true));
        let plain = window_at(m, atom, t, WS_POPUP, 0, 40, 40, 200, 150);
        assert_eq!(enable(m, plain, SB_VERT, ESB_ENABLE_BOTH), Ok(false));
        assert_eq!(bars(m, plain), Err(Failure::NoScrollBars));
        assert_eq!(enable(m, plain, SB_VERT, ESB_DISABLE_BOTH), Ok(true));
        assert_eq!(bars(m, plain).unwrap().flags, 0xC);
        assert_eq!(style(m, plain) & WS_VSCROLL, 0, "no bar shown");
    }

    /// ScrollWindowEx's answers over a shown 200x100 window: the uncovered box invalidated with
    /// SW_INVALIDATE only; a hidden window scrolls nothing. The children SW_SCROLLCHILDREN moves:
    /// those the scroll rectangle reaches.
    #[test]
    fn scroll_window_invalidates_what_it_uncovers() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP | WS_VISIBLE, 0, 40, 40, 200, 100);
        let id = m.windows.window_from_handle(h).unwrap();
        crate::win32k::paint::validate(&mut m.windows, id, None);
        let (area, client) = scroll_window(&mut m.windows, h, 0, -10, None, None, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            (area.complexity, area.bounds),
            (SIMPLEREGION, Rect::new(0, 90, 200, 100))
        );
        assert_eq!(client, Rect::new(40, 40, 240, 140));
        assert_eq!(crate::win32k::paint::update_of(&m.windows, id), None);
        let (area, _) = scroll_window(&mut m.windows, h, 5, 5, None, None, SW_INVALIDATE)
            .unwrap()
            .unwrap();
        assert_eq!(area.complexity, COMPLEXREGION);
        assert_eq!(
            crate::win32k::paint::update_of(&m.windows, id),
            Some((Rect::new(0, 0, 200, 100), false))
        );
        let (area, _) = scroll_window(&mut m.windows, h, 0, 0, None, None, SW_INVALIDATE)
            .unwrap()
            .unwrap();
        assert_eq!((area.complexity, area.bounds), (NULLREGION, Rect::EMPTY));
        let child = window_at(m, atom, t, WS_CHILD | WS_VISIBLE, h, 10, 10, 30, 30);
        let moved = children_to_scroll::<4>(&m.windows, h, 0, 15, None);
        assert_eq!(moved.as_slice(), &[(child, 10, 25)]);
        let reach = Some(Rect::new(100, 0, 200, 100));
        assert!(children_to_scroll::<4>(&m.windows, h, 0, 15, reach).is_empty());
        let hidden = window_at(m, atom, t, WS_POPUP, 0, 40, 40, 200, 100);
        assert_eq!(
            scroll_window(&mut m.windows, hidden, 0, -10, None, None, SW_INVALIDATE),
            Ok(None)
        );
        assert_eq!(
            scroll_window(&mut m.windows, 0x1234, 0, -10, None, None, 0),
            Err(Failure::InvalidWindowHandle)
        );
    }
}
