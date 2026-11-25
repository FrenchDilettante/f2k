//! Scroll bars' shared shapes and rules: what win32k (a window's own bars, WS_HSCROLL and
//! WS_VSCROLL) and user32 (the ScrollBar control, and the reads of a window's bars) agree a scroll
//! bar is and how its parameters move.
//!
//! A bar is a range (`min` to `max`, both included), a page (how much of the range shows at once,
//! 0 for none) and a position, Windows 2000's SBDATA ([`ScrollData`]); a window's two bars and the
//! arrows' disabled bits are its SBINFO ([`ScrollBars`]), which Windows 2000 hangs on the window
//! (pwnd->pSBInfo) and F2K's win32k keeps for it. The ScrollBar control keeps one bar in its own
//! window (SBWND), F2K's in its extra bytes.
//!
//! The rules are Windows 2000's SBSetParms, as the scroll capture shows them ([`set_parms`]):
//!
//! - SIF_RANGE sets the range, a maximum below the minimum taken as the minimum; a range that
//!   changes brings the page and the position along (clamped to it again);
//! - SIF_PAGE sets the page, clamped to the range's size (`max - min + 1`), bringing the position
//!   along when it changes;
//! - SIF_POS sets the position, clamped to `min` and to `max - page + 1` (`max` with no page);
//! - SIF_TRACKPOS is never set (nTrackPos is the position while no thumb is being dragged);
//! - the call answers the new position, the old one with SIF_RETURNOLDPOS (SetScrollPos's);
//! - a call with SIF_RANGE or SIF_PAGE decides whether the bar has anything to scroll: a range of
//!   more than one value that the page does not cover whole. A window's bar that has nothing to
//!   scroll is hidden, one that has something is shown, unless SIF_DISABLENOSCROLL asks a shown bar
//!   to be kept and its arrows disabled instead; a call that changes nothing changes nothing of
//!   that either.
//!
//! EnableScrollBar's arrows ([`enable_arrows`]): a window's SBINFO holds ESB_DISABLE_LEFT and
//! ESB_DISABLE_RIGHT in its low two bits, the vertical bar's ESB_DISABLE_UP and ESB_DISABLE_DOWN
//! two bits up, each set by the flags asked (whatever bits they carry: a bad flag of 7 sets three),
//! ESB_ENABLE_BOTH clearing the bar's two; the call answers whether the bits changed.
//!
//! The layout a bar is drawn in ([`Layout`]): an arrow at each end, square, halved when the bar is
//! too short for two; the thumb between them, as long as the page is of the range (no shorter
//! than [`MIN_THUMB`]), or square with no page, placed as the position is between `min` and
//! `max - page + 1`; no thumb when the bar has nothing to scroll or no room for one.

use crate::gdi::Rect;
use crate::pod::Pod;

/// The bars (winuser.h's SB_*): a window's horizontal and vertical ones, a ScrollBar control, both
/// of a window's.
pub const SB_HORZ: i32 = 0;
pub const SB_VERT: i32 = 1;
pub const SB_CTL: i32 = 2;
pub const SB_BOTH: i32 = 3;

/// SCROLLINFO's fMask bits (winuser.h's SIF_*).
pub const SIF_RANGE: u32 = 0x0001;
pub const SIF_PAGE: u32 = 0x0002;
pub const SIF_POS: u32 = 0x0004;
pub const SIF_DISABLENOSCROLL: u32 = 0x0008;
pub const SIF_TRACKPOS: u32 = 0x0010;
pub const SIF_ALL: u32 = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS;
/// The old position answered instead of the new one: SetScrollPos's and the control's SBM_SETPOS
/// (Windows 2000's internal bit, winuser.h's under _WIN32_WINNT).
pub const SIF_RETURNOLDPOS: u32 = 0x1000;

/// EnableScrollBar's arrows (winuser.h's ESB_*).
pub const ESB_ENABLE_BOTH: u32 = 0x0000;
pub const ESB_DISABLE_LTUP: u32 = 0x0001;
pub const ESB_DISABLE_RTDN: u32 = 0x0002;
pub const ESB_DISABLE_BOTH: u32 = 0x0003;

/// The ScrollBar control's messages (winuser.h's SBM_*).
pub const SBM_SETPOS: u32 = 0x00E0;
pub const SBM_GETPOS: u32 = 0x00E1;
pub const SBM_SETRANGE: u32 = 0x00E2;
pub const SBM_GETRANGE: u32 = 0x00E3;
pub const SBM_ENABLE_ARROWS: u32 = 0x00E4;
pub const SBM_SETRANGEREDRAW: u32 = 0x00E6;
pub const SBM_SETSCROLLINFO: u32 = 0x00E9;
pub const SBM_GETSCROLLINFO: u32 = 0x00EA;

/// The ScrollBar control's styles (winuser.h's SBS_*): a vertical bar (a horizontal one without).
pub const SBS_VERT: u32 = 0x0001;

/// ScrollWindowEx's flags (winuser.h's SW_*).
pub const SW_SCROLLCHILDREN: u32 = 0x0001;
pub const SW_INVALIDATE: u32 = 0x0002;
pub const SW_ERASE: u32 = 0x0004;

/// A region's complexity, as ScrollWindowEx and the region calls answer it (wingdi.h's).
pub const ERROR: i32 = 0;
pub const NULLREGION: i32 = 1;
pub const SIMPLEREGION: i32 = 2;
pub const COMPLEXREGION: i32 = 3;

/// ERROR_NO_SCROLLBARS (1447): the window has no scroll bars to read or set.
pub const ERROR_NO_SCROLLBARS: u32 = 1447;
/// ERROR_INVALID_SCROLLBAR_RANGE (1448): SetScrollRange's range is wider than MAXLONG.
pub const ERROR_INVALID_SCROLLBAR_RANGE: u32 = 1448;

/// The shortest thumb drawn for a bar with a page (SM_CXHTHUMB's half: an assumption).
pub const MIN_THUMB: i32 = 8;

/// SCROLLINFO (28 bytes; 24 without nTrackPos, the size Windows 2000 takes as well).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollInfo {
    pub cb_size: u32,
    pub mask: u32,
    pub min: i32,
    pub max: i32,
    pub page: u32,
    pub pos: i32,
    pub track_pos: i32,
}

// SAFETY: seven 32-bit fields, no padding; every bit pattern is valid.
unsafe impl Pod for ScrollInfo {}

/// The sizes a SCROLLINFO may have: whole, or without nTrackPos.
pub const SCROLLINFO_SIZE: u32 = 28;
pub const SCROLLINFO_SIZE_V1: u32 = 24;

/// One bar's parameters (Windows 2000's SBDATA): its range, its page, its position.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollData {
    pub min: i32,
    pub max: i32,
    pub page: i32,
    pub pos: i32,
}

// SAFETY: four 32-bit fields, no padding; every bit pattern is valid.
unsafe impl Pod for ScrollData {}

impl ScrollData {
    /// A ScrollBar control's bar as it is made: all zeros (the scroll capture's `control`).
    pub const CONTROL: ScrollData = ScrollData {
        min: 0,
        max: 0,
        page: 0,
        pos: 0,
    };
    /// A window's bar as it is made: a range of 0 to 100, no page, at 0 (Windows 2000's
    /// _InitPwSB; the scroll capture's `info` and `show`).
    pub const WINDOW: ScrollData = ScrollData {
        min: 0,
        max: 100,
        page: 0,
        pos: 0,
    };

    /// Whether the bar has anything to scroll: a range of more than one value the page does not
    /// cover whole.
    pub fn scrollable(&self) -> bool {
        self.min != self.max && i64::from(self.page) <= i64::from(self.max) - i64::from(self.min)
    }

    /// The highest position: `max - page + 1` (`max` with no page).
    pub fn max_pos(&self) -> i32 {
        self.max.wrapping_sub(if self.page != 0 {
            self.page.wrapping_sub(1)
        } else {
            0
        })
    }
}

/// A window's scroll bars (Windows 2000's SBINFO): the arrows' disabled bits ([`enable_arrows`]),
/// then the horizontal bar, then the vertical one.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollBars {
    pub flags: u32,
    pub horz: ScrollData,
    pub vert: ScrollData,
}

// SAFETY: a 32-bit field and two four-field structures of them, no padding.
unsafe impl Pod for ScrollBars {}

impl ScrollBars {
    /// A window's bars as they are made.
    pub const WINDOW: ScrollBars = ScrollBars {
        flags: 0,
        horz: ScrollData::WINDOW,
        vert: ScrollData::WINDOW,
    };

    /// The bar `bar` names: the horizontal one for SB_HORZ, the vertical one for anything else,
    /// as Windows 2000's xxxSetScrollBar takes it (SB_BOTH sets the vertical bar: the scroll
    /// capture's `info`).
    pub fn bar_mut(&mut self, bar: i32) -> &mut ScrollData {
        if bar == SB_HORZ {
            &mut self.horz
        } else {
            &mut self.vert
        }
    }

    /// The bar `bar` names, read: see [`ScrollBars::bar_mut`].
    pub fn bar(&self, bar: i32) -> &ScrollData {
        if bar == SB_HORZ {
            &self.horz
        } else {
            &self.vert
        }
    }

    /// The disabled arrows of the bar `bar` names (ESB_DISABLE_LTUP, ESB_DISABLE_RTDN).
    pub fn disabled(&self, bar: i32) -> u32 {
        if bar == SB_HORZ {
            self.flags & ESB_DISABLE_BOTH
        } else {
            (self.flags >> 2) & ESB_DISABLE_BOTH
        }
    }
}

/// What [`set_parms`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetParms {
    /// Something of the bar changed.
    pub changed: bool,
    /// Whether the bar has anything to scroll, when the call decided it (SIF_RANGE or SIF_PAGE).
    pub scrollable: Option<bool>,
    /// The call's answer: the new position, the old one with SIF_RETURNOLDPOS.
    pub result: i32,
}

/// SetScrollInfo's parameters set on `data`, as Windows 2000's SBSetParms sets them (see the
/// module notes). `info` is the caller's, its members read as its mask names them.
pub fn set_parms(data: &mut ScrollData, info: &ScrollInfo) -> SetParms {
    let mut mask = info.mask;
    let mut page = info.page;
    let mut pos = info.pos;
    let old = data.pos;
    let mut changed = false;
    if mask & SIF_RANGE != 0 {
        let max = info.max.max(info.min);
        if data.min != info.min || data.max != max {
            data.min = info.min;
            data.max = max;
            if mask & SIF_PAGE == 0 {
                mask |= SIF_PAGE;
                page = data.page as u32;
            }
            if mask & SIF_POS == 0 {
                mask |= SIF_POS;
                pos = data.pos;
            }
            changed = true;
        }
    }
    if mask & SIF_PAGE != 0 {
        // The page is clipped to the range's size, unsigned (a range of 0 to MAXLONG is 2^31).
        let most = data
            .max
            .wrapping_sub(data.min)
            .unsigned_abs()
            .wrapping_add(1);
        let page = page.min(most) as i32;
        if data.page != page {
            data.page = page;
            if mask & SIF_POS == 0 {
                mask |= SIF_POS;
                pos = data.pos;
            }
            changed = true;
        }
    }
    if mask & SIF_POS != 0 {
        let pos = if pos < data.min {
            data.min
        } else if pos > data.max_pos() {
            data.max_pos()
        } else {
            pos
        };
        if data.pos != pos {
            data.pos = pos;
            changed = true;
        }
    }
    let scrollable = if mask & (SIF_RANGE | SIF_PAGE) != 0 {
        Some(data.scrollable())
    } else {
        None
    };
    SetParms {
        changed,
        scrollable,
        result: if info.mask & SIF_RETURNOLDPOS != 0 {
            old
        } else {
            data.pos
        },
    }
}

/// GetScrollInfo's members of `data` written into `info` as its mask names them, nTrackPos the
/// position (no thumb is ever being dragged), and only those inside its `cb_size`; whether the
/// mask names any.
pub fn get_parms(data: &ScrollData, info: &mut ScrollInfo) -> bool {
    let mask = info.mask;
    if mask & SIF_RANGE != 0 {
        info.min = data.min;
        info.max = data.max;
    }
    if mask & SIF_PAGE != 0 {
        info.page = data.page as u32;
    }
    if mask & SIF_POS != 0 {
        info.pos = data.pos;
    }
    if mask & SIF_TRACKPOS != 0 && info.cb_size >= SCROLLINFO_SIZE {
        info.track_pos = data.pos;
    }
    mask & SIF_ALL != 0
}

/// EnableScrollBar's arrows on a window's bars (Windows 2000's xxxEnableWndSBArrows): `flags`
/// (an SBINFO's) with `arrows` set on the bar `bar` names (SB_HORZ, SB_VERT, SB_BOTH), cleared for
/// ESB_ENABLE_BOTH; the new flags and whether they changed (the call's answer).
pub fn enable_arrows(flags: u32, bar: i32, arrows: u32) -> (u32, bool) {
    let mut new = flags;
    if bar == SB_HORZ || bar == SB_BOTH {
        if arrows == ESB_ENABLE_BOTH {
            new &= !ESB_DISABLE_BOTH;
        } else {
            new |= arrows;
        }
    }
    if bar == SB_VERT || bar == SB_BOTH {
        if arrows == ESB_ENABLE_BOTH {
            new &= !(ESB_DISABLE_BOTH << 2);
        } else {
            new |= arrows << 2;
        }
    }
    (new, new != flags)
}

/// What EnableScrollBar does to a ScrollBar control (Windows 2000's xxxEnableScrollBar for
/// SB_CTL), from the arrows the control has disabled (`disabled`, its two bits) and those asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlEnable {
    /// The arrows are as asked already: FALSE, nothing done.
    Unchanged,
    /// The control enabled (`true`) or disabled as a window: EnableWindow's change, which its
    /// WM_ENABLE takes into its arrows.
    Window(bool),
    /// The arrows changed through SBM_ENABLE_ARROWS, whose answer is the call's.
    Arrows,
}

/// See [`ControlEnable`]: both arrows disabled (at once, or the second of two) disables the
/// control; both enabled from both disabled enables it; anything else is the arrows' alone.
pub fn control_enable(disabled: u32, arrows: u32) -> ControlEnable {
    let disabled = disabled & ESB_DISABLE_BOTH;
    if disabled == arrows {
        return ControlEnable::Unchanged;
    }
    match arrows {
        ESB_DISABLE_BOTH => ControlEnable::Window(false),
        ESB_ENABLE_BOTH if disabled == ESB_DISABLE_BOTH => ControlEnable::Window(true),
        ESB_ENABLE_BOTH => ControlEnable::Arrows,
        _ if disabled | arrows == ESB_DISABLE_BOTH => ControlEnable::Window(false),
        _ => ControlEnable::Arrows,
    }
}

/// A ScrollBar control's SBM_ENABLE_ARROWS (Windows 2000's xxxEnableSBCtlArrows): its disabled
/// bits with `arrows` set, cleared for ESB_ENABLE_BOTH; the new bits and whether they changed.
pub fn control_arrows(disabled: u32, arrows: u32) -> (u32, bool) {
    let new = if arrows == ESB_ENABLE_BOTH {
        disabled & !ESB_DISABLE_BOTH
    } else {
        disabled | arrows
    };
    (new, new != disabled)
}

/// Where a bar's parts are drawn ([`Layout::of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The arrow at the bar's start (up or left) and at its end (down or right).
    pub start: Rect,
    pub end: Rect,
    /// The track between them.
    pub track: Rect,
    /// The thumb on the track, when there is one.
    pub thumb: Option<Rect>,
}

impl Layout {
    /// The layout of a bar drawn in `rect`, `vertical` or not, with the parameters `data`: see the
    /// module notes. `thumbed` is false for a bar drawn with no thumb (its arrows both disabled).
    pub fn of(rect: Rect, vertical: bool, data: &ScrollData, thumbed: bool) -> Layout {
        // Work along the bar's length, then turn the spans back into rectangles.
        let (from, to, breadth) = if vertical {
            (rect.top, rect.bottom, rect.width())
        } else {
            (rect.left, rect.right, rect.height())
        };
        let length = (to - from).max(0);
        let arrow = if length < 2 * breadth {
            length / 2
        } else {
            breadth
        };
        let span = |a: i32, b: i32| {
            if vertical {
                Rect::new(rect.left, a, rect.right, b)
            } else {
                Rect::new(a, rect.top, b, rect.bottom)
            }
        };
        let track_from = from + arrow;
        let track_to = to - arrow;
        let track = track_to - track_from;
        let range = i64::from(data.max) - i64::from(data.min) + 1;
        let thumb = if !thumbed || !data.scrollable() || track <= 0 {
            None
        } else {
            let size = if data.page != 0 {
                ((i64::from(track) * i64::from(data.page) / range) as i32).max(MIN_THUMB)
            } else {
                breadth
            };
            if size >= track {
                None
            } else {
                let room = i64::from(track - size);
                let steps = i64::from(data.max_pos()) - i64::from(data.min);
                let at = if steps <= 0 {
                    0
                } else {
                    (room * (i64::from(data.pos) - i64::from(data.min)) / steps) as i32
                };
                Some(span(track_from + at, track_from + at + size))
            }
        };
        Layout {
            start: span(from, track_from),
            end: span(track_to, to),
            track: span(track_from, track_to),
            thumb,
        }
    }
}

/// A rectangle's complexity as a region's: NULLREGION for an empty one, SIMPLEREGION otherwise.
pub fn rect_complexity(rect: Rect) -> i32 {
    if rect.is_empty() {
        NULLREGION
    } else {
        SIMPLEREGION
    }
}

/// What ScrollWindowEx uncovers ([`scroll_area`]): the region to repaint as up to four disjoint
/// rectangles, its complexity and its box; and the blit that moves what stays in view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrollArea {
    /// The region's rectangles (the first `count`).
    pub parts: [Rect; 4],
    pub count: usize,
    /// NULLREGION, SIMPLEREGION or COMPLEXREGION.
    pub complexity: i32,
    /// The region's box ([`Rect::EMPTY`] for none): ScrollWindowEx's prcUpdate.
    pub bounds: Rect,
    /// Where the bits that stay in view go (none for no blit), the source being it moved back by
    /// the scroll's offsets.
    pub destination: Rect,
}

impl ScrollArea {
    /// The region's rectangles.
    pub fn parts(&self) -> &[Rect] {
        &self.parts[..self.count]
    }
}

/// ScrollWindowEx's arithmetic, in client coordinates: the area `scroll` (the client area for
/// none, cut to it) moved by `dx` and `dy`, kept inside `clip` (the client area for none, cut to
/// it). The uncovered part, what of the scroll area inside the clip the moved area does not cover,
/// is the region to repaint: a rectangle when one side is uncovered, an L or a frame (complex)
/// when more are.
pub fn scroll_area(
    client: Rect,
    scroll: Option<Rect>,
    clip: Option<Rect>,
    dx: i32,
    dy: i32,
) -> ScrollArea {
    let scroll = scroll.map_or(client, |r| r.intersect(client));
    let clip = clip.map_or(client, |r| r.intersect(client));
    let seen = scroll.intersect(clip);
    let destination = scroll.saturating_offset(dx, dy).intersect(clip);
    let mut parts = [Rect::EMPTY; 4];
    let mut count = 0;
    if !seen.is_empty() {
        let cover = destination.intersect(seen);
        if cover.is_empty() {
            parts[0] = seen;
            count = 1;
        } else {
            // The bands above and below the covered part, then its left and right between them.
            for part in [
                Rect::new(seen.left, seen.top, seen.right, cover.top),
                Rect::new(seen.left, cover.bottom, seen.right, seen.bottom),
                Rect::new(seen.left, cover.top, cover.left, cover.bottom),
                Rect::new(cover.right, cover.top, seen.right, cover.bottom),
            ] {
                if !part.is_empty() {
                    parts[count] = part;
                    count += 1;
                }
            }
        }
    }
    let bounds = parts[..count]
        .iter()
        .fold(Rect::EMPTY, |bounds, part| bounds.union(*part));
    ScrollArea {
        parts,
        count,
        complexity: match count {
            0 => NULLREGION,
            1 => SIMPLEREGION,
            _ => COMPLEXREGION,
        },
        bounds,
        destination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(mask: u32, min: i32, max: i32, page: u32, pos: i32) -> ScrollInfo {
        ScrollInfo {
            cb_size: SCROLLINFO_SIZE,
            mask,
            min,
            max,
            page,
            pos,
            track_pos: pos,
        }
    }

    fn data(min: i32, max: i32, page: i32, pos: i32) -> ScrollData {
        ScrollData {
            min,
            max,
            page,
            pos,
        }
    }

    /// The scroll capture's `info` block, step by step on a window's vertical bar.
    #[test]
    fn the_info_blocks_clamping() {
        let mut bar = ScrollData::WINDOW;
        let set = set_parms(&mut bar, &info(SIF_RANGE, 0, 99, 0, 0));
        assert_eq!((set.result, set.scrollable), (0, Some(true)));
        assert_eq!(bar, data(0, 99, 0, 0));
        assert_eq!(set_parms(&mut bar, &info(SIF_PAGE, 0, 0, 10, 0)).result, 0);
        assert_eq!(set_parms(&mut bar, &info(SIF_POS, 0, 0, 0, 50)).result, 50);
        assert_eq!(set_parms(&mut bar, &info(SIF_POS, 0, 0, 0, 90)).result, 90);
        let set = set_parms(&mut bar, &info(SIF_POS, 0, 0, 0, 95));
        assert_eq!((set.result, set.changed, set.scrollable), (90, false, None));
        assert_eq!(set_parms(&mut bar, &info(SIF_POS, 0, 0, 0, -5)).result, 0);
        assert_eq!(set_parms(&mut bar, &info(SIF_POS, 0, 0, 0, 60)).result, 60);
        // A page that leaves the position past the end brings it back.
        assert_eq!(set_parms(&mut bar, &info(SIF_PAGE, 0, 0, 50, 0)).result, 50);
        assert_eq!(bar, data(0, 99, 50, 50));
        // A page larger than the range is the range's size: nothing to scroll.
        let set = set_parms(&mut bar, &info(SIF_PAGE, 0, 0, 200, 0));
        assert_eq!((set.result, set.scrollable), (0, Some(false)));
        assert_eq!(bar, data(0, 99, 100, 0));
        // An inverted range is a range of its minimum alone.
        let set = set_parms(&mut bar, &info(SIF_PAGE | SIF_RANGE, 50, 10, 0, 0));
        assert_eq!((set.result, set.scrollable), (50, Some(false)));
        assert_eq!(bar, data(50, 50, 0, 50));
        assert_eq!(set_parms(&mut bar, &info(SIF_ALL, 0, 20, 5, 30)).result, 16);
        assert_eq!(
            set_parms(&mut bar, &info(SIF_ALL, -10, 10, 4, -20)).result,
            -10
        );
        // SIF_TRACKPOS sets nothing.
        let set = set_parms(&mut bar, &info(SIF_TRACKPOS, 0, 0, 0, 3));
        assert_eq!((set.result, set.changed), (-10, false));
        assert_eq!(bar, data(-10, 10, 4, -10));
    }

    /// A range the page covers has nothing to scroll; a range of one value neither, whatever the
    /// page; a call that sets the same range changes nothing.
    #[test]
    fn what_has_nothing_to_scroll() {
        let mut bar = ScrollData::WINDOW;
        let set = set_parms(&mut bar, &info(SIF_RANGE | SIF_PAGE | SIF_POS, 0, 9, 10, 0));
        assert_eq!(set.scrollable, Some(false));
        let set = set_parms(&mut bar, &info(SIF_RANGE | SIF_PAGE, 0, 9, 10, 0));
        assert_eq!((set.changed, set.scrollable), (false, Some(false)));
        let set = set_parms(&mut bar, &info(SIF_RANGE | SIF_PAGE, 0, 99, 10, 0));
        assert_eq!((set.changed, set.scrollable), (true, Some(true)));
        // A range of one value: the page is clipped to 1.
        let set = set_parms(&mut bar, &info(SIF_RANGE, 0, 0, 0, 0));
        assert_eq!((set.changed, set.scrollable), (true, Some(false)));
        assert_eq!(bar, data(0, 0, 1, 0));
        let set = set_parms(&mut bar, &info(SIF_RANGE, 0, 0, 0, 0));
        assert_eq!((set.changed, set.scrollable), (false, Some(false)));
        // fMask 0 answers the position and changes nothing.
        let set = set_parms(&mut bar, &info(0, 0, 5, 1, 1));
        assert_eq!((set.result, set.changed, set.scrollable), (0, false, None));
    }

    /// SetScrollPos's SIF_RETURNOLDPOS answers the position before; SetScrollRange's range brings
    /// the position and the page along (the capture's `posrange`).
    #[test]
    fn the_old_position_and_a_range_that_moves_it() {
        let mut bar = data(0, 50, 0, 0);
        let pos = |bar: &mut ScrollData, pos| {
            set_parms(bar, &info(SIF_POS | SIF_RETURNOLDPOS, 0, 0, 0, pos)).result
        };
        assert_eq!(pos(&mut bar, 20), 0);
        assert_eq!(pos(&mut bar, 80), 20);
        assert_eq!(bar.pos, 50);
        assert_eq!(pos(&mut bar, -3), 50);
        assert_eq!(bar.pos, 0);
        assert_eq!(pos(&mut bar, 25), 0);
        set_parms(&mut bar, &info(SIF_PAGE, 0, 0, 10, 0));
        assert_eq!(pos(&mut bar, 50), 25);
        assert_eq!(bar.pos, 41);
        set_parms(&mut bar, &info(SIF_RANGE, 0, 30, 0, 0));
        assert_eq!(bar, data(0, 30, 10, 21));
        // A range of 0 to MAXLONG: the page's limit is 2^31, unsigned.
        set_parms(&mut bar, &info(SIF_RANGE, 0, i32::MAX, 0, 0));
        assert_eq!(bar, data(0, i32::MAX, 10, 21));
    }

    /// GetScrollInfo writes only what the mask names, nTrackPos the position, nothing past a
    /// 24-byte structure; a mask naming nothing answers FALSE.
    #[test]
    fn get_writes_what_the_mask_names() {
        let bar = data(0, 99, 10, 30);
        let mut out = ScrollInfo {
            cb_size: SCROLLINFO_SIZE,
            mask: SIF_POS,
            min: -7,
            max: -7,
            page: 7,
            pos: -7,
            track_pos: -7,
        };
        assert!(get_parms(&bar, &mut out));
        assert_eq!(
            (out.min, out.max, out.page, out.pos, out.track_pos),
            (-7, -7, 7, 30, -7)
        );
        out.mask = SIF_TRACKPOS;
        assert!(get_parms(&bar, &mut out));
        assert_eq!(out.track_pos, 30);
        out.mask = SIF_ALL;
        out.cb_size = SCROLLINFO_SIZE_V1;
        out.track_pos = -7;
        assert!(get_parms(&bar, &mut out));
        assert_eq!((out.min, out.max, out.page, out.track_pos), (0, 99, 10, -7));
        out.mask = 0;
        assert!(!get_parms(&bar, &mut out));
    }

    /// The window bars' arrows: each change answers TRUE once, SB_BOTH sets both, a bad flag sets
    /// whatever bits it carries (the capture's `enable`).
    #[test]
    fn the_arrows_of_a_windows_bars() {
        let (flags, changed) = enable_arrows(0, SB_VERT, ESB_DISABLE_BOTH);
        assert_eq!((flags, changed), (0xC, true));
        assert_eq!(
            enable_arrows(flags, SB_VERT, ESB_DISABLE_BOTH),
            (0xC, false)
        );
        let (flags, _) = enable_arrows(flags, SB_VERT, ESB_ENABLE_BOTH);
        assert_eq!(enable_arrows(flags, SB_VERT, ESB_ENABLE_BOTH), (0, false));
        let (flags, _) = enable_arrows(flags, SB_VERT, ESB_DISABLE_LTUP);
        assert_eq!(enable_arrows(flags, SB_VERT, ESB_DISABLE_LTUP), (4, false));
        let (flags, changed) = enable_arrows(flags, SB_VERT, ESB_DISABLE_RTDN);
        assert!(changed);
        assert_eq!(
            enable_arrows(flags, SB_VERT, ESB_DISABLE_BOTH),
            (0xC, false)
        );
        let (flags, _) = enable_arrows(flags, SB_BOTH, ESB_ENABLE_BOTH);
        let (flags, _) = enable_arrows(flags, SB_BOTH, ESB_DISABLE_BOTH);
        assert_eq!(flags, 0xF);
        let (flags, _) = enable_arrows(flags, SB_BOTH, ESB_ENABLE_BOTH);
        let (flags, changed) = enable_arrows(flags, SB_VERT, 7);
        assert_eq!((flags, changed), (0x1C, true));
        assert_eq!(
            enable_arrows(flags, SB_VERT, ESB_DISABLE_BOTH),
            (0x1C, false)
        );
        let bars = ScrollBars {
            flags: 0x1D,
            ..ScrollBars::WINDOW
        };
        assert_eq!((bars.disabled(SB_HORZ), bars.disabled(SB_VERT)), (1, 3));
    }

    /// The control's EnableScrollBar: both arrows at once or one after the other disable the
    /// window, both enabled from disabled enable it, one arrow is the arrows' message.
    #[test]
    fn the_arrows_of_a_control() {
        use ControlEnable::*;
        assert_eq!(control_enable(0, ESB_DISABLE_BOTH), Window(false));
        assert_eq!(control_enable(3, ESB_DISABLE_BOTH), Unchanged);
        assert_eq!(control_enable(3, ESB_ENABLE_BOTH), Window(true));
        assert_eq!(control_enable(0, ESB_DISABLE_LTUP), Arrows);
        assert_eq!(control_enable(1, ESB_DISABLE_RTDN), Window(false));
        assert_eq!(control_enable(1, ESB_ENABLE_BOTH), Arrows);
        assert_eq!(control_enable(0, ESB_ENABLE_BOTH), Unchanged);
        assert_eq!(control_arrows(1, ESB_ENABLE_BOTH), (0, true));
        assert_eq!(control_arrows(0, ESB_ENABLE_BOTH), (0, false));
        assert_eq!(control_arrows(1, ESB_DISABLE_RTDN), (3, true));
    }

    /// A bar's layout: square arrows at its ends, the thumb as long as the page is of the range
    /// and placed as the position is; no thumb with nothing to scroll; halved arrows on a short
    /// bar.
    #[test]
    fn a_bars_layout() {
        let rect = Rect::new(0, 0, 16, 116);
        let layout = Layout::of(rect, true, &data(0, 99, 10, 0), true);
        assert_eq!(layout.start, Rect::new(0, 0, 16, 16));
        assert_eq!(layout.end, Rect::new(0, 100, 16, 116));
        assert_eq!(layout.track, Rect::new(0, 16, 16, 100));
        assert_eq!(layout.thumb, Some(Rect::new(0, 16, 16, 24)));
        let layout = Layout::of(rect, true, &data(0, 99, 50, 50), true);
        assert_eq!(layout.thumb, Some(Rect::new(0, 58, 16, 100)));
        let layout = Layout::of(rect, true, &data(0, 9, 10, 0), true);
        assert_eq!(layout.thumb, None);
        let layout = Layout::of(rect, true, &data(0, 100, 0, 0), false);
        assert_eq!(layout.thumb, None);
        let short = Layout::of(Rect::new(0, 0, 20, 16), false, &ScrollData::WINDOW, true);
        assert_eq!(short.start, Rect::new(0, 0, 10, 16));
        assert_eq!(short.end, Rect::new(10, 0, 20, 16));
        assert_eq!(short.thumb, None);
    }

    /// The scroll capture's `scrollex` rectangles over a 200x100 client area.
    #[test]
    fn what_a_scroll_uncovers() {
        let client = Rect::new(0, 0, 200, 100);
        let area = |scroll, clip, dx, dy| scroll_area(client, scroll, clip, dx, dy);
        let up = area(None, None, 0, -10);
        assert_eq!(
            (up.complexity, up.bounds),
            (SIMPLEREGION, Rect::new(0, 90, 200, 100))
        );
        assert_eq!(up.destination, Rect::new(0, 0, 200, 90));
        assert_eq!(area(None, None, 0, 10).bounds, Rect::new(0, 0, 200, 10));
        assert_eq!(area(None, None, 20, 0).bounds, Rect::new(0, 0, 20, 100));
        assert_eq!(area(None, None, -20, 0).bounds, Rect::new(180, 0, 200, 100));
        let diagonal = area(None, None, 5, 5);
        assert_eq!(
            (diagonal.complexity, diagonal.bounds),
            (COMPLEXREGION, client)
        );
        let away = area(None, None, 0, -150);
        assert_eq!((away.complexity, away.bounds), (SIMPLEREGION, client));
        assert!(away.destination.is_empty());
        let none = area(None, None, 0, 0);
        assert_eq!((none.complexity, none.bounds), (NULLREGION, Rect::EMPTY));
        let scroll = Some(Rect::new(50, 0, 150, 100));
        assert_eq!(
            area(scroll, None, 0, -10).bounds,
            Rect::new(50, 90, 150, 100)
        );
        let clip = Some(Rect::new(0, 0, 200, 50));
        let clipped = area(None, clip, 0, 10);
        assert_eq!(clipped.bounds, Rect::new(0, 0, 200, 10));
        assert_eq!(clipped.destination, Rect::new(0, 10, 200, 50));
        let clip = Some(Rect::new(0, 50, 200, 100));
        let both = area(scroll, clip, 0, -10);
        assert_eq!(
            (both.complexity, both.bounds),
            (SIMPLEREGION, Rect::new(50, 90, 150, 100))
        );
    }
}
