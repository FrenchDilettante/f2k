//! NtUserQueryWindow's answers, ChildWindowFromPointEx's and FindWindowEx's searches.

use rtl::user::{WS_DISABLED, WS_EX_TRANSPARENT, WS_VISIBLE};

use super::*;
use crate::sched::thread::ThreadId;
use crate::status::*;
use crate::win32k::class;

/// NtUserQueryWindow's answer, by its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query {
    /// QUERY_WINDOW_INFO: the window's WINDOWINFO.
    Info(WindowInfo),
    /// QUERY_WINDOW_VISIBLE: IsWindowVisible's answer, a 32-bit boolean.
    Visible(u32),
    /// QUERY_WINDOW_DATA: the window's own fields.
    Data(WindowData),
    /// QUERY_WINDOW_TEXT: the window's text's length, the answer's head (its units follow it,
    /// as many as the answer holds: the service copies them, [`query_window`]).
    TextLength(u32),
    /// QUERY_WINDOW_EXTRA and QUERY_CLASS_EXTRA: a value of the window's extra bytes or its
    /// class's, its first `.1` bytes
    /// (little-endian) the answer.
    Extra([u8; 4], u8),
    /// QUERY_WINDOW_PARENT: the parent's handle, 0 for none.
    Parent(u32),
    /// QUERY_WINDOW_MENU: GetMenu's answer.
    Menu(u32),
    /// QUERY_WINDOW_LINKS: the window's relatives.
    Links(rtl::window::WindowLinks),
    /// QUERY_WINDOW_CLASS: the fields of the window's class GetClassLong reads.
    Class(rtl::window::WindowClass),
}

impl Query {
    /// The answer's bytes, as the caller's buffer receives them.
    pub fn bytes(&self) -> &[u8] {
        use rtl::pod::Pod;
        match self {
            Query::Info(info) => info.as_bytes(),
            Query::Visible(visible)
            | Query::Parent(visible)
            | Query::Menu(visible)
            | Query::TextLength(visible) => visible.as_bytes(),
            Query::Data(data) => data.as_bytes(),
            Query::Links(links) => links.as_bytes(),
            Query::Class(class) => class.as_bytes(),
            Query::Extra(bytes, length) => &bytes[..*length as usize],
        }
    }
}

/// Whether NtUserQueryWindow answers the index `index` (ERROR_INVALID_INDEX, carried, when it has
/// no answer for it) with an answer of `length` bytes (STATUS_INFO_LENGTH_MISMATCH when the
/// answer's length is another): each index's answer has its own length, an extra-bytes value 2 or
/// 4, the text any even length from 4 (its own length, then the units that fit).
pub fn query_accepts(index: u32, length: usize) -> Result<(), NtStatus> {
    use core::mem::size_of;

    use rtl::window::*;
    let fits = match index {
        QUERY_WINDOW_INFO => length == size_of::<WindowInfo>(),
        QUERY_WINDOW_VISIBLE | QUERY_WINDOW_PARENT | QUERY_WINDOW_MENU => {
            length == size_of::<u32>()
        }
        QUERY_WINDOW_DATA => length == size_of::<WindowData>(),
        QUERY_WINDOW_TEXT => length >= size_of::<u32>() && length % 2 == 0,
        QUERY_WINDOW_LINKS => length == size_of::<WindowLinks>(),
        QUERY_WINDOW_CLASS => length == size_of::<WindowClass>(),
        QUERY_WINDOW_THREAD => length == size_of::<WindowThread>(),
        QUERY_WINDOW_SCROLL_BARS => length == size_of::<rtl::scroll::ScrollBars>(),
        index if index & (QUERY_WINDOW_EXTRA | QUERY_CLASS_EXTRA) != 0 => {
            length == 2 || length == 4
        }
        _ => return Err(Failure::InvalidIndex.status()),
    };
    if fits {
        Ok(())
    } else {
        Err(STATUS_INFO_LENGTH_MISMATCH)
    }
}

impl WindowManager {
    /// NtUserQueryWindow's answer for the window `handle` names, the index `index` and the
    /// answer's length `length` (a pair [`query_accepts`] accepts), for a caller of the process
    /// `caller`.
    pub fn query_window(
        &self,
        handle: Hwnd,
        index: u32,
        length: usize,
        caller: class::Owner,
    ) -> Result<Query, Failure> {
        use rtl::window::*;
        let window = self.windows.window_of(handle)?;
        Ok(match index {
            QUERY_WINDOW_INFO => Query::Info(self.windows.window_info(&self.classes, window)),
            QUERY_WINDOW_VISIBLE => Query::Visible(self.windows.is_window_visible(window) as u32),
            QUERY_WINDOW_DATA => Query::Data(self.windows.window_data(window, caller)),
            QUERY_WINDOW_TEXT => Query::TextLength(self.windows.window_text(window).len() as u32),
            QUERY_WINDOW_PARENT => Query::Parent(
                self.windows
                    .parent_of(window)
                    .map_or(0, |parent| self.windows.handle_of(parent)),
            ),
            QUERY_WINDOW_MENU => Query::Menu(self.windows.window_menu(window)),
            QUERY_WINDOW_LINKS => Query::Links(self.windows.window_links(window)),
            QUERY_WINDOW_CLASS => Query::Class(
                self.windows
                    .at(window)
                    .class
                    .map_or_else(WindowClass::default, |class| self.classes.class_data(class)),
            ),
            index if index & QUERY_WINDOW_EXTRA == 0 && index & QUERY_CLASS_EXTRA != 0 => {
                let offset = (index & !QUERY_CLASS_EXTRA) as i32;
                let class = self.windows.at(window).class.ok_or(Failure::InvalidIndex)?;
                let value = self
                    .classes
                    .extra_value(class, offset, length)
                    .map_err(|_| Failure::InvalidIndex)?;
                Query::Extra(value.to_le_bytes(), length as u8)
            }
            _ => {
                let offset = (index & !QUERY_WINDOW_EXTRA) as i32;
                let value = self.windows.extra_value(window, offset, length)?;
                Query::Extra(value.to_le_bytes(), length as u8)
            }
        })
    }

    /// NtUserChildWindowFromPointEx's decision: the first direct child of `handle`'s window, in
    /// z-order, holding the client point (`x`, `y`), skipping hidden, disabled and transparent
    /// ones as the CWP_ flags ask; the window itself when none does, none outside the window.
    pub fn child_window_from_point(
        &self,
        handle: Hwnd,
        x: i32,
        y: i32,
        flags: u32,
    ) -> Result<Option<Hwnd>, Failure> {
        use rtl::window::{CWP_SKIPDISABLED, CWP_SKIPINVISIBLE, CWP_SKIPTRANSPARENT};
        let w = &self.windows;
        let parent = w.window_of(handle)?;
        let client = w.client_rect(parent);
        let (x, y) = (x.saturating_add(client.left), y.saturating_add(client.top));
        if !w.window_rect(parent).contains(x, y) {
            return Ok(None);
        }
        let mut child = w.first_child(parent);
        while let Some(c) = child {
            let style = w.window_style(c);
            let passed = (flags & CWP_SKIPINVISIBLE != 0 && style & WS_VISIBLE == 0)
                || (flags & CWP_SKIPDISABLED != 0 && style & WS_DISABLED != 0)
                || (flags & CWP_SKIPTRANSPARENT != 0
                    && w.window_ex_style(c) & WS_EX_TRANSPARENT != 0);
            if !passed && w.window_rect(c).contains(x, y) {
                return Ok(Some(w.handle_of(c)));
            }
            child = w.next_sibling(c);
        }
        Ok(Some(handle))
    }

    /// NtUserFindWindowEx's search: the first child of `parent` (none: the caller's desktop
    /// window) after `after` (none: from the top) of class `class` and title `title` (none: any),
    /// titles compared case-insensitively. A class name naming no class finds nothing.
    pub fn find_window(
        &self,
        caller: ThreadId,
        parent: Option<Hwnd>,
        after: Option<Hwnd>,
        class: Option<class::Name>,
        title: Option<&[u16]>,
    ) -> Result<Option<Hwnd>, Failure> {
        let w = &self.windows;
        let parent = match parent {
            Some(handle) => w.window_of(handle)?,
            None => match w.thread_desktop_window(caller) {
                Some(desktop) => desktop,
                None => return Ok(None),
            },
        };
        let mut child = match after {
            Some(handle) => {
                let after = w.window_of(handle)?;
                if w.parent_of(after) != Some(parent) {
                    return Ok(None);
                }
                w.next_sibling(after)
            }
            None => w.first_child(parent),
        };
        let atom = match class {
            Some(name) => match self.classes.atom_of(name) {
                0 => return Ok(None),
                atom => Some(atom),
            },
            None => None,
        };
        while let Some(c) = child {
            let record = w.at(c);
            let class_matches =
                atom.is_none_or(|atom| record.class.map(|id| self.classes.atom(id)) == Some(atom));
            let title_matches = title
                .is_none_or(|title| rtl::text::eq_ignore_case(w.texts.units(record.title), title));
            if class_matches && title_matches {
                return Ok(Some(record.handle));
            }
            child = w.next_sibling(c);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_CHILD, WS_POPUP};
    use rtl::window::{QUERY_WINDOW_INFO, QUERY_WINDOW_VISIBLE};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// The query's indexes and lengths: WINDOWINFO's 60 bytes, the visibility's, the parent's and
    /// the menu's 4, the data's 36, the scroll bars' 36, the text's any even length from 4 (its
    /// length, then the room for its units), an extra-bytes value's 2 or 4, nothing else.
    #[test]
    fn the_query_lengths() {
        use rtl::window::{
            QUERY_WINDOW_DATA,
            QUERY_WINDOW_EXTRA,
            QUERY_WINDOW_MENU,
            QUERY_WINDOW_PARENT,
            QUERY_WINDOW_SCROLL_BARS,
            QUERY_WINDOW_TEXT,
        };
        assert_eq!(query_accepts(QUERY_WINDOW_INFO, 60), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_VISIBLE, 4), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_PARENT, 4), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_MENU, 4), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_DATA, 36), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_TEXT, 4), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_TEXT, 4 + 2 * 10_000), Ok(()));
        assert_eq!(
            query_accepts(QUERY_WINDOW_TEXT, 7),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            query_accepts(QUERY_WINDOW_TEXT, 2),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(query_accepts(QUERY_WINDOW_EXTRA | 8, 2), Ok(()));
        assert_eq!(query_accepts(QUERY_WINDOW_EXTRA, 4), Ok(()));
        assert_eq!(
            query_accepts(QUERY_WINDOW_EXTRA, 3),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            query_accepts(QUERY_WINDOW_VISIBLE, 60),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(query_accepts(QUERY_WINDOW_SCROLL_BARS, 36), Ok(()));
        assert_eq!(
            query_accepts(QUERY_WINDOW_SCROLL_BARS, 4),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(query_accepts(10, 4), Err(Failure::InvalidIndex.status()));
        assert_eq!(Query::Visible(1).bytes(), &[1, 0, 0, 0]);
        assert_eq!(Query::Parent(0x24).bytes(), &[0x24, 0, 0, 0]);
        assert_eq!(Query::Info(WindowInfo::default()).bytes().len(), 60);
    }

    /// The coords capture's windows: a borderless popup at (200, 150), 300x200, its children
    /// child1, child2 (with a grandchild), a hidden one and a disabled one. ChildWindowFromPointEx
    /// finds the child holding a point of the popup's client area, as the CWP_ flags pass over
    /// children; the parent query walks up.
    #[test]
    fn children_are_found_under_a_point() {
        use rtl::window::{CWP_SKIPDISABLED, CWP_SKIPINVISIBLE, QUERY_WINDOW_PARENT};

        use crate::win32k::queue::rig;
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let child = WS_CHILD | WS_VISIBLE;
        let parent = rig::window_at(m, atom, t, WS_POPUP, 0, 200, 150, 300, 200);
        let child1 = rig::window_at(m, atom, t, child, parent, 10, 20, 50, 30);
        let child2 = rig::window_at(m, atom, t, child, parent, 100, 20, 60, 40);
        let grand = rig::window_at(m, atom, t, child, child2, 5, 5, 20, 10);
        let hidden = rig::window_at(m, atom, t, WS_CHILD, parent, 10, 100, 40, 40);
        let disabled = rig::window_at(m, atom, t, child | WS_DISABLED, parent, 100, 100, 40, 40);
        let both = CWP_SKIPINVISIBLE | CWP_SKIPDISABLED;
        let found = |m: &WindowManager, w, x, y, flags| {
            m.child_window_from_point(w, x, y, flags)
                .unwrap()
                .unwrap_or(0)
        };
        for (x, y, all, invisible, skip_disabled, skip_both) in [
            (15, 25, child1, child1, child1, child1),
            (107, 27, child2, child2, child2, child2),
            (15, 105, hidden, parent, hidden, parent),
            (105, 105, disabled, disabled, parent, parent),
            (250, 180, parent, parent, parent, parent),
            (59, 49, child1, child1, child1, child1),
            (60, 25, parent, parent, parent, parent),
            (299, 199, parent, parent, parent, parent),
            (-5, 10, 0, 0, 0, 0),
            (300, 10, 0, 0, 0, 0),
            (10, 200, 0, 0, 0, 0),
        ] {
            assert_eq!(found(m, parent, x, y, 0), all, "({x}, {y})");
            assert_eq!(found(m, parent, x, y, CWP_SKIPINVISIBLE), invisible);
            assert_eq!(found(m, parent, x, y, CWP_SKIPDISABLED), skip_disabled);
            assert_eq!(found(m, parent, x, y, both), skip_both);
        }
        assert_eq!(found(m, child2, 7, 7, 0), grand);
        assert_eq!(
            m.child_window_from_point(0, 15, 25, 0),
            Err(Failure::InvalidWindowHandle)
        );
        let parent_of =
            |m: &WindowManager, w| m.query_window(w, QUERY_WINDOW_PARENT, 4, OWNER).unwrap();
        assert_eq!(parent_of(m, grand), Query::Parent(child2));
        assert_eq!(parent_of(m, child2), Query::Parent(parent));
        let desktop = m
            .windows
            .desktop_by_id(rig::DESKTOP)
            .unwrap()
            .window
            .unwrap();
        assert_eq!(
            parent_of(m, parent),
            Query::Parent(m.windows.handle_of(desktop))
        );
    }

    /// ChildWindowFromPointEx of a point at i32's end, of a window whose client area is away from
    /// the screen's origin: the point is outside the window.
    #[test]
    fn a_point_at_i32s_end_is_outside_every_window() {
        use crate::win32k::queue::rig;
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let parent = rig::window_at(m, atom, t, WS_POPUP, 0, 200, 150, 300, 200);
        rig::window_at(m, atom, t, WS_CHILD | WS_VISIBLE, parent, 10, 20, 50, 30);
        assert_eq!(
            m.child_window_from_point(parent, i32::MAX, i32::MAX, 0),
            Ok(None)
        );
        assert_eq!(m.child_window_from_point(parent, 15, i32::MAX, 0), Ok(None));
    }
}
