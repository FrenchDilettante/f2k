//! The window trees: the parent and owner chains' limits, and a window's place in its parent's
//! child list (the z-order).

use rtl::user::WS_EX_TOPMOST;

use super::*;

/// The nested window/owner depth limit.
const NESTED_WINDOW_LIMIT: u32 = 100;

impl Windows {
    /// The top-level window of `window`: walk up the parent chain while the window is a child.
    pub(super) fn top_level_window(&self, window: WindowId) -> Option<WindowId> {
        let mut current = Some(window);
        while let Some(w) = current {
            if self.at(w).is_child() {
                current = self.at(w).parent;
            } else {
                return Some(w);
            }
        }
        None
    }

    /// The nested-children limit: the depth of `parent`'s chain plus the depth of `window`'s
    /// subtree (when it has one) must stay within the limit. At a create `window` is the new
    /// window (none yet), so only the parent chain counts.
    pub(super) fn validate_parent_depth(
        &self,
        window: Option<WindowId>,
        parent: Option<WindowId>,
    ) -> bool {
        let mut depth = 1u32;
        let mut current = parent;
        while let Some(w) = current {
            current = self.at(w).parent;
            depth += 1;
        }
        let mut max = depth;
        if let Some(w) = window {
            if self.at(w).child.is_some() {
                max = max.max(self.subtree_depth(w, depth));
            }
        }
        max <= NESTED_WINDOW_LIMIT
    }

    /// The deepest level in `w`'s subtree (its children, theirs, and so on), `depth` being `w`'s
    /// own level. The walk follows the child, sibling and parent links, without recursing.
    fn subtree_depth(&self, w: WindowId, depth: u32) -> u32 {
        let mut max = depth;
        let Some(mut current) = self.at(w).child else {
            return max;
        };
        let mut level = depth + 1;
        loop {
            max = max.max(level);
            if let Some(child) = self.at(current).child {
                current = child;
                level += 1;
                continue;
            }
            // Up to the nearest ancestor below `w` with a next sibling.
            loop {
                if let Some(next) = self.at(current).next {
                    current = next;
                    break;
                }
                current = self.at(current).parent.expect("a child has its parent");
                level -= 1;
                if current == w {
                    return max;
                }
            }
        }
    }

    /// The owner-chain limit: no loop (the new window may not appear in it) and no chain deeper
    /// than the limit.
    pub(super) fn validate_owner_depth(&self, window: WindowId, owner: Option<WindowId>) -> bool {
        let mut depth = 1u32;
        let mut current = owner;
        while let Some(w) = current {
            if w == window {
                return false;
            }
            current = self.at(w).owner;
            depth += 1;
            if depth > NESTED_WINDOW_LIMIT {
                return false;
            }
        }
        true
    }

    /// Splice `id` into `parent`'s child list at `z`: at the top (the new head), at the bottom
    /// (after the last sibling before any bottom-most window), or directly after a window.
    pub(super) fn link_window(&mut self, id: WindowId, z: ZOrder, parent: WindowId) {
        if self.at(parent).child == Some(id) {
            // Attempting to link a window to itself.
            return;
        }
        match z {
            ZOrder::Top => self.link_top(id, parent),
            ZOrder::Bottom => {
                // Find the bottom-most window: the last sibling before any bottom-most one.
                let mut insert = self.at(parent).child;
                let link_top = match insert {
                    None => true,
                    Some(first) => self.at(first).flags.bottommost,
                };
                if !link_top {
                    while let Some(next) = insert.and_then(|i| self.at(i).next) {
                        if self.at(next).flags.bottommost {
                            break;
                        }
                        insert = Some(next);
                    }
                }
                match insert {
                    Some(after) => {
                        let next = self.at(after).next;
                        self.at_mut(id).next = next;
                        self.at_mut(after).next = Some(id);
                    }
                    None => self.link_top(id, parent),
                }
            }
            ZOrder::After(after) => {
                let next = self.at(after).next;
                self.at_mut(id).next = next;
                self.at_mut(after).next = Some(id);
            }
        }
    }

    /// Link `id` at the head of `parent`'s child list.
    fn link_top(&mut self, id: WindowId, parent: WindowId) {
        let head = self.at(parent).child;
        self.at_mut(id).next = head;
        self.at_mut(parent).child = Some(id);
    }

    /// Splice `id` out of `parent`'s child list (the head case or a mid-list walk); a window
    /// that is not in the list is tolerated.
    pub(super) fn unlink_window(&mut self, id: WindowId, parent: WindowId) {
        if self.at(parent).child == Some(id) {
            let next = self.at(id).next;
            self.at_mut(parent).child = next;
            self.at_mut(id).next = None;
            return;
        }
        let mut current = self.at(parent).child;
        while let Some(c) = current {
            if self.at(c).next == Some(id) {
                let next = self.at(id).next;
                self.at_mut(c).next = next;
                self.at_mut(id).next = None;
                return;
            }
            current = self.at(c).next;
        }
        // Unlinking a window that is not in the list.
    }

    /// Put `window` at its new place among its siblings; topmost windows head the list.
    /// HWND_TOPMOST: topmost, at the top. HWND_NOTOPMOST: a topmost window becomes ordinary, at the
    /// top of the others (no effect on another). HWND_BOTTOM: ordinary, at the bottom. HWND_TOP:
    /// the top of its pile. A window to go after must be a sibling; one landing in the other pile
    /// goes to the boundary. Children have no topmost status: HWND_TOPMOST is HWND_TOP,
    /// HWND_NOTOPMOST nothing.
    /// Where `window` is among its siblings: its index from the top and whether it is topmost.
    pub(super) fn z_place(&self, window: WindowId) -> (usize, bool) {
        let topmost = self.at(window).ex_style & WS_EX_TOPMOST != 0;
        let Some(parent) = self.at(window).parent else {
            return (0, topmost);
        };
        let mut index = 0;
        let mut current = self.at(parent).child;
        while let Some(c) = current {
            if c == window {
                break;
            }
            index += 1;
            current = self.at(c).next;
        }
        (index, topmost)
    }

    pub(super) fn reorder(&mut self, window: WindowId, after: InsertAfter) {
        /// Where the window goes.
        enum Place {
            Top,
            Bottom,
            After(WindowId),
            /// After the last topmost sibling (the top of the ordinary windows, the bottom of the
            /// topmost ones).
            Boundary,
        }
        let Some(parent) = self.at(window).parent else {
            return;
        };
        let child = self.at(window).is_child();
        let topmost = |s: &Self, id: WindowId| s.at(id).ex_style & WS_EX_TOPMOST != 0;
        let is_topmost = !child && topmost(self, window);
        let (place, make_topmost) = match after {
            InsertAfter::After(w) => {
                if w == window || !self.pool.is_live(w) || self.at(w).parent != Some(parent) {
                    return;
                }
                if child || topmost(self, w) == is_topmost {
                    (Place::After(w), None)
                } else {
                    (Place::Boundary, None)
                }
            }
            InsertAfter::Top if child || is_topmost => (Place::Top, None),
            InsertAfter::Top => (Place::Boundary, None),
            InsertAfter::TopMost if child => (Place::Top, None),
            InsertAfter::TopMost => (Place::Top, Some(true)),
            InsertAfter::NoTopMost if !is_topmost => return,
            InsertAfter::NoTopMost => (Place::Boundary, Some(false)),
            InsertAfter::Bottom if child => (Place::Bottom, None),
            InsertAfter::Bottom => (Place::Bottom, Some(false)),
        };
        self.unlink_window(window, parent);
        match make_topmost {
            Some(true) => self.at_mut(window).ex_style |= WS_EX_TOPMOST,
            Some(false) => self.at_mut(window).ex_style &= !WS_EX_TOPMOST,
            None => {}
        }
        let z = match place {
            Place::Top => ZOrder::Top,
            Place::Bottom => ZOrder::Bottom,
            Place::After(w) => ZOrder::After(w),
            Place::Boundary => {
                let mut last = None;
                let mut current = self.at(parent).child;
                while let Some(c) = current {
                    if !topmost(self, c) {
                        break;
                    }
                    last = Some(c);
                    current = self.at(c).next;
                }
                last.map_or(ZOrder::Top, ZOrder::After)
            }
        };
        self.link_window(window, z, parent);
    }
}

#[cfg(test)]
mod tests {
    use rtl::user::{WS_CHILD, WS_OVERLAPPED, WS_POPUP};
    use rtl::window::{SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE};

    use super::*;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// The nested-window limit: a child whose parent chain already reaches 100 levels fails with
    /// ERROR_INVALID_PARAMETER (87); at 99 levels it is accepted.
    #[test]
    fn the_nested_window_limit() {
        let (w, c, t, atom, _, _) = setup();
        // A chain of 100 windows, each the parent of the next.
        let mut chain = Vec::new();
        let mut parent = None;
        for _ in 0..100 {
            let id = raw_window(w, t, WS_CHILD, parent);
            chain.push(id);
            parent = Some(id);
        }
        let mut pump = Rec::new(t);
        // The deepest parent gives a chain depth of 101: refused.
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(chain[99]);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        // 99 ancestors give a depth of 100: accepted.
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(chain[98]);
        assert!(Windows::create_window_ex(&mut pump.on(w, c), t, &a).is_ok());
    }

    /// The subtree depth counts the window's own descendants, not its siblings'.
    #[test]
    fn the_subtree_depth_is_the_windows_own() {
        let (w, _c, t, _atom, desk, _) = setup();
        let a = raw_window(w, t, WS_OVERLAPPED, Some(desk));
        let b = raw_window(w, t, WS_OVERLAPPED, Some(desk));
        w.link_window(b, ZOrder::Top, desk);
        w.link_window(a, ZOrder::Top, desk);
        assert_eq!(w.at(a).next, Some(b));
        // b has a chain of 5 below it; a has 2.
        let mut parent = b;
        for _ in 0..5 {
            let id = raw_window(w, t, WS_CHILD, Some(parent));
            w.link_window(id, ZOrder::Bottom, parent);
            parent = id;
        }
        let a1 = raw_window(w, t, WS_CHILD, Some(a));
        w.link_window(a1, ZOrder::Bottom, a);
        let a2 = raw_window(w, t, WS_CHILD, Some(a));
        w.link_window(a2, ZOrder::Bottom, a);
        let a21 = raw_window(w, t, WS_CHILD, Some(a2));
        w.link_window(a21, ZOrder::Bottom, a2);
        assert_eq!(w.subtree_depth(a, 1), 3);
        assert_eq!(w.subtree_depth(b, 1), 6);
        assert_eq!(w.subtree_depth(a21, 4), 4);
    }

    /// The z-order: HWND_TOP and HWND_BOTTOM, after a sibling; the topmost pile heads the list —
    /// HWND_TOPMOST joins it, HWND_NOTOPMOST and HWND_BOTTOM leave it, an ordinary window's
    /// HWND_TOP or a place after a topmost window lands below it; a window to go after that is no
    /// sibling changes nothing; a child has no topmost status.
    #[test]
    fn the_z_order_keeps_the_topmost_pile_first() {
        let (w, c, t, atom, desk, _) = setup();
        let mut pump = Rec::new(t);
        // Created in order, each on top: the list is d c b a.
        let [a, b, cc, d] = [0; 4].map(|_| create(w, c, t, atom, WS_POPUP, &mut pump).unwrap());
        let order = |w: &Windows| {
            let mut list = Vec::new();
            let mut cur = w.at(desk).child;
            while let Some(x) = cur {
                list.push(x);
                cur = w.at(x).next;
            }
            list
        };
        assert_eq!(order(w), vec![d, cc, b, a]);
        let pos = |w: &mut Windows, c: &mut class::Registry, id, after, pump: &mut Rec| {
            Windows::set_window_pos(
                &mut pump.on(w, c),
                id,
                after,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            )
            .unwrap()
        };
        pos(w, c, a, InsertAfter::Top, &mut pump);
        assert_eq!(order(w), vec![a, d, cc, b]);
        pos(w, c, a, InsertAfter::Bottom, &mut pump);
        assert_eq!(order(w), vec![d, cc, b, a]);
        pos(w, c, a, InsertAfter::After(d), &mut pump);
        assert_eq!(order(w), vec![d, a, cc, b]);

        // b joins the topmost pile; an ordinary window's HWND_TOP stays below it.
        pos(w, c, b, InsertAfter::TopMost, &mut pump);
        assert_eq!(order(w), vec![b, d, a, cc]);
        assert_ne!(w.at(b).ex_style & WS_EX_TOPMOST, 0);
        pos(w, c, cc, InsertAfter::Top, &mut pump);
        assert_eq!(order(w), vec![b, cc, d, a]);
        pos(w, c, d, InsertAfter::After(b), &mut pump);
        assert_eq!(order(w), vec![b, d, cc, a], "after the topmost pile");
        // HWND_NOTOPMOST: no effect on an ordinary window; b leaves the pile, on top of the rest.
        pos(w, c, a, InsertAfter::NoTopMost, &mut pump);
        assert_eq!(order(w), vec![b, d, cc, a]);
        pos(w, c, cc, InsertAfter::TopMost, &mut pump);
        assert_eq!(order(w), vec![cc, b, d, a]);
        pos(w, c, cc, InsertAfter::NoTopMost, &mut pump);
        assert_eq!(order(w), vec![b, cc, d, a]);
        assert_eq!(w.at(cc).ex_style & WS_EX_TOPMOST, 0);
        // A topmost window sent to the bottom leaves the pile.
        pos(w, c, b, InsertAfter::Bottom, &mut pump);
        assert_eq!(order(w), vec![cc, d, a, b]);
        assert_eq!(w.at(b).ex_style & WS_EX_TOPMOST, 0);
        // Not a sibling, or the window itself: nothing changes.
        let mut ca = args(atom, WS_CHILD);
        ca.parent = Some(a);
        let kid = Windows::create_window_ex(&mut pump.on(w, c), t, &ca).unwrap();
        pos(w, c, d, InsertAfter::After(kid), &mut pump);
        pos(w, c, d, InsertAfter::After(d), &mut pump);
        assert_eq!(order(w), vec![cc, d, a, b]);
        // A child: HWND_TOPMOST is HWND_TOP, without the topmost bit.
        let kid2 = Windows::create_window_ex(&mut pump.on(w, c), t, &ca).unwrap();
        assert_eq!(w.at(a).child, Some(kid), "children stack at the bottom");
        pos(w, c, kid2, InsertAfter::TopMost, &mut pump);
        assert_eq!(w.at(a).child, Some(kid2));
        assert_eq!(w.at(kid2).ex_style & WS_EX_TOPMOST, 0);
        // The WINDOWPOS carries the insert-after handle.
        let (_, _, last) = *pump.positions.last().unwrap();
        assert_eq!(last.insert_after, HWND_TOPMOST);
    }
}
