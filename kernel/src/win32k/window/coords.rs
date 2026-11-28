//! The coordinates a window's position is relative to, and its descendants moved with it.

use super::*;

impl Windows {
    /// The screen position of the origin `window`'s coordinates are relative to: its parent's
    /// client area for a child window, the screen's for any other.
    pub(super) fn parent_origin(&self, window: WindowId) -> (i32, i32) {
        let w = self.at(window);
        match w.parent {
            Some(p) if w.is_child() && self.pool.is_live(p) => {
                let client = self.at(p).client_rect;
                (client.left, client.top)
            }
            _ => (0, 0),
        }
    }

    /// The position of `window`'s client area as WM_MOVE reports it: in its parent's client
    /// coordinates for a child window, in screen coordinates for any other.
    pub(super) fn client_position(&self, window: WindowId) -> (i32, i32) {
        let client = self.at(window).client_rect;
        let origin = self.parent_origin(window);
        (
            client.left.saturating_sub(origin.0),
            client.top.saturating_sub(origin.1),
        )
    }

    /// Move every window below `window` (its children, theirs, and so on) by `dx`, `dy`: their
    /// rectangles are in screen coordinates, and they keep their place in their parents' client
    /// areas. The walk follows the child, sibling and parent links, without recursing.
    pub(super) fn offset_descendants(&mut self, window: WindowId, dx: i32, dy: i32) {
        if dx == 0 && dy == 0 {
            return;
        }
        let Some(mut current) = self.at(window).child else {
            return;
        };
        loop {
            {
                let w = self.at_mut(current);
                w.window_rect = w.window_rect.saturating_offset(dx, dy);
                w.client_rect = w.client_rect.saturating_offset(dx, dy);
            }
            if let Some(child) = self.at(current).child {
                current = child;
                continue;
            }
            loop {
                if let Some(next) = self.at(current).next {
                    current = next;
                    break;
                }
                current = self.at(current).parent.expect("a child has its parent");
                if current == window {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::gdi::Rect;
    use rtl::user::{WS_CHILD, WS_POPUP};

    use super::*;

    /// A window moved near i32's end carries its children along: one lying past the window's
    /// right edge is moved with it, its rectangle saturated at i32::MAX.
    #[test]
    fn children_moved_past_i32s_end_saturate() {
        use crate::win32k::queue::{rig, QueueSession};
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let parent = rig::window_at(m, atom, t, WS_POPUP, 0, 0, 0, 100, 100);
        let child = rig::window_at(m, atom, t, WS_CHILD, parent, 300, 0, 50, 10);
        assert_eq!(
            WindowManager::move_window(
                &mut QueueSession::new(&mut m.windows, &mut m.classes),
                parent,
                0x7FFF_FF00,
                0,
                100,
                100,
                true
            ),
            Ok(())
        );
        let child = m.windows.window_of(child).unwrap();
        assert_eq!(
            m.windows.window_rect(child),
            Rect {
                left: i32::MAX,
                top: 0,
                right: i32::MAX,
                bottom: 10
            }
        );
    }
}
