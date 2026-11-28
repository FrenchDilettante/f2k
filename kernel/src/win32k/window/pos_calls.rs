//! SetWindowPos and MoveWindow over handles, as the services call them.

use rtl::window::{SWP_NOACTIVATE, SWP_NOREDRAW, SWP_NOZORDER};

use super::*;

impl Windows {
    /// The window `handle` names; ERROR_INVALID_WINDOW_HANDLE for none.
    pub fn window_of(&self, handle: Hwnd) -> Result<WindowId, Failure> {
        self.window_from_handle(handle)
            .ok_or(Failure::InvalidWindowHandle)
    }

    /// The services' SetWindowPos over handles: the window and, unless SWP_NOZORDER, the
    /// insert-after handle (HWND_TOP, HWND_BOTTOM, HWND_TOPMOST, HWND_NOTOPMOST or a window) must
    /// name something; ERROR_INVALID_WINDOW_HANDLE otherwise.
    #[allow(clippy::too_many_arguments)]
    pub fn set_window_pos_handle(
        s: &mut dyn Session,
        handle: Hwnd,
        insert_after: Hwnd,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> Result<(), Failure> {
        let windows = s.windows();
        let window = windows.window_of(handle)?;
        let after = if flags & SWP_NOZORDER != 0 {
            InsertAfter::Top
        } else {
            windows
                .insert_after_of(insert_after)
                .ok_or(Failure::InvalidWindowHandle)?
        };
        Windows::set_window_pos(s, window, after, x, y, cx, cy, flags)
    }

    /// The insert-after handle's meaning: a special handle, or a live window; none otherwise.
    pub(super) fn insert_after_of(&self, handle: Hwnd) -> Option<InsertAfter> {
        Some(match handle {
            HWND_TOP => InsertAfter::Top,
            HWND_BOTTOM => InsertAfter::Bottom,
            HWND_TOPMOST => InsertAfter::TopMost,
            HWND_NOTOPMOST => InsertAfter::NoTopMost,
            handle => InsertAfter::After(self.window_from_handle(handle)?),
        })
    }

    /// The handle WINDOWPOS's hwndInsertAfter carries for `after`.
    pub(super) fn insert_after_handle(&self, after: InsertAfter) -> Hwnd {
        match after {
            InsertAfter::Top => HWND_TOP,
            InsertAfter::Bottom => HWND_BOTTOM,
            InsertAfter::TopMost => HWND_TOPMOST,
            InsertAfter::NoTopMost => HWND_NOTOPMOST,
            InsertAfter::After(w) => self.at(w).handle,
        }
    }
}

impl WindowManager {
    /// NtUserMoveWindow's decision over a handle: MoveWindow is SetWindowPos with the window's
    /// place in the z-order and the activation left alone, and without the redraw when `repaint`
    /// is false (the MoveWindow documentation).
    pub fn move_window(
        s: &mut dyn Session,
        handle: Hwnd,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        repaint: bool,
    ) -> Result<(), Failure> {
        let flags = SWP_NOZORDER | SWP_NOACTIVATE | if repaint { 0 } else { SWP_NOREDRAW };
        Windows::set_window_pos_handle(s, handle, HWND_TOP, x, y, cx, cy, flags)
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::WS_OVERLAPPEDWINDOW;
    use rtl::window::{QUERY_WINDOW_INFO, QUERY_WINDOW_VISIBLE, SWP_NOMOVE, SWP_NOSIZE};

    use super::*;
    use crate::win32k::class;
    use crate::win32k::window::testkit::*;

    /// The geometry block of the capture: MoveWindow and SetWindowPos at explicit coordinates,
    /// GetWindowRect's rectangle read back through the query; SetWindowPos changing the z-order
    /// alone; the bogus-handle errors.
    #[test]
    fn move_and_set_pos_read_back_as_the_capture() {
        let m = manager();
        m.boot_desktop(DESKTOP, SCREEN).unwrap();
        register(
            &mut m.classes,
            &m.windows.handles,
            class::Name::Text(&wide("App")),
            &wnd_class(),
        );
        let t = m
            .windows
            .connect_thread(key(1, 0), OWNER, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
            .unwrap();
        let name = wide("App");
        let mut a = args(0, WS_OVERLAPPEDWINDOW);
        a.class_name = class::Name::Text(&name);
        (a.x, a.y, a.cx, a.cy) = (0, 0, 320, 200);
        let h = WindowManager::create_window(
            &mut DefaultSession::new(&mut m.windows, &mut m.classes),
            t,
            0,
            &mut a,
        )
        .unwrap();
        let rect =
            |m: &WindowManager| match m.query_window(h, QUERY_WINDOW_INFO, 60, OWNER).unwrap() {
                Query::Info(info) => {
                    assert_eq!(info.size, 60);
                    let r = info.window;
                    (r.left, r.top, r.right, r.bottom)
                }
                other => panic!("{other:?}"),
            };
        assert_eq!(rect(m), (0, 0, 320, 200));
        assert_eq!(
            WindowManager::move_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                h,
                100,
                100,
                300,
                250,
                true
            ),
            Ok(())
        );
        assert_eq!(rect(m), (100, 100, 400, 350));
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut DefaultSession::new(windows, classes),
                h,
                HWND_TOP,
                50,
                60,
                200,
                150,
                SWP_NOACTIVATE
            ),
            Ok(())
        );
        assert_eq!(rect(m), (50, 60, 250, 210));
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut DefaultSession::new(windows, classes),
                h,
                HWND_TOP,
                0,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOMOVE
            ),
            Ok(())
        );
        assert_eq!(rect(m), (50, 60, 250, 210));

        let bogus = 0x7FFF_FFFC;
        assert_eq!(
            WindowManager::move_window(
                &mut DefaultSession::new(&mut m.windows, &mut m.classes),
                bogus,
                1,
                2,
                3,
                4,
                true
            ),
            Err(Failure::InvalidWindowHandle)
        );
        assert_eq!(
            m.query_window(bogus, QUERY_WINDOW_INFO, 60, OWNER),
            Err(Failure::InvalidWindowHandle)
        );
        assert_eq!(
            m.query_window(bogus, QUERY_WINDOW_VISIBLE, 4, OWNER),
            Err(Failure::InvalidWindowHandle)
        );
        let WindowManager {
            windows, classes, ..
        } = &mut *m;
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut DefaultSession::new(windows, classes),
                bogus,
                HWND_TOP,
                0,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOMOVE
            ),
            Err(Failure::InvalidWindowHandle)
        );
        // A bogus insert-after handle, unless the z-order is left alone.
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut DefaultSession::new(windows, classes),
                h,
                bogus,
                0,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOMOVE
            ),
            Err(Failure::InvalidWindowHandle)
        );
        assert_eq!(
            Windows::set_window_pos_handle(
                &mut DefaultSession::new(windows, classes),
                h,
                bogus,
                0,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER
            ),
            Ok(())
        );
    }
}
