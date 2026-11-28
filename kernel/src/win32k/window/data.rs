//! A window's data: its fields as GetWindowLong reads and SetWindowLong changes them, its extra
//! bytes, its text and its relatives.

use rtl::user::{WM_STYLECHANGED, WM_STYLECHANGING};

use super::*;
use crate::win32k::class;
use crate::win32k::text::Text;

impl Windows {
    /// `window`'s own fields as GetWindowLong reads them ([`WindowData`]), for a caller of the
    /// process `caller`: GWL_ID is a child's id and another window's menu handle; GWL_HWNDPARENT
    /// a child's parent and another window's owner; the procedure 0 when it is the window
    /// manager's own.
    pub fn window_data(&self, window: WindowId, caller: class::Owner) -> WindowData {
        let w = self.at(window);
        let id = match w.menu {
            Menu::None => 0,
            Menu::Id(id) => id,
            Menu::Handle(handle) => handle,
        };
        let parent = if w.is_child() { w.parent } else { w.owner };
        let proc = match w.proc {
            Proc::Client(proc) if !w.flags.server_side_proc => proc,
            _ => 0,
        };
        let mut flags = 0;
        if w.flags.ansi_proc {
            flags |= rtl::window::WINDOW_ANSI_PROC;
        }
        if w.process != caller {
            flags |= rtl::window::WINDOW_OTHER_PROCESS;
        }
        if u32::from(w.fnid) == rtl::window::FNID_DIALOG {
            flags |= rtl::window::WINDOW_DIALOG;
        }
        WindowData {
            style: w.style,
            ex_style: w.ex_style,
            id,
            user_data: w.user_data,
            instance: w.module,
            parent: parent.map_or(0, |p| self.at(p).handle),
            proc,
            flags,
            extra: w.cb_wnd_extra.max(0) as u32,
        }
    }

    /// `window`'s relatives ([`rtl::window::WindowLinks`]): its parent (the desktop window for a
    /// top-level window), its owner, its first child, and its siblings after and before it in the
    /// z-order.
    pub fn window_links(&self, window: WindowId) -> rtl::window::WindowLinks {
        let w = self.at(window);
        let handle = |id: Option<WindowId>| id.map_or(0, |id| self.at(id).handle);
        let mut previous = None;
        let mut sibling = w.parent.and_then(|parent| self.at(parent).child);
        while let Some(s) = sibling {
            if s == window {
                break;
            }
            previous = Some(s);
            sibling = self.at(s).next;
        }
        rtl::window::WindowLinks {
            parent: handle(w.parent),
            owner: handle(w.owner),
            child: handle(w.child),
            next: handle(w.next),
            previous: handle(previous),
            last_active: handle(w.last_active.filter(|&id| self.is_live(id))),
        }
    }

    /// `window` became its thread's active window: it is the last active window of its root
    /// owner (the end of its owner chain, itself for an unowned window), as GetLastActivePopup
    /// answers it.
    pub fn note_active(&mut self, window: WindowId) {
        let mut root = window;
        while let Some(owner) = self.at(root).owner {
            root = owner;
        }
        self.at_mut(root).last_active = Some(window);
    }

    /// NtUserSetWindowFNID's decision: `window` marked as the kind of window `fnid` names, for a
    /// caller of the process `caller`. Windows 2000's rules: another process's window is refused,
    /// and so is a window marked already (a mark is set once, for the window's life).
    pub fn set_window_fnid(
        &mut self,
        window: WindowId,
        fnid: u32,
        caller: class::Owner,
    ) -> Result<(), Failure> {
        let w = self.at_mut(window);
        if w.process != caller {
            return Err(Failure::AccessDenied);
        }
        if w.fnid != 0 || fnid == 0 || fnid > u32::from(u16::MAX) {
            return Err(Failure::InvalidParameter);
        }
        w.fnid = fnid as u16;
        Ok(())
    }

    /// `window`'s text, its title.
    pub fn window_text(&self, window: WindowId) -> &[u16] {
        self.texts.units(self.at(window).title)
    }

    /// The name `window`'s creation messages carry, `name` naming it ([`CreateName`]).
    pub fn create_name(&self, window: WindowId, name: CreateName) -> &[u16] {
        self.texts.units(self.create_text(window, name))
    }

    /// The text of [`Windows::create_name`]'s, as the store ([`Windows::texts`]) names it.
    pub fn create_text(&self, window: WindowId, name: CreateName) -> Text {
        let w = self.at(window);
        match name {
            CreateName::Given => w.create_name,
            CreateName::Title => w.title,
        }
    }

    /// The `length` bytes of `window`'s extra bytes at `offset`, where they are; InvalidIndex
    /// when they are not all inside the window's own (a negative offset included).
    fn extra_at(
        &self,
        window: WindowId,
        offset: i32,
        length: usize,
    ) -> Result<(ExtraBlock, usize), Failure> {
        let w = self.at(window);
        let block = w.extra.ok_or(Failure::InvalidIndex)?;
        let offset = usize::try_from(offset).map_err(|_| Failure::InvalidIndex)?;
        if offset + length > w.cb_wnd_extra.max(0) as usize {
            return Err(Failure::InvalidIndex);
        }
        Ok((block, offset))
    }

    /// The `length` (2 or 4) bytes of `window`'s extra bytes at `offset`, as a little-endian
    /// value (GetWindowWord's and GetWindowLong's answer); InvalidIndex outside the window's own.
    pub fn extra_value(
        &self,
        window: WindowId,
        offset: i32,
        length: usize,
    ) -> Result<u32, Failure> {
        let (block, offset) = self.extra_at(window, offset, length)?;
        let bytes = &self.extra.bytes(block)[offset..offset + length];
        Ok(bytes
            .iter()
            .rev()
            .fold(0, |value, &byte| value << 8 | byte as u32))
    }

    /// Write the `length` (2 or 4) bytes of `value` into `window`'s extra bytes at `offset`: the
    /// value they held.
    fn set_extra_value(
        &mut self,
        window: WindowId,
        offset: i32,
        length: usize,
        value: u32,
    ) -> Result<u32, Failure> {
        let previous = self.extra_value(window, offset, length)?;
        let (block, offset) = self.extra_at(window, offset, length)?;
        let bytes = &mut self.extra.bytes_mut(block)[offset..offset + length];
        bytes.copy_from_slice(&value.to_le_bytes()[..length]);
        Ok(previous)
    }

    /// SetWindowLong's change of the window `handle` names, through the narrow (`ansi`) or wide
    /// entry point: the field at `index` (GWL_* or an extra-bytes offset) set to `value`. Answers
    /// the old value and, for GWL_WNDPROC, whether the old procedure was narrow (user32 maps a
    /// procedure of the other form to a handle of its own, as Windows 2000's does).
    ///
    /// GWL_STYLE/GWL_EXSTYLE send WM_STYLECHANGING (the handler may change the new style) and
    /// WM_STYLECHANGED, wParam the index, lParam the STYLESTRUCT. GWL_WNDPROC replaces the
    /// procedure and its form; refused for another process's window. GWL_HWNDPARENT changes a
    /// top-level window's owner (a child's parent is SetParent's: refused). GWL_ID sets a child's
    /// id, another window's menu handle. Another index is InvalidIndex.
    pub fn set_window_long(
        s: &mut dyn Session,
        caller: class::Owner,
        handle: Hwnd,
        index: i32,
        value: u32,
        ansi: bool,
    ) -> Result<(u32, bool), Failure> {
        let windows = s.windows();
        use rtl::window::*;
        let window = windows.window_of(handle)?;
        if index >= 0 {
            return Ok((windows.set_extra_value(window, index, 4, value)?, false));
        }
        let data = windows.window_data(window, caller);
        let previous = match index {
            GWL_STYLE | GWL_EXSTYLE => Windows::set_style(s, window, index, value),
            GWL_ID => {
                let menu = match value {
                    0 => Menu::None,
                    id if windows.at(window).is_child() => Menu::Id(id),
                    menu => Menu::Handle(menu),
                };
                windows.give_menu(window, menu);
                data.id
            }
            GWL_USERDATA => core::mem::replace(&mut windows.at_mut(window).user_data, value),
            GWL_HINSTANCE => core::mem::replace(&mut windows.at_mut(window).module, value),
            GWL_WNDPROC => {
                if windows.at(window).process != caller {
                    return Err(Failure::AccessDenied);
                }
                let w = windows.at_mut(window);
                let was_ansi = w.flags.ansi_proc;
                w.proc = Proc::Client(value);
                w.flags.ansi_proc = ansi;
                w.flags.server_side_proc = false;
                return Ok((data.proc, was_ansi));
            }
            GWL_HWNDPARENT => {
                if windows.at(window).is_child() {
                    return Err(Failure::InvalidParameter);
                }
                let owner = match value {
                    0 => None,
                    owner => Some(windows.window_of(owner)?),
                };
                if !windows.validate_owner_depth(window, owner) {
                    return Err(Failure::InvalidParameter);
                }
                windows.at_mut(window).owner = owner;
                data.parent
            }
            _ => return Err(Failure::InvalidIndex),
        };
        Ok((previous, false))
    }

    /// GWL_STYLE's or GWL_EXSTYLE's change (`index`) of `window` to `value`, between the
    /// WM_STYLECHANGING and WM_STYLECHANGED the window is sent: the style it had.
    fn set_style(s: &mut dyn Session, window: WindowId, index: i32, value: u32) -> u32 {
        let windows = s.windows();
        fn field(w: &mut Window, index: i32) -> &mut u32 {
            if index == rtl::window::GWL_STYLE {
                &mut w.style
            } else {
                &mut w.ex_style
            }
        }
        let old = *field(windows.at_mut(window), index);
        // The private ANSI-creator bit is never an extended style a window holds.
        let value = if index == rtl::window::GWL_EXSTYLE {
            value & !ANSI_CREATOR_BIT
        } else {
            value
        };
        let mut changing = Message {
            message: WM_STYLECHANGING,
            wparam: index as WParam,
            lparam: 0,
            payload: Payload::Style(StyleStruct {
                style_old: old,
                style_new: value,
            }),
        };
        s.send(window, &mut changing);
        let windows = s.windows();
        // The handler's new style sticks, as Windows 2000's SetWindowLong takes it (the private
        // ANSI-creator bit kept off the extended style still).
        let new = match changing.payload {
            Payload::Style(style) if index == rtl::window::GWL_EXSTYLE => {
                style.style_new & !ANSI_CREATOR_BIT
            }
            Payload::Style(style) => style.style_new,
            _ => value,
        };
        // A handler may have destroyed the window.
        if !windows.pool.is_live(window) {
            return old;
        }
        *field(windows.at_mut(window), index) = new;
        s.send(
            window,
            &mut Message {
                message: WM_STYLECHANGED,
                wparam: index as WParam,
                lparam: 0,
                payload: Payload::Style(StyleStruct {
                    style_old: old,
                    style_new: new,
                }),
            },
        );
        old
    }

    /// SetWindowWord's change of the window `handle` names: the word at `offset` in its extra
    /// bytes set to `value`; the word it held. InvalidIndex outside the window's own.
    pub fn set_window_word(
        &mut self,
        handle: Hwnd,
        offset: i32,
        value: u16,
    ) -> Result<u16, Failure> {
        let window = self.window_of(handle)?;
        Ok(self.set_extra_value(window, offset, 2, value as u32)? as u16)
    }

    /// The window `handle` names given the text `units` (DefWindowProc's WM_SETTEXT, and its
    /// WM_NCCREATE's title), whole: OutOfMemory, the text unchanged, when the store has no room
    /// for it.
    pub fn set_window_text(&mut self, handle: Hwnd, units: &[u16]) -> Result<(), Failure> {
        let window = self.window_of(handle)?;
        let mut title = self.at(window).title;
        if !self.texts.replace(&mut title, units) {
            return Err(Failure::OutOfMemory);
        }
        self.at_mut(window).title = title;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{
        WS_CAPTION,
        WS_CHILD,
        WS_EX_TOOLWINDOW,
        WS_OVERLAPPED,
        WS_SYSMENU,
        WS_THICKFRAME,
    };

    use super::*;
    use crate::win32k::class::RegisterFlags;
    use crate::win32k::handle::UserHandles;
    use crate::win32k::window::testkit::*;

    /// A class of `extra` window extra bytes, registered through the narrow form when `ansi`.
    fn register_data_class(
        c: &mut class::Registry,
        handles: &UserHandles,
        name: &str,
        extra: i32,
        ansi: bool,
    ) -> class::Atom {
        let mut wc = wnd_class();
        wc.cb_wnd_extra = extra;
        let flags = RegisterFlags {
            ansi_proc: ansi,
            ..compat40()
        };
        c.register_class(
            handles,
            &wc,
            class::Name::Text(&wide(name)),
            class::MenuArg::None,
            OWNER,
            flags,
            DESKTOP,
        )
        .unwrap()
    }

    /// The extra bytes: zeroed at creation, read and written as LONGs and WORDs little-endian,
    /// refused past their end and at a negative offset (ERROR_INVALID_INDEX), a window of a class
    /// with none has none; the arena's granules go back with the window.
    #[test]
    fn the_extra_bytes() {
        let (w, c, t, _, _, _) = setup();
        let atom = register_data_class(c, &w.handles, "Extra", 12, false);
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let h = w.handle_of(id);
        assert_eq!(w.extra.taken_granules(), 1);
        for offset in [0, 4, 8] {
            assert_eq!(w.extra_value(id, offset, 4), Ok(0));
        }
        let mut set = |w: &mut Windows, index: i32, value: u32| {
            Windows::set_window_long(&mut pump.on(w, c), OWNER, h, index, value, false)
                .map(|(previous, _)| previous)
        };
        assert_eq!(set(w, 0, 0x1111_1111), Ok(0));
        assert_eq!(set(w, 4, 0x2222_2222), Ok(0));
        assert_eq!(set(w, 8, 0x3333_3333), Ok(0));
        assert_eq!(set(w, 0, 0x4444_4444), Ok(0x1111_1111));
        assert_eq!(w.extra_value(id, 2, 4), Ok(0x2222_4444));
        for index in [9, 12, -100] {
            assert_eq!(set(w, index, 1), Err(Failure::InvalidIndex));
        }
        assert_eq!(w.extra_value(id, 9, 4), Err(Failure::InvalidIndex));
        assert_eq!(w.set_window_word(h, 0, 0xABCD), Ok(0x4444));
        assert_eq!(w.extra_value(id, 0, 4), Ok(0x4444_ABCD));
        assert_eq!(w.set_window_word(h, 10, 0x1234), Ok(0x3333));
        assert_eq!(w.extra_value(id, 8, 4), Ok(0x1234_3333));
        assert_eq!(w.set_window_word(h, 11, 1), Err(Failure::InvalidIndex));
        assert_eq!(w.extra_value(id, 11, 2), Err(Failure::InvalidIndex));
        assert_eq!(w.window_data(id, OWNER).extra, 12);

        let none = register_data_class(c, &w.handles, "None", 0, false);
        let plain = create(w, c, t, none, WS_OVERLAPPED, &mut pump).unwrap();
        assert_eq!(w.extra_value(plain, 0, 4), Err(Failure::InvalidIndex));

        assert!(Windows::destroy_window(&mut pump.on(w, c), t, id).unwrap());
        assert_eq!(w.extra.taken_granules(), 0);
        assert_eq!(
            w.set_window_word(h, 0, 1),
            Err(Failure::InvalidWindowHandle)
        );
    }

    /// GWL_STYLE and GWL_EXSTYLE: WM_STYLECHANGING then WM_STYLECHANGED, their wParam the index,
    /// the new style stored, the old one answered; the ANSI-creator bit is never stored.
    #[test]
    fn the_style_changes_send_their_messages() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_CAPTION, &mut pump).unwrap();
        let h = w.handle_of(id);
        let style = w.at(id).style;
        pump.events.clear();
        assert_eq!(
            Windows::set_window_long(
                &mut pump.on(w, c),
                OWNER,
                h,
                rtl::window::GWL_STYLE,
                style | WS_THICKFRAME,
                false
            ),
            Ok((style, false))
        );
        assert_eq!(w.at(id).style, style | WS_THICKFRAME);
        assert_eq!(
            pump.events,
            [
                Ev::Send(id, WM_STYLECHANGING, -16i32 as u32, 0),
                Ev::Send(id, WM_STYLECHANGED, -16i32 as u32, 0),
            ]
        );
        let ex = w.at(id).ex_style;
        assert_eq!(
            Windows::set_window_long(
                &mut pump.on(w, c),
                OWNER,
                h,
                rtl::window::GWL_EXSTYLE,
                ex | WS_EX_TOOLWINDOW | ANSI_CREATOR_BIT,
                false
            ),
            Ok((ex, false))
        );
        assert_eq!(w.at(id).ex_style, ex | WS_EX_TOOLWINDOW);
    }

    /// A WM_STYLECHANGING handler's new style sticks, and WM_STYLECHANGED reports it (Windows
    /// 2000's SetWindowLong takes the STYLESTRUCT back); its extended style still loses the
    /// private ANSI-creator bit.
    #[test]
    fn a_style_changing_handlers_new_style_sticks() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let id = create(w, c, t, atom, WS_OVERLAPPED | WS_CAPTION, &mut pump).unwrap();
        let h = w.handle_of(id);
        let style = w.at(id).style;
        pump.style_answer = Some(style | WS_THICKFRAME);
        assert_eq!(
            Windows::set_window_long(
                &mut pump.on(w, c),
                OWNER,
                h,
                rtl::window::GWL_STYLE,
                style | WS_SYSMENU,
                false
            ),
            Ok((style, false))
        );
        assert_eq!(w.at(id).style, style | WS_THICKFRAME);
        let ex = w.at(id).ex_style;
        pump.style_answer = Some(ex | WS_EX_TOOLWINDOW | ANSI_CREATOR_BIT);
        assert_eq!(
            Windows::set_window_long(
                &mut pump.on(w, c),
                OWNER,
                h,
                rtl::window::GWL_EXSTYLE,
                ex,
                false
            ),
            Ok((ex, false))
        );
        assert_eq!(w.at(id).ex_style, ex | WS_EX_TOOLWINDOW);
    }

    /// The window's own fields: GWL_USERDATA, GWL_HINSTANCE and a child's GWL_ID set and answered,
    /// GWL_HWNDPARENT a child's parent and a top-level window's owner; the procedure and its form,
    /// replaced by GWL_WNDPROC (another process's window refused); an unknown index refused; the
    /// text set and read back.
    #[test]
    fn the_window_data() {
        let (w, c, t, _, _, _) = setup();
        let atom = register_data_class(c, &w.handles, "Narrow", 0, true);
        let mut pump = Rec::new(t);
        let top = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap();
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(top);
        a.menu = MenuInput::Id(77);
        let child = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let (ht, hc) = (w.handle_of(top), w.handle_of(child));

        let data = w.window_data(child, OWNER);
        assert_eq!((data.id, data.parent, data.instance), (77, ht, MODULE));
        assert_eq!(data.proc, 0x0040_1000);
        assert_eq!(data.flags, rtl::window::WINDOW_ANSI_PROC);
        assert_eq!(
            w.window_data(child, OTHER_OWNER).flags,
            rtl::window::WINDOW_ANSI_PROC | rtl::window::WINDOW_OTHER_PROCESS
        );
        assert_eq!(
            (
                w.window_data(top, OWNER).id,
                w.window_data(top, OWNER).parent
            ),
            (0, 0)
        );

        let mut set = |w: &mut Windows, h: Hwnd, index: i32, value: u32, ansi: bool| {
            Windows::set_window_long(&mut pump.on(w, c), OWNER, h, index, value, ansi)
        };
        assert_eq!(set(w, hc, rtl::window::GWL_ID, 88, false), Ok((77, false)));
        assert_eq!(w.window_data(child, OWNER).id, 88);
        assert_eq!(
            set(w, ht, rtl::window::GWL_USERDATA, 0x1234_5678, false),
            Ok((0, false))
        );
        assert_eq!(
            set(w, ht, rtl::window::GWL_USERDATA, -5i32 as u32, true),
            Ok((0x1234_5678, false))
        );
        assert_eq!(w.window_data(top, OWNER).user_data, -5i32 as u32);
        assert_eq!(
            set(w, ht, rtl::window::GWL_HINSTANCE, 0x50_0000, false),
            Ok((MODULE, false))
        );
        assert_eq!(set(w, ht, -2, 1, false), Err(Failure::InvalidIndex));

        assert_eq!(
            set(w, ht, rtl::window::GWL_WNDPROC, 0x0040_2000, false),
            Ok((0x0040_1000, true))
        );
        let data = w.window_data(top, OWNER);
        assert_eq!((data.proc, data.flags), (0x0040_2000, 0));
        assert_eq!(
            set(w, ht, rtl::window::GWL_WNDPROC, 0x0040_1000, true),
            Ok((0x0040_2000, false))
        );
        assert_eq!(
            Windows::set_window_long(
                &mut pump.on(w, c),
                OTHER_OWNER,
                ht,
                rtl::window::GWL_WNDPROC,
                1,
                false
            ),
            Err(Failure::AccessDenied)
        );

        assert_eq!(w.set_window_text(ht, &wide("a title")), Ok(()));
        assert_eq!(w.window_text(top), &wide("a title")[..]);
        assert_eq!(
            w.set_window_text(0x7FFF_FFFC, &[]),
            Err(Failure::InvalidWindowHandle)
        );
    }
}
