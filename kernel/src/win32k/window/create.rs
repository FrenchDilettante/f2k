//! CreateWindowEx's decision: the validation gates, the class, the record and its wiring; the
//! placement ([`super::create_place`]) and the messages ([`super::create_messages`]) follow.

use rtl::gdi::Rect;
use rtl::user::{
    CS_CLASSDC,
    CS_OWNDC,
    CS_PARENTDC,
    WS_CAPTION,
    WS_CLIPCHILDREN,
    WS_CLIPSIBLINGS,
    WS_DLGFRAME,
    WS_EX_DLGMODALFRAME,
    WS_EX_LAYERED,
    WS_EX_STATICEDGE,
    WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST,
    WS_EX_WINDOWEDGE,
    WS_THICKFRAME,
    WS_VISIBLE,
};

use super::create_messages::Creation;
use super::create_place::Placement;
use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;
use crate::win32k::handle::{Refusal, UserObject};

/// Whether a window of this style/ex-style gets the WS_EX_WINDOWEDGE bit: the dialog-modal
/// frame and the thick frame force it, the static edge forbids it, a caption gets it from a
/// 4.0-or-later app, and a dialog frame always.
fn needs_window_edge(style: u32, ex_style: u32, new_app: bool) -> bool {
    if ex_style & WS_EX_DLGMODALFRAME != 0 {
        true
    } else if ex_style & WS_EX_STATICEDGE != 0 {
        false
    } else if style & WS_THICKFRAME != 0 {
        true
    } else {
        match style & WS_CAPTION {
            WS_DLGFRAME => true,
            WS_CAPTION => new_app,
            _ => false,
        }
    }
}

impl Windows {
    /// The creation decision logic: validate, resolve the class, allocate and wire the record,
    /// position it, and run the message sequence. The answer is the new window's id; the
    /// service answers its handle.
    pub fn create_window_ex(
        s: &mut dyn Session,
        caller: ThreadId,
        args: &CreateArgs,
    ) -> Result<WindowId, Failure> {
        let (windows, classes) = s.parts();
        // The private ANSI-creator bit is consumed here, never stored on the window.
        let ansi_creator = args.ex_style & ANSI_CREATOR_BIT != 0;
        let mut ex_style = args.ex_style & !ANSI_CREATOR_BIT;

        let (process, desktop_id) = {
            let thread = windows.thread(caller);
            (thread.process, thread.desktop)
        };

        // A parent on another desktop is refused before anything else is looked at.
        if let Some(parent) = args.parent {
            if windows.at(parent).desktop != desktop_id {
                return Err(Failure::InvalidParameter);
            }
        }

        let child = kind_of(args.style) == Kind::Child;

        // The desktop access check. It is skipped while the thread has no desktop handle yet:
        // that is the root desktop window's own creation.
        {
            let thread = windows.thread(caller);
            if thread.desktop_handle.is_some() && thread.desktop_access & DESKTOP_CREATEWINDOW == 0
            {
                return Err(Failure::AccessDenied);
            }
        }

        // A child window needs a parent, and the parent chain has a depth limit.
        if child {
            let Some(parent) = args.parent else {
                return Err(Failure::TlwWithWsChild);
            };
            if !windows.validate_parent_depth(None, Some(parent)) {
                return Err(Failure::InvalidParameter);
            }
        }

        // Class resolution: atom 0 (a string name with no atom) fails, and so does a class the
        // calling process cannot see. A null module looks classes up as the client module.
        let atom = args.class_atom;
        if atom == 0 {
            return Err(Failure::CannotFindWindowClass);
        }
        let module = if args.instance == 0 {
            class::CLIENT_MODULE
        } else {
            args.instance
        };
        let Some(class_id) = classes.class_ptr(atom, process, module) else {
            return Err(Failure::CannotFindWindowClass);
        };
        let info = classes
            .get_class_info(class::Name::Atom(atom), Some(module), process, true)
            .map_err(|_| Failure::CannotFindWindowClass)?;

        // The edge style decision.
        let compat = VersionCompat::of(args.version);
        if needs_window_edge(args.style, ex_style, compat.win40) {
            ex_style |= WS_EX_WINDOWEDGE;
        } else {
            ex_style &= !WS_EX_WINDOWEDGE;
        }

        // The record and its handle.
        let Some(id) = windows.pool.allocate() else {
            return Err(Failure::OutOfMemory);
        };
        let entry = UserObject::Window(WindowEntry {
            id,
            owner: caller,
            marked_destroy: false,
            in_destroy: false,
        });
        let handle = match windows.handles.insert(Some(process), entry) {
            Ok(handle) => handle,
            Err(refusal) => {
                windows.pool.free(id);
                return Err(match refusal {
                    Refusal::NoMoreUserHandles => Failure::NoMoreUserHandles,
                    Refusal::NoMemory => Failure::OutOfMemory,
                });
            }
        };
        {
            let monitor = windows.thread(caller).monitor.unwrap_or(PRIMARY_MONITOR);
            let w = windows.at_mut(id);
            w.handle = handle;
            w.thread = caller;
            w.process = process;
            w.desktop = desktop_id;
            w.monitor = monitor;
            w.style = args.style & !WS_VISIBLE; // WS_VISIBLE is stripped from the stored style
            w.ex_style = ex_style & !WS_EX_LAYERED; // so is the layered bit
            w.class = Some(class_id);
            w.cb_wnd_extra = info.cb_wnd_extra;
            w.locks = 1;
        }

        // The window's extra bytes, zeroed, allocated with it as Windows 2000 allocates them with
        // the window from its desktop's heap; none to allocate fails the creation.
        if info.cb_wnd_extra > 0 {
            let Some(block) = windows.extra.allocate(info.cb_wnd_extra as usize) else {
                windows.handles.close(handle);
                windows.pool.free(id);
                return Err(Failure::OutOfMemory);
            };
            windows.at_mut(id).extra = Some(block);
        }

        // The class reference (a class of another desktop is cloned for the window; a clone
        // failure frees the record and takes the class failure path).
        let mut view = class::Window {
            class: class_id,
            owner: process,
            desktop: desktop_id,
        };
        if !classes.reference_class(class_id, &mut view) {
            if let Some(block) = windows.at_mut(id).extra.take() {
                windows.extra.free(block);
            }
            windows.handles.close(handle);
            windows.pool.free(id);
            return Err(Failure::CannotFindWindowClass);
        }
        windows.at_mut(id).class = Some(view.class);

        // The window count goes up early, so the failure paths keep it correct through the free.
        windows.thread_mut(caller).window_count += 1;

        // The name the creation was given, kept for its messages: no room for it fails it.
        let Some(name) = windows.texts.store(args.name) else {
            Windows::rollback_create(s, caller, id);
            return Err(Failure::OutOfMemory);
        };
        let windows = s.windows();
        windows.at_mut(id).create_name = name;

        // The create parameters the WM_NCCREATE and WM_CREATE handlers see.
        let mut params = CreateParams {
            ex_style,
            class_name: match args.class_name {
                class::Name::Atom(a) => ClassArg::Atom(a),
                class::Name::Text(_) if ansi_creator => ClassArg::AnsiName,
                class::Name::Text(_) => ClassArg::Name,
            },
            name: CreateName::Given,
            style: args.style,
            x: args.x,
            y: args.y,
            cx: args.cx,
            cy: args.cy,
            parent: args.parent.map_or(0, |p| windows.at(p).handle),
            menu: if child {
                args.menu.raw()
            } else {
                args.menu.handle()
            },
            instance: args.instance,
            params: args.params,
        };

        // While callbacks run the parent pointer is the desktop's message window, so a parent
        // always exists.
        let desktop = windows.desktop_by_id(desktop_id);
        let desktop_window = desktop.and_then(|d| d.window);
        let message_window = desktop.and_then(|d| d.message_window);
        windows.at_mut(id).parent = message_window;

        // The module and the window procedure are stored before any callback.
        // A class with a narrow form of its procedure (user32's own) gives a narrow caller's
        // window that form: its creator's form decides whether it is a Unicode window.
        {
            let w = windows.at_mut(id);
            w.module = args.instance;
            if ansi_creator && info.wnd_proc_ansi != 0 {
                w.proc = Proc::Client(info.wnd_proc_ansi);
                w.flags.ansi_proc = true;
            } else {
                w.proc = Proc::Client(info.wnd_proc);
                w.flags.ansi_proc = info.ansi_proc;
            }
        }
        {
            let w = windows.at_mut(id);
            w.flags.ansi_creator = ansi_creator;
            w.flags.win31_compat = compat.win31;
            w.flags.win40_compat = compat.win40;
        }

        // A hook can veto the creation outright.
        if s.cbt_create_veto(id, &mut params) {
            Windows::rollback_create(s, caller, id);
            return Err(Failure::OutOfMemory);
        }
        let windows = s.windows();

        let Placement {
            z_order,
            tiled,
            x,
            y,
            cx,
            cy,
            mut src,
            sw,
        } = windows.place_new_window(caller, id, args, child, desktop_window);

        // The class menu when no menu was given (top-level windows only); a load failure is
        // tolerated and leaves the window without a menu.
        let mut menu = args.menu;
        if !child && menu.is_none() && info.menu_name != class::MenuName::None {
            if let Some(handle) = s.load_class_menu(info.instance, &info.menu_name) {
                menu = MenuInput::Handle(handle);
                params.menu = handle;
            }
        }
        let windows = s.windows();
        let menu = if child {
            menu.as_child_menu()
        } else {
            menu.as_window_menu()
        };
        windows.give_menu(id, menu);

        // Owner and parent wiring for top-level windows: the owner is the parent's top-level
        // window; the parent itself becomes the desktop window (a message-window parent stays).
        let mut parent = args.parent;
        if !child {
            {
                let w = windows.at_mut(id);
                w.last_active = Some(id);
                w.owner = None;
            }
            if let Some(p) = parent {
                if Some(p) != message_window && Some(p) != desktop_window {
                    let owner = windows.top_level_window(p);
                    if !windows.validate_owner_depth(id, owner) {
                        Windows::rollback_create(s, caller, id);
                        return Err(Failure::OutOfMemory);
                    }
                    let windows = s.windows();
                    {
                        let owner_topmost =
                            owner.is_some_and(|o| windows.at(o).ex_style & WS_EX_TOPMOST != 0);
                        let w = windows.at_mut(id);
                        w.owner = owner;
                        // A window must sit above a topmost owner.
                        if owner_topmost {
                            w.ex_style |= WS_EX_TOPMOST;
                        }
                    }
                    // An owner on another thread shares input state.
                    if let Some(o) = owner {
                        let owner_thread = windows.at(o).thread;
                        if owner_thread != caller {
                            s.attach_input(caller, owner_thread, true);
                        }
                    }
                }
            }
            if parent.is_none() || parent != message_window {
                parent = desktop_window;
            }
        }
        let windows = s.windows();
        if let Some(p) = parent {
            windows.at_mut(id).parent = Some(p);
        }

        // The CS_PARENTDC compat hack (skipped for pre-4.0 windows): the class style overrides
        // the clip bits unless the parent clips children.
        if !windows.at(id).flags.win31_compat && info.style & CS_PARENTDC != 0 {
            if let Some(p) = parent {
                if windows.at(p).style & WS_CLIPCHILDREN == 0 {
                    let w = windows.at_mut(id);
                    w.style &= !(WS_CLIPCHILDREN | WS_CLIPSIBLINGS);
                }
            }
        }

        // A child of another thread's parent shares input state.
        if child {
            if let Some(p) = parent {
                if Some(p) != desktop_window && windows.at(p).thread != caller {
                    let parent_thread = windows.at(p).thread;
                    s.attach_input(caller, parent_thread, true);
                }
            }
        }

        // Size clamping (WM_GETMINMAXINFO, the creation's first message to a tiled or thick-framed
        // window), the full-screen check, negative sizes, and the final window rect.
        Windows::adjust_size(s, id, &mut src.cx, &mut src.cy);
        if Windows::gone_in_creation(s, id) {
            return Err(Failure::Refused);
        }
        if !child && ex_style & WS_EX_TOOLWINDOW == 0 {
            s.check_full_screen(id, &mut src);
        }
        let windows = s.windows();
        if src.cx < 0 {
            src.cx = 0;
        }
        if src.cy < 0 {
            src.cy = 0;
        }
        {
            let w = windows.at_mut(id);
            w.window_rect = Rect {
                left: src.x,
                top: src.y,
                right: src.x.saturating_add(src.cx),
                bottom: src.y.saturating_add(src.cy),
            };
        }

        // Layered windows and class/own DCs: a failure rolls the creation back.
        if ex_style & WS_EX_LAYERED != 0 && !s.set_layered(id) {
            Windows::rollback_create(s, caller, id);
            return Err(Failure::OutOfMemory);
        }
        if info.style & (CS_OWNDC | CS_CLASSDC) != 0
            && !s.create_window_dc(id, info.style & CS_OWNDC != 0)
        {
            Windows::rollback_create(s, caller, id);
            return Err(Failure::OutOfMemory);
        }

        Windows::create_messages(
            s,
            args,
            Creation {
                caller,
                id,
                child,
                tiled,
                ex_style,
                parent,
                message_window,
                desktop_window,
                z_order,
                sw,
                x,
                y,
                cx,
                cy,
                params,
            },
        )
    }

    /// Whether the window `id` went while its creation sent it a message: freed, or on its way
    /// (a procedure that destroyed it, WM_DESTROY sent already); its creation then answers NULL.
    pub(super) fn gone_in_creation(s: &mut dyn Session, id: WindowId) -> bool {
        let windows = s.windows();
        !windows.pool.is_live(id)
            || windows.at(id).flags.destroyed
            || windows.at(id).flags.destroying
    }

    /// The shared rollback path of the create's failure points: mark the window destroyed, make
    /// sure it is not treated as visible, and free it (which sends WM_NCDESTROY, destroys any
    /// children, dereferences the class, drops the window count and frees the record and handle;
    /// no WM_DESTROY is sent — the window was never linked).
    pub(super) fn rollback_create(s: &mut dyn Session, caller: ThreadId, id: WindowId) {
        let windows = s.windows();
        {
            let w = windows.at_mut(id);
            w.flags.destroyed = true;
            w.flags.destroying = true;
            w.style &= !WS_VISIBLE;
        }
        Windows::free_window(s, caller, id);
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;
    use rtl::user::{WM_NCCREATE, WS_CHILD, WS_OVERLAPPED, WS_POPUP};

    use super::*;
    use crate::win32k::window::testkit::*;

    /// A parent on another desktop is refused before anything else: ERROR_INVALID_PARAMETER
    /// (87), and nothing is allocated.
    #[test]
    fn a_parent_on_another_desktop_is_refused() {
        let (w, c, t, atom, _, _) = setup();
        let other = raw_window_on(w, t, OTHER_DESKTOP, WS_OVERLAPPED, None);
        let before = live(w);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.parent = Some(other);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(err, Failure::InvalidParameter);
        assert_eq!(err.code(), 87);
        assert_eq!(live(w), before, "nothing was allocated");
    }

    /// The desktop access check: a thread whose desktop access lacks DESKTOP_CREATEWINDOW is
    /// refused with ERROR_ACCESS_DENIED (5); a thread with no desktop handle yet (the root
    /// desktop window's own creation) skips the check.
    #[test]
    fn the_desktop_access_check() {
        let (w, c, _t, atom, _, _) = setup();
        let t2 = w.add_thread(OWNER, DESKTOP, 0, Some(0x20), None).unwrap();
        let mut pump = Rec::new(t2);
        let err = create(w, c, t2, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        assert_eq!(err, Failure::AccessDenied);
        assert_eq!(err.code(), 5);
        // No desktop handle: the check is skipped and the create proceeds.
        let t3 = w.add_thread(OWNER, DESKTOP, 0, None, None).unwrap();
        let mut pump = Rec::new(t3);
        assert!(create(w, c, t3, atom, WS_OVERLAPPED, &mut pump).is_ok());
    }

    /// A WS_CHILD window created without a parent fails with ERROR_TLW_WITH_WSCHILD (1406).
    #[test]
    fn a_child_window_needs_a_parent() {
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_CHILD, &mut pump).unwrap_err();
        assert_eq!(err, Failure::TlwWithWsChild);
        assert_eq!(err.code(), 1406);
    }

    /// The private ANSI-creator bit is consumed at the create: it never reaches the stored
    /// ex-style, the window carries the ANSI-creator flag, and the create parameters name the
    /// class by its ANSI name.
    #[test]
    fn the_ansi_creator_bit_is_consumed() {
        let (w, c, t, atom, _, _) = setup();
        let name = wide("Test");
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.ex_style = ANSI_CREATOR_BIT | WS_EX_TOPMOST;
        a.class_name = class::Name::Text(&name);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let rec = w.at(id);
        assert_eq!(rec.ex_style & ANSI_CREATOR_BIT, 0, "the bit is not stored");
        assert_eq!(
            rec.ex_style & WS_EX_TOPMOST,
            WS_EX_TOPMOST,
            "the other bits stay"
        );
        assert!(rec.flags.ansi_creator);
        let (_, _, params) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(params.class_name, ClassArg::AnsiName);
    }

    /// The edge style decision: the dialog-modal frame and the thick frame force
    /// WS_EX_WINDOWEDGE, the static edge forbids it, a caption gets it from a 4.0-or-later app,
    /// and anything else clears it.
    #[test]
    fn the_edge_style_decision() {
        assert!(needs_window_edge(WS_CAPTION, 0, true));
        assert!(!needs_window_edge(WS_CAPTION, 0, false));
        assert!(!needs_window_edge(WS_CAPTION, WS_EX_STATICEDGE, true));
        assert!(needs_window_edge(0, WS_EX_DLGMODALFRAME, false));
        assert!(needs_window_edge(WS_THICKFRAME, 0, false));
        assert!(!needs_window_edge(WS_OVERLAPPED, 0, true));
        // Through the create: the stored ex-style carries the decision (a popup, so the tiled
        // path does not re-set the bit).
        let (w, c, t, atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_POPUP);
        a.ex_style = WS_EX_STATICEDGE | WS_EX_WINDOWEDGE;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).ex_style & WS_EX_WINDOWEDGE, 0, "cleared");
        let mut a = args(atom, WS_POPUP);
        a.ex_style = WS_EX_DLGMODALFRAME;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(
            w.at(id).ex_style & WS_EX_WINDOWEDGE,
            WS_EX_WINDOWEDGE,
            "set"
        );
    }

    /// A class name that resolves to no atom fails with ERROR_CANNOT_FIND_WND_CLASS (1407).
    #[test]
    fn an_unknown_class_name_fails() {
        let (w, c, t, _atom, _, _) = setup();
        let mut pump = Rec::new(t);
        let name = wide("NoSuchClass");
        let mut a = args(0, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
    }

    /// An integer atom names the class directly (no atom-table lookup); atom 0 fails the same
    /// way as an unknown string name.
    #[test]
    fn an_integer_atom_names_the_class_directly() {
        let (w, c, t, _atom, _, _) = setup();
        let atom = register(c, &w.handles, class::Name::Atom(0x8002), &wnd_class());
        assert_eq!(atom, 0x8002);
        let mut pump = Rec::new(t);
        let mut a = args(0x8002, WS_OVERLAPPED);
        a.class_name = class::Name::Atom(0x8002);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(w.pool.is_live(id));
        let (_, _, params) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(params.class_name, ClassArg::Atom(0x8002));
        // Atom 0 fails.
        let mut pump = Rec::new(t);
        let a = args(0, WS_OVERLAPPED);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
    }

    /// A class the calling process cannot see (another module's private class) fails with 1407
    /// and allocates nothing.
    #[test]
    fn a_class_the_process_cannot_see_fails() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.instance = OTHER_MODULE;
        let atom = register(c, &w.handles, class::Name::Text(&wide("Private")), &wc);
        let mut pump = Rec::new(t);
        let name = wide("Private");
        let mut a = args(atom, WS_OVERLAPPED);
        a.class_name = class::Name::Text(&name);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
        assert_eq!(live(w), 2, "nothing was allocated");
    }

    /// A failed class reference (a cross-desktop class with no free class record for the clone)
    /// frees the window record and fails with 1407.
    #[test]
    fn a_failed_class_reference_frees_the_record() {
        let (w, c, t, _atom, _, _) = setup();
        // A class registered on the other desktop.
        let atom = register_on(
            c,
            &w.handles,
            class::Name::Text(&wide("Far")),
            &wnd_class(),
            OTHER_DESKTOP,
            OWNER,
            class::MenuArg::None,
        );
        // Fill the class pool's chunk with no page left to grow it, so the clone cannot be made.
        crate::win32k::test_pages::budget(0);
        let mut fill = 0;
        while c
            .register_class(
                &w.handles,
                &wnd_class(),
                class::Name::Text(&wide(&format!("Fill{fill}"))),
                class::MenuArg::None,
                OWNER,
                compat40(),
                DESKTOP,
            )
            .is_ok()
        {
            fill += 1;
        }
        let before = live(w);
        let mut pump = Rec::new(t);
        let err = create(w, c, t, atom, WS_OVERLAPPED, &mut pump).unwrap_err();
        crate::win32k::test_pages::unlimited();
        assert_eq!(err, Failure::CannotFindWindowClass);
        assert_eq!(err.code(), 1407);
        assert_eq!(live(w), before, "the record was freed");
        assert_eq!(w.thread(t).window_count, 0);
    }

    /// The stored state after a happy create: WS_VISIBLE and the layered bit are stripped from
    /// the stored values, the class's cbWndExtra is stored, and the thread's window count went
    /// up (the class's window count is probed by unregistering: refused while it has windows).
    #[test]
    fn the_stored_style_and_counters() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.cb_wnd_extra = 12;
        let atom = register(c, &w.handles, class::Name::Text(&wide("Extra")), &wc);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED | WS_VISIBLE);
        a.ex_style = WS_EX_LAYERED | WS_EX_TOPMOST;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        let rec = w.at(id);
        // WS_VISIBLE and the layered bit are stripped from the stored style (seen at
        // WM_NCCREATE, before any show re-sets the visible bit).
        assert_eq!(pump.styles[0].0, id);
        assert_eq!(pump.styles[0].1 & WS_VISIBLE, 0, "WS_VISIBLE is stripped");
        assert_eq!(
            rec.ex_style & WS_EX_LAYERED,
            0,
            "the layered bit is stripped"
        );
        assert_eq!(rec.ex_style & WS_EX_TOPMOST, WS_EX_TOPMOST);
        assert_eq!(rec.cb_wnd_extra, 12);
        assert_eq!(w.thread(t).window_count, 1);
        let err = c
            .unregister_class(
                &mut w.handles,
                class::Name::Text(&wide("Extra")),
                OWNER,
                MODULE,
            )
            .unwrap_err();
        assert_eq!(
            err,
            class::Failure::ClassHasWindows,
            "the class reference is held"
        );
    }

    /// Before any callback the record holds the class, the stored styles, the module and the
    /// procedure, and the parent pointer is the desktop's message window; the create parameters
    /// carry the arguments, the menu by kind.
    #[test]
    fn the_pre_callback_state() {
        let (w, c, t, atom, _, msg) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(parent).client_rect = Rect {
            left: 10,
            top: 20,
            right: 500,
            bottom: 400,
        };
        let mut pump = Rec::new(t);
        let name = wide("hello");
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(7);
        a.name = &name;
        a.params = 0x1234;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        // While the create hook ran, the parent pointer was the message window (a parent always
        // exists during early callbacks).
        assert_eq!(pump.parents[0], (id, Some(msg)));
        // After the create it is the real parent.
        assert_eq!(w.at(id).parent, Some(parent));
        let rec = w.at(id);
        assert!(rec.class.is_some());
        assert_eq!(rec.module, MODULE);
        assert_eq!(rec.proc, Proc::Client(0x0040_1000));
        let (_, _, p) = &pump.params[0];
        assert_eq!(p.menu, 7, "a child's menu is the raw id");
        assert_eq!(p.parent, w.at(parent).handle);
        assert_eq!(pump.names[0], wide("hello"));
        assert_eq!(p.params, 0x1234);
        assert_eq!(p.style, WS_CHILD);
        // A top-level window's menu is a handle.
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).menu, Menu::Handle(0x9000));
        let (_, _, p) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(p.menu, 0x9000);
    }

    /// The owner of a top-level window is the parent's top-level window; a topmost owner makes
    /// the window topmost; the parent link itself goes to the desktop window; an owner chain
    /// with a loop fails the create.
    #[test]
    fn the_owner_comes_from_the_parents_top_level() {
        let (w, c, t, atom, desk, _) = setup();
        let owner = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(owner).ex_style |= WS_EX_TOPMOST;
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(owner);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).owner, Some(owner));
        assert_eq!(
            w.at(id).ex_style & WS_EX_TOPMOST,
            WS_EX_TOPMOST,
            "above its owner"
        );
        assert_eq!(
            w.at(id).parent,
            Some(desk),
            "the parent link is the desktop window"
        );
        // An owner on another thread shares input state.
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x30), None)
            .unwrap();
        let foreign = raw_window(w, t2, WS_OVERLAPPED, None);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(foreign);
        let _ = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(pump.events.contains(&Ev::Attach(t, t2, true)));
        // An owner-chain loop is refused and the record rolled back.
        let x = raw_window(w, t, WS_OVERLAPPED, None);
        let y = raw_window(w, t, WS_OVERLAPPED, None);
        w.at_mut(x).owner = Some(y);
        w.at_mut(y).owner = Some(x);
        let before = live(w);
        let mut a = args(atom, WS_POPUP);
        a.parent = Some(x);
        let err = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap_err();
        assert_eq!(
            err,
            Failure::OutOfMemory,
            "the owner-depth failure rolls back"
        );
        assert_eq!(live(w), before);
    }

    /// A top-level window with no parent is parented to the desktop window; a message-window
    /// parent stays the message window.
    #[test]
    fn a_missing_parent_defaults_to_the_desktop_window() {
        let (w, c, t, atom, desk, msg) = setup();
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).parent, Some(desk));
        assert_eq!(w.at(desk).child, Some(id));
        // A message-window parent stays.
        let mut a = args(atom, WS_OVERLAPPED);
        a.parent = Some(msg);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).parent, Some(msg));
        assert_eq!(w.at(msg).child, Some(id));
    }

    /// A top-level window with no menu given inherits the class menu; a load failure is
    /// tolerated and leaves the window menu-less.
    #[test]
    fn the_class_menu_is_loaded_when_none_is_given() {
        let (w, c, t, _atom, _, _) = setup();
        let atom = register_on(
            c,
            &w.handles,
            class::Name::Text(&wide("Menu")),
            &wnd_class(),
            DESKTOP,
            OWNER,
            class::MenuArg::Id(42),
        );
        let mut pump = Rec::new(t);
        let a = args(atom, WS_OVERLAPPED);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(pump.events.contains(&Ev::LoadMenu(MODULE)));
        assert_eq!(w.at(id).menu, Menu::Handle(0x5000));
        let (_, _, p) = pump
            .params
            .iter()
            .find(|(_, m, _)| *m == WM_NCCREATE)
            .unwrap();
        assert_eq!(p.menu, 0x5000);
        // A load failure is tolerated.
        pump.no_menus = true;
        let a = args(atom, WS_OVERLAPPED);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).menu, Menu::None);
    }

    /// The menu is stored by kind: a child's as a raw id, a top-level window's as a handle.
    #[test]
    fn the_menu_is_stored_by_kind() {
        let (w, c, t, atom, _, _) = setup();
        let parent = raw_window(w, t, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        a.menu = MenuInput::Id(9);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).menu, Menu::Id(9));
        let mut a = args(atom, WS_OVERLAPPED);
        a.menu = MenuInput::Handle(0x9000);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).menu, Menu::Handle(0x9000));
    }

    /// The CS_PARENTDC hack: a class with CS_PARENTDC clears the window's clip bits when the
    /// parent does not clip children (skipped for pre-4.0 windows).
    #[test]
    fn the_parentdc_hack_clears_the_clip_bits() {
        let (w, c, t, _atom, _, _) = setup();
        let mut wc = wnd_class();
        wc.style = CS_PARENTDC;
        let atom = register(c, &w.handles, class::Name::Text(&wide("PD")), &wc);
        let parent = raw_window(w, t, WS_OVERLAPPED, None); // no WS_CLIPCHILDREN
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);
        a.parent = Some(parent);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).style & (WS_CLIPCHILDREN | WS_CLIPSIBLINGS), 0);
        // A pre-4.0 window keeps them.
        let mut a = args(atom, WS_CHILD | WS_CLIPSIBLINGS);
        a.parent = Some(parent);
        a.version = 0x0003_0000;
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert_eq!(w.at(id).style & WS_CLIPSIBLINGS, WS_CLIPSIBLINGS);
    }

    /// A child of another thread's parent attaches input.
    #[test]
    fn a_cross_thread_child_attaches_input() {
        let (w, c, t, atom, _, _) = setup();
        let t2 = w
            .add_thread(OTHER_OWNER, DESKTOP, DESKTOP_CREATEWINDOW, Some(0x40), None)
            .unwrap();
        let parent = raw_window(w, t2, WS_OVERLAPPED, None);
        let mut pump = Rec::new(t);
        let mut a = args(atom, WS_CHILD);
        a.parent = Some(parent);
        let id = Windows::create_window_ex(&mut pump.on(w, c), t, &a).unwrap();
        assert!(pump.events.contains(&Ev::Attach(t, t2, true)));
        assert_eq!(w.at(id).parent, Some(parent));
    }
}
