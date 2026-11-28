//! The window manager's host tests' kit: fresh registries, a recording session, and the
//! scaffolding the tests build windows with.

use rtl::gdi::Rect;
use rtl::testing::wide;
use rtl::user::{
    WM_CREATE,
    WM_DESTROY,
    WM_NCACTIVATE,
    WM_NCCALCSIZE,
    WM_NCCREATE,
    WM_SIZE,
    WM_STYLECHANGING,
    WM_WINDOWPOSCHANGED,
    WM_WINDOWPOSCHANGING,
    WS_OVERLAPPED,
    WS_POPUP,
    WS_VISIBLE,
};
use rtl::window::{SWP_HIDEWINDOW, SW_HIDE};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class::{self, RegisterFlags};
use crate::win32k::handle::{UserHandles, UserObject};

/// A fresh window registry, leaked at its final address (the pool's records stay put, as on
/// target).
pub(super) fn windows() -> &'static mut Windows {
    let mut registry = Box::<Windows>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { Windows::write_empty(registry.as_mut_ptr()) };
    // SAFETY: written whole just above.
    Box::leak(unsafe { registry.assume_init() })
}

/// A fresh class registry, leaked the same way.
fn classes() -> &'static mut class::Registry {
    let mut registry = Box::<class::Registry>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { class::Registry::write_empty(registry.as_mut_ptr()) };
    // SAFETY: written whole just above.
    Box::leak(unsafe { registry.assume_init() })
}

pub(super) const OWNER: class::Owner = 1;

pub(super) const OTHER_OWNER: class::Owner = 2;

pub(super) const MODULE: u32 = 0x0040_0000;

pub(super) const OTHER_MODULE: u32 = 0x0050_0000;

pub(super) const DESKTOP: u32 = 1;

pub(super) const OTHER_DESKTOP: u32 = 2;

/// An expected-version word of a 5.0 app.
const VERSION_50: u32 = 0x0005_0000;

pub(super) fn wnd_class() -> class::WndClassExW {
    class::WndClassExW {
        cb_size: 48,
        style: 0,
        wnd_proc: 0x0040_1000,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        instance: MODULE,
        icon: 0,
        cursor: 0,
        background: 0,
        menu_name: 0,
        class_name: 0,
        icon_sm: 0,
    }
}

pub(super) fn compat40() -> RegisterFlags {
    RegisterFlags {
        win40_compat: true,
        ..RegisterFlags::default()
    }
}

pub(super) fn register(
    c: &mut class::Registry,
    handles: &UserHandles,
    name: class::Name,
    wc: &class::WndClassExW,
) -> class::Atom {
    register_on(c, handles, name, wc, DESKTOP, OWNER, class::MenuArg::None)
}

pub(super) fn register_on(
    c: &mut class::Registry,
    handles: &UserHandles,
    name: class::Name,
    wc: &class::WndClassExW,
    desktop: u32,
    owner: class::Owner,
    menu: class::MenuArg,
) -> class::Atom {
    c.register_class(handles, wc, name, menu, owner, compat40(), desktop)
        .unwrap()
}

/// A thread on the test desktop, with full desktop access and the primary monitor.
fn thread(w: &mut Windows) -> ThreadId {
    w.add_thread(
        OWNER,
        DESKTOP,
        DESKTOP_CREATEWINDOW,
        Some(0x10),
        Some(PRIMARY_MONITOR),
    )
    .unwrap()
}

/// A bare window record (pool and handle only), as the scaffolding would make one.
pub(super) fn raw_window(
    w: &mut Windows,
    t: ThreadId,
    style: u32,
    parent: Option<WindowId>,
) -> WindowId {
    raw_window_on(w, t, DESKTOP, style, parent)
}

pub(super) fn raw_window_on(
    w: &mut Windows,
    t: ThreadId,
    desktop: u32,
    style: u32,
    parent: Option<WindowId>,
) -> WindowId {
    let id = w.pool.allocate().unwrap();
    let handle = w
        .handles
        .insert(
            Some(OWNER),
            UserObject::Window(WindowEntry {
                id,
                owner: t,
                marked_destroy: false,
                in_destroy: false,
            }),
        )
        .unwrap();
    let rec = w.pool.at_mut(id);
    rec.handle = handle;
    rec.thread = t;
    rec.process = OWNER;
    rec.desktop = desktop;
    rec.style = style;
    rec.parent = parent;
    rec.locks = 1;
    id
}

/// How many window records are live.
pub(super) fn live(w: &Windows) -> usize {
    w.pool.live()
}

/// A registry pair with a thread, the desktop's window and message window, a 640x480 monitor
/// and one registered class.
pub(super) fn setup() -> (
    &'static mut Windows,
    &'static mut class::Registry,
    ThreadId,
    class::Atom,
    WindowId,
    WindowId,
) {
    let w = windows();
    let c = classes();
    let t = thread(w);
    let desk = raw_window(w, t, WS_OVERLAPPED, None);
    let msg = raw_window(w, t, WS_POPUP, None);
    w.set_desktop(DESKTOP, Some(desk), Some(msg));
    w.set_monitor(
        PRIMARY_MONITOR,
        Rect {
            left: 0,
            top: 0,
            right: 640,
            bottom: 480,
        },
    );
    let atom = register(
        c,
        &w.handles,
        class::Name::Text(&wide("Test")),
        &wnd_class(),
    );
    (w, c, t, atom, desk, msg)
}

/// Create arguments for a plain create.
pub(super) fn args(atom: class::Atom, style: u32) -> CreateArgs<'static> {
    CreateArgs {
        ex_style: 0,
        class_name: class::Name::Atom(atom),
        class_atom: atom,
        name: &[],
        style,
        x: 10,
        y: 20,
        cx: 100,
        cy: 80,
        parent: None,
        menu: MenuInput::None,
        instance: MODULE,
        params: 0,
        version: VERSION_50,
    }
}

pub(super) fn create(
    w: &mut Windows,
    c: &mut class::Registry,
    t: ThreadId,
    atom: class::Atom,
    style: u32,
    pump: &mut Rec,
) -> Result<WindowId, Failure> {
    let a = args(atom, style);
    Windows::create_window_ex(&mut pump.on(w, c), t, &a)
}

/// One recorded session call.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Ev {
    Send(WindowId, u32, WParam, LParam),
    Show(WindowId, u32),
    SetPos(WindowId, u32),
    Activate(WindowId, Activate),
    MinMax(WindowId, u32),
    Focus(WindowId),
    Attach(ThreadId, ThreadId, bool),
    Redraw(WindowId),
    ReleaseCapture,
    Caret,
    PostEvent(ThreadId, WindowId),
    MinMaxInfo(WindowId),
    LoadMenu(u32),
    DestroyMenu(Hwnd),
    WindowDc(WindowId, bool),
    Layered(WindowId),
    FullScreen(WindowId),
    InsertAfter(WindowId),
    Clipboard(WindowId),
    Quit(WindowId),
    Teardown(WindowId),
    Props(WindowId),
}

/// A recorder of a session's calls ([`Rec::on`]): logs every call, answers WM_NCCREATE with 1
/// and WM_CREATE with 0 unless told otherwise, and can play a handler that sets a title or
/// destroys a sibling.
pub(super) struct Rec {
    pub(super) events: Vec<Ev>,
    /// (target, message, params) for every WM_NCCREATE/WM_CREATE.
    pub(super) params: Vec<(WindowId, u32, CreateParams)>,
    /// The window name each of those carries, as its receipt would read it.
    pub(super) names: Vec<Vec<u16>>,
    /// The parent pointer seen at each send (the create's pre-callback parent).
    pub(super) parents: Vec<(WindowId, Option<WindowId>)>,
    /// The target's stored style at each send.
    pub(super) styles: Vec<(WindowId, u32)>,
    /// (target, message, WINDOWPOS) for every WM_WINDOWPOSCHANGING/WM_WINDOWPOSCHANGED.
    pub(super) positions: Vec<(WindowId, u32, WindowPos)>,
    /// The WINDOWPOS a WM_WINDOWPOSCHANGING handler answers instead of the one it got.
    pub(super) changing_answer: Option<WindowPos>,
    /// The client rectangle a WM_NCCALCSIZE handler answers, as an inset of the window's.
    pub(super) nccalc_inset: i32,
    /// (target, wParam, payload) for every WM_NCCALCSIZE, as sent.
    pub(super) calcs: Vec<(WindowId, WParam, Payload)>,
    /// The new style a WM_STYLECHANGING handler answers instead of the one it got.
    pub(super) style_answer: Option<u32>,
    pub(super) nccreate_answer: LResult,
    pub(super) create_answer: LResult,
    pub(super) hide_works: bool,
    pub(super) veto_destroy: bool,
    /// A window whose destroy alone the hook vetoes.
    pub(super) veto_window: Option<WindowId>,
    pub(super) activate_ok: bool,
    pub(super) no_menus: bool,
    /// The MINMAXINFO a WM_GETMINMAXINFO handler answers (none: the window manager's defaults
    /// stand).
    pub(super) mmi: Option<MinMaxInfo>,
    /// Every WM_GETMINMAXINFO's MINMAXINFO, as sent.
    pub(super) minmax_sent: Vec<(WindowId, MinMaxInfo)>,
    caller: ThreadId,
    /// A title a fake handler sets during WM_NCCREATE.
    pub(super) title_on_nccreate: Option<Vec<u16>>,
    title_done: bool,
    /// When WM_DESTROY reaches `watch`, destroy `victim` (a handler destroying a sibling).
    pub(super) destroy_on_destroy: Option<(WindowId, WindowId)>,
    /// When this message reaches any window, its handler destroys that window.
    pub(super) destroy_self_on: Option<u32>,
    next_menu_handle: Hwnd,
}

impl Rec {
    pub(super) fn new(caller: ThreadId) -> Self {
        Rec {
            events: Vec::new(),
            params: Vec::new(),
            names: Vec::new(),
            parents: Vec::new(),
            styles: Vec::new(),
            positions: Vec::new(),
            changing_answer: None,
            nccalc_inset: 0,
            calcs: Vec::new(),
            style_answer: None,
            nccreate_answer: 1,
            create_answer: 0,
            hide_works: true,
            veto_destroy: false,
            veto_window: None,
            activate_ok: true,
            no_menus: false,
            mmi: None,
            minmax_sent: Vec::new(),
            caller,
            title_on_nccreate: None,
            title_done: false,
            destroy_on_destroy: None,
            destroy_self_on: None,
            next_menu_handle: 0x5000,
        }
    }

    /// Every message sent, as (target, message).
    pub(super) fn sends(&self) -> Vec<(WindowId, u32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Ev::Send(w, m, _, _) => Some((*w, *m)),
                _ => None,
            })
            .collect()
    }

    /// The messages sent, as messages only.
    pub(super) fn messages(&self) -> Vec<u32> {
        self.sends().iter().map(|(_, m)| *m).collect()
    }

    /// The flags of every WM_WINDOWPOSCHANGING, by target.
    pub(super) fn changing_flags(&self) -> Vec<(WindowId, u32)> {
        self.positions
            .iter()
            .filter(|(_, m, _)| *m == WM_WINDOWPOSCHANGING)
            .map(|(id, _, pos)| (*id, pos.flags))
            .collect()
    }
}

/// A session over the two registries whose sends and calls a [`Rec`] records and plays.
pub(super) struct RecSession<'a> {
    windows: &'a mut Windows,
    classes: &'a mut class::Registry,
    rec: &'a mut Rec,
}

impl Rec {
    /// A session over `windows` and `classes` that this records.
    pub(super) fn on<'a>(
        &'a mut self,
        windows: &'a mut Windows,
        classes: &'a mut class::Registry,
    ) -> RecSession<'a> {
        RecSession {
            windows,
            classes,
            rec: self,
        }
    }
}

impl Session for RecSession<'_> {
    fn parts(&mut self) -> (&mut Windows, &mut class::Registry) {
        (&mut *self.windows, &mut *self.classes)
    }

    /// The frame paints are not among the decisions' messages these tests follow.
    fn paint_frame(&mut self, _target: WindowId) {}

    fn send(&mut self, target: WindowId, message: &mut Message) -> LResult {
        // WM_GETMINMAXINFO is followed apart from the other messages: the handler's answer.
        if let Payload::MinMax(ref mut mmi) = message.payload {
            self.rec.events.push(Ev::MinMaxInfo(target));
            self.rec.minmax_sent.push((target, *mmi));
            if let Some(answer) = self.rec.mmi {
                *mmi = answer;
            }
            return 0;
        }
        if let Payload::Create(ref p) = message.payload {
            self.rec.params.push((target, message.message, *p));
            self.rec
                .names
                .push(self.windows.create_name(target, p.name).to_vec());
        }
        self.rec
            .parents
            .push((target, self.windows.at(target).parent));
        self.rec
            .styles
            .push((target, self.windows.at(target).style));
        self.rec.events.push(Ev::Send(
            target,
            message.message,
            message.wparam,
            message.lparam,
        ));
        if message.message == WM_NCCREATE && !self.rec.title_done {
            if let Some(units) = self.rec.title_on_nccreate.clone() {
                self.rec.title_done = true;
                let handle = self.windows.at(target).handle;
                self.windows.set_window_text(handle, &units).unwrap();
                self.windows.at_mut(target).flags.title_set = true;
            }
        }
        // The handler hands WM_WINDOWPOSCHANGING to the default procedure first (its clamp),
        // then changes what it answers, as guigeo `edits`' does.
        if message.message == WM_WINDOWPOSCHANGING {
            default_send(self, target, message);
        }
        if let Payload::WindowPos(ref mut pos) = message.payload {
            if message.message == WM_WINDOWPOSCHANGING {
                if let Some(answer) = self.rec.changing_answer {
                    *pos = answer;
                }
            }
            self.rec.positions.push((target, message.message, *pos));
            // A handler that shows the window again undoes the hide.
            if message.message == WM_WINDOWPOSCHANGED
                && pos.flags & SWP_HIDEWINDOW != 0
                && !self.rec.hide_works
            {
                self.windows.at_mut(target).style |= WS_VISIBLE;
            }
        }
        if let Payload::Style(ref mut style) = message.payload {
            if message.message == WM_STYLECHANGING {
                if let Some(answer) = self.rec.style_answer {
                    style.style_new = answer;
                }
            }
        }
        // WM_NCCALCSIZE: the handler's inset when it has one, the default procedure's frame
        // otherwise.
        if message.message == WM_NCCALCSIZE {
            self.rec
                .calcs
                .push((target, message.wparam, message.payload.clone()));
            let inset = self.rec.nccalc_inset;
            let r = match message.payload {
                Payload::Rect(ref mut r) => Some(r),
                Payload::CalcSize(ref mut calc) => Some(&mut calc.rects[0]),
                _ => None,
            };
            match r {
                Some(r) if inset != 0 => {
                    r.left += inset;
                    r.top += inset;
                    r.right -= inset;
                    r.bottom -= inset;
                }
                _ => {
                    default_procedure(self.windows, target, message);
                }
            }
        }
        if self.rec.destroy_self_on == Some(message.message) {
            // Once: a handler destroying its window from every WM_DESTROY would nest forever.
            self.rec.destroy_self_on = None;
            let caller = self.rec.caller;
            let _ = Windows::destroy_window(self, caller, target);
        }
        if message.message == WM_DESTROY {
            if let Some((watch, victim)) = self.rec.destroy_on_destroy {
                if target == watch {
                    let caller = self.rec.caller;
                    let _ = Windows::destroy_window(self, caller, victim);
                }
            }
        }
        match message.message {
            WM_NCCREATE => self.rec.nccreate_answer,
            WM_CREATE => self.rec.create_answer,
            WM_NCACTIVATE => 1,
            _ => 0,
        }
    }

    fn send_size(&mut self, target: WindowId, command: u32) {
        let c = self.windows.at(target).client_rect;
        let size = makelong((c.right - c.left) as u16, (c.bottom - c.top) as u16);
        self.rec
            .events
            .push(Ev::Send(target, WM_SIZE, command, size as LParam));
    }

    fn show(&mut self, target: WindowId, command: u32) -> bool {
        self.rec.events.push(Ev::Show(target, command));
        // A successful show sets the visible bit, a hide clears it.
        if self.rec.hide_works {
            let w = self.windows.at_mut(target);
            if command == SW_HIDE as u32 {
                w.style &= !WS_VISIBLE;
            } else {
                w.style |= WS_VISIBLE;
            }
        }
        true
    }

    fn set_window_pos(&mut self, target: WindowId, flags: u32) {
        self.rec.events.push(Ev::SetPos(target, flags));
        if self.rec.hide_works && flags & SWP_HIDEWINDOW != 0 {
            self.windows.at_mut(target).style &= !WS_VISIBLE;
        }
    }

    fn activate(&mut self, target: WindowId, command: Activate) -> bool {
        self.rec.events.push(Ev::Activate(target, command));
        self.rec.activate_ok
    }

    fn min_maximize(&mut self, target: WindowId, command: u32) {
        self.rec.events.push(Ev::MinMax(target, command));
    }

    fn check_focus(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Focus(target));
    }

    fn attach_input(&mut self, from: ThreadId, to: ThreadId, attach: bool) {
        self.rec.events.push(Ev::Attach(from, to, attach));
    }

    fn redraw_below(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Redraw(target));
    }

    fn release_capture(&mut self) {
        self.rec.events.push(Ev::ReleaseCapture);
    }

    fn destroy_caret(&mut self) {
        self.rec.events.push(Ev::Caret);
    }

    fn post_destroy_event(&mut self, thread: ThreadId, window: WindowId) {
        self.rec.events.push(Ev::PostEvent(thread, window));
    }

    fn load_class_menu(&mut self, module: u32, _name: &class::MenuName) -> Option<Hwnd> {
        self.rec.events.push(Ev::LoadMenu(module));
        if self.rec.no_menus {
            return None;
        }
        let h = self.rec.next_menu_handle;
        self.rec.next_menu_handle += 4;
        Some(h)
    }

    fn destroy_menu(&mut self, menu: Hwnd) {
        self.rec.events.push(Ev::DestroyMenu(menu));
    }

    fn create_window_dc(&mut self, target: WindowId, own_dc: bool) -> bool {
        self.rec.events.push(Ev::WindowDc(target, own_dc));
        true
    }

    fn set_layered(&mut self, target: WindowId) -> bool {
        self.rec.events.push(Ev::Layered(target));
        true
    }

    fn check_full_screen(&mut self, target: WindowId, _rect: &mut SizeRect) {
        self.rec.events.push(Ev::FullScreen(target));
    }

    fn foreground_insert_after(&mut self, target: WindowId) -> ZOrder {
        self.rec.events.push(Ev::InsertAfter(target));
        ZOrder::Top
    }

    fn cbt_create_veto(&mut self, target: WindowId, _params: &mut CreateParams) -> bool {
        self.rec
            .parents
            .push((target, self.windows.at(target).parent));
        false
    }

    fn cbt_destroy_veto(&mut self, target: WindowId) -> bool {
        self.rec.veto_destroy || self.rec.veto_window == Some(target)
    }

    fn disown_clipboard(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Clipboard(target));
    }

    fn repost_quit(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Quit(target));
    }

    fn window_teardown(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Teardown(target));
    }

    fn delete_properties(&mut self, target: WindowId) {
        self.rec.events.push(Ev::Props(target));
    }
}

/// A fresh window manager, built in place and leaked, as the target's lock builds it.
pub(super) fn manager() -> &'static mut WindowManager {
    let mut manager = Box::<WindowManager>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { WindowManager::write_empty(manager.as_mut_ptr()) };
    // SAFETY: written whole just above.
    Box::leak(unsafe { manager.assume_init() })
}

/// A 640x480 work area.
pub(super) const SCREEN: Rect = Rect {
    left: 0,
    top: 0,
    right: 640,
    bottom: 480,
};

pub(super) fn key(index: u16, generation: u16) -> ThreadKey {
    ThreadKey { index, generation }
}
