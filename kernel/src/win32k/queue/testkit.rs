//! The message layer's test rig: a window manager with the boot's desktop, a registered class,
//! threads with their queues, and windows of the class made through the queue's session.

use rtl::callback::{CallbackMsg, OUT_MAX};
use rtl::gdi::Rect;
use rtl::user::{Msg, WS_POPUP};

use super::*;
use crate::sched::thread::ThreadId;
use crate::win32k::class;
use crate::win32k::window::{
    CreateArgs,
    Hwnd,
    MenuInput,
    Message,
    Payload,
    ThreadKey,
    WParam,
    WindowManager,
    DESKTOP_CREATEWINDOW,
};

pub const DESKTOP: u32 = 1;
pub const OWNER: class::Owner = 0;
pub const OTHER_OWNER: class::Owner = 1;
pub const MODULE: u32 = 0x0040_0000;
/// The class's window procedure.
pub const PROC: u32 = 0x0040_1000;

/// A window manager with the boot's desktop (640x480) and the class "Rig" registered, leaked
/// at its final address; the class's atom.
pub fn manager() -> (&'static mut WindowManager, class::Atom) {
    let mut manager = Box::<WindowManager>::new_uninit();
    // SAFETY: the box is valid, aligned and the records' final address once leaked.
    unsafe { WindowManager::write_empty(manager.as_mut_ptr()) };
    // SAFETY: written whole just above.
    let m = Box::leak(unsafe { manager.assume_init() });
    m.boot_desktop(
        DESKTOP,
        Rect {
            left: 0,
            top: 0,
            right: 640,
            bottom: 480,
        },
    )
    .unwrap();
    let atom = register(m, OWNER);
    (m, atom)
}

/// The class "Rig" registered for the process `owner`: its atom.
pub fn register(m: &mut WindowManager, owner: class::Owner) -> class::Atom {
    let name: Vec<u16> = "Rig".encode_utf16().collect();
    let wc = class::WndClassExW {
        cb_size: 48,
        style: 0,
        wnd_proc: PROC,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        instance: MODULE,
        icon: 0,
        cursor: 0,
        background: 0,
        menu_name: 0,
        class_name: 0,
        icon_sm: 0,
    };
    let flags = class::RegisterFlags {
        win40_compat: true,
        ..class::RegisterFlags::default()
    };
    m.classes
        .register_class(
            &m.windows.handles,
            &wc,
            class::Name::Text(&name),
            class::MenuArg::None,
            owner,
            flags,
            DESKTOP,
        )
        .unwrap()
}

/// A thread of the process `owner` (its thread object's slot `slot`, client id `client_id`),
/// connected, with its queue.
pub fn thread_of(
    m: &mut WindowManager,
    slot: u16,
    client_id: u32,
    owner: class::Owner,
) -> ThreadId {
    let key = ThreadKey {
        index: slot,
        generation: 0,
    };
    let t = m
        .windows
        .connect_thread(key, owner, DESKTOP, DESKTOP_CREATEWINDOW, 0x10)
        .unwrap();
    attach(&mut m.windows, t, key, client_id);
    t
}

/// A thread of the rig's process.
pub fn thread(m: &mut WindowManager, slot: u16, client_id: u32) -> ThreadId {
    thread_of(m, slot, client_id, OWNER)
}

/// A window of the class, `style` at (`x`, `y`) `cx` by `cy`, child of `parent` (0: a
/// top-level window), made by `t` through the queue's session: its handle.
#[allow(clippy::too_many_arguments)]
pub fn window_at(
    m: &mut WindowManager,
    atom: class::Atom,
    t: ThreadId,
    style: u32,
    parent: Hwnd,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
) -> Hwnd {
    let name: Vec<u16> = "Title".encode_utf16().collect();
    let mut args = CreateArgs {
        ex_style: 0,
        class_name: class::Name::Atom(atom),
        class_atom: atom,
        name: &name,
        style,
        x,
        y,
        cx,
        cy,
        parent: None,
        menu: MenuInput::None,
        instance: MODULE,
        params: 0x1234,
        version: 0x0005_0000,
    };
    WindowManager::create_window(
        &mut QueueSession::new(&mut m.windows, &mut m.classes),
        t,
        parent,
        &mut args,
    )
    .unwrap()
}

/// A hidden 320x200 popup at (0, 0), as the fixtures make theirs.
pub fn popup(m: &mut WindowManager, atom: class::Atom, t: ThreadId) -> Hwnd {
    window_at(m, atom, t, WS_POPUP, 0, 0, 0, 320, 200)
}

/// Read `t`'s queue at `now` with `filter`, taking out.
pub fn read(m: &mut WindowManager, t: ThreadId, filter: &Filter, now: u64) -> Taken {
    take(&mut m.windows, t, filter, true, now).unwrap()
}

/// Hand out and end every sent message waiting for `t`, as user32 delivers them: (window,
/// message) each.
pub fn deliver(m: &mut WindowManager, t: ThreadId) -> Vec<(Hwnd, u32)> {
    let only_sent = Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
    let mut got = Vec::new();
    while let Taken::Sent(id) = read(m, t, &only_sent, 0) {
        let head = head_of(&m.windows, id).unwrap();
        got.push((head.msg.hwnd, head.msg.message));
        assert!(end_sent(&mut m.windows, t, 0));
    }
    got
}

/// The payload the callback that delivers the sent message `id` carries.
pub fn payload_of(m: &WindowManager, id: SentId) -> Payload {
    match delivery(&m.windows, &m.classes, id) {
        Some(Delivery::Structure(_, message)) => message.payload,
        other => panic!("a structure's callback, not {other:?}"),
    }
}

/// The text the callback that delivers the sent message `id` carries: its slot, its head, the
/// text and WM_GETTEXT's buffer units.
pub fn text_of(m: &WindowManager, id: SentId) -> (u32, CallbackMsg, Vec<u16>, u32) {
    match delivery(&m.windows, &m.classes, id) {
        Some(Delivery::Text {
            api,
            head,
            text,
            room,
        }) => (api, head, carried_units(&m.windows, text).to_vec(), room),
        other => panic!("a text's callback, not {other:?}"),
    }
}

/// Any message, window or range.
pub fn all() -> Filter {
    Filter::new(0, 0, 0, 0)
}

/// The message a read found.
pub fn msg_of(taken: Taken) -> Msg {
    match taken {
        Taken::Message(msg) => msg,
        other => panic!("a message, not {other:?}"),
    }
}

/// A callback's output: `bytes` after the LRESULT.
pub fn out(bytes: &[u8]) -> CallbackOut {
    let mut out = CallbackOut {
        bytes: [0; OUT_MAX],
        length: bytes.len().min(OUT_MAX),
    };
    out.bytes[..out.length].copy_from_slice(&bytes[..out.length]);
    out
}

/// The sent messages in the pool, live.
pub fn live_sends(m: &WindowManager) -> usize {
    m.windows.queues.sent.live() as usize
}

/// A decision's message to another thread's window with an in-out structure.
pub fn decision_message(message: u32, wparam: WParam, payload: Payload) -> Message {
    Message {
        message,
        wparam,
        lparam: 0,
        payload,
    }
}
