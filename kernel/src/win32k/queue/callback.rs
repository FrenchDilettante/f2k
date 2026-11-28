//! The callbacks the window manager's messages go through: their slots, input blocks and
//! read-back.

use core::mem::size_of;

use rtl::callback::{
    CallbackMsg,
    FN_DWORD,
    FN_INLPCREATESTRUCT,
    FN_INLPWINDOWPOS,
    FN_INOUTLPPOINT5,
    FN_INOUTLPWINDOWPOS,
    FN_INOUTNCCALCSIZE,
    FN_INOUTSTYLECHANGE,
    FN_NCDESTROY,
    OUT_MAX,
};
use rtl::pod::Pod;
use rtl::user::{CreateStructW, StyleStruct, WM_NCDESTROY, WM_WINDOWPOSCHANGING};

use crate::win32k::class;
use crate::win32k::window::{self, ClassArg, Hwnd, Message, Payload, WindowId, WindowPos, Windows};

/// The `__fn*` slot a message the window manager sends goes through, by its payload's kind (see
/// [`callback_input`]).
pub(super) fn slot(message: u32, payload: &Payload) -> u32 {
    match payload {
        Payload::None if message == WM_NCDESTROY => FN_NCDESTROY,
        Payload::None => FN_DWORD,
        Payload::Rect(_) | Payload::CalcSize(_) => FN_INOUTNCCALCSIZE,
        Payload::WindowPos(_) if message == WM_WINDOWPOSCHANGING => FN_INOUTLPWINDOWPOS,
        Payload::WindowPos(_) => FN_INLPWINDOWPOS,
        Payload::Style(_) => FN_INOUTSTYLECHANGE,
        Payload::MinMax(_) => FN_INOUTLPPOINT5,
        Payload::Create(_) => FN_INLPCREATESTRUCT,
    }
}

/// The callback for a message the window manager sends to `target` (procedure `proc`), per
/// rtl::callback's notes: the `__fn*` slot of its payload's kind ([`slot`]), the input block's
/// head, and the structure after it (its first `length` bytes). A creation message's window name
/// follows the structure ([`Windows::create_text`]); its CREATESTRUCTW's lpszClass is the class's
/// atom. WM_NCCALCSIZE's NCCALCSIZE_PARAMS is followed by its WINDOWPOS (lppos 0: user32 points it
/// at the copy); WM_WINDOWPOSCHANGING takes the in-out WINDOWPOS slot, WM_WINDOWPOSCHANGED the
/// input-only one.
pub fn callback_input(
    windows: &Windows,
    classes: &class::Registry,
    target: WindowId,
    proc: u32,
    message: &Message,
) -> CallbackInput {
    callback_input_for(windows, classes, windows.handle_of(target), proc, message)
}

/// [`callback_input`] for the window `hwnd`, by its handle: a message another thread sent, whose
/// window may be gone by its delivery.
pub(super) fn callback_input_for(
    windows: &Windows,
    classes: &class::Registry,
    hwnd: Hwnd,
    proc: u32,
    message: &Message,
) -> CallbackInput {
    let mut input = CallbackInput {
        api: slot(message.message, &message.payload),
        head: CallbackMsg {
            proc,
            hwnd,
            message: message.message,
            wparam: message.wparam,
            lparam: message.lparam,
        },
        carried: [0; CARRIED],
        length: 0,
    };
    let mut put = |bytes: &[u8]| {
        input.carried[input.length..input.length + bytes.len()].copy_from_slice(bytes);
        input.length += bytes.len();
    };
    match &message.payload {
        Payload::None => {}
        Payload::Rect(r) => put(r.as_bytes()),
        Payload::CalcSize(calc) => {
            let params = rtl::window::NcCalcSizeParams {
                rects: calc.rects,
                pos: 0,
            };
            put(params.as_bytes());
            put(calc.pos.as_bytes());
        }
        Payload::WindowPos(p) => put(p.as_bytes()),
        Payload::Style(style) => put(style.as_bytes()),
        Payload::MinMax(mmi) => put(mmi.raw().as_bytes()),
        Payload::Create(p) => {
            let class = match p.class_name {
                ClassArg::Atom(atom) => atom,
                ClassArg::Name | ClassArg::AnsiName => windows
                    .class_window(hwnd)
                    .map_or(0, |w| classes.atom(w.class)),
            };
            let create = CreateStructW {
                create_params: p.params,
                instance: p.instance,
                menu: p.menu,
                parent: p.parent,
                cy: p.cy,
                cx: p.cx,
                y: p.y,
                x: p.x,
                style: p.style,
                name: 0,
                class: u32::from(class),
                ex_style: p.ex_style,
            };
            put(create.as_bytes());
        }
    }
    input
}

/// The longest structure a callback's block carries: an NCCALCSIZE_PARAMS and its WINDOWPOS (a
/// CREATESTRUCTW is shorter).
const CARRIED: usize = size_of::<rtl::window::NcCalcSizeParams>() + size_of::<WindowPos>();
const _: () = assert!(CARRIED >= size_of::<CreateStructW>());

/// What a callback's output block hands back after the LRESULT (rtl::callback's notes): at most
/// [`OUT_MAX`] bytes, read from the user's output block by the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackOut {
    pub bytes: [u8; OUT_MAX],
    /// How many of them the routine handed back.
    pub length: usize,
}

/// The structure `message` carried, written back from the callback output `out` (the bytes after
/// the LRESULT): in-out slots only ([`rtl::callback::out_size`]), and only when the routine handed
/// back the whole structure; anything shorter (an untrusted routine's short or missing block)
/// leaves it as sent, anything longer is not read. WM_NCCALCSIZE's TRUE form takes back its three
/// rectangles, not lppos; WM_WINDOWPOSCHANGED and the creation's structures are input only.
pub fn read_back(api: u32, message: &mut Message, out: &CallbackOut) {
    let wanted = rtl::callback::out_size(api, message.wparam);
    if wanted == 0 || out.length < wanted {
        return;
    }
    let bytes = &out.bytes[..wanted];
    match (&mut message.payload, api) {
        (Payload::Rect(rect), FN_INOUTNCCALCSIZE) => {
            if let Some(back) = rtl::gdi::Rect::from_bytes(bytes) {
                *rect = back;
            }
        }
        (Payload::CalcSize(calc), FN_INOUTNCCALCSIZE) => {
            if let Some(back) = rtl::window::NcCalcSizeParams::from_bytes(bytes) {
                calc.rects = back.rects;
            }
        }
        (Payload::WindowPos(pos), FN_INOUTLPWINDOWPOS) => {
            if let Some(back) = WindowPos::from_bytes(bytes) {
                *pos = back;
            }
        }
        (Payload::Style(style), FN_INOUTSTYLECHANGE) => {
            if let Some(back) = StyleStruct::from_bytes(bytes) {
                *style = back;
            }
        }
        (Payload::MinMax(mmi), FN_INOUTLPPOINT5) => {
            if let Some(back) = rtl::user::MinMaxInfo::from_bytes(bytes) {
                *mmi = window::MinMaxInfo::of_raw(&back);
            }
        }
        _ => {}
    }
}

/// A message's callback, as [`callback_input`] makes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackInput {
    /// The `__fn*` slot.
    pub api: u32,
    pub head: CallbackMsg,
    /// The structure, its first `length` bytes.
    pub carried: [u8; CARRIED],
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use rtl::user::{
        WM_DESTROY,
        WM_GETMINMAXINFO,
        WM_NCCALCSIZE,
        WM_NCCREATE,
        WM_NCDESTROY,
        WM_STYLECHANGING,
        WM_WINDOWPOSCHANGED,
        WS_POPUP,
    };

    use super::*;
    use crate::win32k::queue::testkit::*;

    /// A creation message's callback: `__fnINLPCREATESTRUCT`, the class's procedure, and the
    /// CREATESTRUCTW the creation's parameters make (the class's atom for a class named by its
    /// string, lpszName left for the routine to point at the name after it); WM_NCDESTROY's is
    /// `__fnNCDESTROY`, another plain message's `__fnDWORD` with its lParam as it is, and
    /// WM_NCCALCSIZE's `__fnINOUTNCCALCSIZE` with the rectangle.
    #[test]
    fn a_messages_callback_carries_its_structure() {
        let (m, atom) = manager();
        let t = thread(m, 1, 0x100);
        let h = window_at(m, atom, t, WS_POPUP, 0, 5, 6, 30, 40);
        let w = m.windows.window_from_handle(h).unwrap();
        let params = window::CreateParams {
            ex_style: 0x8,
            class_name: ClassArg::Name,
            name: window::CreateName::Given,
            style: WS_POPUP,
            x: 5,
            y: 6,
            cx: 30,
            cy: 40,
            parent: 0,
            menu: 0,
            instance: MODULE,
            params: 0x1234,
        };
        let message = |message, payload| Message {
            message,
            wparam: 3,
            lparam: 4,
            payload,
        };
        let create = message(WM_NCCREATE, Payload::Create(params));
        let input = callback_input(&m.windows, &m.classes, w, PROC, &create);
        assert_eq!(input.api, FN_INLPCREATESTRUCT);
        assert_eq!(
            input.head,
            CallbackMsg {
                proc: PROC,
                hwnd: h,
                message: WM_NCCREATE,
                wparam: 3,
                lparam: 4,
            }
        );
        assert_eq!(input.length, 48);
        let cs = CreateStructW::from_bytes(&input.carried).unwrap();
        assert_eq!((cs.x, cs.y, cs.cx, cs.cy), (5, 6, 30, 40));
        assert_eq!(cs.create_params, 0x1234);
        assert_eq!(cs.instance, MODULE);
        assert_eq!((cs.style, cs.ex_style), (WS_POPUP, 0x8));
        assert_eq!(cs.name, 0);
        assert_eq!(cs.class, u32::from(atom));

        let plain = |number| {
            let input = callback_input(
                &m.windows,
                &m.classes,
                w,
                PROC,
                &message(number, Payload::None),
            );
            (input.api, input.head.lparam, input.length)
        };
        assert_eq!(plain(WM_NCDESTROY), (FN_NCDESTROY, 4, 0));
        assert_eq!(plain(WM_DESTROY), (FN_DWORD, 4, 0));
        let rect = rtl::gdi::Rect::new(1, 2, 3, 4);
        let input = callback_input(
            &m.windows,
            &m.classes,
            w,
            PROC,
            &message(WM_NCCALCSIZE, Payload::Rect(rect)),
        );
        assert_eq!((input.api, input.length), (FN_INOUTNCCALCSIZE, 16));
        assert_eq!(&input.carried[..16], rect.as_bytes());

        // A resize's WM_NCCALCSIZE (wParam TRUE): the NCCALCSIZE_PARAMS, lppos 0, then the
        // WINDOWPOS.
        let pos = WindowPos {
            hwnd: h,
            cx: 250,
            flags: 0x14,
            ..WindowPos::default()
        };
        let calc = window::CalcSize {
            rects: [rect, rtl::gdi::Rect::new(5, 6, 7, 8), rect],
            pos,
        };
        let mut resize = message(WM_NCCALCSIZE, Payload::CalcSize(calc));
        resize.wparam = 1;
        let input = callback_input(&m.windows, &m.classes, w, PROC, &resize);
        assert_eq!((input.api, input.length), (FN_INOUTNCCALCSIZE, 80));
        let params = rtl::window::NcCalcSizeParams::from_bytes(&input.carried[..52]).unwrap();
        assert_eq!((params.rects, params.pos), (calc.rects, 0));
        assert_eq!(&input.carried[52..80], pos.as_bytes());

        // WM_WINDOWPOSCHANGING's WINDOWPOS goes in and out, WM_WINDOWPOSCHANGED's in only.
        let slot = |number| {
            let input = callback_input(
                &m.windows,
                &m.classes,
                w,
                PROC,
                &message(number, Payload::WindowPos(pos)),
            );
            assert_eq!(&input.carried[..28], pos.as_bytes());
            (input.api, input.length)
        };
        assert_eq!(slot(WM_WINDOWPOSCHANGING), (FN_INOUTLPWINDOWPOS, 28));
        assert_eq!(slot(WM_WINDOWPOSCHANGED), (FN_INLPWINDOWPOS, 28));

        // WM_GETMINMAXINFO's MINMAXINFO, five POINTs, in and out.
        let mmi = window::MinMaxInfo {
            reserved: (1, 2),
            max_size: (3, 4),
            max_position: (5, 6),
            min_track: (7, 8),
            max_track: (9, 10),
        };
        let input = callback_input(
            &m.windows,
            &m.classes,
            w,
            PROC,
            &message(WM_GETMINMAXINFO, Payload::MinMax(mmi)),
        );
        assert_eq!((input.api, input.length), (FN_INOUTLPPOINT5, 40));
        let words: Vec<i32> = input.carried[..40]
            .chunks(4)
            .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    /// The in-out slots' structures come back as the procedure left them: WM_NCCALCSIZE's
    /// rectangle, or its NCCALCSIZE_PARAMS's three rectangles (not lppos, nor the WINDOWPOS);
    /// WM_WINDOWPOSCHANGING's WINDOWPOS; WM_STYLECHANGING's STYLESTRUCT.
    #[test]
    fn a_callbacks_structure_comes_back() {
        let message = |message, wparam, payload| Message {
            message,
            wparam,
            lparam: 0,
            payload,
        };
        let rect = rtl::gdi::Rect::new(0, 0, 200, 100);
        let client = rtl::gdi::Rect::new(10, 10, 190, 90);
        let mut m = message(WM_NCCALCSIZE, 0, Payload::Rect(rect));
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(client.as_bytes()));
        assert_eq!(m.payload, Payload::Rect(client));

        let calc = window::CalcSize {
            rects: [rect; 3],
            pos: WindowPos::default(),
        };
        let back = rtl::window::NcCalcSizeParams {
            rects: [client, rect, client],
            pos: 0x7FFE_0000,
        };
        let mut m = message(WM_NCCALCSIZE, 1, Payload::CalcSize(calc));
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(back.as_bytes()));
        assert_eq!(
            m.payload,
            Payload::CalcSize(window::CalcSize {
                rects: [client, rect, client],
                pos: WindowPos::default(),
            })
        );

        let pos = WindowPos {
            x: 60,
            y: 70,
            cx: 220,
            cy: 130,
            ..WindowPos::default()
        };
        let edited = WindowPos {
            cx: 250,
            flags: 0x2,
            ..pos
        };
        let mut m = message(WM_WINDOWPOSCHANGING, 0, Payload::WindowPos(pos));
        read_back(FN_INOUTLPWINDOWPOS, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(edited));

        let style = StyleStruct {
            style_old: 0x04C0_0000,
            style_new: 0x04C8_0000,
        };
        let stuck = StyleStruct {
            style_new: 0x04CC_0000,
            ..style
        };
        let mut m = message(WM_STYLECHANGING, -16i32 as u32, Payload::Style(style));
        read_back(FN_INOUTSTYLECHANGE, &mut m, &out(stuck.as_bytes()));
        assert_eq!(m.payload, Payload::Style(stuck));

        // WM_GETMINMAXINFO's MINMAXINFO, whatever the procedure left in it (guigeo `edits`').
        let defaults = window::MinMaxInfo::unbounded();
        let answered = window::MinMaxInfo {
            reserved: (0, 0),
            max_size: (380, 280),
            max_position: (20, 30),
            min_track: (300, 250),
            max_track: (400, 300),
        };
        let mut m = message(WM_GETMINMAXINFO, 0, Payload::MinMax(defaults));
        read_back(FN_INOUTLPPOINT5, &mut m, &out(answered.raw().as_bytes()));
        assert_eq!(m.payload, Payload::MinMax(answered));
    }

    /// A routine's output is untrusted: one shorter than the slot's structure leaves the structure
    /// as it was sent, the bytes past it are not read, an input-only slot's are ignored, and a
    /// payload of another kind than the slot's is not written.
    #[test]
    fn a_short_or_foreign_callback_output_changes_nothing() {
        let rect = rtl::gdi::Rect::new(0, 0, 200, 100);
        let client = rtl::gdi::Rect::new(10, 10, 190, 90);
        let mut m = Message {
            message: WM_NCCALCSIZE,
            wparam: 0,
            lparam: 0,
            payload: Payload::Rect(rect),
        };
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&client.as_bytes()[..12]));
        assert_eq!(m.payload, Payload::Rect(rect), "short");
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&[]));
        assert_eq!(m.payload, Payload::Rect(rect), "none");
        let mut long = client.as_bytes().to_vec();
        long.extend_from_slice(&[0xFF; 36]);
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(&long));
        assert_eq!(
            m.payload,
            Payload::Rect(client),
            "longer: the rectangle alone"
        );

        // The TRUE form wants the whole NCCALCSIZE_PARAMS: a RECT's worth is short.
        let calc = window::CalcSize {
            rects: [rect; 3],
            pos: WindowPos::default(),
        };
        let mut m = Message {
            message: WM_NCCALCSIZE,
            wparam: 1,
            lparam: 0,
            payload: Payload::CalcSize(calc),
        };
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(client.as_bytes()));
        assert_eq!(m.payload, Payload::CalcSize(calc));

        let pos = WindowPos {
            cx: 220,
            ..WindowPos::default()
        };
        let edited = WindowPos { cx: 250, ..pos };
        let mut m = Message {
            message: WM_WINDOWPOSCHANGED,
            wparam: 0,
            lparam: 0,
            payload: Payload::WindowPos(pos),
        };
        read_back(FN_INLPWINDOWPOS, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(pos), "input only");
        read_back(FN_INOUTNCCALCSIZE, &mut m, &out(edited.as_bytes()));
        assert_eq!(m.payload, Payload::WindowPos(pos), "another kind's slot");

        // A MINMAXINFO short of its last POINT stays the defaults.
        let defaults = window::MinMaxInfo::unbounded();
        let answered = window::MinMaxInfo {
            min_track: (300, 250),
            ..defaults
        };
        let mut m = Message {
            message: WM_GETMINMAXINFO,
            wparam: 0,
            lparam: 0,
            payload: Payload::MinMax(defaults),
        };
        read_back(
            FN_INOUTLPPOINT5,
            &mut m,
            &out(&answered.raw().as_bytes()[..32]),
        );
        assert_eq!(m.payload, Payload::MinMax(defaults), "MINMAXINFO short");
        read_back(FN_INOUTLPWINDOWPOS, &mut m, &out(answered.raw().as_bytes()));
        assert_eq!(m.payload, Payload::MinMax(defaults), "another slot's");
    }
}
