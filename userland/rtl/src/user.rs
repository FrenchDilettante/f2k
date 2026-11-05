//! USER's shared shapes: the message constants user32's message calls and win32k's queue agree on
//! (the messages the queue makes or reads, PeekMessage's flags, the queue-status bits), the
//! structures Windows 2000's winuser.h lays out on x86 (MSG, PAINTSTRUCT, CREATESTRUCTW), and F2K's
//! own shapes of the services behind them: the receipt win32k's GetMessage and PeekMessage services
//! hand user32 ([`Receipt`]), and the routines of the NtUserCall* services ([`ONE_PARAM_*`],
//! [`HWND_LOCK_*`]). Only F2K's user32 calls those services, so their shapes are F2K's.
//!
//! A message another thread sent, or one win32k sent on its own behalf (the window's creation and
//! destruction messages), reaches the window procedure through the receiving thread's own message
//! calls: the receipt names the procedure, user32 calls it and hands its answer back
//! ([`ONE_PARAM_END_SENT_MESSAGE`]).
//!
//! [`ONE_PARAM_*`]: ONE_PARAM_POST_QUIT_MESSAGE
//! [`HWND_LOCK_*`]: HWND_LOCK_UPDATE_WINDOW

use crate::gdi::Rect;
use crate::pod::Pod;
use crate::window::WindowPos;

// --- The messages (winuser.h's WM_*) -------------------------------------------------------------

pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_USER: u32 = 0x0400;

/// PostMessage's window that names every top-level window (HWND_BROADCAST).
pub const HWND_BROADCAST: u32 = 0xFFFF;

// --- PeekMessage's flags (winuser.h's PM_*) ------------------------------------------------------

/// The message stays in the queue.
pub const PM_NOREMOVE: u32 = 0x0000;
/// The message is taken out of the queue (WM_PAINT excepted: only validating the window does).
pub const PM_REMOVE: u32 = 0x0001;
/// No yield to other threads when nothing is found (there is nothing to yield on F2K's queue).
pub const PM_NOYIELD: u32 = 0x0002;

// --- The queue-status bits (winuser.h's QS_*) ----------------------------------------------------

pub const QS_KEY: u32 = 0x0001;
pub const QS_MOUSEMOVE: u32 = 0x0002;
pub const QS_MOUSEBUTTON: u32 = 0x0004;
pub const QS_POSTMESSAGE: u32 = 0x0008;
pub const QS_TIMER: u32 = 0x0010;
pub const QS_PAINT: u32 = 0x0020;
pub const QS_SENDMESSAGE: u32 = 0x0040;
pub const QS_HOTKEY: u32 = 0x0080;
pub const QS_ALLPOSTMESSAGE: u32 = 0x0100;
pub const QS_MOUSE: u32 = QS_MOUSEMOVE | QS_MOUSEBUTTON;
pub const QS_INPUT: u32 = QS_MOUSE | QS_KEY;

/// PeekMessage's kinds of message to look at (PM_QS_*): the queue-status bits in the high word.
/// None of them set looks at every kind.
pub const PM_QS_INPUT: u32 = QS_INPUT << 16;
pub const PM_QS_POSTMESSAGE: u32 = (QS_POSTMESSAGE | QS_HOTKEY | QS_TIMER) << 16;
pub const PM_QS_PAINT: u32 = QS_PAINT << 16;
pub const PM_QS_SENDMESSAGE: u32 = QS_SENDMESSAGE << 16;

// --- The structures (winuser.h) ------------------------------------------------------------------

/// POINT.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

// SAFETY: two integers.
unsafe impl Pod for Point {}

/// MSG: a message as GetMessage and PeekMessage retrieve it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msg {
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u32,
    pub lparam: i32,
    /// When the message was posted (or made, for the ones the queue makes), in milliseconds since
    /// the boot.
    pub time: u32,
    /// The cursor's position then.
    pub pt: Point,
}

// SAFETY: integers only.
unsafe impl Pod for Msg {}

/// PAINTSTRUCT: what BeginPaint hands its caller.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaintStruct {
    pub hdc: u32,
    /// fErase: the background still needs erasing (a BOOL).
    pub erase: i32,
    /// rcPaint: the area to paint, in client coordinates.
    pub paint: Rect,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}

// SAFETY: integers and bytes only.
unsafe impl Pod for PaintStruct {}

/// CREATESTRUCTW: WM_NCCREATE's and WM_CREATE's lParam.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateStructW {
    pub create_params: u32,
    pub instance: u32,
    pub menu: u32,
    pub parent: u32,
    pub cy: i32,
    pub cx: i32,
    pub y: i32,
    pub x: i32,
    pub style: u32,
    /// lpszName: the window name.
    pub name: u32,
    /// lpszClass: the class name, or its atom.
    pub class: u32,
    pub ex_style: u32,
}

// SAFETY: integers only.
unsafe impl Pod for CreateStructW {}

// --- F2K's receipt -------------------------------------------------------------------------------

/// What a receipt holds: WM_QUIT (GetMessage answers 0 for it), a posted message or one the queue
/// made (WM_PAINT, WM_TIMER), a sent message for the window procedure the receipt names, or nothing
/// (PeekMessage on a queue with nothing for the filter).
pub const RECEIVED_QUIT: u32 = 0;
pub const RECEIVED_MESSAGE: u32 = 1;
pub const RECEIVED_SENT: u32 = 2;
pub const RECEIVED_NONE: u32 = 3;

/// The longest window name a receipt carries, its terminator included.
pub const RECEIPT_TEXT: usize = 129;

/// What win32k's GetMessage and PeekMessage services write into user32's buffer.
///
/// For a sent message, `proc` is the window procedure to call with `msg`'s window, message and
/// parameters; when the message carries a structure, `msg.lparam` points at the receipt's own copy
/// of it: `create` (WM_NCCREATE, WM_CREATE: its `name` points at `name`, its `class` holds the
/// class's atom) or `rect` (WM_NCCALCSIZE). The answer goes back with
/// [`ONE_PARAM_END_SENT_MESSAGE`] once the procedure returns.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub kind: u32,
    pub proc: u32,
    pub msg: Msg,
    pub create: CreateStructW,
    pub rect: Rect,
    pub window_pos: WindowPos,
    pub name: [u16; RECEIPT_TEXT],
    /// Keeps the size a multiple of four.
    pub pad: u16,
}

// SAFETY: integers and arrays of them; the trailing unit fills what would be padding.
unsafe impl Pod for Receipt {}

/// The part of a receipt every message has: what it is, the procedure, the message.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiptHead {
    pub kind: u32,
    pub proc: u32,
    pub msg: Msg,
}

// SAFETY: integers only.
unsafe impl Pod for ReceiptHead {}

// --- The NtUserCall* services' routines (F2K's numbering) ----------------------------------------

/// NtUserCallOneParam's routines: PostQuitMessage (the parameter is the exit code), ReplyMessage
/// (the parameter is the answer; the result is whether the thread was answering another thread's
/// message), and the end of a sent message's delivery (the parameter is the window procedure's
/// answer, handed to the sender unless ReplyMessage did already).
pub const ONE_PARAM_POST_QUIT_MESSAGE: u32 = 0;
pub const ONE_PARAM_REPLY_MESSAGE: u32 = 1;
pub const ONE_PARAM_END_SENT_MESSAGE: u32 = 2;

/// NtUserCallHwndLock's routines: UpdateWindow (a WM_PAINT sent to the window when its update
/// region is not empty).
pub const HWND_LOCK_UPDATE_WINDOW: u32 = 0;

/// NtUserGetUpdateRect's answer bits: the update region is not empty; the caller is to send the
/// window WM_ERASEBKGND (it asked for the erase, and one was pending).
pub const UPDATE_NOT_EMPTY: u32 = 0x1;
pub const UPDATE_ERASE: u32 = 0x2;

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::*;

    /// The structures' sizes and offsets, as winuser.h lays them out on x86; the receipt's parts
    /// where user32 finds them.
    #[test]
    fn the_layouts_are_windows_2000s() {
        assert_eq!(size_of::<Point>(), 8);
        assert_eq!(size_of::<Msg>(), 28);
        assert_eq!(offset_of!(Msg, time), 16);
        assert_eq!(offset_of!(Msg, pt), 20);
        assert_eq!(size_of::<PaintStruct>(), 64);
        assert_eq!(offset_of!(PaintStruct, paint), 8);
        assert_eq!(offset_of!(PaintStruct, reserved), 32);
        assert_eq!(size_of::<CreateStructW>(), 48);
        assert_eq!(offset_of!(CreateStructW, cy), 16);
        assert_eq!(offset_of!(CreateStructW, x), 28);
        assert_eq!(offset_of!(CreateStructW, ex_style), 44);
        assert_eq!(size_of::<ReceiptHead>(), 36);
        assert_eq!(offset_of!(Receipt, msg), 8);
        assert_eq!(offset_of!(Receipt, create), 36);
        assert_eq!(offset_of!(Receipt, rect), 84);
        assert_eq!(offset_of!(Receipt, window_pos), 100);
        assert_eq!(offset_of!(Receipt, name), 128);
        assert_eq!(size_of::<Receipt>() % 4, 0);
    }

    /// PeekMessage's kinds are the status bits in the high word.
    #[test]
    fn the_peek_kinds_are_the_status_bits() {
        assert_eq!(PM_QS_INPUT, 0x0007_0000);
        assert_eq!(PM_QS_POSTMESSAGE, 0x0098_0000);
        assert_eq!(PM_QS_PAINT, 0x0020_0000);
        assert_eq!(PM_QS_SENDMESSAGE, 0x0040_0000);
    }
}
