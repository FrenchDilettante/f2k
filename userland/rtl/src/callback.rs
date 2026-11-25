//! The kernel's calls into user mode (KeUserModeCallback): what the kernel and user32 agree on.
//!
//! The kernel enters ntdll's KiUserCallbackDispatcher with an API number and an input block on the
//! user stack; the dispatcher calls `PEB.KernelCallbackTable[api](input, length)`, a table user32
//! sets at its process attach, and the routine answers through NtCallbackReturn (its output block,
//! its length, a status). The table's slots are Windows 2000's `__fn*` dispatch routines
//! ([`FN_DWORD`] and the others), [`CALLBACK_SLOTS`] of them, the last F2K's own [`SMOKE_API`].
//!
//! A message the window manager sends to a window of the thread it decides for (the creation's
//! WM_NCCREATE and WM_CREATE, the destruction's WM_DESTROY and WM_NCDESTROY, what showing, moving
//! and activating send) is a callback to the slot its lParam's kind names, as Windows 2000's
//! win32k picks the `__fn*` thunk by message: the input block is a [`CallbackMsg`] (the procedure
//! to call and the message), then the structure the lParam points at, if the message carries one,
//! which the routine points the lParam at; WM_NCCREATE's and WM_CREATE's CREATESTRUCTW is followed
//! by the window name, NUL-terminated, which the routine points its lpszName at. The routine
//! answers the procedure's LRESULT as its output block (four bytes); an `__fnINOUT*` slot's
//! output block goes on with the structure as the procedure left it ([`out_size`]), which the
//! kernel reads back (no more than that many bytes, and nothing from a shorter block: a user-mode
//! answer is untrusted) — WM_NCCALCSIZE's client rectangle, WM_WINDOWPOSCHANGING's new place,
//! WM_STYLECHANGING's new style.
//!
//! WM_NCCALCSIZE comes in two forms, by its wParam: FALSE carries a RECT, TRUE an
//! NCCALCSIZE_PARAMS ([`crate::window::NcCalcSizeParams`]) and the move's WINDOWPOS after it,
//! which the routine points the structure's lppos at.
//!
//! The smoke slot serves the kernel's `callback-smoke` boot: each [`SmokeRequest`] names an
//! operation ([`op`]), and a routine that calls back into the kernel for a nested level enters it
//! through NtQuerySystemInformation with the class [`SMOKE_INFORMATION_CLASS`] and a request of its
//! own (so user32 keeps entering the kernel only as Windows 2000's does: its win32k stubs, and
//! ntdll's for the rest). Without that feature the kernel never calls the slot, and the class is
//! the invalid one it is to every other kernel.

use crate::pod::Pod;

/// The callback table's length: Windows 2000's `__fn*` slots and F2K's smoke slot.
pub const CALLBACK_SLOTS: usize = 128;

// The Windows 2000 slots F2K serves (apfnDispatch's order, as later Windows versions keep it): a
// message's thunk by the kind of its lParam.

/// `__fnDWORD`: a message whose parameters are plain values.
pub const FN_DWORD: u32 = 2;
/// `__fnNCDESTROY`: WM_NCDESTROY (a plain message, the window's client-side state let go after).
pub const FN_NCDESTROY: u32 = 3;
/// `__fnINLPCREATESTRUCT`: WM_NCCREATE and WM_CREATE, the CREATESTRUCTW and the window name.
pub const FN_INLPCREATESTRUCT: u32 = 10;
/// `__fnINLPWINDOWPOS`: WM_WINDOWPOSCHANGED, the WINDOWPOS (in only).
pub const FN_INLPWINDOWPOS: u32 = 17;
/// `__fnINOUTNCCALCSIZE`: WM_NCCALCSIZE, the window rectangle (wParam FALSE) or the
/// NCCALCSIZE_PARAMS and its WINDOWPOS (wParam TRUE); out: the RECT, or the NCCALCSIZE_PARAMS.
pub const FN_INOUTNCCALCSIZE: u32 = 21;
/// `__fnINOUTLPWINDOWPOS`: WM_WINDOWPOSCHANGING, the WINDOWPOS in and out. (Its slot number is
/// F2K's pick among the table's, not checked against Windows 2000's apfnDispatch.)
pub const FN_INOUTLPWINDOWPOS: u32 = 22;
/// `__fnINOUTSTYLECHANGE`: WM_STYLECHANGING and WM_STYLECHANGED, the STYLESTRUCT in and out.
pub const FN_INOUTSTYLECHANGE: u32 = 39;

/// The size of the structure a message slot's output block carries after the LRESULT: the
/// `__fnINOUT*` slots' (WM_NCCALCSIZE's by its form, `wparam`), none for the others.
pub const fn out_size(api: u32, wparam: u32) -> usize {
    match api {
        FN_INOUTNCCALCSIZE if wparam != 0 => {
            core::mem::size_of::<crate::window::NcCalcSizeParams>()
        }
        FN_INOUTNCCALCSIZE => core::mem::size_of::<crate::gdi::Rect>(),
        FN_INOUTLPWINDOWPOS => core::mem::size_of::<crate::window::WindowPos>(),
        FN_INOUTSTYLECHANGE => core::mem::size_of::<crate::user::StyleStruct>(),
        _ => 0,
    }
}

/// The longest structure an output block carries after the LRESULT.
pub const OUT_MAX: usize = core::mem::size_of::<crate::window::NcCalcSizeParams>();

/// The head of a message callback's input block: the procedure to call and the message. The
/// structure the message carries follows it, if any (see the module notes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackMsg {
    /// The window procedure's address.
    pub proc: u32,
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u32,
    /// The lParam, for a message that carries no structure.
    pub lparam: i32,
}

// SAFETY: five 32-bit integers, no padding.
unsafe impl Pod for CallbackMsg {}

/// The smoke slot: the table's last, past every Windows 2000 slot.
pub const SMOKE_API: u32 = CALLBACK_SLOTS as u32 - 1;

/// The information class a smoke routine asks NtQuerySystemInformation for: the request as the
/// buffer (its length the request's), the reply's address as the return length's place. Served
/// only by a `callback-smoke` kernel; no Windows class is near it.
pub const SMOKE_INFORMATION_CLASS: u32 = 0xF2C0_0001;

/// What a smoke callback or the smoke's kernel entry is asked to do.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmokeRequest {
    /// One of [`op`].
    pub op: u32,
    /// The levels still to nest ([`op::NEST`], [`op::EXIT`]).
    pub depth: u32,
    /// The operation's argument: a value to echo, an address to touch, an APC routine.
    pub argument: u32,
}

// SAFETY: three u32s, no padding.
unsafe impl Pod for SmokeRequest {}

/// A smoke callback's answer (its NtCallbackReturn output) or the smoke's kernel entry's reply.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmokeReply {
    pub answer: u32,
    pub detail: u32,
}

// SAFETY: two u32s, no padding.
unsafe impl Pod for SmokeReply {}

/// The smoke operations. A callback for each answers as follows; the smoke's kernel entry, asked
/// for one, calls back with the same request (APC and a zero-depth EXIT excepted).
pub mod op {
    /// Answer the argument plus one.
    pub const ECHO: u32 = 1;
    /// At depth 1, answer 1; deeper, call back one level less deep through the service and answer
    /// the inner answer times ten plus the depth (3 deep: 123). A failed inner call's status is
    /// the answer's, the inner reply with it.
    pub const NEST: u32 = 2;
    /// Read the byte at the argument under an exception frame of the routine's own: answer 1 when
    /// it could be read, 0 when the read faulted.
    pub const PROBE: u32 = 3;
    /// Call back RAISE (same argument) through the service under an exception frame of the
    /// routine's own: answer the exception code it caught, 0 for none.
    pub const ESCAPE: u32 = 4;
    /// Read the byte at the argument with no exception frame of the routine's own.
    pub const RAISE: u32 = 5;
    /// Ask the service to queue a user APC on the calling thread and arm its delivery: answer the
    /// value the APC routine left (the routine's context), 0 when it did not run.
    pub const APC: u32 = 6;
    /// Call back EXIT one level less deep through the service; at depth 1, ask the service to end
    /// the process ([`super::SMOKE_EXIT_CODE`]).
    pub const EXIT: u32 = 7;
}

/// The exit code a smoke EXIT ends the process with.
pub const SMOKE_EXIT_CODE: u32 = 203;

/// The APC context the smoke APC routine is queued with, and leaves for its callback to answer.
pub const SMOKE_APC_CONTEXT: u32 = 0x00A9_C000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smoke_slot_is_the_tables_last() {
        assert_eq!(SMOKE_API, 127);
        assert_eq!(core::mem::size_of::<SmokeRequest>(), 12);
        assert_eq!(core::mem::size_of::<SmokeReply>(), 8);
        assert!(SMOKE_INFORMATION_CLASS > 0xFFFF);
        assert_eq!(core::mem::size_of::<CallbackMsg>(), 20);
        for slot in [
            FN_DWORD,
            FN_NCDESTROY,
            FN_INLPCREATESTRUCT,
            FN_INLPWINDOWPOS,
            FN_INOUTNCCALCSIZE,
            FN_INOUTLPWINDOWPOS,
            FN_INOUTSTYLECHANGE,
        ] {
            assert!(slot < SMOKE_API);
        }
    }

    /// The in-out slots' output structures; the input-only slots carry none back.
    #[test]
    fn out_sizes() {
        assert_eq!(out_size(FN_INOUTNCCALCSIZE, 0), 16);
        assert_eq!(out_size(FN_INOUTNCCALCSIZE, 1), 52);
        assert_eq!(out_size(FN_INOUTLPWINDOWPOS, 0), 28);
        assert_eq!(out_size(FN_INOUTSTYLECHANGE, 0), 8);
        assert_eq!(out_size(FN_INLPWINDOWPOS, 0), 0);
        assert_eq!(out_size(FN_INLPCREATESTRUCT, 0), 0);
        assert_eq!(OUT_MAX, 52);
    }
}
