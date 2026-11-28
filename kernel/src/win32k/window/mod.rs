//! Windows: the window records behind HWNDs, and the create/destroy, show and position decisions.
//!
//! A window is a record in the window pool ([`Windows`]), named by a generation-tagged id
//! ([`WindowId`]), with a handle in the user handle table ([`super::handle`]). Its
//! parent/child/next/owner links are the z-order and ownership lists. Threads ([`Thread`]),
//! desktops ([`Desktop`]) and monitors ([`Monitor`]) are the calling context the decisions read.
//!
//! - Create ([`Windows::create_window_ex`]): validation gates, class resolution ([`super::class`]),
//!   style normalization (the ANSI-creator bit, the edge bit, WS_VISIBLE and the layered bit kept
//!   off the stored values), positioning (CW_USEDEFAULT, child offsets, the tiled cascade, monitor
//!   clamping, min/max track), owner/parent wiring, then WM_GETMINMAXINFO (tiled or thick-framed
//!   windows), WM_NCCREATE, link, WM_NCCALCSIZE, WM_CREATE, WM_SIZE/WM_MOVE, WM_PARENTNOTIFY, show.
//!   A refused WM_NCCREATE rolls back (WM_NCDESTROY only); a refused WM_CREATE destroys in full.
//! - Destroy ([`Windows::destroy_window`]): ownership checks, parent notify, hide, owned windows
//!   first, activation fixups, WM_DESTROY parent before children, unlink, free; a still-referenced
//!   window becomes a zombie of the icon-title class.
//! - Show ([`Windows::show_window`]) and position ([`Windows::set_window_pos`]): WM_SHOWWINDOW,
//!   WM_WINDOWPOSCHANGING (the handler may change the WINDOWPOS), the new rectangles
//!   (WM_NCCALCSIZE, children moved with the client area), the z-order (topmost pile first), the
//!   visibility, the activation, WM_WINDOWPOSCHANGED, and a tiled window's deferred
//!   WM_SIZE/WM_MOVE.
//!
//! The window and class registries sit behind one lock ([`WindowManager`]). The decisions reach
//! them through a [`Session`], which may let the lock go around a send: nothing borrowed from the
//! registries lives across a send, only ids and values, read again after it. The boot makes each
//! desktop's window and message window ([`WindowManager::boot_desktop`]); a process thread gets
//! its record at its first win32k service ([`Windows::connect_thread`]).
//!
//! Services (F2K's argument lists, see [`crate::win32k`]; Windows 2000's numbers):
//!
//! - NtUserCreateWindowEx (0x114D), NtUserDestroyWindow (0x1159);
//! - NtUserSetWindowPos (0x120F), NtUserMoveWindow (0x11C1);
//! - NtUserShowWindow (0x1218), NtUserShowWindowAsync (0x1219, carried out at once);
//! - NtUserQueryWindow (0x11D2): what Windows 2000's user32 reads from the window records mapped
//!   into its process (WINDOWINFO, IsWindowVisible, GetWindowLong's fields, extra bytes, class
//!   fields, text), by an index of F2K's own ([`rtl::window`]);
//! - NtUserSetWindowLong (0x120D), NtUserSetWindowWord (0x1214) ([`Windows::set_window_long`]);
//! - NtUserDefSetText (0x1153): DefWindowProc's change of the window's text.
//!
//! A window's text is a block of the registry's text store ([`super::text`]) and its extra bytes
//! a block of [`ExtraBytes`], as Windows 2000 allocates both from the desktop's heap.
//!
//! Every send and window-manager call goes through [`Session`]: the services use
//! [`super::queue::QueueSession`], the boot [`DefaultSession`]. The client rectangle is
//! WM_NCCALCSIZE's answer ([`Session::calc_client`]; the default procedure's is
//! [`Windows::default_client`]). The track sizes are WM_GETMINMAXINFO's answer
//! ([`Session::min_max_info`]); the default WM_WINDOWPOSCHANGING clamps a resize into them
//! ([`Windows::window_pos_changing`]). A framed window's frame shows anew with WM_NCPAINT; a
//! hidden window uncovers the windows under it. A thread's end takes its windows and queue
//! ([`WindowManager::end_thread`]); its record outlives it until the process's end
//! ([`WindowManager::end_process`]).

// Parts of the decision logic have no caller until the message slice lands (the activation and
// hook state, the zombie's references).
#![allow(dead_code)]

mod coords;
mod create;
mod create_messages;
mod create_place;
mod data;
mod destroy;
mod end;
mod free;
mod manager;
mod minmax;
mod placement;
mod pos;
mod pos_calls;
mod query;
mod record;
mod registry;
mod services;
mod session;
mod show;
#[cfg(test)]
mod testkit;
mod tree;
mod types;
mod view;

pub use rtl::user::StyleStruct;
pub use rtl::window::{WindowData, WindowInfo, WindowPos};

pub use self::manager::*;
pub use self::query::*;
pub use self::record::*;
pub use self::registry::*;
pub use self::services::*;
pub use self::session::*;
pub use self::types::*;
