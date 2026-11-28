//! What the screen tests' programs (tests/screens/<program>) share, so that each keeps only what
//! makes its screen differ:
//! - the user32, gdi32 and kernel32 calls more than one of them makes, and the structures they pass
//!   (src/ffi.rs), which a program's own `ffi` module re-exports beside the calls only it makes;
//! - a string widened to UTF-16 in a buffer of the program's own ([`Wide`], src/wide.rs);
//! - a top-level window of a class of its own, centred on the screen ([`TopLevel`]), its children
//!   ([`Window::child`]), its painting ([`paint`]), the procedure that ends the loop with the
//!   window ([`procedure`]), and the message loop that says when the queue is idle ([`pump`],
//!   [`pump_ready`]), all in src/window.rs; the ANSI class of the programs that make theirs with
//!   RegisterClassExA ([`register_class_a`]).
//!
//! It is not part of the runtime (userland/exe), which the system's own programs (pwd, ps, cmd,
//! FiSH) link too: these are the test programs' windows, kept beside them.
//!
//! The calls are built only for F2K's target; [`Wide`] is host-tested.

#![cfg_attr(not(test), no_std)]

#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub mod ffi;
mod wide;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
mod window;

#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub use ffi::WindowProc;
pub use wide::Wide;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub use window::{paint, procedure, pump, pump_ready, register_class_a, with, TopLevel, Window};
