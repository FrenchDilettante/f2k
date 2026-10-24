//! user32's user-mode code: the bodies of its exports (the window station and desktop calls,
//! [`winsta`]; MessageBeep, [`sound`]), as Windows 2000's user32 runs them, over ntdll's and
//! kernel32's exports and win32k's services ([`imports`]: as Windows 2000's user32 imports the
//! first and enters the kernel itself for the others, through its own stubs).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`imports`]' stand-ins.
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

pub mod imports;
pub mod sound;
pub mod stub;
pub mod winsta;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));
