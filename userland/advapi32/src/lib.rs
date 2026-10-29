//! advapi32's user-mode code: the bodies of its exports (the registry first), as Windows 2000's
//! advapi32 runs them, over ntdll's and kernel32's exports ([`imports`], as Windows 2000's
//! advapi32 imports them).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`imports`]' stand-ins.
//!
//! An export converts its caller's pointers once, on entry: a string into a slice of its units, a
//! buffer into a slice ([`caller_bytes`], [`caller_bytes_mut`]), an out parameter into an [`Out`].
//! The code below the exports is safe.
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

pub mod imports;
pub mod registry;
pub mod stub;

/// A caller's out parameter and buffers, as every system DLL's exports take them.
pub use rtl::edge::{caller_bytes, caller_bytes_mut, Out};

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));
