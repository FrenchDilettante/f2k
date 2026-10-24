//! msvcrt's user-mode code: the bodies of the C runtime's exports, as Windows 2000's msvcrt.dll
//! (6.1) runs them, over kernel32's exports ([`imports`]: msvcrt imports kernel32 alone).
//!
//! An export here is a cdecl function named `f2k_export_<Name>` (its spec's convention is cdecl),
//! or, for an exported variable, a static of that name ([`data`]): the DLL's module-definition file
//! exports it under its name (build-support/stubs.rs finds them; the export spec declares it
//! `impl = { native = "<Name>" }`, a variable `data = true`). The DLL (src/main.rs) links this
//! library; the host tests run its code against [`imports`]' stand-ins.
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

pub mod data;
pub mod imports;
pub mod stub;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));
