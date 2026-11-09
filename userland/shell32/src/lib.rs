//! shell32's user-mode code. It implements nothing yet: the exports the programs F2K runs import
//! from it are stubs, whose generated bodies log the call and fail ([`stub`]), over kernel32's and
//! ntdll's exports ([`imports`], as Windows 2000's shell32 imports them).
//!
//! An export written here will be an `extern "system"` function named `f2k_export_<Name>`, which
//! the DLL's module-definition file exports under its name (build-support/stubs.rs finds them; the
//! export spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this
//! library; the host tests run its code against [`imports`]' stand-ins.

#![cfg_attr(not(test), no_std)]

pub mod imports;
pub mod stub;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));
