//! kernel32's user-mode code: the bodies of its exports that run in the calling thread, as Windows
//! 2000's kernel32 runs them, over ntdll's exports ([`nt`]: the system services and the runtime
//! library, imported as Windows 2000's kernel32 imports them).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`nt`]'s stand-ins.
//!
//! The shared helpers are here ([`base`]: the last error, and a failed service's status mapped to
//! it). The exports' bodies are not, yet: the trivial natives are assembly (src/natives.s), the
//! rest are the kernel's transitional Win32 services (generated stubs) or unimplemented stubs, which
//! later work rewrites here group by group (`tests/test_repository.py` ratchets both counts
//! down).

#![cfg_attr(not(test), no_std)]

pub mod base;
pub mod nt;

#[cfg(test)]
mod scenarios;
