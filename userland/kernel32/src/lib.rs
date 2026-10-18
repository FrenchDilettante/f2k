//! kernel32's user-mode code: the bodies of its exports that run in the calling thread, as Windows
//! 2000's kernel32 runs them.
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code.
//!
//! None yet: every kernel32 export is a kernel-served stub or a forwarder into ntdll. The groups
//! move here as the increments rewrite them over ntdll.

#![cfg_attr(not(test), no_std)]
