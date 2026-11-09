//! ntoskrnl.exe's exports (`kernel/exports.toml`): the bodies the spec implements, kept in the
//! link.
//!
//! An implemented export is the kernel's own code or storage, defined in its Rust under its
//! `f2k_export_<body>` symbol. Nothing in the kernel need reach it, so the link would drop it; the
//! build script's table (`NTOSKRNL_EXPORTS`) takes every body's address in a section the linker
//! script keeps, so each one stays in the image, where the image's export directory names it.

/// A table of addresses the image keeps: never read, only held, so that the link keeps what each
/// one names.
#[cfg(target_arch = "x86")]
#[repr(transparent)]
struct Kept<const N: usize>([*const (); N]);

// SAFETY: the table is never read through, and its addresses are constants of the link: sharing it
// shares nothing that can change.
#[cfg(target_arch = "x86")]
unsafe impl<const N: usize> Sync for Kept<N> {}

#[cfg(target_arch = "x86")]
include!(concat!(env!("OUT_DIR"), "/ntoskrnl_exports.rs"));
