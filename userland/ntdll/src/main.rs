//! ntdll.dll: the system DLL Windows 2000 loads into every process first.
//!
//! It carries Windows 2000's system-service stubs (`Nt*`, each under its `Zw` name too, raising the
//! gate on Windows 2000's own number), generated from the export specs (exports.toml);
//! RtlNtStatusToDosError (`src/status.rs`, over `rtl::status`); the kernel-served export Windows
//! 2000 keeps in ntdll (RtlUnwind, a floor; kernel32 forwards to it); and the F2K-internal entry
//! point the kernel sends a thread to (`src/internal.s`): the thread-exit trampoline a child
//! thread's function returns onto. The kernel finds it by its export name
//! (`F2kThreadExitTrampoline`); kernel32's surface carries Windows 2000's names alone.

#![no_std]
#![no_main]

extern crate rtl;

mod status;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("internal.s"),
);
