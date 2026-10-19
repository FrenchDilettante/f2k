//! ntdll.dll: the system DLL Windows 2000 loads into every process first.
//!
//! It carries Windows 2000's system-service stubs (`Nt*`, each under its `Zw` name too, raising the
//! gate on Windows 2000's own number), generated from the export specs (exports.toml);
//! RtlNtStatusToDosError (`src/status.rs`, over `rtl::status`); CsrClientCallServer (`src/csr.s`:
//! kernel32's console calls, to the kernel's console server); the exception dispatcher, entirely in
//! user mode (KiUserExceptionDispatcher, RtlUnwind — kernel32 forwards to it —, RtlRaiseException
//! and RtlRaiseStatus: `src/except.s` and `src/except.rs` over `rtl::seh`); and the F2K-internal
//! entry point the kernel sends a thread to (`src/internal.s`): the thread-exit trampoline a child
//! thread's function returns onto. The kernel finds the trampoline and KiUserExceptionDispatcher by
//! their export names; kernel32's surface carries Windows 2000's names alone.

#![no_std]
#![no_main]

extern crate rtl;

mod except;
mod status;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("internal.s"),
    include_str!("except.s"),
    include_str!("csr.s"),
);
