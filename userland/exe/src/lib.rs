//! The runtime of F2K's own programs: Win32 console programs written in Rust, without a C runtime,
//! that import kernel32 alone, so they run unchanged on Windows 2000 too.
//!
//! A program is a crate of its own (userland/<program>) whose binary names its `main` with
//! [`entry!`] and builds with build-support/exe.rs's `build_exe`. This crate gives it:
//! - the entry point the linker names: the program's `main`, then ExitProcess with its code;
//! - the standard output and error ([`stdout`], [`stderr`]): `core::fmt::Write` writers, to a
//!   console as UTF-16 (WriteConsoleW), redirected as bytes in the OEM code page (WriteFile), as
//!   Windows 2000's own console tools write theirs;
//! - a panic handler: the panic's message on the standard error, then exit code 3;
//! - the kernel32 calls the programs make, wrapped safely ([`current_directory`], [`exit`]).
//!
//! `unsafe` lives here, at the seam to kernel32 (src/sys.rs); the programs are safe Rust. The
//! writer's buffering (src/output.rs) is host-tested; the rest is only built for F2K's target.

#![cfg_attr(not(test), no_std)]

// What the compiler expects of an MSVC environment without its CRT: the 64-bit division helpers
// and the `_fltused` marker (core's formatting calls them), linked into every program.
extern crate compiler_helpers as _;

mod output;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
mod sys;

pub use output::{Error, Sink, Writer};
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub use sys::{current_directory, exit, stderr, stdout, Stream, MAX_PATH};

/// The program's entry point: `entry!(main)` in its binary's root defines the function the
/// linker's /ENTRY names (build-support/exe.rs), which runs `main` (`fn() -> u32`) and ends the
/// process with the code it returns.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        /// The image's entry point (the runtime's: `exe::entry!`).
        #[unsafe(no_mangle)]
        extern "C" fn f2k_start() -> ! {
            $crate::exit($main())
        }
    };
}

/// A panic ends the program: its message on the standard error, then exit code 3 (the code the
/// C runtime's `abort` ends a program with).
#[cfg(all(target_arch = "x86", target_os = "windows"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = stderr().print(format_args!("{info}\r\n"));
    exit(3)
}
