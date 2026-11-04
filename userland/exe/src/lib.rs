//! The runtime of F2K's own programs: Win32 console programs written in Rust, without a C runtime,
//! that import kernel32 (and user32, for one that sets the display mode) as Windows 2000's own
//! programs do, so they run unchanged on Windows 2000 too.
//!
//! A program is a crate of its own (userland/<program>) whose binary names its `main` with
//! [`entry!`] and builds with build-support/exe.rs's `build_exe`. This crate gives it:
//! - the entry point the linker names: the program's `main`, then ExitProcess with its code;
//! - the standard output and error ([`stdout`], [`stderr`]): `core::fmt::Write` writers, to a
//!   console as UTF-16 (WriteConsoleW), redirected as bytes in the OEM code page (WriteFile), as
//!   Windows 2000's own console tools write theirs;
//! - a panic handler: the panic's message on the standard error, then exit code 3;
//! - the standard input's lines, from a console ([`read_line`]), and a shell's survival of Ctrl+C
//!   and Ctrl+Break ([`outlive_interrupts`], [`take_interrupt`]);
//! - the calls the programs make, wrapped safely ([`command_line`], [`current_directory`],
//!   [`set_current_directory`], [`create_process`] and [`create_process_of`] and the [`Process`]
//!   they start, [`exit`]; the environment's variables and block; the local time; whether a file
//!   exists, and its bytes; OEM text decoded; the console's screen cleared), the system's
//!   process list ([`ProcessSnapshot`], kernel32's ToolHelp), the child processes FiSH starts
//!   ([`create_child`] over a NUL-terminated [`CommandLine`]), and the display mode it sets
//!   through user32 ([`change_display_mode`]).
//!
//! `unsafe` lives here, at the seam to the system's DLLs (src/sys.rs, src/toolhelp.rs); the
//! programs are safe Rust. The writer's buffering (src/output.rs) and the command line
//! (src/command.rs) are host-tested; the rest is only built for F2K's target.

#![cfg_attr(not(test), no_std)]

// What the compiler expects of an MSVC environment without its CRT: the 64-bit division helpers
// and the `_fltused` marker (core's formatting calls them) and the stack probe, linked into every
// program.
extern crate compiler_helpers as _;

mod command;
mod output;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
mod sys;
#[cfg(all(target_arch = "x86", target_os = "windows"))]
mod toolhelp;

pub use command::CommandLine;
pub use output::{Error, Sink, Writer};
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub use sys::{
    change_display_mode,
    clear_screen,
    command_line,
    command_line_a,
    create_child,
    create_process,
    create_process_of,
    current_directory,
    environment,
    environment_variable,
    exit,
    file_exists,
    local_time,
    oem_to_wide,
    open_file,
    outlive_interrupts,
    read_line,
    set_current_directory,
    set_environment_variable,
    stderr,
    stdout,
    take_interrupt,
    write_stdout_bytes,
    Child,
    Environment,
    File,
    Input,
    Process,
    Stream,
    SystemTime,
    INFINITE,
    MAX_PATH,
};
#[cfg(all(target_arch = "x86", target_os = "windows"))]
pub use toolhelp::{ProcessEntry, ProcessSnapshot, Processes};

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
