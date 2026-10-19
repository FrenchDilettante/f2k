//! kernel32's user-mode code: the bodies of its exports that run in the calling thread, as Windows
//! 2000's kernel32 runs them, over ntdll's exports ([`nt`]: the system services and the runtime
//! library, imported as Windows 2000's kernel32 imports them).
//!
//! An export here is an `extern "system"` function named `f2k_export_<Name>`, which the DLL's
//! module-definition file exports under its name (build-support/stubs.rs finds them; the export
//! spec declares it `impl = { native = "<Name>" }`). The DLL (src/main.rs) links this library; the
//! host tests run its code against [`nt`]'s stand-ins.
//!
//! The shared helpers are [`base`]'s (the last error, a failed service's status mapped to it, the
//! PEB, the process parameters, the process heap and the environment block). The groups: the
//! console ([`console`], to the console server), the start-up calls ([`startup`]), the modules
//! ([`module`]), the synchronization objects, the waits and the handle calls ([`sync`]), the files'
//! read side ([`files`], over ntdll's file services) and the current directory ([`curdir`]),
//! the environment ([`env`], over ntdll's), the TLS indexes ([`thread`]), the process's end
//! ([`process`]), exceptions ([`except`]: RaiseException, the pointer probes' unwind), the locale
//! group ([`locale`] over `rtl::codepage`, with [`collate`] and [`localeinfo`]), the clocks
//! ([`time`], over the shared data page, [`shared`]), the system messages ([`message`]), virtual
//! memory and the system's memory facts ([`vm`]) and the paging file's mappings ([`filemap`]). The
//! heap and Local/Global functions are the DLL's (src/main.rs and src/memory.s, over ntdll's heap
//! exports). The trivial natives (src/natives.s), the main thread's start (src/start.s) and the
//! pointer probes (src/probe.s) are assembly. No export enters the kernel itself: only ntdll's
//! system-service stubs do (`tests/test_repository.py` checks the built DLL holds no `int 2Eh`).

#![cfg_attr(not(test), no_std)]

pub mod base;
pub mod collate;
pub mod console;
pub mod curdir;
pub mod env;
pub mod error;
pub mod except;
pub mod filemap;
pub mod files;
pub mod locale;
pub mod localeinfo;
pub mod message;
pub mod module;
pub mod nt;
pub mod process;
pub mod shared;
pub mod startup;
pub mod sync;
pub mod thread;
pub mod time;
pub mod vm;

#[cfg(test)]
mod scenarios;
