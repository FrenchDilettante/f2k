//! msvcrt's user-mode code: the bodies of the C runtime's exports, as Windows 2000's msvcrt.dll
//! (6.1) runs them, over kernel32's exports ([`imports`]: msvcrt imports kernel32 alone).
//!
//! An export here is a cdecl function named `f2k_export_<Name>` (its spec's convention is cdecl),
//! or, for an exported variable, a static of that name ([`data`]): the DLL's module-definition file
//! exports it under its name (build-support/stubs.rs finds them; the export spec declares it
//! `impl = { native = "<Name>" }`, a variable `data = true`). The exports taking variable
//! arguments are thunks handing their arguments' address to a body here ([`stdio`]); the exception
//! handling and setjmp exports are assembly (src/seh.s, linked into the DLL). The DLL
//! (src/main.rs) links this library; the host tests run its code against [`imports`]' stand-ins.
//!
//! The areas: program start-up and exit ([`startup`]), the per-thread data and the lock
//! ([`thread`]), the allocator ([`heap`]), the descriptors ([`lowio`]), the streams ([`stdio`])
//! and the formatter and scanner they share ([`format`], [`float`], [`scan`]), the locale and the
//! character functions ([`ctype`]), strings ([`string`]), number conversions ([`convert`]), and
//! qsort, rand and time ([`utility`]).
//!
//! The exports not written yet are stubs: their generated bodies log the call and fail ([`stub`]).

#![cfg_attr(not(test), no_std)]

pub mod convert;
pub mod ctype;
pub mod data;
pub mod float;
pub mod format;
pub mod heap;
pub mod imports;
pub mod lowio;
pub mod scan;
pub mod startup;
pub mod stdio;
pub mod string;
pub mod stub;
pub mod thread;
pub mod utility;

/// The registrations above `frame` unwound (their handlers called, the record marked unwinding),
/// for src/seh.s: `_except_handler3` before it runs a handler, longjmp before it jumps. RtlUnwind
/// resumes its caller as from a return.
///
/// # Safety
///
/// `frame` is a registration on the calling thread's chain; `record` is null or the exception's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn f2k_msvcrt_global_unwind(frame: usize, record: usize) {
    // SAFETY: kernel32's export (ntdll's, forwarded).
    unsafe { imports::RtlUnwind(frame, 0, record, 0) }
}

/// DLL_PROCESS_DETACH, DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH.
const PROCESS_DETACH: u32 = 0;
const PROCESS_ATTACH: u32 = 1;
const THREAD_DETACH: u32 = 3;

/// The DLL's entry point's work, for each reason: the process attach sets up the heap, the
/// per-thread slot and the lock, the descriptors over the standard handles, `_iob`'s standard
/// streams and `_environ` (FALSE when one cannot be had); a thread's detach frees its data; the
/// process's detach, when the program did not end through exit or _exit, runs what exit would.
pub fn dll_main(reason: u32, _reserved: usize) -> u32 {
    match reason {
        PROCESS_ATTACH => {
            if !heap::initialize() || !thread::initialize() {
                return 0;
            }
            lowio::initialize();
            data::open_standard_streams();
            startup::initialize_environment() as u32
        }
        THREAD_DETACH => {
            thread::detach_thread();
            1
        }
        PROCESS_DETACH => {
            startup::detach_process();
            1
        }
        _ => 1,
    }
}

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));
