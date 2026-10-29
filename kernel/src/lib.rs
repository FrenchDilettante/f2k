//! F2K kernel library.
//!
//! Built two ways: as the `f2k-kernel` binary (entered by the Multiboot `_start` stub), and as a
//! host test harness where the x86-only assembly is cfg'd out and the pure-Rust parts get unit
//! tests (`make run-tests`). The host's plain library build exists for the documentation tests:
//! the compile-fail examples of the level tokens and the locks, which `make run-tests` runs too.

#![cfg_attr(not(test), no_std)]
// Host builds exist only to run unit tests.
#![cfg_attr(not(target_arch = "x86"), allow(dead_code))]
// The host's plain library build compiles the test-only paths' callees without the tests: what is
// unused there is not the target's concern.
#![cfg_attr(all(not(test), not(target_arch = "x86")), allow(unused))]

// The host's plain library build (the documentation tests' dependency) has std, as the unit tests
// do: the host's processor control region is a thread-local.
#[cfg(all(not(test), not(target_arch = "x86")))]
extern crate std;

// Boot module (Multiboot header and _start stub)
mod boot;

// The CPU tables: GDT (segments, TEB, TSS) and IDT (exceptions, the syscall gate, the
// hardware-vector stubs)
mod cpu;

// The hardware layer: the interrupt controller pair, the interval timer, the IDE disk, and the
// serial port, reached through abstract port I/O
mod hw;

// The interrupt core: interrupt objects, the vector table, the level discipline, the deferred
// procedure call queue, and the interval clock
mod interrupt;

// Level tokens: the interrupt level as a type, and the state each level owns. Public on the host,
// where the documentation tests name it from outside the crate.
#[cfg(target_arch = "x86")]
mod level;
#[cfg(not(target_arch = "x86"))]
pub mod level;

// The processor control region: the level ledger, the deferred procedure call queue and the
// processor's threads
mod pcr;

// Memory management: physical frame allocator
mod mem;

// State outside the level cells: set-once values, static buffers handed out once, and the short
// lock for passive-level state. Public on the host, as the level tokens are.
#[cfg(target_arch = "x86")]
mod sync;
#[cfg(not(target_arch = "x86"))]
pub mod sync;

// Executable loading: PE32 parsing, and the kernel-side loader (staging, section mapping, entry
// into ring 3)
mod exec;

// Ring 3: user-mode entry, the syscall gate and its argument types, the user-mode heap, process end
mod user;

// The NT system services: Windows 2000's Nt* calls, by Windows 2000's numbers, over the object
// manager
mod nt;

// win32k: window stations and desktops, and the second service table (user32's own NtUser* calls,
// by Windows 2000's numbers from 0x1000)
mod win32k;

// The console server: the kernel's stand-in for csrss, which kernel32's console calls reach through
// ntdll's CsrClientCallServer
mod csr;

// The debugger's print channel: ntdll's DbgPrint, written to COM1
mod dbgprint;

// The process object and the suite runner: per-process directory, gate stack, user heap
mod process;

// NT status codes: the documented values the kernel's internal APIs report
mod status;

// Block devices: the description and read contract every storage device implements, partition
// views, and the device registry
mod block;

// File systems: the FAT32 volume over a block device
mod fs;

// The scheduler: thread objects, priority bands, ready queues, the quantum, the dispatcher's state
// machines
mod sched;

// The object manager: the typed object pools, object ids, pointer and handle counts, names
mod ob;

// The configuration manager: the registry's keys and values, in kernel memory
mod cm;

// Wall-clock time and the performance counter: the boot's real-time clock reading, the FILETIME
// the system services and the shared data page report
mod time;

// The opt-in performance trace (the perf-trace feature): the clock interrupt's sampler and the
// COM1 dump the harness turns into a profiler.firefox.com profile
#[cfg(feature = "perf-trace")]
mod perf;

// The C library's memory routines for the target (linker support).
#[cfg(target_arch = "x86")]
mod c_lib;

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Print the panic message on COM1 and halt.
///
/// The `#[panic_handler]` must be defined exactly once, in the final binary (a library must not
/// define one); the binary's handler forwards here so both crates share this one code path.
#[cfg(all(not(test), target_arch = "x86"))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt()
}

/// Halt the CPU with interrupts disabled: the terminal state of a kernel that cannot continue
/// (panic, unhandled fault). Ticks do not resume here.
#[cfg(target_arch = "x86")]
pub(crate) fn halt() -> ! {
    loop {
        // SAFETY: ring 0, where `cli` and `hlt` are permitted; they touch no memory and no stack,
        // and the loop halts again if a non-maskable interrupt wakes the CPU.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Kernel entry point
///
/// Called by `_start` (boot/mod.rs) with the values the Multiboot loader left in EAX and EBX. The
/// boot's phases run in order ([`boot`]), each diagnostic boot at its place in them, then the
/// boot context becomes the idle thread under the first user process.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub extern "C" fn kmain(magic: u32, multiboot_info: u32) -> ! {
    // Phase 0: the processor, memory, the executive's tables.
    boot::early();
    boot::diagnostics::cpu_faults();
    boot::memory(magic, multiboot_info);
    boot::executive();

    // Phase 1: interrupts and the scheduler, then the devices.
    boot::interrupts();
    boot::diagnostics::interrupts();
    boot::devices();
    boot::diagnostics::devices();

    // The user processes (the programs the kernel command line lists, else exit0, through the PE
    // loader, one after another; the fault-test features substitute their own), each entered as
    // its main thread: this boot context becomes the idle thread. An image ends through its exit
    // import, which reports the exit code on COM1; the idle thread then tears the process down
    // and starts the next, or rests.
    user::run_user_process()
}
