//! The runtime library, as Windows 2000's Rtl: the support code the system DLLs link.
//!
//! What every build shares, host-tested: the status mapping ([`status`]: RtlNtStatusToDosError's
//! table, which kernel32 reports every failed system service through), the code pages and their
//! conversions ([`codepage`], [`cp1252`]), the counted strings ([`string`]: ntdll's
//! RtlAnsiStringToUnicodeString family, which kernel32's narrow calls convert through), the time
//! conversions ([`time`]: ntdll's RtlTimeToTimeFields and RtlTimeFieldsToTime), the bitmaps
//! ([`bitmap`]: ntdll's RtlFindClearBitsAndSet family, kernel32's TLS slots), the critical sections
//! ([`critsec`]: ntdll's RtlEnterCriticalSection family, over the system it is handed), the heaps
//! ([`heap`] over the allocator core [`heapcore`]: ntdll's RtlCreateHeap family), Local and Global
//! memory ([`localmem`]: kernel32's, over ntdll's heap and handle-table calls), the handle tables
//! ([`handles`]: ntdll's RtlAllocateHandle family), the resources and the message tables
//! ([`resource`]: ntdll's LdrFindResource_U family and RtlFindMessage), the message formatter
//! ([`message`]: ntdll's RtlFormatMessage), the environment blocks ([`env`]:
//! ntdll's RtlSetEnvironmentVariable family), the process parameters block ([`params`]: the
//! kernel's first block and ntdll's RtlCreateProcessParameters share its layout), an image's
//! execution options ([`execution_options`]: ntdll's LdrQueryImageFileExecutionOptions), the
//! loader's share of a thread's start ([`ldr`]) and the image headers it reads ([`image`]: ntdll's
//! RtlImageNtHeader too), the loader's module lists and export lookups
//! ([`modules`]: ntdll's LdrGetDllHandle family), the console server's message format and rules
//! ([`console`]: kernel32's side and the kernel's stand-in for csrss share them), and structured
//! exception handling's walks ([`seh`]: ntdll's RtlDispatchException and RtlUnwind, with the
//! CONTEXT and record layouts the kernel writes), the stubs' log line ([`stub`]: the system DLLs'
//! exports not written yet, and the paths their code does not handle) and DbgPrint's formatting
//! ([`printf`]).
//!
//! The building blocks under them: the NT structures every side shares ([`nt`]: UNICODE_STRING,
//! OBJECT_ATTRIBUTES, CLIENT_ID, IO_STATUS_BLOCK, generic over their pointers' width), plain data
//! viewed as bytes ([`pod`]), a vector of fixed capacity for the code without an allocator
//! ([`array_vec`]), NUL-terminated strings read once ([`cstr`]) and a process's state behind a
//! lock ([`sync`]).
//!
//! On the DLLs' target (i686 Windows) only: what the compiler expects of an MSVC environment
//! without its CRT (the compiler-helpers crate, which this library links into every DLL), the
//! panic handler, [`sys`], the calling thread's TEB, the gate and the raises, and [`probe`], a read
//! probe under an exception frame of its own (the stub routines of the DLLs whose imports hold no
//! memory query read their string arguments through it).

#![cfg_attr(not(test), no_std)]

pub mod array_vec;
pub mod bitmap;
pub mod codepage;
pub mod console;
pub mod cp1252;
pub mod critsec;
pub mod cstr;
pub mod env;
pub mod execution_options;
pub mod handles;
pub mod heap;
pub mod heapcore;
pub mod image;
pub mod ldr;
pub mod localmem;
pub mod message;
pub mod modules;
pub mod nt;
pub mod params;
pub mod path;
pub mod pod;
pub mod printf;
#[cfg(all(target_arch = "x86", target_os = "windows", not(test)))]
pub mod probe;
pub mod resource;
pub mod seh;
pub mod status;
mod status_table;
pub mod string;
pub mod stub;
pub mod sync;
#[cfg(all(target_arch = "x86", target_os = "windows", not(test)))]
pub mod sys;
pub mod time;

// What the compiler expects of an MSVC environment without its CRT: the 64-bit division helpers
// and the `_fltused` marker, linked into every DLL with this library.
extern crate compiler_helpers as _;

/// A panic in user-mode support code faults the process (an invalid opcode), never the system.
#[cfg(all(target_arch = "x86", target_os = "windows", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: ud2 raises the invalid-opcode fault; nothing follows it.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
