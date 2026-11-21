//! The host tests' stand-ins for the ntdll and kernel32 imports the system DLLs share: each DLL's
//! `host` module (the one its imports' wrappers call in the host tests, in place of the imports)
//! re-exports these with `pub use`, beside the stand-ins of its own (the services that record
//! what they were given for its tests, or keep a state of their own). Like [`crate::testing`], the
//! module is behind rtl's `testing` feature, which the DLLs' dev-dependencies turn on: the code
//! that ships never compiles it.
//!
//! The stand-ins have the imports' shapes and behave as the imports do as far as the tests reach
//! them: the last error and the debugger's lines kept per thread ([`LAST_ERROR`],
//! [`DEBUG_PRINTS`]), a raise a panic, the heap the host's allocator, the conversions and the
//! status mapping rtl's own (as ntdll runs them), and every address the tests hand over readable
//! ([`Probed`]).

#![allow(non_snake_case, clippy::missing_safety_doc)]

extern crate std;

use std::cell::{Cell, RefCell};
use std::string::String;
use std::vec::Vec;

use crate::string::{AnsiString, UnicodeString};

/// The caller's `length` items at `at`: none when `length` is 0, whatever `at` is (a null pointer
/// makes no slice, not even an empty one), as a caller may pass NULL with no length.
///
/// # Safety
///
/// For a length, `at` is readable for that many items for `'a`.
pub unsafe fn items<'a, T>(at: *const T, length: usize) -> &'a [T] {
    if length == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(at, length) }
}

/// [`items`], writable.
///
/// # Safety
///
/// For a length, `at` is writable for that many items for `'a`, and nothing else uses them.
pub unsafe fn items_mut<'a, T>(at: *mut T, length: usize) -> &'a mut [T] {
    if length == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(at, length) }
}

// --- kernel32 ------------------------------------------------------------------------------------

std::thread_local! {
    /// The calling thread's last error, as SetLastError left it.
    pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
    /// The text each DbgPrint printed, in order.
    pub static DEBUG_PRINTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

pub unsafe extern "system" fn SetLastError(code: u32) {
    LAST_ERROR.with(|error| error.set(code));
}

pub unsafe extern "system" fn GetLastError() -> u32 {
    LAST_ERROR.with(|error| error.get())
}

pub unsafe extern "system" fn RaiseException(
    code: u32,
    flags: u32,
    _count: u32,
    _arguments: *const usize,
) {
    panic!("RaiseException({code:#010x}, {flags:#x})")
}

// --- ntdll ---------------------------------------------------------------------------------------

/// DbgPrint, as the DLLs call it: `"%s"` and the text (the stand-in serves that format alone),
/// kept.
pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const u8) -> u32 {
    // SAFETY: the caller's NUL-terminated format and text.
    let (format, text) = unsafe {
        (
            core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
            core::ffi::CStr::from_ptr(text.cast()),
        )
    };
    assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
    DEBUG_PRINTS.with(|prints| {
        prints
            .borrow_mut()
            .push(text.to_string_lossy().into_owned())
    });
    0
}

pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
    crate::status::dos_error(status)
}

/// The host process has no PEB: the stand-ins' one heap, at an address a process heap has.
pub fn process_heap() -> usize {
    0x0014_0000
}

/// The heap: the host's allocator, a block zeroed (whatever the flags), its size kept before it.
pub unsafe extern "system" fn RtlAllocateHeap(_heap: usize, _flags: u32, size: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
    // SAFETY: a non-zero layout; the size goes in the first word.
    unsafe {
        let block = std::alloc::alloc_zeroed(layout);
        (block as *mut usize).write(size);
        block.add(8)
    }
}

pub unsafe extern "system" fn RtlFreeHeap(_heap: usize, _flags: u32, block: *mut u8) -> u32 {
    // SAFETY: a block RtlAllocateHeap made.
    unsafe {
        let start = block.sub(8);
        let size = (start as *const usize).read();
        std::alloc::dealloc(
            start,
            std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
        );
    }
    1
}

/// A block on the stand-in heap, as ntdll's string conversions allocate (the allocator
/// rtl::string's conversions are handed).
pub fn string_block(size: usize) -> *mut u8 {
    // SAFETY: the stand-in heap.
    unsafe { RtlAllocateHeap(process_heap(), 0, size) }
}

/// ntdll's string calls, over the stand-in heap (rtl::string, as ntdll runs them).
pub unsafe extern "system" fn RtlAnsiStringToUnicodeString(
    destination: *mut UnicodeString,
    source: *const AnsiString,
    allocate: u32,
) -> u32 {
    // SAFETY: the caller's strings.
    unsafe {
        crate::string::ansi_string_to_unicode_string(
            &mut *destination,
            &*source,
            allocate as u8 != 0,
            string_block,
        )
    }
}

pub unsafe extern "system" fn RtlUnicodeStringToAnsiString(
    destination: *mut AnsiString,
    source: *const UnicodeString,
    allocate: u32,
) -> u32 {
    // SAFETY: the caller's strings.
    unsafe {
        crate::string::unicode_string_to_ansi_string(
            &mut *destination,
            &*source,
            allocate as u8 != 0,
            string_block,
        )
    }
}

pub unsafe extern "system" fn RtlFreeUnicodeString(string: *mut UnicodeString) {
    // SAFETY: the caller's string, its buffer the stand-in heap's.
    crate::string::free_unicode_string(unsafe { &mut *string }, |buffer| unsafe {
        RtlFreeHeap(process_heap(), 0, buffer);
    });
}

pub unsafe extern "system" fn RtlUnicodeToMultiByteN(
    multi_byte: *mut u8,
    max_bytes: u32,
    bytes_written: *mut u32,
    unicode: *const u16,
    unicode_bytes: u32,
) -> u32 {
    // SAFETY: the caller's buffers, of the sizes given.
    let written = unsafe {
        crate::string::unicode_to_multi_byte(
            items_mut(multi_byte, max_bytes as usize),
            items(unicode, unicode_bytes as usize / 2),
        )
    };
    if !bytes_written.is_null() {
        // SAFETY: the caller's count.
        unsafe { bytes_written.write(written as u32) };
    }
    0
}

pub unsafe extern "system" fn RtlMultiByteToUnicodeN(
    unicode: *mut u16,
    max_bytes: u32,
    bytes_written: *mut u32,
    multi_byte: *const u8,
    multi_byte_bytes: u32,
) -> u32 {
    // SAFETY: the caller's buffers, of the sizes given.
    let written = unsafe {
        crate::string::multi_byte_to_unicode(
            items_mut(unicode, max_bytes as usize / 2),
            items(multi_byte, multi_byte_bytes as usize),
        )
    };
    if !bytes_written.is_null() {
        // SAFETY: the caller's count.
        unsafe { bytes_written.write(2 * written as u32) };
    }
    0
}

pub unsafe extern "system" fn RtlUnicodeToMultiByteSize(
    bytes: *mut u32,
    _unicode: *const u16,
    unicode_bytes: u32,
) -> u32 {
    // SAFETY: the caller's count.
    unsafe { bytes.write(crate::string::unicode_to_multi_byte_size(unicode_bytes)) };
    0
}

// --- The memory probe ----------------------------------------------------------------------------

/// The host process's memory: every address the tests hand over is their own.
pub struct Probed;

impl crate::stub::Memory for Probed {
    fn readable(&self, _address: usize) -> bool {
        true
    }
}
