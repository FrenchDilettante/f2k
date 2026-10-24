//! The counted strings and the ANSI code page (`rtl::string`): the conversions kernel32's narrow
//! calls hand their strings to, as Windows 2000's kernel32 does. A string a conversion allocates
//! comes from the process heap, and RtlFreeUnicodeString returns it there.

use rtl::status::STATUS_SUCCESS;
use rtl::string::{self, AnsiString, UnicodeString};
use rtl::sys::{self, Native};

/// A block of `size` bytes on the process heap (null when it has no room).
fn allocate(size: usize) -> *mut u8 {
    sys::process_heap()
        .alloc(&Native, 0, size)
        .map_or(core::ptr::null_mut(), |at| at as *mut u8)
}

/// RtlInitAnsiString: the counted form of a NUL-terminated string (an empty one for null).
///
/// # Safety
///
/// `destination` is writable; `source` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_RtlInitAnsiString")]
pub unsafe extern "system" fn rtl_init_ansi_string(
    destination: *mut AnsiString,
    source: *const u8,
) {
    // SAFETY: the caller's contract.
    unsafe { destination.write(string::init_ansi_string(source)) };
}

/// RtlAnsiStringToUnicodeString: the ANSI string converted into the Unicode one, its buffer from
/// the process heap when asked (see `rtl::string::ansi_string_to_unicode_string`).
///
/// # Safety
///
/// The strings' buffers hold their lengths (and, unless allocating, the destination's its room).
#[unsafe(export_name = "f2k_export_RtlAnsiStringToUnicodeString")]
pub unsafe extern "system" fn rtl_ansi_string_to_unicode_string(
    destination: *mut UnicodeString,
    source: *const AnsiString,
    allocate_destination: u32,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        string::ansi_string_to_unicode_string(
            &mut *destination,
            &*source,
            allocate_destination as u8 != 0,
            allocate,
        )
    }
}

/// RtlUnicodeStringToAnsiString: the Unicode string converted into the ANSI one, its buffer from
/// the process heap when asked (see `rtl::string::unicode_string_to_ansi_string`).
///
/// # Safety
///
/// The strings' buffers hold their lengths (and, unless allocating, the destination's its room).
#[unsafe(export_name = "f2k_export_RtlUnicodeStringToAnsiString")]
pub unsafe extern "system" fn rtl_unicode_string_to_ansi_string(
    destination: *mut AnsiString,
    source: *const UnicodeString,
    allocate_destination: u32,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        string::unicode_string_to_ansi_string(
            &mut *destination,
            &*source,
            allocate_destination as u8 != 0,
            allocate,
        )
    }
}

/// RtlFreeUnicodeString: a string a conversion allocated, its buffer back to the process heap.
///
/// # Safety
///
/// `string` is a string a conversion allocated (or an empty one).
#[unsafe(export_name = "f2k_export_RtlFreeUnicodeString")]
pub unsafe extern "system" fn rtl_free_unicode_string(string: *mut UnicodeString) {
    // SAFETY: the caller's contract.
    string::free_unicode_string(unsafe { &mut *string }, |buffer| {
        sys::process_heap().free(&Native, 0, buffer as usize);
    });
}

/// RtlUnicodeToMultiByteN: as many of the UTF-16 bytes' units as the ANSI buffer holds, converted;
/// the bytes written (when asked). STATUS_SUCCESS.
///
/// # Safety
///
/// `multi_byte` holds `max_bytes` bytes, `unicode` holds `unicode_bytes` bytes; `bytes_written` is
/// null or writable.
#[unsafe(export_name = "f2k_export_RtlUnicodeToMultiByteN")]
pub unsafe extern "system" fn rtl_unicode_to_multi_byte_n(
    multi_byte: *mut u8,
    max_bytes: u32,
    bytes_written: *mut u32,
    unicode: *const u16,
    unicode_bytes: u32,
) -> u32 {
    // SAFETY: the caller's buffers, of the sizes given.
    let written = unsafe {
        string::unicode_to_multi_byte(
            slice_mut(multi_byte, max_bytes as usize),
            slice(unicode, unicode_bytes as usize / 2),
        )
    };
    if !bytes_written.is_null() {
        // SAFETY: the caller's count.
        unsafe { bytes_written.write(written as u32) };
    }
    STATUS_SUCCESS
}

/// RtlUnicodeToMultiByteSize: the bytes the UTF-16 bytes take in the ANSI code page.
/// STATUS_SUCCESS.
///
/// # Safety
///
/// `bytes` is writable.
#[unsafe(export_name = "f2k_export_RtlUnicodeToMultiByteSize")]
pub unsafe extern "system" fn rtl_unicode_to_multi_byte_size(
    bytes: *mut u32,
    _unicode: *const u16,
    unicode_bytes: u32,
) -> u32 {
    // SAFETY: the caller's count.
    unsafe { bytes.write(string::unicode_to_multi_byte_size(unicode_bytes)) };
    STATUS_SUCCESS
}

/// The `length` units at `at` (none for a null or empty buffer).
///
/// # Safety
///
/// `at` holds `length` units.
unsafe fn slice<'a, T>(at: *const T, length: usize) -> &'a [T] {
    if at.is_null() || length == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(at, length) }
}

/// The `length` units at `at`, writable (none for a null or empty buffer).
///
/// # Safety
///
/// `at` holds `length` writable units.
unsafe fn slice_mut<'a, T>(at: *mut T, length: usize) -> &'a mut [T] {
    if at.is_null() || length == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(at, length) }
}
