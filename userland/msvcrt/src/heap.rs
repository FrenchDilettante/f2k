//! The allocator: malloc, calloc, realloc and free over a heap of the C runtime's own (HeapCreate,
//! when the DLL is loaded), and memmove, memset and memcmp (which answers -1, 0 or 1, as strcmp
//! does).
//!
//! As wide's capture shows: malloc(0) and calloc(0, n) hand out a block; realloc(p, 0) frees `p`
//! and answers NULL; realloc(NULL, n) is malloc; a request the heap cannot serve answers NULL with
//! errno untouched; free(NULL) does nothing.

use crate::data::Global;
use crate::imports;

/// HEAP_ZERO_MEMORY.
const HEAP_ZERO_MEMORY: u32 = 0x08;

/// The largest request the allocator passes to the heap (MSVC's `_HEAP_MAXREQ`): beyond it,
/// rounding the size up would wrap.
const MAXIMUM_REQUEST: usize = 0xFFFF_FFE0;

/// The C runtime's heap (0 before the DLL's initialization).
static HEAP: Global<usize> = Global::new(0);

/// The DLL's process attach: the heap, growable. False when it cannot be had.
pub fn initialize() -> bool {
    // SAFETY: kernel32's export.
    let heap = unsafe { imports::HeapCreate(0, 0x1000, 0) };
    HEAP.write(heap);
    heap != 0
}

/// A block of `size` bytes (one at least), zeroed when asked; null when the heap cannot serve it.
pub fn allocate(size: usize, zeroed: bool) -> *mut u8 {
    if size > MAXIMUM_REQUEST {
        return core::ptr::null_mut();
    }
    let flags = if zeroed { HEAP_ZERO_MEMORY } else { 0 };
    // SAFETY: kernel32's export, over the C runtime's heap.
    unsafe { imports::HeapAlloc(HEAP.read(), flags, size.max(1)) }
}

/// A block given back (null: nothing).
///
/// # Safety
///
/// `block` is null or a block of the C runtime's heap, not given back since.
pub unsafe fn release(block: *mut u8) {
    if !block.is_null() {
        // SAFETY: the caller's block.
        unsafe { imports::HeapFree(HEAP.read(), 0, block) };
    }
}

/// `block` resized to `size` bytes (one at least), its contents kept; null, the block untouched,
/// when the heap cannot serve it.
///
/// # Safety
///
/// `block` is a block of the C runtime's heap.
pub unsafe fn resize(block: *mut u8, size: usize) -> *mut u8 {
    if size > MAXIMUM_REQUEST {
        return core::ptr::null_mut();
    }
    // SAFETY: kernel32's export, over the caller's block.
    unsafe { imports::HeapReAlloc(HEAP.read(), 0, block, size.max(1)) }
}

/// The size of a block of the C runtime's heap.
///
/// # Safety
///
/// `block` is a block of the C runtime's heap.
pub unsafe fn size_of(block: *const u8) -> usize {
    // SAFETY: kernel32's export, over the caller's block.
    unsafe { imports::HeapSize(HEAP.read(), 0, block) }
}

/// malloc: a block of `size` bytes.
#[unsafe(export_name = "f2k_export_malloc")]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    allocate(size, false)
}

/// calloc: `count` elements of `size` bytes, zeroed; NULL when the product overflows.
#[unsafe(export_name = "f2k_export_calloc")]
pub extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    match count.checked_mul(size) {
        Some(total) => allocate(total, true),
        None => core::ptr::null_mut(),
    }
}

/// realloc: the block resized, its contents kept up to the smaller size; NULL `block` allocates,
/// a zero `size` frees and answers NULL.
///
/// # Safety
///
/// `block` is null or a block malloc, calloc or realloc handed out.
#[unsafe(export_name = "f2k_export_realloc")]
pub unsafe extern "C" fn realloc(block: *mut u8, size: usize) -> *mut u8 {
    if block.is_null() {
        return allocate(size, false);
    }
    if size == 0 {
        // SAFETY: the caller's block.
        unsafe { release(block) };
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's block.
    unsafe { resize(block, size) }
}

/// free: the block given back.
///
/// # Safety
///
/// `block` is null or a block malloc, calloc or realloc handed out, not freed since.
#[unsafe(export_name = "f2k_export_free")]
pub unsafe extern "C" fn free(block: *mut u8) {
    // SAFETY: the caller's block.
    unsafe { release(block) };
}

/// memmove: `count` bytes copied from `source` to `destination`, the ranges free to overlap;
/// answers `destination`.
///
/// # Safety
///
/// Both ranges are the caller's, `count` bytes each.
#[unsafe(export_name = "f2k_export_memmove")]
pub unsafe extern "C" fn memmove(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    // SAFETY: the caller's ranges.
    unsafe { core::ptr::copy(source, destination, count) };
    destination
}

/// memset: `count` bytes at `destination` set to `c` (as an unsigned char); answers `destination`.
///
/// # Safety
///
/// `destination` holds `count` bytes.
#[unsafe(export_name = "f2k_export_memset")]
pub unsafe extern "C" fn memset(destination: *mut u8, c: i32, count: usize) -> *mut u8 {
    // SAFETY: the caller's range.
    unsafe { core::ptr::write_bytes(destination, c as u8, count) };
    destination
}

/// The order of two byte ranges, as -1, 0 or 1: the first bytes that differ, as unsigned chars.
fn order(a: &[u8], b: &[u8]) -> i32 {
    a.iter()
        .zip(b)
        .find(|(x, y)| x != y)
        .map_or(0, |(x, y)| x.cmp(y) as i32)
}

/// memcmp: the first `count` bytes' order, as -1, 0 or 1.
///
/// # Safety
///
/// Both ranges hold `count` bytes.
#[unsafe(export_name = "f2k_export_memcmp")]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, count: usize) -> i32 {
    if count == 0 {
        return 0;
    }
    // SAFETY: the caller's ranges.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(a, count),
            core::slice::from_raw_parts(b, count),
        )
    };
    order(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// wide's memory block: realloc growing and shrinking keeps the contents, realloc to zero
    /// frees, calloc zeroes, malloc(0) is a block, an impossible request is NULL with errno
    /// untouched, memmove copies overlapping ranges both ways.
    #[test]
    fn the_allocator_as_captured() {
        initialize();
        // SAFETY: the blocks the allocator hands out, used within their sizes.
        unsafe {
            let p = malloc(16);
            for i in 0..16 {
                *p.add(i) = b'a' + i as u8;
            }
            let q = realloc(p, 4096);
            assert!((0..16).all(|i| *q.add(i) == b'a' + i as u8));
            let p = realloc(q, 8);
            assert!((0..8).all(|i| *p.add(i) == b'a' + i as u8));
            free(p);
            assert!(realloc(realloc(core::ptr::null_mut(), 32), 0).is_null());
            let z = calloc(8, 8);
            assert!((0..64).all(|i| *z.add(i) == 0));
            free(z);
            let empty = malloc(0);
            assert!(!empty.is_null());
            free(empty);
            crate::thread::set_errno(0);
            assert!(malloc(0x7FFF_FFF0).is_null());
            assert_eq!(*crate::thread::errno_address(), 0);
            assert!(calloc(usize::MAX, 2).is_null());
            free(core::ptr::null_mut());

            let mut buf = *b"0123456789";
            let b = buf.as_mut_ptr();
            assert_eq!(memmove(b.add(2), b, 5), b.add(2));
            assert_eq!(&buf, b"0101234789");
            let mut buf = *b"0123456789";
            let b = buf.as_mut_ptr();
            memmove(b, b.add(2), 5);
            assert_eq!(&buf, b"2345656789");
        }
    }

    /// memset fills with the value's low byte; memcmp orders by the first differing bytes as
    /// unsigned chars, and compares nothing for a zero count.
    #[test]
    fn memset_and_memcmp() {
        // SAFETY: buffers of the lengths used.
        unsafe {
            let mut buf = *b"0123456789";
            let b = buf.as_mut_ptr();
            assert_eq!(memset(b.add(2), 0x141, 3), b.add(2));
            assert_eq!(&buf, b"01AAA56789");
            memset(b, 0, 0);
            assert_eq!(&buf, b"01AAA56789");
            let cmp = |x: &[u8], y: &[u8], n| memcmp(x.as_ptr(), y.as_ptr(), n);
            assert_eq!(
                [
                    cmp(b"PE\0\0", b"PE\0\0", 4),
                    cmp(b"abc", b"abd", 3),
                    cmp(b"abd", b"abc", 3),
                    cmp(b"abc", b"abd", 2),
                    cmp(b"\x80", b"\x7F", 1),
                    cmp(b"x", b"y", 0)
                ],
                [0, -1, 1, 0, 1, 0]
            );
            assert_eq!(memcmp(core::ptr::null(), core::ptr::null(), 0), 0);
        }
    }
}
