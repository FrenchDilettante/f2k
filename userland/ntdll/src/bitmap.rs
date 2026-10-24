//! The bitmaps (`rtl::bitmap`): runs of bits found and set, cleared and tested in an RTL_BITMAP,
//! kernel32's TlsAlloc and TlsFree's work over the PEB's TLS bitmaps, as on Windows 2000.

use rtl::bitmap::{self, RtlBitmap};

/// The bitmap's dwords and its size in bits.
///
/// # Safety
///
/// `header` is an RTL_BITMAP whose buffer holds its size's bits.
unsafe fn bits<'a>(header: *const RtlBitmap) -> (&'a mut [u32], u32) {
    // SAFETY: the caller's contract.
    unsafe {
        let size = (*header).size_of_bit_map;
        let words = bitmap::words(size);
        if words == 0 {
            return (&mut [], 0);
        }
        (
            core::slice::from_raw_parts_mut((*header).buffer, words),
            size,
        )
    }
}

/// RtlFindClearBitsAndSet: the first run of `count` clear bits from the hint on (else from the
/// start), set; its first index, or 0xFFFFFFFF when none is clear.
///
/// # Safety
///
/// `header` is an RTL_BITMAP whose buffer holds its size's bits.
#[unsafe(export_name = "f2k_export_RtlFindClearBitsAndSet")]
pub unsafe extern "system" fn rtl_find_clear_bits_and_set(
    header: *mut RtlBitmap,
    count: u32,
    hint: u32,
) -> u32 {
    // SAFETY: the caller's contract.
    let (bits, size) = unsafe { bits(header) };
    bitmap::find_clear_and_set(bits, size, count, hint)
}

/// RtlClearBits: `count` bits from `start` cleared.
///
/// # Safety
///
/// `header` is an RTL_BITMAP whose buffer holds its size's bits.
#[unsafe(export_name = "f2k_export_RtlClearBits")]
pub unsafe extern "system" fn rtl_clear_bits(header: *mut RtlBitmap, start: u32, count: u32) {
    // SAFETY: the caller's contract.
    let (bits, size) = unsafe { bits(header) };
    bitmap::clear(bits, size, start, count);
}

/// RtlAreBitsSet: TRUE when the `length` bits from `start` are all set (FALSE for a range past the
/// end, or an empty one).
///
/// # Safety
///
/// `header` is an RTL_BITMAP whose buffer holds its size's bits.
#[unsafe(export_name = "f2k_export_RtlAreBitsSet")]
pub unsafe extern "system" fn rtl_are_bits_set(
    header: *const RtlBitmap,
    start: u32,
    length: u32,
) -> u32 {
    // SAFETY: the caller's contract.
    let (bits, size) = unsafe { bits(header) };
    u32::from(bitmap::are_set(bits, size, start, length))
}
