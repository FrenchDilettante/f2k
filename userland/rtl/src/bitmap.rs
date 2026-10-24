//! Bitmaps, as ntdll's bitmap functions keep them (RtlFindClearBitsAndSet, RtlClearBits,
//! RtlAreBitsSet): kernel32's TlsAlloc and TlsFree mark the PEB's TLS slots in them, as Windows
//! 2000's kernel32 does.
//!
//! The header is the documented RTL_BITMAP: the bitmap's size in bits, then its buffer of dwords,
//! bit `n` the bit `n % 32` of dword `n / 32`. The functions here take the buffer as the dwords
//! that hold the size's bits.

/// An RTL_BITMAP: its size in bits and its buffer.
#[repr(C)]
pub struct RtlBitmap {
    pub size_of_bit_map: u32,
    pub buffer: *mut u32,
}

/// RtlFindClearBitsAndSet's answer when no run is clear.
pub const NOT_FOUND: u32 = 0xFFFF_FFFF;

/// The dwords that hold `size` bits.
pub const fn words(size: u32) -> usize {
    size.div_ceil(32) as usize
}

fn is_set(bits: &[u32], index: u32) -> bool {
    bits[(index / 32) as usize] & 1 << (index % 32) != 0
}

/// The first run of `count` clear bits wholly inside `from..to`.
fn clear_run(bits: &[u32], from: u32, to: u32, count: u32) -> Option<u32> {
    let (mut index, mut run) = (from, 0);
    while index < to {
        if index % 32 == 0 && to - index >= 32 && bits[(index / 32) as usize] == u32::MAX {
            (index, run) = (index + 32, 0);
            continue;
        }
        run = if is_set(bits, index) { 0 } else { run + 1 };
        index += 1;
        if run == count {
            return Some(index - count);
        }
    }
    None
}

/// RtlFindClearBits: the first run of `count` clear bits among the bitmap's `size` from `hint` on,
/// else from its start (a run never wraps past the end; a hint past the end is the start); none
/// when no run is clear. Zero bits are found at the hint.
pub fn find_clear(bits: &[u32], size: u32, count: u32, hint: u32) -> Option<u32> {
    let hint = if hint < size { hint } else { 0 };
    if count == 0 {
        return Some(hint);
    }
    if count > size {
        return None;
    }
    clear_run(bits, hint, size, count)
        .or_else(|| clear_run(bits, 0, hint.saturating_add(count - 1).min(size), count))
}

/// RtlSetBits: `count` bits from `start` set (none past the bitmap's `size`).
pub fn set(bits: &mut [u32], size: u32, start: u32, count: u32) {
    for index in start..start.saturating_add(count).min(size) {
        bits[(index / 32) as usize] |= 1 << (index % 32);
    }
}

/// RtlClearBits: `count` bits from `start` cleared (none past the bitmap's `size`).
pub fn clear(bits: &mut [u32], size: u32, start: u32, count: u32) {
    for index in start..start.saturating_add(count).min(size) {
        bits[(index / 32) as usize] &= !(1 << (index % 32));
    }
}

/// RtlFindClearBitsAndSet: [`find_clear`]'s run, set; its first index, or [`NOT_FOUND`].
pub fn find_clear_and_set(bits: &mut [u32], size: u32, count: u32, hint: u32) -> u32 {
    match find_clear(bits, size, count, hint) {
        Some(start) => {
            set(bits, size, start, count);
            start
        }
        None => NOT_FOUND,
    }
}

/// RtlAreBitsSet: whether the `length` bits from `start` are all set; false for an empty range or
/// one past the bitmap's `size`.
pub fn are_set(bits: &[u32], size: u32, start: u32, length: u32) -> bool {
    match start.checked_add(length) {
        Some(end) if length != 0 && end <= size => (start..end).all(|index| is_set(bits, index)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One bit at a time from hint 0, as TlsAlloc asks: the lowest clear bit, set, until none is
    /// left; a cleared one is found again.
    #[test]
    fn single_bits_come_lowest_first() {
        let mut bits = [0u32; 2];
        for expected in 0..64 {
            assert_eq!(find_clear_and_set(&mut bits, 64, 1, 0), expected);
        }
        assert_eq!(bits, [u32::MAX; 2]);
        assert_eq!(find_clear_and_set(&mut bits, 64, 1, 0), NOT_FOUND);
        clear(&mut bits, 64, 37, 1);
        assert!(!are_set(&bits, 64, 37, 1));
        assert_eq!(find_clear_and_set(&mut bits, 64, 1, 0), 37);
    }

    /// The bits past the size are not the bitmap's: a 40-bit bitmap is full at 40, whatever its
    /// last dword's upper bits hold.
    #[test]
    fn the_size_bounds_the_search() {
        let mut bits = [u32::MAX, 0xFF];
        assert_eq!(find_clear_and_set(&mut bits, 40, 1, 0), NOT_FOUND);
        assert_eq!(bits, [u32::MAX, 0xFF]);
        assert_eq!(find_clear(&bits, 41, 1, 0), Some(40));
    }

    /// A run starts at the hint or past it, then from the start; it never wraps past the end.
    #[test]
    fn runs_search_from_the_hint_then_from_the_start() {
        let mut bits = [0u32; 1];
        set(&mut bits, 32, 10, 4);
        assert_eq!(find_clear(&bits, 32, 3, 8), Some(14));
        assert_eq!(find_clear(&bits, 32, 3, 30), Some(0));
        assert_eq!(find_clear(&bits, 32, 10, 12), Some(14));
        assert_eq!(find_clear(&bits, 32, 19, 0), None);
        assert_eq!(find_clear(&bits, 32, 2, 99), Some(0), "a hint past the end");
        assert_eq!(find_clear(&bits, 32, 0, 5), Some(5));
        assert_eq!(find_clear_and_set(&mut bits, 32, 4, 11), 14);
        assert!(are_set(&bits, 32, 10, 8));
        assert!(!are_set(&bits, 32, 9, 2));
    }

    /// RtlAreBitsSet's ranges: empty, or past the end, is false.
    #[test]
    fn ranges_past_the_end_are_not_set() {
        let bits = [u32::MAX; 2];
        assert!(are_set(&bits, 64, 0, 64));
        assert!(!are_set(&bits, 64, 63, 2));
        assert!(!are_set(&bits, 64, 1088, 1));
        assert!(!are_set(&bits, 64, 3, 0));
        assert!(!are_set(&bits, 64, u32::MAX, 2));
    }

    /// Full dwords are skipped whole: a run after them is still found at its first bit.
    #[test]
    fn full_dwords_are_skipped() {
        let mut bits = [u32::MAX, u32::MAX, 0b1011, 0];
        assert_eq!(find_clear(&bits, 128, 1, 0), Some(66));
        assert_eq!(find_clear(&bits, 128, 3, 0), Some(68));
        clear(&mut bits, 128, 30, 4);
        assert_eq!(bits[..2], [0x3FFF_FFFF, 0xFFFF_FFFC]);
        assert_eq!(find_clear(&bits, 128, 4, 0), Some(30));
    }
}
