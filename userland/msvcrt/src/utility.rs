//! qsort, rand and srand, time.
//!
//! rand is the C runtime's linear congruential generator, per thread: the seed becomes
//! `seed * 214013 + 2531011` and rand answers its bits 16 to 30 (RAND_MAX 32767), the seed 1 until
//! srand sets it (wide's capture: 41, 18467, 6334… without srand and after srand(1)).

use crate::thread;

/// The comparison qsort calls (cdecl).
pub type Compare = unsafe extern "C" fn(*const u8, *const u8) -> i32;

/// Two elements of `width` bytes swapped.
///
/// # Safety
///
/// Both are elements of the caller's array.
unsafe fn swap(a: *mut u8, b: *mut u8, width: usize) {
    if a != b {
        // SAFETY: the caller's elements, distinct.
        unsafe { core::ptr::swap_nonoverlapping(a, b, width) };
    }
}

/// qsort: `count` elements of `width` bytes sorted in place by `compare`: a quicksort, its pivot
/// the median of three, short runs sorted by insertion, the smaller side first so the depth stays
/// logarithmic.
///
/// # Safety
///
/// `base` holds `count` elements of `width` bytes; `compare` orders two of them.
#[unsafe(export_name = "f2k_export_qsort")]
pub unsafe extern "C" fn qsort(base: *mut u8, count: usize, width: usize, compare: Compare) {
    if count < 2 || width == 0 {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { sort(base, count, width, compare) };
}

/// The quicksort's body over `count` elements at `base`.
///
/// # Safety
///
/// As qsort's.
unsafe fn sort(mut base: *mut u8, mut count: usize, width: usize, compare: Compare) {
    // SAFETY: every element touched is inside the caller's array.
    unsafe {
        let element = |base: *mut u8, i: usize| base.add(i * width);
        while count > 8 {
            let (first, middle, last) = (
                element(base, 0),
                element(base, count / 2),
                element(base, count - 1),
            );
            // The median of three to the front.
            if compare(middle, first) < 0 {
                swap(middle, first, width);
            }
            if compare(last, middle) < 0 {
                swap(last, middle, width);
                if compare(middle, first) < 0 {
                    swap(middle, first, width);
                }
            }
            swap(first, middle, width);
            // Partition the rest around the pivot at the front.
            let (mut low, mut high) = (1, count - 1);
            loop {
                while low <= high && compare(element(base, low), first) < 0 {
                    low += 1;
                }
                while high >= low && compare(element(base, high), first) > 0 {
                    high -= 1;
                }
                if low >= high {
                    break;
                }
                swap(element(base, low), element(base, high), width);
                low += 1;
                high -= 1;
            }
            swap(first, element(base, high), width);
            let (left, right) = (high, count - high - 1);
            if left < right {
                sort(base, left, width, compare);
                base = element(base, high + 1);
                count = right;
            } else {
                sort(element(base, high + 1), right, width, compare);
                count = left;
            }
        }
        for i in 1..count {
            let mut j = i;
            while j > 0 && compare(element(base, j - 1), element(base, j)) > 0 {
                swap(element(base, j - 1), element(base, j), width);
                j -= 1;
            }
        }
    }
}

/// rand: the next pseudo-random number, 0 to 32767.
#[unsafe(export_name = "f2k_export_rand")]
pub extern "C" fn rand() -> i32 {
    let data = thread::data();
    // SAFETY: the thread's own data.
    unsafe {
        (*data).seed = (*data).seed.wrapping_mul(214_013).wrapping_add(2_531_011);
        ((*data).seed >> 16 & 0x7FFF) as i32
    }
}

/// srand: rand's seed.
#[unsafe(export_name = "f2k_export_srand")]
pub extern "C" fn srand(seed: u32) {
    // SAFETY: the thread's own data.
    unsafe { (*thread::data()).seed = seed };
}

/// The FILETIME of 1970-01-01 00:00:00 UTC, in 100-nanosecond intervals since 1601.
const UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// time: the seconds since 1970-01-01 00:00:00 UTC, stored in `timer` too when it is given.
///
/// # Safety
///
/// `timer` is null or a `time_t`'s storage.
#[unsafe(export_name = "f2k_export_time")]
pub unsafe extern "C" fn time(timer: *mut i32) -> i32 {
    let mut now = 0u64;
    // SAFETY: kernel32's export, over the FILETIME.
    unsafe { crate::imports::GetSystemTimeAsFileTime(&mut now) };
    let seconds = (now.saturating_sub(UNIX_EPOCH) / 10_000_000) as i32;
    if !timer.is_null() {
        // SAFETY: the caller's time_t.
        unsafe { timer.write_unaligned(seconds) };
    }
    seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn by_int(a: *const u8, b: *const u8) -> i32 {
        // SAFETY: two ints of the test's array.
        let (x, y) = unsafe {
            (
                (a as *const i32).read_unaligned(),
                (b as *const i32).read_unaligned(),
            )
        };
        x.cmp(&y) as i32
    }

    /// wide's sort block, and sizes past the insertion sort's.
    #[test]
    fn qsort_sorts() {
        let mut ints = [
            42,
            -7,
            1000,
            0,
            13,
            -2147483647,
            8,
            99,
            2147483647,
            5,
            -1,
            64,
        ];
        // SAFETY: the test's array of ints.
        unsafe { qsort(ints.as_mut_ptr().cast(), 12, 4, by_int) };
        assert_eq!(
            ints,
            [
                -2147483647,
                -7,
                -1,
                0,
                5,
                8,
                13,
                42,
                64,
                99,
                1000,
                2147483647
            ]
        );
        let mut many: Vec<i32> = (0..1000).map(|i| (i * 7919 % 1009) - 500).collect();
        many.extend([3; 50]);
        let mut expected = many.clone();
        expected.sort();
        // SAFETY: as above.
        unsafe { qsort(many.as_mut_ptr().cast(), many.len(), 4, by_int) };
        assert_eq!(many, expected);
    }

    /// wide's rand block.
    #[test]
    fn rand_as_captured() {
        let eight = || (0..8).map(|_| rand()).collect::<Vec<_>>();
        let first = [41, 18467, 6334, 26500, 19169, 15724, 11478, 29358];
        std::thread::spawn(move || {
            assert_eq!(eight(), first);
            srand(1);
            assert_eq!(eight(), first);
            srand(42);
            assert_eq!(eight(), [175, 400, 17869, 30056, 16083, 12879, 8016, 7644]);
        })
        .join()
        .unwrap();
    }
}
