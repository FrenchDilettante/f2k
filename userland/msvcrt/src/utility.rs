//! qsort, rand and srand, time.
//!
//! rand is the C runtime's linear congruential generator, per thread: the seed becomes
//! `seed * 214013 + 2531011` and rand answers its bits 16 to 30 (RAND_MAX 32767), the seed 1 until
//! srand sets it (wide's capture: 41, 18467, 6334… without srand and after srand(1)).

use core::sync::atomic::Ordering::Relaxed;

use crate::kernel32;
use crate::thread;

/// The comparison qsort calls (cdecl).
pub type Compare = unsafe extern "C" fn(*const u8, *const u8) -> i32;

/// An array of elements of `width` bytes, sorted in place by a comparison of two of them.
struct Elements<'a> {
    bytes: &'a mut [u8],
    width: usize,
    compare: &'a dyn Fn(&[u8], &[u8]) -> i32,
}

impl Elements<'_> {
    /// Element `i`.
    fn at(&self, i: usize) -> &[u8] {
        &self.bytes[i * self.width..][..self.width]
    }

    /// Elements `i` and `j` compared.
    fn order(&self, i: usize, j: usize) -> i32 {
        (self.compare)(self.at(i), self.at(j))
    }

    /// Elements `i` and `j` swapped.
    fn swap(&mut self, i: usize, j: usize) {
        if i != j {
            let (low, high) = (i.min(j), i.max(j));
            let (front, back) = self.bytes.split_at_mut(high * self.width);
            front[low * self.width..][..self.width].swap_with_slice(&mut back[..self.width]);
        }
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
    let Some(length) = count.checked_mul(width) else {
        return;
    };
    // SAFETY: the caller's array of `count` elements of `width` bytes, the sort's alone meanwhile.
    let bytes = unsafe { core::slice::from_raw_parts_mut(base, length) };
    let compare = |a: &[u8], b: &[u8]| {
        // SAFETY: the caller's comparison, over two elements of its array (it reads them only).
        unsafe { compare(a.as_ptr(), b.as_ptr()) }
    };
    sort(&mut Elements {
        bytes,
        width,
        compare: &compare,
    });
}

/// The quicksort's body.
fn sort(array: &mut Elements) {
    let width = array.width;
    let mut count = array.bytes.len() / width;
    while count > 8 {
        let (first, middle, last) = (0, count / 2, count - 1);
        // The median of three to the front.
        if array.order(middle, first) < 0 {
            array.swap(middle, first);
        }
        if array.order(last, middle) < 0 {
            array.swap(last, middle);
            if array.order(middle, first) < 0 {
                array.swap(middle, first);
            }
        }
        array.swap(first, middle);
        // Partition the rest around the pivot at the front.
        let (mut low, mut high) = (1, count - 1);
        loop {
            while low <= high && array.order(low, first) < 0 {
                low += 1;
            }
            while high >= low && array.order(high, first) > 0 {
                high -= 1;
            }
            if low >= high {
                break;
            }
            array.swap(low, high);
            low += 1;
            high -= 1;
        }
        array.swap(first, high);
        let (left, right) = (high, count - high - 1);
        // The smaller side sorted first (recursively), the larger by the loop.
        let bytes = core::mem::take(&mut array.bytes);
        let (front, back) = bytes.split_at_mut(high * width);
        let back = &mut back[width..];
        let (smaller, larger) = if left < right {
            (front, back)
        } else {
            (back, front)
        };
        sort(&mut Elements {
            bytes: smaller,
            width,
            compare: array.compare,
        });
        array.bytes = larger;
        count = left.max(right);
    }
    for i in 1..count {
        let mut j = i;
        while j > 0 && array.order(j - 1, j) > 0 {
            array.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// rand: the next pseudo-random number, 0 to 32767.
#[unsafe(export_name = "f2k_export_rand")]
pub extern "C" fn rand() -> i32 {
    thread::with_data(|data| {
        let seed = data
            .seed
            .load(Relaxed)
            .wrapping_mul(214_013)
            .wrapping_add(2_531_011);
        data.seed.store(seed, Relaxed);
        (seed >> 16 & 0x7FFF) as i32
    })
}

/// srand: rand's seed.
#[unsafe(export_name = "f2k_export_srand")]
pub extern "C" fn srand(seed: u32) {
    thread::with_data(|data| data.seed.store(seed, Relaxed));
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
    let now = kernel32::system_time();
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
