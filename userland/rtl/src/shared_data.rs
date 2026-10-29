//! KUSER_SHARED_DATA as NT 5.0 lays it out on x86: the page the kernel keeps current and maps
//! read-only into every process at 0x7FFE0000, which user-mode code reads without a kernel
//! transition (the tick count, the interrupt and system times, the time-zone bias, the system root,
//! the product and version facts). One definition for every side: the kernel writes it, ntdll and
//! kernel32 read it.
//!
//! [`KUserSharedData`] covers the page up to SuiteMask, the last field anything on F2K reads; the
//! fields between those F2K fills or reads are kept as reserved space. The page is shared memory
//! that the kernel changes under its readers (the clock interrupt updates the times between any two
//! instructions of user code), so its writes are volatile ([`publish`]), and a time is published in
//! the order its readers' retry relies on ([`KSystemTime::store`]).

use core::mem::{offset_of, size_of};

use crate::pod::Pod;

/// Where every process sees the page.
pub const USER_ADDRESS: u32 = 0x7FFE_0000;

/// The system root's room in UTF-16 units: MAX_PATH, its terminator included.
pub const SYSTEM_ROOT_UNITS: usize = 260;

/// A KSYSTEM_TIME: a 64-bit time its readers take without a lock. The kernel writes High2Time,
/// then LowPart, then High1Time; a reader reads High1Time, LowPart and High2Time in the opposite
/// order and takes the value when the two highs agree, retrying otherwise.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KSystemTime {
    pub low_part: u32,
    pub high1_time: u32,
    pub high2_time: u32,
}

impl KSystemTime {
    /// Publish `value`: High2Time, LowPart, then High1Time, each a volatile write, so that a reader
    /// that sees High1Time equal to High2Time read a consistent value.
    pub fn store(&mut self, value: u64) {
        let high = (value >> 32) as u32;
        publish(&mut self.high2_time, high);
        publish(&mut self.low_part, value as u32);
        publish(&mut self.high1_time, high);
    }
}

/// KUSER_SHARED_DATA, NT 5.0's, as far as SuiteMask.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KUserSharedData {
    /// The clock ticks since boot, and the tick's length in milliseconds as an 8.24 fixed-point
    /// value: GetTickCount is `TickCountLow * TickCountMultiplier >> 24`.
    pub tick_count_low: u32,
    pub tick_count_multiplier: u32,
    /// The interrupt time (100 ns units since boot), the system time (a FILETIME, UTC) and the
    /// time-zone bias (UTC less local time, 100 ns units).
    pub interrupt_time: KSystemTime,
    pub system_time: KSystemTime,
    pub time_zone_bias: KSystemTime,
    /// The machine types of the images the system runs (IMAGE_FILE_MACHINE_I386 for both).
    pub image_number_low: u16,
    pub image_number_high: u16,
    /// The system root (`C:\WINNT`), NUL-terminated UTF-16.
    pub nt_system_root: [u16; SYSTEM_ROOT_UNITS],
    pub max_stack_trace_depth: u32,
    pub crypto_exponent: u32,
    /// TIME_ZONE_ID_UNKNOWN, _STANDARD or _DAYLIGHT.
    pub time_zone_id: u32,
    pub reserved_1: [u32; 8],
    /// The product: NtProductWinNt (a workstation), NtProductLanManNt or NtProductServer; valid
    /// when ProductTypeIsValid (a BOOLEAN) is set.
    pub nt_product_type: u32,
    pub product_type_is_valid: u8,
    pub reserved_2: [u8; 3],
    /// The system's version.
    pub nt_major_version: u32,
    pub nt_minor_version: u32,
    pub processor_features: [u8; 64],
    pub reserved_3: [u32; (0x2D0 - 0x2B4) / 4],
    /// The product suites installed (VER_SUITE_*), GetVersionExA's wSuiteMask.
    pub suite_mask: u32,
}

// SAFETY: integers and their arrays; the u16 pair fills a dword, the BOOLEAN's three reserved bytes
// fill its own, and every other field is a whole number of dwords, so there is no padding (the
// layout asserts below pin every offset and the size).
unsafe impl Pod for KUserSharedData {}
// SAFETY: three u32s.
unsafe impl Pod for KSystemTime {}

const _: () = {
    type Layout = KUserSharedData;
    assert!(size_of::<KSystemTime>() == 12);
    assert!(offset_of!(Layout, tick_count_multiplier) == 0x004);
    assert!(offset_of!(Layout, interrupt_time) == 0x008);
    assert!(offset_of!(Layout, system_time) == 0x014);
    assert!(offset_of!(Layout, time_zone_bias) == 0x020);
    assert!(offset_of!(Layout, image_number_low) == 0x02C);
    assert!(offset_of!(Layout, image_number_high) == 0x02E);
    assert!(offset_of!(Layout, nt_system_root) == 0x030);
    assert!(offset_of!(Layout, max_stack_trace_depth) == 0x238);
    assert!(offset_of!(Layout, time_zone_id) == 0x240);
    assert!(offset_of!(Layout, nt_product_type) == 0x264);
    assert!(offset_of!(Layout, product_type_is_valid) == 0x268);
    assert!(offset_of!(Layout, nt_major_version) == 0x26C);
    assert!(offset_of!(Layout, nt_minor_version) == 0x270);
    assert!(offset_of!(Layout, processor_features) == 0x274);
    assert!(offset_of!(Layout, suite_mask) == 0x2D0);
    assert!(size_of::<Layout>() == 0x2D4);
};

/// Store `value` in `place` with a volatile write: the page's readers are outside the program (user
/// mode, through its own mapping), so the store is made exactly, in program order.
pub fn publish<T: Copy>(place: &mut T, value: T) {
    // SAFETY: `place` is a live, exclusive, aligned reference to a `T`.
    unsafe { core::ptr::write_volatile(place, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored time reads back whole, its two highs equal.
    #[test]
    fn a_stored_time_reads_back() {
        let mut time = KSystemTime::default();
        time.store(0x0123_4567_89AB_CDEF);
        assert_eq!(
            time,
            KSystemTime {
                low_part: 0x89AB_CDEF,
                high1_time: 0x0123_4567,
                high2_time: 0x0123_4567,
            }
        );
    }
}
