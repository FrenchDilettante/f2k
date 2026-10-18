//! KUSER_SHARED_DATA, as kernel32 reads it: the page the kernel maps read-only at 0x7FFE0000 in
//! every process and keeps current (the tick count, the system time, the time-zone bias), and the
//! product type and suite mask GetVersionExA reports. The host
//! tests read a page of their own instead.

/// The fields kernel32 reads, at their NT 5.0 offsets.
pub const TICK_COUNT_LOW: usize = 0x000;
pub const TICK_COUNT_MULTIPLIER: usize = 0x004;
pub const SYSTEM_TIME: usize = 0x014;
pub const TIME_ZONE_BIAS: usize = 0x020;
pub const TIME_ZONE_ID: usize = 0x240;
pub const NT_PRODUCT_TYPE: usize = 0x264;
pub const SUITE_MASK: usize = 0x2D0;

/// The page's address.
#[cfg(not(test))]
fn page() -> *const u32 {
    0x7FFE_0000 as *const u32
}

/// The dword at `offset`.
pub fn read(offset: usize) -> u32 {
    // SAFETY: the shared data page is mapped read-only in every process for its whole life (the
    // host tests' stand-in for theirs).
    unsafe { page().add(offset / 4).read_volatile() }
}

/// The KSYSTEM_TIME at `offset`, consistently: High1Time, LowPart, High2Time, again while the
/// kernel's update fell between the reads (it writes High2Time first and High1Time last).
pub fn time(offset: usize) -> u64 {
    loop {
        let high = read(offset + 4);
        let low = read(offset);
        if read(offset + 8) == high {
            return (u64::from(high) << 32) | u64::from(low);
        }
    }
}

#[cfg(test)]
pub use host::page;

/// The host tests' page: one per test thread, its fields set by the test.
#[cfg(test)]
pub mod host {
    use std::cell::RefCell;

    std::thread_local! {
        static PAGE: RefCell<Box<[u32; 1024]>> = RefCell::new(Box::new([0; 1024]));
    }

    pub fn page() -> *const u32 {
        PAGE.with(|page| page.borrow().as_ptr())
    }

    /// Set the dword at `offset`.
    pub fn set(offset: usize, value: u32) {
        PAGE.with(|page| page.borrow_mut()[offset / 4] = value);
    }

    /// Set the KSYSTEM_TIME at `offset`.
    pub fn set_time(offset: usize, value: u64) {
        set(offset, value as u32);
        set(offset + 4, (value >> 32) as u32);
        set(offset + 8, (value >> 32) as u32);
    }
}
