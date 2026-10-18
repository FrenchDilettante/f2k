//! KUSER_SHARED_DATA: the page every process maps read-only at 0x7FFE0000, which the kernel keeps
//! current and user-mode code reads without a kernel transition — the tick count, the interrupt
//! and system times, the time-zone bias, the version and product facts (Windows 2000's layout,
//! NT 5.0 x86). kernel32's GetTickCount, GetSystemTimeAsFileTime and GetLocalTime read it, as
//! Windows 2000's do.
//!
//! One frame, the kernel's: written through its own mapping at 0xFFDF0000 (where Windows 2000's
//! kernel keeps it), mapped into each process, whose teardown leaves it alone (it is no process's
//! to free: [`is_frame`]; the frame holders, once they exist, make it one more holder instead). The clock interrupt
//! updates the times ([`update`]); a KSYSTEM_TIME is written High2Time, LowPart, High1Time, so a
//! reader that sees High1Time equal to High2Time read a consistent value.

/// Where every process sees the page.
pub const USER_ADDRESS: u32 = 0x7FFE_0000;

/// Where the kernel writes it (Windows 2000's own address for it).
pub const KERNEL_ADDRESS: u32 = 0xFFDF_0000;

/// The fields, at their NT 5.0 offsets.
pub mod offset {
    pub const TICK_COUNT_LOW: u32 = 0x000;
    pub const TICK_COUNT_MULTIPLIER: u32 = 0x004;
    pub const INTERRUPT_TIME: u32 = 0x008;
    pub const SYSTEM_TIME: u32 = 0x014;
    pub const TIME_ZONE_BIAS: u32 = 0x020;
    pub const IMAGE_NUMBER_LOW: u32 = 0x02C;
    pub const IMAGE_NUMBER_HIGH: u32 = 0x02E;
    pub const NT_SYSTEM_ROOT: u32 = 0x030;
    pub const TIME_ZONE_ID: u32 = 0x240;
    pub const NT_PRODUCT_TYPE: u32 = 0x264;
    pub const PRODUCT_TYPE_IS_VALID: u32 = 0x268;
    pub const NT_MAJOR_VERSION: u32 = 0x26C;
    pub const NT_MINOR_VERSION: u32 = 0x270;
}

/// TickCountMultiplier: the tick's length in milliseconds, as a 8.24 fixed-point value
/// (GetTickCount is `TickCountLow * TickCountMultiplier >> 24`).
pub const fn tick_count_multiplier(increment_100ns: u32) -> u32 {
    (((increment_100ns as u64) << 24) / 10_000) as u32
}

/// GetTickCount's arithmetic over the page's fields.
pub const fn tick_count_ms(tick_count_low: u32, multiplier: u32) -> u32 {
    ((tick_count_low as u64 * multiplier as u64) >> 24) as u32
}

/// The page's constant fields: the tick's multiplier, the image machine (i386), the system root,
/// the product (a workstation, NtProductWinNt) and the version (5.0), no time zone (a zero bias,
/// TIME_ZONE_ID_UNKNOWN).
pub fn constant_fields(out: &mut [u8; 0x1000]) {
    let mut put = |at: u32, bytes: &[u8]| out[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    put(
        offset::TICK_COUNT_MULTIPLIER,
        &tick_count_multiplier(crate::interrupt::clock::INTERVAL_100NS).to_le_bytes(),
    );
    put(offset::IMAGE_NUMBER_LOW, &0x014Cu16.to_le_bytes());
    put(offset::IMAGE_NUMBER_HIGH, &0x014Cu16.to_le_bytes());
    for (index, &byte) in b"C:\\WINNT".iter().enumerate() {
        put(offset::NT_SYSTEM_ROOT + 2 * index as u32, &u16::from(byte).to_le_bytes());
    }
    put(offset::NT_PRODUCT_TYPE, &1u32.to_le_bytes());
    put(offset::PRODUCT_TYPE_IS_VALID, &[1]);
    put(offset::NT_MAJOR_VERSION, &5u32.to_le_bytes());
    put(offset::NT_MINOR_VERSION, &0u32.to_le_bytes());
}

/// The page's frame, once made at boot.
#[cfg(target_arch = "x86")]
static mut FRAME: u32 = 0;

/// Make the page, before any process and before the clock's first tick: the kernel's frame, mapped
/// at [`KERNEL_ADDRESS`] (a kernel-half table every process directory inherits), its constant
/// fields written and its system time the boot's wall-clock reading.
#[cfg(target_arch = "x86")]
pub fn init(boot_filetime: u64) {
    let mut page = [0u8; 0x1000];
    constant_fields(&mut page);
    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, &page);
    crate::mem::paging::map_kernel_page(KERNEL_ADDRESS, frame);
    // SAFETY: boot, before any reader.
    unsafe { FRAME = frame };
    write_time(offset::SYSTEM_TIME, boot_filetime);
}

/// Write a KSYSTEM_TIME: High2Time, LowPart, High1Time (a reader retries while High1Time and
/// High2Time differ).
#[cfg(target_arch = "x86")]
fn write_time(at: u32, value: u64) {
    let field = (KERNEL_ADDRESS + at) as *mut u32;
    // SAFETY: the kernel's own mapping of the page (made at boot, never unmapped); the clock
    // interrupt is the only writer after boot.
    unsafe {
        field.add(2).write_volatile((value >> 32) as u32);
        field.write_volatile(value as u32);
        field.add(1).write_volatile((value >> 32) as u32);
    }
}

/// The clock interrupt's update: the interrupt time on every interrupt; the system time (the boot's
/// wall-clock reading plus the kernel's system time) and the tick count on a full tick.
#[cfg(target_arch = "x86")]
pub fn update(interrupt_time: u64, full_tick: Option<(u64, u64)>) {
    write_time(offset::INTERRUPT_TIME, interrupt_time);
    if let Some((system_time, tick_count)) = full_tick {
        write_time(offset::SYSTEM_TIME, crate::time::boot_filetime() + system_time);
        // SAFETY: as `write_time`.
        unsafe { ((KERNEL_ADDRESS + offset::TICK_COUNT_LOW) as *mut u32).write_volatile(tick_count as u32) };
    }
}

/// Map the page into `space` (the running process's), read-only, inside its region.
#[cfg(target_arch = "x86")]
pub fn map_into(space: &mut crate::mem::vm::AddressSpace) {
    // SAFETY: made at boot, read-only afterwards.
    let frame = unsafe { FRAME };
    crate::mem::vm::map_prepared(space, USER_ADDRESS, frame, crate::mem::vm::PAGE_READONLY);
}

/// Whether `frame` is the page's: the kernel's, which a process's teardown must not free.
#[cfg(target_arch = "x86")]
pub fn is_frame(frame: u32) -> bool {
    // SAFETY: made at boot, read-only afterwards.
    frame == unsafe { FRAME }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NT 5.0 layout user code reads, and GetTickCount's arithmetic at the captured rate.
    #[test]
    fn the_page_is_the_nt_layout() {
        assert_eq!(offset::SYSTEM_TIME, 0x14);
        assert_eq!(offset::NT_SYSTEM_ROOT, 0x30);
        assert_eq!(offset::NT_MAJOR_VERSION, 0x26C);
        let multiplier = tick_count_multiplier(100_144);
        assert_eq!(multiplier, 0x0A03_AFB7, "10.0144 ms in 8.24");
        assert_eq!(tick_count_ms(100, multiplier), 1001);
        assert_eq!(tick_count_ms(0, multiplier), 0);
        let mut page = [0u8; 0x1000];
        constant_fields(&mut page);
        assert_eq!(page[0x26C], 5);
        assert_eq!(&page[0x30..0x34], &[b'C', 0, b':', 0]);
        assert_eq!(&page[0x2C..0x30], &[0x4C, 0x01, 0x4C, 0x01]);
    }

    /// GetTickCount's milliseconds at the captured interval, floored once at the read: the ms
    /// clock runs a hair ahead of the round number (a tick is 10.0144 ms), never behind.
    #[test]
    fn tick_counts_floor_to_milliseconds() {
        let ms = |ticks| tick_count_ms(ticks, tick_count_multiplier(crate::interrupt::clock::INTERVAL_100NS));
        assert_eq!(ms(0), 0);
        assert_eq!(ms(1), 10);
        assert_eq!(ms(10), 100);
        assert_eq!(ms(20), 200);
        assert_eq!(ms(50), 500);
        assert_eq!(ms(100), 1001);
    }

    /// The captured cadence, as arithmetic: a sleep of ms milliseconds parks for ceil(ms × 10_000 /
    /// interval) whole ticks (the tick is the resolution floor), and both GetTickCount reads derive
    /// from the same tick-quantized count, so the span reads back as the requested value at the
    /// captured boot phase. (A phase change could carry the tick's fractional overshoot into a
    /// carry — 0.288 ms per 20-tick span — a property of the floor, not a timer bug.)
    #[test]
    fn the_captured_cadence_is_whole_ticks_floored() {
        const INTERVAL: u64 = crate::interrupt::clock::INTERVAL_100NS as u64;
        let ms = |ticks| tick_count_ms(ticks, tick_count_multiplier(INTERVAL as u32));
        for (milliseconds, span) in [(200u32, 20u32), (100, 10), (0, 0), (5, 1)] {
            let interval = u64::from(milliseconds) * 10_000;
            let ticks = interval.div_ceil(INTERVAL);
            assert_eq!(ticks, u64::from(span), "{milliseconds} ms");
            // The span at the canonical phase (entry at tick 0) reads back as requested; Sleep(5)
            // quantizes to the tick — the resolution floor.
            let read = ms(span) - ms(0);
            if milliseconds == 5 {
                assert_eq!(read, 10);
            } else {
                assert_eq!(read, milliseconds);
            }
        }
    }
}
