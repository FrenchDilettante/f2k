//! KUSER_SHARED_DATA: the page every process maps read-only at 0x7FFE0000, which the kernel keeps
//! current and user-mode code reads without a kernel transition — the tick count, the interrupt
//! and system times, the time-zone bias, the version and product facts (Windows 2000's layout,
//! NT 5.0 x86, `rtl::shared_data`). kernel32's GetTickCount, GetSystemTimeAsFileTime and
//! GetLocalTime read it, as Windows 2000's do.
//!
//! One frame, the kernel's: written through its own mapping at 0xFFDF0000 (where Windows 2000's
//! kernel keeps it), mapped into each process as one more holder of it (`mem::vm::map_shared`), so
//! a process's teardown drops its hold and leaves the frame to the kernel. The clock interrupt
//! updates the times ([`update`]); a KSYSTEM_TIME is written High2Time, LowPart, High1Time
//! (`KSystemTime::store`), so a reader that sees High1Time equal to High2Time read a consistent
//! value.

use rtl::pod::Pod;
pub use rtl::shared_data::KUserSharedData;

/// Where every process sees the page.
pub const USER_ADDRESS: u32 = rtl::shared_data::USER_ADDRESS;

/// Where the kernel writes it (Windows 2000's own address for it).
pub const KERNEL_ADDRESS: u32 = 0xFFDF_0000;

/// The system root, the page's NtSystemRoot: the one place every system path comes from (ntdll's
/// DLL search and its own module path read it from the page; the kernel finds kernel32 under it on
/// the boot volume, `exec::modules`; every process's starting environment names it,
/// `user::params::ENVIRONMENT`).
pub const NT_SYSTEM_ROOT: &[u8] = b"C:\\WINNT";

/// IMAGE_FILE_MACHINE_I386: the machine of the images the system runs.
const MACHINE_I386: u16 = 0x014C;
/// NtProductWinNt: a workstation.
const PRODUCT_WIN_NT: u32 = 1;

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
/// TIME_ZONE_ID_UNKNOWN). Everything else is zero.
pub fn constant_fields() -> KUserSharedData {
    let mut page = KUserSharedData::zeroed();
    page.tick_count_multiplier = tick_count_multiplier(crate::interrupt::clock::INTERVAL_100NS);
    page.image_number_low = MACHINE_I386;
    page.image_number_high = MACHINE_I386;
    for (unit, &byte) in page.nt_system_root.iter_mut().zip(NT_SYSTEM_ROOT) {
        *unit = u16::from(byte);
    }
    page.nt_product_type = PRODUCT_WIN_NT;
    page.product_type_is_valid = 1;
    page.nt_major_version = 5;
    page.nt_minor_version = 0;
    page
}

/// The page's frame, once made at boot.
#[cfg(target_arch = "x86")]
static FRAME: crate::sync::InitOnce<u32> = crate::sync::InitOnce::new();

/// The page, through the kernel's own mapping, lent to `write`: the one way the kernel reaches it.
/// Its writers never overlap: [`init`] runs before the clock's first tick, the clock interrupt
/// writes it ([`update`]), and NtSetSystemTime writes it with interrupts masked
/// ([`set_system_time`]).
#[cfg(target_arch = "x86")]
fn with_page<R>(write: impl FnOnce(&mut KUserSharedData) -> R) -> R {
    // SAFETY: KERNEL_ADDRESS maps the page's frame for the kernel's whole life (`init` maps it
    // before any writer runs), page-aligned and larger than the structure; no two writers overlap
    // (above), so the borrow is exclusive for the call. User mode reads the frame only through its
    // own read-only mapping, which the volatile stores publish to.
    write(unsafe { &mut *(KERNEL_ADDRESS as *mut KUserSharedData) })
}

/// Make the page, before any process and before the clock's first tick: the kernel's frame, mapped
/// at [`KERNEL_ADDRESS`] (a kernel-half table every process directory inherits), its constant
/// fields written and its system time the boot's wall-clock reading.
#[cfg(target_arch = "x86")]
pub fn init(boot_filetime: u64) {
    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, constant_fields().as_bytes());
    crate::mem::paging::map_kernel_page(KERNEL_ADDRESS, frame);
    FRAME.set(frame);
    with_page(|page| page.system_time.store(boot_filetime));
}

/// The system time written now (NtSetSystemTime's, `crate::time::set_system_filetime`), with
/// interrupts masked: the clock interrupt is the page's other writer.
#[cfg(target_arch = "x86")]
pub fn set_system_time(value: u64) {
    with_page(|page| page.system_time.store(value));
}

/// The clock interrupt's update: the interrupt time on every interrupt; the system time (the boot's
/// wall-clock reading plus the kernel's system time) and the tick count on a full tick.
#[cfg(target_arch = "x86")]
pub fn update(
    at_clock: &mut crate::level::At<crate::level::Clock>,
    interrupt_time: u64,
    full_tick: Option<(u64, u64)>,
) {
    with_page(|page| {
        page.interrupt_time.store(interrupt_time);
        if let Some((system_time, tick_count)) = full_tick {
            page.system_time
                .store(crate::time::boot_filetime_at(at_clock) + system_time);
            rtl::shared_data::publish(&mut page.tick_count_low, tick_count as u32);
        }
    });
}

/// Map the page into `space` (the running process's), read-only, inside its region: one more
/// holder of the kernel's frame.
#[cfg(target_arch = "x86")]
pub fn map_into(space: &mut crate::mem::vm::AddressSpace) {
    space
        .map_shared(
            &mut crate::mem::vm::CurrentPages,
            USER_ADDRESS,
            *FRAME.get(),
            crate::mem::vm::PAGE_READONLY,
        )
        .expect("the shared data page maps once, inside its region");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NT 5.0 layout user code reads, and GetTickCount's arithmetic at the captured rate.
    #[test]
    fn the_page_is_the_nt_layout() {
        let multiplier = tick_count_multiplier(100_144);
        assert_eq!(multiplier, 0x0A03_AFB7, "10.0144 ms in 8.24");
        assert_eq!(tick_count_ms(100, multiplier), 1001);
        assert_eq!(tick_count_ms(0, multiplier), 0);
        let fields = constant_fields();
        let page = fields.as_bytes();
        assert_eq!(
            &page[4..8],
            &tick_count_multiplier(crate::interrupt::clock::INTERVAL_100NS).to_le_bytes()
        );
        assert_eq!(&page[0x2C..0x30], &[0x4C, 0x01, 0x4C, 0x01]);
        assert_eq!(&page[0x30..0x34], &[b'C', 0, b':', 0]);
        assert_eq!(&page[0x40..0x42], &[0, 0], "C:\\WINNT, terminated");
        assert_eq!(
            &page[0x264..0x26C],
            &[1, 0, 0, 0, 1, 0, 0, 0],
            "NtProductWinNt, valid"
        );
        assert_eq!(&page[0x26C..0x274], &[5, 0, 0, 0, 0, 0, 0, 0], "5.0");
        // Nothing else: the times, the tick count and the time zone start zero.
        let set = [4..8, 0x2C..0x40, 0x264..0x265, 0x268..0x269, 0x26C..0x26D];
        for (at, &byte) in page.iter().enumerate() {
            if !set.iter().any(|range| range.contains(&at)) {
                assert_eq!(byte, 0, "{at:#x}");
            }
        }
    }

    /// GetTickCount's milliseconds at the captured interval, floored once at the read: the ms
    /// clock runs a hair ahead of the round number (a tick is 10.0144 ms), never behind.
    #[test]
    fn tick_counts_floor_to_milliseconds() {
        let ms = |ticks| {
            tick_count_ms(
                ticks,
                tick_count_multiplier(crate::interrupt::clock::INTERVAL_100NS),
            )
        };
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
