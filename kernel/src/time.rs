//! Wall-clock time: the FILETIME the system services and the shared data page report, the FAT
//! timestamps' conversions, and the performance counter.
//!
//! The kernel's clock counts from boot; the wall clock is that count plus the boot's own wall-clock
//! reading, taken once from the real-time clock (see [`crate::hw::rtc`]). A FILETIME is 100 ns
//! units since 1601-01-01 UTC, the same unit as the kernel's clock, so the sum needs no scaling.
//! With no time zone configured, local time is UTC: the time-zone services report a zero bias and
//! no daylight saving.
//!
//! The performance counter runs at the interval timer's input clock, 1193182 Hz — what the
//! platform's uniprocessor HAL reports — as that HAL reads it: the ticks taken (the kernel's
//! interrupt time on the counter's scale) plus what the timer has run down since the last one, so
//! it resolves well below a tick, and it never goes back.

use crate::hw::rtc::CivilTime;

/// The performance counter's frequency: the 8254's input clock.
pub const PERFORMANCE_FREQUENCY: u64 = 1_193_182;

pub use rtl::time::system_time_from_filetime;
use rtl::time::UNITS_PER_SECOND;
#[cfg(test)]
use rtl::time::{filetime_from_system_time, SystemTime};

/// The wall clock's fallback when the real-time clock gives no valid reading: 2000-01-01 00:00.
pub const FALLBACK_BOOT: u64 = 125_911_584_000_000_000;

/// The FILETIME of a civil time.
pub fn filetime_from_civil(time: CivilTime) -> u64 {
    rtl::time::filetime_from_fields(
        time.year,
        time.month as u16,
        time.day as u16,
        time.hour as u16,
        time.minute as u16,
        time.second as u16,
    )
}

/// The FILETIME of a FAT timestamp (local time, which is UTC here): a date's year counts from
/// 1980, a time's seconds come in units of two, and the hundredths (0-199) add up to two seconds
/// more. A zero or impossible date is no time at all (zero).
pub fn fat_filetime(date: u16, time: u16, hundredths: u8) -> u64 {
    let (month, day) = (((date >> 5) & 0xF) as u8, (date & 0x1F) as u8);
    if date == 0 || !(1..=12).contains(&month) || day == 0 {
        return 0;
    }
    let civil = CivilTime {
        year: 1980 + (date >> 9),
        month,
        day,
        hour: (time >> 11) as u8,
        minute: ((time >> 5) & 0x3F) as u8,
        second: ((time & 0x1F) * 2) as u8,
    };
    filetime_from_civil(civil) + hundredths as u64 * 100_000
}

/// A FILETIME as a FAT timestamp (date, time, hundredths): local time, which is UTC here. Times
/// before 1980 take the format's first day; the two-second units round down, the hundredths
/// carry the rest.
#[cfg_attr(target_arch = "x86", allow(dead_code))]
pub fn fat_from_filetime(filetime: u64) -> (u16, u16, u8) {
    let civil = system_time_from_filetime(filetime);
    if civil.year < 1980 {
        return ((1 << 5) | 1, 0, 0);
    }
    let year = (civil.year - 1980).min(127);
    let date = year << 9 | civil.month << 5 | civil.day;
    let time = civil.hour << 11 | civil.minute << 5 | civil.second / 2;
    let hundredths = (civil.second % 2) * 100 + civil.milliseconds / 10;
    (date, time, hundredths as u8)
}

/// A clock reading (100 ns units) on the performance counter's scale.
pub fn performance_count(units: u64) -> u64 {
    units / UNITS_PER_SECOND * PERFORMANCE_FREQUENCY
        + units % UNITS_PER_SECOND * PERFORMANCE_FREQUENCY / UNITS_PER_SECOND
}

/// The performance counter's reader: what the last reading reported, which no later one goes
/// below.
pub struct PerformanceCounter {
    last: u64,
}

impl PerformanceCounter {
    /// A reader that has reported nothing yet.
    pub const fn new() -> Self {
        PerformanceCounter { last: 0 }
    }

    /// The counter at a reading: `base`, the ticks taken on the counter's scale, plus the counts
    /// the interval timer has run down from `divisor` to `count` since. `pending` is the clock's
    /// request line, raised and not taken yet (the reader runs with interrupts masked): the timer
    /// has reloaded since the last tick taken, and the interval it finished counts too — unless
    /// the count read is past the middle of an interval, when the request came after the latch.
    /// A reading below the last one reported (a reload the request line does not show yet)
    /// reports the last one again.
    pub fn read(&mut self, base: u64, count: u16, pending: bool, divisor: u16) -> u64 {
        let elapsed = divisor.saturating_sub(count);
        let mut value = base + u64::from(elapsed);
        if pending && elapsed < divisor / 2 {
            value += u64::from(divisor);
        }
        self.last = self.last.max(value);
        self.last
    }
}

/// The kernel's performance counter reader.
#[cfg(target_arch = "x86")]
static mut PERFORMANCE_COUNTER: PerformanceCounter = PerformanceCounter::new();

/// The performance counter now: the interrupt time, the interval timer's count, and the clock's
/// request line read together with interrupts masked.
#[cfg(target_arch = "x86")]
pub fn performance_counter() -> u64 {
    let state = crate::interrupt::irql::state_mut();
    let enabled = state.interrupts_enabled();
    state.mask_interrupts();
    let base = performance_count(crate::interrupt::clock::interrupt_time());
    let count = crate::hw::pit::read_count(&mut crate::hw::portio::Ports);
    let pending = crate::interrupt::clock_requested();
    // SAFETY: the reader's one user, serialized with interrupts masked.
    let value = unsafe {
        (*core::ptr::addr_of_mut!(PERFORMANCE_COUNTER)).read(
            base,
            count,
            pending,
            crate::hw::pit::programmed_divisor(),
        )
    };
    if enabled {
        state.unmask_interrupts();
    }
    value
}

/// The boot's wall-clock reading, a FILETIME: set at boot, and moved when the system time is set
/// ([`set_system_filetime`]).
#[cfg(target_arch = "x86")]
static mut BOOT_FILETIME: u64 = FALLBACK_BOOT;

/// Record the boot's wall-clock reading from the real-time clock (the fallback when it has none).
/// Call once, at boot, while the kernel clock still reads zero.
#[cfg(target_arch = "x86")]
pub fn init<IoT: crate::hw::portio::Io>(io: &mut IoT) {
    let boot = crate::hw::rtc::read(io).map_or(FALLBACK_BOOT, filetime_from_civil);
    // SAFETY: written once at boot, before any reader runs.
    unsafe { BOOT_FILETIME = boot };
}

/// The boot's wall-clock reading.
#[cfg(target_arch = "x86")]
pub fn boot_filetime() -> u64 {
    // SAFETY: a single processor; the writer ([`set_system_filetime`]) masks interrupts across its
    // write, so a reader never sees half of it.
    unsafe { BOOT_FILETIME }
}

/// The current wall-clock time, a FILETIME.
#[cfg(target_arch = "x86")]
pub fn system_filetime() -> u64 {
    boot_filetime() + crate::interrupt::clock::system_time()
}

/// Set the wall-clock time (NtSetSystemTime's work): the boot's reading moved so that the current
/// time reads `now`, and the shared data page's system time written at once rather than at the
/// next full tick. The kernel's clock and its timers keep their own count (a relative wait is not
/// moved), and the real-time clock is not written: the machine's next boot reads its own again.
#[cfg(target_arch = "x86")]
pub fn set_system_filetime(now: u64) {
    let state = crate::interrupt::irql::state_mut();
    let enabled = state.interrupts_enabled();
    state.mask_interrupts();
    let boot = now.wrapping_sub(crate::interrupt::clock::system_time());
    // SAFETY: a single processor, interrupts masked: no reader runs across the write.
    unsafe { BOOT_FILETIME = boot };
    crate::user::shared::set_system_time(now);
    if enabled {
        state.unmask_interrupts();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture's time survives the round trip through a SYSTEMTIME and the FAT encoding.
    #[test]
    fn fat_round_trip() {
        let st = SystemTime {
            year: 2001,
            month: 2,
            day_of_week: 0,
            day: 3,
            hour: 4,
            minute: 5,
            second: 6,
            milliseconds: 0,
        };
        let ft = filetime_from_system_time(st).unwrap();
        let (date, time, hundredths) = fat_from_filetime(ft);
        assert_eq!(fat_filetime(date, time, 0), ft);
        assert_eq!(hundredths, 0);
        let back = system_time_from_filetime(fat_filetime(date, time, 0));
        assert_eq!(
            (
                back.year,
                back.month,
                back.day,
                back.hour,
                back.minute,
                back.second
            ),
            (2001, 2, 3, 4, 5, 6)
        );
        assert_eq!(
            filetime_from_system_time(SystemTime { month: 13, ..st }),
            None
        );
        assert_eq!(
            filetime_from_system_time(SystemTime {
                day: 29,
                month: 2,
                ..st
            }),
            None
        );
    }

    fn civil(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> CivilTime {
        CivilTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// The anchors: the FILETIME epoch, the Unix epoch, and the fallback boot time.
    #[test]
    fn the_epochs_convert() {
        assert_eq!(filetime_from_civil(civil(1601, 1, 1, 0, 0, 0)), 0);
        assert_eq!(
            filetime_from_civil(civil(1970, 1, 1, 0, 0, 0)),
            116_444_736_000_000_000
        );
        assert_eq!(
            filetime_from_civil(civil(2000, 1, 1, 0, 0, 0)),
            FALLBACK_BOOT
        );
    }

    /// FAT timestamps: 2026-10-16 18:42:30 plus 57 hundredths, and the no-time zero date.
    #[test]
    fn fat_timestamps_convert() {
        let date = ((2026 - 1980) << 9) | (10 << 5) | 16;
        let time = (18 << 11) | (42 << 5) | 15;
        let base = filetime_from_civil(civil(2026, 10, 16, 18, 42, 30));
        assert_eq!(fat_filetime(date, time, 57), base + 5_700_000);
        assert_eq!(fat_filetime(date, time, 0), base);
        assert_eq!(fat_filetime(0, 0, 0), 0);
    }

    /// The performance counter between ticks: the taken ticks' counts plus what the interval timer
    /// has run down since the last one, so a section shorter than a tick measures more
    /// than zero; a reload the clock interrupt has not been taken for yet counts a full interval
    /// more; and a reading never goes back.
    #[test]
    fn the_performance_counter_counts_within_a_tick() {
        use crate::hw::pit::INTERVAL_DIVISOR as N;
        let base = performance_count(10 * 100_144);
        let mut counter = PerformanceCounter::new();
        // Just after the tick: the count is at the divisor, nothing elapsed.
        assert_eq!(counter.read(base, N, false, N), base);
        // A tenth of the way through, then half.
        assert_eq!(counter.read(base, N - 1_195, false, N), base + 1_195);
        assert_eq!(
            counter.read(base, N / 2, false, N),
            base + (N - N / 2) as u64
        );
        // The timer reloaded and raised its line, the interrupt not taken yet (the gate masks
        // it): the interval it finished counts.
        assert_eq!(counter.read(base, N - 40, true, N), base + N as u64 + 40);
        // Taken now: the next tick's base, a little further on.
        let next = performance_count(11 * 100_144);
        assert_eq!(counter.read(next, N - 60, false, N), next + 60);
        // A reload the request line does not show yet (it lags the count) would read back: the
        // counter holds instead.
        let last = next + 60;
        assert_eq!(counter.read(next, N - 2, false, N), last);
        // A request raised after the latch (the count read near its end): no interval added.
        assert_eq!(counter.read(next, 3, true, N), next + (N - 3) as u64);
    }

    /// The performance counter: a second is the frequency, without overflow far from boot.
    #[test]
    fn the_performance_count_scales_exactly() {
        assert_eq!(performance_count(UNITS_PER_SECOND), PERFORMANCE_FREQUENCY);
        assert_eq!(performance_count(2_000_000), 238_636);
        let year = 365 * rtl::time::UNITS_PER_DAY;
        assert_eq!(
            performance_count(year),
            365 * 86_400 * PERFORMANCE_FREQUENCY
        );
    }
}
