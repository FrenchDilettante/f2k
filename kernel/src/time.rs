//! Wall-clock time: the FILETIME the system services and the shared data page report, and the
//! performance counter.
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

use rtl::time::UNITS_PER_SECOND;

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
        (*core::ptr::addr_of_mut!(PERFORMANCE_COUNTER)).read(base, count, pending, crate::hw::pit::INTERVAL_DIVISOR)
    };
    if enabled {
        state.unmask_interrupts();
    }
    value
}

/// The boot's wall-clock reading, a FILETIME; set once at boot.
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
    // SAFETY: written once at boot; read-only afterwards.
    unsafe { BOOT_FILETIME }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(filetime_from_civil(civil(1970, 1, 1, 0, 0, 0)), 116_444_736_000_000_000);
        assert_eq!(filetime_from_civil(civil(2000, 1, 1, 0, 0, 0)), FALLBACK_BOOT);
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
        assert_eq!(counter.read(base, N / 2, false, N), base + (N - N / 2) as u64);
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
        assert_eq!(performance_count(year), 365 * 86_400 * PERFORMANCE_FREQUENCY);
    }
}
