//! The interval clock: tick math and the clock's deferred work.
//!
//! The 8254 channel 0 raises the timer interrupt at the programmed
//! rate; this module owns everything after that. The interrupt adds
//! the time increment to interrupt time; a fractional accumulator
//! (fed by the same increment and refilled by the maximum) decides
//! whether the interrupt was a full tick — only a full tick advances
//! system time and the tick count. System time moves by the
//! adjustable time-slew value, the tick count does not.
//!
//! The rate lives entirely in the four variables set by
//! [`Clock::set_time_increment`]; the tick math itself is
//! rate-agnostic. On a full tick the clock enqueues its deferred
//! work (the timer-expiry DPC) with the same single-flight discipline
//! every DPC enqueue uses, and the runtime accounting folds the DPC
//! request-rate history.

use crate::interrupt::dpc::{Dpc, DpcQueue};
use core::ptr::addr_of_mut;

/// The interval in 100 ns units a real machine of this platform
/// family reports as its default time increment (10.0144 ms).
pub const INTERVAL_100NS: u32 = 100_144;

/// The finest rate the same machine offers for slewing (1.0032 ms).
pub const FINEST_100NS: u32 = 10_032;

/// What one interrupt did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tick {
    /// A fractional interrupt: interrupt time advanced, but this was
    /// not a full tick — system time, the tick count, and the
    /// runtime accounting are skipped.
    Fractional,
    /// A full tick: the accumulator refilled, system time slewed,
    /// the tick count advanced.
    Full,
}

/// The interval clock's rate quantities and counters.
pub struct Clock {
    /// What every interrupt adds to interrupt time.
    time_increment: u32,
    /// What a full tick adds back to the fractional accumulator.
    maximum_increment: u32,
    /// The finest rate offered (floored).
    minimum_increment: u32,
    /// What a full tick slews system time by.
    time_adjustment: u32,
    /// The fractional accumulator. Positive after an interrupt that
    /// was not a full tick.
    tick_offset: i32,
    /// Full ticks since boot.
    tick_count: u64,
    /// Interrupt time, 100 ns units.
    interrupt_time: u64,
    /// System time, 100 ns units (slewed by the adjustment).
    system_time: u64,
    /// The published low word of the tick count.
    tick_low: u32,
    /// Every interrupt (fractional included).
    interrupt_count: u32,
}

impl Clock {
    /// A zeroed clock; call [`Clock::set_time_increment`] before
    /// first use.
    pub const fn new() -> Self {
        Self {
            time_increment: 0,
            maximum_increment: 0,
            minimum_increment: 0,
            time_adjustment: 0,
            tick_offset: 0,
            tick_count: 0,
            interrupt_time: 0,
            system_time: 0,
            tick_low: 0,
            interrupt_count: 0,
        }
    }

    /// The clock's rate contract, in 100 ns units: the maximum is the
    /// interval every interrupt adds; the minimum (the finest rate
    /// offered) has a hard floor of 1 ms. The increment, the slew
    /// value, and the fractional accumulator all start at the
    /// maximum.
    pub fn set_time_increment(&mut self, maximum: u32, minimum: u32) {
        self.maximum_increment = maximum;
        self.minimum_increment = if minimum > 10_000 { minimum } else { 10_000 };
        self.time_adjustment = maximum;
        self.time_increment = maximum;
        self.tick_offset = maximum as i32;
    }

    /// Full ticks since boot.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Interrupt time (100 ns units).
    pub fn interrupt_time(&self) -> u64 {
        self.interrupt_time
    }

    /// System time (100 ns units), slewed by the time adjustment.
    pub fn system_time(&self) -> u64 {
        self.system_time
    }

    /// Interrupts taken (fractional included).
    pub fn interrupt_count(&self) -> u32 {
        self.interrupt_count
    }

    /// One interval interrupt: advance interrupt time, decide
    /// whether this was a full tick, and (only then) advance system
    /// time and the tick count. The rate lives in the set-time
    /// variables; nothing here knows the hardware.
    pub fn tick(&mut self) -> Tick {
        self.interrupt_time += self.time_increment as u64;
        self.tick_offset -= self.time_increment as i32;

        let tick_low;
        if self.tick_offset > 0 {
            // Fractional: system time, the tick count, and runtime
            // accounting are skipped.
            tick_low = self.tick_count as u32;
        } else {
            // System time slews by the adjustment, not the raw
            // increment — the addend is adjustable.
            self.system_time += self.time_adjustment as u64;
            self.tick_count += 1;
            tick_low = self.tick_count as u32;
        }
        self.tick_low = tick_low;

        if self.tick_offset > 0 {
            self.interrupt_count += 1;
            return Tick::Fractional;
        }

        // A full tick refills the accumulator.
        self.tick_offset += self.maximum_increment as i32;
        self.interrupt_count += 1;
        Tick::Full
    }

    /// The runtime accounting on a full tick: fold the deferred-work
    /// request-rate history. (The per-thread quantum work belongs to
    /// the scheduler, not the clock.)
    pub fn account_runtime(&self, queue: &mut DpcQueue) {
        queue.update_request_rate();
    }

    /// Whether the deferred timer work should run this tick. The
    /// timer-table walk it will become is future work (the scheduler
    /// milestone); for now the clock's deferred work runs on every
    /// full tick, which is what exercises the machinery.
    fn timer_work_due(&self) -> bool {
        true
    }
}

/// The deferred timer routine: the clock's DPC callback. The
/// timer-table expiry scan it will perform is future work; the call
/// itself is the observable.
static mut TIMER_FIRED: u32 = 0;

/// How many times the deferred timer routine has run.
pub fn timer_fired() -> u32 {
    // SAFETY: single CPU; read-only.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TIMER_FIRED)) }
}

fn timer_routine(_dpc: &Dpc, _context: usize, _argument1: usize, _argument2: usize) {
    // SAFETY: single CPU, called with interrupts enabled from the
    // retire pass.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(TIMER_FIRED),
            core::ptr::read_volatile(core::ptr::addr_of!(TIMER_FIRED)) + 1,
        );
    }
}

// --- Target wiring: the kernel clock --------------------------------------

/// The kernel's clock and its deferred timer work.
#[cfg(target_arch = "x86")]
static mut CLOCK: Clock = Clock::new();

/// The deferred timer work: enqueued by the clock's interrupt on a
/// full tick, drained at the dispatch level. Single-flight like
/// every DPC: a tick that finds it already queued skips the enqueue.
#[cfg(target_arch = "x86")]
static mut TIMER_DPC: Dpc = Dpc::new(timer_routine, 0);

/// The vector the timer interrupt arrives on (IRQ 0 after the remap).
pub const CLOCK_VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE;

/// The clock's interrupt service body: run at the clock level with
/// interrupts masked, after the interrupt has been claimed. Updates
/// the clock and enqueues the deferred timer work when it is due.
#[cfg(target_arch = "x86")]
pub fn service() {
    // SAFETY: single CPU; the clock, its DPC, the queue, and the
    // level state are kernel statics whose accessors run serialized
    // by the level discipline.
    unsafe {
        let clock = &mut *addr_of_mut!(CLOCK);
        if let Tick::Full = clock.tick() {
            if clock.timer_work_due() {
                // The ISR's enqueue: single-flight (a queued DPC is
                // left alone), tail-linked, the low tick word carried
                // as the argument, and a dispatch request through the
                // same gate every enqueue uses.
                let tick_low = clock.tick_count() as u32;
                let dpc = &mut *addr_of_mut!(TIMER_DPC);
                crate::interrupt::dpc::enqueue(dpc, tick_low as usize, 0);
            }
            clock.account_runtime(crate::interrupt::dpc::queue_mut());
        }
    }
}

/// Point the kernel clock at the captured platform rate (10.0144 ms
/// per interrupt; 1.0032 ms the finest offered).
///
/// # Safety
///
/// Boot CPU, interrupts disabled, before the first tick.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    // SAFETY: sole access, before interrupts are enabled.
    unsafe { (*addr_of_mut!(CLOCK)).set_time_increment(INTERVAL_100NS, FINEST_100NS) };
}

/// The kernel clock's tick count (diagnostic and smoke reads).
#[cfg(target_arch = "x86")]
pub fn ticks() -> u64 {
    // SAFETY: read-only.
    unsafe { (*addr_of_mut!(CLOCK)).tick_count() }
}

/// The kernel clock's system time (100 ns units): the wait
/// discipline's source of "now".
#[cfg(target_arch = "x86")]
pub fn system_time() -> u64 {
    // SAFETY: read-only.
    unsafe { (*addr_of_mut!(CLOCK)).system_time() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrupt::irql::IrqlState;

    /// The rate contract: the maximum stands as increment, slew
    /// value, and accumulator start; the minimum has a 1 ms floor.
    #[test]
    fn set_time_increment_contract() {
        let mut clock = Clock::new();
        clock.set_time_increment(100_144, 10_032);
        assert_eq!(clock.time_increment, 100_144);
        assert_eq!(clock.maximum_increment, 100_144);
        assert_eq!(clock.time_adjustment, 100_144);
        assert_eq!(clock.tick_offset, 100_144);
        assert_eq!(clock.minimum_increment, 10_032);

        // The floor: a sub-millisecond minimum is raised to it.
        clock.set_time_increment(100_144, 5_000);
        assert_eq!(clock.minimum_increment, 10_000);
        // The floor leaves a coarser minimum alone.
        clock.set_time_increment(100_144, 15_000);
        assert_eq!(clock.minimum_increment, 15_000);
    }

    /// With the increment equal to the maximum (the captured platform
    /// rate), every interrupt is a full tick: N interrupts produce
    /// exactly N ticks and interrupt time advances N increments.
    #[test]
    fn captured_rate_makes_every_interrupt_a_full_tick() {
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        for i in 1..=10u64 {
            assert_eq!(clock.tick(), Tick::Full);
            assert_eq!(clock.tick_count(), i);
        }
        assert_eq!(clock.interrupt_time(), 10 * INTERVAL_100NS as u64);
        assert_eq!(clock.system_time(), 10 * INTERVAL_100NS as u64);
        assert_eq!(clock.interrupt_count(), 10);
    }

    /// A half-rate source (the increment is half the maximum): the
    /// fractional accumulator decides — every second interrupt is a
    /// full tick, using integer math only.
    #[test]
    fn a_half_rate_source_fulls_every_second_tick() {
        let mut clock = Clock::new();
        clock.set_time_increment(100_000, 10_000);
        clock.time_increment = 50_000; // a source twice as fast

        assert_eq!(clock.tick(), Tick::Fractional); // offset: 50000
        assert_eq!(clock.tick(), Tick::Full); // offset: -50000 -> 50000
        assert_eq!(clock.tick(), Tick::Fractional);
        assert_eq!(clock.tick(), Tick::Full);
        assert_eq!(clock.tick_count(), 2);
        assert_eq!(clock.interrupt_time(), 200_000);
        assert_eq!(clock.interrupt_count(), 4);
    }

    /// System time slews by the adjustment while the tick count
    /// counts ticks: halving the adjustment leaves tick accounting
    /// untouched.
    #[test]
    fn the_adjustment_slews_system_time_not_the_tick_count() {
        let mut clock = Clock::new();
        clock.set_time_increment(100_000, 10_000);
        clock.time_adjustment = 60_000;
        for _ in 0..5 {
            clock.tick();
        }
        assert_eq!(clock.tick_count(), 5);
        assert_eq!(clock.system_time(), 5 * 60_000);
        assert_eq!(clock.interrupt_time(), 5 * 100_000);
    }

    /// There is no catch-up: lost ticks stay lost — each interrupt
    /// counts once, and the counters never read the device back.
    #[test]
    fn no_missed_tick_catch_up() {
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        for i in 1..=7u64 {
            clock.tick();
            assert_eq!(clock.tick_count(), i);
        }
        assert_eq!(clock.tick_count(), 7);
    }

    /// The runtime accounting on a full tick folds the deferred-work
    /// request-rate history into the queue.
    #[test]
    fn full_ticks_fold_the_request_rate() {
        fn noop(_: &Dpc, _: usize, _: usize, _: usize) {}
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        let mut queue = DpcQueue::zeroed();
        queue.init(4, 0);

        // Four distinct deferred works (single flight refuses a
        // re-insert), then four full ticks account for them.
        let mut dpcs: Vec<Dpc> = (0..4).map(|_| Dpc::new(noop, 0)).collect();
        let mut irql = IrqlState::new();
        for dpc in dpcs.iter_mut() {
            assert!(queue.insert(dpc, 0, 0, &mut irql));
        }
        assert_eq!(queue.depth(), 4);
        for expected in [2i32, 1, 0, 0] {
            assert_eq!(clock.tick(), Tick::Full);
            clock.account_runtime(&mut queue);
            assert_eq!(queue.request_rate(), expected);
        }
        assert_eq!(queue.depth(), 4, "accounting does not drain the queue");
    }

    /// The clock's deferred work runs per the minimal trigger (every
    /// full tick) — the stand-in for the timer-table walk.
    #[test]
    fn the_deferred_timer_work_runs_every_full_tick() {
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        for i in 0..3 {
            assert_eq!(clock.tick(), Tick::Full);
            assert!(clock.timer_work_due());
            let _ = i;
        }
    }

    /// The captured constants: the interval a real machine of this
    /// family reports, and the finest rate it offers for slewing.
    #[test]
    fn captured_platform_rates() {
        assert_eq!(INTERVAL_100NS, 100_144);
        assert_eq!(FINEST_100NS, 10_032);
        assert_eq!(
            crate::hw::pit::divisor_for_100ns(INTERVAL_100NS),
            crate::hw::pit::INTERVAL_DIVISOR
        );
        assert_eq!(
            crate::hw::pit::divisor_for_100ns(FINEST_100NS),
            1_197,
            "the finest rate's divisor"
        );
    }
}
