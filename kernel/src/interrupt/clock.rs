//! The interval clock: tick math and the clock's deferred work.
//!
//! The 8254 channel 0 raises the timer interrupt at the programmed rate; this module owns
//! everything after that. The interrupt adds the time increment to interrupt time; a fractional
//! accumulator (fed by the same increment and refilled by the maximum) decides whether the
//! interrupt was a full tick — only a full tick advances system time, the tick count, and the
//! running thread's quantum. System time moves by the adjustable time-slew value, the tick count
//! does not.
//!
//! The rate lives entirely in the four variables set by [`Clock::set_time_increment`]; the tick
//! math itself is rate-agnostic. On a full tick the clock checks the timer table's hand pair (the
//! buckets of ticks N-1 and N) against the advanced interrupt time and, when a timer is due,
//! enqueues its deferred expiry work with the firing tick's low word — the same single-flight
//! discipline every DPC enqueue uses. The runtime accounting folds the DPC request-rate history.

#[cfg(target_arch = "x86")]
use crate::interrupt::dpc;
use crate::interrupt::dpc::Dpc;
#[cfg(target_arch = "x86")]
use crate::level::{self, Above, At, Dispatch, Level, LevelCell};
#[cfg(target_arch = "x86")]
use crate::pcr::pcr;

/// The interval in 100 ns units a real machine of this platform family reports as its default time
/// increment (10.0144 ms).
pub const INTERVAL_100NS: u32 = 100_144;

/// The finest rate the same machine offers for slewing (1.0032 ms).
pub const FINEST_100NS: u32 = 10_032;

/// What one interrupt did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tick {
    /// A fractional interrupt: interrupt time advanced, but this was not a full tick — system
    /// time, the tick count, and the runtime accounting are skipped.
    Fractional,
    /// A full tick: the accumulator refilled, system time slewed, the tick count advanced.
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
    /// The fractional accumulator. Positive after an interrupt that was not a full tick.
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
    /// A zeroed clock; call [`Clock::set_time_increment`] before first use.
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

    /// The clock's rate contract, in 100 ns units: the maximum is the interval every interrupt
    /// adds; the minimum (the finest rate offered) has a hard floor of 1 ms. The increment, the
    /// slew value, and the fractional accumulator all start at the maximum.
    pub fn set_time_increment(&mut self, maximum: u32, minimum: u32) {
        self.maximum_increment = maximum;
        self.minimum_increment = if minimum > 10_000 { minimum } else { 10_000 };
        self.time_adjustment = maximum;
        self.time_increment = maximum;
        self.tick_offset = maximum as i32;
    }

    /// Run the clock's source `per_tick` times per platform tick: every interrupt advances
    /// interrupt time by a `per_tick`th of the maximum, so ticks, system time, and quanta keep
    /// the platform rate. `per_tick` must divide the maximum evenly, or the tick drifts.
    pub fn set_source_per_tick(&mut self, per_tick: u32) {
        self.time_increment = self.maximum_increment / per_tick;
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

    /// The wait discipline's reading: interrupt time, the clock every due is on, and the tick
    /// count.
    pub fn stamp(&self) -> crate::sched::wait::ClockStamp {
        crate::sched::wait::ClockStamp {
            interrupt_time: self.interrupt_time,
            tick: self.tick_count,
        }
    }

    /// One interval interrupt: advance interrupt time, decide whether this was a full tick, and
    /// (only then) advance system time and the tick count. The rate lives in the set-time
    /// variables; nothing here knows the hardware.
    pub fn tick(&mut self) -> Tick {
        self.interrupt_time += self.time_increment as u64;
        self.tick_offset -= self.time_increment as i32;

        let tick_low;
        if self.tick_offset > 0 {
            // Fractional: system time, the tick count, and runtime accounting are skipped.
            tick_low = self.tick_count as u32;
        } else {
            // System time slews by the adjustment, not the raw increment — the addend is
            // adjustable.
            self.system_time += self.time_adjustment as u64;
            self.tick_count += 1;
            tick_low = self.tick_count as u32;
        }
        self.tick_low = tick_low;

        if self.tick_offset > 0 {
            self.interrupt_count = self.interrupt_count.wrapping_add(1);
            return Tick::Fractional;
        }

        // A full tick refills the accumulator.
        self.tick_offset += self.maximum_increment as i32;
        self.interrupt_count = self.interrupt_count.wrapping_add(1);
        Tick::Full
    }
}

/// The deferred timer routine: the clock's DPC callback — the timer table's expiry walk. The
/// argument is the firing tick's low word (the trigger's), and the walk scans the table from that
/// tick's bucket through the current one, waking every thread whose timeout came due.
#[cfg(target_arch = "x86")]
fn timer_routine(
    dispatch: &mut At<Dispatch>,
    _dpc: &Dpc,
    _context: usize,
    argument1: usize,
    _argument2: usize,
) {
    // The readings in one read at the clock level, raised from the routine's own level. The system
    // time is the pass's signal time, what the expired timers' APCs are given.
    let (now, tick, system_time) = read_at(dispatch, |clock| {
        (
            clock.interrupt_time(),
            clock.tick_count() as u32,
            clock.system_time(),
        )
    });
    let signal_time = crate::time::boot_filetime() + system_time;
    crate::sched::DISPATCHER
        .get(dispatch)
        .expire_timers(now, tick, argument1 as u32, signal_time);
}

// --- Target wiring: the kernel clock --------------------------------------

/// The kernel's clock: clock-level state, advanced by the clock interrupt and read by raising to
/// its level.
#[cfg(target_arch = "x86")]
static CLOCK: LevelCell<level::Clock, Clock> = LevelCell::new(Clock::new());

/// The deferred timer work: enqueued by the clock's interrupt on a full tick, drained at the
/// dispatch level. Single-flight like every DPC: a tick that finds it already queued skips the
/// enqueue.
#[cfg(target_arch = "x86")]
static TIMER_DPC: Dpc = Dpc::new(timer_routine, 0);

/// How often the balance-set scan runs, in full ticks: about a second.
pub const BALANCE_PERIOD_TICKS: u32 = 100;

/// The balance-set scan's deferred work (see
/// [`crate::sched::dispatcher::Dispatcher::scan_ready_queues`]): the platform runs it in its
/// balance-set manager thread, woken once a second; here the clock enqueues it once a second.
#[cfg(target_arch = "x86")]
static BALANCE_DPC: Dpc = Dpc::new(balance_routine, 0);

#[cfg(target_arch = "x86")]
fn balance_routine(
    dispatch: &mut At<Dispatch>,
    _dpc: &Dpc,
    _context: usize,
    _argument1: usize,
    _argument2: usize,
) {
    crate::sched::DISPATCHER.get(dispatch).scan_ready_queues();
}

/// The vector the timer interrupt arrives on (IRQ 0 after the remap).
pub const CLOCK_VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE;

/// The clock's interrupt service body, handed the clock-level token by the interrupt dispatch once
/// the interrupt has been claimed (interrupts masked). Updates the clock and enqueues the deferred
/// timer work when a timer is due — the timer table's hand check, with the firing tick's low word
/// as the argument the walk resumes from.
#[cfg(target_arch = "x86")]
pub fn service(at_clock: &mut At<level::Clock>) {
    // The clock's own update, inside its cell's borrow. Everything after works from the readings,
    // with the borrow over and the token free for the raises below.
    let clock = CLOCK.get(at_clock);
    let tick = clock.tick();
    let interrupt_time = clock.interrupt_time();
    let full = matches!(tick, Tick::Full).then(|| (clock.system_time(), clock.tick_count()));
    crate::user::shared::update(at_clock, interrupt_time, full);
    let Some((_, tick_count)) = full else {
        return;
    };
    let tick_low = tick_count as u32;
    // The dispatcher is dispatch-level state, which this interrupt never reaches: what it needs of
    // the scheduler is published for it. The hand check at the transition to tick N: the buckets
    // of ticks N-1 and N against the just-advanced interrupt time, through the dues the timer
    // table publishes (the unlocked bucket-head read Windows 2000's clock interrupt makes too). A
    // due head fires the deferred work, single-flight like every enqueue, carrying the firing
    // tick's low word.
    if let Some(argument) = crate::sched::timer::hand_due(at_clock, interrupt_time, tick_low) {
        dpc::enqueue_at(at_clock, &TIMER_DPC, argument as usize, 0);
    }
    // The runtime accounting: fold the deferred-work request-rate history.
    pcr().dpc_queue.with(
        &mut at_clock.raise::<level::High>(),
        dpc::DpcQueue::update_request_rate,
    );
    // A full tick charges the running thread's quantum, in the processor's slots; a charge that
    // runs the quantum out requests the dispatch window's decision at this interrupt's exit.
    pcr().threads.charge_running_tick(at_clock);
    // Once a second, the balance-set scan.
    if tick_low % BALANCE_PERIOD_TICKS == 0 {
        dpc::enqueue_at(at_clock, &BALANCE_DPC, 0, 0);
    }
}

/// Point the kernel clock at the captured platform rate (10.0144 ms per interrupt; 1.0032 ms the
/// finest offered). Boot calls it, before the first tick.
#[cfg(target_arch = "x86")]
pub fn init() {
    level::raised::<level::Clock, _>(|at_clock| {
        CLOCK
            .get(at_clock)
            .set_time_increment(INTERVAL_100NS, FINEST_100NS)
    });
}

/// Run the kernel clock's source `per_tick` times per platform tick (the perf trace's sampling
/// rate; see [`Clock::set_source_per_tick`]). Boot calls it, before the first tick.
#[cfg(target_arch = "x86")]
pub fn set_source_per_tick(per_tick: u32) {
    level::raised::<level::Clock, _>(|at_clock| CLOCK.get(at_clock).set_source_per_tick(per_tick));
}

/// Read the kernel clock from code that holds a level token below the clock's: raised to the clock
/// level for the read. The 64-bit fields are two loads on this processor; a tick taken in the gap
/// — precisely when the low word carries — would hand back a value about 429 s off.
#[cfg(target_arch = "x86")]
pub fn read_at<L: Level, T>(at: &mut At<L>, read: impl FnOnce(&Clock) -> T) -> T
where
    level::Clock: Above<L>,
{
    read(CLOCK.get(&mut at.raise::<level::Clock>()))
}

/// Read the kernel clock at the clock level itself.
#[cfg(all(target_arch = "x86", feature = "perf-trace"))]
pub fn read_in<T>(at_clock: &mut At<level::Clock>, read: impl FnOnce(&Clock) -> T) -> T {
    read(CLOCK.get(at_clock))
}

/// Read the kernel clock from code that holds no level token yet: [`read_at`], through the bridge
/// to the clock level.
#[cfg(target_arch = "x86")]
fn read_clock<T>(read: impl FnOnce(&Clock) -> T) -> T {
    level::raised::<level::Clock, _>(|at_clock| read(CLOCK.get(at_clock)))
}

/// The kernel clock's tick count (diagnostic and smoke reads).
#[cfg(target_arch = "x86")]
pub fn ticks() -> u64 {
    read_clock(Clock::tick_count)
}

/// The kernel clock's system time (100 ns units): the wall clock's, less the boot's reading.
#[cfg(target_arch = "x86")]
pub fn system_time() -> u64 {
    read_clock(Clock::system_time)
}

/// The kernel clock's interrupt time (100 ns units): the time base the timer table's expiry checks
/// read.
#[cfg(target_arch = "x86")]
pub fn interrupt_time() -> u64 {
    read_clock(Clock::interrupt_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One clock for every due: a wait's stamp reads interrupt time, the clock the timer
    /// table expires against, so a slewed system time moves no wait's deadline.
    #[test]
    fn a_wait_expires_on_interrupt_time_whatever_the_slew() {
        use crate::sched::process::SchedProcess;
        use crate::sched::thread::ThreadState;
        use crate::sched::wait::{WaitDisposition, WaitMode};

        let d = crate::sched::testkit::dispatcher();
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let t = crate::sched::testkit::thread(p);

        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        clock.time_adjustment = INTERVAL_100NS / 2; // system time slewed to half speed
        for _ in 0..10 {
            clock.tick();
        }
        assert_eq!(clock.stamp().interrupt_time, clock.interrupt_time());
        assert_eq!(clock.stamp().tick, 10);
        assert_ne!(
            clock.system_time(),
            clock.interrupt_time(),
            "the slew shows"
        );
        let interval = 3 * INTERVAL_100NS as i64;
        assert_eq!(
            d.delay(t, WaitMode::User, false, interval, clock.stamp()),
            WaitDisposition::Yield
        );
        for n in 1..=3 {
            clock.tick();
            let tick = clock.tick_count() as u32;
            d.expire_timers(clock.interrupt_time(), tick, tick - 1, 0);
            assert_eq!(
                t.state() == ThreadState::Ready,
                n == 3,
                "woken at the third tick, not before"
            );
        }
    }

    /// The rate contract: the maximum stands as increment, slew value, and accumulator start; the
    /// minimum has a 1 ms floor.
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

    /// With the increment equal to the maximum (the captured platform rate), every interrupt is a
    /// full tick: N interrupts produce exactly N ticks and interrupt time advances N increments.
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

    /// A half-rate source (the increment is half the maximum): the fractional accumulator decides —
    /// every second interrupt is a full tick, using integer math only.
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

    /// A source run per-tick by `set_source_per_tick` keeps the platform tick: full ticks arrive
    /// every `per_tick` interrupts, and N of them are N maxima of interrupt time.
    #[test]
    fn a_per_tick_source_keeps_the_platform_tick() {
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        clock.set_source_per_tick(4);

        for _ in 0..3 {
            assert_eq!(clock.tick(), Tick::Fractional);
        }
        assert_eq!(clock.tick(), Tick::Full);
        assert_eq!(clock.tick_count(), 1);
        assert_eq!(clock.interrupt_time(), INTERVAL_100NS as u64);

        for _ in 0..3 {
            assert_eq!(clock.tick(), Tick::Fractional);
        }
        assert_eq!(clock.tick(), Tick::Full);
        assert_eq!(clock.tick_count(), 2);
        assert_eq!(clock.interrupt_time(), 2 * INTERVAL_100NS as u64);
        assert_eq!(clock.interrupt_count(), 8);
    }

    /// System time slews by the adjustment while the tick count counts ticks: halving the
    /// adjustment leaves tick accounting untouched.
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

    /// There is no catch-up: lost ticks stay lost — each interrupt counts once, and the counters
    /// never read the device back.
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

    /// The runtime accounting on a full tick folds the deferred-work request-rate history into the
    /// queue.
    #[test]
    fn full_ticks_fold_the_request_rate() {
        use crate::interrupt::dpc::DpcQueue;
        use crate::level::{At, Dispatch};

        fn noop(_: &mut At<Dispatch>, _: &Dpc, _: usize, _: usize, _: usize) {}
        let mut clock = Clock::new();
        clock.set_time_increment(INTERVAL_100NS, FINEST_100NS);
        let mut queue = DpcQueue::new(4, 0);

        // Four distinct deferred works (single flight refuses a re-insert), then four full ticks
        // account for them, as the service does on each.
        for _ in 0..4 {
            assert!(queue.insert(Box::leak(Box::new(Dpc::new(noop, 0))), 0, 0));
        }
        assert_eq!(queue.depth(), 4);
        for expected in [2i32, 1, 0, 0] {
            assert_eq!(clock.tick(), Tick::Full);
            queue.update_request_rate();
            assert_eq!(queue.request_rate(), expected);
        }
        assert_eq!(queue.depth(), 4, "accounting does not drain the queue");
    }

    /// The captured constants: the interval a real machine of this family reports, and the finest
    /// rate it offers for slewing.
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

    /// The full-tick arm is the only charge site: a fractional interrupt advances the time but
    /// leaves the running thread's quantum alone; the full tick that follows charges it.
    #[test]
    fn only_a_full_tick_charges_the_quantum() {
        use crate::sched::process::SchedProcess;
        use crate::sched::thread::ThreadState;

        let d = crate::sched::testkit::dispatcher();
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let mut t = crate::sched::testkit::thread(p);
        t.state = ThreadState::Running;
        d.enter(t.id());

        let mut clock = Clock::new();
        clock.set_time_increment(100_000, 10_000);
        clock.time_increment = 50_000; // a source twice as fast

        // The service's composition: the charge runs inside the full-tick arm and nowhere else.
        assert_eq!(clock.tick(), Tick::Fractional);
        assert_eq!(
            t.quantum(),
            crate::sched::QUANTUM_RESET,
            "a fractional tick charges nothing"
        );
        assert_eq!(clock.tick(), Tick::Full);
        crate::level::raised::<crate::level::Clock, _>(|at_clock| {
            crate::pcr::pcr().threads.charge_running_tick(at_clock)
        });
        assert_eq!(
            t.quantum(),
            crate::sched::QUANTUM_RESET - crate::sched::QUANTUM_TICK,
            "one full tick charges once"
        );
    }
}
