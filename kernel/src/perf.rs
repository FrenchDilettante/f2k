//! The opt-in performance trace (`perf-trace`): every interval interrupt samples the
//! interrupted context and its frame-pointer call stack into a static ring buffer, and the
//! boot's end dumps the samples on COM1, before the line the test harness stops the boot on.
//!
//! The stack walk is the `[ebp]`/`[ebp+4]` frame-pointer chain, validated at every step so it
//! cannot read a page it does not know to be mapped: kernel frames stay in the kernel window
//! with return addresses in the kernel image; user frames and their return addresses must lie in
//! regions the current process records. The walk needs frame pointers, so the perf build forces
//! them (the Makefile passes the flag); the hand-written entry stubs keep no chain, so a stack
//! starts at the first Rust frame below them.
//!
//! Nothing here compiles without the feature.

#[cfg(target_arch = "x86")]
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

#[cfg(target_arch = "x86")]
use crate::level::{self, Clock, LevelCell};

/// Samples the ring buffer keeps (~10 s of platform ticks at the default rate; a longer boot
/// keeps the most recent ones).
pub const CAPACITY: usize = 1024;

/// How deep one sample's stack walk goes; deeper stacks are truncated, never dropped.
pub const MAX_STACK: usize = 24;

/// Samples per platform tick: the interval timer and the clock run this many times per tick, and
/// every interrupt is a sample. 1, 2, 4, 8, or 16 — the rate must divide the platform interval
/// evenly, or the tick drifts. Above 1 the faster source lets a wait armed mid-tick quantize one
/// tick longer, so the tick-exact pins (the sleep smoke's) hold only at 1: this is a diagnostic
/// build, verify at the default.
pub const SAMPLES_PER_TICK: u32 = 1;

// The rate is a tunable: at its default of 1 the remainder is trivially zero.
#[cfg(target_arch = "x86")]
#[allow(clippy::modulo_one)]
const _: () = assert!(
    crate::interrupt::clock::INTERVAL_100NS % SAMPLES_PER_TICK == 0 && SAMPLES_PER_TICK <= 16,
    "SAMPLES_PER_TICK must be 1, 2, 4, 8, or 16"
);

/// One recorded sample: the interrupted context and its call stack at one tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sample {
    /// The sample's interrupt time, 100 ns units.
    pub interrupt_time: u64,
    /// The interrupted code segment (its RPL says which ring was running).
    pub cs: u32,
    /// The call stack, leaf first: `[0]` is the interrupted instruction pointer, the rest the
    /// walk's return addresses, nearest caller first. `[depth..]` is not valid.
    pub frames: [u32; MAX_STACK],
    /// How many of `frames` are valid.
    pub depth: usize,
}

impl Sample {
    /// A zeroed sample (the buffer's filler).
    pub const ZERO: Self = Self {
        interrupt_time: 0,
        cs: 0,
        frames: [0; MAX_STACK],
        depth: 0,
    };
}

/// The trace: a ring buffer of samples and the totals for its header.
pub struct Trace {
    samples: [Sample; CAPACITY],
    /// Where the next sample lands.
    next: usize,
    /// Samples taken (wrapping past the capacity: the oldest were dropped).
    taken: u64,
}

impl Trace {
    /// An empty trace.
    pub const fn new() -> Self {
        Self {
            samples: [Sample::ZERO; CAPACITY],
            next: 0,
            taken: 0,
        }
    }

    /// Record one sample, wrapping past the capacity (the oldest sample is dropped).
    pub fn record(&mut self, sample: Sample) {
        self.samples[self.next] = sample;
        self.next = (self.next + 1) % CAPACITY;
        self.taken = self.taken.wrapping_add(1);
    }

    /// Samples taken; more than the capacity means the oldest are gone.
    pub fn taken(&self) -> u64 {
        self.taken
    }

    /// How many samples it keeps: those taken, up to the capacity.
    pub fn kept_len(&self) -> usize {
        self.taken.min(CAPACITY as u64) as usize
    }

    /// The kept sample at `index`, oldest first; none past the kept ones.
    pub fn kept_sample(&self, index: usize) -> Option<Sample> {
        let kept = self.kept_len();
        let start = (self.next + CAPACITY - kept) % CAPACITY;
        (index < kept).then(|| self.samples[(start + index) % CAPACITY])
    }

    /// The kept samples, oldest first.
    #[cfg(test)]
    pub fn kept(&self) -> impl Iterator<Item = Sample> + '_ {
        (0..self.kept_len()).map_while(|index| self.kept_sample(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(time: u64, depth: usize) -> Sample {
        let mut frames = [0u32; MAX_STACK];
        for (at, frame) in frames.iter_mut().enumerate().take(depth) {
            *frame = time as u32 + at as u32;
        }
        Sample {
            interrupt_time: time,
            cs: 0x08,
            frames,
            depth,
        }
    }

    /// A trace wrapped past its start keeps the most recent samples, whole.
    #[test]
    fn a_wrapped_trace_keeps_the_most_recent_samples() {
        let mut trace = Trace::new();
        for time in 0..(CAPACITY + 10) as u64 {
            trace.record(sample(time, 3));
        }
        assert_eq!(trace.taken(), (CAPACITY + 10) as u64);
        let kept: Vec<Sample> = trace.kept().collect();
        assert_eq!(kept.len(), CAPACITY);
        assert_eq!(kept[0].interrupt_time, 10);
        assert_eq!(kept[CAPACITY - 1].interrupt_time, (CAPACITY + 9) as u64);
        assert!(kept.iter().all(|s| s.depth == 3));
        assert_eq!(kept[0].frames[2], 12);
    }

    /// An unwrapped trace returns exactly what was recorded, in order.
    #[test]
    fn an_unwrapped_trace_returns_every_sample_in_order() {
        let mut trace = Trace::new();
        for time in 0..100u64 {
            trace.record(sample(time, 1));
        }
        assert_eq!(trace.taken(), 100);
        assert_eq!(
            trace.kept().map(|s| s.interrupt_time).collect::<Vec<_>>(),
            (0..100).collect::<Vec<_>>()
        );
    }
}

// --- Target wiring ----------------------------------------------------------

/// The kernel's trace: clock-level state, filled by the clock interrupt's sample and copied out a
/// sample at a time by the teardown's dump.
#[cfg(target_arch = "x86")]
static TRACE: LevelCell<Clock, Trace> = LevelCell::new(Trace::new());

/// Whether the trace has stopped: [`report`] sets it before reading the samples, and [`sample`]
/// records nothing from then on, so the ring holds still while the dump copies it out.
#[cfg(target_arch = "x86")]
static STOPPED: AtomicBool = AtomicBool::new(false);

/// The sampling interval in 100 ns units: the platform tick divided by [`SAMPLES_PER_TICK`].
#[cfg(target_arch = "x86")]
const SAMPLE_INTERVAL: u32 = crate::interrupt::clock::INTERVAL_100NS / SAMPLES_PER_TICK;

/// The end of the kernel image window, mapped in every address space: the kernel stacks the image
/// holds (the boot stack's among them) live inside it.
#[cfg(target_arch = "x86")]
const WINDOW_END: u32 = crate::mem::layout::KERNEL_IMAGE.end() as u32;

// The kernel image's bounds, exported by the linker script.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
}

/// The kernel image's addresses, from the linker script's bounds: where a kernel return address
/// must point.
#[cfg(target_arch = "x86")]
fn kernel_text() -> core::ops::Range<u32> {
    // Only the symbols' addresses are taken, never their contents.
    (&raw const _kernel_start as u32)..(&raw const _kernel_end as u32)
}

/// Set the sampling rate ([`SAMPLES_PER_TICK`]): reprogram the interval timer and the clock's
/// source. Called from the interrupt init, before interrupts fly.
#[cfg(target_arch = "x86")]
pub fn init() {
    if SAMPLES_PER_TICK == 1 {
        return;
    }
    let mut ports = crate::hw::portio::Ports;
    crate::hw::pit::program_interval(
        &mut ports,
        crate::hw::pit::divisor_for_100ns(SAMPLE_INTERVAL),
    );
    crate::interrupt::clock::set_source_per_tick(SAMPLES_PER_TICK);
}

/// Record one sample: the interrupted context of the clock interrupt, with its call stack. Once
/// the trace has stopped (see [`report`]), nothing.
///
/// The interrupt dispatch calls it before the claim, interrupts masked and the ledger told so for
/// the sample's length: the clock read and the record each raise to the clock level through the
/// bridge, and each lower puts the masked state back rather than enabling interrupts inside the
/// interrupt.
#[cfg(target_arch = "x86")]
pub fn sample(frame: &crate::cpu::idt::ExceptionFrame) {
    if STOPPED.load(Ordering::Relaxed) {
        return;
    }
    let (eip, cs) = frame.interrupted_pc();
    let mut frames = [0u32; MAX_STACK];
    frames[0] = eip;
    let depth = walk(frame.interrupted_ebp(), cs, &mut frames);
    // Before the interrupt's claim: the raise's lower runs nothing on its way down (the interrupt's
    // exit does).
    level::raised_in_entry::<Clock, _>(|at_clock| {
        let sample = Sample {
            interrupt_time: crate::interrupt::clock::read_in(
                at_clock,
                crate::interrupt::clock::Clock::interrupt_time,
            ),
            cs,
            frames,
            depth,
        };
        TRACE.get(at_clock).record(sample)
    });
}

/// Walk the frame-pointer chain from `ebp`, filling `frames[1..]` with the callers' return
/// addresses (nearest first) and returning the sample's depth. A chain that fails a validation
/// ends the walk where it stands.
///
/// Every read is validated to lie in mapped memory first: kernel-window addresses by construction
/// (the window is mapped in every address space), user addresses by the live page tables.
#[cfg(target_arch = "x86")]
fn walk(mut ebp: u32, cs: u32, frames: &mut [u32; MAX_STACK]) -> usize {
    let ring3 = cs & 3 == 3;
    let kernel_text = kernel_text();
    let mut depth = 1;
    while depth < MAX_STACK {
        if ebp & 3 != 0 {
            break; // a frame pointer is word-aligned
        }
        if ring3 {
            if !user_mapped(ebp) || !user_mapped(ebp.wrapping_add(4)) {
                break;
            }
        } else if !(crate::mem::paging::KERNEL_BASE..=WINDOW_END - 8).contains(&ebp) {
            break; // both of the frame's words must lie in the window
        }
        let frame = ebp as *const u32;
        // SAFETY: `ebp` is word-aligned and was just validated: in ring 3 both of the frame's
        // words lie in regions of the current process, whose page tables match its records; in
        // ring 0 both lie in the kernel image window, mapped in every address space. The
        // read is volatile: the word is another context's stack, not memory this code owns.
        let next = unsafe { frame.read_volatile() };
        // SAFETY: as above, for the frame's second word.
        let ret = unsafe { frame.add(1).read_volatile() };
        // The return address must name code the ring can run, and the chain must rise (stacks
        // grow down); a chain that does not rise is garbage, not a stack.
        let ok = if ring3 {
            user_mapped(ret) && next > ebp && next < crate::mem::paging::KERNEL_BASE
        } else {
            kernel_text.contains(&ret) && next > ebp && next < WINDOW_END
        };
        if !ok {
            break;
        }
        frames[depth] = ret;
        depth += 1;
        ebp = next;
    }
    depth
}

/// Whether `address` is a user address whose page is present in the live page tables: what the
/// walk may read inside the clock interrupt, where the address space's records (behind their
/// lock) are out of reach.
#[cfg(target_arch = "x86")]
fn user_mapped(address: u32) -> bool {
    use crate::mem::paging::{KERNEL_BASE, PAGE_PRESENT, PAGE_SIZE};
    use crate::mem::vm::{CurrentPages, Pages};
    address < KERNEL_BASE && CurrentPages.entry(address & !(PAGE_SIZE - 1)) & PAGE_PRESENT != 0
}

/// Stop the trace and dump it on COM1: the header and one line per kept sample. Runs on the idle
/// thread, before the teardown audit line (the single-process boot) or the suite's summary line —
/// the line the harness stops the boot on. The trace stays stopped: the dump is the boot's last.
///
/// Each sample is copied out at the clock level and printed below it, so the clock keeps ticking
/// through the dump's long write; the stop keeps the ring still between the copies.
#[cfg(target_arch = "x86")]
pub fn report() {
    STOPPED.store(true, Ordering::Relaxed);
    // The ring's reads below must not move above the stop: the clock interrupt is the other side.
    compiler_fence(Ordering::SeqCst);
    let (taken, kept) = level::raised::<Clock, _>(|at_clock| {
        let trace = TRACE.get(at_clock);
        (trace.taken(), trace.kept_len())
    });
    crate::serial_println!(
        "F2K: perf trace: {} samples taken, {} kept (the sample interval is {} 100ns units)",
        taken,
        kept,
        SAMPLE_INTERVAL
    );
    let copied = (0..kept)
        .map_while(|index| level::raised::<Clock, _>(|at| TRACE.get(at).kept_sample(index)));
    for sample in copied {
        if sample.depth > 1 {
            // The callers follow on the same line, nearest first.
            crate::serial_print!(
                "F2K: perf sample: t={} cs={:#04x} eip={:#010x} stack=",
                sample.interrupt_time,
                sample.cs,
                sample.frames[0]
            );
            for (at, frame) in sample.frames[1..sample.depth].iter().enumerate() {
                crate::serial_print!("{}{:#010x}", if at == 0 { "" } else { "," }, frame);
            }
            crate::hw::serial::write_byte_blocking(b'\n');
        } else {
            crate::serial_println!(
                "F2K: perf sample: t={} cs={:#04x} eip={:#010x}",
                sample.interrupt_time,
                sample.cs,
                sample.frames[0]
            );
        }
    }
}
