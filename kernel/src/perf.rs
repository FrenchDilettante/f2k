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

#[cfg(target_arch = "x86")]
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

    /// The kept samples, oldest first.
    pub fn kept(&self) -> impl Iterator<Item = Sample> + '_ {
        let kept = (self.taken.min(CAPACITY as u64)) as usize;
        let start = (self.next + CAPACITY - kept) % CAPACITY;
        (0..kept).map(move |i| self.samples[(start + i) % CAPACITY])
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

/// The kernel's trace, filled by the clock interrupt and drained by the teardown's dump.
#[cfg(target_arch = "x86")]
static mut TRACE: Trace = Trace::new();

/// The sampling interval in 100 ns units (the platform tick by default, its `per_tick`th under
/// `perf-rate`; [init] writes it).
#[cfg(target_arch = "x86")]
static mut SAMPLE_INTERVAL: u32 = crate::interrupt::clock::INTERVAL_100NS;

/// The end of the kernel window: every kernel stack lives inside it.
#[cfg(target_arch = "x86")]
const WINDOW_END: u32 = crate::mem::paging::KERNEL_BASE + 8 * 1024 * 1024;

// The kernel image's bounds, exported by the linker script.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
}

/// Set the sampling rate ([`SAMPLES_PER_TICK`]): reprogram the interval timer and the clock's
/// source. Called from the interrupt init, before interrupts fly.
#[cfg(target_arch = "x86")]
pub fn init() {
    if SAMPLES_PER_TICK == 1 {
        return;
    }
    let interval = crate::interrupt::clock::INTERVAL_100NS / SAMPLES_PER_TICK;
    // SAFETY: boot CPU, interrupts disabled (the interrupt init calls this before they fly);
    // the timer and the clock are programmed here, sole access.
    unsafe {
        let mut ports = crate::hw::portio::Ports;
        crate::hw::pit::program_interval(&mut ports, crate::hw::pit::divisor_for_100ns(interval));
        crate::interrupt::clock::set_source_per_tick(SAMPLES_PER_TICK);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SAMPLE_INTERVAL), interval);
    }
}

/// Record one sample: the interrupted context of the clock interrupt, with its call stack.
#[cfg(target_arch = "x86")]
pub fn sample(frame: &crate::cpu::idt::ExceptionFrame) {
    // SAFETY: single CPU; the trace's only writers run at the clock level, serialized by it.
    unsafe {
        let (eip, cs) = frame.interrupted_pc();
        let mut frames = [0u32; MAX_STACK];
        frames[0] = eip;
        let depth = walk(frame.interrupted_ebp(), cs, &mut frames);
        (*core::ptr::addr_of_mut!(TRACE)).record(Sample {
            interrupt_time: crate::interrupt::clock::interrupt_time(),
            cs,
            frames,
            depth,
        });
    }
}

/// Walk the frame-pointer chain from `ebp`, filling `frames[1..]` with the callers' return
/// addresses (nearest first) and returning the sample's depth. A chain that fails a validation
/// ends the walk where it stands.
///
/// # Safety
///
/// Every read is validated to lie in mapped memory first: kernel-window addresses by
/// construction, user addresses by the current process's region records, which match its page
/// tables.
#[cfg(target_arch = "x86")]
unsafe fn walk(mut ebp: u32, cs: u32, frames: &mut [u32; MAX_STACK]) -> usize {
    let ring3 = cs & 3 == 3;
    let kernel_text =
        unsafe { (&_kernel_start as *const u8 as u32)..(&_kernel_end as *const u8 as u32) };
    let mut depth = 1;
    while depth < MAX_STACK {
        if ebp & 3 != 0 {
            break; // a frame pointer is word-aligned
        }
        if ring3 {
            if !user_mapped(ebp) || !user_mapped(ebp.wrapping_add(4)) {
                break;
            }
        } else if ebp < crate::mem::paging::KERNEL_BASE || ebp >= WINDOW_END {
            break;
        }
        // SAFETY: the frame pointer was just validated to lie in mapped memory.
        let (next, ret) = unsafe {
            (
                (ebp as *const u32).read_volatile(),
                (ebp as *const u32).add(1).read_volatile(),
            )
        };
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

/// Whether the current process's address space records a region containing `address`.
#[cfg(target_arch = "x86")]
fn user_mapped(address: u32) -> bool {
    crate::process::pool::current_mut()
        .vm()
        .region_at(address)
        .is_some()
}

/// Dump the trace on COM1: the header and one line per kept sample. Runs on the idle thread,
/// before the teardown audit line (the single-process boot) or the suite's summary line — the
/// line the harness stops the boot on.
#[cfg(target_arch = "x86")]
pub fn report() {
    // SAFETY: single CPU; the boot is over for user code, and a tick during the dump only
    // advances the ring's cursor, never the kept samples' order.
    let trace = unsafe { &*core::ptr::addr_of!(TRACE) };
    let taken = trace.taken();
    let kept = trace.kept().count() as u64;
    let interval = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SAMPLE_INTERVAL)) };
    crate::serial_println!(
        "F2K: perf trace: {} samples taken, {} kept (the sample interval is {} 100ns units)",
        taken,
        kept,
        interval
    );
    for sample in trace.kept() {
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
