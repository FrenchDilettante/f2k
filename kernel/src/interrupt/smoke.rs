//! The `irq-smoke` boot diagnostic: once the interrupt subsystem is up, report the controller's
//! remap and line masks and the interval timer's programming (read back from the chips where they
//! can be), wait for the live tick and for the clock's deferred timer work, and audit the
//! subsystem, all on COM1; then the normal boot proceeds to the default image's exit, so the tick
//! and the process machinery are seen to coexist rather than just the diagnostic running.
//!
//! The tick is default-on kernel machinery; the feature gates only these lines and their bounded
//! waits.

use core::arch::asm;

use crate::hw::pit::{self, Programming};
use crate::hw::portio::Ports;
use crate::interrupt::clock::{self, CLOCK_VECTOR};
use crate::pcr::pcr;
use crate::sched::timer::TimerId;
use crate::serial_println;

/// The ticks the diagnostic waits for before it calls the timer live.
const LIVE_TICKS: u64 = 5;

/// Sleep until the next interrupt: IF on, halt (interrupts are already enabled hardware-wide here;
/// the idle thread's loop keeps its own, model-tracked form). Not `nomem`: the interrupt it waits
/// for writes the state the caller then reads.
fn wait_for_interrupt() {
    // SAFETY: interrupts are enabled (`interrupt::init` let them fly), so `sti` changes nothing the
    // level model tracks and `hlt` returns at the next interrupt.
    unsafe { asm!("sti", "hlt", options(nostack)) };
}

/// Run the diagnostic. Called once, from the boot, right after `interrupt::init`, before any other
/// driver connects a line.
pub fn run() {
    // The controller is the kernel's own; these reads change no state.
    let controller = &super::target::CONTROLLER;
    let (master_base, slave_base) = controller.vector_bases();
    serial_println!(
        "F2K: irq-smoke: PIC remapped (master {:#04x}, slave {:#04x}, IRQ0 {})",
        master_base,
        slave_base,
        if controller.is_unmasked(CLOCK_VECTOR) {
            "unmasked"
        } else {
            "masked"
        }
    );
    let (master_mask, slave_mask) = controller.line_masks();
    serial_println!(
        "F2K: irq-smoke: PIC line masks: master {:#04x}, slave {:#04x}",
        master_mask,
        slave_mask
    );

    let programmed = Programming::decode(pit::MODE2_LO_HIBYTE);
    serial_println!(
        "F2K: irq-smoke: PIT programmed (mode {}, divisor {}, {}.{:04} ms tick)",
        programmed.mode,
        pit::INTERVAL_DIVISOR,
        pit::INTERVAL_100NS / 10_000,
        pit::INTERVAL_100NS % 10_000
    );
    let status = Programming::decode(pit::read_back_status(&mut Ports));
    serial_println!(
        "F2K: irq-smoke: PIT channel 0 read-back: mode {}, {}, {}",
        status.mode,
        status.access_name(),
        if status.bcd { "BCD" } else { "binary" }
    );

    // Bounded by the tick itself: each `sti; hlt` sleeps until the next interrupt, so progress here
    // means the timer is live (and arrives on the remapped vector: IRQ 0 on the BIOS's 0x08 would
    // be a double fault).
    while clock::ticks() < LIVE_TICKS {
        wait_for_interrupt();
    }
    serial_println!(
        "F2K: irq-smoke: timer live (>= {} ticks observed)",
        LIVE_TICKS
    );

    // The deferred timer work runs only when a timer is due (the table's hand check), so arm one:
    // a notification timer of the diagnostic's own, due one tick out. Its expiry, the DPC's walk,
    // signals it — nobody waits on it, and the signal is the observable.
    let timer = crate::ob::locked(|directory| directory.create_timer(true))
        .expect("the boot's timer pool has room");
    crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        // Read and armed masked: no tick moves the clock between the two.
        let _masked = pcr().mask_guard();
        let now = clock::read_at(dispatch, clock::Clock::interrupt_time);
        crate::sched::DISPATCHER.get(dispatch).set_waitable_timer(
            TimerId::Waitable(timer.index),
            now + pit::INTERVAL_100NS as u64,
            now,
            0,
            false,
            0,
        );
    });
    // The expiry writes the signal state at the dispatch level, from the clock's DPC; each read
    // raises to the dispatcher's level after the halt.
    let signaled = || {
        crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
            crate::sched::DISPATCHER
                .get(dispatch)
                .timer(TimerId::Waitable(timer.index))
                .waitable
                .signal_state()
                > 0
        })
    };
    while !signaled() {
        wait_for_interrupt();
    }
    serial_println!("F2K: irq-smoke: clock DPC fired");
    // The timer goes with its creator's reference: no process holds it, and nothing outlives the
    // diagnostic.
    crate::ob::release(timer);

    match super::audit() {
        Ok(()) => {
            serial_println!("F2K: irq-smoke: interrupt audit: ok");
        }
        Err(why) => {
            serial_println!("F2K: irq-smoke: interrupt audit: FAILED ({})", why);
        }
    }
}
