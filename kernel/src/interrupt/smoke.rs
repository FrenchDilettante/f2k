//! The `irq-smoke` boot diagnostic: once the interrupt subsystem is up, report the controller's
//! remap and line masks and the interval timer's programming (read back from the chips where they
//! can be), wait for the live tick and for the clock's deferred timer work, and audit the
//! subsystem, all on COM1; then the normal boot proceeds to the default image's exit, so the tick
//! and the process machinery are seen to coexist rather than just the diagnostic running.
//!
//! The tick is default-on kernel machinery; the feature gates only these lines and their bounded
//! waits.

use core::arch::asm;
use core::ptr::addr_of_mut;

use crate::hw::pit::{self, Programming};
use crate::hw::portio::Ports;
use crate::interrupt::clock::{self, CLOCK_VECTOR};
use crate::interrupt::irql;
use crate::sched::waitable_timer::WaitableTimer;
use crate::serial_println;

/// The ticks the diagnostic waits for before it calls the timer live.
const LIVE_TICKS: u64 = 5;

/// The diagnostic's timer: the clock's deferred work signals it.
static mut TIMER: WaitableTimer = WaitableTimer::new(true);

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
    // SAFETY: single CPU; the controller is the kernel's own, and these reads change no state.
    let controller = unsafe { &mut *addr_of_mut!(super::target::CONTROLLER) };
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
    let timer = addr_of_mut!(TIMER);
    let previous = irql::state_mut().raise(irql::DISPATCH);
    let now = clock::interrupt_time();
    // SAFETY: single CPU, at the dispatch level; the timer is this diagnostic's static, armed once,
    // here, and initialized at its final address before the set.
    unsafe {
        (*timer).init();
        crate::sched::idle::dispatcher().set_waitable_timer(
            &mut *timer,
            now + pit::INTERVAL_100NS as u64,
            now,
            0,
            false,
            0,
        );
    }
    irql::state_mut().lower(previous);
    // SAFETY: the expiry writes the signal state at the dispatch level, inside an interrupt; each
    // read goes through the pointer after the halt (a memory clobber), so it sees the write.
    while unsafe { (*timer).timer.waitable.signal_state() } == 0 {
        wait_for_interrupt();
    }
    serial_println!("F2K: irq-smoke: clock DPC fired");

    match super::audit() {
        Ok(()) => {
            serial_println!("F2K: irq-smoke: interrupt audit: ok");
        }
        Err(why) => {
            serial_println!("F2K: irq-smoke: interrupt audit: FAILED ({})", why);
        }
    }
}
