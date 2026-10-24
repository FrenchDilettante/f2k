//! The `nest-smoke` boot diagnostic: a disk interrupt that arrives while the keyboard's is in
//! service, made to happen on purpose.
//!
//! The keyboard's level and the disk's are device levels below the hardware floor: their services
//! run with interrupts enabled, and the interrupt controller's in-service state is what holds the
//! disk's line (behind the cascade) while the keyboard's is served. The keyboard's end clears that
//! state, and the held disk interrupt is delivered at the first instruction the interrupt flag
//! allows. It must be claimed after the keyboard's claim has lowered, not between its
//! acknowledgment and its lower — on top of the keyboard's level, where its raise would go below
//! the current level (the order `IrqlState::end_claim` keeps).
//!
//! By chance, this takes a key's interrupt landing just as a disk transfer completes. Here: the
//! keyboard's line is masked at the controller, which still latches its request; the diagnostic
//! asks for a key on COM1 (the harness presses one through QEMU's monitor) and waits for the
//! request; then, with interrupts masked, has the disk complete a command, waits for its request
//! too, unmasks the keyboard's line, and lets both in at once — the keyboard's first, its line
//! outranking the cascade.

use core::ptr::addr_of_mut;

use crate::hw::ide::disk;
use crate::hw::kbd;
use crate::interrupt::clock;
use crate::interrupt::irql;
use crate::serial_println;

/// How long the diagnostic waits for the harness's key, in ticks (about ten seconds).
const KEY_TICKS: u64 = 1000;

/// How many request-register reads the masked wait for the disk's interrupt makes before giving
/// up (the emulator's completes at once).
const DISK_POLLS: u32 = 1_000_000;

/// How long the served interrupts may take, in ticks.
const SERVED_TICKS: u64 = 100;

/// Halt until the next interrupt, or until `ticks` have passed, while `waiting` holds. The test
/// runs masked; the halt enables and halts as one step, so nothing is taken between the test and
/// the halt.
fn halt_while(ticks: u64, mut waiting: impl FnMut() -> bool) -> bool {
    let state = irql::state_mut();
    let deadline = clock::ticks() + ticks;
    loop {
        state.mask_interrupts();
        if !waiting() {
            state.unmask_interrupts();
            return true;
        }
        if clock::ticks() >= deadline {
            state.unmask_interrupts();
            return false;
        }
        state.unmask_and_halt();
    }
}

/// Run the diagnostic. Called once, from the boot, after the disk and the keyboard are up.
pub fn run() {
    // SAFETY: single CPU; the controller is the kernel's own, touched here with the line masks the
    // diagnostic changes and restores.
    let controller = unsafe { &mut *addr_of_mut!(super::target::CONTROLLER) };
    controller.mask(kbd::VECTOR);
    serial_println!("F2K: nest-smoke: keyboard line held at the controller; press a key");
    if !halt_while(KEY_TICKS, || !controller.requested(kbd::VECTOR)) {
        controller.unmask(kbd::VECTOR);
        serial_println!("F2K: nest-smoke: FAILED (no key came)");
        return;
    }

    let state = irql::state_mut();
    state.mask_interrupts();
    let unsolicited = disk::unsolicited();
    disk::request_interrupt();
    let mut polls = 0;
    while !controller.requested(disk::VECTOR) && polls < DISK_POLLS {
        polls += 1;
    }
    if polls == DISK_POLLS {
        controller.unmask(kbd::VECTOR);
        state.unmask_interrupts();
        serial_println!("F2K: nest-smoke: FAILED (the disk's interrupt never came)");
        return;
    }
    controller.unmask(kbd::VECTOR);
    serial_println!("F2K: nest-smoke: keyboard and disk interrupts pending together");

    // Both in: the keyboard's claim, its end, then the disk's.
    let served = halt_while(SERVED_TICKS, || {
        controller.requested(kbd::VECTOR)
            || controller.requested(disk::VECTOR)
            || disk::unsolicited() == unsolicited
    });
    if !served {
        serial_println!("F2K: nest-smoke: FAILED (the pending interrupts were not served)");
        return;
    }
    match super::audit() {
        Ok(()) => {
            serial_println!(
                "F2K: nest-smoke: both served, the disk's after the keyboard's; interrupt audit: ok"
            );
        }
        Err(why) => {
            serial_println!("F2K: nest-smoke: interrupt audit: FAILED ({})", why);
        }
    }
}
