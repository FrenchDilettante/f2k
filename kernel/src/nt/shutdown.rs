//! NtShutdownSystem: the kernel's end of a shutdown or a restart. On Windows 2000 winlogon calls it
//! once the session has ended (csrss has ended its processes); F2K's caller is the console server's
//! stand-in, which takes winlogon's part until there is one. The processes are the caller's to end:
//! the service ends none, and the system ends with whatever still runs.
//!
//! The action is checked first: one of ShutdownNoReboot (0), ShutdownReboot (1) and
//! ShutdownPowerOff (2), anything else STATUS_INVALID_PARAMETER, before the privilege check, as the
//! user32/exitwin capture shows. Then the steps, in order ([`run`]):
//!
//! 1. the boot volume closed to changes: a later change is refused with STATUS_TOO_LATE, and a
//!    writer under way finishes first, holding the volume's lock (`fs::fat32::volume`);
//! 2. the boot volume flushed: FSInfo's free count and next-free hint from a FAT scan, then
//!    FAT[1]'s clean-shutdown bit, as FastFat marks its volumes clean when the system shuts down;
//! 3. the volume's disk told to write its cache out (ATA FLUSH CACHE, `hw::ide`), as FastFat's
//!    shutdown sends its volume's device a flush once the volume is marked clean: a drive that
//!    caches writes could otherwise lose the clean mark and the last writes with its power. It runs
//!    whatever the volume step did, a failed flush included;
//! 4. the registry's hives flushed, as Windows 2000's kernel flushes them (`cm::flush_hives`, which
//!    has nothing to write while the hives live in memory alone);
//! 5. the end announced on COM1;
//! 6. for ShutdownNoReboot and ShutdownPowerOff, "It is now safe to turn off your computer." on the
//!    screen and on COM1, and the processor halts (F2K has no ACPI, so a power-off ends there too,
//!    as Windows 2000's does on a machine without it); for ShutdownReboot, the keyboard
//!    controller's reset line, then a triple fault if the machine still runs.
//!
//! A shutdown that succeeds never returns to its caller.

use core::fmt;

use rtl::nt::ShutdownAction;

use super::call::{NtCall, NtResult};
use crate::block::CacheFlush;
use crate::fs::fat32::volume::Flushed;
use crate::status::*;

/// What a halted shutdown leaves on the screen and on COM1.
pub const SAFE_TO_TURN_OFF: &str = "It is now safe to turn off your computer.";

/// The last line a restart prints, before the reset: under QEMU's `-no-reboot` the reset ends QEMU,
/// and the test harness takes the exit that follows this line for the boot's end.
pub const RESTARTING: &str = "F2K: shutdown: restarting";

/// NtShutdownSystem: the action checked, then the shutdown, which does not return (see the
/// module's documentation).
pub fn shutdown_system(_call: &mut NtCall, action: u32) -> NtResult {
    let action = ShutdownAction::try_from(action)?;
    // Windows 2000 checks the caller's SeShutdownPrivilege here, after the action: without it
    // enabled, STATUS_PRIVILEGE_NOT_HELD (the user32/exitwin capture). F2K checks no privilege, a
    // known deviation: its tokens hold none to check.
    shut_down(action)
}

/// The host build's stand-in for the shutdown: nothing there to shut down.
#[cfg(not(target_arch = "x86"))]
fn shut_down(_: ShutdownAction) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

/// The machine's side of the shutdown's steps, which [`run`] drives in order: the kernel's own on
/// the target, a recording in the host tests.
pub trait Machine {
    /// Close the boot volume to changes.
    fn close_volume(&mut self);
    /// Flush the boot volume: none when no volume is mounted.
    fn flush_volume(&mut self) -> Option<Result<Flushed, NtStatus>>;
    /// Flush the write cache of the boot volume's disk: none when no volume is mounted.
    fn flush_disk_cache(&mut self) -> Option<Result<CacheFlush, NtStatus>>;
    /// Flush the registry's hives.
    fn flush_registry(&mut self);
    /// A line on COM1.
    fn report(&mut self, line: fmt::Arguments);
    /// A line on the screen, alone on it (nothing when the screen is in graphics mode).
    fn show(&mut self, text: &str);
}

/// How the shutdown ends, once its steps are done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// The processor halts.
    Halt,
    /// The machine restarts.
    Reset,
}

/// The shutdown's steps, in order (see the module's documentation): how it ends.
pub fn run(action: ShutdownAction, machine: &mut impl Machine) -> Ending {
    machine.report(format_args!("F2K: shutdown: {}", action.name()));
    machine.close_volume();
    match machine.flush_volume() {
        None => machine.report(format_args!("F2K: shutdown: no volume to flush")),
        Some(Ok(Flushed::Clean(free))) => match free.next_free {
            Some(next) => machine.report(format_args!(
                "F2K: shutdown: volume flushed ({} clusters free, next free {}), marked clean",
                free.count, next
            )),
            None => machine.report(format_args!(
                "F2K: shutdown: volume flushed ({} clusters free, none next), marked clean",
                free.count
            )),
        },
        Some(Ok(Flushed::Unchanged)) => machine.report(format_args!(
            "F2K: shutdown: volume unchanged since its mount"
        )),
        // The shutdown goes on: the volume stays marked dirty, for the check its next mount owes
        // it.
        Some(Err(status)) => machine.report(format_args!(
            "F2K: shutdown: volume flush failed (status {:#010x}), left dirty",
            status.0
        )),
    }
    match machine.flush_disk_cache() {
        None => machine.report(format_args!("F2K: shutdown: no disk cache to flush")),
        Some(Ok(CacheFlush::Flushed)) => {
            machine.report(format_args!("F2K: shutdown: disk cache flushed"))
        }
        Some(Ok(CacheFlush::Unsupported)) => {
            machine.report(format_args!("F2K: shutdown: the disk takes no cache flush"))
        }
        // The shutdown goes on: what the drive still holds may be lost, as it would be with no
        // flush at all.
        Some(Err(status)) => machine.report(format_args!(
            "F2K: shutdown: disk cache flush failed (status {:#010x})",
            status.0
        )),
    }
    machine.flush_registry();
    machine.report(format_args!(
        "F2K: shutdown: registry flushed (no hive on disk)"
    ));
    machine.report(format_args!("F2K: shutdown complete"));
    match action {
        ShutdownAction::Reboot => {
            machine.report(format_args!("{}", RESTARTING));
            Ending::Reset
        }
        ShutdownAction::NoReboot | ShutdownAction::PowerOff => {
            machine.show(SAFE_TO_TURN_OFF);
            machine.report(format_args!("{}", SAFE_TO_TURN_OFF));
            Ending::Halt
        }
    }
}

#[cfg(target_arch = "x86")]
pub use target::shut_down;

#[cfg(target_arch = "x86")]
mod target {
    use rtl::console::screen::Cell;

    use super::*;
    use crate::fs::fat32::volume::with_boot_volume;
    use crate::hw::portio::{Io, Ports};
    use crate::hw::vga::{COLUMNS, ROWS};

    /// How many status reads the reset waits for the controller's line to take the processor: a
    /// tenth of a second or so (a port read takes about a microsecond), where the line takes it in
    /// microseconds.
    const RESET_WAIT_READS: u32 = 100_000;

    /// The text screen's attribute for the closing line: light grey on black.
    const PLAIN: u16 = 0x07;

    /// Shut the system down with `action`: the steps ([`run`]), then the halt or the reset. The
    /// service's path once its action is checked, and the session's end's
    /// (`crate::session::shut_down`), winlogon's call on Windows 2000. Called at the passive
    /// level, holding no console or volume lock, from a thread that can wait for the volume's.
    pub fn shut_down(action: ShutdownAction) -> ! {
        match run(action, &mut Kernel) {
            Ending::Halt => crate::halt(),
            Ending::Reset => {
                crate::pcr::pcr().mask_interrupts();
                if crate::hw::kbd::reset_machine() {
                    for _ in 0..RESET_WAIT_READS {
                        Ports.read(crate::hw::kbd::STATUS);
                    }
                }
                crate::cpu::triple_fault()
            }
        }
    }

    /// The kernel's side of the steps.
    struct Kernel;

    impl Machine for Kernel {
        fn close_volume(&mut self) {
            with_boot_volume(|volume| volume.close());
        }

        fn flush_volume(&mut self) -> Option<Result<Flushed, NtStatus>> {
            with_boot_volume(|volume| volume.flush())
        }

        fn flush_disk_cache(&mut self) -> Option<Result<CacheFlush, NtStatus>> {
            with_boot_volume(|volume| volume.device().flush_cache())
        }

        fn flush_registry(&mut self) {
            crate::cm::flush_hives();
        }

        fn report(&mut self, line: fmt::Arguments) {
            crate::serial_println!("{}", line);
        }

        /// The line centered on a cleared text screen. Interrupts are masked from here to the
        /// halt, so nothing draws over it (a console's echo, from a key's deferred work). In
        /// graphics mode the text screen is not shown: COM1 alone carries the line.
        fn show(&mut self, text: &str) {
            crate::pcr::pcr().mask_interrupts();
            if crate::hw::vbe::graphics_mode_set() {
                return;
            }
            let mut screen = crate::hw::vga::screen();
            screen.clear(PLAIN);
            let column = COLUMNS.saturating_sub(text.len()) / 2;
            for (offset, character) in text.bytes().enumerate() {
                let cell = Cell {
                    character,
                    attribute: PLAIN,
                };
                screen.put(ROWS / 2, column + offset, cell);
            }
            screen.set_cursor(ROWS / 2 + 1, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;

    use super::*;
    use crate::fs::fat32::volume::FreeClusters;

    /// A machine that records each step, and answers the flushes as told.
    struct Recording {
        flush: Option<Result<Flushed, NtStatus>>,
        cache: Option<Result<CacheFlush, NtStatus>>,
        steps: Vec<String>,
    }

    impl Recording {
        /// The volume's flush answered with `flush`, the disk's cache flushed.
        fn answering(flush: Option<Result<Flushed, NtStatus>>) -> Self {
            Recording {
                flush,
                cache: Some(Ok(CacheFlush::Flushed)),
                steps: Vec::new(),
            }
        }
    }

    impl Machine for Recording {
        fn close_volume(&mut self) {
            self.steps.push("close volume".into());
        }

        fn flush_volume(&mut self) -> Option<Result<Flushed, NtStatus>> {
            self.steps.push("flush volume".into());
            self.flush
        }

        fn flush_disk_cache(&mut self) -> Option<Result<CacheFlush, NtStatus>> {
            self.steps.push("flush disk cache".into());
            self.cache
        }

        fn flush_registry(&mut self) {
            self.steps.push("flush registry".into());
        }

        fn report(&mut self, line: fmt::Arguments) {
            self.steps.push(std::format!("COM1: {line}"));
        }

        fn show(&mut self, text: &str) {
            self.steps.push(std::format!("screen: {text}"));
        }
    }

    const FLUSHED: Option<Result<Flushed, NtStatus>> = Some(Ok(Flushed::Clean(FreeClusters {
        count: 90_100,
        next_free: Some(36_900),
    })));

    /// The service checks the action before anything else: an action out of range is
    /// STATUS_INVALID_PARAMETER through the service table, as the capture's; a valid one goes on
    /// (to the host's stand-in, which has nothing to shut down).
    #[test]
    fn the_service_refuses_an_action_out_of_range() {
        let entry = super::super::NT_SERVICES
            .iter()
            .find(|entry| entry.1 == "NtShutdownSystem")
            .expect("NtShutdownSystem is served");
        assert_eq!(entry.0, 0xD9, "Windows 2000's service 0xD9");
        assert_eq!(entry.2, 4, "one argument");
        let mut passive = crate::level::passive_for_test();
        for (action, status) in [
            (3u32, STATUS_INVALID_PARAMETER),
            (0xFFFF_FFFF, STATUS_INVALID_PARAMETER),
            (0, STATUS_NOT_IMPLEMENTED),
        ] {
            let mut frame = crate::user::TrapFrame::default();
            (entry.3)(&mut frame, &[action], &mut passive);
            assert_eq!(frame.eax, status.0, "action {action:#x}");
        }
    }

    /// A shutdown that halts: the volume closed, then flushed, then the disk's cache, then the
    /// registry, the end on COM1, and the closing line on the screen and COM1. A power-off ends
    /// the same way.
    #[test]
    fn a_shutdown_closes_then_flushes_then_halts() {
        let mut machine = Recording::answering(FLUSHED);
        assert_eq!(run(ShutdownAction::NoReboot, &mut machine), Ending::Halt);
        assert_eq!(
            machine.steps,
            [
                "COM1: F2K: shutdown: ShutdownNoReboot",
                "close volume",
                "flush volume",
                "COM1: F2K: shutdown: volume flushed (90100 clusters free, next free 36900), marked clean",
                "flush disk cache",
                "COM1: F2K: shutdown: disk cache flushed",
                "flush registry",
                "COM1: F2K: shutdown: registry flushed (no hive on disk)",
                "COM1: F2K: shutdown complete",
                "screen: It is now safe to turn off your computer.",
                "COM1: It is now safe to turn off your computer.",
            ]
        );
        let mut machine = Recording::answering(FLUSHED);
        assert_eq!(run(ShutdownAction::PowerOff, &mut machine), Ending::Halt);
        assert_eq!(machine.steps[0], "COM1: F2K: shutdown: ShutdownPowerOff");
        assert_eq!(
            machine.steps.last().unwrap(),
            "COM1: It is now safe to turn off your computer."
        );
    }

    /// A restart: the same steps, then the restarting line, and no closing line on the screen.
    #[test]
    fn a_restart_ends_on_the_reset() {
        let mut machine = Recording::answering(FLUSHED);
        assert_eq!(run(ShutdownAction::Reboot, &mut machine), Ending::Reset);
        assert_eq!(machine.steps[0], "COM1: F2K: shutdown: ShutdownReboot");
        assert_eq!(
            &machine.steps[machine.steps.len() - 2..],
            [
                "COM1: F2K: shutdown complete",
                "COM1: F2K: shutdown: restarting"
            ]
        );
        assert!(!machine.steps.iter().any(|step| step.starts_with("screen:")));
    }

    /// The flush's other outcomes are reported, and the shutdown goes on through each, the disk's
    /// cache flushed after each: no volume, a volume never changed, a full one (no next free
    /// cluster), and a failed flush.
    #[test]
    fn every_flush_outcome_is_reported_and_the_shutdown_goes_on() {
        let full = Some(Ok(Flushed::Clean(FreeClusters {
            count: 0,
            next_free: None,
        })));
        for (flush, line) in [
            (None, "F2K: shutdown: no volume to flush"),
            (
                Some(Ok(Flushed::Unchanged)),
                "F2K: shutdown: volume unchanged since its mount",
            ),
            (
                full,
                "F2K: shutdown: volume flushed (0 clusters free, none next), marked clean",
            ),
            (
                Some(Err(STATUS_IO_DEVICE_ERROR)),
                "F2K: shutdown: volume flush failed (status 0xc0000185), left dirty",
            ),
        ] {
            let mut machine = Recording::answering(flush);
            assert_eq!(run(ShutdownAction::NoReboot, &mut machine), Ending::Halt);
            assert_eq!(machine.steps[3], std::format!("COM1: {line}"));
            assert_eq!(machine.steps[4], "flush disk cache");
            assert_eq!(machine.steps[6], "flush registry");
        }
    }

    /// The cache flush's outcomes are reported, and the shutdown goes on through each: no volume
    /// (so no disk to flush), a disk that takes no flush, and a failed flush.
    #[test]
    fn every_cache_flush_outcome_is_reported_and_the_shutdown_goes_on() {
        for (cache, line) in [
            (None, "F2K: shutdown: no disk cache to flush"),
            (
                Some(Ok(CacheFlush::Unsupported)),
                "F2K: shutdown: the disk takes no cache flush",
            ),
            (
                Some(Err(STATUS_IO_TIMEOUT)),
                "F2K: shutdown: disk cache flush failed (status 0xc00000b5)",
            ),
        ] {
            let mut machine = Recording {
                cache,
                ..Recording::answering(FLUSHED)
            };
            assert_eq!(run(ShutdownAction::Reboot, &mut machine), Ending::Reset);
            assert_eq!(machine.steps[4], "flush disk cache");
            assert_eq!(machine.steps[5], std::format!("COM1: {line}"));
            assert_eq!(machine.steps[6], "flush registry");
            assert_eq!(
                machine.steps.last().unwrap(),
                "COM1: F2K: shutdown: restarting"
            );
        }
    }
}
