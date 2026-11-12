//! The hardware abstraction layer: the one interface between the kernel and the platform's system
//! hardware — the port space, the interrupt controller, the interval timer, the real-time clock,
//! and the display's mode state.
//!
//! On Windows 2000 this layer is hal.dll: the kernel and the drivers call its routines
//! (READ_PORT_UCHAR, HalGetInterruptVector, HalEnableSystemInterrupt, HalQueryRealTimeClock and the
//! like) and never program those chips themselves. F2K compiles the layer into the kernel image,
//! and this module is its interface:
//!
//! - **Port I/O:** the port space, [`Io`], and the real one, [`Ports`] — what READ_PORT_UCHAR,
//!   WRITE_PORT_UCHAR and their word forms do. The drivers hold their registers over it, so their
//!   logic runs against a simulated register file in the host tests.
//! - **The interrupt controller:** the hardware vector band ([`FIRST_VECTOR`] to [`LAST_VECTOR`])
//!   and a device line's vector in it ([`interrupt_vector`], HalGetInterruptVector's mapping); the
//!   [`Hal`] methods that settle, acknowledge, enable and disable a vector; and
//!   [`SystemInterrupts`], the interrupt core's [`Controller`] over them.
//! - **The interval timer, the real-time clock, the display:** the rest of [`Hal`]'s methods.
//!
//! [`Hal`] is the platform's side, implemented on target by [`StandardPc`] — the 8259A pair, the
//! 8254 and the CMOS clock of a PC/AT, and the VESA BIOS's mode set — over the hardware modules
//! `hw::portio`, `hw::pic`, `hw::pit`, `hw::rtc` and `hw::vbe`. Outside this module and those, the
//! kernel names none of them, save the exceptions a host test below lists; the test holds that by
//! reading the sources. A separate hal.dll would take [`StandardPc`]'s place behind the same
//! interface.
//!
//! The device drivers — the IDE disk, the keyboard, the serial line, the VGA text screen — are not
//! part of this layer. The kernel calls them directly; they reach the hardware through this
//! layer's port space and vector mapping, as a Windows 2000 driver does through hal.dll.

/// The hal.dll-named entry points over this interface ([`Hal`] and the seams around it): the
/// export surface a driver imports from hal.dll, catalogued in `kernel/hal_exports.toml`, each
/// record implemented here or a stub whose reason names the slice that lands it.
pub mod exports;

/// The interval timer's input clock, in Hz: the scale between its counts and 100 ns units.
pub use crate::hw::pit::INPUT_FREQUENCY_HZ;
pub use crate::hw::portio::Io;
#[cfg(target_arch = "x86")]
pub use crate::hw::portio::Ports;
pub use crate::hw::rtc::CivilTime;
#[cfg(target_arch = "x86")]
pub use crate::hw::rtc::SCREEN_MAILBOX;
use crate::interrupt::irql::{Irql, OldIrql};
use crate::interrupt::{Claim, Controller};
use crate::pcr::pcr;

// --- The interrupt controller's vector band ---------------------------------------------------

/// The first hardware vector: the one device line 0 (the interval timer's) arrives on.
pub const FIRST_VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE;

/// The last hardware vector (device line 15).
pub const LAST_VECTOR: u8 = crate::hw::pic::LAST_VECTOR;

/// The vector device line `line` (an ISA IRQ number) arrives on: HalGetInterruptVector's mapping
/// of a bus interrupt level to a system vector. The controller delivers the lines in order from
/// [`FIRST_VECTOR`].
pub const fn interrupt_vector(line: u8) -> u8 {
    assert!(line <= LAST_VECTOR - FIRST_VECTOR, "no such device line");
    FIRST_VECTOR + line
}

// --- The interface --------------------------------------------------------------------------

/// The platform's side of the hardware abstraction layer: what the kernel asks of the system
/// hardware beyond the port space. [`StandardPc`] implements it on target; the host tests supply
/// fakes.
///
/// A vector is a hardware vector in the band ([`FIRST_VECTOR`] to [`LAST_VECTOR`]). The level
/// bookkeeping is the kernel's (the processor's ledger): the interrupt methods do the chip's part
/// alone, and [`SystemInterrupts`] puts the two together.
pub trait Hal {
    /// Program the interrupt controller at boot: the device lines delivered in the vector band,
    /// every line disabled. Interrupts masked, before any line is enabled.
    fn initialize_interrupts(&self);

    /// Whether a delivered vector is a real interrupt (the chip's side of the claim, where Windows
    /// 2000 calls HalBeginSystemInterrupt). A spurious one is settled here, with whatever partial
    /// acknowledgment the chip needs already done; it is not ended.
    fn begin_system_interrupt(&self, vector: u8) -> bool;

    /// Acknowledge a real interrupt the begin accepted (the chip's side of the end, where Windows
    /// 2000 calls HalEndSystemInterrupt).
    fn end_system_interrupt(&self, vector: u8);

    /// HalEnableSystemInterrupt: enable the vector's line; false if it cannot be.
    fn enable_system_interrupt(&self, vector: u8) -> bool;

    /// HalDisableSystemInterrupt: disable the vector's line.
    fn disable_system_interrupt(&self, vector: u8);

    /// Whether the vector's line is enabled.
    fn system_interrupt_enabled(&self, vector: u8) -> bool;

    /// Whether the vector's line has raised a request the processor has not taken yet.
    fn system_interrupt_requested(&self, vector: u8) -> bool;

    /// Whether no interrupt is left half-served on the controller.
    fn interrupts_in_service_clear(&self) -> bool;

    /// Run `f` with every line disabled, then put the lines back as they were. A request raised
    /// meanwhile is held, and taken once the lines are back and interrupts are enabled.
    fn with_lines_masked<R>(&self, f: impl FnOnce() -> R) -> R;

    /// Run the interval timer at the period nearest `increment`, in 100 ns units
    /// (HalSetTimeIncrement's place). At boot, before interrupts are enabled.
    fn set_time_increment(&self, increment: u32);

    /// The interval timer's current count within the period: its period's length in the timer's
    /// input clocks at the start of a period, down to 1 at its end. Interrupts masked.
    fn interval_timer_count(&self) -> u16;

    /// The interval timer's period, in its input clocks (the counter's scale for
    /// [`Hal::interval_timer_count`]).
    fn interval_timer_period(&self) -> u16;

    /// HalQueryRealTimeClock: the real-time clock's date and time; none when it reads no valid
    /// date.
    fn query_real_time_clock(&self) -> Option<CivilTime>;

    /// Clear the real-time clock's nonvolatile byte `index`, `announce` the wait, then read the
    /// byte until it is nonzero, `reads` times at most: whether it was answered. The test
    /// harness's mailbox (see [`SCREEN_MAILBOX`]).
    fn await_cmos_mailbox(&self, index: u8, reads: u32, announce: impl FnOnce()) -> bool;

    /// Whether the display has left its text mode for a graphics mode.
    fn graphics_mode_set(&self) -> bool;
}

/// The interrupt core's controller ([`Controller`]) over the platform's: the chip's side of each
/// step from the [`Hal`], the level's from the processor's ledger. The claim raises once the chip
/// has found the interrupt real; the end acknowledges the chip before it lowers.
pub struct SystemInterrupts<'a, H: Hal>(pub &'a H);

impl<H: Hal> Controller for SystemInterrupts<'_, H> {
    fn claim(&mut self, vector: u8, level: Irql) -> Claim {
        if self.0.begin_system_interrupt(vector) {
            // Real: raise to the service level. The ledger performs the interrupt-flag transition.
            Claim::Accepted(pcr().raise(level))
        } else {
            // Spurious: the chip's work is already done; nothing was raised.
            Claim::Spurious
        }
    }

    fn end(&mut self, previous: OldIrql, vector: u8) {
        // Acknowledged with interrupts masked: a line the claim held off waits for the lower (see
        // `IrqlState::end_claim`).
        pcr().end_claim(previous, || self.0.end_system_interrupt(vector));
    }

    fn enable(&mut self, vector: u8) -> bool {
        self.0.enable_system_interrupt(vector)
    }

    fn disable(&mut self, vector: u8) {
        self.0.disable_system_interrupt(vector);
    }

    fn is_enabled(&mut self, vector: u8) -> bool {
        self.0.system_interrupt_enabled(vector)
    }

    fn in_service_clear(&mut self) -> bool {
        self.0.interrupts_in_service_clear()
    }
}

// --- The target's platform: a standard PC -----------------------------------------------------

#[cfg(target_arch = "x86")]
pub use target::{StandardPc, PLATFORM};

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::hw::pic::{self, Pic, Verdict};
    use crate::hw::{pit, rtc, vbe};

    /// The platform's interrupt controller: the 8259A pair, remapped to the vector band.
    static PIC: Pic<Ports> = Pic::new(Ports, pic::MASTER_VECTOR_BASE, pic::SLAVE_VECTOR_BASE);

    /// A standard PC: the 8259A interrupt controller pair, the 8254 interval timer's channel 0,
    /// the CMOS real-time clock, and the VESA BIOS's display modes. Its state is the chips'
    /// (and the drivers' statics), so it is a unit: [`PLATFORM`] is the kernel's.
    #[derive(Clone, Copy)]
    pub struct StandardPc;

    /// The kernel's platform.
    pub const PLATFORM: StandardPc = StandardPc;

    impl Hal for StandardPc {
        fn initialize_interrupts(&self) {
            PIC.remap();
        }

        fn begin_system_interrupt(&self, vector: u8) -> bool {
            match PIC.claim(vector) {
                Verdict::Real => true,
                Verdict::SpuriousNoEoi | Verdict::SpuriousCascadeEnded => false,
            }
        }

        fn end_system_interrupt(&self, vector: u8) {
            PIC.end_of_interrupt(vector);
        }

        fn enable_system_interrupt(&self, vector: u8) -> bool {
            PIC.unmask(vector);
            true
        }

        fn disable_system_interrupt(&self, vector: u8) {
            PIC.mask(vector);
        }

        fn system_interrupt_enabled(&self, vector: u8) -> bool {
            PIC.is_unmasked(vector)
        }

        fn system_interrupt_requested(&self, vector: u8) -> bool {
            PIC.requested(vector)
        }

        fn interrupts_in_service_clear(&self) -> bool {
            PIC.in_service_clear()
        }

        /// The real-mode BIOS calls' guard: the BIOS's vector table sends the remapped hardware
        /// vectors to its default handlers, which end no interrupt, so no line may be taken while
        /// it runs.
        fn with_lines_masked<R>(&self, f: impl FnOnce() -> R) -> R {
            let saved = PIC.line_masks();
            PIC.mask_all();
            let result = f();
            PIC.set_line_masks(saved);
            result
        }

        fn set_time_increment(&self, increment: u32) {
            pit::program_interval(&mut Ports, pit::divisor_for_100ns(increment));
        }

        fn interval_timer_count(&self) -> u16 {
            pit::read_count(&mut Ports)
        }

        fn interval_timer_period(&self) -> u16 {
            pit::programmed_divisor()
        }

        fn query_real_time_clock(&self) -> Option<CivilTime> {
            rtc::read(&mut Ports)
        }

        fn await_cmos_mailbox(&self, index: u8, reads: u32, announce: impl FnOnce()) -> bool {
            rtc::await_mailbox(&mut Ports, index, reads, announce)
        }

        fn graphics_mode_set(&self) -> bool {
            vbe::graphics_mode_set()
        }
    }

    /// What the irq-smoke diagnostic reports of the interval timer: the programming the boot
    /// asks for, and the chip's own report of it.
    #[cfg(feature = "irq-smoke")]
    pub struct TimerProgramming {
        /// The control word the boot programs, decoded.
        pub programmed: pit::Programming,
        /// The platform's default divisor.
        pub divisor: u16,
        /// The platform's default period, in 100 ns units.
        pub interval: u32,
        /// Channel 0's read-back status, decoded.
        pub status: pit::Programming,
    }

    /// The platform's own diagnostics, beside the interface: the chips' programming as the
    /// irq-smoke diagnostic reports it.
    #[cfg(feature = "irq-smoke")]
    impl StandardPc {
        /// The vector bases the controller pair was remapped to: (master, slave).
        pub fn vector_bases(&self) -> (u8, u8) {
            PIC.vector_bases()
        }

        /// The pair's interrupt mask registers, (master, slave): a set bit is a disabled line.
        pub fn line_masks(&self) -> (u8, u8) {
            PIC.line_masks()
        }

        /// The interval timer's programming, read back from the chip where it can be.
        pub fn timer_programming(&self) -> TimerProgramming {
            TimerProgramming {
                programmed: pit::Programming::decode(pit::MODE2_LO_HIBYTE),
                divisor: pit::INTERVAL_DIVISOR,
                interval: pit::INTERVAL_100NS,
                status: pit::Programming::decode(pit::read_back_status(&mut Ports)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::vec::Vec;

    use super::*;
    use crate::interrupt::irql::PASSIVE;

    /// A platform whose interrupt controller is one in-service bit and a log, recording the level
    /// the processor's ledger stood at for each step.
    #[derive(Default)]
    struct FakePlatform {
        in_service: RefCell<bool>,
        log: RefCell<Vec<(&'static str, u8, Irql)>>,
    }

    impl FakePlatform {
        fn note(&self, step: &'static str, vector: u8) {
            self.log.borrow_mut().push((step, vector, pcr().current()));
        }
    }

    impl Hal for FakePlatform {
        fn initialize_interrupts(&self) {}

        fn begin_system_interrupt(&self, vector: u8) -> bool {
            self.note("begin", vector);
            *self.in_service.borrow()
        }

        fn end_system_interrupt(&self, vector: u8) {
            self.note("end", vector);
            *self.in_service.borrow_mut() = false;
        }

        fn enable_system_interrupt(&self, vector: u8) -> bool {
            self.note("enable", vector);
            true
        }

        fn disable_system_interrupt(&self, vector: u8) {
            self.note("disable", vector);
        }

        fn system_interrupt_enabled(&self, _vector: u8) -> bool {
            true
        }

        fn system_interrupt_requested(&self, _vector: u8) -> bool {
            false
        }

        fn interrupts_in_service_clear(&self) -> bool {
            !*self.in_service.borrow()
        }

        fn with_lines_masked<R>(&self, f: impl FnOnce() -> R) -> R {
            f()
        }

        fn set_time_increment(&self, _increment: u32) {}

        fn interval_timer_count(&self) -> u16 {
            0
        }

        fn interval_timer_period(&self) -> u16 {
            0
        }

        fn query_real_time_clock(&self) -> Option<CivilTime> {
            None
        }

        fn await_cmos_mailbox(&self, _index: u8, _reads: u32, _announce: impl FnOnce()) -> bool {
            false
        }

        fn graphics_mode_set(&self) -> bool {
            false
        }
    }

    /// A real interrupt: the chip is asked first, at the level the interrupt found; the claim
    /// raises to the service level; the end acknowledges the chip while still at that level, then
    /// lowers back.
    #[test]
    fn a_real_interrupt_is_raised_after_the_chip_and_acknowledged_before_the_lower() {
        let platform = FakePlatform::default();
        *platform.in_service.borrow_mut() = true;
        let mut controller = SystemInterrupts(&platform);
        let level = Irql(8);
        let Claim::Accepted(previous) = controller.claim(FIRST_VECTOR, level) else {
            panic!("a real interrupt is accepted");
        };
        assert_eq!(pcr().current(), level, "raised to the service level");
        controller.end(previous, FIRST_VECTOR);
        assert_eq!(pcr().current(), PASSIVE, "lowered back");
        assert_eq!(
            *platform.log.borrow(),
            [
                ("begin", FIRST_VECTOR, PASSIVE),
                ("end", FIRST_VECTOR, level)
            ]
        );
        assert!(controller.in_service_clear());
    }

    /// A spurious interrupt raises nothing and is never ended.
    #[test]
    fn a_spurious_interrupt_raises_nothing() {
        let platform = FakePlatform::default();
        let mut controller = SystemInterrupts(&platform);
        assert!(matches!(
            controller.claim(LAST_VECTOR, Irql(8)),
            Claim::Spurious
        ));
        assert_eq!(pcr().current(), PASSIVE);
        assert_eq!(*platform.log.borrow(), [("begin", LAST_VECTOR, PASSIVE)]);
    }

    /// A line's enable and disable are the platform's.
    #[test]
    fn enable_and_disable_reach_the_platform() {
        let platform = FakePlatform::default();
        let mut controller = SystemInterrupts(&platform);
        assert!(controller.enable(interrupt_vector(1)));
        controller.disable(interrupt_vector(1));
        let steps: Vec<_> = platform
            .log
            .borrow()
            .iter()
            .map(|&(step, vector, _)| (step, vector))
            .collect();
        assert_eq!(steps, [("enable", 0x31), ("disable", 0x31)]);
    }

    /// The clock's captured rates are ones the 8254 runs: the interval at the platform's captured
    /// divisor (the one the timer's period starts at, before the boot sets it), the finest rate at
    /// a divisor of its own.
    #[test]
    fn the_clock_rates_are_interval_timer_divisors() {
        use crate::hw::pit;
        use crate::interrupt::clock::{FINEST_100NS, INTERVAL_100NS};
        assert_eq!(
            pit::divisor_for_100ns(INTERVAL_100NS),
            pit::INTERVAL_DIVISOR
        );
        assert_eq!(
            pit::divisor_for_100ns(FINEST_100NS),
            1_197,
            "the finest rate's divisor"
        );
    }

    /// The vector band: sixteen device lines from 0x30, clear of the processor's exceptions and the
    /// system-service gate, each line's vector its offset into the band.
    #[test]
    fn the_device_lines_map_onto_the_band_in_order() {
        assert_eq!(FIRST_VECTOR, 0x30);
        assert_eq!(LAST_VECTOR, 0x3F);
        assert_eq!(interrupt_vector(0), FIRST_VECTOR);
        assert_eq!(interrupt_vector(14), 0x3E);
        assert_eq!(interrupt_vector(15), LAST_VECTOR);
    }

    /// The modules behind the seam, as a path names them.
    const SURFACE: [&str; 5] = ["pic", "pit", "rtc", "portio", "vbe"];

    /// The files that may name them: this interface, the hardware layer's module list, and the
    /// modules themselves (paths under `kernel/src`; a trailing `/` takes a directory).
    const BEHIND_THE_SEAM: [&str; 7] = [
        "hal.rs",
        "hw/mod.rs",
        "hw/pic.rs",
        "hw/pit.rs",
        "hw/rtc.rs",
        "hw/portio.rs",
        "hw/vbe/",
    ];

    /// The port instructions a string may open with: an `asm!` doing port I/O of its own.
    const PORT_INSTRUCTIONS: [&str; 5] = ["out dx", "out 0x", "in al", "in ax", "in eax"];

    /// The named exceptions: files outside this layer's reach that still reach the hardware past
    /// it, each with what it reaches. Each must still do so; one that no longer does leaves the
    /// list.
    const EXCEPTIONS: [(&str, &str); 7] = [
        (
            "boot/mod.rs",
            "the POST code's write to port 0x80, an inline `out` before the serial line is up",
        ),
        (
            "win32k/dc.rs",
            "the display driver's framebuffer (hw::vbe's Framebuffer, PixelMemory, LfbMemory and \
             with_framebuffer)",
        ),
        (
            "win32k/display.rs",
            "the display driver's mode set, mode test, mode list and geometry (hw::vbe)",
        ),
        (
            "win32k/fonts/mod.rs",
            "the display driver's framebuffer and pixel memory a TrueType run draws into (hw::vbe)",
        ),
        (
            "win32k/fonts/tests.rs",
            "the display driver's framebuffer, pixel memory and geometry, faked for the glyph runs",
        ),
        (
            "win32k/raster.rs",
            "the display driver's pixel memory and geometry (hw::vbe)",
        ),
        (
            "win32k/winsta.rs",
            "the display's default size (hw::vbe's DEFAULT_WIDTH and DEFAULT_HEIGHT)",
        ),
    ];

    /// Every `.rs` file under `dir`, as its path under `root` and its text.
    fn sources(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("the kernel's sources are readable")
            .map(|entry| entry.expect("a readable directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                sources(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((name, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }

    /// Whether a line of `file` names one of the modules behind the seam: `hw::pic` and the like,
    /// a `hw::{...}` group holding one, or (in a module of the hardware layer itself) `super::pic`.
    fn names_the_surface(file: &str, line: &str) -> bool {
        let in_hw = file.starts_with("hw/") && file.matches('/').count() == 1;
        let direct = SURFACE.iter().any(|module| {
            line.contains(&std::format!("hw::{module}"))
                || (in_hw && line.contains(&std::format!("super::{module}")))
        });
        let grouped = line.split("hw::{").skip(1).any(|group| {
            group
                .split('}')
                .next()
                .unwrap_or("")
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| SURFACE.contains(&word))
        });
        direct || grouped
    }

    /// Whether a line holds a string that opens with a port instruction.
    fn issues_port_io(line: &str) -> bool {
        line.split('"').skip(1).step_by(2).any(|string| {
            let string = string.trim_start();
            PORT_INSTRUCTIONS
                .iter()
                .any(|instruction| string.starts_with(instruction))
        })
    }

    /// The audit: outside this interface and the modules behind it, nothing in the kernel names
    /// `hw::pic`, `hw::pit`, `hw::rtc`, `hw::portio` or `hw::vbe`, and nothing issues port I/O of
    /// its own, save the named exceptions, each still holding. Comment lines are not code. By
    /// hand, the first half is `grep -rnE 'hw::(pic|pit|rtc|portio|vbe)' kernel/src`, less comments
    /// and the files behind the seam.
    #[test]
    fn only_the_hal_reaches_the_system_hardware() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &root, &mut files);
        assert!(files.iter().any(|(name, _)| name == "hal.rs"));

        let mut reaching = std::collections::BTreeSet::new();
        let mut unexpected = Vec::new();
        for (name, text) in &files {
            let behind = BEHIND_THE_SEAM.iter().any(|behind| {
                name == behind || (behind.ends_with('/') && name.starts_with(behind))
            });
            if behind {
                continue;
            }
            for (number, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if names_the_surface(name, line) || issues_port_io(line) {
                    reaching.insert(name.as_str());
                    if !EXCEPTIONS.iter().any(|(file, _)| file == name) {
                        unexpected.push(std::format!("{name}:{}: {}", number + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            unexpected.is_empty(),
            "reached past the HAL:\n{}",
            unexpected.join("\n")
        );
        for (file, what) in EXCEPTIONS {
            assert!(
                reaching.contains(file),
                "{file} no longer reaches past the HAL ({what}): take it off the exceptions"
            );
        }
    }

    /// The audit's matchers: a path, a group and a hardware module's `super::` form are seen; a
    /// device driver's path and a string that merely starts with "out" are not.
    #[test]
    fn the_audit_sees_the_surface_and_only_it() {
        assert!(names_the_surface(
            "time.rs",
            "use crate::hw::rtc::CivilTime;"
        ));
        assert!(names_the_surface("csr.rs", "use crate::hw::{vga, pit};"));
        assert!(names_the_surface("hw/vga.rs", "use super::portio::Io;"));
        assert!(!names_the_surface(
            "hw/ide/read.rs",
            "use super::regs::DATA;"
        ));
        assert!(!names_the_surface("csr.rs", "crate::hw::vga::screen()"));
        assert!(!names_the_surface("csr.rs", "use crate::hw::{ide, kbd};"));
        assert!(issues_port_io(r#"asm!("out 0x80, al", in("al") 0xFEu8)"#));
        assert!(issues_port_io(r#"    "    in al, dx","#));
        assert!(!issues_port_io(r#"(1, "out of range"),"#));
        assert!(!issues_port_io(r#""nothing handed out yet""#));
    }
}
