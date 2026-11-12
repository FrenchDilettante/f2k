//! Interrupt routing: the table that takes a PCI function's interrupt pin to the ISA line the
//! platform routes it to, and that line to the hardware vector in the HAL's band.
//!
//! The route comes from the ISA bridge's PIRQ route-control registers, read at the boot scan
//! ([`pci::PirqRoutes`]): on bus 0 the slot/pin pair selects a PIRQ line by the platform's
//! rotation `(dev + pin - 1) mod 4`, and the line's route-control byte gives the ISA IRQ unless
//! its bit 7 disables the line. An explicit override ([`pci::set_route`]) is consulted before
//! that default — the seam a firmware routing table feeds. The ACPI `_PRT` / MADT
//! interrupt-source-override table is not parsed yet, so the seam stays recorded here: nothing
//! calls [`pci::set_route`] on target today.
//!
//! The interrupt controller's band stays sixteen device lines: a line outside it routes
//! nowhere. The vector is the HAL's mapping ([`hal::interrupt_vector`]); the line's IRQL is
//! [`line_irql`], and the affinity is every processor (there is one today). Together they are
//! what the HAL contract's vector query reports ([`line_vector`]).
//!
//! The controller side stays behind the interrupt core's
//! [`Controller`](crate::interrupt::Controller) seam, which the IO APIC slice joins later: routing
//! decides *which* vector a line takes, never how the chip is driven.

use super::Interrupt;
use crate::hal;
use crate::hw::pci;
use crate::interrupt::irql::{Irql, CLOCK, IDE, KEYBOARD};

/// The largest device line the HAL's vector band holds (line 15).
pub const MAX_LINE: u8 = hal::LAST_VECTOR - hal::FIRST_VECTOR;

/// The affinity every routed line carries: all processors (the one there is today).
pub const ALL_PROCESSORS: u32 = 0xFFFF_FFFF;

/// Route one PCI function's interrupt pin against the given PIRQ routes: the pin, the ISA line
/// and the line's vector, when the pin routes somewhere inside the band. A device with no pin
/// (pin 0), a route nowhere, or a line outside the band routes to nothing.
pub fn route_interrupt(
    routes: Option<&pci::PirqRoutes>,
    bus: u8,
    dev: u8,
    func: u8,
    pin: u8,
) -> Option<Interrupt> {
    if pin == 0 {
        return None;
    }
    let line = pci::route(bus, dev, func, pin, routes?)?;
    (line <= MAX_LINE).then(|| Interrupt {
        pin,
        isa_line: line,
        vector: hal::interrupt_vector(line),
    })
}

/// Route one PCI function's interrupt pin against the boot scan's PIRQ routes
/// ([`pci::routes`]).
pub fn routed_interrupt(bus: u8, dev: u8, func: u8, pin: u8) -> Option<Interrupt> {
    route_interrupt(pci::routes(), bus, dev, func, pin)
}

/// The IRQL a device line runs at: the level the kernel's own driver for the line connects at
/// (the interval timer on line 0, the keyboard on line 1, the IDE disk on line 14), and the
/// band's descending assignment (CLOCK − line) for the rest. A driver connecting an interrupt
/// object names its level itself; this is the level the vector query reports for the line.
pub fn line_irql(line: u8) -> Irql {
    match line {
        0 => CLOCK,
        1 => KEYBOARD,
        14 => IDE,
        n => Irql(CLOCK.0.saturating_sub(n)),
    }
}

/// The vector query's answer for one ISA device line: its system vector, its IRQL and its
/// affinity. `None` when the line lies outside the band — the caller reports the failed
/// translation as a zero affinity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LineVector {
    pub vector: u8,
    pub irql: Irql,
    pub affinity: u32,
}

/// The system vector, IRQL and affinity one ISA device line maps to in the HAL's band.
pub fn line_vector(line: u8) -> Option<LineVector> {
    (line <= MAX_LINE).then(|| LineVector {
        vector: hal::interrupt_vector(line),
        irql: line_irql(line),
        affinity: ALL_PROCESSORS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrupt::irql::{HIGH, PASSIVE};

    // PIRQA=5, PIRQB=10, PIRQC=11, PIRQD disabled.
    const ROUTES: pci::PirqRoutes = pci::PirqRoutes([0x05, 0x0A, 0x0B, 0x80]);

    /// The rotation routes slot and pin to a line and its vector: dev 1 pin 1 -> PIRQB -> IRQ 10
    /// -> vector 0x3A; a disabled line, a zero nibble, no pin and a line past the band route
    /// nowhere.
    #[test]
    fn a_pin_routes_to_its_line_and_vector() {
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 1, 0, 1),
            Some(Interrupt {
                pin: 1,
                isa_line: 10,
                vector: 0x3A
            })
        );
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 2, 0, 1),
            Some(Interrupt {
                pin: 1,
                isa_line: 11,
                vector: 0x3B
            })
        );
        // Pins rotate within a slot: dev 1 pin 2 is PIRQC too.
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 1, 0, 2).map(|i| i.isa_line),
            Some(11)
        );
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 3, 0, 1),
            None,
            "PIRQD is disabled"
        );
        assert_eq!(route_interrupt(Some(&ROUTES), 0, 1, 0, 0), None, "no pin");
        assert_eq!(
            route_interrupt(None, 0, 1, 0, 1),
            None,
            "no ISA bridge, no routes"
        );
        // The band check holds even if a route ever names a line past it.
        assert!(MAX_LINE == 15);
    }

    /// An override (the firmware-table seam) wins over the PIRQ default, including a line past
    /// the band check, and clearing it restores the default.
    #[test]
    fn an_override_wins_over_the_default() {
        // dev 20 pin 2: PIRQ index (20 + 2 - 1) mod 4 = 1 -> PIRQB -> IRQ 10.
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 20, 0, 2).map(|i| i.isa_line),
            Some(10)
        );
        pci::set_route(0, 20, 0, 2, Some(9));
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 20, 0, 2),
            Some(Interrupt {
                pin: 2,
                isa_line: 9,
                vector: hal::interrupt_vector(9)
            }),
            "the override wins"
        );
        pci::set_route(0, 20, 0, 2, None);
        assert_eq!(
            route_interrupt(Some(&ROUTES), 0, 20, 0, 2).map(|i| i.isa_line),
            Some(10),
            "cleared, the default applies"
        );
    }

    /// The vector query's answer: each line in the band maps to its vector, IRQL and the
    /// all-processors affinity; a line past the band fails (the caller reports zero affinity).
    #[test]
    fn a_line_maps_to_its_vector_irql_and_affinity() {
        let first = line_vector(0).unwrap();
        assert_eq!(first.vector, hal::FIRST_VECTOR);
        assert_eq!(first.irql, CLOCK);
        assert_eq!(first.affinity, ALL_PROCESSORS);

        let keyboard = line_vector(1).unwrap();
        assert_eq!(keyboard.vector, 0x31);
        assert_eq!(keyboard.irql, KEYBOARD);

        let ide = line_vector(14).unwrap();
        assert_eq!(ide.vector, 0x3E);
        assert_eq!(ide.irql, IDE);

        let last = line_vector(15).unwrap();
        assert_eq!(last.vector, hal::LAST_VECTOR);
        assert_eq!(last.irql, Irql(CLOCK.0 - 15));

        assert_eq!(line_vector(16), None, "past the band");
        assert_eq!(line_vector(255), None);

        // The band's IRQLs stay within the hardware floor and HIGH.
        for line in 0..=MAX_LINE {
            let irql = line_irql(line);
            assert!(irql >= Irql(13) && irql <= HIGH, "line {line} at {irql:?}");
            assert!(irql > PASSIVE);
        }
    }
}
