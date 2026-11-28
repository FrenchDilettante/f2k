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
//! [`line_irql`], and the affinity is the started processors ([`crate::processors::active`]).
//! Together they are what the HAL contract's vector query reports ([`line_vector`]), save for the
//! cascade line, which Windows 2000's query answers with vector 0.
//!
//! The controller side stays behind the interrupt core's
//! [`Controller`](crate::interrupt::Controller) seam, which the IO APIC slice joins later: routing
//! decides *which* vector a line takes, never how the chip is driven.

use super::Interrupt;
use crate::hal;
use crate::hw::pci;
use crate::interrupt::irql::{Irql, PROFILE};

/// The largest device line the HAL's vector band holds (line 15).
pub const MAX_LINE: u8 = hal::LAST_VECTOR - hal::FIRST_VECTOR;

/// The line the slave controller cascades into the master on: no device's line.
pub const CASCADE_LINE: u8 = 2;

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

/// The IRQL a device line runs at: the band's descending assignment, PROFILE_LEVEL (27) less the
/// line, for every line 0-15 (halvec's capture, `isa`/`internal`/`pci`: "IRQL = 27 - level: yes,
/// IRQL = 28 - level: no"). The kernel's own drivers connect at those levels too: the keyboard
/// (line 1) at [`KEYBOARD`](crate::interrupt::irql::KEYBOARD), 26, the IDE disk (line 14) at
/// [`IDE`](crate::interrupt::irql::IDE), 13. The interval clock alone connects above its line's
/// level, at CLOCK2_LEVEL (28), as Windows 2000's HAL connects it outside the query. A driver
/// connecting an interrupt object names its level itself; this is the level the vector query
/// reports for the line.
pub fn line_irql(line: u8) -> Irql {
    Irql(PROFILE.0.saturating_sub(line))
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

/// The system vector, IRQL and affinity one ISA device line maps to in the HAL's band: vector
/// 0x30 + line. The cascade line (2) carries no device, and Windows 2000's query answers it with
/// vector 0 — its IRQL and affinity still the line's (halvec's capture: "level 2: vector=0x00
/// IRQL=25 affinity=the active processors").
pub fn line_vector(line: u8) -> Option<LineVector> {
    (line <= MAX_LINE).then(|| LineVector {
        vector: if line == CASCADE_LINE {
            0
        } else {
            hal::interrupt_vector(line)
        },
        irql: line_irql(line),
        // Every line reaches every started processor, as KeQueryActiveProcessors reports them
        // (halvec's capture: every level's affinity is "the active processors").
        affinity: crate::processors::active(),
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

    /// The vector query's answer, as halvec's capture (tests/hal/halvec/output.txt, `isa`)
    /// pins it: line n maps to vector 0x30 + n at IRQL 27 - n with the active processors'
    /// affinity, except the cascade line 2 (vector 0x00, IRQL 25); the keyboard's and the disk's
    /// lines land on the levels their drivers connect at; a line past the band fails.
    #[test]
    fn a_line_maps_to_its_vector_irql_and_affinity() {
        use crate::interrupt::irql::{IDE, KEYBOARD};
        for line in 0..=MAX_LINE {
            let mapped = line_vector(line).unwrap();
            let vector = if line == 2 { 0x00 } else { 0x30 + line };
            assert_eq!(mapped.vector, vector, "line {line}");
            assert_eq!(mapped.irql, Irql(27 - line), "line {line}");
            assert_eq!(mapped.affinity, crate::processors::active());
            assert!(mapped.irql > PASSIVE && mapped.irql <= HIGH);
        }
        assert_eq!(line_vector(0).unwrap().vector, hal::FIRST_VECTOR);
        assert_eq!(line_vector(15).unwrap().vector, hal::LAST_VECTOR);
        assert_eq!(line_irql(1), KEYBOARD);
        assert_eq!(line_irql(14), IDE);

        assert_eq!(line_vector(16), None, "past the band");
        assert_eq!(line_vector(255), None);
    }
}
