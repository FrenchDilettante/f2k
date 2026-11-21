//! The device tree, and the I/O manager the legacy drivers run under.
//!
//! A bus scan (today the PCI scan in [`crate::hw::pci`]) becomes a fixed-capacity registry of
//! [`DeviceNode`]s ([`Nodes`]): each node carries its bus and bus address, its hardware IDs, its
//! BARs, and its interrupt — the pin, the routed ISA line, and the vector the HAL's vector mapping
//! gives the line, through the routing table in [`routing`] ([`crate::hal::interrupt_vector`]).
//! [`Nodes::from_pci`] builds the registry from the scan's device table and PIRQ routes. Nothing
//! claims the nodes yet: the drivers F2K loads are legacy ones, which [`io`] loads and runs, their
//! structures in Windows 2000's layout ([`ntddk`]) and their exports in [`ntoskrnl`].

pub mod io;
pub mod irp;
pub mod loader;
pub mod ntddk;
pub mod ntoskrnl;
pub mod routing;

use crate::hw::pci::{self, Bar};
use crate::sync::{InitOnce, StaticBuf};

// --- The device tree ------------------------------------------------------------------------

/// The bus a node sits on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bus {
    /// A PCI function.
    Pci,
}

/// A node's address on its bus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BusAddress {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

/// A node's interrupt: the pin, the routed ISA line, and the line's vector in the HAL's hardware
/// vector band.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interrupt {
    pub pin: u8,
    pub isa_line: u8,
    pub vector: u8,
}

/// A node in the device tree: one function a bus scan found, with its IDs and its resources.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceNode {
    pub id: NodeId,
    pub bus: Bus,
    pub address: BusAddress,
    pub vendor: u16,
    pub device: u16,
    /// The 24-bit class code: base class, subclass, prog IF.
    pub class_code: u32,
    pub revision: u8,
    /// The interrupt pin the function reports (0 when it does not interrupt).
    pub interrupt_pin: u8,
    /// The routed interrupt (pin, ISA line, vector), when the pin routes somewhere.
    pub interrupt: Option<Interrupt>,
    pub bars: [Bar; 6],
}

impl DeviceNode {
    pub const fn new(
        bus: Bus,
        address: BusAddress,
        vendor: u16,
        device: u16,
        class_code: u32,
        revision: u8,
        interrupt_pin: u8,
        interrupt: Option<Interrupt>,
        bars: [Bar; 6],
    ) -> Self {
        DeviceNode {
            id: NodeId(0),
            bus,
            address,
            vendor,
            device,
            class_code,
            revision,
            interrupt_pin,
            interrupt,
            bars,
        }
    }
}

/// A node's id: its index in the registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeId(pub u16);

/// The registry's capacity, matching the PCI scan table's.
pub const MAX_NODES: usize = pci::MAX_DEVICES;

const EMPTY_NODE: DeviceNode = DeviceNode::new(
    Bus::Pci,
    BusAddress {
        bus: 0,
        dev: 0,
        func: 0,
    },
    0,
    0,
    0,
    0,
    0,
    None,
    [Bar::None; 6],
);

/// The device tree: a fixed-capacity table of nodes (no allocator at this layer).
pub struct Nodes {
    nodes: [DeviceNode; MAX_NODES],
    count: usize,
}

impl Nodes {
    pub const fn new() -> Self {
        Nodes {
            nodes: [EMPTY_NODE; MAX_NODES],
            count: 0,
        }
    }

    /// Build the registry from a bus scan's devices and its interrupt routes
    /// ([`Nodes::fill_from_pci`]), by value: for the host tests. The kernel fills its registry
    /// in place instead, since a `Nodes` is tens of KiB and the kernel builds at opt-level 0,
    /// where a by-value registry sits on the stack.
    #[cfg(test)]
    pub fn from_pci<'a>(
        devices: impl IntoIterator<Item = &'a pci::Device>,
        routes: Option<&pci::PirqRoutes>,
    ) -> Self {
        let mut nodes = Nodes::new();
        nodes.fill_from_pci(devices, routes);
        nodes
    }

    /// Add a bus scan's devices to the registry, with their interrupt routes: each device becomes
    /// a PCI node whose interrupt is the pin routed to an ISA line and mapped to its vector, when
    /// the pin routes somewhere in the HAL's vector band (see [`routing`]).
    pub fn fill_from_pci<'a>(
        &mut self,
        devices: impl IntoIterator<Item = &'a pci::Device>,
        routes: Option<&pci::PirqRoutes>,
    ) {
        for d in devices {
            let interrupt = routing::route_interrupt(routes, d.bus, d.dev, d.func, d.interrupt_pin);
            self.push(DeviceNode::new(
                Bus::Pci,
                BusAddress {
                    bus: d.bus,
                    dev: d.dev,
                    func: d.func,
                },
                d.vendor,
                d.device,
                d.class_code,
                d.revision,
                d.interrupt_pin,
                interrupt,
                d.bars,
            ));
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// The nodes, in enumeration order.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceNode> {
        self.nodes[..self.count].iter()
    }

    /// Add a node, assigning its id. Returns `None` when the registry is full.
    pub fn push(&mut self, node: DeviceNode) -> Option<NodeId> {
        if self.count >= MAX_NODES {
            return None;
        }
        let id = NodeId(self.count as u16);
        self.nodes[self.count] = DeviceNode { id, ..node };
        self.count += 1;
        Some(id)
    }
}

impl Default for Nodes {
    fn default() -> Self {
        Self::new()
    }
}

static NODES: StaticBuf<Nodes> = StaticBuf::new(Nodes::new());
static NODES_REF: InitOnce<&'static Nodes> = InitOnce::new();

/// Fill the global node registry from the boot's PCI scan and keep it for the kernel's lifetime.
pub fn init_nodes_from_pci() -> &'static Nodes {
    // Filled where it lies: a by-value registry would sit on the boot stack.
    let nodes = NODES.take();
    nodes.fill_from_pci(pci::devices().iter(), pci::routes());
    NODES_REF.set(&*nodes);
    NODES_REF.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal;

    /// The registry carries the scan's IDs, BARs and class, and the routed interrupt with its
    /// HAL vector.
    #[test]
    fn nodes_from_pci_carry_the_scan_and_the_routing() {
        let devices = [
            pci::Device {
                bus: 0,
                dev: 1,
                func: 3,
                vendor: 0x8086,
                device: 0x7000,
                revision: 0x02,
                class_code: 0x0601_00,
                header_type: 0x81,
                bars: [Bar::None; 6],
                interrupt_pin: 1,
                interrupt_line: 0xFF,
            },
            pci::Device {
                bus: 0,
                dev: 2,
                func: 0,
                vendor: 0x10EC,
                device: 0x8139,
                revision: 0x01,
                class_code: 0x0200_00,
                header_type: 0x00,
                bars: [
                    Bar::Memory {
                        base: 0xE100_0000,
                        size: 0x2000,
                        prefetchable: false,
                        wide: false,
                    },
                    Bar::Io(0xD000),
                    Bar::None,
                    Bar::None,
                    Bar::None,
                    Bar::None,
                ],
                interrupt_pin: 3,
                interrupt_line: 0x0B,
            },
            pci::Device {
                bus: 0,
                dev: 4,
                func: 0,
                vendor: 0x8086,
                device: 0x1237,
                revision: 0x02,
                class_code: 0x0601_00,
                header_type: 0x00,
                bars: [Bar::None; 6],
                interrupt_pin: 0,
                interrupt_line: 0xFF,
            },
        ];
        // PIRQA=5, PIRQB=10, PIRQC=11, PIRQD disabled.
        let routes = pci::PirqRoutes([0x05, 0x0A, 0x0B, 0x80]);

        let nodes = Nodes::from_pci(&devices, Some(&routes));
        assert_eq!(nodes.len(), 3);

        let found: std::vec::Vec<&DeviceNode> = nodes.iter().collect();
        assert_eq!(
            found
                .iter()
                .map(|node| node.id)
                .collect::<std::vec::Vec<_>>(),
            [NodeId(0), NodeId(1), NodeId(2)],
            "the ids are the enumeration order"
        );

        let bridge = found[0];
        assert_eq!(bridge.bus, Bus::Pci);
        assert_eq!(
            bridge.address,
            BusAddress {
                bus: 0,
                dev: 1,
                func: 3
            }
        );
        assert_eq!((bridge.vendor, bridge.device), (0x8086, 0x7000));
        assert_eq!(bridge.class_code, 0x0601_00);
        assert_eq!(bridge.revision, 0x02);
        // dev 1, pin 1 -> PIRQ index (1 + 1 - 1) mod 4 = 1 -> IRQ 10.
        assert_eq!(
            bridge.interrupt,
            Some(Interrupt {
                pin: 1,
                isa_line: 10,
                vector: hal::interrupt_vector(10)
            })
        );

        let nic = found[1];
        // dev 2, pin 3 -> PIRQ index (2 + 3 - 1) mod 4 = 0 -> IRQ 5.
        assert_eq!(
            nic.interrupt,
            Some(Interrupt {
                pin: 3,
                isa_line: 5,
                vector: hal::interrupt_vector(5)
            })
        );
        assert_eq!(
            nic.bars[0],
            Bar::Memory {
                base: 0xE100_0000,
                size: 0x2000,
                prefetchable: false,
                wide: false
            }
        );
        assert_eq!(nic.bars[1], Bar::Io(0xD000));

        let no_pin = found[2];
        assert_eq!(no_pin.interrupt_pin, 0);
        assert_eq!(
            no_pin.interrupt, None,
            "a device without a pin has no interrupt"
        );
        assert_eq!(no_pin.bars, [Bar::None; 6]);

        // Without routes, the pins have no lines.
        let unrouted = Nodes::from_pci(&devices, None);
        assert_eq!(unrouted.iter().next().unwrap().interrupt, None);
    }
}
