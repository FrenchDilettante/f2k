//! PCI bus enumeration: the configuration-space seam, the bus walk, the device records, and
//! PIRQ interrupt routing.
//!
//! Configuration space is reached through the [`ConfigIo`] seam — dword reads and writes of
//! one function's registers, addressed by [`ConfigAddress`] (configuration mechanism #1: the
//! address dword's bit 31 enables the cycle, bits 23-16 carry the bus number, 15-11 the device,
//! 10-8 the function, 7-2 the dword-aligned register number). On target the seam is the
//! mechanism's address and data ports, selected with [`ConfigAddress::dword`]; the host tests
//! run it against a simulated config space.
//!
//! [`scan`] walks bus 0's 32 devices — all eight functions of a multifunction device (header
//! type bit 7), function 0 only otherwise — and recurses into PCI-to-PCI bridges (class 0x06,
//! subclass 0x04) through the secondary-bus register, so every reachable function lands in the
//! fixed-capacity [`Devices`] table with its IDs, revision, 24-bit class code, header type,
//! sized BARs (a 64-bit memory BAR consumes two slots), and interrupt pin/line. An empty slot
//! reads vendor 0xFFFF and is skipped.
//!
//! Interrupt routing starts at the ISA bridge's four PIRQ route-control registers (class 0x06,
//! subclass 0x01, config offsets 0x60-0x63): on bus 0 a device's pin selects the PIRQ line by
//! the platform's rotation `(dev + pin - 1) mod 4`, and the line's byte gives the ISA IRQ
//! unless its bit 7 disables the line. [`set_route`] records explicit per-device overrides
//! (the seam a firmware routing table feeds), consulted before that default.

// The boot calls [`init`], which fills the scan table and the routes; the routing override
// table is the later slices' seam, so the target build sees no caller for it yet.
#![cfg_attr(not(test), allow(dead_code))]

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::Io;
use crate::sync::{InitOnce, StaticBuf};

// Configuration-space register offsets (dword-aligned unless noted).
/// Vendor ID (0x00) and device ID (0x02) share the first dword.
pub const VENDOR_DEVICE: u8 = 0x00;
/// Revision ID (0x08), then the 24-bit class code (prog IF, subclass, base class) at 0x09-0x0B.
pub const REVISION_CLASS: u8 = 0x08;
/// Header type at 0x0E, inside the dword at 0x0C.
pub const HEADER_TYPE: u8 = 0x0C;
/// BAR0; BARs run 0x10-0x27, six slots.
pub const BAR: u8 = 0x10;
/// The last BAR slot's offset (0x27 is the high byte of BAR5).
pub const BAR_END: u8 = 0x28;
/// The bridge header's bus-number registers: primary 0x18, secondary 0x19, subordinate 0x1A.
pub const BRIDGE_BUS_NUMBERS: u8 = 0x18;
/// Interrupt line (0x3C) and pin (0x3D) share the dword at 0x3C.
pub const INTERRUPT_LINE: u8 = 0x3C;
/// The ISA bridge's PIRQ route-control registers, 0x60-0x63.
pub const PIRQ_ROUTE_CONTROL: u8 = 0x60;

/// The vendor ID an empty slot reads.
pub const INVALID_VENDOR: u16 = 0xFFFF;

/// Devices per bus and functions per device.
pub const MAX_DEVICES_PER_BUS: u8 = 32;
pub const MAX_FUNCTIONS: u8 = 8;

/// The scan table's capacity: a fixed array plus a count, since this layer runs before any
/// allocator exists.
pub const MAX_DEVICES: usize = 256;

// Header type: bit 7 marks a multifunction device; the low bits give the layout (0 = general
// device with six BARs, 1 = PCI-to-PCI bridge with two BARs, 2 = CardBus).
const HEADER_TYPE_MULTIFUNCTION: u32 = 0x80 << 16;
const HEADER_LAYOUT_MASK: u8 = 0x7F;

// BAR encodings: bit 0 set = I/O space, memory type in bits 2-1 (3 = 64-bit), bit 3 =
// prefetchable; the address masks clear the low bits.
const BAR_IO: u32 = 0x1;
const BAR_TYPE_64BIT: u32 = 0x3;
const BAR_PREFETCHABLE: u32 = 0x8;
const IO_ADDRESS_MASK: u32 = 0xFFFF_FFFC;
const MEMORY_ADDRESS_MASK: u32 = 0xFFFF_FFF0;

/// A PCI configuration-space register address: bus, device (slot), function, and the
/// register offset within the function's 256-byte space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfigAddress {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub offset: u8,
}

impl ConfigAddress {
    pub const fn new(bus: u8, dev: u8, func: u8, offset: u8) -> Self {
        Self {
            bus,
            dev,
            func,
            offset,
        }
    }

    /// The configuration-mechanism-#1 address dword for this register: bit 31 set to enable
    /// the cycle, bus in bits 23-16, device in 15-11, function in 10-8, the dword-aligned
    /// register number in 7-2.
    pub const fn dword(&self) -> u32 {
        0x8000_0000
            | (self.bus as u32) << 16
            | (self.dev as u32) << 11
            | (self.func as u32) << 8
            | (self.offset as u32) & 0xFC
    }
}

/// The configuration-space access seam: dword reads and writes of one function's registers.
/// The port-based adapter (the mechanism's address/data ports) implements this on target; the
/// host tests implement it over a simulated config space.
pub trait ConfigIo {
    /// Read one dword-aligned register.
    fn read_config(&mut self, addr: ConfigAddress) -> u32;
    /// Write one dword-aligned register.
    fn write_config(&mut self, addr: ConfigAddress, value: u32);
}

/// The configuration mechanism's address port: the address dword goes here.
pub const CONFIG_ADDRESS_PORT: u16 = 0xCF8;
/// The configuration mechanism's data port: the selected register's dword reads/writes here.
pub const CONFIG_DATA_PORT: u16 = 0xCFC;

/// The seam over the port space: configuration mechanism #1's address/data port pair, reached
/// through the [`Io`] abstraction like every device's registers. On target `io` is the real
/// port space; the host tests hand it a simulated one.
pub struct PortsConfig<IoT: Io> {
    io: IoT,
}

impl<IoT: Io> PortsConfig<IoT> {
    pub const fn new(io: IoT) -> Self {
        PortsConfig { io }
    }
}

impl<IoT: Io> ConfigIo for PortsConfig<IoT> {
    fn read_config(&mut self, addr: ConfigAddress) -> u32 {
        self.io.out_dword(CONFIG_ADDRESS_PORT, addr.dword());
        self.io.read_dword(CONFIG_DATA_PORT)
    }

    fn write_config(&mut self, addr: ConfigAddress, value: u32) {
        self.io.out_dword(CONFIG_ADDRESS_PORT, addr.dword());
        self.io.out_dword(CONFIG_DATA_PORT, value);
    }
}

// The boot's scan table lives in bss, not on the boot stack (a 24 KiB stack local would
// overflow it into the frame table beside it): the scan fills the static buffer directly.
static SCAN: StaticBuf<Devices> = StaticBuf::new(Devices::new());
static SCAN_REF: InitOnce<&'static Devices> = InitOnce::new();
static ROUTES: InitOnce<Option<PirqRoutes>> = InitOnce::new();

/// The devices the boot scan found ([`init`]).
pub fn devices() -> &'static Devices {
    SCAN_REF.get()
}

/// The ISA bridge's PIRQ routes the boot read; `None` when the bus has no ISA bridge.
pub fn routes() -> Option<&'static PirqRoutes> {
    ROUTES.get().as_ref()
}

/// Scan the PCI bus at boot, over the config address/data ports, keep the device table and the
/// PIRQ routes for the later driver slices, and report the enumeration on COM1.
#[cfg(target_arch = "x86")]
pub fn init() {
    let mut cfg = PortsConfig::new(crate::hal::Ports);
    let devices = SCAN.take();
    scan_into(&mut cfg, devices);
    SCAN_REF.set(&*devices);
    let routes = PirqRoutes::read(&mut cfg, devices);
    crate::serial_println!("F2K: pci: {} devices", devices.len());
    for d in devices.iter() {
        let irq = if d.interrupt_pin == 0 {
            None
        } else {
            routes
                .as_ref()
                .and_then(|r| route(d.bus, d.dev, d.func, d.interrupt_pin, r))
        };
        if let Some(irq) = irq {
            crate::serial_println!(
                "F2K: pci: {:02x}:{:02x}.{} {:04x}:{:04x} class {:06x} rev {:02x} pin {} irq {}",
                d.bus,
                d.dev,
                d.func,
                d.vendor,
                d.device,
                d.class_code,
                d.revision,
                d.interrupt_pin,
                irq
            );
        } else {
            crate::serial_println!(
                "F2K: pci: {:02x}:{:02x}.{} {:04x}:{:04x} class {:06x} rev {:02x} pin {} irq -",
                d.bus,
                d.dev,
                d.func,
                d.vendor,
                d.device,
                d.class_code,
                d.revision,
                d.interrupt_pin
            );
        }
    }
    ROUTES.set(routes);
}

/// One base address register, decoded and sized.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    /// The slot is not implemented (sizing it reads back zero).
    None,
    /// An I/O BAR: the base address (bits 31-2).
    Io(u32),
    /// A memory BAR: the base address, the sized extent in bytes, whether it is
    /// prefetchable, and whether it is 64-bit (its upper half occupied the next slot).
    Memory {
        base: u32,
        size: u32,
        prefetchable: bool,
        wide: bool,
    },
}

/// One enumerated function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Device {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
    /// The 24-bit class code: base class, subclass, prog IF.
    pub class_code: u32,
    pub header_type: u8,
    pub bars: [Bar; 6],
    pub interrupt_pin: u8,
    pub interrupt_line: u8,
}

impl Device {
    /// The base class code.
    pub fn class(&self) -> u8 {
        (self.class_code >> 16) as u8
    }

    /// The subclass code.
    pub fn subclass(&self) -> u8 {
        (self.class_code >> 8) as u8
    }

    /// Whether header-type bit 7 marks the device multifunction.
    pub fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }

    /// Whether this is a PCI-to-PCI bridge (class 0x06, subclass 0x04).
    pub fn is_pci_bridge(&self) -> bool {
        self.class() == 0x06 && self.subclass() == 0x04
    }

    /// Whether this is the ISA bridge (class 0x06, subclass 0x01) carrying the PIRQ
    /// route-control registers.
    pub fn is_isa_bridge(&self) -> bool {
        self.class() == 0x06 && self.subclass() == 0x01
    }
}

const EMPTY_DEVICE: Device = Device {
    bus: 0,
    dev: 0,
    func: 0,
    vendor: INVALID_VENDOR,
    device: 0,
    revision: 0,
    class_code: 0,
    header_type: 0,
    bars: [Bar::None; 6],
    interrupt_pin: 0,
    interrupt_line: 0,
};

/// The devices a scan found, in a fixed-capacity table (no allocator at this layer): the
/// array plus the count of entries in use.
pub struct Devices {
    devices: [Device; MAX_DEVICES],
    count: usize,
}

impl Devices {
    pub const fn new() -> Self {
        Devices {
            devices: [EMPTY_DEVICE; MAX_DEVICES],
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The devices found, in enumeration order.
    pub fn as_slice(&self) -> &[Device] {
        &self.devices[..self.count]
    }

    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.as_slice().iter()
    }

    /// The device at an exact bus/device/function address, if the scan found one.
    pub fn find(&self, bus: u8, dev: u8, func: u8) -> Option<&Device> {
        self.as_slice()
            .iter()
            .find(|d| d.bus == bus && d.dev == dev && d.func == func)
    }

    fn has_room(&self) -> bool {
        self.count < MAX_DEVICES
    }

    fn push(&mut self, device: Device) {
        if self.has_room() {
            self.devices[self.count] = device;
            self.count += 1;
        }
    }
}

impl Default for Devices {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a Devices {
    type IntoIter = core::slice::Iter<'a, Device>;
    type Item = &'a Device;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// Scan every reachable PCI function, starting at bus 0: all 32 devices, each one's functions
/// (all eight for a multifunction device, function 0 otherwise), recursing into PCI-to-PCI
/// bridges through their secondary-bus register. Empty slots (vendor 0xFFFF) are skipped.
pub fn scan<C: ConfigIo>(cfg: &mut C) -> Devices {
    let mut devices = Devices::new();
    scan_into(cfg, &mut devices);
    devices
}

/// Scan into an existing table. The boot scans into its static table directly: a 24 KiB
/// [`Devices`] as a stack local would overflow the boot stack into the bss beside it.
pub fn scan_into<C: ConfigIo>(cfg: &mut C, devices: &mut Devices) {
    let mut visited = [false; 256];
    visited[0] = true;
    scan_bus(cfg, 0, devices, &mut visited);
}

fn scan_bus<C: ConfigIo>(cfg: &mut C, bus: u8, devices: &mut Devices, visited: &mut [bool; 256]) {
    for dev in 0..MAX_DEVICES_PER_BUS {
        if read_vendor(cfg, bus, dev, 0) == INVALID_VENDOR {
            continue;
        }
        let header = cfg.read_config(ConfigAddress::new(bus, dev, 0, HEADER_TYPE));
        let functions = if header & HEADER_TYPE_MULTIFUNCTION != 0 {
            0..MAX_FUNCTIONS
        } else {
            0..1
        };
        for func in functions {
            if func != 0 && read_vendor(cfg, bus, dev, func) == INVALID_VENDOR {
                continue;
            }
            let device = read_device(cfg, bus, dev, func);
            let secondary = if device.is_pci_bridge() {
                let buses = cfg.read_config(ConfigAddress::new(bus, dev, func, BRIDGE_BUS_NUMBERS));
                Some((buses >> 8) as u8) // the secondary-bus register is offset 0x19
            } else {
                None
            };
            devices.push(device);
            if let Some(secondary) = secondary {
                let known = visited[secondary as usize];
                if secondary != 0 && !known && devices.has_room() {
                    visited[secondary as usize] = true;
                    scan_bus(cfg, secondary, devices, visited);
                }
            }
        }
    }
}

fn read_vendor<C: ConfigIo>(cfg: &mut C, bus: u8, dev: u8, func: u8) -> u16 {
    cfg.read_config(ConfigAddress::new(bus, dev, func, VENDOR_DEVICE)) as u16
}

/// Read one function's common header and size its BARs into a device record.
fn read_device<C: ConfigIo>(cfg: &mut C, bus: u8, dev: u8, func: u8) -> Device {
    let addr = |offset: u8| ConfigAddress::new(bus, dev, func, offset);
    let vendor_device = cfg.read_config(addr(VENDOR_DEVICE));
    let revision_class = cfg.read_config(addr(REVISION_CLASS));
    let header = cfg.read_config(addr(HEADER_TYPE));
    let header_type = (header >> 16) as u8;

    // Only the type-0 layout carries six BARs; a bridge header has two, and past them sit
    // the bus-number registers, which the sizing probe must not touch.
    let bar_slots = match header_type & HEADER_LAYOUT_MASK {
        0 => 6,
        1 => 2,
        _ => 0,
    };
    let mut bars = [Bar::None; 6];
    let mut slot = 0;
    while slot < bar_slots {
        let offset = BAR + 4 * slot as u8;
        let original = cfg.read_config(addr(offset));
        cfg.write_config(addr(offset), 0xFFFF_FFFF);
        let sized = cfg.read_config(addr(offset));
        cfg.write_config(addr(offset), original);
        let (bar, used) = size_bar(cfg, addr(offset), original, sized);
        bars[slot] = bar;
        slot += used;
    }

    let interrupts = cfg.read_config(addr(INTERRUPT_LINE));
    Device {
        bus,
        dev,
        func,
        vendor: vendor_device as u16,
        device: (vendor_device >> 16) as u16,
        revision: revision_class as u8,
        class_code: (revision_class >> 8) & 0x00FF_FFFF,
        header_type,
        bars,
        interrupt_line: interrupts as u8,
        interrupt_pin: (interrupts >> 8) as u8,
    }
}

/// Decode one BAR from its value before the probe (`original`) and its read-back after the
/// all-ones write (`sized`). Returns the BAR and how many slots it consumed: two for a
/// 64-bit memory BAR, whose upper half sits in the next slot.
fn size_bar<C: ConfigIo>(
    cfg: &mut C,
    addr: ConfigAddress,
    original: u32,
    sized: u32,
) -> (Bar, usize) {
    if sized & BAR_IO != 0 {
        let mask = sized & IO_ADDRESS_MASK;
        let size = (!mask).wrapping_add(1);
        if size == 0 {
            (Bar::None, 1)
        } else {
            (Bar::Io(original & IO_ADDRESS_MASK), 1)
        }
    } else {
        // Memory BAR: type in bits 2-1 (3 = 64-bit), bit 3 prefetchable.
        let wide = (sized >> 1) & 0x3 == BAR_TYPE_64BIT;
        let prefetchable = sized & BAR_PREFETCHABLE != 0;
        let low = (sized & MEMORY_ADDRESS_MASK) as u64;
        let mask = if wide {
            let upper = ConfigAddress {
                offset: addr.offset + 4,
                ..addr
            };
            let upper_original = cfg.read_config(upper);
            cfg.write_config(upper, 0xFFFF_FFFF);
            let upper_sized = cfg.read_config(upper);
            cfg.write_config(upper, upper_original);
            low | (upper_sized as u64) << 32
        } else {
            low
        };
        let size = (!mask).wrapping_add(1);
        let used = if wide { 2 } else { 1 };
        if size == 0 {
            (Bar::None, used)
        } else {
            // The size field is 32 bits: an extent of 4 GiB or more keeps its low 32 bits.
            (
                Bar::Memory {
                    base: original & MEMORY_ADDRESS_MASK,
                    size: size as u32,
                    prefetchable,
                    wide,
                },
                used,
            )
        }
    }
}

/// The four PIRQ route-control registers of the ISA bridge (config offsets 0x60-0x63): one
/// byte per PIRQ line, its low nibble the ISA IRQ the line routes to, bit 7 set when the line
/// is disabled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PirqRoutes(pub [u8; 4]);

impl PirqRoutes {
    /// Read the route-control registers from the ISA bridge (class 0x06, subclass 0x01) on
    /// bus 0, as the scan found it. `None` when the bus has no ISA bridge.
    pub fn read<C: ConfigIo>(cfg: &mut C, devices: &Devices) -> Option<PirqRoutes> {
        let bridge = devices.iter().find(|d| d.bus == 0 && d.is_isa_bridge())?;
        let dword = cfg.read_config(ConfigAddress::new(
            0,
            bridge.dev,
            bridge.func,
            PIRQ_ROUTE_CONTROL,
        ));
        Some(PirqRoutes([
            dword as u8,
            (dword >> 8) as u8,
            (dword >> 16) as u8,
            (dword >> 24) as u8,
        ]))
    }
}

/// Route a device's interrupt pin to an ISA IRQ.
///
/// The explicit override table ([`set_route`]) is consulted first. Otherwise, on bus 0 the
/// slot/pin pair selects a PIRQ line by the rotation `(dev + pin - 1) mod 4`, and the line's
/// route-control byte gives the IRQ: `None` when the line is disabled (bit 7 set) or its IRQ
/// nibble is zero. Any other bus routes `None` for now (bridged devices' routing comes from a
/// firmware table through the override seam), and so does a device with no pin (pin 0).
pub fn route(bus: u8, dev: u8, func: u8, pin: u8, routes: &PirqRoutes) -> Option<u8> {
    if let Some(irq) = routed_override(bus, dev, func, pin) {
        return Some(irq);
    }
    if bus != 0 || pin == 0 {
        return None;
    }
    let control = routes.0[(dev as usize + pin as usize - 1) % 4];
    if control & 0x80 != 0 {
        return None; // the PIRQ line is disabled
    }
    let irq = control & 0x0F;
    if irq == 0 {
        None
    } else {
        Some(irq)
    }
}

/// The override table's capacity.
const MAX_OVERRIDES: usize = 16;

// One packed override per slot (the target is 32-bit, so the entry fits one atomic word):
// bits 0-7 bus, 8-12 device, 13-15 function, 16-18 pin, 19-22 the ISA IRQ, bit 23 set while
// the slot is in use; zero is a free slot.
const OVERRIDE_USED: u32 = 1 << 23;
const OVERRIDE_KEY: u32 = 0x0007_FFFF; // the bus/dev/func/pin bits (0-18)
const OVERRIDE_IRQ: u32 = 0xF << 19;

static ROUTE_OVERRIDES: [AtomicU32; MAX_OVERRIDES] = [const { AtomicU32::new(0) }; MAX_OVERRIDES];

fn override_key(bus: u8, dev: u8, func: u8, pin: u8) -> u32 {
    bus as u32
        | (dev as u32 & 0x1F) << 8
        | (func as u32 & 0x7) << 13
        | (pin as u32 & 0x7) << 16
        | OVERRIDE_USED
}

/// Record an explicit route for one device pin, consulted before the PIRQ default:
/// `Some(irq)` overrides the default (including on secondary buses), `None` clears the
/// override so the default applies again. A full table drops new entries.
pub fn set_route(bus: u8, dev: u8, func: u8, pin: u8, irq: Option<u8>) {
    let key = override_key(bus, dev, func, pin);
    for slot in ROUTE_OVERRIDES.iter() {
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let in_use = current & OVERRIDE_USED != 0;
            let matches = in_use && current & OVERRIDE_KEY == key & OVERRIDE_KEY;
            let free = current == 0;
            if matches || (free && irq.is_some()) {
                let new = match irq {
                    Some(irq) => key | (irq as u32 & 0xF) << 19,
                    None => 0,
                };
                match slot.compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
                {
                    Ok(_) => return,
                    Err(actual) => current = actual,
                }
            } else {
                break;
            }
        }
    }
}

fn routed_override(bus: u8, dev: u8, func: u8, pin: u8) -> Option<u8> {
    let key = override_key(bus, dev, func, pin);
    for slot in ROUTE_OVERRIDES.iter() {
        let current = slot.load(Ordering::Relaxed);
        if current & OVERRIDE_USED != 0 && current & OVERRIDE_KEY == key & OVERRIDE_KEY {
            return Some(((current & OVERRIDE_IRQ) >> 19) as u8);
        }
    }
    None
}

// --- Byte-granular config access and the bus-data surface ------------------------------------

/// The BUS_DATA_TYPE value that names PCI configuration space (the documented enum's
/// `PCIConfiguration`).
pub const PCI_CONFIGURATION: i32 = 4;

/// A slot number's parts, as the documented `PCI_SLOT_NUMBER` lays them out: the device number
/// in bits 3-7, the function in bits 0-2 (slot = device << 3 | function).
pub fn slot_parts(slot: u32) -> (u8, u8) {
    (((slot >> 3) & 0x1F) as u8, (slot & 0x7) as u8)
}

/// Whether the scan found the bus: bus 0 always exists (the config mechanism is there), any
/// other bus exists when the scan found a function on it.
pub fn bus_exists(devices: &Devices, bus: u8) -> bool {
    bus == 0 || devices.iter().any(|d| d.bus == bus)
}

/// Read up to `buffer.len()` bytes of a function's configuration space starting at byte
/// `offset`, through dword config accesses (an unaligned start or tail is assembled from the
/// covering dwords). Returns the bytes read: the buffer's length capped at the 256-byte space
/// past `offset`.
pub fn read_config_bytes<C: ConfigIo>(
    cfg: &mut C,
    bus: u8,
    dev: u8,
    func: u8,
    offset: u8,
    buffer: &mut [u8],
) -> usize {
    let start = offset as usize;
    let count = buffer.len().min(256 - start);
    let mut done = 0;
    while done < count {
        let at = (start + done) & !3;
        let dword = cfg.read_config(ConfigAddress::new(bus, dev, func, at as u8));
        let bytes = dword.to_le_bytes();
        let skip = (start + done) - at;
        let take = (count - done).min(4 - skip);
        buffer[done..done + take].copy_from_slice(&bytes[skip..skip + take]);
        done += take;
    }
    count
}

/// Write `buffer` into a function's configuration space starting at byte `offset`,
/// read-modify-write per touched dword so the bytes beside the written range keep their values.
/// Returns the bytes written, capped like [`read_config_bytes`].
pub fn write_config_bytes<C: ConfigIo>(
    cfg: &mut C,
    bus: u8,
    dev: u8,
    func: u8,
    offset: u8,
    buffer: &[u8],
) -> usize {
    let start = offset as usize;
    let count = buffer.len().min(256 - start);
    let mut done = 0;
    while done < count {
        let at = (start + done) & !3;
        let addr = ConfigAddress::new(bus, dev, func, at as u8);
        let mut dword = cfg.read_config(addr);
        let mut bytes = dword.to_le_bytes();
        let skip = (start + done) - at;
        let take = (count - done).min(4 - skip);
        bytes[skip..skip + take].copy_from_slice(&buffer[done..done + take]);
        dword = u32::from_le_bytes(bytes);
        cfg.write_config(addr, dword);
        done += take;
    }
    count
}

/// HalGetBusData's PCI shape: read the slot's configuration space from offset 0 into `buffer`.
/// Returns the bytes read; 0 when the bus data type is not PCI configuration or the bus does not
/// exist; 2 with the vendor ID 0xFFFF in the buffer's first two bytes when the slot is empty.
pub fn get_bus_data<C: ConfigIo>(
    cfg: &mut C,
    devices: &Devices,
    bus_data_type: i32,
    bus: u32,
    slot: u32,
    buffer: &mut [u8],
) -> u32 {
    get_bus_data_by_offset(cfg, devices, bus_data_type, bus, slot, buffer, 0)
}

/// HalGetBusDataByOffset's PCI shape, at byte `offset` in the slot's configuration space.
pub fn get_bus_data_by_offset<C: ConfigIo>(
    cfg: &mut C,
    devices: &Devices,
    bus_data_type: i32,
    bus: u32,
    slot: u32,
    buffer: &mut [u8],
    offset: u32,
) -> u32 {
    if bus_data_type != PCI_CONFIGURATION || offset >= 256 {
        return 0;
    }
    let bus = bus as u8; // bus numbers are 8 bits in the address dword
    if !bus_exists(devices, bus) {
        return 0;
    }
    let (dev, func) = slot_parts(slot);
    if cfg.read_config(ConfigAddress::new(bus, dev, func, VENDOR_DEVICE)) as u16 == INVALID_VENDOR {
        if buffer.len() >= 2 {
            buffer[..2].copy_from_slice(&INVALID_VENDOR.to_le_bytes());
        }
        return 2;
    }
    read_config_bytes(cfg, bus, dev, func, offset as u8, buffer) as u32
}

/// HalSetBusData's PCI shape: write `buffer` to the slot's configuration space from offset 0.
/// Returns the bytes written; 0 when the bus data type is not PCI configuration, the bus does
/// not exist, or the slot is empty.
pub fn set_bus_data<C: ConfigIo>(
    cfg: &mut C,
    devices: &Devices,
    bus_data_type: i32,
    bus: u32,
    slot: u32,
    buffer: &[u8],
) -> u32 {
    set_bus_data_by_offset(cfg, devices, bus_data_type, bus, slot, buffer, 0)
}

/// HalSetBusDataByOffset's PCI shape, at byte `offset` in the slot's configuration space.
pub fn set_bus_data_by_offset<C: ConfigIo>(
    cfg: &mut C,
    devices: &Devices,
    bus_data_type: i32,
    bus: u32,
    slot: u32,
    buffer: &[u8],
    offset: u32,
) -> u32 {
    if bus_data_type != PCI_CONFIGURATION || offset >= 256 {
        return 0;
    }
    let bus = bus as u8;
    if !bus_exists(devices, bus) {
        return 0;
    }
    let (dev, func) = slot_parts(slot);
    if cfg.read_config(ConfigAddress::new(bus, dev, func, VENDOR_DEVICE)) as u16 == INVALID_VENDOR {
        return 0;
    }
    write_config_bytes(cfg, bus, dev, func, offset as u8, buffer) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated PCI configuration space: the functions the test programmed, each a
    /// 256-byte register file. A BAR slot reads its stored value masked with the slot's size
    /// mask — the value an all-ones write reads back — so any other write reads back the
    /// written base. An absent function reads all ones, the empty slot.
    struct SimConfig {
        funcs: Vec<SimFunc>,
        writes: Vec<(ConfigAddress, u32)>,
    }

    struct SimFunc {
        bus: u8,
        dev: u8,
        func: u8,
        regs: [u32; 64],
        bar_masks: [u32; 6],
    }

    impl SimConfig {
        fn new() -> Self {
            SimConfig {
                funcs: Vec::new(),
                writes: Vec::new(),
            }
        }

        fn add(&mut self, bus: u8, dev: u8, func: u8) {
            self.funcs.push(SimFunc {
                bus,
                dev,
                func,
                regs: [0; 64],
                bar_masks: [0; 6],
            });
        }

        fn func_mut(&mut self, bus: u8, dev: u8, func: u8) -> &mut SimFunc {
            self.funcs
                .iter_mut()
                .find(|f| f.bus == bus && f.dev == dev && f.func == func)
                .expect("the test programs this function first")
        }

        /// Store a raw register value (what a plain write leaves in the register).
        fn set(&mut self, bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
            self.func_mut(bus, dev, func).regs[(offset / 4) as usize] = value;
        }

        /// A BAR slot's size mask: its hardwired type bits plus the address bits it
        /// implements, i.e. what an all-ones write reads back.
        fn set_bar_mask(&mut self, bus: u8, dev: u8, func: u8, slot: usize, mask: u32) {
            self.func_mut(bus, dev, func).bar_masks[slot] = mask;
        }

        /// A register's stored value, bypassing the BAR mask.
        fn raw(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
            self.funcs
                .iter()
                .find(|f| f.bus == bus && f.dev == dev && f.func == func)
                .map(|f| f.regs[(offset / 4) as usize])
                .unwrap_or(0xFFFF_FFFF)
        }
    }

    impl ConfigIo for SimConfig {
        fn read_config(&mut self, addr: ConfigAddress) -> u32 {
            let Some(f) = self
                .funcs
                .iter_mut()
                .find(|f| f.bus == addr.bus && f.dev == addr.dev && f.func == addr.func)
            else {
                return 0xFFFF_FFFF; // an empty slot
            };
            let index = (addr.offset / 4) as usize;
            let value = f.regs[index];
            // Only the header layout's BAR slots mask: a bridge header has two BARs, and
            // past them (0x18 up) sit its plain bus-number registers.
            let header_type = (f.regs[HEADER_TYPE as usize / 4] >> 16) as u8;
            let bar_slots = match header_type & HEADER_LAYOUT_MASK {
                0 => 6,
                1 => 2,
                _ => 0,
            };
            if (BAR..BAR_END).contains(&addr.offset) && index - 4 < bar_slots {
                value & f.bar_masks[index - 4]
            } else {
                value
            }
        }

        fn write_config(&mut self, addr: ConfigAddress, value: u32) {
            self.writes.push((addr, value));
            if let Some(f) = self
                .funcs
                .iter_mut()
                .find(|f| f.bus == addr.bus && f.dev == addr.dev && f.func == addr.func)
            {
                f.regs[(addr.offset / 4) as usize] = value;
            }
        }
    }

    /// Program a function's common header fields.
    fn program_device(
        sim: &mut SimConfig,
        bus: u8,
        dev: u8,
        func: u8,
        vendor: u16,
        device: u16,
        revision: u8,
        class_code: u32,
        header_type: u8,
    ) {
        sim.add(bus, dev, func);
        sim.set(
            bus,
            dev,
            func,
            VENDOR_DEVICE,
            (device as u32) << 16 | vendor as u32,
        );
        sim.set(
            bus,
            dev,
            func,
            REVISION_CLASS,
            class_code << 8 | revision as u32,
        );
        sim.set(bus, dev, func, HEADER_TYPE, (header_type as u32) << 16);
    }

    /// Program a BAR slot: `base` is the stored value, `mask` the all-ones read-back.
    fn set_bar(sim: &mut SimConfig, bus: u8, dev: u8, func: u8, slot: usize, base: u32, mask: u32) {
        sim.set(bus, dev, func, BAR + 4 * slot as u8, base);
        sim.set_bar_mask(bus, dev, func, slot, mask);
    }

    fn set_interrupts(sim: &mut SimConfig, bus: u8, dev: u8, func: u8, line: u8, pin: u8) {
        sim.set(
            bus,
            dev,
            func,
            INTERRUPT_LINE,
            (pin as u32) << 8 | line as u32,
        );
    }

    /// The mechanism-#1 address dword: enable bit 31, bus in 23-16, device in 15-11,
    /// function in 10-8, the dword-aligned register in 7-2.
    #[test]
    fn config_address_dword_encodes_mechanism_one() {
        assert_eq!(ConfigAddress::new(0, 0, 0, 0x00).dword(), 0x8000_0000);
        assert_eq!(ConfigAddress::new(0, 1, 0, 0x08).dword(), 0x8000_0808);
        assert_eq!(ConfigAddress::new(0, 7, 0, 0x60).dword(), 0x8000_3860);
        assert_eq!(ConfigAddress::new(2, 31, 7, 0xFF).dword(), 0x8002_FFFC);
    }

    /// An empty slot reads vendor 0xFFFF and is skipped; only the programmed functions
    /// appear, and a bus with nothing on it scans to nothing.
    #[test]
    fn empty_slots_are_skipped() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 3, 0, 0x8086, 0x1237, 0x02, 0x060100, 0x00);
        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices.find(0, 3, 0).unwrap().vendor, 0x8086);
        assert!(devices.find(0, 0, 0).is_none());
        assert!(devices.find(0, 3, 1).is_none());

        let empty = scan(&mut SimConfig::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.iter().count(), 0);
    }

    /// A type-0 device decodes in full: IDs, revision, the 24-bit class code, the header
    /// type, each BAR (sized by the all-ones probe, then restored), and the interrupt
    /// line/pin pair.
    #[test]
    fn a_device_decodes_in_full() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 4, 0, 0x8086, 0x100E, 0x03, 0x020000, 0x00);
        // BAR0: 32-bit memory, 4 KiB at 0xE000_0000.
        set_bar(&mut sim, 0, 4, 0, 0, 0xE000_0000, 0xFFFF_F000);
        // BAR1: I/O, 16 bytes at 0xC000.
        set_bar(&mut sim, 0, 4, 0, 1, 0xC001, 0xFFFF_FFF1);
        // BAR2: unimplemented (no mask).
        // BAR3: prefetchable 32-bit memory, 8 KiB at 0xE100_0000.
        set_bar(&mut sim, 0, 4, 0, 3, 0xE100_0008, 0xFFFF_E008);
        set_interrupts(&mut sim, 0, 4, 0, 0x0B, 0x01);

        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 1);
        let d = devices.find(0, 4, 0).unwrap();
        assert_eq!((d.bus, d.dev, d.func), (0, 4, 0));
        assert_eq!((d.vendor, d.device), (0x8086, 0x100E));
        assert_eq!(d.revision, 0x03);
        assert_eq!(d.class_code, 0x020000);
        assert_eq!(d.header_type, 0x00);
        assert_eq!(
            d.bars[0],
            Bar::Memory {
                base: 0xE000_0000,
                size: 0x1000,
                prefetchable: false,
                wide: false
            }
        );
        assert_eq!(d.bars[1], Bar::Io(0xC000));
        assert_eq!(d.bars[2], Bar::None);
        assert_eq!(
            d.bars[3],
            Bar::Memory {
                base: 0xE100_0000,
                size: 0x2000,
                prefetchable: true,
                wide: false
            }
        );
        assert_eq!(d.bars[4], Bar::None);
        assert_eq!(d.bars[5], Bar::None);
        assert_eq!(d.interrupt_pin, 0x01);
        assert_eq!(d.interrupt_line, 0x0B);

        // The sizing probe wrote all ones and restored every BAR to its programmed value.
        assert_eq!(sim.raw(0, 4, 0, BAR), 0xE000_0000);
        assert_eq!(sim.raw(0, 4, 0, BAR + 4), 0xC001);
        assert_eq!(
            sim.raw(0, 4, 0, BAR + 8),
            0,
            "BAR2 probed and restored to 0"
        );
        assert_eq!(sim.raw(0, 4, 0, BAR + 12), 0xE100_0008);
        assert!(sim
            .writes
            .iter()
            .any(|(a, v)| a.offset == BAR && *v == 0xFFFF_FFFF));
    }

    /// Header-type bit 7 marks a multifunction device: all eight functions are probed and
    /// the empty ones skipped; without it only function 0 is.
    #[test]
    fn multifunction_devices_enumerate_all_functions() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 5, 0, 0x8086, 0x7010, 0x00, 0x060100, 0x80);
        program_device(&mut sim, 0, 5, 2, 0x8086, 0x7011, 0x00, 0x020000, 0x80);
        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 2);
        assert!(devices.find(0, 5, 0).is_some());
        assert!(devices.find(0, 5, 1).is_none());
        assert_eq!(devices.find(0, 5, 2).unwrap().device, 0x7011);

        // Single-function: a stray function 1 is not probed.
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 6, 0, 0x8086, 0x1237, 0x00, 0x060100, 0x00);
        program_device(&mut sim, 0, 6, 1, 0x8086, 0x9999, 0x00, 0x060100, 0x00);
        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 1);
        assert!(devices.find(0, 6, 1).is_none());
    }

    /// A 64-bit memory BAR (type bits 11) consumes two slots: the low dword carries the base
    /// and type, the next dword the upper half of the address and size.
    #[test]
    fn a_64_bit_bar_consumes_two_slots() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 8, 0, 0x10DE, 0x0A38, 0xA1, 0x030000, 0x00);
        // BAR0: 64-bit prefetchable memory, 512 MiB at 0xC000_0000; BAR1 is its upper half.
        set_bar(&mut sim, 0, 8, 0, 0, 0xC000_000E, 0xE000_000E);
        set_bar(&mut sim, 0, 8, 0, 1, 0, 0x0000_0000);
        // BAR2: an I/O BAR right after the wide one.
        set_bar(&mut sim, 0, 8, 0, 2, 0xD001, 0xFFFF_FFFD);

        let devices = scan(&mut sim);
        let d = devices.find(0, 8, 0).unwrap();
        assert_eq!(
            d.bars[0],
            Bar::Memory {
                base: 0xC000_0000,
                size: 0x2000_0000,
                prefetchable: true,
                wide: true
            }
        );
        assert_eq!(d.bars[1], Bar::None, "the upper half belongs to BAR0");
        assert_eq!(d.bars[2], Bar::Io(0xD000));
        // Both halves were restored after sizing.
        assert_eq!(sim.raw(0, 8, 0, BAR), 0xC000_000E);
        assert_eq!(sim.raw(0, 8, 0, BAR + 4), 0);
    }

    /// A PCI-to-PCI bridge (class 0x06, subclass 0x04) is recursed into through its
    /// secondary-bus register (offset 0x19), so the devices on the secondary bus are
    /// enumerated under their own bus number. A bridge looping back to an already-visited
    /// bus is not walked again, and the bridge's own BAR probing stops at its two BAR
    /// slots — the bus-number registers are never written.
    #[test]
    fn bridge_recursion_enumerates_the_secondary_bus() {
        let mut sim = SimConfig::new();
        // Bus 0, device 1: the bridge, secondary bus 2.
        program_device(&mut sim, 0, 1, 0, 0x8086, 0x7010, 0x00, 0x060400, 0x01);
        sim.set(0, 1, 0, BRIDGE_BUS_NUMBERS, 0x0002_0200); // primary 0, secondary 2
                                                           // Bus 2, device 0: a VGA card with one
                                                           // memory BAR.
        program_device(&mut sim, 2, 0, 0, 0x1234, 0x5678, 0x02, 0x030000, 0x00);
        set_bar(&mut sim, 2, 0, 0, 0, 0xE200_0000, 0xFFFF_F000);
        // Bus 2, device 1: a bridge pointing back at bus 0 (a loop).
        program_device(&mut sim, 2, 1, 0, 0x8086, 0x244E, 0x00, 0x060400, 0x01);
        sim.set(2, 1, 0, BRIDGE_BUS_NUMBERS, 0x0000_0202); // primary 2, secondary 0

        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 3);
        let bridge = devices.find(0, 1, 0).unwrap();
        assert!(bridge.is_pci_bridge());
        assert_eq!(bridge.header_type, 0x01);
        assert_eq!(bridge.bars[0], Bar::None);
        let vga = devices.find(2, 0, 0).expect("the secondary bus was walked");
        assert_eq!(vga.bus, 2);
        assert_eq!((vga.vendor, vga.device), (0x1234, 0x5678));
        assert_eq!(vga.class_code, 0x030000);
        assert_eq!(
            vga.bars[0],
            Bar::Memory {
                base: 0xE200_0000,
                size: 0x1000,
                prefetchable: false,
                wide: false
            }
        );
        assert!(
            devices.find(2, 1, 0).is_some(),
            "the looping bridge itself is listed"
        );

        // The bridge's registers past its two BAR slots were never probed.
        assert!(sim
            .writes
            .iter()
            .all(|(a, _)| !(a.bus == 0 && a.dev == 1 && a.offset >= BRIDGE_BUS_NUMBERS)));
        assert_eq!(sim.raw(0, 1, 0, BRIDGE_BUS_NUMBERS), 0x0002_0200);
    }

    /// The interrupt registers (line at 0x3C, pin at 0x3D) decode into the device record;
    /// pin 0 is a device that does not interrupt, 0xFF line is unassigned.
    #[test]
    fn interrupt_pin_and_line_decode() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 9, 0, 0x10EC, 0x8139, 0x01, 0x020000, 0x00);
        set_interrupts(&mut sim, 0, 9, 0, 0x05, 0x03);
        program_device(&mut sim, 0, 10, 0, 0x8086, 0x1237, 0x02, 0x060100, 0x00);
        set_interrupts(&mut sim, 0, 10, 0, 0xFF, 0x00);

        let devices = scan(&mut sim);
        let nic = devices.find(0, 9, 0).unwrap();
        assert_eq!(nic.interrupt_pin, 0x03);
        assert_eq!(nic.interrupt_line, 0x05);
        let isa = devices.find(0, 10, 0).unwrap();
        assert_eq!(isa.interrupt_pin, 0x00);
        assert_eq!(isa.interrupt_line, 0xFF);
    }

    /// The PIRQ route-control registers (0x60-0x63) are read from the ISA bridge (class
    /// 0x06, subclass 0x01) on bus 0; without one there are no routes.
    #[test]
    fn pirq_routes_are_read_from_the_isa_bridge() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 7, 0, 0x8086, 0x7000, 0x02, 0x060100, 0x00);
        sim.set(0, 7, 0, PIRQ_ROUTE_CONTROL, 0x800B_0A05); // PIRQA=5, PIRQB=10, PIRQC=11, PIRQD
                                                           // disabled
        let devices = scan(&mut sim);
        let routes = PirqRoutes::read(&mut sim, &devices).expect("the ISA bridge is present");
        assert_eq!(routes, PirqRoutes([0x05, 0x0A, 0x0B, 0x80]));

        let none = scan(&mut SimConfig::new());
        assert!(PirqRoutes::read(&mut sim, &none).is_none());
    }

    /// On bus 0 the slot/pin pair selects the PIRQ line by the rotation (dev + pin - 1)
    /// mod 4, and the route-control byte's low nibble is the ISA IRQ (reserved bits
    /// ignored); a disabled line (bit 7) or a zero nibble routes nowhere, and so does any
    /// other bus or a device with no pin.
    #[test]
    fn the_pirq_rotation_routes_slot_and_pin_to_an_irq() {
        let routes = PirqRoutes([0x05, 0x80, 0x0B, 0x00]);
        assert_eq!(route(0, 0, 0, 1, &routes), Some(5)); // slot 0 INTA -> PIRQA
        assert_eq!(route(0, 1, 0, 1, &routes), None); // slot 1 INTA -> PIRQB, disabled
        assert_eq!(route(0, 2, 0, 1, &routes), Some(11)); // slot 2 INTA -> PIRQC
        assert_eq!(route(0, 3, 0, 1, &routes), None); // slot 3 INTA -> PIRQD, zero nibble
                                                      // The rotation wraps: slot 4 INTA is PIRQA
                                                      // again, and slot 5 INTD too.
        assert_eq!(route(0, 4, 0, 1, &routes), Some(5));
        assert_eq!(route(0, 5, 0, 4, &routes), Some(5));
        // Pins rotate within a slot: slot 0 INTB is PIRQB (disabled), INTC is PIRQC.
        assert_eq!(route(0, 0, 0, 2, &routes), None);
        assert_eq!(route(0, 0, 0, 3, &routes), Some(11));
        // Reserved bits in the route byte do not affect the IRQ nibble.
        assert_eq!(
            route(0, 0, 0, 1, &PirqRoutes([0x75, 0x80, 0x0B, 0x00])),
            Some(5)
        );
        // A device without a pin, and any bus other than 0, route nowhere.
        assert_eq!(route(0, 2, 0, 0, &routes), None);
        assert_eq!(route(1, 2, 0, 1, &routes), None);
    }

    /// An explicit route override is consulted before the PIRQ default — it wins both
    /// where the default gives an IRQ and where it gives none, and on secondary buses —
    /// and clearing it restores the default.
    #[test]
    fn an_override_wins_over_the_pirq_default() {
        let routes = PirqRoutes([0x05, 0x80, 0x0B, 0x00]);

        // (0, 30, 1, 3): PIRQ index (30 + 3 - 1) mod 4 = 0, default IRQ 5.
        assert_eq!(route(0, 30, 1, 3, &routes), Some(5));
        set_route(0, 30, 1, 3, Some(9));
        assert_eq!(route(0, 30, 1, 3, &routes), Some(9), "the override wins");
        set_route(0, 30, 1, 3, None);
        assert_eq!(
            route(0, 30, 1, 3, &routes),
            Some(5),
            "cleared, the default applies"
        );

        // (0, 31, 3, 3): PIRQ index (31 + 3 - 1) mod 4 = 1, disabled by default.
        assert_eq!(route(0, 31, 3, 3, &routes), None);
        set_route(0, 31, 3, 3, Some(9));
        assert_eq!(
            route(0, 31, 3, 3, &routes),
            Some(9),
            "overrides a disabled line"
        );
        set_route(0, 31, 3, 3, None);
        assert_eq!(route(0, 31, 3, 3, &routes), None);

        // (3, 2, 0, 1): a secondary bus, no PIRQ default of its own.
        assert_eq!(route(3, 2, 0, 1, &routes), None);
        set_route(3, 2, 0, 1, Some(7));
        assert_eq!(route(3, 2, 0, 1, &routes), Some(7));
        set_route(3, 2, 0, 1, None);
        assert_eq!(route(3, 2, 0, 1, &routes), None);
    }

    /// A simulated port space holding the mechanism's address/data port pair: the address
    /// dword latches at 0xCF8, and 0xCFC reads/writes the addressed register of a two-function
    /// config space.
    struct PortSim {
        address: u32,
        space: [[u32; 64]; 2],
    }

    impl PortSim {
        fn new() -> Self {
            PortSim {
                address: 0,
                space: [[0; 64]; 2],
            }
        }

        /// The function the latched address selects, if the cycle is enabled and the function
        /// is one of the two this space models; None is the empty slot (all ones).
        fn selected(&self) -> Option<usize> {
            if self.address & 0x8000_0000 == 0 {
                return None;
            }
            let func = ((self.address >> 8) & 0x7) as usize;
            (func < 2).then_some(func)
        }
    }

    impl Io for PortSim {
        fn out(&mut self, port: u16, byte: u8) {
            let _ = (port, byte);
            unimplemented!("this port space takes no byte writes");
        }

        fn read(&mut self, port: u16) -> u8 {
            let _ = port;
            unimplemented!("this port space takes no byte reads");
        }

        fn read_word(&mut self, port: u16) -> u16 {
            let _ = port;
            unimplemented!("this port space takes no word reads");
        }

        fn read_dword(&mut self, port: u16) -> u32 {
            match port {
                CONFIG_DATA_PORT => match self.selected() {
                    Some(func) => {
                        let offset = (self.address & 0xFC) as usize / 4;
                        self.space[func][offset]
                    }
                    None => 0xFFFF_FFFF,
                },
                _ => unimplemented!("no such port"),
            }
        }

        fn out_dword(&mut self, port: u16, value: u32) {
            match port {
                CONFIG_ADDRESS_PORT => self.address = value,
                CONFIG_DATA_PORT => {
                    if let Some(func) = self.selected() {
                        let offset = (self.address & 0xFC) as usize / 4;
                        self.space[func][offset] = value;
                    }
                }
                _ => unimplemented!("no such port"),
            }
        }
    }

    /// The port adapter selects the register with the address dword and moves the data dword
    /// through 0xCFC, in both directions.
    #[test]
    fn the_port_adapter_moves_config_dwords_through_0xcf8_and_0xcfc() {
        let mut sim = PortSim::new();
        sim.space[1][0] = 0x1234_5678; // function 1's vendor/device dword
        let mut cfg = PortsConfig::new(&mut sim);
        // The read goes to function 1 (func bits 10-8): 0x8000_0000 | 1 << 8 | 0x00.
        assert_eq!(
            cfg.read_config(ConfigAddress::new(0, 0, 1, VENDOR_DEVICE)),
            0x1234_5678
        );
        cfg.write_config(ConfigAddress::new(0, 0, 1, INTERRUPT_LINE), 0x0000_0B00);
        assert_eq!(sim.space[1][0x3C / 4], 0x0000_0B00);
        // A disabled cycle (bit 31 clear) must not be generated: the address dword always has
        // it set.
        assert_eq!(sim.address & 0x8000_0000, 0x8000_0000);
    }

    /// The development machine's PCI bus as its boot report showed it (the QEMU pc machine):
    /// five functions, and the one interrupt pin in use routes to ISA IRQ 10 through PIRQB.
    /// The expected values below are that report's, replayed through the simulated config
    /// space — the enumeration and the routing must come out identical.
    #[test]
    fn the_development_machine_enumerates_as_its_boot_reported() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 0, 0, 0x8086, 0x1237, 0x02, 0x060000, 0x00); // host bridge
        program_device(&mut sim, 0, 1, 0, 0x8086, 0x7000, 0x00, 0x060100, 0x80); // ISA bridge,
                                                                                 // multifunction
        program_device(&mut sim, 0, 1, 1, 0x8086, 0x7010, 0x00, 0x010180, 0x00); // IDE
        program_device(&mut sim, 0, 1, 3, 0x8086, 0x7113, 0x03, 0x068000, 0x00); // PM
        sim.set(0, 1, 3, INTERRUPT_LINE, 0x0100); // pin 1, line unassigned
        program_device(&mut sim, 0, 2, 0, 0x1234, 0x1111, 0x02, 0x030000, 0x00); // VGA
                                                                                 // The ISA bridge's
                                                                                 // PIRQ route
                                                                                 // controls: B ->
                                                                                 // IRQ 10, the rest
                                                                                 // disabled.
        sim.set(0, 1, 0, PIRQ_ROUTE_CONTROL, 0x8080_0A80);

        let devices = scan(&mut sim);
        assert_eq!(devices.len(), 5);
        let expected = [
            (0, 0, 0, 0x8086, 0x1237, 0x060000, 0x02, 0),
            (0, 1, 0, 0x8086, 0x7000, 0x060100, 0x00, 0),
            (0, 1, 1, 0x8086, 0x7010, 0x010180, 0x00, 0),
            (0, 1, 3, 0x8086, 0x7113, 0x068000, 0x03, 1),
            (0, 2, 0, 0x1234, 0x1111, 0x030000, 0x02, 0),
        ];
        for (d, e) in devices.iter().zip(expected) {
            assert_eq!(
                (
                    d.bus,
                    d.dev,
                    d.func,
                    d.vendor,
                    d.device,
                    d.class_code,
                    d.revision,
                    d.interrupt_pin
                ),
                e,
                "the scan must reproduce the boot report's device"
            );
        }

        let routes = PirqRoutes::read(&mut sim, &devices).expect("the ISA bridge is there");
        assert_eq!(routes.0, [0x80, 0x0A, 0x80, 0x80]);
        assert_eq!(route(0, 1, 3, 1, &routes), Some(10));
        assert_eq!(route(0, 2, 0, 1, &routes), None, "PIRQA is disabled");
    }

    /// Byte-granular config reads assemble across dword boundaries: an unaligned start and tail
    /// come from the covering dwords, and the read caps at the 256-byte space.
    #[test]
    fn config_bytes_read_across_dword_boundaries() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 4, 0, 0x8086, 0x100E, 0x03, 0x020000, 0x00);
        sim.set(0, 4, 0, INTERRUPT_LINE, (0x03u32 << 8) | 0x0B); // pin 3, line 11
        sim.set(0, 4, 0, 0x40, 0xDEAD_BEEF);

        // From 0x3C, eight bytes: the interrupt dword whole, then the low half of 0x40.
        let mut buffer = [0u8; 8];
        let read = read_config_bytes(&mut sim, 0, 4, 0, 0x3C, &mut buffer);
        assert_eq!(read, 8);
        assert_eq!(
            buffer,
            [0x0B, 0x03, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE],
            "little-endian bytes from the two covering dwords"
        );

        // An unaligned start: from 0x3D, four bytes span the 0x3C and 0x40 dwords.
        let mut four = [0u8; 4];
        let read = read_config_bytes(&mut sim, 0, 4, 0, 0x3D, &mut four);
        assert_eq!(read, 4);
        assert_eq!(four, [0x03, 0x00, 0x00, 0xEF]);

        // Past the space's end the read stops at 256.
        let mut tail = [0u8; 8];
        let read = read_config_bytes(&mut sim, 0, 4, 0, 0xFE, &mut tail);
        assert_eq!(read, 2);
    }

    /// Byte-granular config writes are read-modify-write per touched dword: the bytes beside the
    /// written range keep their values.
    #[test]
    fn config_bytes_write_preserves_the_neighbouring_bytes() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 4, 0, 0x8086, 0x100E, 0x03, 0x020000, 0x00);
        sim.set(0, 4, 0, INTERRUPT_LINE, 0x0000_0B03);

        // Write four bytes at 0x3E: the top half of the 0x3C dword and the low half of 0x40.
        let written = write_config_bytes(&mut sim, 0, 4, 0, 0x3E, &[0xA5, 0x5A, 0x11, 0x22]);
        assert_eq!(written, 4);
        assert_eq!(
            sim.raw(0, 4, 0, INTERRUPT_LINE),
            0x5AA5_0B03,
            "the low half of the 0x3C dword is untouched"
        );
        assert_eq!(sim.raw(0, 4, 0, 0x40), 0x0000_2211);
    }

    /// The bus-data surface: a present slot reads its config space (0 offset, and by offset),
    /// an empty slot reports 2 with vendor 0xFFFF, an absent bus or a non-PCI data type reports
    /// 0, and writes go through with the same rules.
    #[test]
    fn the_bus_data_surface_serves_pci_config_space() {
        let mut sim = SimConfig::new();
        program_device(&mut sim, 0, 4, 0, 0x8086, 0x100E, 0x03, 0x020000, 0x00);
        set_interrupts(&mut sim, 0, 4, 0, 0x0B, 0x03);
        let devices = scan(&mut sim);

        // Slot 4<<3|0 = 32: read the whole common header.
        let mut buffer = [0u8; 64];
        let read = get_bus_data(&mut sim, &devices, PCI_CONFIGURATION, 0, 32, &mut buffer);
        assert_eq!(read, 64);
        assert_eq!(
            &buffer[0..4],
            &0x100E_8086u32.to_le_bytes(),
            "vendor, device"
        );
        assert_eq!(
            &buffer[8..12],
            &((0x020000u32 << 8) | 0x03).to_le_bytes(),
            "rev, class"
        );
        assert_eq!(&buffer[0x3C..0x3E], &[0x0B, 0x03], "line, pin");

        // By offset: four bytes at 0x3C.
        let mut four = [0u8; 4];
        let read = get_bus_data_by_offset(
            &mut sim,
            &devices,
            PCI_CONFIGURATION,
            0,
            32,
            &mut four,
            0x3C,
        );
        assert_eq!(read, 4);
        assert_eq!(four, [0x0B, 0x03, 0x00, 0x00]);

        // An empty slot: 2 bytes, vendor 0xFFFF.
        let mut empty = [0u8; 64];
        let read = get_bus_data(&mut sim, &devices, PCI_CONFIGURATION, 0, 9 << 3, &mut empty);
        assert_eq!(read, 2);
        assert_eq!(&empty[..2], &0xFFFFu16.to_le_bytes());

        // A bus the scan did not find, and a data type that is not PCI config.
        assert_eq!(
            get_bus_data(&mut sim, &devices, PCI_CONFIGURATION, 7, 0, &mut buffer),
            0
        );
        assert_eq!(
            get_bus_data(&mut sim, &devices, 0, 0, 32, &mut buffer),
            0,
            "Cmos is not served"
        );
        // Bus 0 exists even when the scan found nothing on it: an empty slot there reports 2.
        let none = Devices::new();
        assert_eq!(
            get_bus_data(&mut sim, &none, PCI_CONFIGURATION, 0, 5 << 3, &mut buffer),
            2,
            "bus 0 exists: the slot is empty"
        );

        // Writes: by offset into the interrupt dword, and from offset 0 (the vendor/device
        // dword) round-tripping; an empty slot and a foreign type write nothing.
        let by_offset = set_bus_data_by_offset(
            &mut sim,
            &devices,
            PCI_CONFIGURATION,
            0,
            32,
            &[0x05, 0x01],
            0x3C,
        );
        assert_eq!(by_offset, 2);
        assert_eq!(sim.raw(0, 4, 0, INTERRUPT_LINE) & 0xFFFF, 0x0105);
        let written = set_bus_data(&mut sim, &devices, PCI_CONFIGURATION, 0, 32, &[0x86, 0x80]);
        assert_eq!(written, 2);
        assert_eq!(
            sim.raw(0, 4, 0, VENDOR_DEVICE),
            0x100E_8086,
            "vendor restored"
        );
        assert_eq!(
            set_bus_data(&mut sim, &devices, PCI_CONFIGURATION, 0, 9 << 3, &[1, 2]),
            0,
            "an empty slot takes no write"
        );
        assert_eq!(
            set_bus_data(&mut sim, &devices, 1, 0, 32, &[1]),
            0,
            "Eisa is not served"
        );
        let top = set_bus_data_by_offset(
            &mut sim,
            &devices,
            PCI_CONFIGURATION,
            0,
            32,
            &[0xAA, 0xBB],
            0x3E,
        );
        assert_eq!(top, 2);
        assert_eq!(
            sim.raw(0, 4, 0, 0x3C),
            0xBBAA_0105,
            "only the top half of the dword moved"
        );

        // An offset past the 256-byte configuration space reads and writes nothing.
        assert_eq!(
            get_bus_data_by_offset(&mut sim, &devices, PCI_CONFIGURATION, 0, 32, &mut buffer, 256),
            0
        );
        assert_eq!(
            set_bus_data_by_offset(&mut sim, &devices, PCI_CONFIGURATION, 0, 32, &[1], 300),
            0
        );

        // Slot parts: device in bits 3-7, function in bits 0-2.
        assert_eq!(slot_parts(32), (4, 0));
        assert_eq!(slot_parts(0x2B), (5, 3));
        assert_eq!(slot_parts(0xFF), (31, 7));
    }
}
