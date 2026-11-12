//! The device tree and the driver model: the nodes the buses report, the registered drivers, the
//! device objects their attachments create, and the probe/start flow that claims nodes — the layer
//! the PnP start and every later driver slice sit on.
//!
//! A bus scan (today the PCI scan in [`crate::hw::pci`]) becomes a fixed-capacity registry of
//! [`DeviceNode`]s ([`Nodes`]): each node carries its bus and bus address, its hardware IDs, its
//! BARs, and its interrupt — the pin, the routed ISA line, and the vector the HAL's vector mapping
//! gives the line, through the routing table in [`routing`] ([`crate::hal::interrupt_vector`]).
//! [`Nodes::from_pci`] builds the registry from the scan's device table and PIRQ routes.
//!
//! Drivers register as a `&'static` [`DriverObject`] — a name, the `MajorFunction[IRP_MJ_MAX]`
//! dispatch table, an add-device entry, and the node match (a hardware-ID list, a class, or any)
//! — into a fixed table ([`register_driver`], [`DriverTable`]). A driver matches nodes by its
//! choice of [`MatchSpec`].
//!
//! For each unclaimed node, [`probe_and_start`] runs the first matching driver's add-device entry,
//! which creates the attachment's [`DeviceObject`] (node id, driver, attached-device link, device
//! type, and the opaque driver-owned extension pointer) in the fixed [`DeviceObjects`] table, then
//! sends an `IRP_MJ_PNP`/`IRP_MN_START_DEVICE` packet carrying the node's resources down the
//! device's dispatch table ([`irp`]). A successful start claims the node.

// The boot fills the node registry from the PCI scan ([`init_nodes_from_pci`]); nothing runs the
// probe/start flow yet (that wiring is a later slice), so the target build sees no caller for it.
#![cfg_attr(not(test), allow(dead_code))]

pub mod irp;
pub mod routing;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicU16, AtomicU8, Ordering};

use irp::{Irp, IRP_MJ_PNP, IRP_MN_START_DEVICE};

// The tests read the HAL's vector mapping through it.
#[cfg(test)]
use crate::hal;
use crate::hw::pci::{self, Bar};
use crate::status::NtStatus;
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

/// The resources a PnP start hands the driver: the BARs and the interrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Resources {
    pub bars: [Bar; 6],
    pub interrupt: Option<Interrupt>,
}

impl Resources {
    /// No resources.
    pub const EMPTY: Resources = Resources {
        bars: [Bar::None; 6],
        interrupt: None,
    };
}

/// A node's hardware ID (PCI vendor and device ID).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HardwareId {
    pub vendor: u16,
    pub device: u16,
}

impl HardwareId {
    pub const fn new(vendor: u16, device: u16) -> Self {
        HardwareId { vendor, device }
    }
}

/// A node in the device tree: one function a bus scan found, with the IDs and the resources a
/// PnP start needs.
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

    /// The base class code.
    pub fn class(&self) -> u8 {
        (self.class_code >> 16) as u8
    }

    /// The node's hardware ID.
    pub fn hardware_id(&self) -> HardwareId {
        HardwareId {
            vendor: self.vendor,
            device: self.device,
        }
    }

    /// The node's resources, as a start-device packet carries them.
    pub fn resources(&self) -> Resources {
        Resources {
            bars: self.bars,
            interrupt: self.interrupt,
        }
    }
}

/// A node's id: its index in the registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeId(pub u16);

/// The registry's capacity, matching the PCI scan table's.
pub const MAX_NODES: usize = pci::MAX_DEVICES;

/// A claim slot's free value (driver ids are small, so 0xFF marks an unclaimed node).
const CLAIM_FREE: u8 = 0xFF;

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

/// The device tree: a fixed-capacity table of nodes (no allocator at this layer), plus the claim
/// flag per node. The claim flags are atomic so a shared registry can be probed without a lock.
pub struct Nodes {
    nodes: [DeviceNode; MAX_NODES],
    claimed: [AtomicU8; MAX_NODES],
    count: usize,
}

impl Nodes {
    pub const fn new() -> Self {
        Nodes {
            nodes: [EMPTY_NODE; MAX_NODES],
            claimed: [const { AtomicU8::new(CLAIM_FREE) }; MAX_NODES],
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

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The node with this id, if the registry holds it.
    pub fn get(&self, id: NodeId) -> Option<&DeviceNode> {
        let index = id.0 as usize;
        if index >= self.count {
            return None;
        }
        let node = &self.nodes[index];
        (node.id == id).then_some(node)
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
        self.claimed[self.count].store(CLAIM_FREE, Ordering::Release);
        self.count += 1;
        Some(id)
    }

    /// The driver that claimed the node, if any.
    pub fn claimed_by(&self, id: NodeId) -> Option<DriverId> {
        match self.claimed.get(id.0 as usize) {
            Some(slot) => match slot.load(Ordering::Acquire) {
                CLAIM_FREE => None,
                driver => Some(DriverId(driver as u16)),
            },
            None => None,
        }
    }

    /// Claim the node for a driver. Returns false when another driver claimed it first.
    pub fn claim(&self, id: NodeId, driver: DriverId) -> bool {
        match self.claimed.get(id.0 as usize) {
            Some(slot) => slot
                .compare_exchange(
                    CLAIM_FREE,
                    driver.0 as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok(),
            None => false,
        }
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

/// The global node registry ([`init_nodes_from_pci`]).
pub fn nodes() -> &'static Nodes {
    NODES_REF.get()
}

// --- The driver objects ----------------------------------------------------------------------

/// A dispatch entry: `NTSTATUS(PDEVICE_OBJECT, PIRP)`'s shape.
pub type DispatchFn = fn(&DeviceObject, &mut Irp) -> NtStatus;

/// The add-device entry: `PDRIVER_ADD_DEVICE`'s shape, with the node standing in for the physical
/// device object. The driver creates its device object in `objects` here.
pub type AddDeviceFn = fn(&'static DriverObject, &DeviceNode, &DeviceObjects) -> NtStatus;

/// How a driver picks the nodes it drives: any node, a base class, or a hardware-ID list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchSpec {
    Any,
    Class(u8),
    HardwareIds {
        ids: [HardwareId; MAX_HARDWARE_IDS],
        count: usize,
    },
}

/// A hardware-ID list's capacity.
pub const MAX_HARDWARE_IDS: usize = 8;

impl MatchSpec {
    pub const fn any() -> Self {
        MatchSpec::Any
    }

    pub const fn class(class: u8) -> Self {
        MatchSpec::Class(class)
    }

    pub const fn hardware_ids(ids: &[HardwareId]) -> Self {
        let mut list = [HardwareId::new(0, 0); MAX_HARDWARE_IDS];
        let mut i = 0;
        while i < ids.len() && i < MAX_HARDWARE_IDS {
            list[i] = ids[i];
            i += 1;
        }
        MatchSpec::HardwareIds {
            ids: list,
            count: i,
        }
    }
}

/// A driver's registration: a name, the major-function dispatch table, the add-device entry, and
/// the node match. Registered as a `&'static` into a [`DriverTable`].
pub struct DriverObject {
    pub name: &'static str,
    pub major_function: [Option<DispatchFn>; irp::IRP_MJ_MAX],
    pub add_device: Option<AddDeviceFn>,
    pub match_spec: MatchSpec,
    id: AtomicU16,
}

/// The id a registration has not assigned yet.
const DRIVER_NONE: u16 = 0xFFFF;

impl DriverObject {
    pub const fn new(
        name: &'static str,
        major_function: [Option<DispatchFn>; irp::IRP_MJ_MAX],
        add_device: Option<AddDeviceFn>,
        match_spec: MatchSpec,
    ) -> Self {
        DriverObject {
            name,
            major_function,
            add_device,
            match_spec,
            id: AtomicU16::new(DRIVER_NONE),
        }
    }

    /// The id the driver's last registration assigned it.
    pub fn id(&self) -> DriverId {
        DriverId(self.id.load(Ordering::Acquire))
    }

    /// Whether this driver drives the node, by its match spec.
    pub fn matches(&self, node: &DeviceNode) -> bool {
        match &self.match_spec {
            MatchSpec::Any => true,
            MatchSpec::Class(class) => node.class() == *class,
            MatchSpec::HardwareIds { ids, count } => {
                ids[..*count].iter().any(|id| *id == node.hardware_id())
            }
        }
    }
}

/// A driver's id: its slot in a [`DriverTable`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DriverId(pub u16);

/// The driver table's capacity.
pub const MAX_DRIVERS: usize = 32;

/// A fixed table of registered drivers. The slots are atomic so registration needs no lock.
pub struct DriverTable {
    slots: [AtomicPtr<DriverObject>; MAX_DRIVERS],
}

impl DriverTable {
    pub const fn new() -> Self {
        DriverTable {
            slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_DRIVERS],
        }
    }

    /// Register a driver, assigning its id. Returns `None` when the table is full.
    pub fn register(&self, driver: &'static DriverObject) -> Option<DriverId> {
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(
                    core::ptr::null_mut(),
                    driver as *const DriverObject as *mut DriverObject,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let id = DriverId(index as u16);
                driver.id.store(id.0, Ordering::Release);
                return Some(id);
            }
        }
        None
    }

    /// The driver registered under this id.
    pub fn get(&self, id: DriverId) -> Option<&'static DriverObject> {
        let ptr = self.slots.get(id.0 as usize)?.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            // SAFETY: a non-null slot holds a `&'static DriverObject` written by the registration
            // that claimed the slot.
            Some(unsafe { &*ptr })
        }
    }

    /// The registered drivers, in registration order, with their ids.
    pub fn iter(&self) -> impl Iterator<Item = (DriverId, &'static DriverObject)> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let ptr = slot.load(Ordering::Acquire);
            if ptr.is_null() {
                None
            } else {
                // SAFETY: as in `get`.
                Some((DriverId(index as u16), unsafe { &*ptr }))
            }
        })
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DriverTable {
    fn default() -> Self {
        Self::new()
    }
}

static DRIVERS: DriverTable = DriverTable::new();

/// Register a driver into the global table.
pub fn register_driver(driver: &'static DriverObject) -> Option<DriverId> {
    DRIVERS.register(driver)
}

/// The global driver table ([`register_driver`]).
pub fn drivers() -> &'static DriverTable {
    &DRIVERS
}

// --- The device objects ----------------------------------------------------------------------

/// A device object's kind: the documented `FILE_DEVICE_*` values.
pub type DeviceType = u32;

pub const FILE_DEVICE_DISK: DeviceType = 0x0000_0007;
pub const FILE_DEVICE_FILE_SYSTEM: DeviceType = 0x0000_0008;
pub const FILE_DEVICE_KEYBOARD: DeviceType = 0x0000_000b;
pub const FILE_DEVICE_NETWORK: DeviceType = 0x0000_0012;
pub const FILE_DEVICE_UNKNOWN: DeviceType = 0x0000_0022;

/// The volume parameter block a mount carries.
#[derive(Clone, Copy, Debug)]
pub struct Vpb {
    pub flags: u8,
}

/// The volume is mounted.
pub const VPB_MOUNTED: u8 = 0x1;

impl Vpb {
    pub const fn new() -> Self {
        Vpb { flags: 0 }
    }
}

/// A device object's id: its slot in the [`DeviceObjects`] table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceId(pub u16);

/// The attached-device link's none value.
const DEVICE_NONE: u16 = 0xFFFF;

/// The per-attachment object a driver's add-device entry creates: the node it is attached to, the
/// driver, the attached-device link (the device stacked on top of this one), the device type, and
/// the opaque driver-owned extension pointer (the device extension stand-in).
pub struct DeviceObject {
    pub node: Option<NodeId>,
    pub driver: &'static DriverObject,
    pub driver_id: DriverId,
    attached: AtomicU16,
    pub device_type: DeviceType,
    pub extension: *mut c_void,
    /// The I/O stack size packets sent to this device are built with.
    pub stack_size: u8,
    pub vpb: Vpb,
}

impl DeviceObject {
    pub fn new(
        driver: &'static DriverObject,
        node: Option<NodeId>,
        device_type: DeviceType,
        extension: *mut c_void,
    ) -> Self {
        DeviceObject {
            node,
            driver,
            driver_id: driver.id(),
            attached: AtomicU16::new(DEVICE_NONE),
            device_type,
            extension,
            stack_size: 2,
            vpb: Vpb::new(),
        }
    }

    /// The device attached on top of this one, if any.
    pub fn attached(&self) -> Option<DeviceId> {
        match self.attached.load(Ordering::Acquire) {
            DEVICE_NONE => None,
            id => Some(DeviceId(id)),
        }
    }

    /// Set the attached-device link.
    pub fn set_attached(&self, id: DeviceId) {
        self.attached.store(id.0, Ordering::Release);
    }
}

/// The device-object table's capacity.
pub const MAX_DEVICE_OBJECTS: usize = 64;

const SLOT_FREE: u8 = 0;
const SLOT_USED: u8 = 1;

struct DeviceSlot {
    state: AtomicU8,
    object: UnsafeCell<MaybeUninit<DeviceObject>>,
}

/// The fixed-capacity table the add-device entries create device objects in.
pub struct DeviceObjects {
    slots: [DeviceSlot; MAX_DEVICE_OBJECTS],
}

// SAFETY: a slot's object is written once, by the `create` that claimed the slot (the state's
// release), before any reader that sees the state USED (acquire) reads it; after that the object
// is shared read-only except for the attached-device link, which is itself atomic.
unsafe impl Sync for DeviceObjects {}

impl DeviceObjects {
    pub const fn new() -> Self {
        DeviceObjects {
            slots: [const {
                DeviceSlot {
                    state: AtomicU8::new(SLOT_FREE),
                    object: UnsafeCell::new(MaybeUninit::uninit()),
                }
            }; MAX_DEVICE_OBJECTS],
        }
    }

    /// Create a device object in a free slot, returning its id. Returns `None` when the table is
    /// full.
    pub fn create(&self, object: DeviceObject) -> Option<DeviceId> {
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .state
                .compare_exchange(SLOT_FREE, SLOT_USED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // SAFETY: this `create` claimed the slot, so it is the only writer.
                unsafe { (*slot.object.get()).write(object) };
                return Some(DeviceId(index as u16));
            }
        }
        None
    }

    /// The device object under this id.
    pub fn get(&self, id: DeviceId) -> Option<&DeviceObject> {
        let slot = self.slots.get(id.0 as usize)?;
        if slot.state.load(Ordering::Acquire) != SLOT_USED {
            return None;
        }
        // SAFETY: the state reads USED, so the object was written and is never written again.
        Some(unsafe { (*slot.object.get()).assume_init_ref() })
    }

    /// The device objects created so far.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceObject> {
        (0..MAX_DEVICE_OBJECTS as u16).filter_map(|i| self.get(DeviceId(i)))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DeviceObjects {
    fn default() -> Self {
        Self::new()
    }
}

static DEVICE_OBJECTS: DeviceObjects = DeviceObjects::new();

/// The global device-object table.
pub fn device_objects() -> &'static DeviceObjects {
    &DEVICE_OBJECTS
}

/// Attach `device` on top of `target`'s attachment chain: the new device's attached link points at
/// the chain's current top, which is returned.
pub fn io_attach_device_to_device_stack(
    objects: &DeviceObjects,
    device: DeviceId,
    target: DeviceId,
) -> Option<DeviceId> {
    let top = io_get_attached_device(objects, target);
    objects.get(device)?.set_attached(top);
    Some(top)
}

/// The top of the attachment chain `device` is in.
pub fn io_get_attached_device(objects: &DeviceObjects, device: DeviceId) -> DeviceId {
    let mut current = device;
    while let Some(object) = objects.get(current) {
        match object.attached() {
            Some(next) => current = next,
            None => return current,
        }
    }
    current
}

// --- The probe and start flow ----------------------------------------------------------------

/// Build the `IRP_MJ_PNP`/`IRP_MN_START_DEVICE` packet for a node, carrying the node's resources
/// in the start-device parameters (bus and translated forms alike, since this layer has one
/// resource view).
pub fn io_build_start_device_irp(node: &DeviceNode, device: &DeviceObject) -> Irp {
    let mut irp = Irp::new(device.stack_size as usize);
    let loc = irp::io_get_next_irp_stack_location_mut(&mut irp);
    loc.major = IRP_MJ_PNP;
    loc.minor = IRP_MN_START_DEVICE;
    loc.parameters.start_device.allocated_resources = node.resources();
    loc.parameters.start_device.allocated_resources_translated = node.resources();
    irp
}

/// Send the start-device packet down `device`'s dispatch table and complete it; the status the
/// start came back with.
pub fn send_start_device(node: &DeviceNode, device: &DeviceObject) -> NtStatus {
    let mut irp = io_build_start_device_irp(node, device);
    let status = irp::io_call_driver(device, &mut irp);
    if !irp.is_completed() {
        irp::io_complete_request(&mut irp, status);
    }
    status
}

/// Probe the registry with the driver table: for each unclaimed node, run the first matching
/// driver's add-device entry, send the start-device packet down the created device object, and
/// claim the node when the start succeeds. Returns the number of nodes started.
pub fn probe_and_start(nodes: &Nodes, drivers: &DriverTable, objects: &DeviceObjects) -> usize {
    let mut started = 0;
    for node in nodes.iter() {
        if nodes.claimed_by(node.id).is_some() {
            continue;
        }
        let Some((driver_id, driver)) = drivers.iter().find(|(_, d)| d.matches(node)) else {
            continue;
        };
        let Some(add_device) = driver.add_device else {
            continue;
        };
        if !add_device(driver, node, objects).is_success() {
            continue;
        }
        let Some(device) = objects.iter().find(|o| o.node == Some(node.id)) else {
            continue;
        };
        if send_start_device(node, device).is_success() && nodes.claim(node.id, driver_id) {
            started += 1;
        }
    }
    started
}

/// Probe the registry with the globally registered drivers and the global device-object table.
pub fn probe_registered(nodes: &Nodes) -> usize {
    probe_and_start(nodes, drivers(), device_objects())
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::sync::Mutex;

    use super::*;
    use crate::status::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

    // What a test driver's PnP dispatch observed at its MajorFunction entry.
    struct ObservedStart {
        major: u8,
        minor: u8,
        resources: Resources,
        device: usize,
        location_device: usize,
    }

    static OBSERVED: Mutex<Vec<ObservedStart>> = Mutex::new(Vec::new());
    static EXT: AtomicU32 = AtomicU32::new(0);

    fn pnp_dispatch(device: &DeviceObject, irp: &mut Irp) -> NtStatus {
        let loc = irp::io_get_current_irp_stack_location(irp);
        OBSERVED.lock().unwrap().push(ObservedStart {
            major: loc.major,
            minor: loc.minor,
            resources: loc.parameters.start_device.allocated_resources,
            device: device as *const DeviceObject as usize,
            location_device: loc.device_object as usize,
        });
        let status = STATUS_SUCCESS;
        irp::io_complete_request(irp, status);
        status
    }

    fn failing_pnp_dispatch(_device: &DeviceObject, _irp: &mut Irp) -> NtStatus {
        STATUS_UNSUCCESSFUL
    }

    fn add_device(
        driver: &'static DriverObject,
        node: &DeviceNode,
        objects: &DeviceObjects,
    ) -> NtStatus {
        let object = DeviceObject::new(
            driver,
            Some(node.id),
            FILE_DEVICE_DISK,
            &EXT as *const AtomicU32 as *mut c_void,
        );
        assert!(objects.create(object).is_some());
        STATUS_SUCCESS
    }

    /// The test driver: matches the 8086:7010 hardware ID, handles PnP at its major entry.
    fn test_driver() -> &'static DriverObject {
        static DRIVER: DriverObject = DriverObject::new(
            "f2k-dev-test",
            {
                let mut table: [Option<DispatchFn>; irp::IRP_MJ_MAX] = [None; irp::IRP_MJ_MAX];
                table[IRP_MJ_PNP as usize] = Some(pnp_dispatch);
                table
            },
            Some(add_device),
            MatchSpec::hardware_ids(&[HardwareId::new(0x8086, 0x7010)]),
        );
        &DRIVER
    }

    /// A driver whose start always fails.
    fn failing_driver() -> &'static DriverObject {
        static DRIVER: DriverObject = DriverObject::new(
            "f2k-dev-fail",
            {
                let mut table: [Option<DispatchFn>; irp::IRP_MJ_MAX] = [None; irp::IRP_MJ_MAX];
                table[IRP_MJ_PNP as usize] = Some(failing_pnp_dispatch);
                table
            },
            Some(add_device),
            MatchSpec::any(),
        );
        &DRIVER
    }

    fn synthetic_node(dev: u8, vendor: u16, device: u16, class_code: u32) -> DeviceNode {
        DeviceNode::new(
            Bus::Pci,
            BusAddress {
                bus: 0,
                dev,
                func: 0,
            },
            vendor,
            device,
            class_code,
            0x02,
            1,
            Some(Interrupt {
                pin: 1,
                isa_line: 10,
                vector: hal::interrupt_vector(10),
            }),
            [
                Bar::Memory {
                    base: 0xE000_0000,
                    size: 0x1000,
                    prefetchable: false,
                    wide: false,
                },
                Bar::Io(0xC000),
                Bar::None,
                Bar::None,
                Bar::None,
                Bar::None,
            ],
        )
    }

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

        let bridge = nodes.get(NodeId(0)).unwrap();
        assert_eq!(bridge.bus, Bus::Pci);
        assert_eq!(
            bridge.address,
            BusAddress {
                bus: 0,
                dev: 1,
                func: 3
            }
        );
        assert_eq!(bridge.hardware_id(), HardwareId::new(0x8086, 0x7000));
        assert_eq!(bridge.class(), 0x06);
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

        let nic = nodes.get(NodeId(1)).unwrap();
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
            nic.resources().bars[0],
            Bar::Memory {
                base: 0xE100_0000,
                size: 0x2000,
                prefetchable: false,
                wide: false
            }
        );
        assert_eq!(nic.resources().bars[1], Bar::Io(0xD000));

        let no_pin = nodes.get(NodeId(2)).unwrap();
        assert_eq!(no_pin.interrupt_pin, 0);
        assert_eq!(
            no_pin.interrupt, None,
            "a device without a pin has no interrupt"
        );
        assert_eq!(no_pin.resources(), Resources::EMPTY);

        // Without routes, the pins have no lines.
        let unrouted = Nodes::from_pci(&devices, None);
        assert_eq!(unrouted.get(NodeId(0)).unwrap().interrupt, None);
    }

    /// The probe/start flow: a registered test driver, a matched and an unmatched synthetic node;
    /// the matched node is claimed, its device object created, and the start-device packet
    /// observed at the MajorFunction entry with the right stack location and resources.
    #[test]
    fn probe_and_start_claims_matched_nodes_with_the_start_irp() {
        OBSERVED.lock().unwrap().clear();

        let mut nodes = Nodes::new();
        let matched = nodes
            .push(synthetic_node(3, 0x8086, 0x7010, 0x0101_00))
            .unwrap();
        let unmatched = nodes
            .push(synthetic_node(4, 0x1234, 0x5678, 0x0300_00))
            .unwrap();

        let drivers = DriverTable::new();
        let driver_id = drivers.register(test_driver()).unwrap();
        let objects = DeviceObjects::new();

        let started = probe_and_start(&nodes, &drivers, &objects);
        assert_eq!(started, 1, "only the matched node started");

        assert_eq!(nodes.claimed_by(matched), Some(driver_id));
        assert_eq!(
            nodes.claimed_by(unmatched),
            None,
            "an unmatched node stays unclaimed"
        );

        // The add-device entry created one device object for the matched node.
        assert_eq!(objects.len(), 1);
        let device = objects.iter().next().unwrap();
        assert_eq!(device.node, Some(matched));
        assert_eq!(device.driver_id, driver_id);
        assert_eq!(device.driver.name, "f2k-dev-test");
        assert_eq!(device.device_type, FILE_DEVICE_DISK);
        assert_eq!(
            device.extension, &EXT as *const AtomicU32 as *mut c_void,
            "the driver-owned extension pointer"
        );

        // The start-device IRP was observed at the MajorFunction entry. Other tests share the
        // observation log; this test's device address is its own.
        let observed = OBSERVED.lock().unwrap();
        let mine: Vec<&ObservedStart> = observed
            .iter()
            .filter(|o| o.device == device as *const DeviceObject as usize)
            .collect();
        assert_eq!(mine.len(), 1);
        let seen = mine[0];
        assert_eq!(seen.major, IRP_MJ_PNP);
        assert_eq!(seen.minor, IRP_MN_START_DEVICE);
        assert_eq!(seen.device, device as *const DeviceObject as usize);
        assert_eq!(
            seen.location_device, seen.device,
            "the location names the device"
        );
        let expected = nodes.get(matched).unwrap().resources();
        assert_eq!(
            seen.resources, expected,
            "the packet carries the node's resources"
        );
        assert_eq!(
            seen.resources.bars[0],
            Bar::Memory {
                base: 0xE000_0000,
                size: 0x1000,
                prefetchable: false,
                wide: false,
            }
        );
        assert_eq!(seen.resources.bars[1], Bar::Io(0xC000));
        assert_eq!(
            seen.resources.interrupt,
            Some(Interrupt {
                pin: 1,
                isa_line: 10,
                vector: hal::interrupt_vector(10)
            })
        );
    }

    /// A start that fails does not claim the node, though the device object was created.
    #[test]
    fn a_failing_start_leaves_the_node_unclaimed() {
        let mut nodes = Nodes::new();
        let node = nodes
            .push(synthetic_node(5, 0x8086, 0x7000, 0x0601_00))
            .unwrap();

        let drivers = DriverTable::new();
        let driver_id = drivers.register(failing_driver()).unwrap();
        let objects = DeviceObjects::new();

        let started = probe_and_start(&nodes, &drivers, &objects);
        assert_eq!(started, 0);
        assert_eq!(
            nodes.claimed_by(node),
            None,
            "the failed start did not claim"
        );
        assert_eq!(objects.len(), 1, "add-device ran before the start failed");
        let _ = driver_id;
    }

    /// A class-matched driver claims every node of the class; a hardware-ID match beats nothing
    /// here but is checked per ID.
    #[test]
    fn match_specs_select_the_nodes() {
        static CLASS_DRIVER: DriverObject = DriverObject::new(
            "f2k-dev-class",
            {
                let mut table: [Option<DispatchFn>; irp::IRP_MJ_MAX] = [None; irp::IRP_MJ_MAX];
                table[IRP_MJ_PNP as usize] = Some(pnp_dispatch);
                table
            },
            Some(add_device),
            MatchSpec::class(0x01),
        );

        let mut nodes = Nodes::new();
        let ide = nodes
            .push(synthetic_node(6, 0x8086, 0x7010, 0x0101_80))
            .unwrap();
        let vga = nodes
            .push(synthetic_node(7, 0x10DE, 0x0A38, 0x0300_00))
            .unwrap();

        assert!(CLASS_DRIVER.matches(nodes.get(ide).unwrap()));
        assert!(!CLASS_DRIVER.matches(nodes.get(vga).unwrap()));
        assert!(
            test_driver().matches(nodes.get(ide).unwrap()),
            "the hardware-ID match"
        );
        assert!(!test_driver().matches(nodes.get(vga).unwrap()));

        let drivers = DriverTable::new();
        drivers.register(&CLASS_DRIVER).unwrap();
        let objects = DeviceObjects::new();
        let started = probe_and_start(&nodes, &drivers, &objects);
        assert_eq!(started, 1, "the class driver took only the class-0x01 node");
        assert!(nodes.claimed_by(ide).is_some());
        assert_eq!(nodes.claimed_by(vga), None);
    }

    /// The attached-device link: attaching one device to another chains them, and the attached
    /// query walks to the top.
    #[test]
    fn the_attached_device_link_chains() {
        let driver = test_driver();
        let table = DriverTable::new();
        table.register(driver).unwrap();
        let objects = DeviceObjects::new();
        let base = objects
            .create(DeviceObject::new(
                driver,
                None,
                FILE_DEVICE_DISK,
                core::ptr::null_mut(),
            ))
            .unwrap();
        let filter = objects
            .create(DeviceObject::new(
                driver,
                None,
                FILE_DEVICE_DISK,
                core::ptr::null_mut(),
            ))
            .unwrap();

        assert_eq!(objects.get(base).unwrap().attached(), None);
        assert_eq!(io_get_attached_device(&objects, base), base);

        let top = io_attach_device_to_device_stack(&objects, filter, base).unwrap();
        assert_eq!(top, base, "the chain's previous top");
        assert_eq!(objects.get(filter).unwrap().attached(), Some(base));
        assert_eq!(io_get_attached_device(&objects, filter), base);

        let upper = objects
            .create(DeviceObject::new(
                driver,
                None,
                FILE_DEVICE_DISK,
                core::ptr::null_mut(),
            ))
            .unwrap();
        io_attach_device_to_device_stack(&objects, upper, filter);
        assert_eq!(objects.get(upper).unwrap().attached(), Some(base));
        assert_eq!(
            io_get_attached_device(&objects, upper),
            base,
            "the walk reaches the top"
        );
    }

    /// The global registration: register_driver fills the global fixed table.
    #[test]
    fn register_driver_fills_the_global_table() {
        let before = drivers().len();
        let id = register_driver(test_driver()).expect("the global table has room");
        assert_eq!(drivers().len(), before + 1);
        let driver = drivers().get(id).unwrap();
        assert_eq!(driver.name, "f2k-dev-test");
        assert_eq!(driver.id(), id);
        assert_eq!(driver.major_function[IRP_MJ_PNP as usize].is_some(), true);
    }
}
