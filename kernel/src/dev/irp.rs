//! The I/O request packet (IRP) spine: the packet, its fixed I/O stack of locations, and the
//! call/complete pattern the drivers' dispatch tables run on.
//!
//! An [`Irp`] carries a fixed stack of [`IoStackLocation`]s — at most [`IRP_STACK_LOCATIONS`],
//! with one extra slot in the array so a freshly built packet's current-location pointer can sit
//! one past the top, the way the public packet's does. The current location is the one the next
//! [`io_call_driver`] dispatches at: [`io_call_driver`] moves the pointer down one location, sets
//! that location's device object, and calls the device's driver's `MajorFunction[major]`. A
//! driver passing the packet down copies its location one slot down
//! ([`io_copy_current_irp_stack_location_to_next`]) and pushes
//! ([`io_set_next_irp_stack_location`]); [`io_complete_request`] walks the locations back up,
//! running each location's completion routine where its control bits ask for it, and then the
//! packet is done.
//!
//! The major and minor function codes are the documented `IRP_MJ_*` / `IRP_MN_*` values, and the
//! stack-location parameters carry the common cases as named fields; a request kind that does not
//! apply reads as zeroes.

// Nothing calls the spine yet (the boot wiring is a later slice), so the target build sees no
// caller for it.
#![cfg_attr(not(test), allow(dead_code))]

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use super::{DeviceObject, Resources, Vpb};
use crate::status::{NtStatus, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

// --- The major function codes ---------------------------------------------------------------

pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_QUERY_EA: u8 = 0x07;
pub const IRP_MJ_SET_EA: u8 = 0x08;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0a;
pub const IRP_MJ_SET_VOLUME_INFORMATION: u8 = 0x0b;
pub const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0c;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0d;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: u8 = 0x13;
pub const IRP_MJ_QUERY_SECURITY: u8 = 0x14;
pub const IRP_MJ_SET_SECURITY: u8 = 0x15;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: u8 = 0x18;
pub const IRP_MJ_QUERY_QUOTA: u8 = 0x19;
pub const IRP_MJ_SET_QUOTA: u8 = 0x1a;
pub const IRP_MJ_PNP: u8 = 0x1b;

/// The dispatch table's entry count: the major codes 0x00 through 0x1b.
pub const IRP_MJ_MAX: usize = 0x1c;

// --- The minor function codes ---------------------------------------------------------------

// PnP requests (under IRP_MJ_PNP):
pub const IRP_MN_START_DEVICE: u8 = 0x00;
pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x07;
pub const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;
pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0a;
pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0b;
pub const IRP_MN_QUERY_DEVICE_TEXT: u8 = 0x0c;
pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0d;
pub const IRP_MN_READ_CONFIG: u8 = 0x0f;
pub const IRP_MN_WRITE_CONFIG: u8 = 0x10;
pub const IRP_MN_EJECT: u8 = 0x11;
pub const IRP_MN_SET_LOCK: u8 = 0x12;
pub const IRP_MN_QUERY_ID: u8 = 0x13;
pub const IRP_MN_QUERY_PNP_DEVICE_STATE: u8 = 0x14;
pub const IRP_MN_QUERY_BUS_INFORMATION: u8 = 0x15;
pub const IRP_MN_DEVICE_USAGE_NOTIFICATION: u8 = 0x16;
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;
pub const IRP_MN_QUERY_LEGACY_BUS_INFORMATION: u8 = 0x18;

// File-system-control requests (under IRP_MJ_FILE_SYSTEM_CONTROL):
pub const IRP_MN_MOUNT_VOLUME: u8 = 0x01;
pub const IRP_MN_VERIFY_VOLUME: u8 = 0x02;
pub const IRP_MN_LOAD_FILE_SYSTEM: u8 = 0x03;

// --- The stack-location control bits --------------------------------------------------------

/// The completion routine runs when the packet completes with a cancel.
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
/// The completion routine runs when the packet completes successfully.
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
/// The completion routine runs when the packet completes with an error.
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// The I/O stack's capacity: the most stack locations a packet built here carries.
pub const IRP_STACK_LOCATIONS: usize = 8;

// --- The stack location's parameters --------------------------------------------------------

/// A read or write request's parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReadWrite {
    pub length: u32,
    pub key: u32,
    pub byte_offset: u64,
}

/// A device I/O control request's parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceIoControl {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub io_control_code: u32,
}

/// A file-system control request's parameters (the same shape as a device I/O control's).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FileSystemControl {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub fs_control_code: u32,
}

/// A mount-volume request's parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MountVolume {
    pub vpb: *mut Vpb,
    pub device_object: *const DeviceObject,
}

impl Default for MountVolume {
    fn default() -> Self {
        MountVolume {
            vpb: null_mut(),
            device_object: null(),
        }
    }
}

/// A start-device request's parameters: the resources the PnP manager allocated for the device,
/// in bus terms and in translated (system) terms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StartDevice {
    pub allocated_resources: Resources,
    pub allocated_resources_translated: Resources,
}

impl Default for StartDevice {
    fn default() -> Self {
        StartDevice {
            allocated_resources: Resources::EMPTY,
            allocated_resources_translated: Resources::EMPTY,
        }
    }
}

/// The catch-all parameters for the request kinds without a named case here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Others {
    pub argument1: usize,
    pub argument2: usize,
    pub argument3: usize,
    pub argument4: usize,
}

/// A stack location's parameters: every case as a named field, so the one that applies to the
/// request's major/minor codes is the one that carries values and the rest read as zeroes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parameters {
    pub read: ReadWrite,
    pub write: ReadWrite,
    pub device_io_control: DeviceIoControl,
    pub file_system_control: FileSystemControl,
    pub mount_volume: MountVolume,
    pub start_device: StartDevice,
    pub others: Others,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            read: ReadWrite::default(),
            write: ReadWrite::default(),
            device_io_control: DeviceIoControl::default(),
            file_system_control: FileSystemControl::default(),
            mount_volume: MountVolume::default(),
            start_device: StartDevice::default(),
            others: Others::default(),
        }
    }
}

// --- The I/O stack location -----------------------------------------------------------------

/// The completion routine a stack location runs when the packet completes: the device object of
/// the location above (`None` at the top of the stack), the packet, and the location's context.
pub type CompletionFn = fn(Option<&DeviceObject>, &mut Irp, *mut c_void) -> NtStatus;

/// One driver's slot in the packet's I/O stack: the function codes, the parameters, and the
/// device object the packet is being sent to.
#[derive(Clone, Copy, Debug)]
pub struct IoStackLocation {
    pub major: u8,
    pub minor: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: Parameters,
    pub device_object: *const DeviceObject,
    pub completion: Option<CompletionFn>,
    pub completion_context: *mut c_void,
}

impl Default for IoStackLocation {
    fn default() -> Self {
        IoStackLocation {
            major: 0,
            minor: 0,
            flags: 0,
            control: 0,
            parameters: Parameters::default(),
            device_object: null(),
            completion: None,
            completion_context: null_mut(),
        }
    }
}

// --- The packet ------------------------------------------------------------------------------

/// An I/O request packet: a fixed I/O stack plus the status block. `current` is the index of the
/// current stack location; a freshly built packet's `current` is `stack_count`, one past the top
/// slot, and the build helpers fill the top slot through the next-location accessors.
pub struct Irp {
    stack: [IoStackLocation; IRP_STACK_LOCATIONS + 1],
    stack_count: u8,
    current: u8,
    /// The packet's I/O status block: the final status and the information word.
    pub status: NtStatus,
    pub information: usize,
    pub flags: u32,
    completed: bool,
}

impl Irp {
    /// A packet with `stack_count` I/O stack locations (1 to [`IRP_STACK_LOCATIONS`]).
    ///
    /// # Panics
    ///
    /// `stack_count` is out of range.
    pub fn new(stack_count: usize) -> Self {
        assert!(
            (1..=IRP_STACK_LOCATIONS).contains(&stack_count),
            "an IRP's stack size is 1 to IRP_STACK_LOCATIONS"
        );
        Irp {
            stack: [IoStackLocation::default(); IRP_STACK_LOCATIONS + 1],
            stack_count: stack_count as u8,
            current: stack_count as u8,
            status: STATUS_SUCCESS,
            information: 0,
            flags: 0,
            completed: false,
        }
    }

    /// The number of I/O stack locations the packet was built with.
    pub fn stack_count(&self) -> usize {
        self.stack_count as usize
    }

    /// The current location's index: `stack_count` on a freshly built packet, one less for every
    /// [`io_call_driver`] that has dispatched it.
    pub fn current_location(&self) -> usize {
        self.current as usize
    }

    /// Whether [`io_complete_request`] has run on the packet.
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

// --- The stack-location accessors ------------------------------------------------------------

/// The current I/O stack location.
pub fn io_get_current_irp_stack_location(irp: &Irp) -> &IoStackLocation {
    &irp.stack[irp.current as usize]
}

/// The current I/O stack location, mutable, for the builder filling the packet.
pub fn io_get_current_irp_stack_location_mut(irp: &mut Irp) -> &mut IoStackLocation {
    &mut irp.stack[irp.current as usize]
}

/// The next (one below the current) I/O stack location: the slot a build helper fills and a
/// driver's copy-to-next targets.
///
/// # Panics
///
/// The current location is the bottom of the stack.
pub fn io_get_next_irp_stack_location(irp: &Irp) -> &IoStackLocation {
    assert!(irp.current >= 1, "no more IRP stack locations");
    &irp.stack[irp.current as usize - 1]
}

/// The next I/O stack location, mutable.
pub fn io_get_next_irp_stack_location_mut(irp: &mut Irp) -> &mut IoStackLocation {
    assert!(irp.current >= 1, "no more IRP stack locations");
    &mut irp.stack[irp.current as usize - 1]
}

/// Push the stack: the current location becomes the next one down.
///
/// # Panics
///
/// The current location is the bottom of the stack.
pub fn io_set_next_irp_stack_location(irp: &mut Irp) {
    assert!(irp.current >= 1, "no more IRP stack locations");
    irp.current -= 1;
}

/// Copy the current location's function codes, parameters and device object down to the next
/// location, and zero the next location's control byte (the completion fields are not copied).
pub fn io_copy_current_irp_stack_location_to_next(irp: &mut Irp) {
    assert!(irp.current >= 1, "no more IRP stack locations");
    let current = irp.current as usize;
    let mut next = irp.stack[current];
    next.control = 0;
    next.completion = None;
    next.completion_context = null_mut();
    irp.stack[current - 1] = next;
}

/// Skip the current location: the current location becomes the one above it, leaving the
/// packet's arguments for the next driver unchanged.
pub fn io_skip_current_irp_stack_location(irp: &mut Irp) {
    assert!(
        (irp.current as usize) < irp.stack_count as usize,
        "no more IRP stack locations"
    );
    irp.current += 1;
}

/// Set the next location's completion routine and the control bits that invoke it.
pub fn io_set_completion_routine(
    irp: &mut Irp,
    routine: CompletionFn,
    context: *mut c_void,
    invoke_on_success: bool,
    invoke_on_error: bool,
    invoke_on_cancel: bool,
) {
    let loc = io_get_next_irp_stack_location_mut(irp);
    loc.completion = Some(routine);
    loc.completion_context = context;
    loc.control = (if invoke_on_success {
        SL_INVOKE_ON_SUCCESS
    } else {
        0
    }) | (if invoke_on_error {
        SL_INVOKE_ON_ERROR
    } else {
        0
    }) | (if invoke_on_cancel {
        SL_INVOKE_ON_CANCEL
    } else {
        0
    });
}

// --- The call and complete pattern -----------------------------------------------------------

/// Send the packet to `device`: move the stack pointer down one location, set that location's
/// device object, and call the device's driver's `MajorFunction[major]` with the packet. The
/// returned status is the dispatch entry's.
///
/// # Panics
///
/// The packet's I/O stack is exhausted.
pub fn io_call_driver(device: &DeviceObject, irp: &mut Irp) -> NtStatus {
    assert!(irp.current >= 1, "no more IRP stack locations");
    irp.current -= 1;
    irp.stack[irp.current as usize].device_object = device as *const DeviceObject;
    let major = irp.stack[irp.current as usize].major as usize;
    assert!(
        major < IRP_MJ_MAX,
        "a major function code past the dispatch table"
    );
    match device.driver.major_function[major] {
        Some(dispatch) => dispatch(device, irp),
        None => STATUS_NOT_IMPLEMENTED,
    }
}

/// Complete the packet with `status`: walk the stack locations from the current one back up to
/// the top, running each location's completion routine when its control bits and the status ask
/// for it (each location is cleared as it is passed), then the packet is done.
pub fn io_complete_request(irp: &mut Irp, status: NtStatus) {
    irp.status = status;
    let stack_count = irp.stack_count as usize;
    let mut index = irp.current as usize;
    loop {
        let control = irp.stack[index].control;
        let invoke = (status.is_success() && control & SL_INVOKE_ON_SUCCESS != 0)
            || (!status.is_success() && control & SL_INVOKE_ON_ERROR != 0);
        if invoke {
            if let Some(routine) = irp.stack[index].completion {
                let context = irp.stack[index].completion_context;
                // The location above's device object, or none at the top of the stack.
                let above = if index + 1 <= stack_count {
                    let ptr = irp.stack[index + 1].device_object;
                    if ptr.is_null() {
                        None
                    } else {
                        // SAFETY: a non-null device object pointer in a stack location names a
                        // device object in the registry, which outlives the packet.
                        Some(unsafe { &*ptr })
                    }
                } else {
                    None
                };
                let _ = routine(above, irp, context);
            }
        }
        irp.stack[index] = IoStackLocation::default();
        if index >= stack_count {
            break;
        }
        index += 1;
    }
    irp.completed = true;
}

// --- The build helpers -----------------------------------------------------------------------

/// Build an `IRP_MJ_DEVICE_CONTROL` packet for `device` (the simplified shape of the public
/// builder: the control code and the two buffer lengths, no buffers or event).
pub fn io_build_device_io_control_request(
    device: &DeviceObject,
    io_control_code: u32,
    input_buffer_length: u32,
    output_buffer_length: u32,
) -> Irp {
    let mut irp = Irp::new(device.stack_size as usize);
    let loc = io_get_next_irp_stack_location_mut(&mut irp);
    loc.major = IRP_MJ_DEVICE_CONTROL;
    loc.parameters.device_io_control.io_control_code = io_control_code;
    loc.parameters.device_io_control.input_buffer_length = input_buffer_length;
    loc.parameters.device_io_control.output_buffer_length = output_buffer_length;
    irp
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::dev::{
        Bus,
        BusAddress,
        DeviceId,
        DeviceNode,
        DeviceObjects,
        DriverObject,
        DriverTable,
        HardwareId,
        MatchSpec,
        FILE_DEVICE_DISK,
    };
    use crate::status::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

    // A test driver with dispatch entries and an add-device entry, plus the observations its
    // dispatch makes of the packet it receives.
    struct Observed {
        major: u8,
        minor: u8,
        control_code: u32,
        device: usize,
        location_device: usize,
        current: usize,
    }

    static OBSERVED: Mutex<Vec<Observed>> = Mutex::new(Vec::new());
    static COMPLETIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new()); // (above, context)

    fn dispatch(device: &DeviceObject, irp: &mut Irp) -> NtStatus {
        let loc = io_get_current_irp_stack_location(irp);
        OBSERVED.lock().unwrap().push(Observed {
            major: loc.major,
            minor: loc.minor,
            control_code: loc.parameters.device_io_control.io_control_code,
            device: device as *const DeviceObject as usize,
            location_device: loc.device_object as usize,
            current: irp.current_location(),
        });
        let status = STATUS_SUCCESS;
        io_complete_request(irp, status);
        status
    }

    /// A dispatch entry that returns without completing the packet.
    fn open_dispatch(_device: &DeviceObject, _irp: &mut Irp) -> NtStatus {
        STATUS_SUCCESS
    }

    /// A dispatch entry that fails the packet and leaves it open.
    fn failing_dispatch(_device: &DeviceObject, _irp: &mut Irp) -> NtStatus {
        STATUS_UNSUCCESSFUL
    }

    fn completion(above: Option<&DeviceObject>, _irp: &mut Irp, context: *mut c_void) -> NtStatus {
        COMPLETIONS.lock().unwrap().push((
            above
                .map(|d| d as *const DeviceObject as usize)
                .unwrap_or(0),
            context as usize,
        ));
        STATUS_SUCCESS
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
            core::ptr::null_mut(),
        );
        assert!(objects.create(object).is_some());
        STATUS_SUCCESS
    }

    fn test_driver() -> &'static DriverObject {
        static DRIVER: DriverObject = DriverObject::new(
            "f2k-irp-test",
            {
                let mut table: [Option<crate::dev::DispatchFn>; IRP_MJ_MAX] = [None; IRP_MJ_MAX];
                table[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch);
                table[IRP_MJ_CREATE as usize] = Some(open_dispatch);
                table[IRP_MJ_READ as usize] = Some(failing_dispatch);
                table
            },
            Some(add_device),
            MatchSpec::hardware_ids(&[HardwareId::new(0x8086, 0x7010)]),
        );
        &DRIVER
    }

    fn test_device() -> (DeviceObjects, DeviceId) {
        let driver = test_driver();
        let table = DriverTable::new();
        let driver_id = table.register(driver).unwrap();
        assert_eq!(driver.id(), driver_id);
        let objects = DeviceObjects::new();
        let node = DeviceNode::new(
            Bus::Pci,
            BusAddress {
                bus: 0,
                dev: 3,
                func: 0,
            },
            0x8086,
            0x7010,
            0x060100,
            0x02,
            1,
            None,
            [crate::hw::pci::Bar::None; 6],
        );
        let id = objects
            .create(DeviceObject::new(
                driver,
                Some(node.id),
                FILE_DEVICE_DISK,
                core::ptr::null_mut(),
            ))
            .unwrap();
        (objects, id)
    }

    /// Push, copy and skip: the pointer moves down with io_set_next_irp_stack_location, the copy
    /// carries the function codes and parameters down and zeroes the control byte, and skip moves
    /// the pointer back up.
    #[test]
    fn the_stack_pushes_copies_and_skips() {
        let mut irp = Irp::new(3);
        assert_eq!(irp.stack_count(), 3);
        assert_eq!(irp.current_location(), 3);

        // The builder fills the top slot through the next-location accessor.
        let loc = io_get_next_irp_stack_location_mut(&mut irp);
        loc.major = IRP_MJ_READ;
        loc.minor = 0x07;
        loc.control = SL_INVOKE_ON_SUCCESS;
        loc.parameters.read.length = 512;
        loc.parameters.read.byte_offset = 0x1000;

        io_set_next_irp_stack_location(&mut irp);
        assert_eq!(irp.current_location(), 2);
        let current = io_get_current_irp_stack_location(&irp);
        assert_eq!(current.major, IRP_MJ_READ);
        assert_eq!(current.minor, 0x07);
        assert_eq!(current.parameters.read.length, 512);

        io_copy_current_irp_stack_location_to_next(&mut irp);
        let next = io_get_next_irp_stack_location(&irp);
        assert_eq!(
            next.major, IRP_MJ_READ,
            "the copy carries the function codes"
        );
        assert_eq!(next.parameters.read.length, 512, "and the parameters");
        assert_eq!(next.parameters.read.byte_offset, 0x1000);
        assert_eq!(next.control, 0, "the copy zeroes the control byte");
        assert!(
            next.completion.is_none(),
            "and does not copy the completion fields"
        );

        io_set_next_irp_stack_location(&mut irp);
        assert_eq!(irp.current_location(), 1);
        io_skip_current_irp_stack_location(&mut irp);
        assert_eq!(irp.current_location(), 2);
        assert_eq!(
            io_get_current_irp_stack_location(&irp)
                .parameters
                .read
                .length,
            512
        );
    }

    /// io_call_driver moves the pointer down to the location the builder filled, sets that
    /// location's device object, dispatches at MajorFunction[major], and the dispatch's status and
    /// completion come back out.
    #[test]
    fn io_call_driver_dispatches_the_built_location_and_propagates_the_status() {
        OBSERVED.lock().unwrap().clear();
        let (objects, id) = test_device();
        let device = objects.get(id).unwrap();

        let mut irp = io_build_device_io_control_request(device, 0x2D_1234, 8, 16);
        assert_eq!(
            irp.current_location(),
            2,
            "a fresh packet points one past the top"
        );
        assert_eq!(
            io_get_next_irp_stack_location(&irp).major,
            IRP_MJ_DEVICE_CONTROL
        );

        let status = io_call_driver(device, &mut irp);
        assert_eq!(
            status, STATUS_SUCCESS,
            "the dispatch's status propagates out"
        );
        assert_eq!(irp.status, STATUS_SUCCESS);
        assert!(irp.is_completed(), "the dispatch completed the packet");
        assert_eq!(
            irp.current_location(),
            1,
            "the call moved the pointer down one"
        );

        let observed = OBSERVED.lock().unwrap();
        // Other tests share the observation log; this test's device address is its own.
        let mine: Vec<&Observed> = observed
            .iter()
            .filter(|o| o.device == device as *const DeviceObject as usize)
            .collect();
        assert_eq!(mine.len(), 1);
        let seen = mine[0];
        assert_eq!(seen.major, IRP_MJ_DEVICE_CONTROL);
        assert_eq!(seen.control_code, 0x2D_1234);
        assert_eq!(
            seen.current, 1,
            "the dispatch saw the location it was called at"
        );
        assert_eq!(seen.device, device as *const DeviceObject as usize);
        assert_eq!(
            seen.location_device, seen.device,
            "io_call_driver set the location's device object"
        );
    }

    /// A dispatch entry that does not complete the packet: io_complete_request runs the location's
    /// completion routine on the error path (control bits decide), per stack location, and then
    /// the packet is done.
    #[test]
    fn io_complete_request_runs_completions_per_stack_location() {
        COMPLETIONS.lock().unwrap().clear();
        let (objects, id) = test_device();
        let device = objects.get(id).unwrap();

        // A read packet with two locations: the top one (index 1) has a completion routine that
        // runs on error; the dispatch fails without completing.
        let mut irp = Irp::new(2);
        {
            let loc = io_get_next_irp_stack_location_mut(&mut irp);
            loc.major = IRP_MJ_READ;
        }
        io_set_completion_routine(
            &mut irp,
            completion,
            0xABCD as *mut c_void,
            false,
            true,
            false,
        );

        let status = io_call_driver(device, &mut irp);
        assert_eq!(
            status, STATUS_UNSUCCESSFUL,
            "the failing dispatch's status propagates"
        );
        assert!(!irp.is_completed(), "the dispatch left the packet open");

        io_complete_request(&mut irp, STATUS_UNSUCCESSFUL);
        assert!(irp.is_completed());
        assert_eq!(irp.status, STATUS_UNSUCCESSFUL);

        let completions = COMPLETIONS.lock().unwrap();
        // Other tests share the completion log; this test's context marks its own entries.
        let mine: Vec<&(usize, usize)> = completions
            .iter()
            .filter(|(_, context)| *context == 0xABCD)
            .collect();
        assert_eq!(mine.len(), 1, "one location asked for an error completion");
        assert_eq!(
            mine[0].0, 0,
            "the top location's completion sees no device above it"
        );
        assert!(
            io_get_current_irp_stack_location(&irp).major == 0,
            "a completed location is cleared"
        );
    }

    /// A success status runs the completion routine only where SL_INVOKE_ON_SUCCESS is set: the
    /// open dispatch returns without completing, and io_complete_request runs the location's
    /// routine on the success path.
    #[test]
    fn a_success_completion_runs_on_the_success_path() {
        COMPLETIONS.lock().unwrap().clear();
        let (objects, id) = test_device();
        let device = objects.get(id).unwrap();

        let mut irp = Irp::new(1);
        {
            let loc = io_get_next_irp_stack_location_mut(&mut irp);
            loc.major = IRP_MJ_CREATE;
        }
        io_set_completion_routine(
            &mut irp,
            completion,
            0x55AA as *mut c_void,
            true,
            false,
            false,
        );

        let status = io_call_driver(device, &mut irp);
        assert_eq!(status, STATUS_SUCCESS);
        assert!(
            !irp.is_completed(),
            "the open dispatch left the packet open"
        );

        io_complete_request(&mut irp, STATUS_SUCCESS);
        assert!(irp.is_completed());
        let completions = COMPLETIONS.lock().unwrap();
        let mine: Vec<&(usize, usize)> = completions
            .iter()
            .filter(|(_, context)| *context == 0x55AA)
            .collect();
        assert_eq!(mine.len(), 1, "the success bit invoked the routine");
        assert_eq!(mine[0].0, 0, "no device object above the top location");
    }

    /// The stack is finite: a call past the bottom location panics, the packet's own
    /// no-more-stack-locations check.
    #[test]
    #[should_panic(expected = "no more IRP stack locations")]
    fn a_call_past_the_bottom_of_the_stack_panics() {
        let (objects, id) = test_device();
        let device = objects.get(id).unwrap();

        let mut irp = Irp::new(1);
        {
            let loc = io_get_next_irp_stack_location_mut(&mut irp);
            loc.major = IRP_MJ_DEVICE_CONTROL;
        }
        let _ = io_call_driver(device, &mut irp); // current 1 -> 0, dispatched
        let _ = io_call_driver(device, &mut irp); // past the bottom
    }

    /// A major code with no dispatch entry in the driver's table reports not-implemented.
    #[test]
    fn an_undispatched_major_code_reports_not_implemented() {
        let (objects, id) = test_device();
        let device = objects.get(id).unwrap();

        let mut irp = Irp::new(1);
        {
            let loc = io_get_next_irp_stack_location_mut(&mut irp);
            loc.major = IRP_MJ_POWER; // the test driver has no power entry
        }
        assert_eq!(io_call_driver(device, &mut irp), STATUS_NOT_IMPLEMENTED);
    }
}
