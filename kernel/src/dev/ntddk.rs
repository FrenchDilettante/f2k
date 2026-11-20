//! The structures a legacy driver reads and writes, in Windows 2000's x86 layout (the DDK's
//! `ntddk.h`, as `drvload`'s capture prints each field's offset): DRIVER_OBJECT, DRIVER_EXTENSION,
//! DEVICE_OBJECT and its DEVOBJ_EXTENSION, the VPB, FILE_OBJECT, IRP and IO_STACK_LOCATION,
//! IO_SECURITY_CONTEXT, and the counted strings among them.
//!
//! A driver is built against these offsets, so F2K's must be them: every structure is `repr(C)`
//! with its pointers as 32-bit addresses (`u32`), so the layouts hold on the host too, where the
//! tests check each offset the capture shows. The fields F2K does not use keep their room as
//! padding, named after the field it stands for. What fills them is the I/O manager's
//! ([`super::io`]); nothing here touches memory.

use core::mem::{offset_of, size_of};

/// A UNICODE_STRING: the length and the room in bytes, and the buffer's address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u32,
}

// --- The object types (the CSHORT Type every I/O structure starts with) -----------------------

pub const IO_TYPE_DEVICE: u16 = 3;
pub const IO_TYPE_DRIVER: u16 = 4;
pub const IO_TYPE_FILE: u16 = 5;
pub const IO_TYPE_IRP: u16 = 6;
pub const IO_TYPE_VPB: u16 = 10;
pub const IO_TYPE_DEVICE_OBJECT_EXTENSION: u16 = 13;

// --- DRIVER_OBJECT ----------------------------------------------------------------------------

/// The dispatch table's entries: IRP_MJ_CREATE through IRP_MJ_PNP.
pub const MAJOR_FUNCTIONS: usize = 28;

/// DRVO_LEGACY_DRIVER: a driver NtLoadDriver loaded (not a PnP driver's AddDevice start).
pub const DRVO_LEGACY_DRIVER: u32 = 0x2;
/// DRVO_UNLOAD_INVOKED: its DriverUnload has run.
pub const DRVO_UNLOAD_INVOKED: u32 = 0x1;

/// DRIVER_OBJECT (0xA8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverObject {
    pub kind: u16,
    pub size: u16,
    pub device_object: u32,
    pub flags: u32,
    pub driver_start: u32,
    pub driver_size: u32,
    pub driver_section: u32,
    pub driver_extension: u32,
    pub driver_name: UnicodeString,
    pub hardware_database: u32,
    pub fast_io_dispatch: u32,
    pub driver_init: u32,
    pub driver_start_io: u32,
    pub driver_unload: u32,
    pub major_function: [u32; MAJOR_FUNCTIONS],
}

/// DRIVER_EXTENSION (0x18 bytes: Windows 2000's ends with ClientDriverExtension).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverExtension {
    pub driver_object: u32,
    pub add_device: u32,
    pub count: u32,
    pub service_key_name: UnicodeString,
    pub client_driver_extension: u32,
}

/// The module record DriverSection names: the head of Windows 2000's LDR_DATA_TABLE_ENTRY (its
/// three list links, then the image's base, entry point and size, and its two names), opaque to
/// the driver and kept by the I/O manager.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleEntry {
    pub links: [u32; 6],
    pub dll_base: u32,
    pub entry_point: u32,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

// --- DEVICE_OBJECT ----------------------------------------------------------------------------

/// DO_* flags.
pub const DO_EXCLUSIVE: u32 = 0x0000_0008;
pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
pub const DO_DIRECT_IO: u32 = 0x0000_0010;
pub const DO_DEVICE_HAS_NAME: u32 = 0x0000_0040;
pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

/// The documented FILE_DEVICE_* device types (winioctl.h), the kernel's one list. CD_ROM, DISK,
/// TAPE and VIRTUAL_DISK are the types that carry a volume (a VPB made with the device); 0x8 is
/// the *disk* file system's type, and the plain FILE_SYSTEM's is 0x9 (the value kernel32 routes
/// FSCTLs by).
pub const FILE_DEVICE_CD_ROM: u32 = 0x02;
pub const FILE_DEVICE_DISK: u32 = 0x07;
pub const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 0x08;
pub const FILE_DEVICE_FILE_SYSTEM: u32 = 0x09;
pub const FILE_DEVICE_KEYBOARD: u32 = 0x0B;
pub const FILE_DEVICE_NETWORK: u32 = 0x12;
pub const FILE_DEVICE_TAPE: u32 = 0x1F;
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const FILE_DEVICE_VIRTUAL_DISK: u32 = 0x24;

/// DEVOBJ_EXTENSION's ExtensionFlags: its driver's unload waits for the device's last reference
/// (NtUnloadDriver while it is open), and the device's delete does.
pub const DOE_UNLOAD_PENDING: u32 = 0x1;
pub const DOE_DELETE_PENDING: u32 = 0x2;

/// DEVICE_OBJECT (0xB8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DeviceObject {
    pub kind: u16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: u32,
    pub next_device: u32,
    pub attached_device: u32,
    pub current_irp: u32,
    pub timer: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: u32,
    pub device_extension: u32,
    pub device_type: u32,
    pub stack_size: u8,
    pub stack_size_padding: [u8; 3],
    /// Queue: a LIST_ENTRY or a WAIT_CONTEXT_BLOCK (0x28 bytes).
    pub queue: [u32; 10],
    pub alignment_requirement: u32,
    /// DeviceQueue: a KDEVICE_QUEUE (0x14 bytes).
    pub device_queue: [u32; 5],
    /// Dpc: a KDPC (0x20 bytes).
    pub dpc: [u32; 8],
    pub active_thread_count: u32,
    pub security_descriptor: u32,
    /// DeviceLock: a KEVENT (0x10 bytes).
    pub device_lock: [u32; 4],
    pub sector_size: u16,
    pub spare1: u16,
    pub device_object_extension: u32,
    pub reserved: u32,
}

/// DEVOBJ_EXTENSION (Windows 2000's, 0x20 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DevObjExtension {
    pub kind: u16,
    pub size: u16,
    pub device_object: u32,
    pub power_flags: u32,
    pub dope: u32,
    pub extension_flags: u32,
    pub device_node: u32,
    pub attached_to: u32,
    pub start_io_count: u32,
}

/// VPB (0x58 bytes): the volume parameter block a disk's device carries.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Vpb {
    pub kind: u16,
    pub size: u16,
    pub flags: u16,
    pub volume_label_length: u16,
    pub device_object: u32,
    pub real_device: u32,
    pub serial_number: u32,
    pub reference_count: u32,
    pub volume_label: [u16; 32],
}

// --- FILE_OBJECT ------------------------------------------------------------------------------

/// FO_SYNCHRONOUS_IO: the file was opened for synchronous I/O.
pub const FO_SYNCHRONOUS_IO: u32 = 0x0000_0002;

/// FILE_OBJECT (0x70 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileObject {
    pub kind: u16,
    pub size: u16,
    pub device_object: u32,
    pub vpb: u32,
    pub fs_context: u32,
    pub fs_context2: u32,
    pub section_object_pointer: u32,
    pub private_cache_map: u32,
    pub final_status: i32,
    pub related_file_object: u32,
    pub lock_operation: u8,
    pub delete_pending: u8,
    pub read_access: u8,
    pub write_access: u8,
    pub delete_access: u8,
    pub shared_read: u8,
    pub shared_write: u8,
    pub shared_delete: u8,
    pub flags: u32,
    pub file_name: UnicodeString,
    pub current_byte_offset: u64,
    pub waiters: u32,
    pub busy: u32,
    pub last_lock: u32,
    /// Lock and Event: two KEVENTs (0x10 bytes each).
    pub lock: [u32; 4],
    pub event: [u32; 4],
    pub completion_context: u32,
}

// --- IRP and IO_STACK_LOCATION ----------------------------------------------------------------

/// IRP flags.
pub const IRP_SYNCHRONOUS_API: u32 = 0x0000_0004;
pub const IRP_BUFFERED_IO: u32 = 0x0000_0010;
pub const IRP_DEALLOCATE_BUFFER: u32 = 0x0000_0020;
pub const IRP_INPUT_OPERATION: u32 = 0x0000_0040;
pub const IRP_CREATE_OPERATION: u32 = 0x0000_0080;
pub const IRP_READ_OPERATION: u32 = 0x0000_0100;
pub const IRP_WRITE_OPERATION: u32 = 0x0000_0200;
pub const IRP_CLOSE_OPERATION: u32 = 0x0000_0400;
pub const IRP_DEFER_IO_COMPLETION: u32 = 0x0000_0800;

/// The stack location's Control bits: a completion routine's conditions, and the pending mark.
pub const SL_PENDING_RETURNED: u8 = 0x01;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// The requestor modes.
pub const KERNEL_MODE: u8 = 0;
pub const USER_MODE: u8 = 1;

/// IRP (0x70 bytes; its stack locations follow it).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Irp {
    pub kind: u16,
    pub size: u16,
    pub mdl_address: u32,
    pub flags: u32,
    /// AssociatedIrp: MasterIrp, IrpCount or SystemBuffer.
    pub system_buffer: u32,
    pub thread_list_entry: [u32; 2],
    pub io_status_status: i32,
    pub io_status_information: u32,
    pub requestor_mode: u8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub cancel: u8,
    pub cancel_irql: u8,
    pub apc_environment: i8,
    pub allocation_flags: u8,
    pub user_iosb: u32,
    pub user_event: u32,
    /// Overlay: AsynchronousParameters (UserApcRoutine, UserApcContext) or AllocationSize.
    pub overlay: [u32; 2],
    pub cancel_routine: u32,
    pub user_buffer: u32,
    /// Tail.Overlay: DeviceQueueEntry or DriverContext[4] (0x10 bytes).
    pub driver_context: [u32; 4],
    pub thread: u32,
    pub auxiliary_buffer: u32,
    pub list_entry: [u32; 2],
    /// CurrentStackLocation (or PacketType).
    pub current_stack_location: u32,
    pub original_file_object: u32,
    /// The rest of Tail: room for its KAPC alternative (0x30 bytes in all).
    pub tail_rest: [u32; 2],
}

/// IO_STACK_LOCATION (0x24 bytes). Parameters is four dwords whose meaning the major function
/// gives (see [`CreateParameters`] and [`DeviceIoControlParameters`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: [u32; 4],
    pub device_object: u32,
    pub file_object: u32,
    pub completion_routine: u32,
    pub context: u32,
}

/// Parameters.Create: the security context, the options (the disposition in the top byte), the
/// file attributes and share access, the extended attributes' length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateParameters {
    pub security_context: u32,
    pub options: u32,
    pub file_attributes: u16,
    pub share_access: u16,
    pub ea_length: u32,
}

/// Parameters.DeviceIoControl.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceIoControlParameters {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub io_control_code: u32,
    pub type3_input_buffer: u32,
}

/// IO_SECURITY_CONTEXT: what an IRP_MJ_CREATE's Create.SecurityContext names.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoSecurityContext {
    pub security_qos: u32,
    pub access_state: u32,
    pub desired_access: u32,
    pub full_create_options: u32,
}

/// An IRP's size with `stack_count` stack locations (IoSizeOfIrp).
pub const fn irp_size(stack_count: u8) -> usize {
    size_of::<Irp>() + stack_count as usize * size_of::<IoStackLocation>()
}

// The layouts, as the DDK's: checked at compile time on every target.
const _: () = {
    assert!(size_of::<UnicodeString>() == 8);
    assert!(size_of::<DriverObject>() == 0xA8);
    assert!(offset_of!(DriverObject, driver_name) == 0x1C);
    assert!(offset_of!(DriverObject, hardware_database) == 0x24);
    assert!(offset_of!(DriverObject, driver_unload) == 0x34);
    assert!(offset_of!(DriverObject, major_function) == 0x38);
    assert!(size_of::<DriverExtension>() == 0x18);
    assert!(offset_of!(DriverExtension, service_key_name) == 0x0C);
    assert!(size_of::<DeviceObject>() == 0xB8);
    assert!(offset_of!(DeviceObject, flags) == 0x1C);
    assert!(offset_of!(DeviceObject, device_type) == 0x2C);
    assert!(offset_of!(DeviceObject, stack_size) == 0x30);
    assert!(offset_of!(DeviceObject, alignment_requirement) == 0x5C);
    assert!(offset_of!(DeviceObject, sector_size) == 0xAC);
    assert!(offset_of!(DeviceObject, device_object_extension) == 0xB0);
    assert!(size_of::<DevObjExtension>() == 0x20);
    assert!(size_of::<Vpb>() == 0x58);
    assert!(size_of::<FileObject>() == 0x70);
    assert!(offset_of!(FileObject, related_file_object) == 0x20);
    assert!(offset_of!(FileObject, flags) == 0x2C);
    assert!(offset_of!(FileObject, file_name) == 0x30);
    assert!(size_of::<Irp>() == 0x70);
    assert!(offset_of!(Irp, flags) == 0x08);
    assert!(offset_of!(Irp, system_buffer) == 0x0C);
    assert!(offset_of!(Irp, io_status_status) == 0x18);
    assert!(offset_of!(Irp, requestor_mode) == 0x20);
    assert!(offset_of!(Irp, pending_returned) == 0x21);
    assert!(offset_of!(Irp, stack_count) == 0x22);
    assert!(offset_of!(Irp, current_location) == 0x23);
    assert!(offset_of!(Irp, cancel) == 0x24);
    assert!(offset_of!(Irp, user_buffer) == 0x3C);
    assert!(offset_of!(Irp, thread) == 0x50);
    assert!(offset_of!(Irp, current_stack_location) == 0x60);
    assert!(offset_of!(Irp, original_file_object) == 0x64);
    assert!(size_of::<IoStackLocation>() == 0x24);
    assert!(offset_of!(IoStackLocation, parameters) == 0x04);
    assert!(offset_of!(IoStackLocation, device_object) == 0x14);
    assert!(offset_of!(IoStackLocation, file_object) == 0x18);
    assert!(size_of::<CreateParameters>() == 16);
    assert!(size_of::<DeviceIoControlParameters>() == 16);
    assert!(size_of::<ModuleEntry>() == 0x34);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes the capture prints: the driver object's 168, the device object's 184, the file
    /// object's 112, and an IRP of one stack location's 148 (IoSizeOfIrp).
    #[test]
    fn the_sizes_are_the_captures() {
        assert_eq!(size_of::<DriverObject>(), 168);
        assert_eq!(size_of::<DeviceObject>(), 184);
        assert_eq!(size_of::<FileObject>(), 112);
        assert_eq!(irp_size(1), 148);
    }

    /// The device types are winioctl.h's: the file system's is 0x9, and 0x8 the disk file
    /// system's.
    #[test]
    fn the_device_types_are_winioctl_values() {
        assert_eq!(FILE_DEVICE_DISK_FILE_SYSTEM, 0x8);
        assert_eq!(FILE_DEVICE_FILE_SYSTEM, 0x9);
        assert_eq!(
            [
                FILE_DEVICE_CD_ROM,
                FILE_DEVICE_DISK,
                FILE_DEVICE_KEYBOARD,
                FILE_DEVICE_NETWORK
            ],
            [0x2, 0x7, 0xB, 0x12]
        );
        assert_eq!(
            [
                FILE_DEVICE_TAPE,
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_VIRTUAL_DISK
            ],
            [0x1F, 0x22, 0x24]
        );
    }
}
