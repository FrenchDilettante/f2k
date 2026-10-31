//! ntdll's own calls on the system services, through the gate (`rtl::sys::system_service`): one
//! typed function per service, which lays out its argument block from references and handles, so
//! the code over them stays safe. A service whose effect safe code could not answer for (resuming
//! a context, raising an exception, unmapping a view, changing a protection) is an `unsafe fn` with
//! its contract.

use core::mem::size_of;

use rtl::nt::info::{FileBasicInformation, MemoryBasicInformation};
use rtl::nt::IoStatusBlock;
use rtl::pod::Pod;
use rtl::status::STATUS_SUCCESS;
use rtl::string::UnicodeString;
use rtl::sys::{nr, system_service, SYS_DEBUG_PRINT};

/// OBJECT_ATTRIBUTES (`rtl::nt`'s): a name for the open services, borrowed for as long as the
/// attributes are.
pub(crate) type ObjectAttributes<'a> = rtl::nt::ObjectAttributes<u32, &'a UnicodeString, usize>;

/// The current-process pseudo-handle.
pub(crate) const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// MemoryBasicInformation, NtQueryVirtualMemory's class.
const MEMORY_BASIC_INFORMATION: u32 = 0;

/// The address of `value`, as an argument block carries it.
fn address_of<T>(value: &T) -> u32 {
    core::ptr::from_ref(value) as u32
}

/// The address of `value`, for a service that writes it.
fn address_of_mut<T>(value: &mut T) -> u32 {
    core::ptr::from_mut(value) as u32
}

/// A handle, or the service's status.
fn handle_or(status: u32, handle: u32) -> Result<u32, u32> {
    match status {
        STATUS_SUCCESS => Ok(handle),
        status => Err(status),
    }
}

/// NtClose: its status.
pub(crate) fn close(handle: u32) -> u32 {
    // SAFETY: NtClose's one argument, a handle (no address).
    unsafe { system_service(nr::NtClose, &[handle]) }
}

/// NtOpenFile: the file `attributes` name, opened with `access`, the share modes `share` and the
/// options `options`; its handle, or the status (the I/O status block is not kept).
pub(crate) fn open_file(
    attributes: &ObjectAttributes,
    access: u32,
    share: u32,
    options: u32,
) -> Result<u32, u32> {
    let mut io_status = IoStatusBlock::<u32>::default();
    let mut handle = 0u32;
    let args = [
        address_of_mut(&mut handle),
        access,
        address_of(attributes),
        address_of_mut(&mut io_status),
        share,
        options,
    ];
    // SAFETY: NtOpenFile's arguments: the handle and the I/O status block it writes, on this frame;
    // the attributes and the name they borrow, which it reads.
    let status = unsafe { system_service(nr::NtOpenFile, &args) };
    handle_or(status, handle)
}

/// NtQueryAttributesFile: the basic information of the file `attributes` name, into `basic`; the
/// status.
pub(crate) fn query_attributes_file(
    attributes: &ObjectAttributes,
    basic: &mut FileBasicInformation,
) -> u32 {
    let args = [address_of(attributes), address_of_mut(basic)];
    // SAFETY: NtQueryAttributesFile's arguments: the attributes it reads, the information it
    // writes, both borrowed for the call.
    unsafe { system_service(nr::NtQueryAttributesFile, &args) }
}

/// NtOpenKey: the key `attributes` name, opened with `access`; its handle, or the status.
pub(crate) fn open_key(attributes: &ObjectAttributes, access: u32) -> Result<u32, u32> {
    let mut handle = 0u32;
    let args = [address_of_mut(&mut handle), access, address_of(attributes)];
    // SAFETY: NtOpenKey's arguments: the handle it writes, on this frame, and the attributes it
    // reads.
    let status = unsafe { system_service(nr::NtOpenKey, &args) };
    handle_or(status, handle)
}

/// NtQueryValueKey: value `name` of `key` in the information class `class`, into `information`
/// (its whole size offered); the status (STATUS_BUFFER_OVERFLOW when the answer does not fit).
pub(crate) fn query_value_key<T: Pod>(
    key: u32,
    name: &UnicodeString,
    class: u32,
    information: &mut T,
) -> u32 {
    let mut result = 0u32;
    let args = [
        key,
        address_of(name),
        class,
        address_of_mut(information),
        size_of::<T>() as u32,
        address_of_mut(&mut result),
    ];
    // SAFETY: NtQueryValueKey's arguments: the name it reads; the information it writes, within
    // the size given (any bytes make a `T`: plain data), and the result length, on this frame.
    unsafe { system_service(nr::NtQueryValueKey, &args) }
}

/// NtQueryVirtualMemory: the calling process's region holding `address` (MemoryBasicInformation),
/// or the status.
pub(crate) fn query_virtual_memory(address: usize) -> Result<MemoryBasicInformation, u32> {
    let mut info = MemoryBasicInformation::default();
    let args = [
        CURRENT_PROCESS,
        address as u32,
        MEMORY_BASIC_INFORMATION,
        address_of_mut(&mut info),
        size_of::<MemoryBasicInformation>() as u32,
        0,
    ];
    // SAFETY: NtQueryVirtualMemory's arguments: the address it describes (only looked up, never
    // read) and the information it writes, on this frame; no result length asked for.
    match unsafe { system_service(nr::NtQueryVirtualMemory, &args) } {
        STATUS_SUCCESS => Ok(info),
        status => Err(status),
    }
}

/// NtCreateSection: an unnamed section over `file` (no maximum size: the file's), with `access`,
/// the page protection `protection` and the allocation attributes `kind` (SEC_IMAGE); its handle,
/// or the status.
pub(crate) fn create_section(
    access: u32,
    protection: u32,
    kind: u32,
    file: u32,
) -> Result<u32, u32> {
    let mut section = 0u32;
    let args = [
        address_of_mut(&mut section),
        access,
        0,
        0,
        protection,
        kind,
        file,
    ];
    // SAFETY: NtCreateSection's arguments: the handle it writes, on this frame; no attributes and
    // no maximum size (no address).
    let status = unsafe { system_service(nr::NtCreateSection, &args) };
    handle_or(status, section)
}

/// NtMapViewOfSection: a view of `section` in the calling process, wherever the system places it
/// (`base` zero) or at `base`, of `size` bytes (zero: the whole section), inherited as `inherit`,
/// with the protection `protect`: the view's base and size written back; the status.
pub(crate) fn map_view_of_section(
    section: u32,
    base: &mut u32,
    size: &mut u32,
    inherit: u32,
    protect: u32,
) -> u32 {
    let args = [
        section,
        CURRENT_PROCESS,
        address_of_mut(base),
        0,
        0,
        0,
        address_of_mut(size),
        inherit,
        0,
        protect,
    ];
    // SAFETY: NtMapViewOfSection's arguments: the base and size it reads and writes, borrowed for
    // the call; no section offset (no address). A new view takes free addresses only.
    unsafe { system_service(nr::NtMapViewOfSection, &args) }
}

/// NtUnmapViewOfSection: the calling process's view at `base` unmapped; the status.
///
/// # Safety
///
/// No reference into the view is in use, nor used again.
pub(crate) unsafe fn unmap_view_of_section(base: u32) -> u32 {
    // SAFETY: NtUnmapViewOfSection's arguments: the process and the view's base (no address it
    // reads); the view is the caller's to let go (the function's contract).
    unsafe { system_service(nr::NtUnmapViewOfSection, &[CURRENT_PROCESS, base]) }
}

/// NtProtectVirtualMemory: the calling process's pages from `base`, `size` bytes, given the
/// protection `protect` (the range they cover written back): their old protection, or the status.
///
/// # Safety
///
/// No reference into the pages is in use that the new protection denies.
pub(crate) unsafe fn protect_virtual_memory(
    base: &mut u32,
    size: &mut u32,
    protect: u32,
) -> Result<u32, u32> {
    let mut old = 0u32;
    let args = [
        CURRENT_PROCESS,
        address_of_mut(base),
        address_of_mut(size),
        protect,
        address_of_mut(&mut old),
    ];
    // SAFETY: NtProtectVirtualMemory's arguments: the base and size it reads and writes, and the
    // old protection it writes, all borrowed for the call; the new protection is the caller's to
    // allow (the function's contract).
    match unsafe { system_service(nr::NtProtectVirtualMemory, &args) } {
        STATUS_SUCCESS => Ok(old),
        status => Err(status),
    }
}

/// NtDelayExecution: the calling thread waits `interval` (100 ns units), not alertable.
pub(crate) fn delay_execution(interval: u32) {
    let due = -i64::from(interval);
    // SAFETY: NtDelayExecution's arguments: Alertable FALSE and the relative due time it reads,
    // borrowed for the call.
    unsafe { system_service(nr::NtDelayExecution, &[0, address_of(&due)]) };
}

/// NtTerminateProcess: the process `process` ends with `status`; the service's own status (a
/// termination of the calling process does not return).
pub(crate) fn terminate_process(process: u32, status: u32) -> u32 {
    // SAFETY: NtTerminateProcess's arguments: a handle and the exit status (no address).
    unsafe { system_service(nr::NtTerminateProcess, &[process, status]) }
}

/// NtContinue: the calling thread resumed in the CONTEXT at `context`, its alert state untouched;
/// only a failure returns, with its status.
///
/// # Safety
///
/// `context` is a CONTEXT the thread may resume in: its stack and its code in place.
pub(crate) unsafe fn continue_context(context: u32) -> u32 {
    // SAFETY: NtContinue's arguments: the context it reads and resumes (the function's contract),
    // not testing for an alert.
    unsafe { system_service(nr::NtContinue, &[context, 0]) }
}

/// NtRaiseException: the EXCEPTION_RECORD at `record` raised from the CONTEXT at `context`, its
/// second chance (FirstChance FALSE: the process ends with its code); only a failure returns, with
/// its status.
///
/// # Safety
///
/// `record` and `context` are the calling thread's exception record and context, readable whole.
pub(crate) unsafe fn raise_second_chance(record: u32, context: u32) -> u32 {
    // SAFETY: NtRaiseException's arguments: the record and the context it reads (the function's
    // contract), and FirstChance FALSE.
    unsafe { system_service(nr::NtRaiseException, &[record, context, 0]) }
}

/// SYS_DEBUG_PRINT: `text` to the kernel's debugger channel.
pub(crate) fn debug_print(text: &[u8]) {
    // SAFETY: the internal service's arguments: the text's address and length, which it reads.
    unsafe { system_service(SYS_DEBUG_PRINT, &[text.as_ptr() as u32, text.len() as u32]) };
}
