//! The environment, where Windows 2000 keeps it: a block of virtual memory the process parameters'
//! Environment points at (or a block the caller names), edited and read by ntdll's functions over
//! `rtl::env`, the process's under the PEB lock. A set that outgrows the block moves it: a larger
//! allocation (NtAllocateVirtualMemory), the block copied, the old one released
//! (NtFreeVirtualMemory) and the pointer updated, as Windows 2000's RtlSetEnvironmentVariable does.

use rtl::env::{self, EnvError};
use rtl::status::{
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_SUCCESS,
    STATUS_VARIABLE_NOT_FOUND,
};
use rtl::sys::{self, nr, system_service};

/// A UNICODE_STRING.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

/// The process parameters' Environment.
const ENVIRONMENT: usize = 0x48;

/// The current-process pseudo-handle, and the virtual-memory calls' constants.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const GRANULARITY: usize = 0x1_0000;

/// The block at `block` with the room its allocation leaves after it (NtQueryVirtualMemory's region
/// from its page on), in units, and the allocation's base.
///
/// # Safety
///
/// `block` is an environment block in committed memory.
unsafe fn block_at(block: *mut u16) -> (&'static mut [u16], usize) {
    let mut info = [0u32; 7];
    let args = [
        CURRENT_PROCESS,
        block as u32,
        0, // MemoryBasicInformation
        info.as_mut_ptr() as u32,
        28,
        0,
    ];
    let status = system_service(nr::NtQueryVirtualMemory, &args);
    let (base, allocation, size) = if status == STATUS_SUCCESS {
        (info[0] as usize, info[1] as usize, info[3] as usize)
    } else {
        (block as usize, block as usize, 0x1000)
    };
    let room = (base + size - block as usize) / 2;
    // SAFETY: the caller's block, inside its committed region.
    (
        unsafe { core::slice::from_raw_parts_mut(block, room) },
        allocation,
    )
}

/// A UNICODE_STRING's units.
///
/// # Safety
///
/// The string's buffer holds its length.
unsafe fn units<'a>(string: *const UnicodeString) -> &'a [u16] {
    // SAFETY: the caller's contract.
    let string = unsafe { &*string };
    if string.length == 0 {
        return &[];
    }
    // SAFETY: as above.
    unsafe { core::slice::from_raw_parts(string.buffer, string.length as usize / 2) }
}

/// Run `body` over the environment `environment` names: the process's (under the PEB lock) for
/// null.
fn with_environment<R>(environment: *mut u16, body: impl FnOnce(*mut u16) -> R) -> R {
    if !environment.is_null() {
        return body(environment);
    }
    let lock = sys::peb_lock();
    lock.enter(&sys::Native);
    let result = body(sys::read(sys::process_parameters() + ENVIRONMENT) as *mut u16);
    lock.leave(&sys::Native);
    result
}

/// RtlQueryEnvironmentVariable_U: the value of `name` in the environment (the process's for null)
/// into `value`'s buffer, its length in bytes in `value.Length`, terminated when there is room.
/// STATUS_VARIABLE_NOT_FOUND for an unset name; STATUS_BUFFER_TOO_SMALL, the length it needs in
/// `value.Length`, when the buffer cannot hold it.
///
/// # Safety
///
/// `name` and `value` are UNICODE_STRINGs whose buffers hold their lengths and rooms.
#[unsafe(export_name = "f2k_export_RtlQueryEnvironmentVariable_U")]
pub unsafe extern "system" fn rtl_query_environment_variable_u(
    environment: *mut u16,
    name: *const UnicodeString,
    value: *mut UnicodeString,
) -> u32 {
    with_environment(environment, |block| {
        // SAFETY: the environment block and the caller's strings.
        let (block, _) = unsafe { block_at(block) };
        let Some(found) = env::query(block, unsafe { units(name) }) else {
            return STATUS_VARIABLE_NOT_FOUND;
        };
        // SAFETY: the caller's string.
        let value = unsafe { &mut *value };
        let bytes = 2 * found.len();
        value.length = bytes as u16;
        if bytes > value.maximum_length as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller's buffer, which holds the value (and its terminator when there is
        // room).
        unsafe {
            value
                .buffer
                .copy_from_nonoverlapping(found.as_ptr(), found.len());
            if bytes + 2 <= value.maximum_length as usize {
                value.buffer.add(found.len()).write(0);
            }
        }
        STATUS_SUCCESS
    })
}

/// RtlSetEnvironmentVariable: set `name` to `value` in the environment `*environment` names (the
/// process's for a null pointer), or delete it for a null value. STATUS_INVALID_PARAMETER for a
/// name that is not one; STATUS_NO_MEMORY when the block cannot grow.
///
/// # Safety
///
/// `environment` is null or points at an environment block's pointer; `name` and `value` (when
/// given) are UNICODE_STRINGs whose buffers hold their lengths.
#[unsafe(export_name = "f2k_export_RtlSetEnvironmentVariable")]
pub unsafe extern "system" fn rtl_set_environment_variable(
    environment: *mut *mut u16,
    name: *const UnicodeString,
    value: *const UnicodeString,
) -> u32 {
    // SAFETY: the caller's strings.
    let (name, value) = unsafe { (units(name), (!value.is_null()).then(|| units(value))) };
    let slot = if environment.is_null() {
        let lock = sys::peb_lock();
        lock.enter(&sys::Native);
        let slot = (sys::process_parameters() + ENVIRONMENT) as *mut *mut u16;
        // SAFETY: the process parameters' Environment, under the PEB lock.
        let status = unsafe { set_in(slot, name, value) };
        lock.leave(&sys::Native);
        return status;
    } else {
        environment
    };
    // SAFETY: the caller's block pointer.
    unsafe { set_in(slot, name, value) }
}

/// The set, over the block `*slot` names, the block moved when it must grow.
///
/// # Safety
///
/// `slot` points at an environment block's pointer.
unsafe fn set_in(slot: *mut *mut u16, name: &[u16], value: Option<&[u16]>) -> u32 {
    // SAFETY: the caller's block.
    let (block, allocation) = unsafe { block_at(*slot) };
    match env::set(block, name, value) {
        Ok(()) => STATUS_SUCCESS,
        Err(EnvError::InvalidName) => STATUS_INVALID_PARAMETER,
        Err(EnvError::NeedsRoom(needed)) => {
            let size = (2 * needed).next_multiple_of(GRANULARITY);
            let Ok(base) =
                sys::allocate_virtual_memory(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
            else {
                return STATUS_NO_MEMORY;
            };
            // SAFETY: a fresh allocation of `size` bytes; the old block's used units copied in.
            let grown = unsafe { core::slice::from_raw_parts_mut(base as *mut u16, size / 2) };
            let used = env::block_length(block);
            grown[..used].copy_from_slice(&block[..used]);
            if env::set(grown, name, value).is_err() {
                sys::release_virtual_memory(base);
                return STATUS_NO_MEMORY;
            }
            sys::release_virtual_memory(allocation);
            // SAFETY: the caller's block pointer.
            unsafe { *slot = base as *mut u16 };
            STATUS_SUCCESS
        }
    }
}

/// RtlExpandEnvironmentStrings_U: `source` with its `%NAME%` references expanded through the
/// environment (the process's for null) into `destination`'s buffer, terminated; the bytes the
/// expansion takes, its terminator included, in `returned` (when given). STATUS_BUFFER_TOO_SMALL
/// when the buffer cannot hold it (what fits is written).
///
/// # Safety
///
/// `source` and `destination` are UNICODE_STRINGs whose buffers hold their length and room;
/// `returned` is null or writable.
#[unsafe(export_name = "f2k_export_RtlExpandEnvironmentStrings_U")]
pub unsafe extern "system" fn rtl_expand_environment_strings_u(
    environment: *mut u16,
    source: *const UnicodeString,
    destination: *mut UnicodeString,
    returned: *mut u32,
) -> u32 {
    with_environment(environment, |block| {
        // SAFETY: the environment block and the caller's strings.
        let (block, _) = unsafe { block_at(block) };
        let source = unsafe { units(source) };
        let destination = unsafe { &mut *destination };
        let room = destination.maximum_length as usize / 2;
        let mut produced = 0usize;
        env::expand(block, source, |unit| {
            if produced < room {
                // SAFETY: inside the caller's buffer.
                unsafe { destination.buffer.add(produced).write(unit) };
            }
            produced += 1;
        });
        let fits = produced < room;
        if fits {
            // SAFETY: as above.
            unsafe { destination.buffer.add(produced).write(0) };
            destination.length = (2 * produced) as u16;
        }
        if !returned.is_null() {
            // SAFETY: the caller's count.
            unsafe { returned.write((2 * (produced + 1)) as u32) };
        }
        if fits {
            STATUS_SUCCESS
        } else {
            STATUS_BUFFER_TOO_SMALL
        }
    })
}
