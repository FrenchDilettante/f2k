//! The environment, where Windows 2000 keeps it: a block of virtual memory the process parameters'
//! Environment points at (or a block the caller names), edited and read by ntdll's functions over
//! `rtl::env`, the process's under the PEB lock. A set that outgrows the block moves it: a larger
//! allocation (NtAllocateVirtualMemory), the block copied, the old one released
//! (NtFreeVirtualMemory) and the pointer updated, as Windows 2000's RtlSetEnvironmentVariable does.
//! RtlCreateEnvironment makes a block of its own (a copy of the process's, or an empty one), which
//! RtlDestroyEnvironment releases.

use rtl::env::{self, EnvError};
use rtl::nt::info::MemoryBasicInformation;
use rtl::status::{
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_SUCCESS,
    STATUS_VARIABLE_NOT_FOUND,
};
use rtl::string::UnicodeString;
use rtl::sys::{self, nr, system_service};

use crate::params::with_own_parameters;

/// The current-process pseudo-handle, and the virtual-memory calls' constants.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const GRANULARITY: usize = 0x1_0000;

/// MemoryBasicInformation, NtQueryVirtualMemory's class.
const MEMORY_BASIC_INFORMATION: u32 = 0;

/// Run `body` over the block at `block` with the room its allocation leaves after it
/// (NtQueryVirtualMemory's region from its page on), in units, and the allocation's base.
///
/// # Safety
///
/// `block` is an environment block in committed memory, which nothing else reads or writes while
/// `body` runs.
unsafe fn with_block<R>(block: *mut u16, body: impl FnOnce(&mut [u16], usize) -> R) -> R {
    let mut info = MemoryBasicInformation::default();
    let args = [
        CURRENT_PROCESS,
        block as u32,
        MEMORY_BASIC_INFORMATION,
        &mut info as *mut MemoryBasicInformation as u32,
        core::mem::size_of::<MemoryBasicInformation>() as u32,
        0,
    ];
    let status = system_service(nr::NtQueryVirtualMemory, &args);
    let (base, allocation, size) = if status == STATUS_SUCCESS {
        (
            info.base_address as usize,
            info.allocation_base as usize,
            info.region_size as usize,
        )
    } else {
        (block as usize, block as usize, 0x1000)
    };
    let room = (base + size - block as usize) / 2;
    // SAFETY: the caller's block, inside its committed region, the body's alone while it runs.
    body(
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

/// Run `body` over the process's environment block, under the PEB lock.
fn with_process_environment<R>(body: impl FnOnce(&mut [u16]) -> R) -> R {
    with_own_parameters(|own| {
        // SAFETY: the process parameters' Environment: the process's block, in committed memory,
        // read and changed only under the PEB lock, held while `body` runs.
        unsafe { with_block(*own.environment as *mut u16, |block, _| body(block)) }
    })
}

/// Run `body` over the environment `environment` names: the process's (under the PEB lock) for
/// null.
///
/// # Safety
///
/// `environment` is null or an environment block in committed memory, which nothing else reads or
/// writes while `body` runs.
unsafe fn with_environment<R>(environment: *mut u16, body: impl FnOnce(&mut [u16]) -> R) -> R {
    if environment.is_null() {
        return with_process_environment(body);
    }
    // SAFETY: the caller's block.
    unsafe { with_block(environment, |block, _| body(block)) }
}

/// The value of `name` in the process's environment, under the PEB lock, into `out` (cut to its
/// room): its length in units, zero for an unset name.
pub(crate) fn process_variable(name: &[u16], out: &mut [u16]) -> usize {
    with_process_environment(|block| {
        let found = env::query(block, name).unwrap_or(&[]);
        let length = found.len().min(out.len());
        out[..length].copy_from_slice(&found[..length]);
        length
    })
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
    let query = |block: &mut [u16]| {
        // SAFETY: the caller's string.
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
    };
    // SAFETY: the caller's block, or the process's for null.
    unsafe { with_environment(environment, query) }
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
    if environment.is_null() {
        return with_own_parameters(|own| {
            let mut block = *own.environment as *mut u16;
            // SAFETY: the process parameters' Environment, under the PEB lock.
            let status = unsafe { set_in(&mut block, name, value) };
            *own.environment = block as usize;
            status
        });
    }
    // SAFETY: the caller's block pointer.
    unsafe { set_in(&mut *environment, name, value) }
}

/// The set, over the block `*slot` names, the block moved when it must grow.
///
/// # Safety
///
/// `*slot` is an environment block in committed memory, which nothing else reads or writes
/// meanwhile.
unsafe fn set_in(slot: &mut *mut u16, name: &[u16], value: Option<&[u16]>) -> u32 {
    let block = *slot;
    let set = |block: &mut [u16], allocation: usize| match env::set(block, name, value) {
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
            *slot = base as *mut u16;
            STATUS_SUCCESS
        }
    };
    // SAFETY: the caller's block.
    unsafe { with_block(block, set) }
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
    let expand = |block: &mut [u16]| {
        // SAFETY: the caller's strings.
        let (source, destination) = unsafe { (units(source), &mut *destination) };
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
    };
    // SAFETY: the caller's block, or the process's for null.
    unsafe { with_environment(environment, expand) }
}

/// RtlCreateEnvironment: a new environment block in `*environment`, in virtual memory of its own
/// (NtAllocateVirtualMemory): a copy of the process's environment when `inherit` (a BOOLEAN, in the
/// argument's low byte) is set, empty (two NULs) otherwise. STATUS_INVALID_PARAMETER without a
/// place for it; the allocation's status when it fails.
///
/// # Safety
///
/// `environment` is null or writable.
#[unsafe(export_name = "f2k_export_RtlCreateEnvironment")]
pub unsafe extern "system" fn rtl_create_environment(inherit: u32, environment: *mut usize) -> u32 {
    // SAFETY: the caller's slot.
    let Some(out) = (unsafe { environment.as_mut() }) else {
        return STATUS_INVALID_PARAMETER;
    };
    if inherit as u8 == 0 {
        // A fresh allocation is zeroed: an empty block.
        return match sys::allocate_virtual_memory(0, 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) {
            Ok(base) => {
                *out = base;
                STATUS_SUCCESS
            }
            Err(status) => status,
        };
    }
    with_process_environment(|block| {
        let used = env::block_length(block);
        let base = match sys::allocate_virtual_memory(
            0,
            2 * used,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) {
            Ok(base) => base,
            Err(status) => return status,
        };
        // SAFETY: a fresh allocation of `used` units, the calling process's alone.
        let copy = unsafe { core::slice::from_raw_parts_mut(base as *mut u16, used) };
        copy.copy_from_slice(&block[..used]);
        *out = base;
        STATUS_SUCCESS
    })
}

/// RtlDestroyEnvironment: a block RtlCreateEnvironment made, released (NtFreeVirtualMemory); the
/// release's status.
#[unsafe(export_name = "f2k_export_RtlDestroyEnvironment")]
pub extern "system" fn rtl_destroy_environment(environment: usize) -> u32 {
    sys::release_virtual_memory(environment)
}
