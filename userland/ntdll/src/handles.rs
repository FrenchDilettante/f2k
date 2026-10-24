//! Handle tables (`rtl::handles`): entries handed out of a table its caller owns, freed and
//! checked — kernel32's Local and Global memory's movable handles, as on Windows 2000. A table's
//! entries are the process's virtual memory, reserved at the first allocation and committed as the
//! table grows.

use rtl::handles::HandleTable;
use rtl::sys::Native;

/// RtlInitializeHandleTable: an empty table of up to `maximum` entries of `size` bytes each (no
/// memory yet: the first allocation reserves it).
///
/// # Safety
///
/// `table` is a writable RTL_HANDLE_TABLE.
#[unsafe(export_name = "f2k_export_RtlInitializeHandleTable")]
pub unsafe extern "system" fn rtl_initialize_handle_table(
    maximum: u32,
    size: u32,
    table: *mut HandleTable,
) {
    // SAFETY: the caller's contract.
    unsafe { &mut *table }.initialize(maximum, size);
}

/// RtlAllocateHandle: a free entry (its first dword cleared: the caller marks it
/// RTL_HANDLE_ALLOCATED), its index written to `index` when not NULL; NULL when the table is full
/// or its memory cannot be had.
///
/// # Safety
///
/// `table` is an RTL_HANDLE_TABLE RtlInitializeHandleTable made; `index` is writable when not NULL.
#[unsafe(export_name = "f2k_export_RtlAllocateHandle")]
pub unsafe extern "system" fn rtl_allocate_handle(
    table: *mut HandleTable,
    index: *mut u32,
) -> usize {
    // SAFETY: the caller's contract.
    match unsafe { &mut *table }.allocate(&Native) {
        Some((entry, number)) => {
            if !index.is_null() {
                // SAFETY: the caller's contract.
                unsafe { index.write_unaligned(number) };
            }
            entry
        }
        None => 0,
    }
}

/// RtlFreeHandle: the entry in use back on the table's free list; FALSE for what is not one.
///
/// # Safety
///
/// `table` is an RTL_HANDLE_TABLE RtlInitializeHandleTable made.
#[unsafe(export_name = "f2k_export_RtlFreeHandle")]
pub unsafe extern "system" fn rtl_free_handle(table: *mut HandleTable, entry: usize) -> u32 {
    // SAFETY: the caller's contract.
    u32::from(unsafe { &mut *table }.free(entry))
}

/// RtlIsValidHandle: TRUE for an entry of the table in use (RTL_HANDLE_ALLOCATED set).
///
/// # Safety
///
/// `table` is an RTL_HANDLE_TABLE RtlInitializeHandleTable made.
#[unsafe(export_name = "f2k_export_RtlIsValidHandle")]
pub unsafe extern "system" fn rtl_is_valid_handle(table: *const HandleTable, entry: usize) -> u32 {
    // SAFETY: the caller's contract.
    u32::from(unsafe { &*table }.is_valid(entry))
}
