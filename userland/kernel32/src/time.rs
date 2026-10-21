//! The clocks and the time conversions, kernel32's own code as on Windows 2000: the tick count, the
//! system time and the time-zone bias from KUSER_SHARED_DATA ([`crate::shared`]), the time zone and
//! the performance counter from ntdll's system services, the FILETIME/SYSTEMTIME conversions
//! through rtl's (RtlTimeToTimeFields, RtlTimeFieldsToTime).

use rtl::time::{filetime_from_system_time, system_time_from_filetime, SystemTime};

use crate::base::{set_last_error, set_last_nt_error};
use crate::error::ERROR_INVALID_PARAMETER;
use crate::nt;
use crate::shared;

/// GetTickCount: the milliseconds since boot, `TickCountLow * TickCountMultiplier >> 24`.
#[unsafe(export_name = "f2k_export_GetTickCount")]
pub extern "system" fn get_tick_count() -> u32 {
    let ticks = shared::read(shared::TICK_COUNT_LOW);
    let multiplier = shared::read(shared::TICK_COUNT_MULTIPLIER);
    ((u64::from(ticks) * u64::from(multiplier)) >> 24) as u32
}

/// The system time, a FILETIME (UTC).
fn system_time() -> u64 {
    shared::time(shared::SYSTEM_TIME)
}

/// The local time: the system time less the time-zone bias.
fn local_time() -> u64 {
    system_time().wrapping_sub(shared::time(shared::TIME_ZONE_BIAS))
}

/// GetSystemTimeAsFileTime: the system time.
///
/// # Safety
///
/// `file_time` points at a writable FILETIME.
#[unsafe(export_name = "f2k_export_GetSystemTimeAsFileTime")]
pub unsafe extern "system" fn get_system_time_as_file_time(file_time: *mut u64) {
    // SAFETY: the caller's FILETIME.
    unsafe { file_time.write_unaligned(system_time()) };
}

/// GetSystemTime: the system time as a SYSTEMTIME.
///
/// # Safety
///
/// `out` points at a writable SYSTEMTIME.
#[unsafe(export_name = "f2k_export_GetSystemTime")]
pub unsafe extern "system" fn get_system_time(out: *mut u8) {
    // SAFETY: the caller's SYSTEMTIME.
    unsafe { write_system_time(out, system_time_from_filetime(system_time())) };
}

/// GetLocalTime: the local time as a SYSTEMTIME.
///
/// # Safety
///
/// `out` points at a writable SYSTEMTIME.
#[unsafe(export_name = "f2k_export_GetLocalTime")]
pub unsafe extern "system" fn get_local_time(out: *mut u8) {
    // SAFETY: the caller's SYSTEMTIME.
    unsafe { write_system_time(out, system_time_from_filetime(local_time())) };
}

/// # Safety
///
/// `out` points at 16 writable bytes.
unsafe fn write_system_time(out: *mut u8, time: SystemTime) {
    let bytes = time.to_bytes();
    // SAFETY: the caller's contract.
    unsafe { out.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
}

/// SystemCurrentTimeZoneInformation, and the structure's size.
const SYSTEM_CURRENT_TIME_ZONE_INFORMATION: u32 = 44;
const TIME_ZONE_INFORMATION_SIZE: usize = 172;
/// TIME_ZONE_ID_INVALID.
const TIME_ZONE_ID_INVALID: u32 = 0xFFFF_FFFF;

/// GetTimeZoneInformation: the time zone in effect, from the system (NtQuerySystemInformation's
/// SystemCurrentTimeZoneInformation), into the caller's structure; its id, as the shared data page
/// keeps it. A failed query is TIME_ZONE_ID_INVALID, its error set.
///
/// # Safety
///
/// `information` points at a writable TIME_ZONE_INFORMATION.
#[unsafe(export_name = "f2k_export_GetTimeZoneInformation")]
pub unsafe extern "system" fn get_time_zone_information(information: *mut u8) -> u32 {
    let mut zone = [0u8; TIME_ZONE_INFORMATION_SIZE];
    // SAFETY: ntdll's export, into a buffer of the length given.
    let status = unsafe {
        nt::NtQuerySystemInformation(
            SYSTEM_CURRENT_TIME_ZONE_INFORMATION,
            zone.as_mut_ptr(),
            zone.len() as u32,
            core::ptr::null_mut(),
        )
    };
    if !rtl::status::nt_success(status) {
        set_last_nt_error(status);
        return TIME_ZONE_ID_INVALID;
    }
    // SAFETY: the caller's structure.
    unsafe { information.copy_from_nonoverlapping(zone.as_ptr(), zone.len()) };
    shared::read(shared::TIME_ZONE_ID)
}

/// QueryPerformanceCounter: the counter, from NtQueryPerformanceCounter; FALSE with its error when
/// the query fails.
///
/// # Safety
///
/// `count` points at a writable LARGE_INTEGER.
#[unsafe(export_name = "f2k_export_QueryPerformanceCounter")]
pub unsafe extern "system" fn query_performance_counter(count: *mut u64) -> u32 {
    // SAFETY: ntdll's export; the system service checks the caller's pointer.
    let status = unsafe { nt::NtQueryPerformanceCounter(count, core::ptr::null_mut()) };
    if !rtl::status::nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// QueryPerformanceFrequency: the counter's frequency, from NtQueryPerformanceCounter; FALSE with
/// its error when the query fails.
///
/// # Safety
///
/// `frequency` points at a writable LARGE_INTEGER.
#[unsafe(export_name = "f2k_export_QueryPerformanceFrequency")]
pub unsafe extern "system" fn query_performance_frequency(frequency: *mut u64) -> u32 {
    let mut counter = 0u64;
    // SAFETY: ntdll's export; the system service checks the caller's pointer.
    let status = unsafe { nt::NtQueryPerformanceCounter(&mut counter, frequency) };
    if !rtl::status::nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// SystemTimeToFileTime: the SYSTEMTIME's FILETIME; FALSE with ERROR_INVALID_PARAMETER for a field
/// out of its range (the day of the week is not consulted).
///
/// # Safety
///
/// `system_time` points at a SYSTEMTIME, `file_time` at a writable FILETIME.
#[unsafe(export_name = "f2k_export_SystemTimeToFileTime")]
pub unsafe extern "system" fn system_time_to_file_time(
    system_time: *const u8,
    file_time: *mut u64,
) -> u32 {
    let mut bytes = [0u8; 16];
    // SAFETY: the caller's SYSTEMTIME.
    unsafe {
        bytes
            .as_mut_ptr()
            .copy_from_nonoverlapping(system_time, bytes.len())
    };
    match filetime_from_system_time(SystemTime::from_bytes(&bytes)) {
        Some(time) => {
            // SAFETY: the caller's FILETIME.
            unsafe { file_time.write_unaligned(time) };
            1
        }
        None => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

/// FileTimeToSystemTime: the FILETIME's civil fields; FALSE with ERROR_INVALID_PARAMETER for a
/// FILETIME past the signed range.
///
/// # Safety
///
/// `file_time` points at a FILETIME, `system_time` at a writable SYSTEMTIME.
#[unsafe(export_name = "f2k_export_FileTimeToSystemTime")]
pub unsafe extern "system" fn file_time_to_system_time(
    file_time: *const u64,
    system_time: *mut u8,
) -> u32 {
    // SAFETY: the caller's FILETIME.
    let time = unsafe { file_time.read_unaligned() };
    if time >= 1 << 63 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's SYSTEMTIME.
    unsafe { write_system_time(system_time, system_time_from_filetime(time)) };
    1
}

/// FileTimeToLocalFileTime: the FILETIME less the time-zone bias.
///
/// # Safety
///
/// `file_time` points at a FILETIME, `local` at a writable one.
#[unsafe(export_name = "f2k_export_FileTimeToLocalFileTime")]
pub unsafe extern "system" fn file_time_to_local_file_time(
    file_time: *const u64,
    local: *mut u64,
) -> u32 {
    // SAFETY: the caller's FILETIMEs.
    unsafe {
        local.write_unaligned(
            file_time
                .read_unaligned()
                .wrapping_sub(shared::time(shared::TIME_ZONE_BIAS)),
        )
    };
    1
}
