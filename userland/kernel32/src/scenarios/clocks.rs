//! The clocks and the time conversions: the shared data page's tick count and times, the system's
//! time zone and performance counter (ntdll's system services), and the FILETIME/SYSTEMTIME
//! conversions. The sched fixture's clock block and the fswrite fixture's times block are the
//! contract on the machine.

use super::last_error;
use crate::nt::host::{COUNTER, FAIL_NEXT, FREQUENCY};
use crate::shared::{self, host};
use crate::time::*;

/// 2001-02-03 04:05:06.789 UTC, a Saturday.
const FEB_3_2001: u64 = 126_256_467_067_890_000;

fn fields(bytes: &[u8; 16]) -> [u16; 8] {
    core::array::from_fn(|i| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
}

/// GetTickCount is the page's tick count scaled by its multiplier (8.24 milliseconds per tick).
///
/// Pins: kernel32.GetTickCount
#[test]
fn the_tick_count_scales_the_shared_ticks() {
    host::set(shared::TICK_COUNT_LOW, 100);
    host::set(shared::TICK_COUNT_MULTIPLIER, 0x0A03_AFB7); // 10.0144 ms
    assert_eq!(get_tick_count(), 1001);
    host::set(shared::TICK_COUNT_LOW, 0xFFFF_FFFF);
    host::set(shared::TICK_COUNT_MULTIPLIER, 0x0100_0000); // 1 ms
    assert_eq!(get_tick_count(), 0xFFFF_FFFF);
}

/// The system time is the page's; the local time less its bias; the SYSTEMTIMEs their fields.
///
/// Pins: kernel32.GetLocalTime, kernel32.GetSystemTime, kernel32.GetSystemTimeAsFileTime
/// Pins: kernel32.FileTimeToLocalFileTime
#[test]
fn the_system_and_local_times_read_the_shared_page() {
    host::set_time(shared::SYSTEM_TIME, FEB_3_2001);
    host::set_time(shared::TIME_ZONE_BIAS, 3600 * 10_000_000); // one hour west
    let mut file_time = 0u64;
    unsafe { get_system_time_as_file_time(&mut file_time) };
    assert_eq!(file_time, FEB_3_2001);
    let mut system = [0u8; 16];
    unsafe { get_system_time(system.as_mut_ptr()) };
    assert_eq!(fields(&system), [2001, 2, 6, 3, 4, 5, 6, 789]);
    let mut local = [0u8; 16];
    unsafe { get_local_time(local.as_mut_ptr()) };
    assert_eq!(fields(&local), [2001, 2, 6, 3, 3, 5, 6, 789]);
    let mut local_file_time = 0u64;
    assert_eq!(
        unsafe { file_time_to_local_file_time(&FEB_3_2001, &mut local_file_time) },
        1
    );
    assert_eq!(local_file_time, FEB_3_2001 - 3600 * 10_000_000);
}

/// GetTimeZoneInformation copies the system's zone and answers the page's id; a failed query is
/// TIME_ZONE_ID_INVALID with the status's error.
///
/// Pins: kernel32.GetTimeZoneInformation
#[test]
fn the_time_zone_comes_from_the_system() {
    host::set(shared::TIME_ZONE_ID, 0);
    let mut zone = [0xCCu8; 172];
    assert_eq!(unsafe { get_time_zone_information(zone.as_mut_ptr()) }, 0);
    assert_eq!(zone, [0; 172]);
    FAIL_NEXT.with(|next| next.set(0xC000_0005));
    assert_eq!(
        unsafe { get_time_zone_information(zone.as_mut_ptr()) },
        0xFFFF_FFFF
    );
    assert_eq!(last_error(), 998);
}

/// The performance counter and its frequency come from NtQueryPerformanceCounter; a failed query
/// is FALSE with the status's error.
///
/// Pins: kernel32.QueryPerformanceCounter, kernel32.QueryPerformanceFrequency
#[test]
fn the_performance_counter_comes_from_the_system() {
    let mut value = 0u64;
    assert_eq!(unsafe { query_performance_counter(&mut value) }, 1);
    assert_eq!(value, COUNTER);
    assert_eq!(unsafe { query_performance_frequency(&mut value) }, 1);
    assert_eq!(value, FREQUENCY);
    FAIL_NEXT.with(|next| next.set(0xC000_0005));
    assert_eq!(unsafe { query_performance_counter(&mut value) }, 0);
    assert_eq!(last_error(), 998);
}

/// SystemTimeToFileTime and FileTimeToSystemTime round-trip; a field out of range, or a FILETIME
/// past the signed range, is ERROR_INVALID_PARAMETER.
///
/// Pins: kernel32.FileTimeToSystemTime, kernel32.SystemTimeToFileTime
#[test]
fn the_conversions_round_trip_and_refuse_out_of_range_values() {
    let mut system = [0u8; 16];
    assert_eq!(
        unsafe { file_time_to_system_time(&FEB_3_2001, system.as_mut_ptr()) },
        1
    );
    assert_eq!(fields(&system), [2001, 2, 6, 3, 4, 5, 6, 789]);
    let mut back = 0u64;
    assert_eq!(
        unsafe { system_time_to_file_time(system.as_ptr(), &mut back) },
        1
    );
    assert_eq!(back, FEB_3_2001);
    system[2] = 13; // month 13
    assert_eq!(
        unsafe { system_time_to_file_time(system.as_ptr(), &mut back) },
        0
    );
    assert_eq!(last_error(), 87);
    assert_eq!(
        unsafe { file_time_to_system_time(&(1 << 63), system.as_mut_ptr()) },
        0
    );
    assert_eq!(last_error(), 87);
}
