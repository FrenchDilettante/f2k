//! The clocks and the time conversions, kernel32's own code as on Windows 2000: the tick count, the
//! system time and the time-zone bias from KUSER_SHARED_DATA ([`crate::shared`]), the time zone and
//! the performance counter from ntdll's system services, the FILETIME/SYSTEMTIME conversions
//! through ntdll's (RtlTimeToTimeFields, RtlTimeFieldsToTime), the FILETIME comparison, and the
//! local time's setting (NtSetSystemTime).

use rtl::time::{SystemTime, TimeFields};

use crate::edge::{In, Out, OutBuf};
use crate::error::{answer, bool_answer, Failure, ERROR_INVALID_PARAMETER};
use crate::ntcall;
use crate::shared;

/// A SYSTEMTIME, as the caller's structure holds it: its 16 bytes.
type SystemTimeBytes = [u8; 16];

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
    // SAFETY: the caller's FILETIME (the contract).
    let mut file_time = unsafe { Out::new(file_time) };
    file_time.set(system_time());
}

/// GetSystemTime: the system time as a SYSTEMTIME.
///
/// # Safety
///
/// `out` points at a writable SYSTEMTIME.
#[unsafe(export_name = "f2k_export_GetSystemTime")]
pub unsafe extern "system" fn get_system_time(out: *mut u8) {
    // SAFETY: the caller's SYSTEMTIME (the contract).
    let mut out = unsafe { Out::<SystemTimeBytes>::new(out.cast()) };
    out.set(civil(system_time()).to_bytes());
}

/// GetLocalTime: the local time as a SYSTEMTIME.
///
/// # Safety
///
/// `out` points at a writable SYSTEMTIME.
#[unsafe(export_name = "f2k_export_GetLocalTime")]
pub unsafe extern "system" fn get_local_time(out: *mut u8) {
    // SAFETY: the caller's SYSTEMTIME (the contract).
    let mut out = unsafe { Out::<SystemTimeBytes>::new(out.cast()) };
    out.set(civil(local_time()).to_bytes());
}

/// A time's SYSTEMTIME: ntdll's RtlTimeToTimeFields, its TIME_FIELDS in the SYSTEMTIME's order
/// (the day of the week third, where TIME_FIELDS has it last).
fn civil(time: u64) -> SystemTime {
    let fields = ntcall::time_to_fields(time as i64);
    SystemTime {
        year: fields.year as u16,
        month: fields.month as u16,
        day_of_week: fields.weekday as u16,
        day: fields.day as u16,
        hour: fields.hour as u16,
        minute: fields.minute as u16,
        second: fields.second as u16,
        milliseconds: fields.milliseconds as u16,
    }
}

/// A SYSTEMTIME's time: its fields as a TIME_FIELDS to ntdll's RtlTimeFieldsToTime, which judges
/// them; none for a field out of its range (the day of the week is not consulted).
fn time_of(civil: SystemTime) -> Option<u64> {
    let fields = TimeFields {
        year: civil.year as i16,
        month: civil.month as i16,
        day: civil.day as i16,
        hour: civil.hour as i16,
        minute: civil.minute as i16,
        second: civil.second as i16,
        milliseconds: civil.milliseconds as i16,
        weekday: civil.day_of_week as i16,
    };
    ntcall::fields_to_time(&fields).map(|time| time as u64)
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
    // SAFETY: the caller's TIME_ZONE_INFORMATION (the contract).
    let information = unsafe { OutBuf::new(information, TIME_ZONE_INFORMATION_SIZE) };
    answer(time_zone_information(information), TIME_ZONE_ID_INVALID)
}

/// GetTimeZoneInformation's work.
fn time_zone_information(mut information: OutBuf<'_, u8>) -> Result<u32, Failure> {
    let zone = ntcall::query_system_information::<[u8; TIME_ZONE_INFORMATION_SIZE]>(
        SYSTEM_CURRENT_TIME_ZONE_INFORMATION,
    )
    .map_err(Failure::Status)?;
    information.put(&zone);
    Ok(shared::read(shared::TIME_ZONE_ID))
}

/// QueryPerformanceCounter: the counter, from NtQueryPerformanceCounter; FALSE with its error when
/// the query fails.
///
/// # Safety
///
/// `count` points at a writable LARGE_INTEGER.
#[unsafe(export_name = "f2k_export_QueryPerformanceCounter")]
pub unsafe extern "system" fn query_performance_counter(count: *mut u64) -> u32 {
    // SAFETY: the caller's LARGE_INTEGER (the contract; the service probes it).
    let mut count = unsafe { Out::new(count) };
    bool_answer(ntcall::query_performance_counter(&mut count, None).map_err(Failure::Status))
}

/// QueryPerformanceFrequency: the counter's frequency, from NtQueryPerformanceCounter; FALSE with
/// its error when the query fails.
///
/// # Safety
///
/// `frequency` points at a writable LARGE_INTEGER.
#[unsafe(export_name = "f2k_export_QueryPerformanceFrequency")]
pub unsafe extern "system" fn query_performance_frequency(frequency: *mut u64) -> u32 {
    // SAFETY: the caller's LARGE_INTEGER (the contract; the service probes it).
    let mut frequency = unsafe { Out::new(frequency) };
    let mut counter = 0u64;
    let queried =
        ntcall::query_performance_counter(&mut Out::from(&mut counter), Some(&mut frequency));
    bool_answer(queried.map_err(Failure::Status))
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
    // SAFETY: the caller's SYSTEMTIME and FILETIME (the contract).
    let (system_time, file_time) = unsafe {
        (
            In::<SystemTimeBytes>::new(system_time.cast()),
            Out::new(file_time),
        )
    };
    bool_answer(to_file_time(system_time, file_time))
}

/// SystemTimeToFileTime's work.
fn to_file_time(
    system_time: In<'_, SystemTimeBytes>,
    mut file_time: Out<'_, u64>,
) -> Result<(), Failure> {
    let time = time_of(SystemTime::from_bytes(&system_time.read()))
        .ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    file_time.set(time);
    Ok(())
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
    // SAFETY: the caller's FILETIME and SYSTEMTIME (the contract).
    let (file_time, system_time) = unsafe {
        (
            In::new(file_time),
            Out::<SystemTimeBytes>::new(system_time.cast()),
        )
    };
    bool_answer(to_system_time(file_time, system_time))
}

/// FileTimeToSystemTime's work.
fn to_system_time(
    file_time: In<'_, u64>,
    mut system_time: Out<'_, SystemTimeBytes>,
) -> Result<(), Failure> {
    let time = file_time.read();
    if time >= 1 << 63 {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    system_time.set(civil(time).to_bytes());
    Ok(())
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
    // SAFETY: the caller's FILETIMEs (the contract).
    let (file_time, mut local) = unsafe { (In::new(file_time), Out::new(local)) };
    local.set(
        file_time
            .read()
            .wrapping_sub(shared::time(shared::TIME_ZONE_BIAS)),
    );
    1
}

/// CompareFileTime: -1, 0 or 1 as the first FILETIME is earlier than, the same as or later than the
/// second, each compared as the unsigned 64-bit count it is (the high dword first, then the low,
/// neither signed: the runtime capture).
///
/// # Safety
///
/// Both point at FILETIMEs.
#[unsafe(export_name = "f2k_export_CompareFileTime")]
pub unsafe extern "system" fn compare_file_time(first: *const u64, second: *const u64) -> i32 {
    // SAFETY: the caller's FILETIMEs (the contract).
    let (first, second) = unsafe { (In::new(first), In::new(second)) };
    first.read().cmp(&second.read()) as i32
}

/// SetLocalTime: the local time a SYSTEMTIME gives (judged by ntdll's RtlTimeFieldsToTime: a field
/// out of its range is ERROR_INVALID_PARAMETER, the day of the week not consulted) made the system
/// time, the time-zone bias added back, through NtSetSystemTime as Windows 2000's does; its failure
/// is the last error. Windows 2000 enables the caller's system-time privilege first; F2K has no
/// privileges to enable.
///
/// # Safety
///
/// `local` points at a SYSTEMTIME.
#[unsafe(export_name = "f2k_export_SetLocalTime")]
pub unsafe extern "system" fn set_local_time(local: *const u8) -> u32 {
    // SAFETY: the caller's SYSTEMTIME (the contract).
    let local = unsafe { In::<SystemTimeBytes>::new(local.cast()) };
    bool_answer(set_local(local))
}

/// SetLocalTime's work.
fn set_local(local: In<'_, SystemTimeBytes>) -> Result<(), Failure> {
    let local = time_of(SystemTime::from_bytes(&local.read()))
        .ok_or(Failure::Error(ERROR_INVALID_PARAMETER))?;
    let system = local.wrapping_add(shared::time(shared::TIME_ZONE_BIAS));
    ntcall::set_system_time(system).map_err(Failure::Status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt;

    fn compare(first: u64, second: u64) -> i32 {
        // SAFETY: the FILETIMEs above.
        unsafe { compare_file_time(&first, &second) }
    }

    /// The comparison is unsigned over the whole count: the high dword decides, a top bit set is
    /// the larger.
    #[test]
    fn file_times_compare_unsigned() {
        assert_eq!(compare(0x1_0000_0005, 0x1_0000_0005), 0);
        assert_eq!(compare(0x1_0000_0004, 0x1_0000_0005), -1);
        assert_eq!(compare(0x1_FFFF_FFFF, 0x2_0000_0000), -1);
        assert_eq!(compare(0x1_8000_0000, 0x1_7FFF_FFFF), 1);
        assert_eq!(compare(0x8000_0000_0000_0000, 0x7FFF_FFFF_0000_0000), 1);
        assert_eq!(compare(0, u64::MAX), -1);
    }

    /// SetLocalTime sets the system time through ntdll, the day of the week ignored; a field out of
    /// range is ERROR_INVALID_PARAMETER, nothing set.
    #[test]
    fn set_local_time_sets_the_system_time() {
        let time = |month: u16, day: u16, weekday: u16| {
            SystemTime {
                year: 2026,
                month,
                day_of_week: weekday,
                day,
                hour: 15,
                minute: 28,
                second: 15,
                milliseconds: 260,
            }
            .to_bytes()
        };
        nt::TIMES_SET.with(|times| times.borrow_mut().clear());
        assert_eq!(unsafe { set_local_time(time(10, 24, 9).as_ptr()) }, 1);
        let local = time_of(SystemTime::from_bytes(&time(10, 24, 6))).unwrap();
        let expected = local.wrapping_add(shared::time(shared::TIME_ZONE_BIAS));
        nt::TIMES_SET.with(|times| assert_eq!(*times.borrow(), [expected]));
        crate::base::set_last_error(0);
        assert_eq!(unsafe { set_local_time(time(2, 30, 0).as_ptr()) }, 0);
        assert_eq!(crate::base::last_error(), ERROR_INVALID_PARAMETER);
        nt::TIMES_SET.with(|times| assert_eq!(times.borrow().len(), 1));
    }
}
