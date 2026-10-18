//! The system queries: NtQuerySystemInformation (the classes F2K answers) and the performance
//! counter. kernel32's GetTimeZoneInformation and QueryPerformanceCounter/Frequency are Win32 code
//! over them, as on Windows 2000.

use super::call::{NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_SUCCESS};

/// STATUS_INVALID_INFO_CLASS: a class the service does not answer.
pub const STATUS_INVALID_INFO_CLASS: Status = Status(0xC000_0003);
/// STATUS_INFO_LENGTH_MISMATCH: a buffer of the wrong length for the class's structure.
pub const STATUS_INFO_LENGTH_MISMATCH: Status = Status(0xC000_0004);

/// SystemCurrentTimeZoneInformation: the RTL_TIME_ZONE_INFORMATION in effect.
const SYSTEM_CURRENT_TIME_ZONE_INFORMATION: u32 = 44;
/// sizeof(RTL_TIME_ZONE_INFORMATION) (TIME_ZONE_INFORMATION's layout).
const TIME_ZONE_INFORMATION_SIZE: u32 = 172;

/// What a query of `class` into a buffer of `length` bytes answers: the structure's bytes, or the
/// status that refuses it. The time zone takes its structure's length exactly, as Windows 2000
/// checks it. STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn system_information(class: u32, length: u32) -> Result<&'static [u8], Status> {
    const NO_TIME_ZONE: [u8; TIME_ZONE_INFORMATION_SIZE as usize] =
        [0; TIME_ZONE_INFORMATION_SIZE as usize];
    match class {
        SYSTEM_CURRENT_TIME_ZONE_INFORMATION if length == TIME_ZONE_INFORMATION_SIZE => {
            Ok(&NO_TIME_ZONE)
        }
        SYSTEM_CURRENT_TIME_ZONE_INFORMATION => Err(STATUS_INFO_LENGTH_MISMATCH),
        _ => Err(STATUS_INVALID_INFO_CLASS),
    }
}

/// NtQuerySystemInformation: the current time zone (no zone configured: a zero bias, no names, no
/// daylight-saving dates). The basic, processor and performance classes (GetSystemInfo,
/// GlobalMemoryStatus) are refused too; every other class is STATUS_INVALID_INFO_CLASS.
pub fn query_system_information(
    _call: &mut NtCall,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let structure = system_information(class, length)?;
    information.write(structure)?;
    return_length.write_optional(structure.len() as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryPerformanceCounter: the counter (the interval timer's input clock: the ticks taken and
/// the timer's count within the current one, see `crate::time`) and, when asked, its frequency.
pub fn query_performance_counter(
    _call: &mut NtCall,
    counter: UserPtr<u64>,
    frequency: UserPtr<u64>,
) -> NtResult {
    #[cfg(target_arch = "x86")]
    let value = crate::time::performance_counter();
    #[cfg(not(target_arch = "x86"))]
    let value = 0u64;
    counter.write(value)?;
    frequency.write_optional(crate::time::PERFORMANCE_FREQUENCY)?;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The time zone: a zero structure of its exact length; another length is a mismatch, another
    /// class not answered (GetTimeZoneInformation's error is the status's).
    #[test]
    fn the_time_zone_is_none_at_its_length() {
        assert_eq!(system_information(44, 172), Ok(&[0u8; 172][..]));
        assert_eq!(system_information(44, 171), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(system_information(44, 0), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(system_information(0x77, 172), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(rtl::status::dos_error(STATUS_INFO_LENGTH_MISMATCH.0), 24);
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_INFO_CLASS.0), 87);
    }
}
