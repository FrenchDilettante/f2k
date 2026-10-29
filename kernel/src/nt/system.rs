//! The system queries: NtQuerySystemInformation (the classes F2K answers) and the performance
//! counter, and the system time's setting (NtSetSystemTime). kernel32's GetSystemInfo and
//! GlobalMemoryStatus are Win32 code over the first (with the process's counters, `nt::process`),
//! GetTimeZoneInformation and QueryPerformanceCounter/Frequency over the others, SetLocalTime over
//! the last, as on Windows 2000.

use rtl::nt::info::{
    RtlTimeZoneInformation,
    SystemBasicInformation,
    SystemPerformanceInformation,
    SystemProcessorInformation,
};
use rtl::pod::Pod;

use super::call::{NtCall, NtResult, UserAddr, UserPtr};
use crate::mem::vm::{GRANULARITY, PAGE, USER_HIGH, USER_LOW};
use crate::status::*;

info_class! {
    /// The classes NtQuerySystemInformation answers (SYSTEM_INFORMATION_CLASS).
    pub enum SystemClass {
        /// SYSTEM_BASIC_INFORMATION: the page size, the physical pages, the allocation
        /// granularity, the application range and the processors.
        Basic = 0,
        /// SYSTEM_PROCESSOR_INFORMATION: the processor's architecture, level and revision.
        Processor = 1,
        /// SYSTEM_PERFORMANCE_INFORMATION: the memory manager's page counts among the system's
        /// counters.
        Performance = 2,
        /// The RTL_TIME_ZONE_INFORMATION in effect.
        CurrentTimeZone = 44,
    }
}

/// The clock's interval (KeMaximumIncrement), in 100 ns units: the basic information's timer
/// resolution.
const TIMER_RESOLUTION: u32 = crate::interrupt::clock::INTERVAL_100NS;

/// The processor: an x86 (PROCESSOR_ARCHITECTURE_INTEL) of level 6, a P6, revision 0.
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_LEVEL: u16 = 6;

/// The machine's memory, in pages: all of it and what is free.
#[cfg(target_arch = "x86")]
fn memory_pages() -> (u32, u32) {
    crate::mem::bootmem::with_frame_db(|db| (db.frame_count(), db.available()))
}

#[cfg(not(target_arch = "x86"))]
fn memory_pages() -> (u32, u32) {
    (0, 0)
}

/// SYSTEM_BASIC_INFORMATION for `pages` pages of memory: one processor, 4 KiB pages on the 64 KiB
/// granularity, the application range 0x10000..=0x7FFEFFFF, the physical pages numbered from 1.
pub fn basic_information(pages: u32) -> SystemBasicInformation {
    SystemBasicInformation {
        timer_resolution: TIMER_RESOLUTION,
        page_size: PAGE,
        number_of_physical_pages: pages,
        lowest_physical_page_number: 1,
        highest_physical_page_number: pages.saturating_sub(1),
        allocation_granularity: GRANULARITY,
        minimum_user_mode_address: USER_LOW,
        maximum_user_mode_address: USER_HIGH - 1,
        active_processors_affinity_mask: 1,
        number_of_processors: 1,
        ..Default::default()
    }
}

/// SYSTEM_PROCESSOR_INFORMATION: the architecture, the level and the revision; no feature bits.
pub fn processor_information() -> SystemProcessorInformation {
    SystemProcessorInformation {
        processor_architecture: PROCESSOR_ARCHITECTURE_INTEL,
        processor_level: PROCESSOR_LEVEL,
        ..Default::default()
    }
}

/// SYSTEM_PERFORMANCE_INFORMATION for `pages` pages of memory, `available` of them free: the
/// available, committed and peak pages and the commit limit (no paging file beyond memory itself:
/// the limit is memory, and what is not available is committed, the peak not kept); the other
/// counters zero.
pub fn performance_information(pages: u32, available: u32) -> SystemPerformanceInformation {
    let committed = pages - available;
    SystemPerformanceInformation {
        available_pages: available,
        committed_pages: committed,
        commit_limit: pages,
        peak_commitment: committed,
        ..Pod::zeroed()
    }
}

/// A query's answer: the class's structure.
pub enum Answer {
    Basic(SystemBasicInformation),
    Processor(SystemProcessorInformation),
    Performance(SystemPerformanceInformation),
    TimeZone(RtlTimeZoneInformation),
}

impl Answer {
    /// The structure's bytes, as the caller's buffer receives them.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Answer::Basic(info) => info.as_bytes(),
            Answer::Processor(info) => info.as_bytes(),
            Answer::Performance(info) => info.as_bytes(),
            Answer::TimeZone(info) => info.as_bytes(),
        }
    }
}

/// What a query of `class` into a buffer of `length` bytes answers, for a machine of `pages` pages
/// of memory, `available` of them free, or the status that refuses it. The basic and processor
/// information and the time zone (no zone configured: a zero bias, no names, no daylight-saving
/// dates) take their structure's length exactly, the performance information at least its
/// structure's, as Windows 2000 checks them. STATUS_INVALID_INFO_CLASS for the classes F2K does not
/// answer.
pub fn system_information(
    class: u32,
    length: u32,
    (pages, available): (u32, u32),
) -> Result<Answer, NtStatus> {
    let length = length as usize;
    let exactly = |size: usize| {
        if length == size {
            Ok(())
        } else {
            Err(STATUS_INFO_LENGTH_MISMATCH)
        }
    };
    Ok(match SystemClass::try_from(class)? {
        SystemClass::Basic => {
            exactly(size_of::<SystemBasicInformation>())?;
            Answer::Basic(basic_information(pages))
        }
        SystemClass::Processor => {
            exactly(size_of::<SystemProcessorInformation>())?;
            Answer::Processor(processor_information())
        }
        SystemClass::Performance => {
            if length < size_of::<SystemPerformanceInformation>() {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            Answer::Performance(performance_information(pages, available))
        }
        SystemClass::CurrentTimeZone => {
            exactly(size_of::<RtlTimeZoneInformation>())?;
            Answer::TimeZone(RtlTimeZoneInformation::default())
        }
    })
}

/// NtQuerySystemInformation: the basic, processor and performance information, and the current
/// time zone (see [`system_information`]).
pub fn query_system_information(
    _call: &mut NtCall,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let answer = system_information(class, length, memory_pages())?;
    information.write(answer.bytes())?;
    return_length.write_optional(answer.bytes().len() as u32)?;
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

/// NtSetSystemTime: the system time (a FILETIME, UTC) set to `time`'s, the time it replaces written
/// to `previous` when asked; a NULL `time` only reads it. A time past the signed range is
/// STATUS_INVALID_PARAMETER. No privilege is checked: F2K has no tokens (Windows 2000 asks for
/// SeSystemtimePrivilege, which kernel32's SetLocalTime and SetSystemTime enable first).
pub fn set_system_time(_call: &mut NtCall, time: UserPtr<u64>, previous: UserPtr<u64>) -> NtResult {
    let new = if time.is_null() {
        None
    } else {
        Some(time.read()?)
    };
    if new.is_some_and(|new| new >> 63 != 0) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    #[cfg(target_arch = "x86")]
    let now = crate::time::system_filetime();
    #[cfg(not(target_arch = "x86"))]
    let now = 0u64;
    previous.write_optional(now)?;
    #[cfg(target_arch = "x86")]
    if let Some(new) = new {
        crate::time::set_system_filetime(new);
    }
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn query(class: u32, length: u32) -> Result<std::vec::Vec<u8>, NtStatus> {
        let answer = system_information(class, length, (0x4000, 0x1000))?;
        Ok(answer.bytes().to_vec())
    }

    /// The time zone: a zero structure of its exact length; another length is a mismatch, another
    /// class not answered (GetTimeZoneInformation's error is the status's).
    #[test]
    fn the_time_zone_is_none_at_its_length() {
        assert_eq!(query(44, 172), Ok(std::vec![0u8; 172]));
        assert_eq!(query(44, 171), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(query(44, 0), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(query(0x77, 172), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(rtl::status::dos_error(STATUS_INFO_LENGTH_MISMATCH.0), 24);
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_INFO_CLASS.0), 87);
    }

    /// The facts the memory fixture's sysinfo block prints come from the basic information: 4 KiB
    /// pages, 64 KiB granularity, the application range 0x00010000..0x7FFEFFFF, one processor.
    #[test]
    fn the_basic_information_is_the_captured_machine() {
        let basic = query(0, 44).unwrap();
        assert_eq!(
            (word(&basic, 0x08), word(&basic, 0x0C), word(&basic, 0x18)),
            (0x1000, 0x4000, 0x1_0000)
        );
        assert_eq!(
            (word(&basic, 0x1C), word(&basic, 0x20)),
            (0x1_0000, 0x7FFE_FFFF)
        );
        assert_eq!((word(&basic, 0x24), basic[0x28]), (1, 1));
        assert_eq!(query(0, 48), Err(STATUS_INFO_LENGTH_MISMATCH), "exactly");
        let processor = query(1, 12).unwrap();
        assert_eq!((processor[0], processor[2]), (0, 6), "an x86 of level 6");
    }

    #[test]
    fn the_performance_information_counts_pages() {
        let performance = query(2, 0x200).unwrap();
        assert_eq!(performance.len(), 312, "at least its structure's length");
        assert_eq!(
            (
                word(&performance, 0x2C),
                word(&performance, 0x30),
                word(&performance, 0x34)
            ),
            (0x1000, 0x3000, 0x4000)
        );
        assert_eq!(query(2, 0x137), Err(STATUS_INFO_LENGTH_MISMATCH));
    }
}
