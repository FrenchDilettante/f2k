//! The system queries: NtQuerySystemInformation (the classes F2K answers) and the performance
//! counter, and the system time's setting (NtSetSystemTime). kernel32's GetSystemInfo and
//! GlobalMemoryStatus are Win32 code over the first (with the process's counters, `nt::process`),
//! its ToolHelp snapshots over the first's process listing ([`listing`]),
//! GetTimeZoneInformation and QueryPerformanceCounter/Frequency over the others, SetLocalTime over
//! the last, as on Windows 2000.

/// The process information: the listing of every process and its threads.
pub mod listing;

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

use core::sync::atomic::{AtomicU32, Ordering};

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
        /// The process listing: a SYSTEM_PROCESS_INFORMATION record per process, its threads'
        /// SYSTEM_THREAD_INFORMATION after it (see [`listing`]).
        Process = 5,
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

/// The machine's memory numbers, in pages: all physical pages, the free ones, the commit limit
/// and the total committed against it.
#[derive(Clone, Copy, Debug)]
pub struct MemoryNumbers {
    /// The physical pages.
    pub pages: u32,
    /// The free physical pages (the frame database's).
    pub available: u32,
    /// The commit limit (the commit seam's).
    pub limit: u32,
    /// The total committed (the commit seam's).
    pub committed: u32,
}

/// The machine's memory numbers: the frame database's pages (all of them and the free ones) and
/// the commit seam's (the limit and the total committed), in pages.
#[cfg(target_arch = "x86")]
fn memory_numbers() -> MemoryNumbers {
    let (pages, available) =
        crate::mem::bootmem::with_frame_db(|db| (db.frame_count(), db.available()));
    MemoryNumbers {
        pages,
        available,
        limit: (crate::mem::system_commit_limit() / u64::from(PAGE)) as u32,
        committed: (crate::mem::total_committed() / u64::from(PAGE)) as u32,
    }
}

/// Host builds have no frame database: the tests pass the numbers in.
#[cfg(not(target_arch = "x86"))]
fn memory_numbers() -> MemoryNumbers {
    MemoryNumbers {
        pages: 0,
        available: 0,
        limit: 0,
        committed: 0,
    }
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

/// The peak commitment reported so far, in pages: the running max of the committed count.
static PEAK_COMMITMENT_PAGES: AtomicU32 = AtomicU32::new(0);

/// SYSTEM_PERFORMANCE_INFORMATION for the machine's memory numbers `memory`: the available pages
/// (the frame database's free ones), the committed pages and the commit limit (the commit seam's)
/// and the peak commitment (the running max of the committed count); the other counters zero.
pub fn performance_information(memory: MemoryNumbers) -> SystemPerformanceInformation {
    let peak = PEAK_COMMITMENT_PAGES
        .fetch_max(memory.committed, Ordering::Relaxed)
        .max(memory.committed);
    SystemPerformanceInformation {
        available_pages: memory.available,
        committed_pages: memory.committed,
        commit_limit: memory.limit,
        peak_commitment: peak,
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

/// What a query of `class` into a buffer of `length` bytes answers, for the machine's memory
/// numbers `memory`, or the status that refuses it. The basic and processor information and the
/// time zone (no zone configured: a zero bias, no names, no daylight-saving dates) take their
/// structure's length exactly, the performance information at least its structure's, as Windows
/// 2000 checks them. STATUS_INVALID_INFO_CLASS for the classes F2K does not answer. The process
/// listing is no structure of a fixed size: [`query_system_information`] answers it apart, never
/// through here.
pub fn system_information(
    class: u32,
    length: u32,
    memory: MemoryNumbers,
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
            Answer::Basic(basic_information(memory.pages))
        }
        SystemClass::Processor => {
            exactly(size_of::<SystemProcessorInformation>())?;
            Answer::Processor(processor_information())
        }
        SystemClass::Performance => {
            if length < size_of::<SystemPerformanceInformation>() {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            Answer::Performance(performance_information(memory))
        }
        SystemClass::CurrentTimeZone => {
            exactly(size_of::<RtlTimeZoneInformation>())?;
            Answer::TimeZone(RtlTimeZoneInformation::default())
        }
        SystemClass::Process => unreachable!("the process listing is answered apart"),
    })
}

/// NtQuerySystemInformation: the basic, processor and performance information, and the current
/// time zone (see [`system_information`]); the process listing (see [`listing`]).
pub fn query_system_information(
    _call: &mut NtCall,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    if SystemClass::try_from(class) == Ok(SystemClass::Process) {
        #[cfg(target_arch = "x86")]
        return listing::query_processes(information, length, return_length);
        // Host builds have no processes to list.
        #[cfg(not(target_arch = "x86"))]
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let answer = system_information(class, length, memory_numbers())?;
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
    use std::sync::Mutex;
    use std::vec::Vec;

    /// The performance tests share the peak-commitment static, so they run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn numbers(pages: u32, available: u32, limit: u32, committed: u32) -> MemoryNumbers {
        MemoryNumbers {
            pages,
            available,
            limit,
            committed,
        }
    }

    fn query(class: u32, length: u32, memory: MemoryNumbers) -> Result<Vec<u8>, NtStatus> {
        let answer = system_information(class, length, memory)?;
        Ok(answer.bytes().to_vec())
    }

    fn query_performance(memory: MemoryNumbers) -> Result<Vec<u8>, NtStatus> {
        query(2, 0x200, memory)
    }

    /// The time zone: a zero structure of its exact length; another length is a mismatch, another
    /// class not answered (GetTimeZoneInformation's error is the status's).
    #[test]
    fn the_time_zone_is_none_at_its_length() {
        assert_eq!(query(44, 172, numbers(0x4000, 0x1000, 0x4000, 0x3000)), Ok(std::vec![0u8; 172]));
        assert_eq!(query(44, 171, numbers(0x4000, 0x1000, 0x4000, 0x3000)), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(query(44, 0, numbers(0x4000, 0x1000, 0x4000, 0x3000)), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(query(0x77, 172, numbers(0x4000, 0x1000, 0x4000, 0x3000)), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(rtl::status::dos_error(STATUS_INFO_LENGTH_MISMATCH.0), 24);
        assert_eq!(rtl::status::dos_error(STATUS_INVALID_INFO_CLASS.0), 87);
    }

    /// The facts the memory fixture's sysinfo block prints come from the basic information: 4 KiB
    /// pages, 64 KiB granularity, the application range 0x00010000..0x7FFEFFFF, one processor.
    #[test]
    fn the_basic_information_is_the_captured_machine() {
        let basic = query(0, 44, numbers(0x4000, 0x1000, 0x4000, 0x3000)).unwrap();
        assert_eq!(
            (word(&basic, 0x08), word(&basic, 0x0C), word(&basic, 0x18)),
            (0x1000, 0x4000, 0x1_0000)
        );
        assert_eq!(
            (word(&basic, 0x1C), word(&basic, 0x20)),
            (0x1_0000, 0x7FFE_FFFF)
        );
        assert_eq!((word(&basic, 0x24), basic[0x28]), (1, 1));
        assert_eq!(query(0, 48, numbers(0x4000, 0x1000, 0x4000, 0x3000)), Err(STATUS_INFO_LENGTH_MISMATCH), "exactly");
        let processor = query(1, 12, numbers(0x4000, 0x1000, 0x4000, 0x3000)).unwrap();
        assert_eq!((processor[0], processor[2]), (0, 6), "an x86 of level 6");
    }

    /// The performance class carries the memory numbers: the available pages at 0x2C, the
    /// committed at 0x30, the commit limit at 0x34 and the peak commitment at 0x38, and it takes
    /// at least its structure's length.
    #[test]
    fn the_performance_information_carries_the_memory_numbers() {
        let _serial = SERIAL.lock().unwrap();
        let performance = query_performance(numbers(0x4000, 0x1000, 0x8000, 0x3000)).unwrap();
        assert_eq!(performance.len(), 312, "at least its structure's length");
        assert_eq!(
            (
                word(&performance, 0x2C),
                word(&performance, 0x30),
                word(&performance, 0x34)
            ),
            (0x1000, 0x3000, 0x8000)
        );
        assert!(
            word(&performance, 0x38) >= 0x3000,
            "the peak is at least the committed count"
        );
        assert_eq!(
            query(2, 0x137, numbers(0x4000, 0x1000, 0x8000, 0x3000)),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
    }

    /// The peak commitment is the running max of the committed count: a later query with less
    /// committed still reports the peak the earlier one reached.
    #[test]
    fn the_peak_commitment_is_the_running_max_of_the_committed_count() {
        let _serial = SERIAL.lock().unwrap();
        let high = query_performance(numbers(0x4000, 0x1000, 0x8000, 0x7000)).unwrap();
        assert_eq!(word(&high, 0x38), 0x7000, "the peak reaches the committed count");
        let low = query_performance(numbers(0x4000, 0x1000, 0x8000, 0x100)).unwrap();
        assert_eq!(word(&low, 0x30), 0x100);
        assert_eq!(word(&low, 0x38), 0x7000, "a smaller committed count does not lower the peak");
    }
}
