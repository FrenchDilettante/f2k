//! The system queries: NtQuerySystemInformation (the classes F2K answers) and the performance
//! counter. kernel32's GetSystemInfo and GlobalMemoryStatus are Win32 code over the first (with
//! the process's counters, `nt::process`), GetTimeZoneInformation and
//! QueryPerformanceCounter/Frequency over the others, as on Windows 2000.

use super::call::{NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_SUCCESS};
use crate::mem::vm::{GRANULARITY, PAGE, USER_HIGH, USER_LOW};

/// STATUS_INVALID_INFO_CLASS: a class the service does not answer.
pub const STATUS_INVALID_INFO_CLASS: Status = Status(0xC000_0003);
/// STATUS_INFO_LENGTH_MISMATCH: a buffer of the wrong length for the class's structure.
pub const STATUS_INFO_LENGTH_MISMATCH: Status = Status(0xC000_0004);

/// SystemBasicInformation: the page size, the physical pages, the allocation granularity, the
/// application range and the processors (SYSTEM_BASIC_INFORMATION, 44 bytes).
const SYSTEM_BASIC_INFORMATION: u32 = 0;
const SYSTEM_BASIC_INFORMATION_SIZE: u32 = 44;
/// SystemProcessorInformation: the processor's architecture, level and revision
/// (SYSTEM_PROCESSOR_INFORMATION, 12 bytes).
const SYSTEM_PROCESSOR_INFORMATION: u32 = 1;
const SYSTEM_PROCESSOR_INFORMATION_SIZE: u32 = 12;
/// SystemPerformanceInformation: the memory manager's page counts among the system's counters
/// (SYSTEM_PERFORMANCE_INFORMATION, 0x138 bytes).
const SYSTEM_PERFORMANCE_INFORMATION: u32 = 2;
const SYSTEM_PERFORMANCE_INFORMATION_SIZE: u32 = 0x138;
/// SystemCurrentTimeZoneInformation: the RTL_TIME_ZONE_INFORMATION in effect.
const SYSTEM_CURRENT_TIME_ZONE_INFORMATION: u32 = 44;
/// sizeof(RTL_TIME_ZONE_INFORMATION) (TIME_ZONE_INFORMATION's layout).
const TIME_ZONE_INFORMATION_SIZE: u32 = 172;

/// The clock's interval (KeMaximumIncrement), in 100 ns units: the basic information's timer
/// resolution.
const TIMER_RESOLUTION: u32 = crate::interrupt::clock::INTERVAL_100NS;

/// The processor: an x86 (PROCESSOR_ARCHITECTURE_INTEL) of level 6, a P6, revision 0.
const PROCESSOR_ARCHITECTURE_INTEL: u32 = 0;
const PROCESSOR_LEVEL: u32 = 6;

/// The machine's memory, in pages: all of it and what is free.
#[cfg(target_arch = "x86")]
fn memory_pages() -> (u32, u32) {
    crate::mem::bootmem::with_frame_db(|db| (db.frame_count(), db.available()))
}

#[cfg(not(target_arch = "x86"))]
fn memory_pages() -> (u32, u32) {
    (0, 0)
}

/// Dwords as the bytes of the structure they lay out (the rest zero).
pub(super) fn layout<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// SYSTEM_BASIC_INFORMATION for `pages` pages of memory: one processor, 4 KiB pages on the 64 KiB
/// granularity, the application range 0x10000..=0x7FFEFFFF, the physical pages numbered from 1.
pub fn basic_information(pages: u32) -> [u8; SYSTEM_BASIC_INFORMATION_SIZE as usize] {
    layout(&[
        0, // Reserved
        TIMER_RESOLUTION,
        PAGE,
        pages,
        1,                       // LowestPhysicalPageNumber
        pages.saturating_sub(1), // HighestPhysicalPageNumber
        GRANULARITY,
        USER_LOW,
        USER_HIGH - 1,
        1, // ActiveProcessorsAffinityMask
        1, // NumberOfProcessors (a CCHAR, padded)
    ])
}

/// SYSTEM_PROCESSOR_INFORMATION: the architecture, the level and the revision; no feature bits.
pub fn processor_information() -> [u8; SYSTEM_PROCESSOR_INFORMATION_SIZE as usize] {
    layout(&[PROCESSOR_ARCHITECTURE_INTEL | PROCESSOR_LEVEL << 16])
}

/// SYSTEM_PERFORMANCE_INFORMATION for `pages` pages of memory, `available` of them free: the
/// available, committed and peak pages and the commit limit (no paging file beyond memory itself:
/// the limit is memory, and what is not available is committed, the peak not kept); the other
/// counters zero.
pub fn performance_information(
    pages: u32,
    available: u32,
) -> [u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE as usize] {
    // AvailablePages at 0x2C, CommittedPages 0x30, CommitLimit 0x34, PeakCommitment 0x38: past the
    // four LARGE_INTEGER counters and the three operation counts.
    let committed = pages - available;
    let mut words = [0u32; SYSTEM_PERFORMANCE_INFORMATION_SIZE as usize / 4];
    words[0x2C / 4..0x3C / 4].copy_from_slice(&[available, committed, pages, committed]);
    layout(&words)
}

/// What a query of `class` into a buffer of `length` bytes answers, for a machine of `pages` pages
/// of memory, `available` of them free: the structure's bytes into `out`, their length, or the
/// status that refuses it. The basic and processor information and the time zone (no zone
/// configured: a zero bias, no names, no daylight-saving dates) take their structure's length
/// exactly, the performance information at least its structure's, as Windows 2000 checks them.
/// STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn system_information(
    class: u32,
    length: u32,
    (pages, available): (u32, u32),
    out: &mut [u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE as usize],
) -> Result<usize, Status> {
    let exactly = |size: u32| {
        if length == size {
            Ok(size as usize)
        } else {
            Err(STATUS_INFO_LENGTH_MISMATCH)
        }
    };
    let size = match class {
        SYSTEM_BASIC_INFORMATION => {
            let size = exactly(SYSTEM_BASIC_INFORMATION_SIZE)?;
            out[..size].copy_from_slice(&basic_information(pages));
            size
        }
        SYSTEM_PROCESSOR_INFORMATION => {
            let size = exactly(SYSTEM_PROCESSOR_INFORMATION_SIZE)?;
            out[..size].copy_from_slice(&processor_information());
            size
        }
        SYSTEM_PERFORMANCE_INFORMATION => {
            if length < SYSTEM_PERFORMANCE_INFORMATION_SIZE {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            *out = performance_information(pages, available);
            out.len()
        }
        SYSTEM_CURRENT_TIME_ZONE_INFORMATION => {
            let size = exactly(TIME_ZONE_INFORMATION_SIZE)?;
            out[..size].fill(0);
            size
        }
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    Ok(size)
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
    let mut out = [0u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE as usize];
    let size = system_information(class, length, memory_pages(), &mut out)?;
    information.write(&out[..size])?;
    return_length.write_optional(size as u32)?;
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

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn query(class: u32, length: u32) -> Result<std::vec::Vec<u8>, Status> {
        let mut out = [0u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE as usize];
        let size = system_information(class, length, (0x4000, 0x1000), &mut out)?;
        Ok(out[..size].to_vec())
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
