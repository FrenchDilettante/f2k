//! Virtual memory and the system's memory facts: kernel32's own code over ntdll's system services,
//! as on Windows 2000. VirtualAlloc, VirtualFree, VirtualProtect and VirtualQuery
//! act on the calling process (NtCurrentProcess), a failed service's status setting the last error
//! through BaseSetLastNTError; GetSystemInfo and GlobalMemoryStatus read
//! NtQuerySystemInformation's basic, processor and performance classes and the process's
//! virtual-memory counters (NtQueryInformationProcess). Windows 2000 reads the basic information
//! from the base server's static data, which csrss fills at its start with the same query (no
//! csrss).

use rtl::status::nt_success;

pub use crate::base::CURRENT_PROCESS;
use crate::base::{set_last_nt_error, succeeded};
use crate::nt;

const MEM_RELEASE: u32 = 0x8000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// NtQuerySystemInformation's classes, NtQueryInformationProcess's, and their structures' sizes.
const SYSTEM_BASIC_INFORMATION: u32 = 0;
const SYSTEM_PROCESSOR_INFORMATION: u32 = 1;
const SYSTEM_PERFORMANCE_INFORMATION: u32 = 2;
const PROCESS_VM_COUNTERS: u32 = 3;
const BASIC_SIZE: usize = 44;
const PROCESSOR_SIZE: usize = 12;
const PERFORMANCE_SIZE: usize = 0x138;
const VM_COUNTERS_SIZE: usize = 44;

/// The processor types GetSystemInfo reports for an x86 by its level.
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_INTEL_386: u32 = 386;
const PROCESSOR_INTEL_486: u32 = 486;
const PROCESSOR_INTEL_PENTIUM: u32 = 586;

/// VirtualAlloc: a reservation, a commit inside one, or both; the base the call settled on (the
/// granularity's for a reservation, the first page's for a commit), or null with the status's
/// error.
#[unsafe(export_name = "f2k_export_VirtualAlloc")]
pub extern "system" fn virtual_alloc(
    address: usize,
    size: usize,
    kind: u32,
    protect: u32,
) -> usize {
    let (mut base, mut size) = (address, size);
    // SAFETY: ntdll's export, over the in/out values above.
    let status = unsafe {
        nt::NtAllocateVirtualMemory(CURRENT_PROCESS, &mut base, 0, &mut size, kind, protect)
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    base
}

/// VirtualFree: a release (a reservation's base, no size: ERROR_INVALID_PARAMETER for a size, as
/// Windows 2000 checks before the call) or a decommit.
#[unsafe(export_name = "f2k_export_VirtualFree")]
pub extern "system" fn virtual_free(address: usize, size: usize, kind: u32) -> u32 {
    if kind & MEM_RELEASE != 0 && size != 0 {
        set_last_nt_error(STATUS_INVALID_PARAMETER);
        return 0;
    }
    let (mut base, mut size) = (address, size);
    // SAFETY: ntdll's export, over the in/out values above.
    succeeded(unsafe { nt::NtFreeVirtualMemory(CURRENT_PROCESS, &mut base, &mut size, kind) })
}

/// VirtualProtect: the pages' new protection, the first one's old protection into `old` (which the
/// service probes: a bad pointer is ERROR_NOACCESS).
///
/// # Safety
///
/// `old` is the caller's (the service reaches it through the user-memory copy).
#[unsafe(export_name = "f2k_export_VirtualProtect")]
pub unsafe extern "system" fn virtual_protect(
    address: usize,
    size: usize,
    protect: u32,
    old: *mut u32,
) -> u32 {
    let (mut base, mut size) = (address, size);
    // SAFETY: ntdll's export, over the in/out values above.
    succeeded(unsafe {
        nt::NtProtectVirtualMemory(CURRENT_PROCESS, &mut base, &mut size, protect, old)
    })
}

/// VirtualQuery: the MEMORY_BASIC_INFORMATION of the pages from `address` into `buffer`; the
/// structure's size, or zero with the status's error (ERROR_BAD_LENGTH for a short buffer).
///
/// # Safety
///
/// `buffer` is the caller's (the service reaches it through the user-memory copy).
#[unsafe(export_name = "f2k_export_VirtualQuery")]
pub unsafe extern "system" fn virtual_query(
    address: usize,
    buffer: *mut u8,
    length: usize,
) -> usize {
    let mut returned = 0;
    // SAFETY: ntdll's export.
    let status = unsafe {
        nt::NtQueryVirtualMemory(CURRENT_PROCESS, address, 0, buffer, length, &mut returned)
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    returned
}

/// A system query's structure, as dwords; none when the query fails.
fn query<const N: usize>(class: u32) -> Option<[u32; N]> {
    let mut words = [0u32; N];
    // SAFETY: ntdll's export, into the buffer above.
    let status = unsafe {
        nt::NtQuerySystemInformation(
            class,
            words.as_mut_ptr().cast(),
            (4 * N) as u32,
            core::ptr::null_mut(),
        )
    };
    nt_success(status).then_some(words)
}

/// SYSTEM_INFO, as the caller's structure lays it out.
#[repr(C)]
pub struct SystemInfo {
    pub processor_architecture: u16,
    pub reserved: u16,
    pub page_size: u32,
    pub minimum_application_address: u32,
    pub maximum_application_address: u32,
    pub active_processor_mask: u32,
    pub number_of_processors: u32,
    pub processor_type: u32,
    pub allocation_granularity: u32,
    pub processor_level: u16,
    pub processor_revision: u16,
}

/// GetSystemInfo: the page size and allocation granularity, the application range, the processors,
/// and the processor's architecture, type, level and revision. Left untouched when the system
/// cannot say.
///
/// # Safety
///
/// `info` points at a writable SYSTEM_INFO (a bad pointer faults the caller, as on the platform).
#[unsafe(export_name = "f2k_export_GetSystemInfo")]
pub unsafe extern "system" fn get_system_info(info: *mut SystemInfo) {
    let (Some(basic), Some(processor)) = (
        query::<{ BASIC_SIZE / 4 }>(SYSTEM_BASIC_INFORMATION),
        query::<{ PROCESSOR_SIZE / 4 }>(SYSTEM_PROCESSOR_INFORMATION),
    ) else {
        return;
    };
    let architecture = processor[0] as u16;
    let level = (processor[0] >> 16) as u16;
    let processor_type = match (architecture, level) {
        (PROCESSOR_ARCHITECTURE_INTEL, 3) => PROCESSOR_INTEL_386,
        (PROCESSOR_ARCHITECTURE_INTEL, 4) => PROCESSOR_INTEL_486,
        (PROCESSOR_ARCHITECTURE_INTEL, _) => PROCESSOR_INTEL_PENTIUM,
        _ => 0,
    };
    let filled = SystemInfo {
        processor_architecture: architecture,
        reserved: 0,
        page_size: basic[2],
        minimum_application_address: basic[7],
        maximum_application_address: basic[8],
        active_processor_mask: basic[9],
        number_of_processors: basic[10] & 0xFF,
        processor_type,
        allocation_granularity: basic[6],
        processor_level: level,
        processor_revision: processor[1] as u16,
    };
    // SAFETY: the caller's structure.
    unsafe { info.write_unaligned(filled) };
}

/// MEMORYSTATUS, as the caller's structure lays it out.
#[repr(C)]
pub struct MemoryStatus {
    pub length: u32,
    pub memory_load: u32,
    pub total_phys: u32,
    pub avail_phys: u32,
    pub total_page_file: u32,
    pub avail_page_file: u32,
    pub total_virtual: u32,
    pub avail_virtual: u32,
}

/// GlobalMemoryStatus: physical memory (the basic information's pages, the performance
/// information's available ones), the commit limit and what remains of it (the "page file"), and
/// the application range with what the process has not reserved of it (its VM counters' virtual
/// size). The load is the share of physical memory in use, in percent. Only the length is written
/// when the system cannot say.
///
/// # Safety
///
/// `buffer` points at a writable MEMORYSTATUS (a bad pointer faults the caller, as on the
/// platform).
#[unsafe(export_name = "f2k_export_GlobalMemoryStatus")]
pub unsafe extern "system" fn global_memory_status(buffer: *mut MemoryStatus) {
    let mut status = MemoryStatus {
        length: core::mem::size_of::<MemoryStatus>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
    };
    let mut counters = [0u32; VM_COUNTERS_SIZE / 4];
    // SAFETY: ntdll's export, into the buffer above.
    let counted = nt_success(unsafe {
        nt::NtQueryInformationProcess(
            CURRENT_PROCESS,
            PROCESS_VM_COUNTERS,
            counters.as_mut_ptr().cast(),
            VM_COUNTERS_SIZE as u32,
            core::ptr::null_mut(),
        )
    });
    if let (Some(basic), Some(performance), true) = (
        query::<{ BASIC_SIZE / 4 }>(SYSTEM_BASIC_INFORMATION),
        query::<{ PERFORMANCE_SIZE / 4 }>(SYSTEM_PERFORMANCE_INFORMATION),
        counted,
    ) {
        let page = u64::from(basic[2]);
        let bytes = |pages: u32| (u64::from(pages) * page).min(u64::from(u32::MAX)) as u32;
        let (pages, available) = (basic[3], performance[0x2C / 4]);
        let (committed, limit) = (performance[0x30 / 4], performance[0x34 / 4]);
        status.memory_load = if pages == 0 {
            0
        } else {
            100 - (u64::from(available) * 100 / u64::from(pages)) as u32
        };
        status.total_phys = bytes(pages);
        status.avail_phys = bytes(available);
        status.total_page_file = bytes(limit);
        status.avail_page_file = bytes(limit.saturating_sub(committed));
        status.total_virtual = basic[8] - basic[7] + 1;
        status.avail_virtual = status.total_virtual.saturating_sub(counters[1]);
    }
    // SAFETY: the caller's structure.
    unsafe { buffer.write_unaligned(status) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{last_error, set_last_error};
    use crate::nt::host::{AVAILABLE, BASE, FAIL_NEXT, LAST_VM, PAGES, VIRTUAL_SIZE};

    fn fail_next(status: u32) {
        FAIL_NEXT.with(|cell| cell.set(status));
    }

    fn last_vm() -> Option<(usize, usize, u32)> {
        LAST_VM.with(|cell| cell.take())
    }

    #[test]
    fn allocations_return_the_settled_base_or_the_mapped_error() {
        assert_eq!(virtual_alloc(0x3000_1234, 0x1000, 0x3000, 4), BASE);
        assert_eq!(last_vm(), Some((0x3000_1234, 0x1000, 0x3000)));
        fail_next(0xC000_0018);
        assert_eq!(virtual_alloc(0x2000_0000, 0x1_0000, 0x2000, 4), 0);
        assert_eq!(last_error(), 487, "STATUS_CONFLICTING_ADDRESSES");
        fail_next(0xC000_00F2);
        assert_eq!(virtual_alloc(0, 0, 0x2000, 4), 0);
        assert_eq!(last_error(), 87, "STATUS_INVALID_PARAMETER_4");
    }

    /// The memory fixture's VirtualFree refusals (memory/virtual): a release with a size is refused
    /// before the call; one not at the base is the service's STATUS_FREE_VM_NOT_AT_BASE.
    #[test]
    fn frees_refuse_a_release_with_a_size() {
        set_last_error(0);
        assert_eq!(virtual_free(BASE, 0x1000, MEM_RELEASE), 0);
        assert_eq!(last_error(), 87);
        assert_eq!(last_vm(), None, "refused before the call");
        fail_next(0xC000_009F);
        assert_eq!(virtual_free(BASE + 0x1_0000, 0, MEM_RELEASE), 0);
        assert_eq!(last_error(), 487);
        assert_eq!(virtual_free(BASE, 0, MEM_RELEASE), 1);
        assert_eq!(last_vm(), Some((BASE, 0, MEM_RELEASE)));
    }

    #[test]
    fn protections_and_queries_answer_through_the_services() {
        let mut old = 0;
        // SAFETY: a writable old protection.
        assert_eq!(unsafe { virtual_protect(BASE, 0x1000, 2, &mut old) }, 1);
        assert_eq!((old, last_vm()), (4, Some((BASE, 0x1000, 2))));
        fail_next(0xC000_002D);
        // SAFETY: as above.
        assert_eq!(unsafe { virtual_protect(BASE, 0x1_0000, 4, &mut old) }, 0);
        assert_eq!(last_error(), 487, "STATUS_NOT_COMMITTED");
        let mut info = [0u8; 28];
        // SAFETY: a 28-byte buffer.
        assert_eq!(
            unsafe { virtual_query(BASE + 0x10, info.as_mut_ptr(), 28) },
            28
        );
        assert_eq!(
            u32::from_le_bytes(info[..4].try_into().unwrap()),
            BASE as u32
        );
        // SAFETY: a short buffer.
        assert_eq!(unsafe { virtual_query(BASE, info.as_mut_ptr(), 27) }, 0);
        assert_eq!(last_error(), 24, "ERROR_BAD_LENGTH");
    }

    /// The memory fixture's sysinfo block: 4 KiB pages, 64 KiB granularity, the application range,
    /// one x86 processor; GlobalMemoryStatus's length and total virtual size.
    #[test]
    fn the_system_facts_come_from_the_queries() {
        // SAFETY: a zeroed SYSTEM_INFO is a valid one.
        let mut info: SystemInfo = unsafe { core::mem::zeroed() };
        // SAFETY: a writable SYSTEM_INFO.
        unsafe { get_system_info(&mut info) };
        assert_eq!(
            (info.page_size, info.allocation_granularity),
            (0x1000, 0x1_0000)
        );
        assert_eq!(
            (
                info.minimum_application_address,
                info.maximum_application_address
            ),
            (0x1_0000, 0x7FFE_FFFF)
        );
        assert_eq!(
            (
                info.processor_architecture,
                info.number_of_processors,
                info.active_processor_mask
            ),
            (0, 1, 1)
        );
        assert_eq!(
            (
                info.processor_type,
                info.processor_level,
                info.processor_revision
            ),
            (586, 6, 0)
        );
        assert_eq!(core::mem::size_of::<SystemInfo>(), 36);

        // SAFETY: a zeroed MEMORYSTATUS is a valid one.
        let mut status: MemoryStatus = unsafe { core::mem::zeroed() };
        // SAFETY: a writable MEMORYSTATUS.
        unsafe { global_memory_status(&mut status) };
        assert_eq!((status.length, status.total_virtual), (32, 0x7FFE_0000));
        assert_eq!(
            (status.total_phys, status.avail_phys),
            (PAGES * 0x1000, AVAILABLE * 0x1000)
        );
        assert_eq!(
            (status.total_page_file, status.avail_page_file),
            (PAGES * 0x1000, AVAILABLE * 0x1000)
        );
        assert_eq!(status.memory_load, 75);
        assert_eq!(status.avail_virtual, 0x7FFE_0000 - VIRTUAL_SIZE);
    }
}
