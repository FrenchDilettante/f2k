//! NTSTATUS values and their Win32 errors: RtlNtStatusToDosError's mapping, which kernel32 reports
//! every failed Nt* call through (BaseSetLastNTError), as Windows 2000's does.
//!
//! The mapping, as ntdll's: a success status (zero) and a customer status (bit 29 set) are their
//! own answer; a 0xD... status is the 0xC... one; the Win32-facility statuses (0xC001xxxx,
//! 0x8007xxxx, 0xC007xxxx) carry the Win32 error in their low word; anything else is looked up in
//! the [`table`](crate::status_table), ERROR_MR_MID_NOT_FOUND (317) when it has no entry.

use crate::status_table::{ERRORS, RANGES};

/// An NTSTATUS value, as the NT interfaces carry it: a 32-bit code whose top two bits are its
/// severity (success, informational, warning, error), bit 29 the customer flag, the next twelve
/// bits the facility and the low word the code.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

/// An NTSTATUS's severity, its top two bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Success = 0,
    Informational = 1,
    Warning = 2,
    Error = 3,
}

impl NtStatus {
    /// The severity bits.
    pub const fn severity(self) -> Severity {
        match self.0 >> 30 {
            0 => Severity::Success,
            1 => Severity::Informational,
            2 => Severity::Warning,
            _ => Severity::Error,
        }
    }

    /// NT_SUCCESS: a success or informational status (the value non-negative as a signed one).
    pub const fn is_success(self) -> bool {
        (self.0 as i32) >= 0
    }

    /// NT_INFORMATION: an informational status.
    pub const fn is_information(self) -> bool {
        self.0 >> 30 == 1
    }

    /// NT_WARNING: a warning status.
    pub const fn is_warning(self) -> bool {
        self.0 >> 30 == 2
    }

    /// NT_ERROR: an error status.
    pub const fn is_error(self) -> bool {
        self.0 >> 30 == 3
    }
}

/// A status prints as its hexadecimal value, the form the documentation lists it in.
impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtStatus({:#010x})", self.0)
    }
}

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_ABANDONED: u32 = 0x0000_0080;
pub const STATUS_USER_APC: u32 = 0x0000_00C0;
pub const STATUS_KERNEL_APC: u32 = 0x0000_0100;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
pub const STATUS_IMAGE_NOT_AT_BASE: u32 = 0x4000_0003;
pub const STATUS_NO_YIELD_PERFORMED: u32 = 0x4000_0024;
pub const STATUS_TIMER_RESUME_IGNORED: u32 = 0x4000_0025;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;
pub const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_CID: u32 = 0xC000_000B;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_NOT_MAPPED_VIEW: u32 = 0xC000_0019;
pub const STATUS_INVALID_VIEW_SIZE: u32 = 0xC000_001F;
pub const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xC000_0020;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
pub const STATUS_NOT_COMMITTED: u32 = 0xC000_002D;
pub const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
pub const STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
pub const STATUS_MUTANT_NOT_OWNED: u32 = 0xC000_0046;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;
pub const STATUS_SECTION_NOT_IMAGE: u32 = 0xC000_0049;
pub const STATUS_SUSPEND_COUNT_EXCEEDED: u32 = 0xC000_004A;
pub const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
pub const STATUS_SECTION_PROTECTION: u32 = 0xC000_004E;
pub const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
pub const STATUS_DISK_FULL: u32 = 0xC000_007F;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_FREE_VM_NOT_AT_BASE: u32 = 0xC000_009F;
pub const STATUS_MEMORY_NOT_ALLOCATED: u32 = 0xC000_00A0;
pub const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
pub const STATUS_IO_TIMEOUT: u32 = 0xC000_00B5;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_CANT_TERMINATE_SELF: u32 = 0xC000_00DB;
pub const STATUS_INVALID_USER_BUFFER: u32 = 0xC000_00E8;
pub const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
pub const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
pub const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
pub const STATUS_INVALID_PARAMETER_6: u32 = 0xC000_00F4;
pub const STATUS_INVALID_PARAMETER_8: u32 = 0xC000_00F6;
pub const STATUS_INVALID_PARAMETER_9: u32 = 0xC000_00F7;
pub const STATUS_VARIABLE_NOT_FOUND: u32 = 0xC000_0100;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const STATUS_FILE_CORRUPT_ERROR: u32 = 0xC000_0102;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
pub const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
pub const STATUS_INVALID_IMAGE_NE_FORMAT: u32 = 0xC000_011B;
pub const STATUS_MAPPED_FILE_SIZE_ZERO: u32 = 0xC000_011E;
pub const STATUS_TOO_MANY_OPENED_FILES: u32 = 0xC000_011F;
pub const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
pub const STATUS_INVALID_IMAGE_LE_FORMAT: u32 = 0xC000_012E;
pub const STATUS_INVALID_IMAGE_NOT_MZ: u32 = 0xC000_012F;
pub const STATUS_INVALID_IMAGE_PROTECT: u32 = 0xC000_0130;
pub const STATUS_INVALID_IMAGE_WIN_16: u32 = 0xC000_0131;
pub const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
pub const STATUS_KEY_DELETED: u32 = 0xC000_017C;
pub const STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;
pub const STATUS_MAPPED_ALIGNMENT: u32 = 0xC000_0220;
pub const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;
pub const STATUS_USER_MAPPED_FILE: u32 = 0xC000_0243;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
/// The loader's: an export name a module does not have, or a module without exports; a module the
/// process has not loaded; an ordinal a module does not export; an entry point not found; a DLL's
/// entry point answering FALSE to DLL_PROCESS_ATTACH.
pub const STATUS_PROCEDURE_NOT_FOUND: u32 = 0xC000_007A;
pub const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
pub const STATUS_ORDINAL_NOT_FOUND: u32 = 0xC000_0138;
pub const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;
pub const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;

/// ERROR_MR_MID_NOT_FOUND: a status the table does not map.
pub const ERROR_MR_MID_NOT_FOUND: u32 = 317;

/// Whether a status is a success or an informational one (its severity bits below 2).
pub const fn nt_success(status: u32) -> bool {
    (status as i32) >= 0
}

/// The Win32 error a status maps to (RtlNtStatusToDosErrorNoTeb).
// The table's element type is the generator's choice (u16 or u32, by its widest error).
#[allow(clippy::useless_conversion)]
pub fn dos_error(status: u32) -> u32 {
    if status == 0 || status & 0x2000_0000 != 0 {
        return status;
    }
    let status = if status & 0xF000_0000 == 0xD000_0000 {
        status & !0x1000_0000
    } else {
        status
    };
    if matches!(status >> 16, 0xC001 | 0x8007 | 0xC007) {
        return status & 0xFFFF;
    }
    // The runs are in status order: the last one starting at or below the status holds it, if any.
    let run = RANGES.partition_point(|&(start, _, _)| start <= status);
    match run.checked_sub(1).map(|index| RANGES[index]) {
        Some((start, count, offset)) if status - start < u32::from(count) => {
            u32::from(ERRORS[usize::from(offset) + (status - start) as usize])
        }
        _ => ERROR_MR_MID_NOT_FOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The synchronization services' statuses, to the errors the sync and sched fixtures pin.
    #[test]
    fn the_synchronization_statuses_map_as_the_fixtures_pin() {
        for (status, error) in [
            (0xC000_0008, 6),    // STATUS_INVALID_HANDLE
            (0xC000_0024, 6),    // STATUS_OBJECT_TYPE_MISMATCH: a name or handle of another kind
            (0xC000_0034, 2),    // STATUS_OBJECT_NAME_NOT_FOUND: an open of a missing name
            (0xC000_0035, 183),  // STATUS_OBJECT_NAME_COLLISION
            (0xC000_0046, 288),  // STATUS_MUTANT_NOT_OWNED: ERROR_NOT_OWNER
            (0xC000_0047, 298),  // STATUS_SEMAPHORE_LIMIT_EXCEEDED: ERROR_TOO_MANY_POSTS
            (0xC000_000D, 87),   // STATUS_INVALID_PARAMETER
            (0xC000_00EF, 87),   // STATUS_INVALID_PARAMETER_1: a wait on no objects, or over 64
            (0xC000_00F1, 87),   // STATUS_INVALID_PARAMETER_3
            (0xC000_0030, 87),   // STATUS_INVALID_PARAMETER_MIX: a wait-all naming one twice
            (0xC000_009A, 1450), // STATUS_INSUFFICIENT_RESOURCES
            (0xC000_0005, 998),  // STATUS_ACCESS_VIOLATION: ERROR_NOACCESS
        ] {
            assert_eq!(dos_error(status), error, "{status:#x}");
        }
    }

    /// The statuses F2K's services return, to the errors the fixtures pin.
    #[test]
    fn the_common_statuses_map_as_on_the_platform() {
        for (status, error) in [
            (STATUS_SUCCESS, 0),
            (STATUS_TIMEOUT, 1460),
            (STATUS_PENDING, 997),
            (STATUS_UNSUCCESSFUL, 31),
            (STATUS_NOT_IMPLEMENTED, 1),
            (STATUS_ACCESS_VIOLATION, 998),
            (STATUS_INVALID_HANDLE, 6),
            (STATUS_INVALID_PARAMETER, 87),
            (STATUS_NO_MEMORY, 8),
            (STATUS_ACCESS_DENIED, 5),
            (STATUS_BUFFER_TOO_SMALL, 122),
            (STATUS_OBJECT_NAME_INVALID, 123),
            (STATUS_OBJECT_NAME_NOT_FOUND, 2),
            (STATUS_OBJECT_NAME_COLLISION, 183),
            (STATUS_OBJECT_PATH_NOT_FOUND, 3),
            (STATUS_OBJECT_PATH_SYNTAX_BAD, 161),
            (STATUS_SHARING_VIOLATION, 32),
            (STATUS_DELETE_PENDING, 5),
            (STATUS_FILE_IS_A_DIRECTORY, 5),
            (STATUS_VARIABLE_NOT_FOUND, 203),
            (STATUS_DIRECTORY_NOT_EMPTY, 145),
            (STATUS_NOT_A_DIRECTORY, 267),
            (STATUS_NAME_TOO_LONG, 206),
            (STATUS_NO_MORE_FILES, 18),
            (STATUS_BUFFER_OVERFLOW, 234),
            (STATUS_PROCEDURE_NOT_FOUND, 127),
            (STATUS_DLL_NOT_FOUND, 126),
            (STATUS_ORDINAL_NOT_FOUND, 182),
            (STATUS_ENTRYPOINT_NOT_FOUND, 127),
            (STATUS_DLL_INIT_FAILED, 1114),
        ] {
            assert_eq!(dos_error(status), error, "{status:#010x}");
        }
    }

    /// The file system services' statuses, to the errors the files and fswrite fixtures pin (and
    /// the ones they report beside those).
    #[test]
    fn the_file_statuses_map_as_the_fixtures_pin() {
        for (status, error) in [
            (STATUS_OBJECT_NAME_NOT_FOUND, 2), // a missing file
            (STATUS_NO_SUCH_FILE, 2),          // a search matching nothing
            (STATUS_OBJECT_PATH_NOT_FOUND, 3), // a missing directory, a file used as one
            (STATUS_OBJECT_NAME_INVALID, 123), // a wildcard, a trailing backslash on a file
            (STATUS_NAME_TOO_LONG, 206),
            (STATUS_FILE_IS_A_DIRECTORY, 5), // DeleteFileA of a directory
            (STATUS_CANNOT_DELETE, 5),       // DeleteFileA of a read-only file
            (STATUS_ACCESS_DENIED, 5),       // write access to a read-only file
            (STATUS_DELETE_PENDING, 5),
            (STATUS_SHARING_VIOLATION, 32),
            (STATUS_OBJECT_NAME_COLLISION, 183), /* CreateDirectoryA, MoveFileA onto an existing
                                                  * name */
            (STATUS_DIRECTORY_NOT_EMPTY, 145),
            (STATUS_NOT_A_DIRECTORY, 267), // RemoveDirectoryA of a file
            (STATUS_NO_MORE_FILES, 18),
            (STATUS_END_OF_FILE, 38),
            (STATUS_ACCESS_VIOLATION, 998), // a read into a read-only buffer
            (STATUS_INVALID_DEVICE_REQUEST, 1), // a read or write of a directory
            (STATUS_USER_MAPPED_FILE, 1224),
            (STATUS_DISK_FULL, 112),
            (STATUS_TOO_MANY_OPENED_FILES, 4),
            (STATUS_NOT_SUPPORTED, 50),
            (STATUS_INVALID_INFO_CLASS, 87),
            (STATUS_INFO_LENGTH_MISMATCH, 24),
            (0xC000_0102, 1392), // STATUS_FILE_CORRUPT_ERROR
            (0xC000_0185, 1117), // STATUS_IO_DEVICE_ERROR
        ] {
            assert_eq!(dos_error(status), error, "{status:#010x}");
        }
    }

    #[test]
    fn the_special_cases() {
        assert_eq!(
            dos_error(0xE000_0001),
            0xE000_0001,
            "a customer status is its own answer"
        );
        assert_eq!(dos_error(0xD000_0022), 5, "0xD... is 0xC...");
        assert_eq!(
            dos_error(0xC001_0005),
            5,
            "the Win32 facility carries the error"
        );
        assert_eq!(dos_error(0x8007_0057), 87);
        assert_eq!(dos_error(0xC000_7FFF), ERROR_MR_MID_NOT_FOUND);
        assert_eq!(dos_error(0x0000_0000), 0);
        assert!(nt_success(STATUS_TIMEOUT) && nt_success(STATUS_OBJECT_NAME_EXISTS));
        assert!(!nt_success(STATUS_BUFFER_OVERFLOW) && !nt_success(STATUS_ACCESS_DENIED));
    }

    /// The severity bits, and the NT_SUCCESS, NT_INFORMATION, NT_WARNING and NT_ERROR rules.
    #[test]
    fn the_severities() {
        for (status, severity, success) in [
            (STATUS_SUCCESS, Severity::Success, true),
            (STATUS_TIMEOUT, Severity::Success, true),
            (STATUS_OBJECT_NAME_EXISTS, Severity::Informational, true),
            (STATUS_NO_YIELD_PERFORMED, Severity::Informational, true),
            (STATUS_BUFFER_OVERFLOW, Severity::Warning, false),
            (STATUS_PARTIAL_COPY, Severity::Warning, false),
            (STATUS_ACCESS_DENIED, Severity::Error, false),
            (0xE000_0001, Severity::Error, false),
        ] {
            let status = NtStatus(status);
            assert_eq!(status.severity(), severity, "{status:?}");
            assert_eq!(status.is_success(), success, "{status:?}");
            assert_eq!(status.is_success(), nt_success(status.0), "{status:?}");
            assert_eq!(status.is_information(), severity == Severity::Informational);
            assert_eq!(status.is_warning(), severity == Severity::Warning);
            assert_eq!(status.is_error(), severity == Severity::Error);
        }
    }

    #[test]
    fn a_status_debugs_as_hex() {
        assert_eq!(
            format!("{:?}", NtStatus(STATUS_ACCESS_VIOLATION)),
            "NtStatus(0xc0000005)"
        );
        assert_eq!(
            format!("{:?}", NtStatus(STATUS_SUCCESS)),
            "NtStatus(0x00000000)"
        );
    }

    /// The table's runs are ordered and disjoint (the lookup's binary search relies on it).
    #[test]
    fn the_runs_are_ordered() {
        for pair in RANGES.windows(2) {
            assert!(
                pair[0].0 + u32::from(pair[0].1) <= pair[1].0,
                "{:#x}",
                pair[1].0
            );
        }
        let (_, count, offset) = RANGES[RANGES.len() - 1];
        assert_eq!(usize::from(offset) + usize::from(count), ERRORS.len());
    }
}
