//! NT status codes: the documented NTSTATUS values the kernel's internal APIs report.
//!
//! A status is a signed 32-bit value whose top two bits are the severity: success and
//! informational codes are non-negative, warnings and errors negative. Only the codes the kernel
//! produces are defined here. The user boundary's raw exception codes (`user::syscall`) are written
//! straight into user registers as unsigned values and stay with it.

/// An NTSTATUS value.
pub type NtStatus = i32;

/// The operation completed.
pub const STATUS_SUCCESS: NtStatus = 0x0000_0000;
/// A wait's timeout elapsed first. The Win32 wait returns this value raw (`WAIT_TIMEOUT`).
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
/// A wait broken so a kernel APC could be delivered. The wait replays; the APC machinery reports
/// this to itself, never to a caller.
pub const STATUS_KERNEL_APC: NtStatus = 0x0000_0100;
/// A wait broken so a user APC could be delivered. The user-mode APC delivery does not exist yet
/// (the runtime layer that would receive the APC arrives with the real-DLL pivot); the queue and
/// this status are armed data, and no code path produces it.
pub const STATUS_USER_APC: NtStatus = 0x0000_00C0;
/// A wait took a mutex its previous owner ended holding: the wait succeeded, and the protected
/// state may be inconsistent. OR'd with the satisfying index (`WAIT_ABANDONED_0 + n`).
pub const STATUS_ABANDONED: NtStatus = 0x0000_0080;
/// A parameter is out of range (a block read past the device's end).
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as NtStatus;
/// No such device (no usable disk where one was asked for).
pub const STATUS_NO_SUCH_DEVICE: NtStatus = 0xC000_000Eu32 as NtStatus;
/// No such file: a path component names no entry of its directory.
pub const STATUS_NO_SUCH_FILE: NtStatus = 0xC000_000Fu32 as NtStatus;
/// The caller's buffer cannot hold the data (a file read into less than the file's size).
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as NtStatus;
/// The name is malformed (an empty path or component, or a component that is not an 8.3 name).
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033u32 as NtStatus;
/// The file's on-volume structure is corrupt (a broken cluster chain or directory).
pub const STATUS_FILE_CORRUPT_ERROR: NtStatus = 0xC000_0102u32 as NtStatus;
/// A path continues through something that is not a directory.
pub const STATUS_NOT_A_DIRECTORY: NtStatus = 0xC000_0103u32 as NtStatus;
/// A device did not respond in time.
pub const STATUS_IO_TIMEOUT: NtStatus = 0xC000_00B5u32 as NtStatus;
/// A device reported an error.
pub const STATUS_IO_DEVICE_ERROR: NtStatus = 0xC000_0185u32 as NtStatus;
/// The volume holds no file system the kernel recognizes (a refused mount).
pub const STATUS_UNRECOGNIZED_VOLUME: NtStatus = 0xC000_014Fu32 as NtStatus;
/// A thread's suspend count is at its documented maximum (127).
pub const STATUS_SUSPEND_COUNT_EXCEEDED: NtStatus = 0xC000_004Au32 as NtStatus;
/// A semaphore release would push the count past its limit.
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = 0xC000_0047u32 as NtStatus;
/// A mutex release by a thread that does not own it.
pub const STATUS_MUTANT_NOT_OWNED: NtStatus = 0xC000_0046u32 as NtStatus;
/// The thread is terminating; operations that would queue work on it are refused.
pub const STATUS_THREAD_IS_TERMINATING: NtStatus = 0xC000_004Bu32 as NtStatus;

/// Whether a status reports success (the non-negative severities: success and informational).
pub fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented values, and their severity: success and the timeout are non-negative
    /// (success and informational), the I/O failures are errors.
    #[test]
    fn the_documented_values_and_their_severity() {
        assert_eq!(STATUS_SUCCESS as u32, 0x0000_0000);
        assert_eq!(STATUS_TIMEOUT as u32, 0x0000_0102);
        assert_eq!(STATUS_KERNEL_APC as u32, 0x0000_0100);
        assert_eq!(STATUS_USER_APC as u32, 0x0000_00C0);
        assert_eq!(STATUS_SUSPEND_COUNT_EXCEEDED as u32, 0xC000_004A);
        assert_eq!(STATUS_SEMAPHORE_LIMIT_EXCEEDED as u32, 0xC000_0047);
        assert_eq!(STATUS_THREAD_IS_TERMINATING as u32, 0xC000_004B);
        assert_eq!(STATUS_INVALID_PARAMETER as u32, 0xC000_000D);
        assert_eq!(STATUS_NO_SUCH_DEVICE as u32, 0xC000_000E);
        assert_eq!(STATUS_IO_TIMEOUT as u32, 0xC000_00B5);
        assert_eq!(STATUS_IO_DEVICE_ERROR as u32, 0xC000_0185);
        assert_eq!(STATUS_UNRECOGNIZED_VOLUME as u32, 0xC000_014F);
        assert_eq!(STATUS_NO_SUCH_FILE as u32, 0xC000_000F);
        assert_eq!(STATUS_BUFFER_TOO_SMALL as u32, 0xC000_0023);
        assert_eq!(STATUS_OBJECT_NAME_INVALID as u32, 0xC000_0033);
        assert_eq!(STATUS_FILE_CORRUPT_ERROR as u32, 0xC000_0102);
        assert_eq!(STATUS_NOT_A_DIRECTORY as u32, 0xC000_0103);

        assert!(nt_success(STATUS_SUCCESS));
        assert!(nt_success(STATUS_TIMEOUT));
        for status in [
            STATUS_INVALID_PARAMETER,
            STATUS_NO_SUCH_DEVICE,
            STATUS_IO_TIMEOUT,
            STATUS_IO_DEVICE_ERROR,
            STATUS_UNRECOGNIZED_VOLUME,
            STATUS_NO_SUCH_FILE,
            STATUS_BUFFER_TOO_SMALL,
            STATUS_OBJECT_NAME_INVALID,
            STATUS_FILE_CORRUPT_ERROR,
            STATUS_NOT_A_DIRECTORY,
        ] {
            assert!(!nt_success(status), "{:#010x} is an error", status as u32);
        }
    }
}
