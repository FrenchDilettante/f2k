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
/// A parameter is out of range (a block read past the device's end).
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as NtStatus;
/// No such device (no usable disk where one was asked for).
pub const STATUS_NO_SUCH_DEVICE: NtStatus = 0xC000_000Eu32 as NtStatus;
/// A device did not respond in time.
pub const STATUS_IO_TIMEOUT: NtStatus = 0xC000_00B5u32 as NtStatus;
/// A device reported an error.
pub const STATUS_IO_DEVICE_ERROR: NtStatus = 0xC000_0185u32 as NtStatus;

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
        assert_eq!(STATUS_INVALID_PARAMETER as u32, 0xC000_000D);
        assert_eq!(STATUS_NO_SUCH_DEVICE as u32, 0xC000_000E);
        assert_eq!(STATUS_IO_TIMEOUT as u32, 0xC000_00B5);
        assert_eq!(STATUS_IO_DEVICE_ERROR as u32, 0xC000_0185);

        assert!(nt_success(STATUS_SUCCESS));
        assert!(nt_success(STATUS_TIMEOUT));
        for status in [
            STATUS_INVALID_PARAMETER,
            STATUS_NO_SUCH_DEVICE,
            STATUS_IO_TIMEOUT,
            STATUS_IO_DEVICE_ERROR,
        ] {
            assert!(!nt_success(status), "{:#010x} is an error", status as u32);
        }
    }
}
