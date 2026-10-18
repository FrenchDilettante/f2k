//! The status-to-error mapping kernel32 reports every failed system service through.

use rtl::sys;

/// RtlNtStatusToDosError: the Win32 error `status` maps to ([`rtl::status::dos_error`]), the status
/// kept as the calling thread's last status (TEB LastStatusValue), as Windows 2000's does.
#[unsafe(export_name = "f2k_export_RtlNtStatusToDosError")]
extern "system" fn rtl_nt_status_to_dos_error(status: u32) -> u32 {
    sys::set_last_status(status);
    rtl::status::dos_error(status)
}
