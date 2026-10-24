//! The time conversions (`rtl::time`): a time (100 ns units since 1601) to its TIME_FIELDS and
//! back, kernel32's FileTimeToSystemTime and SystemTimeToFileTime's work, as on Windows 2000.

use rtl::time::{self, TimeFields};

/// RtlTimeToTimeFields: the time's civil fields, its day of the week with them.
///
/// # Safety
///
/// `time` points at a LARGE_INTEGER, `fields` at a writable TIME_FIELDS.
#[unsafe(export_name = "f2k_export_RtlTimeToTimeFields")]
pub unsafe extern "system" fn rtl_time_to_time_fields(time: *const i64, fields: *mut TimeFields) {
    // SAFETY: the caller's contract.
    unsafe { fields.write_unaligned(time::time_to_time_fields(time.read_unaligned())) };
}

/// RtlTimeFieldsToTime: the time of the civil fields (the weekday not consulted); FALSE, nothing
/// written, for a field out of its range.
///
/// # Safety
///
/// `fields` points at a TIME_FIELDS, `time` at a writable LARGE_INTEGER.
#[unsafe(export_name = "f2k_export_RtlTimeFieldsToTime")]
pub unsafe extern "system" fn rtl_time_fields_to_time(
    fields: *const TimeFields,
    time: *mut i64,
) -> u32 {
    // SAFETY: the caller's contract.
    match time::time_fields_to_time(unsafe { &fields.read_unaligned() }) {
        Some(converted) => {
            // SAFETY: as above.
            unsafe { time.write_unaligned(converted) };
            1
        }
        None => 0,
    }
}
