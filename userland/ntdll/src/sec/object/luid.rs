//! The impersonation no-op and the LUID helpers: the trivial 8-byte copies and compares.

use super::*;

// --- Impersonation and the LUID helpers --------------------------------------------------------

/// RtlImpersonateSelf: F2K's threads never impersonate, so the call succeeds and changes
/// nothing.
#[unsafe(export_name = "f2k_export_RtlImpersonateSelf")]
pub unsafe extern "system" fn rtl_impersonate_self(_impersonation_level: u32) -> u32 {
    STATUS_SUCCESS
}

/// The 8 bytes of the LUID at `source` into `destination`.
pub(crate) fn copy_luid(destination: *mut u8, source: *const u8) {
    // SAFETY: both are the caller's 8-byte LUIDs, writable and readable for the call.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, 8) };
}

/// RtlCopyLuid: the LUID at `source_luid` copied to `destination_luid`.
#[unsafe(export_name = "f2k_export_RtlCopyLuid")]
pub unsafe extern "system" fn rtl_copy_luid(destination_luid: *mut u8, source_luid: *const u8) {
    copy_luid(destination_luid, source_luid);
}

/// RtlEqualLuid: whether the LUIDs at `luid1` and `luid2` are the same 8 bytes.
#[unsafe(export_name = "f2k_export_RtlEqualLuid")]
pub unsafe extern "system" fn rtl_equal_luid(luid1: *const u8, luid2: *const u8) -> u32 {
    u32::from(
        dword(luid1) == dword(luid2)
            && dword(luid1.wrapping_add(4)) == dword(luid2.wrapping_add(4)),
    )
}

/// RtlCopyLuidAndAttributesArray: `count` LUID_AND_ATTRIBUTES (an 8-byte LUID then a dword of
/// attributes, 12 bytes each) from `source` to `destination`.
#[unsafe(export_name = "f2k_export_RtlCopyLuidAndAttributesArray")]
pub unsafe extern "system" fn rtl_copy_luid_and_attributes_array(
    count: u32,
    source: *const u8,
    destination: *mut u8,
) {
    // SAFETY: the caller's arrays hold `count` elements of 12 bytes, non-overlapping.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, count as usize * 12) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impersonation_is_a_successful_no_op() {
        assert_eq!(unsafe { rtl_impersonate_self(2) }, STATUS_SUCCESS);
        assert_eq!(unsafe { rtl_impersonate_self(0) }, STATUS_SUCCESS);
    }

    #[test]
    fn the_luid_helpers_copy_and_compare_eight_bytes() {
        let source = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut destination = [0u8; 8];
        unsafe { rtl_copy_luid(destination.as_mut_ptr(), source.as_ptr()) };
        assert_eq!(destination, source);
        assert_eq!(
            unsafe { rtl_equal_luid(source.as_ptr(), destination.as_ptr()) },
            1
        );
        let other = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89];
        assert_eq!(
            unsafe { rtl_equal_luid(source.as_ptr(), other.as_ptr()) },
            0
        );
        let low_differs = [0x12, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(
            unsafe { rtl_equal_luid(source.as_ptr(), low_differs.as_ptr()) },
            0
        );
        // An array of LUID_AND_ATTRIBUTES: 12 bytes per element, count zero copies nothing.
        let mut source_array = [0u8; 36];
        for (index, byte) in source_array.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut destination_array = [0xFFu8; 36];
        unsafe {
            rtl_copy_luid_and_attributes_array(
                3,
                source_array.as_ptr(),
                destination_array.as_mut_ptr(),
            )
        };
        assert_eq!(destination_array, source_array);
        let mut untouched = [0xEEu8; 12];
        unsafe {
            rtl_copy_luid_and_attributes_array(0, source_array.as_ptr(), untouched.as_mut_ptr())
        };
        assert_eq!(untouched, [0xEEu8; 12]);
    }
}
