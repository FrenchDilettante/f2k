//! The SID's field pointers, its length, its copy and its prefix comparison:
//! GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, GetSidLengthRequired,
//! CopySid and EqualPrefixSid, each over ntdll's Rtl* helper through the [`super::services`] seam.
//! The field pointers answer with the last error ERROR_SUCCESS; the length leaves it alone; a
//! failed copy maps its status to the last error (ERROR_INSUFFICIENT_BUFFER when the buffer is too
//! small) and answers FALSE.

// ERROR_INVALID_PARAMETER: a null argument to the copy.
use rtl::winerror::ERROR_INVALID_PARAMETER;

use super::services;
use crate::imports::{self as nt};
use crate::token::failed;

/// GetSidIdentifierAuthority: the address of the SID's identifier authority; the last error
/// ERROR_SUCCESS.
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_GetSidIdentifierAuthority")]
pub unsafe extern "system" fn get_sid_identifier_authority(sid: *const u8) -> usize {
    nt::set_last_error(0);
    if sid.is_null() {
        return 0;
    }
    services::identifier_authority_sid(sid)
}

/// GetSidSubAuthority: the address of the SID's `index`'th sub-authority (the index is not
/// checked against the count); the last error ERROR_SUCCESS.
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_GetSidSubAuthority")]
pub unsafe extern "system" fn get_sid_sub_authority(sid: *const u8, index: u32) -> usize {
    nt::set_last_error(0);
    if sid.is_null() {
        return 0;
    }
    services::sub_authority_sid(sid, index)
}

/// GetSidSubAuthorityCount: the address of the SID's sub-authority count; the last error
/// ERROR_SUCCESS.
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_GetSidSubAuthorityCount")]
pub unsafe extern "system" fn get_sid_sub_authority_count(sid: *const u8) -> usize {
    nt::set_last_error(0);
    if sid.is_null() {
        return 0;
    }
    services::sub_authority_count_sid(sid)
}

/// GetSidLengthRequired: the bytes a SID of `count` sub-authorities takes; the last error
/// untouched.
#[unsafe(export_name = "f2k_export_GetSidLengthRequired")]
pub unsafe extern "system" fn get_sid_length_required(count: u32) -> u32 {
    services::length_required_sid(count & 0xFF)
}

/// CopySid: the source SID copied into the destination buffer of `length` bytes: FALSE with the
/// copy's status as the last error (ERROR_INSUFFICIENT_BUFFER when the buffer is too small)
/// when it does not fit, TRUE with the last error untouched when it does.
///
/// # Safety
///
/// `destination` is a buffer of `length` bytes the call may write; `source` a SID it may read.
#[unsafe(export_name = "f2k_export_CopySid")]
pub unsafe extern "system" fn copy_sid(
    length: u32,
    destination: *mut u8,
    source: *const u8,
) -> u32 {
    if source.is_null() || destination.is_null() {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    match services::copy_sid(length, destination, source).ok() {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// EqualPrefixSid: whether the two SIDs are equal except for the last sub-authority; the last
/// error ERROR_SUCCESS whatever the answer.
///
/// # Safety
///
/// `sid1` and `sid2` are SIDs the call may read.
#[unsafe(export_name = "f2k_export_EqualPrefixSid")]
pub unsafe extern "system" fn equal_prefix_sid(sid1: *const u8, sid2: *const u8) -> u32 {
    nt::set_last_error(0);
    if sid1.is_null() || sid2.is_null() {
        return 0;
    }
    services::equal_prefix_sid(sid1, sid2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// The SID of `authority` and `subs`: S-1-<authority>-<subs...>.
    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// GetSidIdentifierAuthority, GetSidSubAuthority and GetSidSubAuthorityCount answer the
    /// field's address inside the SID with the last error ERROR_SUCCESS; GetSidLengthRequired
    /// answers 8 + 4*count and leaves the last error alone.
    #[test]
    fn the_part_pointers_and_the_length_answer() {
        let admins = sid(5, &[32, 544]);
        arm();
        let authority = unsafe { get_sid_identifier_authority(admins.as_ptr()) };
        assert_eq!((authority, last_error()), (admins.as_ptr() as usize + 2, 0));
        arm();
        let sub = unsafe { get_sid_sub_authority(admins.as_ptr(), 1) };
        assert_eq!((sub, last_error()), (admins.as_ptr() as usize + 12, 0));
        // SAFETY: the sub-authority pointer the call answered.
        assert_eq!(unsafe { (sub as *const u32).read_unaligned() }, 544);
        arm();
        let count = unsafe { get_sid_sub_authority_count(admins.as_ptr()) };
        assert_eq!((count, last_error()), (admins.as_ptr() as usize + 1, 0));
        // SAFETY: the count pointer the call answered.
        assert_eq!(unsafe { (count as *const u8).read_unaligned() }, 2);
        arm();
        assert_eq!(unsafe { get_sid_length_required(2) }, 16);
        assert_eq!(last_error(), 0xF2F2, "the length leaves the last error");
        assert_eq!(unsafe { get_sid_length_required(0) }, 8);
        arm();
        assert_eq!(
            unsafe { get_sid_identifier_authority(core::ptr::null()) },
            0
        );
        assert_eq!(last_error(), 0);
    }

    /// CopySid copies the whole SID into a roomy buffer (the last error untouched), answers
    /// FALSE with ERROR_INSUFFICIENT_BUFFER (122) when the buffer is too small, and
    /// ERROR_INVALID_PARAMETER (87) for a null source or destination.
    #[test]
    fn copy_sid_copies_or_asks_for_room() {
        let admins = sid(5, &[32, 544]);
        let mut buffer = [0xCCu8; 256];
        arm();
        let ok = unsafe { copy_sid(256, buffer.as_mut_ptr(), admins.as_ptr()) };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        assert_eq!(&buffer[..16], &admins[..]);
        arm();
        let ok = unsafe { copy_sid(4, buffer.as_mut_ptr(), admins.as_ptr()) };
        assert_eq!((ok, last_error()), (0, 122));
        arm();
        let ok = unsafe { copy_sid(256, buffer.as_mut_ptr(), core::ptr::null()) };
        assert_eq!((ok, last_error()), (0, 87));
        let ok = unsafe { copy_sid(256, core::ptr::null_mut(), admins.as_ptr()) };
        assert_eq!((ok, last_error()), (0, 87));
    }

    /// EqualPrefixSid answers whether the two SIDs share all but the last sub-authority, with
    /// the last error ERROR_SUCCESS either way: a prefix of the SID is not equal to it, the SID
    /// is equal to itself, and two SIDs differing only in the last sub-authority share a prefix.
    #[test]
    fn equal_prefix_compares_all_but_the_last() {
        let admins = sid(5, &[32, 544]);
        let users = sid(5, &[32, 545]);
        let builtin = sid(5, &[32]);
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(admins.as_ptr(), builtin.as_ptr()) },
                last_error()
            ),
            (0, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(builtin.as_ptr(), admins.as_ptr()) },
                last_error()
            ),
            (0, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(admins.as_ptr(), admins.as_ptr()) },
                last_error()
            ),
            (1, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(admins.as_ptr(), users.as_ptr()) },
                last_error()
            ),
            (1, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(admins.as_ptr(), sid(1, &[0]).as_ptr()) },
                last_error()
            ),
            (0, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { equal_prefix_sid(admins.as_ptr(), core::ptr::null()) },
                last_error()
            ),
            (0, 0)
        );
    }
}
