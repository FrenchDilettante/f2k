//! The ACL-entry calls: GetExplicitEntriesFromAcl and SetEntriesInAcl, A and W. The first walks
//! an ACL's ACEs into the caller's EXPLICIT_ACCESS array (the count argument holds the array's
//! capacity on entry, the entries found on return); the second builds a new heap ACL from an
//! entries array merged with the old ACL — a NULL entries array leaves only the old ACL's
//! inherited ACEs, the inherited ACL restored — and hands its address out for the caller to
//! free. Both return NO_ERROR, or the error, which is also set as the last error.

use rtl::status::NtStatus;
use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

use super::{
    ace_count,
    caller_sid,
    dword,
    entry_at,
    fail,
    read_trustee,
    services,
    sid_offset,
    word,
    ExplicitAccess,
    Trustee,
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE,
    ACL_REVISION,
    DENY_ACCESS,
    ENTRY_SIZE,
    ERROR_INVALID_ACL,
    ERROR_NONE_MAPPED,
    FAILED_ACCESS_ACE_FLAG,
    GRANT_ACCESS,
    IMPERSONATION,
    INHERITED_ACE,
    NO_MULTIPLE_TRUSTEE,
    REVOKE_ACCESS,
    SET_ACCESS,
    SET_AUDIT_FAILURE,
    SET_AUDIT_SUCCESS,
    SUCCESSFUL_ACCESS_ACE_FLAG,
    SYSTEM_AUDIT_ACE_TYPE,
    TRUSTEE_IS_NAME,
    TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN,
};
use crate::imports::{self as nt, HeapBlock};
use crate::Out;

/// The SID a trustee names: its name pointer for the SID form, the multiple trustee's for an
/// impersonation one. A name form is ERROR_NONE_MAPPED (F2K resolves no account names), any
/// other form ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// The trustee is the caller's, and so is any trustee it points at.
unsafe fn trustee_sid(trustee: &Trustee) -> Result<*const u8, u32> {
    if trustee.multiple_trustee_operation == IMPERSONATION && trustee.p_multiple_trustee != 0 {
        // SAFETY: the caller's multiple trustee.
        let source = unsafe { read_trustee(trustee.p_multiple_trustee as *const u8) };
        // SAFETY: as above.
        return unsafe { trustee_sid(&source) };
    }
    match trustee.trustee_form {
        TRUSTEE_IS_SID if trustee.ptstr_name != 0 => Ok(trustee.ptstr_name as *const u8),
        TRUSTEE_IS_NAME => Err(ERROR_NONE_MAPPED),
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

/// GetExplicitEntriesFromAcl's body (the A and W forms share it: the SID a trustee points at is
/// the same memory either way): the ACL's ACEs walked into the caller's array.
///
/// # Safety
///
/// The pointers are the caller's: the ACL, the count in/out and the entries array of the
/// capacity it holds on entry.
unsafe fn explicit_entries_from_acl(p_acl: *const u8, pc_count: *mut u32, p_list: *mut u8) -> u32 {
    // SAFETY: the caller's place for the count.
    let place = unsafe { Out::optional(pc_count) };
    let Some(mut count) = place else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    if p_acl.is_null() || !services::valid_acl(p_acl) {
        return fail(ERROR_INVALID_ACL);
    }
    let found = match ace_count(p_acl) {
        Ok(count) => count,
        Err(status) => return fail(nt::dos_error(status)),
    };
    let capacity = count.get();
    count.set(found);
    if found > capacity {
        return fail(ERROR_INSUFFICIENT_BUFFER);
    }
    for index in 0..found {
        let ace = match services::get_ace(p_acl, index) {
            Ok(ace) => ace,
            Err(status) => return fail(nt::dos_error(status)),
        };
        // SAFETY: the ACE is inside the caller's ACL.
        let ace_type = unsafe { *ace };
        let ace_flags = unsafe { *ace.add(1) };
        let mode = match ace_type {
            ACCESS_DENIED_ACE_TYPE | 6 => DENY_ACCESS,
            SYSTEM_AUDIT_ACE_TYPE | 7 | 3 | 8 => {
                if ace_flags & FAILED_ACCESS_ACE_FLAG != 0 {
                    SET_AUDIT_FAILURE
                } else {
                    SET_AUDIT_SUCCESS
                }
            }
            _ => GRANT_ACCESS,
        };
        // SAFETY: the SID is inside the ACE, at its type's offset.
        let sid = unsafe { ace.add(sid_offset(ace_type, ace)) };
        let entry = ExplicitAccess {
            grf_access_permissions: dword(unsafe { ace.add(4) }),
            grf_access_mode: mode,
            grf_inheritance: u32::from(ace_flags),
            trustee: Trustee {
                p_multiple_trustee: 0,
                multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                trustee_form: TRUSTEE_IS_SID,
                trustee_type: TRUSTEE_IS_UNKNOWN,
                ptstr_name: sid as usize,
            },
        };
        // SAFETY: the caller's array, this entry's place written unaligned.
        unsafe {
            (p_list.add(index as usize * ENTRY_SIZE) as *mut ExplicitAccess).write_unaligned(entry)
        };
    }
    rtl::status::STATUS_SUCCESS
}

/// Remove every ACE of the ACL whose SID is `sid`.
fn remove_for(acl: *mut u8, sid: *const u8) -> Result<(), NtStatus> {
    let mut index = ace_count(acl)?;
    while index > 0 {
        index -= 1;
        let ace = services::get_ace(acl, index)?;
        // SAFETY: the ACE's type and SID are inside the ACL.
        let ace_sid = unsafe { ace.add(sid_offset(*ace, ace)) };
        if services::equal_sid(ace_sid, sid) {
            services::delete_ace(acl, index)?;
        }
    }
    Ok(())
}

/// An entry's ACE, built in `buffer`: header, mask, the SID.
fn entry_ace<'a>(
    mode: u32,
    inheritance: u32,
    mask: u32,
    sid: &[u8],
    buffer: &'a mut [u8; 128],
) -> &'a [u8] {
    let (ace_type, flags) = match mode {
        DENY_ACCESS => (ACCESS_DENIED_ACE_TYPE, inheritance),
        SET_AUDIT_SUCCESS => (
            SYSTEM_AUDIT_ACE_TYPE,
            inheritance | u32::from(SUCCESSFUL_ACCESS_ACE_FLAG),
        ),
        SET_AUDIT_FAILURE => (
            SYSTEM_AUDIT_ACE_TYPE,
            inheritance | u32::from(FAILED_ACCESS_ACE_FLAG),
        ),
        _ => (ACCESS_ALLOWED_ACE_TYPE, inheritance),
    };
    let size = 8 + sid.len();
    buffer[0] = ace_type;
    buffer[1] = flags as u8;
    buffer[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    buffer[4..8].copy_from_slice(&mask.to_le_bytes());
    buffer[8..size].copy_from_slice(sid);
    &buffer[..size]
}

/// SetEntriesInAcl's body (the A and W forms share it): a new heap ACL built from the entries
/// merged with the old ACL, its address handed out. A NULL entries array leaves only the old
/// ACL's inherited ACEs.
///
/// # Safety
///
/// The pointers are the caller's: the entries array of `count` entries, the old ACL (or null),
/// and the place for the new ACL's address (the caller frees it).
unsafe fn set_entries_in_acl(
    count: u32,
    p_entries: *const u8,
    p_old_acl: *const u8,
    p_new_acl: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's place for the new ACL's address.
    let place = unsafe { Out::optional(p_new_acl) };
    let Some(mut new_acl) = place else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    if count > 0 && p_entries.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // The old ACL, when given: it must be valid; its revision and size size the new one.
    let (old_revision, old_size) = if p_old_acl.is_null() {
        (ACL_REVISION, 0)
    } else {
        if !services::valid_acl(p_old_acl) {
            return fail(ERROR_INVALID_ACL);
        }
        // SAFETY: the caller's ACL header.
        (
            u32::from(unsafe { *p_old_acl }),
            usize::from(word(unsafe { p_old_acl.add(2) })),
        )
    };
    // Size the new ACL first: the old one's room plus each entry's ACE (header, mask, SID).
    let mut size = old_size.max(8) + 8;
    for index in 0..count as usize {
        // SAFETY: the caller's entries array.
        let entry = unsafe { entry_at(p_entries, index) };
        // SAFETY: the entry's trustee is the caller's.
        let sid = match unsafe { trustee_sid(&entry.trustee) } {
            Ok(sid) => sid,
            Err(error) => return fail(error),
        };
        // SAFETY: the trustee's SID.
        let place = unsafe { caller_sid(sid) };
        let Some(sid) = place else {
            return fail(ERROR_INVALID_PARAMETER);
        };
        size += 8 + sid.len();
    }
    let Some(mut block) = HeapBlock::new(size) else {
        return fail(ERROR_NOT_ENOUGH_MEMORY);
    };
    let acl = block.bytes_mut().as_mut_ptr();
    if let Err(status) = services::create_acl(acl, size as u32, old_revision) {
        return fail(nt::dos_error(status));
    }
    // The old ACL's ACEs come first: all of them, or only the inherited ones when the entries
    // array is NULL (the inherited ACL restored).
    if !p_old_acl.is_null() {
        let inherited_only = p_entries.is_null();
        let old_count = match ace_count(p_old_acl) {
            Ok(count) => count,
            Err(status) => return fail(nt::dos_error(status)),
        };
        for index in 0..old_count {
            let ace = match services::get_ace(p_old_acl, index) {
                Ok(ace) => ace,
                Err(status) => return fail(nt::dos_error(status)),
            };
            // SAFETY: the ACE's flags and size are inside the old ACL.
            let flags = unsafe { *ace.add(1) };
            if inherited_only && flags & INHERITED_ACE == 0 {
                continue;
            }
            let ace_size = usize::from(word(unsafe { ace.add(2) }));
            if let Err(status) = services::add_ace(acl, old_revision, ace, ace_size as u32) {
                return fail(nt::dos_error(status));
            }
        }
    }
    // Each entry, in order: SET_ACCESS and REVOKE_ACCESS first drop the trustee's ACEs, the
    // rest then append the entry's own ACE.
    let mut buffer = [0u8; 128];
    for index in 0..count as usize {
        // SAFETY: as above.
        let entry = unsafe { entry_at(p_entries, index) };
        // SAFETY: as above.
        let sid = match unsafe { trustee_sid(&entry.trustee) } {
            Ok(sid) => sid,
            Err(error) => return fail(error),
        };
        // SAFETY: as above.
        let place = unsafe { caller_sid(sid) };
        let Some(sid_bytes) = place else {
            return fail(ERROR_INVALID_PARAMETER);
        };
        match entry.grf_access_mode {
            REVOKE_ACCESS => {
                if let Err(status) = remove_for(acl, sid) {
                    return fail(nt::dos_error(status));
                }
            }
            SET_ACCESS | GRANT_ACCESS | DENY_ACCESS | SET_AUDIT_SUCCESS | SET_AUDIT_FAILURE => {
                if entry.grf_access_mode == SET_ACCESS {
                    if let Err(status) = remove_for(acl, sid) {
                        return fail(nt::dos_error(status));
                    }
                }
                let ace = entry_ace(
                    entry.grf_access_mode,
                    entry.grf_inheritance,
                    entry.grf_access_permissions,
                    sid_bytes,
                    &mut buffer,
                );
                if let Err(status) =
                    services::add_ace(acl, old_revision, ace.as_ptr(), ace.len() as u32)
                {
                    return fail(nt::dos_error(status));
                }
            }
            _ => {}
        }
    }
    new_acl.set(acl);
    // The caller owns the new ACL now (freed with LocalFree); the block must not free it here.
    core::mem::forget(block);
    rtl::status::STATUS_SUCCESS
}

/// GetExplicitEntriesFromAclA: the ACL's ACEs as EXPLICIT_ACCESS entries; the count holds the
/// array's capacity on entry, the entries found on return. NO_ERROR, or the error (also the
/// last error): ERROR_INVALID_ACL for what is not an ACL, ERROR_INSUFFICIENT_BUFFER for an
/// array smaller than the ACE count.
///
/// # Safety
///
/// The pointers are the caller's, as [`explicit_entries_from_acl`]'s.
#[unsafe(export_name = "f2k_export_GetExplicitEntriesFromAclA")]
pub unsafe extern "system" fn get_explicit_entries_from_acl_a(
    p_acl: *const u8,
    pc_count_of_explicit_entries: *mut u32,
    p_list_of_explicit_entries: *mut u8,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        explicit_entries_from_acl(
            p_acl,
            pc_count_of_explicit_entries,
            p_list_of_explicit_entries,
        )
    }
}

/// GetExplicitEntriesFromAclW: the A form's body, the entries the same.
///
/// # Safety
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetExplicitEntriesFromAclW")]
pub unsafe extern "system" fn get_explicit_entries_from_acl_w(
    p_acl: *const u8,
    pc_count_of_explicit_entries: *mut u32,
    p_list_of_explicit_entries: *mut u8,
) -> u32 {
    // SAFETY: as the A form's.
    unsafe {
        explicit_entries_from_acl(
            p_acl,
            pc_count_of_explicit_entries,
            p_list_of_explicit_entries,
        )
    }
}

/// SetEntriesInAclA: a new ACL built from the entries merged with the old one, its address into
/// `new_acl` (the caller frees it). NO_ERROR, or the error (also the last error).
///
/// # Safety
///
/// The pointers are the caller's, as [`set_entries_in_acl`]'s.
#[unsafe(export_name = "f2k_export_SetEntriesInAclA")]
pub unsafe extern "system" fn set_entries_in_acl_a(
    c_count_of_explicit_entries: u32,
    p_list_of_explicit_entries: *const u8,
    p_old_acl: *const u8,
    p_new_acl: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        set_entries_in_acl(
            c_count_of_explicit_entries,
            p_list_of_explicit_entries,
            p_old_acl,
            p_new_acl,
        )
    }
}

/// SetEntriesInAclW: the A form's body, the entries the same.
///
/// # Safety
/// As the A form's.
#[unsafe(export_name = "f2k_export_SetEntriesInAclW")]
pub unsafe extern "system" fn set_entries_in_acl_w(
    c_count_of_explicit_entries: u32,
    p_list_of_explicit_entries: *const u8,
    p_old_acl: *const u8,
    p_new_acl: *mut *mut u8,
) -> u32 {
    // SAFETY: as the A form's.
    unsafe {
        set_entries_in_acl(
            c_count_of_explicit_entries,
            p_list_of_explicit_entries,
            p_old_acl,
            p_new_acl,
        )
    }
}

#[cfg(test)]
mod tests {
    use rtl::heap::ProcessHeap as _;
    use rtl::status::STATUS_SUCCESS;
    use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER};

    use super::*;
    use crate::explicit::tests_support::{ace_of, count_of, make_acl, sid};
    use crate::explicit::{
        ACCESS_ALLOWED_ACE_TYPE,
        DENY_ACCESS,
        ERROR_INVALID_ACL,
        ERROR_NONE_MAPPED,
        GRANT_ACCESS,
        NO_MULTIPLE_TRUSTEE,
        REVOKE_ACCESS,
        SET_ACCESS,
        SET_AUDIT_SUCCESS,
        TRUSTEE_IS_NAME,
        TRUSTEE_IS_SID,
        TRUSTEE_IS_UNKNOWN,
    };
    use crate::imports::ProcessHeap;
    use crate::testkit::{arm, last_error};

    /// An EXPLICIT_ACCESS in a test's buffer, for a SID-form trustee.
    fn entry_for(sid: &[u8], mode: u32, mask: u32, inheritance: u32) -> ExplicitAccess {
        ExplicitAccess {
            grf_access_permissions: mask,
            grf_access_mode: mode,
            grf_inheritance: inheritance,
            trustee: Trustee {
                p_multiple_trustee: 0,
                multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                trustee_form: TRUSTEE_IS_SID,
                trustee_type: TRUSTEE_IS_UNKNOWN,
                ptstr_name: sid.as_ptr() as usize,
            },
        }
    }

    fn zeroed_entry() -> ExplicitAccess {
        ExplicitAccess {
            grf_access_permissions: 0xCC,
            grf_access_mode: 0xCC,
            grf_inheritance: 0xCC,
            trustee: Trustee {
                p_multiple_trustee: 0xCC,
                multiple_trustee_operation: 0xCC,
                trustee_form: 0xCC,
                trustee_type: 0xCC,
                ptstr_name: 0xCC,
            },
        }
    }

    /// GetExplicitEntriesFromAcl walks the ACEs into the array: permissions, mode, inheritance
    /// and a SID-form trustee pointing at the SID inside the ACE; the count is the ACE count on
    /// return; a smaller capacity is ERROR_INSUFFICIENT_BUFFER; a bad ACL ERROR_INVALID_ACL.
    #[test]
    fn explicit_entries_walk_the_aces() {
        let admins = sid(5, &[32, 544]);
        let everyone = sid(1, &[0]);
        let acl = make_acl(&[
            (0, 0, 0x1234, &admins),
            (1, 0x10, 0xFF, &everyone),
            (2, 0x40, 0x55, &admins),
        ]);
        let mut entries = vec![zeroed_entry(); 3];
        let list = entries.as_mut_ptr() as *mut u8;
        let mut count = 3u32;
        arm();
        assert_eq!(
            (
                unsafe { get_explicit_entries_from_acl_a(acl.as_ptr(), &mut count, list) },
                last_error(),
                count
            ),
            (STATUS_SUCCESS, 0xF2F2, 3)
        );
        assert_eq!(
            (
                entries[0].grf_access_permissions,
                entries[0].grf_access_mode,
                entries[0].grf_inheritance,
                entries[0].trustee.trustee_form
            ),
            (0x1234, GRANT_ACCESS, 0, TRUSTEE_IS_SID)
        );
        assert_eq!(
            entries[0].trustee.ptstr_name,
            unsafe { ace_of(acl.as_ptr(), 0).add(8) } as usize
        );
        assert_eq!(
            (entries[1].grf_access_mode, entries[1].grf_inheritance),
            (DENY_ACCESS, 0x10)
        );
        assert_eq!(
            entries[1].trustee.ptstr_name,
            unsafe { ace_of(acl.as_ptr(), 1).add(8) } as usize
        );
        assert_eq!(
            (
                entries[2].grf_access_mode,
                entries[2].grf_access_permissions
            ),
            (SET_AUDIT_SUCCESS, 0x55)
        );
        // The W form answers the same.
        let mut count = 3u32;
        assert_eq!(
            unsafe { get_explicit_entries_from_acl_w(acl.as_ptr(), &mut count, list) },
            STATUS_SUCCESS
        );
        assert_eq!(count, 3);
        // A capacity below the ACE count fails, the count set to what is needed.
        let mut count = 1u32;
        arm();
        assert_eq!(
            (
                unsafe { get_explicit_entries_from_acl_a(acl.as_ptr(), &mut count, list) },
                last_error(),
                count
            ),
            (ERROR_INSUFFICIENT_BUFFER, ERROR_INSUFFICIENT_BUFFER, 3)
        );
        // A buffer that is no ACL.
        let mut bad = [0u8; 16];
        bad[0] = 9;
        let mut count = 3u32;
        arm();
        assert_eq!(
            (
                unsafe { get_explicit_entries_from_acl_a(bad.as_ptr(), &mut count, list) },
                last_error()
            ),
            (ERROR_INVALID_ACL, ERROR_INVALID_ACL)
        );
        // No place for the count.
        arm();
        assert_eq!(
            (
                unsafe {
                    get_explicit_entries_from_acl_a(acl.as_ptr(), core::ptr::null_mut(), list)
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
    }

    /// SetEntriesInAcl builds a new heap ACL from the entries: a grant appends an allowed ACE
    /// with the mask and SID; with no old ACL the new one holds just the entries.
    #[test]
    fn set_entries_builds_a_new_acl() {
        let admins = sid(5, &[32, 544]);
        let everyone = sid(1, &[0]);
        let entries = [
            entry_for(&admins, GRANT_ACCESS, 0x000F_01FF, 0),
            entry_for(&everyone, DENY_ACCESS, 0xFF, 0x10),
        ];
        let list = entries.as_ptr() as *const u8;
        let mut new_acl: *mut u8 = core::ptr::null_mut();
        arm();
        assert_eq!(
            (
                unsafe { set_entries_in_acl_a(2, list, core::ptr::null(), &mut new_acl) },
                last_error()
            ),
            (STATUS_SUCCESS, 0xF2F2)
        );
        assert!(!new_acl.is_null());
        assert_eq!(count_of(new_acl), 2);
        let first = ace_of(new_acl, 0);
        assert_eq!(unsafe { *first }, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dword(unsafe { first.add(4) }), 0x000F_01FF);
        assert!(services::equal_sid(
            unsafe { first.add(8) },
            admins.as_ptr()
        ));
        let second = ace_of(new_acl, 1);
        assert_eq!(unsafe { *second }, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(unsafe { *second.add(1) }, 0x10);
        assert!(services::equal_sid(
            unsafe { second.add(8) },
            everyone.as_ptr()
        ));
        // The W form answers the same.
        let mut new_acl_w: *mut u8 = core::ptr::null_mut();
        assert_eq!(
            unsafe { set_entries_in_acl_w(1, list, core::ptr::null(), &mut new_acl_w) },
            STATUS_SUCCESS
        );
        assert_eq!(count_of(new_acl_w), 1);
        // The caller frees the new ACLs.
        unsafe {
            ProcessHeap::free(new_acl);
            ProcessHeap::free(new_acl_w);
        }
    }

    /// SetEntriesInAcl merges with the old ACL: SET_ACCESS replaces the trustee's ACEs, REVOKE
    /// removes them; a NULL entries array leaves only the old ACL's inherited ACEs.
    #[test]
    fn set_entries_merges_with_the_old_acl() {
        let admins = sid(5, &[32, 544]);
        let everyone = sid(1, &[0]);
        let old = make_acl(&[
            (0, 0, 0x1111, &admins),
            (0, 0x10, 0x2222, &everyone),
            (1, 0, 0x3333, &everyone),
        ]);
        let mut new_acl: *mut u8 = core::ptr::null_mut();
        // SET_ACCESS for the admins replaces theirs; a deny for Everyone appends.
        let entries = [
            entry_for(&admins, SET_ACCESS, 0xAAAA, 0),
            entry_for(&everyone, DENY_ACCESS, 0xBB, 0),
        ];
        arm();
        assert_eq!(
            unsafe {
                set_entries_in_acl_a(2, entries.as_ptr() as *const u8, old.as_ptr(), &mut new_acl)
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            count_of(new_acl),
            4,
            "the old two for Everyone, the admins' replaced, the new deny"
        );
        assert_eq!(
            dword(unsafe { ace_of(new_acl, 0).add(4) }),
            0x2222,
            "the inherited Everyone ACE first"
        );
        assert_eq!(
            dword(unsafe { ace_of(new_acl, 1).add(4) }),
            0x3333,
            "then the old deny"
        );
        assert_eq!(
            dword(unsafe { ace_of(new_acl, 2).add(4) }),
            0xAAAA,
            "the admins' SET_ACCESS ACE"
        );
        assert!(services::equal_sid(
            unsafe { ace_of(new_acl, 2).add(8) },
            admins.as_ptr()
        ));
        assert_eq!(
            dword(unsafe { ace_of(new_acl, 3).add(4) }),
            0xBB,
            "the new deny last"
        );
        unsafe { ProcessHeap::free(new_acl) };
        // REVOKE removes the trustee's ACEs.
        let entries = [entry_for(&everyone, REVOKE_ACCESS, 0, 0)];
        assert_eq!(
            unsafe {
                set_entries_in_acl_a(1, entries.as_ptr() as *const u8, old.as_ptr(), &mut new_acl)
            },
            STATUS_SUCCESS
        );
        assert_eq!(count_of(new_acl), 1, "only the admins' ACE left");
        assert!(services::equal_sid(
            unsafe { ace_of(new_acl, 0).add(8) },
            admins.as_ptr()
        ));
        unsafe { ProcessHeap::free(new_acl) };
        // A NULL entries array restores the inherited ACL: only the inherited ACEs copied.
        assert_eq!(
            unsafe { set_entries_in_acl_a(0, core::ptr::null(), old.as_ptr(), &mut new_acl) },
            STATUS_SUCCESS
        );
        assert_eq!(count_of(new_acl), 1);
        assert_eq!(
            unsafe { *ace_of(new_acl, 0).add(1) },
            0x10,
            "the inherited ACE"
        );
        unsafe { ProcessHeap::free(new_acl) };
        // A NULL entries array with no old ACL is an empty ACL.
        assert_eq!(
            unsafe { set_entries_in_acl_a(0, core::ptr::null(), core::ptr::null(), &mut new_acl) },
            STATUS_SUCCESS
        );
        assert_eq!(count_of(new_acl), 0);
        unsafe { ProcessHeap::free(new_acl) };
        // A name trustee is ERROR_NONE_MAPPED; a bad old ACL ERROR_INVALID_ACL; counts without
        // an array ERROR_INVALID_PARAMETER; no place for the new ACL ERROR_INVALID_PARAMETER.
        let named = ExplicitAccess {
            grf_access_permissions: 1,
            grf_access_mode: GRANT_ACCESS,
            grf_inheritance: 0,
            trustee: Trustee {
                p_multiple_trustee: 0,
                multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                trustee_form: TRUSTEE_IS_NAME,
                trustee_type: TRUSTEE_IS_UNKNOWN,
                ptstr_name: b"Everyone\0".as_ptr() as usize,
            },
        };
        arm();
        assert_eq!(
            (
                unsafe {
                    set_entries_in_acl_a(
                        1,
                        &named as *const _ as *const u8,
                        core::ptr::null(),
                        &mut new_acl,
                    )
                },
                last_error()
            ),
            (ERROR_NONE_MAPPED, ERROR_NONE_MAPPED)
        );
        let mut bad = [0u8; 16];
        bad[0] = 1;
        arm();
        assert_eq!(
            (
                unsafe { set_entries_in_acl_a(0, core::ptr::null(), bad.as_ptr(), &mut new_acl) },
                last_error()
            ),
            (ERROR_INVALID_ACL, ERROR_INVALID_ACL)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    set_entries_in_acl_a(1, core::ptr::null(), core::ptr::null(), &mut new_acl)
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    set_entries_in_acl_a(0, core::ptr::null(), old.as_ptr(), core::ptr::null_mut())
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
    }
}
