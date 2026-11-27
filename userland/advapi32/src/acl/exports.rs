//! The ACL exports: InitializeAcl, IsValidAcl, AddAce and the Add*ACE family, GetAce, DeleteAce,
//! FindFirstFreeAce, and the audit pair (GetAuditedPermissionsFromAclA/W, SetEntriesInAuditListA/W).

use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use rtl::heap::ProcessHeap as _;
use rtl::winerror::{
    ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_INVALID_SID,
    ERROR_IO_PENDING, ERROR_NOT_ENOUGH_MEMORY,
};

use crate::imports::{self as nt, ProcessHeap};
use crate::sid::{caller_sid, set_ptr_field, sid_equal, ERROR_INVALID_ACL, PTR};
use crate::trustee::TRUSTEE_SIZE;
use crate::{caller_bytes, Out};

use super::edit::*;
use super::*;

/// Map an editor's status to the Win32 error, set it, and answer FALSE.
fn fail(status: NtStatus) -> u32 {
    let error = nt::dos_error(status);
    nt::set_last_error(error);
    0
}

/// Map an editor's status for an *Ex export: STATUS_INVALID_PARAMETER is ERROR_INVALID_FLAGS.
fn fail_ex(status: NtStatus) -> u32 {
    let error = if status.0 == STATUS_INVALID_PARAMETER {
        ERROR_INVALID_FLAGS
    } else {
        nt::dos_error(status)
    };
    nt::set_last_error(error);
    0
}

/// One Add*ACE call's body: the GUIDs and SID read, the editor called, the status mapped.
///
/// # Safety
///
/// `acl` is an ACL the call may read and write; `sid` a SID the call may read; the GUID pointers
/// null or 16 readable bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn add_ace_call(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    plain_kind: u8,
    object_kind: u8,
    ex: bool,
) -> u32 {
    if sid.is_null() {
        // A null SID is ERROR_INVALID_SID, not a bad parameter.
        nt::set_last_error(ERROR_INVALID_SID);
        return 0;
    }
    // SAFETY: the caller's ACL, GUIDs and SID.
    let (buffer, object_type, inherited_object_type, sid) = unsafe {
        (
            caller_acl_mut(acl),
            caller_bytes(object_type, GUID_SIZE),
            caller_bytes(inherited_object_type, GUID_SIZE),
            caller_sid(sid),
        )
    };
    fn to_guid(bytes: Option<&[u8]>) -> Option<&[u8; GUID_SIZE]> {
        bytes.and_then(|b| <&[u8; GUID_SIZE]>::try_from(b).ok())
    }
    let (object_type, inherited_object_type) = (to_guid(object_type), to_guid(inherited_object_type));
    let (Some(buffer), Some(sid)) = (buffer, sid) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let status = add_one_ace(
        buffer,
        ace_revision,
        flags,
        mask,
        object_type,
        inherited_object_type,
        sid,
        plain_kind,
        object_kind,
    );
    match status {
        NtStatus(STATUS_SUCCESS) => 1,
        status => {
            if ex {
                fail_ex(status)
            } else {
                fail(status)
            }
        }
    }
}


// --- The exports -------------------------------------------------------------------------------

/// InitializeAcl: an empty ACL of `length` bytes and `revision` in the caller's buffer; the size
/// is rounded down to a dword. ERROR_INSUFFICIENT_BUFFER for a buffer shorter than the header,
/// ERROR_INVALID_PARAMETER for a revision outside 2..=4. A null ACL faults where the header is
/// written, as the platform's unprobed write does.
///
/// # Safety
///
/// `acl` is null or `length` writable bytes.
#[unsafe(export_name = "f2k_export_InitializeAcl")]
pub unsafe extern "system" fn initialize_acl(acl: *mut u8, length: u32, revision: u32) -> u32 {
    // The checks the editor makes before any write: a buffer shorter than the header, a
    // revision outside 2..=4, a size past a word.
    if (length as usize) < ACL_HEADER {
        return fail(NtStatus(STATUS_BUFFER_TOO_SMALL));
    }
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&revision) || length > u32::from(u16::MAX) {
        return fail(NtStatus(STATUS_INVALID_PARAMETER));
    }
    // SAFETY: the caller's buffer of `length` bytes.
    let buffer = unsafe { caller_bytes_mut(acl, length as usize) };
    let Some(buffer) = buffer else {
        // A null ACL: the header's write faults the caller.
        unsafe { acl.write(revision as u8) };
        unreachable!("the write above faults")
    };
    match create_acl(buffer, length, revision) {
        NtStatus(STATUS_SUCCESS) => 1,
        status => fail(status),
    }
}

/// IsValidAcl: whether the ACL at `acl` is well formed; ERROR_INVALID_ACL when not (a null
/// included).
///
/// # Safety
///
/// `acl` is null or an ACL the call may read.
#[unsafe(export_name = "f2k_export_IsValidAcl")]
pub unsafe extern "system" fn is_valid_acl(acl: *const u8) -> u32 {
    // SAFETY: the caller's ACL.
    let buffer = unsafe { caller_acl(acl) };
    if buffer.is_some_and(valid_acl) {
        1
    } else {
        nt::set_last_error(ERROR_INVALID_ACL);
        0
    }
}

/// AddAce: the ACE list at `list` (of `list_length` bytes) inserted into the ACL at
/// `starting_ace_index` (the end for one past the count), the ACL's revision raised to the ACEs'.
///
/// # Safety
///
/// `acl` is an ACL the call may read and write; `list` the ACE list's `list_length` bytes.
#[unsafe(export_name = "f2k_export_AddAce")]
pub unsafe extern "system" fn add_ace(
    acl: *mut u8,
    ace_revision: u32,
    starting_ace_index: u32,
    list: *const u8,
    list_length: u32,
) -> u32 {
    // SAFETY: the caller's ACL and ACE list.
    let (buffer, list) =
        unsafe { (caller_acl_mut(acl), caller_bytes(list, list_length as usize)) };
    let (Some(buffer), Some(list)) = (buffer, list) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match add_ace_list(buffer, ace_revision, starting_ace_index, list) {
        NtStatus(STATUS_SUCCESS) => 1,
        status => fail(status),
    }
}

/// DeleteAce: the ACE `index` removed from the ACL.
///
/// # Safety
///
/// `acl` is an ACL the call may read and write.
#[unsafe(export_name = "f2k_export_DeleteAce")]
pub unsafe extern "system" fn delete_ace(acl: *mut u8, index: u32) -> u32 {
    // SAFETY: the caller's ACL.
    let buffer = unsafe { caller_acl_mut(acl) };
    let Some(buffer) = buffer else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match remove_ace(buffer, index) {
        NtStatus(STATUS_SUCCESS) => 1,
        status => fail(status),
    }
}

/// GetAce: the address of the ACE `index` in the ACL into `ace`.
///
/// # Safety
///
/// `acl` is an ACL the call may read; `ace` the caller's place for the address.
#[unsafe(export_name = "f2k_export_GetAce")]
pub unsafe extern "system" fn get_ace(acl: *const u8, index: u32, ace: *mut *mut u8) -> u32 {
    // SAFETY: the caller's ACL and place.
    let (buffer, mut place) = unsafe { (caller_acl(acl), Out::optional(ace)) };
    let (Some(buffer), Some(place)) = (buffer, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match ace_offset(buffer, index) {
        Ok(at) => {
            place.set(unsafe { acl.add(at) }.cast_mut());
            1
        }
        Err(status) => fail(status),
    }
}

/// FindFirstFreeAce: the address of the first free byte in the ACL into `ace` (a full ACL's
/// end); ERROR_INVALID_ACL for an ill-formed one.
///
/// # Safety
///
/// `acl` is an ACL the call may read; `ace` the caller's place for the address.
#[unsafe(export_name = "f2k_export_FindFirstFreeAce")]
pub unsafe extern "system" fn find_first_free_ace(acl: *const u8, ace: *mut *mut u8) -> u32 {
    // SAFETY: the caller's ACL and place.
    let (buffer, mut place) = unsafe { (caller_acl(acl), Out::optional(ace)) };
    let (Some(buffer), Some(place)) = (buffer, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    match first_free(buffer) {
        Ok(free) => {
            place.set(free.map_or(::core::ptr::null_mut(), |at| unsafe { acl.add(at) }.cast_mut()));
            1
        }
        Err(()) => {
            nt::set_last_error(ERROR_INVALID_ACL);
            0
        }
    }
}

/// AddAccessAllowedAce: an allowed ACE (no flags) appended.
///
/// # Safety
///
/// `acl` is an ACL the call may read and write; `sid` a SID the call may read.
#[unsafe(export_name = "f2k_export_AddAccessAllowedAce")]
pub unsafe extern "system" fn add_access_allowed_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            0,
            mask,
            core::ptr::null(),
            core::ptr::null(),
            sid,
            ACCESS_ALLOWED_ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            false,
        )
    }
}

/// AddAccessAllowedAceEx: as AddAccessAllowedAce, with flags.
///
/// # Safety
///
/// As AddAccessAllowedAce's.
#[unsafe(export_name = "f2k_export_AddAccessAllowedAceEx")]
pub unsafe extern "system" fn add_access_allowed_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            flags,
            mask,
            core::ptr::null(),
            core::ptr::null(),
            sid,
            ACCESS_ALLOWED_ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            true,
        )
    }
}

/// AddAccessDeniedAce: a denied ACE (no flags) appended.
///
/// # Safety
///
/// As AddAccessAllowedAce's.
#[unsafe(export_name = "f2k_export_AddAccessDeniedAce")]
pub unsafe extern "system" fn add_access_denied_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            0,
            mask,
            core::ptr::null(),
            core::ptr::null(),
            sid,
            ACCESS_DENIED_ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            false,
        )
    }
}

/// AddAccessDeniedAceEx: as AddAccessDeniedAce, with flags.
///
/// # Safety
///
/// As AddAccessAllowedAce's.
#[unsafe(export_name = "f2k_export_AddAccessDeniedAceEx")]
pub unsafe extern "system" fn add_access_denied_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            flags,
            mask,
            core::ptr::null(),
            core::ptr::null(),
            sid,
            ACCESS_DENIED_ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            true,
        )
    }
}

/// AddAuditAccessAce: an audit ACE appended, the flags from `audit_success`/`audit_failure`.
///
/// # Safety
///
/// As AddAccessAllowedAce's.
#[unsafe(export_name = "f2k_export_AddAuditAccessAce")]
pub unsafe extern "system" fn add_audit_access_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    audit_ace_call(
        acl,
        ace_revision,
        0,
        mask,
        core::ptr::null(),
        core::ptr::null(),
        sid,
        audit_success,
        audit_failure,
        false,
    )
}

/// AddAuditAccessAceEx: as AddAuditAccessAce, with flags.
///
/// # Safety
///
/// As AddAccessAllowedAce's.
#[unsafe(export_name = "f2k_export_AddAuditAccessAceEx")]
pub unsafe extern "system" fn add_audit_access_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    audit_ace_call(
        acl,
        ace_revision,
        flags,
        mask,
        core::ptr::null(),
        core::ptr::null(),
        sid,
        audit_success,
        audit_failure,
        true,
    )
}

/// AddAccessAllowedObjectAce: the allowed object kind, the GUIDs optional (both null: the plain
/// allowed ACE).
///
/// # Safety
///
/// As AddAccessAllowedAce's; the GUID pointers null or 16 readable bytes.
#[unsafe(export_name = "f2k_export_AddAccessAllowedObjectAce")]
pub unsafe extern "system" fn add_access_allowed_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_ALLOWED_ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            true,
        )
    }
}

/// AddAccessDeniedObjectAce: the denied object kind, the GUIDs optional.
///
/// # Safety
///
/// As AddAccessAllowedObjectAce's.
#[unsafe(export_name = "f2k_export_AddAccessDeniedObjectAce")]
pub unsafe extern "system" fn add_access_denied_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    unsafe {
        add_ace_call(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_DENIED_ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            true,
        )
    }
}

/// AddAuditAccessObjectAce: the audit object kind, the GUIDs optional (both null: the plain
/// audit ACE).
///
/// # Safety
///
/// As AddAccessAllowedObjectAce's.
#[unsafe(export_name = "f2k_export_AddAuditAccessObjectAce")]
pub unsafe extern "system" fn add_audit_access_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    audit_ace_call(
        acl,
        ace_revision,
        flags,
        mask,
        object_type,
        inherited_object_type,
        sid,
        audit_success,
        audit_failure,
        true,
    )
}

/// The audit Add*ACE calls' shared body: the success/failure flags OR'd into `flags`.
///
/// # Safety
///
/// As the audit exports'.
#[allow(clippy::too_many_arguments)]
unsafe fn audit_ace_call(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
    ex: bool,
) -> u32 {
    let mut flags = flags;
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    add_ace_call(
        acl,
        ace_revision,
        flags,
        mask,
        object_type,
        inherited_object_type,
        sid,
        SYSTEM_AUDIT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        ex,
    )
}


// --- The audit pair ----------------------------------------------------------------------------

/// An accctrl access entry's size: its trustee, then the four dwords and the property pointer
/// (accctrl.h's ACTRL_ACCESS_ENTRY).
pub(crate) const ENTRY_SIZE: usize = TRUSTEE_SIZE + 16 + PTR;
/// An accctrl access list's size: the count and the entries' pointer (ACTRL_LIST).
pub(crate) const LIST_SIZE: usize = 4 + PTR;

/// SetEntriesInAuditListA/W's body: the caller's `entries` entries copied into a fresh accctrl
/// list on the process heap, its address into `new_list`. The answer is the error code
/// ERROR_SUCCESS (0), with the last error left at ERROR_IO_PENDING, as the platform's audit-list
/// build leaves it; F2K keeps no audit, so the list is the call's whole answer.
///
/// # Safety
///
/// `list` is null (for a zero count) or `entries` entries the call may read; `new_list` the
/// caller's place for the list's address.
unsafe fn set_entries_in_audit_list(entries: u32, list: *const u8, new_list: *mut *mut u8) -> u32 {
    // SAFETY: the caller's place.
    let mut place = unsafe { Out::optional(new_list) };
    let Some(place) = place.as_mut() else {
        return ERROR_INVALID_PARAMETER;
    };
    let count = entries as usize;
    // SAFETY: the caller's entries.
    let source = if count == 0 {
        &[][..]
    } else {
        match unsafe { caller_bytes(list, count * ENTRY_SIZE) } {
            Some(bytes) => bytes,
            None => return ERROR_INVALID_PARAMETER,
        }
    };
    let size = LIST_SIZE + count * ENTRY_SIZE;
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    // SAFETY: the heap's new block of `size` bytes, ours to write.
    let out = unsafe { core::slice::from_raw_parts_mut(block, size) };
    out[..4].copy_from_slice(&entries.to_le_bytes());
    set_ptr_field(out, 4, block as usize + LIST_SIZE);
    out[LIST_SIZE..LIST_SIZE + source.len()].copy_from_slice(source);
    place.set(block);
    nt::set_last_error(ERROR_IO_PENDING);
    0
}

/// SetEntriesInAuditListA: as [`set_entries_in_audit_list`], an ANSI trustee name in the entries.
///
/// # Safety
///
/// As [`set_entries_in_audit_list`]'s; `name` a string the call does not read.
#[unsafe(export_name = "f2k_export_SetEntriesInAuditListA")]
pub unsafe extern "system" fn set_entries_in_audit_list_a(
    entries: u32,
    list: *const u8,
    _mode: u32,
    _name: *const u8,
    _old_list: *const u8,
    new_list: *mut *mut u8,
) -> u32 {
    unsafe { set_entries_in_audit_list(entries, list, new_list) }
}

/// SetEntriesInAuditListW: as the A form, a wide trustee name in the entries.
///
/// # Safety
///
/// As [`set_entries_in_audit_list`]'s; `name` a wide string the call does not read.
#[unsafe(export_name = "f2k_export_SetEntriesInAuditListW")]
pub unsafe extern "system" fn set_entries_in_audit_list_w(
    entries: u32,
    list: *const u8,
    _mode: u32,
    _name: *const u16,
    _old_list: *const u8,
    new_list: *mut *mut u8,
) -> u32 {
    unsafe { set_entries_in_audit_list(entries, list, new_list) }
}
/// GetAuditedPermissionsFromAclA/W: the accesses the ACL's audit ACEs say are audited for the
/// trustee: OR'd into `success` (the success-flag ACEs) and `failure` (the failure-flag ones).
/// A trustee by name has no answer without an account database (ERROR_ENVVAR_NOT_FOUND, the
/// masks untouched); the answer is ERROR_SUCCESS. Nulls are ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// `acl` is null or an ACL the call may read; `trustee` null or a trustee structure; `success`
/// and `failure` the caller's places.
#[unsafe(export_name = "f2k_export_GetAuditedPermissionsFromAclA")]
pub unsafe extern "system" fn get_audited_permissions_from_acl_a(
    acl: *const u8,
    trustee: *const u8,
    success: *mut u32,
    failure: *mut u32,
) -> u32 {
    audited_permissions(acl, trustee, success, failure)
}

/// GetAuditedPermissionsFromAclW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetAuditedPermissionsFromAclW")]
pub unsafe extern "system" fn get_audited_permissions_from_acl_w(
    acl: *const u8,
    trustee: *const u8,
    success: *mut u32,
    failure: *mut u32,
) -> u32 {
    audited_permissions(acl, trustee, success, failure)
}

/// The audit query's body.
///
/// # Safety
///
/// As the exports'.
unsafe fn audited_permissions(
    acl: *const u8,
    trustee: *const u8,
    success: *mut u32,
    failure: *mut u32,
) -> u32 {
    // SAFETY: the caller's ACL, trustee and places.
    let (buffer, trustee, mut success, mut failure) = unsafe {
        (
            caller_acl(acl),
            trustee_sid(trustee),
            Out::optional(success),
            Out::optional(failure),
        )
    };
    if buffer.is_none() || trustee.is_none() || success.is_none() || failure.is_none() {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }
    let Some(sid) = trustee.unwrap() else {
        // A trustee by name: no account database to resolve it against.
        nt::set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    };
    let buffer = buffer.unwrap();
    if !valid_acl(buffer) {
        nt::set_last_error(ERROR_INVALID_ACL);
        return ERROR_INVALID_ACL;
    }
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(buffer) {
        let kind = buffer[at + ACE_TYPE_OFF];
        if kind == SYSTEM_AUDIT_ACE_TYPE || kind == SYSTEM_AUDIT_OBJECT_ACE_TYPE {
            let flags = u32::from(buffer[at + ACE_FLAGS_OFF]);
            let mask = dword(buffer, at + ACE_MASK_OFF).unwrap_or(0);
            let sid_off = if kind == SYSTEM_AUDIT_ACE_TYPE {
                at + KNOWN_ACE_FIXED
            } else {
                at + object_ace_sid_offset(dword(buffer, at + 8).unwrap_or(0))
            };
            if let Some(ace_sid) = sid_at(buffer, sid_off) {
                if sid_equal(ace_sid, sid) {
                    if flags & SUCCESSFUL_ACCESS_ACE_FLAG != 0 {
                        let place = success.as_mut().unwrap();
                        let value = place.get() | mask;
                        place.set(value);
                    }
                    if flags & FAILED_ACCESS_ACE_FLAG != 0 {
                        let place = failure.as_mut().unwrap();
                        let value = place.get() | mask;
                        place.set(value);
                    }
                }
            }
        }
        at += word(buffer, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    }
    0
}
