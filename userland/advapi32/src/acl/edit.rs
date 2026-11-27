//! The ACL editors over a byte slice: the well-formedness check, the free-byte walk, and the
//! ACE list and ACE add/remove operations the exports call, answering an NTSTATUS.

use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_REVISION_MISMATCH, STATUS_SUCCESS};

use crate::sid::{caller_sid, ptr_field, valid_sid, MAX_SUB_AUTHORITIES, SID_HEADER, SID_REVISION, STATUS_ALLOTTED_SPACE_EXCEEDED, STATUS_INVALID_ACL, STATUS_INVALID_SID};
use crate::trustee::{FORM_NAME, FORM_OBJECTS_AND_SID, FORM_SID, OAS_SID, OAS_SIZE, TRUSTEE_FORM, TRUSTEE_NAME, TRUSTEE_SIZE};
use crate::caller_bytes;

use super::*;

/// IsValidAcl's check: the revision in 2..=4, the size even and at least the header, and every
/// ACE inside the size, its size even, and — for the known kinds — its SID(s) in bounds.
pub(crate) fn valid_acl(acl: &[u8]) -> bool {
    if !valid_revision(acl) {
        return false;
    }
    let size = acl_size(acl);
    if size % 2 != 0 || size < ACL_HEADER {
        return false;
    }
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(acl) {
        // The ACE header must fit in the ACL, strictly before its end.
        if at + ACE_HEADER >= size {
            return false;
        }
        let ace_size = word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
        if ace_size % 2 != 0 || at + ace_size > size {
            return false;
        }
        let kind = *acl.get(at + ACE_TYPE_OFF).unwrap_or(&0xFF);
        match kind {
            // The plain kinds: a long-aligned size holding the mask and the whole SID.
            ACCESS_ALLOWED_ACE_TYPE..=SYSTEM_ALARM_ACE_TYPE => {
                if ace_size % 4 != 0 || ace_size < KNOWN_ACE_FIXED + 4 {
                    return false;
                }
                let Some(sid) = sid_at(acl, at + KNOWN_ACE_FIXED) else {
                    return false;
                };
                if sid.first() != Some(&SID_REVISION) {
                    return false;
                }
                if usize::from(sid[1]) > MAX_SUB_AUTHORITIES {
                    return false;
                }
                if ace_size < KNOWN_ACE_FIXED + sid.len() {
                    return false;
                }
            }
            // The compound kind (revision 3 and up): two SIDs after the compound type.
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                if u32::from(*acl.get(ACL_REV_OFF).unwrap_or(&0)) < 3 {
                    return false;
                }
                if ace_size % 4 != 0 || ace_size < 20 {
                    return false;
                }
                if word(acl, at + 8) != Some(1) {
                    return false;
                }
                let Some(first) = sid_at(acl, at + 12) else {
                    return false;
                };
                if first.first() != Some(&SID_REVISION) || usize::from(first[1]) > MAX_SUB_AUTHORITIES
                {
                    return false;
                }
                if ace_size < 12 + first.len() + SID_HEADER {
                    return false;
                }
                let Some(second) = sid_at(acl, at + 12 + first.len()) else {
                    return false;
                };
                if second.first() != Some(&SID_REVISION) || usize::from(second[1]) > MAX_SUB_AUTHORITIES
                {
                    return false;
                }
                if ace_size < 12 + first.len() + second.len() {
                    return false;
                }
            }
            // The object kinds (revision 4 and up): the GUIDs their flags name, then the SID.
            ACCESS_ALLOWED_OBJECT_ACE_TYPE..=SYSTEM_ALARM_OBJECT_ACE_TYPE => {
                if u32::from(*acl.get(ACL_REV_OFF).unwrap_or(&0)) < 4 {
                    return false;
                }
                if ace_size % 4 != 0 || ace_size < OBJECT_ACE_FIXED {
                    return false;
                }
                let flags = dword(acl, at + 8).unwrap_or(0);
                let sid_off = at + object_ace_sid_offset(flags);
                if ace_size < sid_off - at + SID_HEADER {
                    return false;
                }
                let Some(sid) = sid_at(acl, sid_off) else {
                    return false;
                };
                if sid.first() != Some(&SID_REVISION) || usize::from(sid[1]) > MAX_SUB_AUTHORITIES {
                    return false;
                }
                if ace_size < sid_off - at + sid.len() {
                    return false;
                }
            }
            // An unknown type: the header checks above are all there is.
            _ => {}
        }
        at += ace_size;
    }
    true
}

/// FindFirstFreeAce's walk: the offset of the first free byte, or None for a full ACL; Err for an
/// ill-formed one (an ACE pointer past the end mid-walk).
pub(crate) fn first_free(acl: &[u8]) -> Result<Option<usize>, ()> {
    let size = acl_size(acl);
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(acl) {
        if at >= size {
            return Err(());
        }
        at += word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    }
    Ok((at <= size).then_some(at))
}

/// An empty ACL's header written into the caller's buffer of `length` bytes.
pub(crate) fn create_acl(buffer: &mut [u8], length: u32, revision: u32) -> NtStatus {
    if (length as usize) < ACL_HEADER {
        return NtStatus(STATUS_BUFFER_TOO_SMALL);
    }
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&revision) || length > u16::MAX as u32 {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    buffer[ACL_REV_OFF] = revision as u8;
    buffer[1] = 0;
    set_word(buffer, ACL_SIZE_OFF, (length & 0xFFFC) as u16);
    set_word(buffer, ACL_COUNT_OFF, 0);
    set_word(buffer, 6, 0);
    NtStatus(STATUS_SUCCESS)
}

/// The offset of the ACE `index`, walking the list (with the revision and bounds checks).
pub(crate) fn ace_offset(acl: &[u8], index: u32) -> Result<usize, NtStatus> {
    if !valid_revision(acl) {
        return Err(NtStatus(STATUS_INVALID_PARAMETER));
    }
    if index as usize >= ace_count(acl) {
        return Err(NtStatus(STATUS_INVALID_PARAMETER));
    }
    let size = acl_size(acl);
    let mut at = ACL_HEADER;
    for _ in 0..index {
        if at >= size {
            return Err(NtStatus(STATUS_INVALID_PARAMETER));
        }
        at += word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    }
    if at >= size {
        return Err(NtStatus(STATUS_INVALID_PARAMETER));
    }
    Ok(at)
}

/// The ACE list `list` inserted at `start` (the end for a start past the count),
/// shifting the tail up.
pub(crate) fn add_ace_list(acl: &mut [u8], ace_revision: u32, start: u32, list: &[u8]) -> NtStatus {
    if !valid_acl(acl) {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    let free = match first_free(acl) {
        Ok(free) => free,
        Err(()) => return NtStatus(STATUS_INVALID_PARAMETER),
    };
    // The list must be well formed: ACEs ending exactly at its end, of types the revision allows.
    let mut at = 0usize;
    let mut added = 0u32;
    while at < list.len() {
        let Some(&kind) = list.get(at) else {
            return NtStatus(STATUS_INVALID_PARAMETER);
        };
        if kind > 3 && kind <= 4 && ace_revision < 3 || kind > 4 && kind <= 8 && ace_revision < 4 {
            return NtStatus(STATUS_INVALID_PARAMETER);
        }
        let Some(size) = word(list, at + ACE_SIZE_OFF) else {
            return NtStatus(STATUS_INVALID_PARAMETER);
        };
        let size = size as usize;
        if size == 0 {
            return NtStatus(STATUS_INVALID_PARAMETER);
        }
        at += size;
        added += 1;
    }
    if at > list.len() {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    let Some(free) = free else {
        return NtStatus(STATUS_BUFFER_TOO_SMALL);
    };
    if free + list.len() > acl_size(acl) {
        return NtStatus(STATUS_BUFFER_TOO_SMALL);
    }
    // The insert position: after the first min(start, count) ACEs.
    let mut at = ACL_HEADER;
    for _ in 0..start.min(ace_count(acl) as u32) {
        at += word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    }
    acl.copy_within(at..free, at + list.len());
    acl[at..at + list.len()].copy_from_slice(list);
    set_word(acl, ACL_COUNT_OFF, (ace_count(acl) + added as usize) as u16);
    acl[ACL_REV_OFF] = u32::from(acl[ACL_REV_OFF]).max(ace_revision) as u8;
    NtStatus(STATUS_SUCCESS)
}

/// The ACE `index` removed, the tail shifted down over it and the vacated tail
/// zeroed.
pub(crate) fn remove_ace(acl: &mut [u8], index: u32) -> NtStatus {
    if !valid_acl(acl) {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    if index as usize >= ace_count(acl) {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    let free = match first_free(acl) {
        Ok(free) => free,
        Err(()) => return NtStatus(STATUS_INVALID_PARAMETER),
    };
    let at = match ace_offset(acl, index) {
        Ok(at) => at,
        Err(status) => return status,
    };
    let Some(free) = free else {
        return NtStatus(STATUS_INVALID_PARAMETER);
    };
    let size = word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    acl.copy_within(at + size..free, at);
    for byte in &mut acl[free - size..free] {
        *byte = 0;
    }
    set_word(acl, ACL_COUNT_OFF, (ace_count(acl) - 1) as u16);
    NtStatus(STATUS_SUCCESS)
}

/// The ACE flags check the Add* editors do: only the inherit flags (and, for the audit kinds, the
/// success/failure flags) may be set.
pub(crate) fn checked_flags(flags: u32, audit: bool) -> Result<(), NtStatus> {
    let mut tested = flags & !VALID_INHERIT_FLAGS;
    if audit {
        tested &= !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
    }
    if tested != 0 {
        return Err(NtStatus(STATUS_INVALID_PARAMETER));
    }
    Ok(())
}

/// A plain ACE appended at the first free byte.
pub(crate) fn add_known_ace(
    acl: &mut [u8],
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: &[u8],
    kind: u8,
) -> NtStatus {
    if !valid_sid(sid) {
        return NtStatus(STATUS_INVALID_SID);
    }
    if u32::from(acl.first().copied().unwrap_or(0)) > MAX_ACL_REVISION
        || ace_revision > MAX_ACL_REVISION
    {
        return NtStatus(STATUS_REVISION_MISMATCH);
    }
    if checked_flags(flags, kind == SYSTEM_AUDIT_ACE_TYPE).is_err() {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    if !valid_acl(acl) {
        return NtStatus(STATUS_INVALID_ACL);
    }
    let free = match first_free(acl) {
        Ok(free) => free,
        Err(()) => return NtStatus(STATUS_INVALID_ACL),
    };
    let ace_size = KNOWN_ACE_FIXED + sid.len();
    let Some(at) = free.filter(|&at| at + ace_size <= acl_size(acl)) else {
        return NtStatus(STATUS_ALLOTTED_SPACE_EXCEEDED);
    };
    acl[at + ACE_TYPE_OFF] = kind;
    acl[at + ACE_FLAGS_OFF] = flags as u8;
    set_word(acl, at + ACE_SIZE_OFF, ace_size as u16);
    set_dword(acl, at + ACE_MASK_OFF, mask);
    acl[at + KNOWN_ACE_FIXED..at + ace_size].copy_from_slice(sid);
    set_word(acl, ACL_COUNT_OFF, (ace_count(acl) + 1) as u16);
    acl[ACL_REV_OFF] = u32::from(acl[ACL_REV_OFF]).max(ace_revision) as u8;
    NtStatus(STATUS_SUCCESS)
}

/// An object ACE appended, the GUIDs in flag order, then the SID. The
/// revision must be 4 exactly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_known_object_ace(
    acl: &mut [u8],
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: Option<&[u8; GUID_SIZE]>,
    inherited_object_type: Option<&[u8; GUID_SIZE]>,
    sid: &[u8],
    kind: u8,
) -> NtStatus {
    if !valid_sid(sid) {
        return NtStatus(STATUS_INVALID_SID);
    }
    if u32::from(acl.first().copied().unwrap_or(0)) > MAX_ACL_REVISION
        || ace_revision != ACL_REVISION_DS
    {
        return NtStatus(STATUS_REVISION_MISMATCH);
    }
    let audit = kind == SYSTEM_AUDIT_OBJECT_ACE_TYPE || kind == SYSTEM_ALARM_OBJECT_ACE_TYPE;
    if checked_flags(flags, audit).is_err() {
        return NtStatus(STATUS_INVALID_PARAMETER);
    }
    if !valid_acl(acl) {
        return NtStatus(STATUS_INVALID_ACL);
    }
    let free = match first_free(acl) {
        Ok(free) => free,
        Err(()) => return NtStatus(STATUS_INVALID_ACL),
    };
    let mut object_flags = 0u32;
    if object_type.is_some() {
        object_flags |= ACE_OBJECT_TYPE_PRESENT;
    }
    if inherited_object_type.is_some() {
        object_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
    }
    let ace_size = object_ace_sid_offset(object_flags) + sid.len();
    let Some(at) = free.filter(|&at| at + ace_size <= acl_size(acl)) else {
        return NtStatus(STATUS_ALLOTTED_SPACE_EXCEEDED);
    };
    acl[at + ACE_TYPE_OFF] = kind;
    acl[at + ACE_FLAGS_OFF] = flags as u8;
    set_word(acl, at + ACE_SIZE_OFF, ace_size as u16);
    set_dword(acl, at + ACE_MASK_OFF, mask);
    set_dword(acl, at + 8, object_flags);
    let mut next = at + OBJECT_ACE_FIXED;
    if let Some(guid) = object_type {
        acl[next..next + GUID_SIZE].copy_from_slice(guid);
        next += GUID_SIZE;
    }
    if let Some(guid) = inherited_object_type {
        acl[next..next + GUID_SIZE].copy_from_slice(guid);
        next += GUID_SIZE;
    }
    acl[next..at + ace_size].copy_from_slice(sid);
    set_word(acl, ACL_COUNT_OFF, (ace_count(acl) + 1) as u16);
    acl[ACL_REV_OFF] = u32::from(acl[ACL_REV_OFF]).max(ace_revision) as u8;
    NtStatus(STATUS_SUCCESS)
}

/// The one Add*ACE shape behind the exports: an object ACE when a GUID is given, else a plain
/// one.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_one_ace(
    acl: &mut [u8],
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: Option<&[u8; GUID_SIZE]>,
    inherited_object_type: Option<&[u8; GUID_SIZE]>,
    sid: &[u8],
    plain_kind: u8,
    object_kind: u8,
) -> NtStatus {
    if object_type.is_none() && inherited_object_type.is_none() {
        add_known_ace(acl, ace_revision, flags, mask, sid, plain_kind)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            object_kind,
        )
    }
}

/// The trustee's SID for GetAuditedPermissionsFromAcl: the SID form's, or the objects-and-SID
/// form's; None for a name form (or a bad one).
///
/// # Safety
///
/// `trustee` is null or a trustee structure the call may read.
pub(crate) unsafe fn trustee_sid<'a>(trustee: *const u8) -> Option<Option<&'a [u8]>> {
    // SAFETY: the caller's trustee.
    let bytes = unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }?;
    let form = dword(bytes, TRUSTEE_FORM)?;
    let name = ptr_field(bytes, TRUSTEE_NAME)?;
    match form {
        FORM_SID => Some(unsafe { caller_sid(name as *const u8) }),
        FORM_NAME => Some(None),
        FORM_OBJECTS_AND_SID => {
            // SAFETY: the objects-and-SID structure the trustee points at.
            let objects = unsafe { caller_bytes(name as *const u8, OAS_SIZE) }?;
            let sid = ptr_field(objects, OAS_SID)?;
            Some(unsafe { caller_sid(sid as *const u8) })
        }
        _ => None,
    }
}
