//! LookupSecurityDescriptorParts A/W: the security descriptor's owner, group, access and audit
//! parts, handed out as heap blocks the caller frees (with LocalFree).
//!
//! The owner and group come out as TRUSTEE structures of the SID form, pointing at copies of the
//! descriptor's SIDs (a null place for a part the descriptor does not carry). The access and
//! audit entries come out as EXPLICIT_ACCESS arrays built from the DACL and SACL, with each
//! entry's trustee a SID-form trustee pointing at a copy of the ACE's SID. The return is the
//! Win32 error code: ERROR_SUCCESS on a success (the last error untouched), the error on a
//! failure. The A and W forms share the body: the parts they build are SID-form trustees either
//! way.

use rtl::heap::ProcessHeap as _;
use rtl::winerror::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

use crate::acl::FAILED_ACCESS_ACE_FLAG;
use crate::acl::{
    ace_count,
    dword,
    object_ace_sid_offset,
    sid_at,
    word,
    ACE_FLAGS_OFF,
    ACE_HEADER,
    ACE_MASK_OFF,
    ACE_SIZE_OFF,
    ACE_TYPE_OFF,
    ACL_HEADER,
};
use crate::explicit::{
    fail,
    ExplicitAccess,
    Trustee,
    DENY_ACCESS,
    ENTRY_SIZE,
    GRANT_ACCESS,
    SET_AUDIT_FAILURE,
    SET_AUDIT_SUCCESS,
};
use crate::imports::{self as nt, ProcessHeap};
use crate::sd::{caller_sd, sd_components, FIELD_DACL, FIELD_GROUP, FIELD_OWNER, FIELD_SACL};
use crate::sid::{set_ptr_field, ERROR_INVALID_SECURITY_DESCR};
use crate::trustee::{
    FORM_SID,
    TRUSTEE_FORM,
    TRUSTEE_MULTIPLE,
    TRUSTEE_NAME,
    TRUSTEE_OP,
    TRUSTEE_SIZE,
    TRUSTEE_TYPE,
};
use crate::Out;

/// The ACE types the entry lists take, and the access mode each maps to (audit kinds by their
/// failed flag).
fn entry_mode(kind: u8, flags: u32) -> Option<u32> {
    use crate::acl::{
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    };
    match kind {
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_OBJECT_ACE_TYPE => Some(GRANT_ACCESS),
        ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => Some(DENY_ACCESS),
        SYSTEM_AUDIT_ACE_TYPE
        | SYSTEM_AUDIT_OBJECT_ACE_TYPE
        | SYSTEM_ALARM_ACE_TYPE
        | SYSTEM_ALARM_OBJECT_ACE_TYPE => {
            if flags & FAILED_ACCESS_ACE_FLAG != 0 {
                Some(SET_AUDIT_FAILURE)
            } else {
                Some(SET_AUDIT_SUCCESS)
            }
        }
        _ => None,
    }
}

/// Where the SID starts in the ACE at `at` in `acl`, when the kind is one the lists take: past the
/// header and mask, and past the GUIDs an object ACE carries (an object ACE that names GUIDs
/// lists nothing).
fn ace_sid_offset(acl: &[u8], at: usize, kind: u8) -> Option<usize> {
    use crate::acl::{
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        KNOWN_ACE_FIXED,
        SYSTEM_ALARM_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    };
    match kind {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_DENIED_ACE_TYPE
        | SYSTEM_AUDIT_ACE_TYPE
        | SYSTEM_ALARM_ACE_TYPE => Some(KNOWN_ACE_FIXED),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | SYSTEM_AUDIT_OBJECT_ACE_TYPE
        | SYSTEM_ALARM_OBJECT_ACE_TYPE => {
            let flags = dword(acl, at + 8).unwrap_or(0);
            if flags
                & (crate::acl::ACE_OBJECT_TYPE_PRESENT
                    | crate::acl::ACE_INHERITED_OBJECT_TYPE_PRESENT)
                != 0
            {
                None
            } else {
                Some(object_ace_sid_offset(flags))
            }
        }
        _ => None,
    }
}

/// A SID-form TRUSTEE pointing at `sid`'s address, in `bytes` (a TRUSTEE-sized slice).
fn sid_trustee(bytes: &mut [u8], sid: usize) {
    bytes.fill(0);
    set_ptr_field(bytes, TRUSTEE_MULTIPLE, 0);
    set_dword_local(bytes, TRUSTEE_OP, 0);
    set_dword_local(bytes, TRUSTEE_FORM, FORM_SID);
    set_dword_local(bytes, TRUSTEE_TYPE, 0);
    set_ptr_field(bytes, TRUSTEE_NAME, sid);
}

/// A dword in a byte slice, when it fits.
fn set_dword_local(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = bytes.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// The descriptor's owner or group as a heap TRUSTEE of the SID form, pointing at a copy of the
/// SID in the same block: its address, or null when there is no room. The block is the caller's
/// to free.
fn sid_trustee_block(sid: &[u8]) -> usize {
    let size = TRUSTEE_SIZE + sid.len();
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        return 0;
    }
    // SAFETY: the block is ours, of `size` bytes.
    unsafe {
        let bytes = core::slice::from_raw_parts_mut(block, size);
        let (trustee, sid_copy) = bytes.split_at_mut(TRUSTEE_SIZE);
        sid_trustee(trustee, block as usize + TRUSTEE_SIZE);
        sid_copy.copy_from_slice(sid);
    }
    block as usize
}

/// The ACL's entries as a heap EXPLICIT_ACCESS array, each entry's trustee a SID-form trustee
/// pointing at a copy of the ACE's SID laid out after the array: the array's address and the
/// count. A missing or empty ACL answers (0, 0); no room answers (0, 0) with the last error set.
fn entries_block(acl: Option<&[u8]>) -> (usize, u32) {
    let Some(acl) = acl else {
        return (0, 0);
    };
    // First pass: how many entries and how many SID bytes they need.
    let mut kept = 0u32;
    let mut sid_bytes = 0usize;
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(acl) {
        let Some(size) = word(acl, at + ACE_SIZE_OFF).map(|size| size as usize) else {
            break;
        };
        if size < ACE_HEADER {
            break;
        }
        let kind = *acl.get(at + ACE_TYPE_OFF).unwrap_or(&0xFF);
        let flags = u32::from(*acl.get(at + ACE_FLAGS_OFF).unwrap_or(&0));
        if entry_mode(kind, flags).is_some() {
            if let Some(offset) = ace_sid_offset(acl, at, kind) {
                if let Some(sid) = sid_at(acl, at + offset) {
                    kept += 1;
                    sid_bytes += sid.len();
                }
            }
        }
        at += size;
    }
    if kept == 0 {
        return (0, 0);
    }
    let size = kept as usize * ENTRY_SIZE + sid_bytes;
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return (0, 0);
    }
    // Second pass: the entries, then the SID copies after them.
    // SAFETY: the block is ours, of `size` bytes.
    unsafe {
        let bytes = core::slice::from_raw_parts_mut(block, size);
        let entries = bytes.as_mut_ptr();
        let mut sid_place = kept as usize * ENTRY_SIZE;
        let mut written = 0u32;
        let mut at = ACL_HEADER;
        for _ in 0..ace_count(acl) {
            let Some(size) = word(acl, at + ACE_SIZE_OFF).map(|size| size as usize) else {
                break;
            };
            if size < ACE_HEADER {
                break;
            }
            let kind = *acl.get(at + ACE_TYPE_OFF).unwrap_or(&0xFF);
            let flags = u32::from(*acl.get(at + ACE_FLAGS_OFF).unwrap_or(&0));
            let mask = dword(acl, at + ACE_MASK_OFF).unwrap_or(0);
            let mode = entry_mode(kind, flags);
            let offset = ace_sid_offset(acl, at, kind);
            let sid = offset.and_then(|offset| sid_at(acl, at + offset));
            if let (Some(mode), Some(sid)) = (mode, sid) {
                let entry = ExplicitAccess {
                    grf_access_permissions: mask,
                    grf_access_mode: mode,
                    grf_inheritance: flags,
                    trustee: Trustee {
                        p_multiple_trustee: 0,
                        multiple_trustee_operation: 0,
                        trustee_form: FORM_SID,
                        trustee_type: 0,
                        ptstr_name: block as usize + sid_place,
                    },
                };
                core::ptr::write_unaligned(
                    entries.add(written as usize * ENTRY_SIZE).cast(),
                    entry,
                );
                bytes[sid_place..sid_place + sid.len()].copy_from_slice(sid);
                sid_place += sid.len();
                written += 1;
            }
            at += size;
        }
    }
    (block as usize, kept)
}

/// LookupSecurityDescriptorPartsA/W's body: the descriptor's parts into the caller's places.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[allow(clippy::too_many_arguments)]
unsafe fn lookup_parts(
    pp_owner: *mut usize,
    pp_group: *mut usize,
    pc_access: *mut u32,
    pp_access: *mut usize,
    pc_audit: *mut u32,
    pp_audit: *mut usize,
    sd: *const u8,
) -> u32 {
    if sd.is_null()
        || (pc_access.is_null() != pp_access.is_null())
        || (pc_audit.is_null() != pp_audit.is_null())
    {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the caller's descriptor.
    let Some(buffer) = (unsafe { caller_sd(sd) }) else {
        return fail(ERROR_INVALID_SECURITY_DESCR);
    };
    let base = sd as usize;
    // SAFETY: the descriptor was read as valid.
    let components = unsafe { sd_components(base, buffer) };
    // The owner and group as SID-form trustees (a null place for a part the descriptor lacks).
    for (place, component) in [
        (pp_owner, components[FIELD_OWNER]),
        (pp_group, components[FIELD_GROUP]),
    ] {
        if place.is_null() {
            continue;
        }
        let value = component.map_or(0, sid_trustee_block);
        // SAFETY: the caller's place.
        if let Some(mut out) = unsafe { Out::optional(place) } {
            out.set(value);
        }
    }
    // The access and audit entry lists.
    for (count, list, component) in [
        (pc_access, pp_access, components[FIELD_DACL]),
        (pc_audit, pp_audit, components[FIELD_SACL]),
    ] {
        if list.is_null() {
            continue;
        }
        let (address, found) = entries_block(component);
        // SAFETY: the caller's places.
        unsafe {
            if let Some(mut count) = Out::optional(count) {
                count.set(found);
            }
            if let Some(mut list) = Out::optional(list) {
                list.set(address);
            }
        }
    }
    0
}

/// LookupSecurityDescriptorPartsA: the descriptor's parts into the caller's places (heap blocks
/// to free). The return is the Win32 error code.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_LookupSecurityDescriptorPartsA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn lookup_security_descriptor_parts_a(
    pp_owner: *mut usize,
    pp_group: *mut usize,
    pc_access: *mut u32,
    pp_access: *mut usize,
    pc_audit: *mut u32,
    pp_audit: *mut usize,
    sd: *const u8,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe {
        lookup_parts(
            pp_owner, pp_group, pc_access, pp_access, pc_audit, pp_audit, sd,
        )
    }
}

/// LookupSecurityDescriptorPartsW: as the A form (the parts are SID-form trustees either way).
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_LookupSecurityDescriptorPartsW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn lookup_security_descriptor_parts_w(
    pp_owner: *mut usize,
    pp_group: *mut usize,
    pc_access: *mut u32,
    pp_access: *mut usize,
    pc_audit: *mut u32,
    pp_audit: *mut usize,
    sd: *const u8,
) -> u32 {
    // SAFETY: as the A form's.
    unsafe {
        lookup_parts(
            pp_owner, pp_group, pc_access, pp_access, pc_audit, pp_audit, sd,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::exports::{add_access_allowed_ace, add_audit_access_ace, initialize_acl};
    use crate::explicit::tests_support::sid;
    use crate::sd::{
        initialize_security_descriptor,
        make_self_relative_sd,
        set_security_descriptor_dacl,
        set_security_descriptor_group,
        set_security_descriptor_owner,
        set_security_descriptor_sacl,
    };
    use crate::sid::ptr_field;
    use crate::testkit::{arm, last_error};

    /// A self-relative descriptor with the owner, group, DACL and SACL given, in a buffer.
    fn make_sd(owner: &[u8], group: &[u8], dacl: &[u8], sacl: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        assert_eq!(
            unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), owner.as_ptr(), 0) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_group(buf.as_mut_ptr(), group.as_ptr(), 0) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_dacl(buf.as_mut_ptr(), 1, dacl.as_ptr(), 0) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_sacl(buf.as_mut_ptr(), 1, sacl.as_ptr(), 0) },
            1
        );
        let mut rel = vec![0u8; 1024];
        let mut len = 1024u32;
        assert_eq!(
            unsafe { make_self_relative_sd(buf.as_ptr(), rel.as_mut_ptr(), &mut len) },
            1
        );
        rel.truncate(len as usize);
        rel
    }

    /// An ACL with the ACEs added, truncated to its header's size.
    fn make_acl(aces: &[(u8, u32, u32, &[u8])]) -> Vec<u8> {
        let mut acl = vec![0u8; 256];
        assert_eq!(unsafe { initialize_acl(acl.as_mut_ptr(), 256, 2) }, 1);
        for (kind, flags, mask, sid) in aces {
            let ok = match *kind {
                0 => unsafe { add_access_allowed_ace(acl.as_mut_ptr(), 2, *mask, sid.as_ptr()) },
                2 => unsafe {
                    add_audit_access_ace(acl.as_mut_ptr(), 2, *mask, sid.as_ptr(), *flags, 0)
                },
                _ => unreachable!(),
            };
            assert_eq!(ok, 1);
        }
        let size = usize::from(crate::acl::word(&acl, crate::acl::ACL_SIZE_OFF).unwrap());
        acl.truncate(size);
        acl
    }

    /// LookupSecurityDescriptorParts hands out the descriptor's parts: the owner and group as
    /// SID-form trustees pointing at copies of the SIDs, the DACL's and SACL's ACEs as
    /// EXPLICIT_ACCESS arrays with SID-form trustees, the counts set; ERROR_SUCCESS returned,
    /// the last error untouched. A part the descriptor lacks answers null and zero.
    #[test]
    fn the_parts_come_out_of_the_descriptor() {
        let admins = sid(5, &[32, 544]);
        let everyone = sid(1, &[0]);
        let dacl = make_acl(&[(0, 0, 0x000F_01FF, &everyone)]);
        let sacl = make_acl(&[(2, 0x40, 0x1234, &admins)]);
        let sd = make_sd(&admins, &everyone, &dacl, &sacl);
        let mut owner = 0xF2F2usize;
        let mut group = 0xF2F2usize;
        let mut access_count = 0xF2F2u32;
        let mut access_list = 0xF2F2usize;
        let mut audit_count = 0xF2F2u32;
        let mut audit_list = 0xF2F2usize;
        arm();
        let code = unsafe {
            lookup_security_descriptor_parts_a(
                &mut owner,
                &mut group,
                &mut access_count,
                &mut access_list,
                &mut audit_count,
                &mut audit_list,
                sd.as_ptr(),
            )
        };
        assert_eq!((code, last_error()), (0, 0xF2F2));
        assert_eq!((access_count, audit_count), (1, 1));
        // The owner trustee: the SID form, its name the SID copy after the trustee.
        let owner_bytes =
            unsafe { core::slice::from_raw_parts(owner as *const u8, TRUSTEE_SIZE + admins.len()) };
        assert_eq!(dword(owner_bytes, TRUSTEE_FORM), Some(FORM_SID));
        let name = ptr_field(owner_bytes, TRUSTEE_NAME).unwrap();
        assert_eq!(name, owner + TRUSTEE_SIZE);
        assert_eq!(&owner_bytes[TRUSTEE_SIZE..], admins.as_slice());
        // The group trustee likewise.
        let group_bytes = unsafe {
            core::slice::from_raw_parts(group as *const u8, TRUSTEE_SIZE + everyone.len())
        };
        assert_eq!(dword(group_bytes, TRUSTEE_FORM), Some(FORM_SID));
        assert_eq!(&group_bytes[TRUSTEE_SIZE..], everyone.as_slice());
        // The access entry: the mask, GRANT_ACCESS, the ACE's flags, a SID-form trustee whose
        // name is the SID copy after the array.
        let entry = unsafe { core::ptr::read_unaligned(access_list as *const ExplicitAccess) };
        assert_eq!(entry.grf_access_permissions, 0x000F_01FF);
        assert_eq!(entry.grf_access_mode, GRANT_ACCESS);
        assert_eq!(entry.trustee.trustee_form, FORM_SID);
        let sid_copy = entry.trustee.ptstr_name;
        assert_eq!(sid_copy, access_list + ENTRY_SIZE);
        let sid_bytes =
            unsafe { core::slice::from_raw_parts(sid_copy as *const u8, everyone.len()) };
        assert_eq!(sid_bytes, everyone.as_slice());
        // The audit entry: SET_AUDIT_SUCCESS for the successful flag.
        let audit = unsafe { core::ptr::read_unaligned(audit_list as *const ExplicitAccess) };
        assert_eq!(audit.grf_access_mode, SET_AUDIT_SUCCESS);
        assert_eq!(audit.grf_access_permissions, 0x1234);
        // The W form answers the same.
        let mut owner = 0usize;
        let mut group = 0usize;
        let mut access_count = 0u32;
        let mut access_list = 0usize;
        let mut audit_count = 0u32;
        let mut audit_list = 0usize;
        let code = unsafe {
            lookup_security_descriptor_parts_w(
                &mut owner,
                &mut group,
                &mut access_count,
                &mut access_list,
                &mut audit_count,
                &mut audit_list,
                sd.as_ptr(),
            )
        };
        assert_eq!(
            (code, owner != 0, group != 0, access_count, audit_count),
            (0, true, true, 1, 1)
        );
    }

    /// A descriptor without a DACL or SACL: the counts zero and the lists null, the owner and
    /// group still out; a null descriptor, or a count without its list, is ERROR_INVALID_PARAMETER
    /// (returned and set as the last error).
    #[test]
    fn missing_parts_and_bad_arguments_answer() {
        let admins = sid(5, &[32, 544]);
        let empty = make_acl(&[]);
        let _ = make_sd(&admins, &admins, &empty, &empty);
        // No DACL: build one without the present flag.
        let mut buf = vec![0u8; 1024];
        assert_eq!(
            unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_owner(buf.as_mut_ptr(), admins.as_ptr(), 0) },
            1
        );
        let mut rel = vec![0u8; 1024];
        let mut len = 1024u32;
        assert_eq!(
            unsafe { make_self_relative_sd(buf.as_ptr(), rel.as_mut_ptr(), &mut len) },
            1
        );
        rel.truncate(len as usize);
        let mut owner = 0xF2F2usize;
        let mut access_count = 0xF2F2u32;
        let mut access_list = 0xF2F2usize;
        arm();
        let code = unsafe {
            lookup_security_descriptor_parts_a(
                &mut owner,
                core::ptr::null_mut(),
                &mut access_count,
                &mut access_list,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                rel.as_ptr(),
            )
        };
        assert_eq!(
            (code, owner != 0, access_count, access_list, last_error()),
            (0, true, 0, 0, 0xF2F2)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    lookup_security_descriptor_parts_a(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null(),
                    )
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    lookup_security_descriptor_parts_a(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        &mut access_count,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        rel.as_ptr(),
                    )
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER),
            "a count with no list"
        );
    }
}
