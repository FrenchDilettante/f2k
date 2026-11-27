//! The ACE builders: the known-type ACEs (allowed, denied, audit, their Ex and object forms) and the compound ACE.

use super::*;

/// Add a known ACE (allowed, denied or audit) to the ACL at `acl`.
pub(crate) fn add_known_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
    new_type: u8,
) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    if unsafe { rtl_valid_sid(sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION || ace_revision > MAX_ACL_REVISION {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    let mut tested = flags & !VALID_INHERIT_FLAGS;
    if tested != 0 {
        if new_type == SYSTEM_AUDIT_ACE_TYPE {
            tested &= !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
        }
        if tested != 0 {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SID's header is readable.
    let sid_len = unsafe { sid_len_of(bytes(sid, SID_HEADER)) };
    let ace_size = 8 + sid_len;
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: new_type,
            ace_flags: flags as u8,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    // SAFETY: the ACE holds the SID; the source is the caller's SID.
    unsafe { bytes_mut((free + 8) as *mut u8, sid_len).copy_from_slice(sid_slice(sid)) };
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// Add an object ACE to the ACL at `acl`, the GUIDs it carries placed before the SID.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_known_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    new_type: u8,
) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    if unsafe { rtl_valid_sid(sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION || ace_revision != MAX_ACL_REVISION {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    let mut tested = flags & !VALID_INHERIT_FLAGS;
    if tested != 0 {
        if new_type == SYSTEM_AUDIT_ACE_TYPE || new_type == SYSTEM_AUDIT_OBJECT_ACE_TYPE {
            tested &= !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
        }
        if tested != 0 {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SID's header is readable.
    let sid_len = unsafe { sid_len_of(bytes(sid, SID_HEADER)) };
    let mut ace_size = 12 + sid_len;
    let mut object_flags = 0;
    if !object_type.is_null() {
        object_flags |= ACE_OBJECT_TYPE_PRESENT;
        ace_size += 16;
    }
    if !inherited_object_type.is_null() {
        object_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
        ace_size += 16;
    }
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: new_type,
            ace_flags: flags as u8,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    set_dword((free + 8) as *mut u8, object_flags);
    let mut at = free + 12;
    // SAFETY: the caller's GUIDs hold 16 bytes each; the ACE holds them and the SID.
    unsafe {
        if !object_type.is_null() {
            bytes_mut(at as *mut u8, 16).copy_from_slice(bytes(object_type, 16));
            at += 16;
        }
        if !inherited_object_type.is_null() {
            bytes_mut(at as *mut u8, 16).copy_from_slice(bytes(inherited_object_type, 16));
            at += 16;
        }
        bytes_mut(at as *mut u8, sid_len).copy_from_slice(sid_slice(sid));
    }
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlAddAccessAllowedAce: an allowed ACE for `sid` appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedAce")]
pub unsafe extern "system" fn rtl_add_access_allowed_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, 0, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
}

/// RtlAddAccessAllowedAceEx: as RtlAddAccessAllowedAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedAceEx")]
pub unsafe extern "system" fn rtl_add_access_allowed_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
}

/// RtlAddAccessAllowedObjectAce: an allowed object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedObjectAce")]
pub unsafe extern "system" fn rtl_add_access_allowed_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddAccessDeniedAce: a denied ACE for `sid` appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedAce")]
pub unsafe extern "system" fn rtl_add_access_denied_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, 0, mask, sid, ACCESS_DENIED_ACE_TYPE)
}

/// RtlAddAccessDeniedAceEx: as RtlAddAccessDeniedAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedAceEx")]
pub unsafe extern "system" fn rtl_add_access_denied_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_DENIED_ACE_TYPE)
}

/// RtlAddAccessDeniedObjectAce: a denied object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedObjectAce")]
pub unsafe extern "system" fn rtl_add_access_denied_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_DENIED_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddAuditAccessAce: an audit ACE appended, its success/failure flags from the booleans.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessAce")]
pub unsafe extern "system" fn rtl_add_audit_access_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    let mut flags = 0;
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
}

/// RtlAddAuditAccessAceEx: as RtlAddAuditAccessAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessAceEx")]
pub unsafe extern "system" fn rtl_add_audit_access_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    mut flags: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
}

/// RtlAddAuditAccessObjectAce: an audit object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessObjectAce")]
pub unsafe extern "system" fn rtl_add_audit_access_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    mut flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddCompoundAce: a compound ACE of the server and client SIDs appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddCompoundAce")]
pub unsafe extern "system" fn rtl_add_compound_ace(
    acl: *mut u8,
    ace_revision: u32,
    compound_type: u8,
    mask: u32,
    server_sid: *const u8,
    client_sid: *const u8,
) -> u32 {
    // SAFETY: the caller's two SIDs, their headers readable.
    if unsafe { rtl_valid_sid(server_sid) } == 0 || unsafe { rtl_valid_sid(client_sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION
        || !(ACL_REVISION3..=MAX_ACL_REVISION).contains(&ace_revision)
    {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SIDs' headers are readable.
    let server_len = unsafe { sid_len_of(bytes(server_sid, SID_HEADER)) };
    let client_len = unsafe { sid_len_of(bytes(client_sid, SID_HEADER)) };
    let ace_size = 12 + client_len + server_len;
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            ace_flags: 0,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    write((free + 8) as *mut u8, compound_type as u16);
    write((free + 10) as *mut u8, 0u16);
    // SAFETY: the ACE holds both SIDs; the sources are the caller's.
    unsafe {
        bytes_mut((free + 12) as *mut u8, server_len).copy_from_slice(sid_slice(server_sid));
        bytes_mut((free + 12 + server_len) as *mut u8, client_len)
            .copy_from_slice(sid_slice(client_sid));
    }
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

    #[test]
    fn adding_aces_checks_their_inputs() {
        let mut buffer = [0u8; 64];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 64, 2) }, STATUS_SUCCESS);
        let sid = admins();
        let mut bad = sid;
        bad[0] = 9;
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, bad.as_ptr()) },
            STATUS_INVALID_SID
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 5, 1, sid.as_ptr()) },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace_ex(acl, 2, 0x20, 1, sid.as_ptr()) },
            STATUS_INVALID_PARAMETER
        );
        // Audit flags are fine on an audit ACE.
        assert_eq!(
            unsafe { rtl_add_audit_access_ace(acl, 2, 1, sid.as_ptr(), 1, 1) },
            STATUS_SUCCESS
        );
        assert_eq!(ace_of((acl as usize + 8) as *const u8).ace_flags, 0xC0);
        // Room: 64 - 8 - 24 = 32 bytes left, one more ACE of 24 fits, the next does not.
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_ALLOTTED_SPACE_EXCEEDED
        );
        // An ill-formed ACL is rejected.
        let mut broken = [0u8; 64];
        broken[0] = 2;
        broken[2..4].copy_from_slice(&64u16.to_le_bytes());
        broken[4..6].copy_from_slice(&1u16.to_le_bytes()); // one ACE, none present
        assert_eq!(unsafe { rtl_valid_acl(broken.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(broken.as_mut_ptr(), 2, 1, sid.as_ptr()) },
            STATUS_INVALID_ACL
        );
    }

    #[test]
    fn an_ace_list_inserts_at_an_index() {
        let mut buffer = [0u8; 128];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 128, 2) }, STATUS_SUCCESS);
        let sid = admins();
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_denied_ace(acl, 2, 2, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        // A one-ACE list inserted at index 0.
        let mut list = [0u8; 24];
        write(
            list.as_mut_ptr(),
            AceHeader {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                ace_flags: 0,
                ace_size: 24,
            },
        );
        set_dword(list.as_mut_ptr().wrapping_add(4), 0x77);
        unsafe { bytes_mut(list.as_mut_ptr().wrapping_add(8), 16).copy_from_slice(&sid) };
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, 0, list.as_ptr(), 24) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).ace_count, 3);
        let mut ace = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 0x77); // the inserted one, at 0
        assert_eq!(unsafe { rtl_get_ace(acl, 2, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 2); // the old denied one, at the end
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // A list that overruns its length is rejected; a type the revision forbids too.
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, MAXULONG, list.as_ptr(), 25) },
            STATUS_INVALID_PARAMETER
        );
        let mut object = [0u8; 48];
        write(
            object.as_mut_ptr(),
            AceHeader {
                ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                ace_flags: 0,
                ace_size: 48,
            },
        );
        // No GUID flags, so the SID sits right after the flags word, at +12.
        unsafe { bytes_mut(object.as_mut_ptr().wrapping_add(12), 16).copy_from_slice(&sid) };
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, MAXULONG, object.as_ptr(), 48) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_add_ace(acl, 4, MAXULONG, object.as_ptr(), 48) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 4);
        assert_eq!(
            unsafe { rtl_add_ace(acl, 4, MAXULONG, list.as_ptr(), 24) },
            STATUS_BUFFER_TOO_SMALL
        );
    }

    #[test]
    fn compound_and_object_aces_append() {
        let mut buffer = [0u8; 256];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 256, 2) }, STATUS_SUCCESS);
        let server = admins();
        let client = world();
        // A compound ACE needs revision 3.
        assert_eq!(
            unsafe { rtl_add_compound_ace(acl, 2, 1, 0x55, server.as_ptr(), client.as_ptr()) },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe { rtl_add_compound_ace(acl, 3, 1, 0x55, server.as_ptr(), client.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 3);
        let ace = (acl as usize + 8) as *const u8;
        assert_eq!(ace_of(ace).ace_type, ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
        assert_eq!(ace_of(ace).ace_size, 12 + 12 + 16);
        assert_eq!(word(ace.wrapping_add(8)), COMPOUND_ACE_IMPERSONATION);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(12)) }, &server[..]);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(12 + 16)) }, &client[..]);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // An object ACE with one GUID needs revision 4.
        let guid = [0xABu8; 16];
        assert_eq!(
            unsafe {
                rtl_add_access_allowed_object_ace(
                    acl,
                    3,
                    0,
                    1,
                    guid.as_ptr(),
                    core::ptr::null(),
                    server.as_ptr(),
                )
            },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe {
                rtl_add_access_allowed_object_ace(
                    acl,
                    4,
                    0,
                    1,
                    guid.as_ptr(),
                    core::ptr::null(),
                    server.as_ptr(),
                )
            },
            STATUS_SUCCESS
        );
        let ace = (acl as usize + 8 + 40) as *const u8;
        assert_eq!(ace_of(ace).ace_type, ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        assert_eq!(ace_of(ace).ace_size, 12 + 16 + 16);
        assert_eq!(dword(ace.wrapping_add(8)), ACE_OBJECT_TYPE_PRESENT);
        assert_eq!(unsafe { bytes(ace.wrapping_add(12), 16) }, &guid[..]);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(28)) }, &server[..]);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // No GUIDs: a plain ACE.
        assert_eq!(
            unsafe {
                rtl_add_access_denied_object_ace(
                    acl,
                    4,
                    0,
                    2,
                    core::ptr::null(),
                    core::ptr::null(),
                    client.as_ptr(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            ace_of((acl as usize + 8 + 40 + 44) as *const u8).ace_type,
            ACCESS_DENIED_ACE_TYPE
        );
    }
}

