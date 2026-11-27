//! The ACL helpers: create, validate, query and set its information, and the ACE list edits.

use super::*;

// --- ACL and ACE helpers ----------------------------------------------------------------

/// The ACL header at `at`.
pub(crate) fn acl_of(at: *const u8) -> Acl {
    read::<Acl>(at)
}

/// The ACE header at `at`.
pub(crate) fn ace_of(at: *const u8) -> AceHeader {
    read::<AceHeader>(at)
}

/// Whether the SID header at `at` is well formed; `at` must hold eight readable bytes.
pub(crate) fn sid_head_ok(at: usize) -> bool {
    // SAFETY: the caller's ACE holds the SID header at `at`.
    let h = unsafe { bytes(at as *const u8, SID_HEADER) };
    h[0] == SID_REVISION && h[1] <= SID_MAX_SUB_AUTHORITIES
}

/// Whether the ACL at `at` is structurally valid: its revision, size and every ACE in it.
pub(crate) fn valid_acl(at: *const u8) -> bool {
    let header = acl_of(at);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return false;
    }
    if !header.size.is_multiple_of(2) || header.size < 8 {
        return false;
    }
    let base = at as usize;
    let end = base + usize::from(header.size);
    let mut offset = 8;
    for _ in 0..header.ace_count {
        let ace = base + offset;
        if ace + 4 >= end {
            return false;
        }
        let head = ace_of(ace as *const u8);
        if !head.ace_size.is_multiple_of(2) || ace + usize::from(head.ace_size) > end {
            return false;
        }
        match head.ace_type {
            // A known ACE: header, mask, then the SID, all inside the ACE.
            0..=3 => {
                if !head.ace_size.is_multiple_of(4) || !sid_head_ok(ace + 8) {
                    return false;
                }
                // SAFETY: the ACE holds the SID's header.
                let len = sid_len_of(unsafe { bytes((ace + 8) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 8 + len {
                    return false;
                }
            }
            // A compound ACE: two SIDs after the compound type.
            4 => {
                if u32::from(header.revision) < ACL_REVISION3
                    || !head.ace_size.is_multiple_of(4)
                    || head.ace_size < 24
                    || word((ace + 8) as *const u8) != COMPOUND_ACE_IMPERSONATION
                    || !sid_head_ok(ace + 12)
                {
                    return false;
                }
                // SAFETY: the ACE holds the first SID.
                let len1 = sid_len_of(unsafe { bytes((ace + 12) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + len1 + 12 || !sid_head_ok(ace + 12 + len1) {
                    return false;
                }
                // SAFETY: the ACE holds the second SID's header.
                let len2 = sid_len_of(unsafe { bytes((ace + 12 + len1) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + len1 + len2 {
                    return false;
                }
            }
            // An object ACE: its flags say which GUIDs it carries before the SID.
            5..=8 => {
                if u32::from(header.revision) < MAX_ACL_REVISION || !head.ace_size.is_multiple_of(4)
                {
                    return false;
                }
                let flags = dword((ace + 8) as *const u8);
                let mut guids = 0;
                if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    guids += 16;
                }
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    guids += 16;
                }
                let sid = ace + 12 + guids;
                if usize::from(head.ace_size) < 12 + guids + SID_HEADER || !sid_head_ok(sid) {
                    return false;
                }
                // SAFETY: the ACE holds the SID's header.
                let len = sid_len_of(unsafe { bytes(sid as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + guids + len {
                    return false;
                }
            }
            _ => {}
        }
        offset += usize::from(head.ace_size);
    }
    true
}

/// The first free byte in the ACL at `at`: `None` when the ACL is ill-formed, `Some(None)` when
/// it is full, else `Some(Some(address))`.
pub(crate) fn first_free(at: *const u8) -> Option<Option<usize>> {
    let header = acl_of(at);
    let base = at as usize;
    let end = base + usize::from(header.size);
    let mut offset = 8;
    for _ in 0..header.ace_count {
        let ace = base + offset;
        if ace >= end {
            return None;
        }
        offset += usize::from(ace_of(ace as *const u8).ace_size);
    }
    Some(if base + offset <= end {
        Some(base + offset)
    } else {
        None
    })
}

/// Shift the `to_size` bytes at `to` up by `from_size`, then copy `from` over the front.
///
/// # Safety
///
/// `to` holds `to_size + from_size` writable bytes, `from` holds `from_size` readable ones.
pub(crate) unsafe fn add_data(from: *const u8, from_size: usize, to: *mut u8, to_size: usize) {
    // SAFETY: the caller's contract; the ranges overlap, so a memmove.
    unsafe { core::ptr::copy(to, to.add(from_size), to_size) };
    // SAFETY: the caller's contract; the ranges no longer overlap.
    unsafe { core::ptr::copy_nonoverlapping(from, to, from_size) };
}

/// Remove `remove_size` bytes at `data` from a run of `total_size`, zeroing the tail.
///
/// # Safety
///
/// `data` holds `total_size` writable bytes.
pub(crate) unsafe fn delete_data(data: *mut u8, remove_size: usize, total_size: usize) {
    // SAFETY: the caller's contract; the ranges overlap, so a memmove.
    unsafe { core::ptr::copy(data.add(remove_size), data, total_size - remove_size) };
    // SAFETY: the caller's contract.
    unsafe { core::ptr::write_bytes(data.add(total_size - remove_size), 0, remove_size) };
}

/// RtlCreateAcl: an empty ACL of `length` bytes at `acl`, at `revision`.
#[unsafe(export_name = "f2k_export_RtlCreateAcl")]
pub unsafe extern "system" fn rtl_create_acl(acl: *mut u8, length: u32, revision: u32) -> u32 {
    if length < 8 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&revision) || length > 0xFFFF {
        return STATUS_INVALID_PARAMETER;
    }
    write(
        acl,
        Acl {
            revision: revision as u8,
            sbz1: 0,
            size: (length & 0xfffc) as u16,
            ace_count: 0,
            sbz2: 0,
        },
    );
    STATUS_SUCCESS
}

/// RtlValidAcl: whether the ACL at `acl` is structurally valid.
#[unsafe(export_name = "f2k_export_RtlValidAcl")]
pub unsafe extern "system" fn rtl_valid_acl(acl: *const u8) -> u32 {
    u32::from(valid_acl(acl))
}

/// RtlQueryInformationAcl: the ACL's revision or size information into `info`.
#[unsafe(export_name = "f2k_export_RtlQueryInformationAcl")]
pub unsafe extern "system" fn rtl_query_information_acl(
    acl: *const u8,
    info: *mut u8,
    info_length: u32,
    class: u32,
) -> u32 {
    let header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    match class {
        ACL_REVISION_INFORMATION => {
            if info_length < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            set_dword(info, u32::from(header.revision));
        }
        ACL_SIZE_INFORMATION => {
            if info_length < 12 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            let Some(free) = first_free(acl) else {
                return STATUS_INVALID_PARAMETER;
            };
            let in_use = free.map_or(usize::from(header.size), |at| at - acl as usize);
            set_dword(info, u32::from(header.ace_count));
            set_dword(info.wrapping_add(4), in_use as u32);
            set_dword(info.wrapping_add(8), header.size as u32 - in_use as u32);
        }
        _ => return STATUS_INVALID_INFO_CLASS,
    }
    STATUS_SUCCESS
}

/// RtlSetInformationAcl: set the ACL's revision (never lowered) from `info`.
#[unsafe(export_name = "f2k_export_RtlSetInformationAcl")]
pub unsafe extern "system" fn rtl_set_information_acl(
    acl: *mut u8,
    info: *const u8,
    info_length: u32,
    class: u32,
) -> u32 {
    let mut header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    match class {
        ACL_REVISION_INFORMATION => {
            if info_length < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            let revision = dword(info);
            if revision < u32::from(header.revision) {
                return STATUS_INVALID_PARAMETER;
            }
            header.revision = revision as u8;
            write(acl, header);
        }
        _ => return STATUS_INVALID_INFO_CLASS,
    }
    STATUS_SUCCESS
}

/// RtlAddAce: the ACE list at `ace_list` inserted into the ACL at `starting_index` (the end when
/// `MAXULONG`).
#[unsafe(export_name = "f2k_export_RtlAddAce")]
pub unsafe extern "system" fn rtl_add_ace(
    acl: *mut u8,
    ace_revision: u32,
    starting_index: u32,
    ace_list: *const u8,
    ace_list_length: u32,
) -> u32 {
    if !valid_acl(acl) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_PARAMETER;
    };
    let header = acl_of(acl);
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    // Walk the list: well formed (it ends exactly at its length), each type allowed by the
    // revision.
    let list = ace_list as usize;
    let end = list + ace_list_length as usize;
    let mut at = list;
    let mut count = 0u32;
    while at < end {
        let head = ace_of(at as *const u8);
        match head.ace_type {
            0..=3 => {}
            4 if ace_revision < ACL_REVISION3 => return STATUS_INVALID_PARAMETER,
            5..=8 if ace_revision < MAX_ACL_REVISION => return STATUS_INVALID_PARAMETER,
            _ => {}
        }
        at += usize::from(head.ace_size);
        count += 1;
    }
    if at > end {
        return STATUS_INVALID_PARAMETER;
    }
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_list_length as usize > acl as usize + usize::from(header.size) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // The insert position: `starting_index` ACEs in, capped at the count.
    let mut position = acl as usize + 8;
    for _ in 0..starting_index.min(u32::from(header.ace_count)) {
        position += usize::from(ace_of(position as *const u8).ace_size);
    }
    // SAFETY: the list fits (checked above); the tail moves within the ACL.
    unsafe {
        add_data(
            ace_list,
            ace_list_length as usize,
            position as *mut u8,
            free - position,
        )
    };
    let mut header = acl_of(acl);
    header.ace_count += count as u16;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlDeleteAce: the ACE at `index` removed from the ACL.
#[unsafe(export_name = "f2k_export_RtlDeleteAce")]
pub unsafe extern "system" fn rtl_delete_ace(acl: *mut u8, index: u32) -> u32 {
    if !valid_acl(acl) {
        return STATUS_INVALID_PARAMETER;
    }
    let header = acl_of(acl);
    if index >= u32::from(header.ace_count) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_PARAMETER;
    };
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    let mut at = acl as usize + 8;
    for _ in 0..index {
        at += usize::from(ace_of(at as *const u8).ace_size);
    }
    let size = usize::from(ace_of(at as *const u8).ace_size);
    // SAFETY: the ACE is inside the ACL, the run up to the first free byte too.
    unsafe { delete_data(at as *mut u8, size, free - at) };
    let mut header = acl_of(acl);
    header.ace_count -= 1;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlGetAce: the address of the ACE at `index`, written to `ace`.
#[unsafe(export_name = "f2k_export_RtlGetAce")]
pub unsafe extern "system" fn rtl_get_ace(acl: *const u8, index: u32, ace: *mut *mut u8) -> u32 {
    let header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    if index >= u32::from(header.ace_count) {
        return STATUS_INVALID_PARAMETER;
    }
    let base = acl as usize;
    let end = base + usize::from(header.size);
    let mut at = base + 8;
    for _ in 0..index {
        if at >= end {
            return STATUS_INVALID_PARAMETER;
        }
        at += usize::from(ace_of(at as *const u8).ace_size);
    }
    if at >= end {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's out parameter.
    unsafe { ace.write_unaligned(at as *mut u8) };
    STATUS_SUCCESS
}

/// RtlFirstFreeAce: the address of the first free byte in the ACL, written to `first_free`;
/// false when the ACL is ill-formed.
#[unsafe(export_name = "f2k_export_RtlFirstFreeAce")]
pub unsafe extern "system" fn rtl_first_free_ace(acl: *const u8, out: *mut *mut u8) -> u32 {
    match first_free(acl) {
        None => 0,
        Some(free) => {
            // SAFETY: the caller's out parameter.
            unsafe { out.write_unaligned(free.map_or(core::ptr::null_mut(), |at| at as *mut u8)) };
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

    #[test]
    fn an_acl_creates_validates_and_edits_aces() {
        let mut buffer = [0u8; 128];
        let acl = buffer.as_mut_ptr();
        assert_eq!(
            unsafe { rtl_create_acl(acl, 7, 2) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 64, 1) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 64, 5) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 0x1_0004, 2) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(unsafe { rtl_create_acl(acl, 66, 2) }, STATUS_SUCCESS);
        let header = acl_of(acl);
        assert_eq!((header.revision, header.size, header.ace_count), (2, 64, 0));
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // An allowed ACE for the admins, then a denied one for Everyone.
        let sid = admins();
        let everyone = world();
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 0x1234, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_denied_ace(acl, 2, 0xFF, everyone.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!((acl_of(acl).ace_count, acl_of(acl).size), (2, 64));
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // Get them back: the first at acl+8, the second past it (24 then 20 bytes).
        let mut ace = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace as usize - acl as usize, 8);
        assert_eq!(
            ace_of(ace as *const u8),
            AceHeader {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                ace_flags: 0,
                ace_size: 24,
            }
        );
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 0x1234);
        assert_eq!(
            unsafe { sid_slice((ace as *const u8).wrapping_add(8)) },
            &sid[..]
        );
        assert_eq!(unsafe { rtl_get_ace(acl, 1, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace_of(ace as *const u8).ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(
            unsafe { rtl_get_ace(acl, 2, &mut ace) },
            STATUS_INVALID_PARAMETER
        );
        // First free is past the second ACE; size info says so.
        let mut free = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_first_free_ace(acl, &mut free) }, 1);
        assert_eq!(free as usize - acl as usize, 8 + 24 + 20);
        let mut info = [0u8; 12];
        assert_eq!(
            unsafe { rtl_query_information_acl(acl, info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION) },
            STATUS_SUCCESS
        );
        assert_eq!(&info, &[2, 0, 0, 0, 52, 0, 0, 0, 12, 0, 0, 0]);
        assert_eq!(
            unsafe {
                rtl_query_information_acl(acl, info.as_mut_ptr(), 4, ACL_REVISION_INFORMATION)
            },
            STATUS_SUCCESS
        );
        assert_eq!(&info[..4], &[2, 0, 0, 0]);
        assert_eq!(
            unsafe { rtl_query_information_acl(acl, info.as_mut_ptr(), 12, 7) },
            STATUS_INVALID_INFO_CLASS
        );
        // Set the revision up to 4, not down.
        let revision = 4u32;
        assert_eq!(
            unsafe {
                rtl_set_information_acl(
                    acl,
                    revision.to_le_bytes().as_ptr(),
                    4,
                    ACL_REVISION_INFORMATION,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 4);
        let low = 2u32;
        assert_eq!(
            unsafe {
                rtl_set_information_acl(
                    acl,
                    low.to_le_bytes().as_ptr(),
                    4,
                    ACL_REVISION_INFORMATION,
                )
            },
            STATUS_INVALID_PARAMETER
        );
        // Delete the first ACE: the second moves up.
        assert_eq!(unsafe { rtl_delete_ace(acl, 0) }, STATUS_SUCCESS);
        assert_eq!(acl_of(acl).ace_count, 1);
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace_of(ace as *const u8).ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        assert_eq!(unsafe { rtl_delete_ace(acl, 1) }, STATUS_INVALID_PARAMETER);
    }
}

