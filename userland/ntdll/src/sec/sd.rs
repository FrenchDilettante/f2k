//! The security-descriptor helpers: create, validate, length, control and attribute bits, the owner/group/SACL/DACL get and set, and RtlCreateAndSetSD.

use super::*;

// --- Security descriptor helpers ----------------------------------------------------------

/// The control word of the SD at `at`.
pub(crate) fn sd_control(at: *const u8) -> u16 {
    word(at.wrapping_add(2))
}

/// The four component fields of the SD at `at`: dword offsets when self-relative, pointers
/// otherwise (read in the form the control bits say, so a relative SD is not over-read).
pub(crate) fn sd_fields(at: *const u8) -> [usize; 4] {
    if sd_control(at) & SE_SELF_RELATIVE != 0 {
        let rel: SecurityDescriptorRelative = read(at);
        [
            rel.owner as usize,
            rel.group as usize,
            rel.sacl as usize,
            rel.dacl as usize,
        ]
    } else {
        let abs: SecurityDescriptor = read(at);
        [abs.owner, abs.group, abs.sacl, abs.dacl]
    }
}

/// The address of the component `field` of the SD at `base`: an offset when self-relative.
pub(crate) fn sd_addr(base: usize, field: usize, self_relative: bool) -> usize {
    if self_relative {
        base + field
    } else {
        field
    }
}

/// The SD's components: their addresses and their long-aligned sizes (zero when absent). The
/// fields are owner, group, SACL, DACL; the first two are SIDs, the last two ACLs.
pub(crate) fn query_sd(at: *const u8) -> ([usize; 4], [usize; 4]) {
    let self_relative = sd_control(at) & SE_SELF_RELATIVE != 0;
    let base = at as usize;
    let fields = sd_fields(at);
    let mut addrs = [0usize; 4];
    let mut sizes = [0usize; 4];
    for index in 0..4 {
        if fields[index] != 0 {
            let addr = sd_addr(base, fields[index], self_relative);
            addrs[index] = addr;
            // SAFETY: the component's header is readable.
            let len = unsafe {
                if index < 2 {
                    sid_len_of(bytes(addr as *const u8, SID_HEADER))
                } else {
                    usize::from(acl_of(addr as *const u8).size)
                }
            };
            sizes[index] = (len + 3) & !3;
        }
    }
    (addrs, sizes)
}

/// Validate an offset into a self-relative SD of `length` bytes holding at least `min` bytes:
/// the room left, or none when the offset is inside the header, past the end, short or
/// unaligned.
pub(crate) fn sd_offset_ok(offset: u32, length: u32, min: u32) -> Option<u32> {
    if offset < 20 || offset >= length || length - offset < min || !offset.is_multiple_of(4) {
        return None;
    }
    Some(length - offset)
}

/// RtlCreateSecurityDescriptor: an empty absolute SD at `sd`, at `revision` (1).
#[unsafe(export_name = "f2k_export_RtlCreateSecurityDescriptor")]
pub unsafe extern "system" fn rtl_create_security_descriptor(sd: *mut u8, revision: u32) -> u32 {
    if revision != u32::from(SECURITY_DESCRIPTOR_REVISION) {
        return STATUS_UNKNOWN_REVISION;
    }
    // SAFETY: the caller's buffer holds a SECURITY_DESCRIPTOR.
    unsafe { core::ptr::write_bytes(sd, 0, core::mem::size_of::<SecurityDescriptor>()) };
    write(
        sd,
        SecurityDescriptor::<usize> {
            revision: SECURITY_DESCRIPTOR_REVISION,
            ..Default::default()
        },
    );
    STATUS_SUCCESS
}

/// RtlValidSecurityDescriptor: whether the SD at `sd` is structurally valid.
#[unsafe(export_name = "f2k_export_RtlValidSecurityDescriptor")]
pub unsafe extern "system" fn rtl_valid_security_descriptor(sd: *const u8) -> u32 {
    if read::<u8>(sd) != SECURITY_DESCRIPTOR_REVISION {
        return 0;
    }
    let self_relative = sd_control(sd) & SE_SELF_RELATIVE != 0;
    let base = sd as usize;
    for (index, field) in sd_fields(sd).iter().enumerate() {
        if *field == 0 {
            continue;
        }
        let at = sd_addr(base, *field, self_relative);
        // SAFETY: the component is the caller's.
        let ok = unsafe {
            if index < 2 {
                rtl_valid_sid(at as *const u8) == 1
            } else {
                valid_acl(at as *const u8)
            }
        };
        if !ok {
            return 0;
        }
    }
    1
}

/// RtlValidRelativeSecurityDescriptor: whether the self-relative SD of `length` bytes at `sd`
/// holds its components within its buffer, and the ones `required` names.
#[unsafe(export_name = "f2k_export_RtlValidRelativeSecurityDescriptor")]
pub unsafe extern "system" fn rtl_valid_relative_security_descriptor(
    sd: *const u8,
    length: u32,
    required: u32,
) -> u32 {
    if length < 20 {
        return 0;
    }
    let rel: SecurityDescriptorRelative = read(sd);
    if rel.revision != SECURITY_DESCRIPTOR_REVISION || rel.control & SE_SELF_RELATIVE == 0 {
        return 0;
    }
    let base = sd as usize;
    for (index, offset) in [rel.owner, rel.group].iter().enumerate() {
        if *offset == 0 {
            if required & [OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION][index] != 0 {
                return 0;
            }
            continue;
        }
        let Some(max) = sd_offset_ok(*offset, length, SID_HEADER as u32) else {
            return 0;
        };
        let sid = base + *offset as usize;
        if !sid_head_ok(sid) {
            return 0;
        }
        // SAFETY: the SD holds the SID's header.
        let len = sid_len_of(unsafe { bytes(sid as *const u8, SID_HEADER) });
        if max < len as u32 {
            return 0;
        }
    }
    for (index, offset) in [rel.sacl, rel.dacl].iter().enumerate() {
        let present = [SE_SACL_PRESENT, SE_DACL_PRESENT][index];
        if rel.control & present == 0 || *offset == 0 {
            continue;
        }
        let Some(max) = sd_offset_ok(*offset, length, 8) else {
            return 0;
        };
        let acl = base + *offset as usize;
        if max < u32::from(acl_of(acl as *const u8).size) || !valid_acl(acl as *const u8) {
            return 0;
        }
    }
    1
}

/// RtlLengthSecurityDescriptor: the bytes the SD at `sd` takes, its components aligned.
#[unsafe(export_name = "f2k_export_RtlLengthSecurityDescriptor")]
pub unsafe extern "system" fn rtl_length_security_descriptor(sd: *const u8) -> u32 {
    let base = if sd_control(sd) & SE_SELF_RELATIVE != 0 {
        core::mem::size_of::<SecurityDescriptorRelative>()
    } else {
        core::mem::size_of::<SecurityDescriptor>()
    };
    let (_, sizes) = query_sd(sd);
    (base + sizes.iter().sum::<usize>()) as u32
}

/// RtlGetControlSecurityDescriptor: the SD's control word and revision out.
#[unsafe(export_name = "f2k_export_RtlGetControlSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_control_security_descriptor(
    sd: *const u8,
    control: *mut u16,
    revision: *mut u32,
) -> u32 {
    let rev = read::<u8>(sd);
    // SAFETY: the caller's out parameters; the revision is always written.
    unsafe { revision.write_unaligned(u32::from(rev)) };
    if rev != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    // SAFETY: the caller's out parameter.
    unsafe { control.write_unaligned(sd_control(sd)) };
    STATUS_SUCCESS
}

/// RtlSetControlSecurityDescriptor: the control bits of `interest` set to `to_set`.
#[unsafe(export_name = "f2k_export_RtlSetControlSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_control_security_descriptor(
    sd: *mut u8,
    interest: u16,
    to_set: u16,
) -> u32 {
    if interest & !SE_VALID_CONTROL_BITS != 0 || to_set & !interest != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let at = sd.wrapping_add(2);
    write(at, (word(at) & !interest) | to_set);
    STATUS_SUCCESS
}

/// RtlSetAttributesSecurityDescriptor: set the control bits (no bit can be cleared through it),
/// the SD's revision out.
#[unsafe(export_name = "f2k_export_RtlSetAttributesSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_attributes_security_descriptor(
    sd: *mut u8,
    control: u16,
    revision: *mut u32,
) -> u32 {
    let rev = read::<u8>(sd);
    // SAFETY: the caller's out parameter; the revision is always written.
    unsafe { revision.write_unaligned(u32::from(rev)) };
    if rev != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let bits = control & SE_VALID_CONTROL_BITS;
    rtl_set_control_security_descriptor(sd, bits, bits)
}

/// Set the DACL (`dacl` true) or SACL of the absolute SD at `sd`.
pub(crate) fn set_acl_sd(
    sd: *mut u8,
    dacl: bool,
    present_bit: u16,
    defaulted_bit: u16,
    present: u32,
    acl: *const u8,
    defaulted: u32,
) -> u32 {
    let mut view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    if view.control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if present != 0 {
        view.control |= present_bit;
        if dacl {
            view.dacl = acl as usize;
        } else {
            view.sacl = acl as usize;
        }
        view.control &= !defaulted_bit;
        if defaulted != 0 {
            view.control |= defaulted_bit;
        }
    } else {
        view.control &= !present_bit;
    }
    write(sd, view);
    STATUS_SUCCESS
}

/// Get the DACL (`dacl` true) or SACL of the SD at `sd`.
pub(crate) fn get_acl_sd(
    sd: *const u8,
    dacl: bool,
    present_bit: u16,
    defaulted_bit: u16,
    present: *mut u32,
    acl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    let view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let is_present = view.control & present_bit != 0;
    // SAFETY: the caller's out parameter.
    unsafe { present.write_unaligned(u32::from(is_present)) };
    if is_present {
        let self_relative = view.control & SE_SELF_RELATIVE != 0;
        let field = if dacl { view.dacl } else { view.sacl };
        let addr = sd_addr(sd as usize, field, self_relative);
        // SAFETY: the caller's out parameters.
        unsafe {
            acl.write_unaligned(addr as *mut u8);
            defaulted.write_unaligned(u32::from(view.control & defaulted_bit != 0));
        }
    }
    STATUS_SUCCESS
}

/// Set the owner (`owner` true) or group of the absolute SD at `sd`.
pub(crate) fn set_sid_sd(sd: *mut u8, owner: bool, defaulted_bit: u16, sid: *const u8, defaulted: u32) -> u32 {
    let mut view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    if view.control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if owner {
        view.owner = sid as usize;
    } else {
        view.group = sid as usize;
    }
    view.control &= !defaulted_bit;
    if defaulted != 0 {
        view.control |= defaulted_bit;
    }
    write(sd, view);
    STATUS_SUCCESS
}

/// Get the owner (`owner` true) or group of the SD at `sd`.
pub(crate) fn get_sid_sd(
    sd: *const u8,
    owner: bool,
    defaulted_bit: u16,
    sid: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    let view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let self_relative = view.control & SE_SELF_RELATIVE != 0;
    let field = if owner { view.owner } else { view.group };
    let addr = sd_addr(sd as usize, field, self_relative);
    // SAFETY: the caller's out parameters.
    unsafe {
        sid.write_unaligned(addr as *mut u8);
        defaulted.write_unaligned(u32::from(view.control & defaulted_bit != 0));
    }
    STATUS_SUCCESS
}

/// RtlSetDaclSecurityDescriptor: set the absolute SD's DACL.
#[unsafe(export_name = "f2k_export_RtlSetDaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_dacl_security_descriptor(
    sd: *mut u8,
    present: u32,
    dacl: *mut u8,
    defaulted: u32,
) -> u32 {
    set_acl_sd(
        sd,
        true,
        SE_DACL_PRESENT,
        SE_DACL_DEFAULTED,
        present,
        dacl,
        defaulted,
    )
}

/// RtlGetDaclSecurityDescriptor: get the SD's DACL.
#[unsafe(export_name = "f2k_export_RtlGetDaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_dacl_security_descriptor(
    sd: *const u8,
    present: *mut u32,
    dacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_acl_sd(
        sd,
        true,
        SE_DACL_PRESENT,
        SE_DACL_DEFAULTED,
        present,
        dacl,
        defaulted,
    )
}

/// RtlSetSaclSecurityDescriptor: set the absolute SD's SACL.
#[unsafe(export_name = "f2k_export_RtlSetSaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_sacl_security_descriptor(
    sd: *mut u8,
    present: u32,
    sacl: *mut u8,
    defaulted: u32,
) -> u32 {
    set_acl_sd(
        sd,
        false,
        SE_SACL_PRESENT,
        SE_SACL_DEFAULTED,
        present,
        sacl,
        defaulted,
    )
}

/// RtlGetSaclSecurityDescriptor: get the SD's SACL.
#[unsafe(export_name = "f2k_export_RtlGetSaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_sacl_security_descriptor(
    sd: *const u8,
    present: *mut u32,
    sacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_acl_sd(
        sd,
        false,
        SE_SACL_PRESENT,
        SE_SACL_DEFAULTED,
        present,
        sacl,
        defaulted,
    )
}

/// RtlSetOwnerSecurityDescriptor: set the absolute SD's owner.
#[unsafe(export_name = "f2k_export_RtlSetOwnerSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_owner_security_descriptor(
    sd: *mut u8,
    owner: *const u8,
    defaulted: u32,
) -> u32 {
    set_sid_sd(sd, true, SE_OWNER_DEFAULTED, owner, defaulted)
}

/// RtlGetOwnerSecurityDescriptor: get the SD's owner.
#[unsafe(export_name = "f2k_export_RtlGetOwnerSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_owner_security_descriptor(
    sd: *const u8,
    owner: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_sid_sd(sd, true, SE_OWNER_DEFAULTED, owner, defaulted)
}

/// RtlSetGroupSecurityDescriptor: set the absolute SD's group.
#[unsafe(export_name = "f2k_export_RtlSetGroupSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_group_security_descriptor(
    sd: *mut u8,
    group: *const u8,
    defaulted: u32,
) -> u32 {
    set_sid_sd(sd, false, SE_GROUP_DEFAULTED, group, defaulted)
}

/// RtlGetGroupSecurityDescriptor: get the SD's group.
#[unsafe(export_name = "f2k_export_RtlGetGroupSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_group_security_descriptor(
    sd: *const u8,
    group: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_sid_sd(sd, false, SE_GROUP_DEFAULTED, group, defaulted)
}

/// RtlGetSecurityDescriptorRMControl: the RM control byte out, when the valid bit is set.
#[unsafe(export_name = "f2k_export_RtlGetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn rtl_get_security_descriptor_rm_control(
    sd: *const u8,
    rm_control: *mut u8,
) -> u32 {
    let control = sd_control(sd);
    // SAFETY: the caller's out parameter.
    unsafe {
        rm_control.write_unaligned(if control & SE_RM_CONTROL_VALID != 0 {
            read::<u8>(sd.wrapping_add(1))
        } else {
            0
        })
    };
    u32::from(control & SE_RM_CONTROL_VALID != 0)
}

/// RtlSetSecurityDescriptorRMControl: set or clear the RM control byte and its valid bit.
#[unsafe(export_name = "f2k_export_RtlSetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn rtl_set_security_descriptor_rm_control(
    sd: *mut u8,
    rm_control: *const u8,
) {
    let at = sd.wrapping_add(2);
    if !rm_control.is_null() {
        write(at, word(at) | SE_RM_CONTROL_VALID);
        // SAFETY: the caller's byte.
        write(sd.wrapping_add(1), read::<u8>(rm_control));
    } else {
        write(at, word(at) & !SE_RM_CONTROL_VALID);
        write(sd.wrapping_add(1), 0u8);
    }
}

/// RtlCreateAndSetSD: an absolute SD in a heap block from the ACE data list, owner and group,
/// its address out.
#[unsafe(export_name = "f2k_export_RtlCreateAndSetSD")]
pub unsafe extern "system" fn rtl_create_and_set_sd(
    ace_data: *const AceData,
    ace_count: u32,
    owner: *const u8,
    group: *const u8,
    new_descriptor: *mut *mut u8,
) -> u32 {
    let mut dacl_size = 8usize;
    let mut sacl_size = 8usize;
    let mut max_ace = 0usize;
    for index in 0..ace_count as usize {
        // SAFETY: the caller's list holds `ace_count` entries.
        let entry = unsafe { &*ace_data.add(index) };
        // SAFETY: the entry's SID.
        let len = unsafe { sid_len_of(bytes(entry.sid as *const u8, SID_HEADER)) };
        let ace_size = len + 8;
        match entry.ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => dacl_size += ace_size,
            SYSTEM_AUDIT_ACE_TYPE => sacl_size += ace_size,
            _ => return STATUS_INVALID_PARAMETER,
        }
        max_ace = max_ace.max(ace_size);
    }
    let header = core::mem::size_of::<SecurityDescriptor>();
    let mut size = header;
    if dacl_size != 8 {
        size += dacl_size;
    }
    if sacl_size != 8 {
        size += sacl_size;
    }
    let Some(sd) = heap_alloc(size) else {
        return STATUS_NO_MEMORY;
    };
    let mut status = STATUS_SUCCESS;
    let mut dacl = 0usize;
    let mut sacl = 0usize;
    let mut current = sd + header;
    if dacl_size != 8 {
        dacl = current;
        current += dacl_size;
        status = rtl_create_acl(dacl as *mut u8, dacl_size as u32, ACL_REVISION);
    }
    if status == STATUS_SUCCESS && sacl_size != 8 {
        sacl = current;
        current += sacl_size;
        status = rtl_create_acl(sacl as *mut u8, sacl_size as u32, ACL_REVISION);
    }
    let _ = current;
    let scratch = if max_ace > 0 {
        heap_alloc(max_ace)
    } else {
        None
    };
    if status == STATUS_SUCCESS && max_ace > 0 && scratch.is_none() {
        status = STATUS_NO_MEMORY;
    }
    if status == STATUS_SUCCESS {
        for index in 0..ace_count as usize {
            // SAFETY: the caller's list holds `ace_count` entries.
            let entry = unsafe { &*ace_data.add(index) };
            // SAFETY: the entry's SID.
            let len = unsafe { sid_len_of(bytes(entry.sid as *const u8, SID_HEADER)) };
            let ace_size = len + 8;
            let ace = scratch.unwrap() as *mut u8;
            write(
                ace,
                AceHeader {
                    ace_type: entry.ace_type,
                    ace_flags: entry.ace_flags | entry.inherit_flags,
                    ace_size: ace_size as u16,
                },
            );
            set_dword(ace.wrapping_add(4), entry.mask);
            // SAFETY: the scratch block holds the ACE; the entry's SID holds its own.
            unsafe {
                bytes_mut(ace.wrapping_add(8), len)
                    .copy_from_slice(sid_slice(entry.sid as *const u8))
            };
            let acl = if entry.ace_type == SYSTEM_AUDIT_ACE_TYPE {
                sacl
            } else {
                dacl
            };
            status = rtl_add_ace(acl as *mut u8, ACL_REVISION, MAXULONG, ace, ace_size as u32);
            if status != STATUS_SUCCESS {
                break;
            }
        }
    }
    if status == STATUS_SUCCESS {
        status =
            rtl_create_security_descriptor(sd as *mut u8, u32::from(SECURITY_DESCRIPTOR_REVISION));
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_owner_security_descriptor(sd as *mut u8, owner, 0);
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_group_security_descriptor(sd as *mut u8, group, 0);
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_dacl_security_descriptor(
            sd as *mut u8,
            1,
            if dacl != 0 {
                dacl as *mut u8
            } else {
                core::ptr::null_mut()
            },
            0,
        );
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_sacl_security_descriptor(sd as *mut u8, 0, core::ptr::null_mut(), 0);
    }
    if let Some(block) = scratch {
        heap_free(block);
    }
    if status == STATUS_SUCCESS {
        // SAFETY: the caller's out parameter.
        unsafe { new_descriptor.write_unaligned(sd as *mut u8) };
    } else {
        heap_free(sd);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

    #[test]
    fn a_descriptor_creates_sets_and_gets() {
        let mut buffer = [0u8; 64];
        let sd = buffer.as_mut_ptr();
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd, 2) },
            STATUS_UNKNOWN_REVISION
        );
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd, 1) },
            STATUS_SUCCESS
        );
        let view: SecurityDescriptor = read(sd);
        assert_eq!(
            (
                view.revision,
                view.control,
                view.owner,
                view.group,
                view.sacl,
                view.dacl
            ),
            (1, 0, 0, 0, 0, 0)
        );
        assert_eq!(unsafe { rtl_valid_security_descriptor(sd) }, 1);
        let sid = admins();
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(sd, sid.as_ptr(), 1) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_group_security_descriptor(sd, sid.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        let mut owner = core::ptr::null_mut();
        let mut defaulted = 0u32;
        assert_eq!(
            unsafe { rtl_get_owner_security_descriptor(sd, &mut owner, &mut defaulted) },
            STATUS_SUCCESS
        );
        assert_eq!(owner as usize, sid.as_ptr() as usize);
        assert_eq!(defaulted, 1);
        let mut group = core::ptr::null_mut();
        assert_eq!(
            unsafe { rtl_get_group_security_descriptor(sd, &mut group, &mut defaulted) },
            STATUS_SUCCESS
        );
        assert_eq!(defaulted, 0);
        // The DACL.
        let mut acl_buffer = [0u8; 64];
        assert_eq!(
            unsafe { rtl_create_acl(acl_buffer.as_mut_ptr(), 64, 2) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl_buffer.as_mut_ptr(), 2, 0xFFFF, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_dacl_security_descriptor(sd, 1, acl_buffer.as_mut_ptr(), 1) },
            STATUS_SUCCESS
        );
        let mut present = 0u32;
        let mut dacl = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_get_dacl_security_descriptor(sd, &mut present, &mut dacl, &mut defaulted)
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            (present, dacl as usize, defaulted),
            (1, acl_buffer.as_ptr() as usize, 1)
        );
        assert_eq!(unsafe { rtl_valid_security_descriptor(sd) }, 1);
        // Length: header + aligned owner + aligned group + aligned ACL.
        let expect = core::mem::size_of::<SecurityDescriptor>() + 16 + 16 + 64;
        assert_eq!(
            unsafe { rtl_length_security_descriptor(sd) } as usize,
            expect
        );
        // Control get/set, and the RM control byte.
        let mut control = 0u16;
        let mut revision = 0u32;
        assert_eq!(
            unsafe { rtl_get_control_security_descriptor(sd, &mut control, &mut revision) },
            STATUS_SUCCESS
        );
        assert_eq!(
            (control, revision),
            (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_OWNER_DEFAULTED, 1)
        );
        assert_eq!(
            unsafe {
                rtl_set_control_security_descriptor(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            },
            STATUS_SUCCESS
        );
        assert_eq!(sd_control(sd) & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        assert_eq!(
            unsafe { rtl_set_control_security_descriptor(sd, SE_DACL_PROTECTED, 0) },
            STATUS_SUCCESS
        );
        assert_eq!(sd_control(sd) & SE_DACL_PROTECTED, 0);
        // SE_OWNER_DEFAULTED is not a settable bit.
        assert_eq!(
            unsafe { rtl_set_control_security_descriptor(sd, 0x0001, 0x0001) },
            STATUS_INVALID_PARAMETER
        );
        let mut rm = 0u8;
        assert_eq!(
            unsafe { rtl_get_security_descriptor_rm_control(sd, &mut rm) },
            0
        );
        assert_eq!(rm, 0);
        unsafe { rtl_set_security_descriptor_rm_control(sd, &0x5A) };
        assert_eq!(
            unsafe { rtl_get_security_descriptor_rm_control(sd, &mut rm) },
            1
        );
        assert_eq!(rm, 0x5A);
        // A bad revision is reported, and the revision out always.
        buffer[0] = 7;
        assert_eq!(
            unsafe { rtl_get_control_security_descriptor(sd, &mut control, &mut revision) },
            STATUS_UNKNOWN_REVISION
        );
        assert_eq!(revision, 7);
        assert_eq!(
            unsafe { rtl_set_dacl_security_descriptor(sd, 1, acl_buffer.as_mut_ptr(), 0) },
            STATUS_UNKNOWN_REVISION
        );
        buffer[0] = 1;
        assert_eq!(buffer[0], 1);
        // A self-relative SD cannot be set through the absolute setters.
        let mut rel = [0u8; 20];
        rel[0] = 1;
        write(rel.as_mut_ptr().wrapping_add(2), SE_SELF_RELATIVE);
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(rel.as_mut_ptr(), sid.as_ptr(), 0) },
            STATUS_INVALID_SECURITY_DESCR
        );
    }

    #[test]
    fn create_and_set_sd_builds_a_descriptor() {
        let owner = admins();
        let group = world();
        let entries = [
            AceData {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0xF0,
                sid: owner.as_ptr() as usize,
            },
            AceData {
                ace_type: SYSTEM_AUDIT_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0x10,
                sid: group.as_ptr() as usize,
            },
        ];
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_create_and_set_sd(
                    entries.as_ptr(),
                    2,
                    owner.as_ptr(),
                    group.as_ptr(),
                    &mut out,
                )
            },
            STATUS_SUCCESS
        );
        let view: SecurityDescriptor = read(out as *const u8);
        assert_eq!(view.revision, 1);
        assert_eq!(view.owner, owner.as_ptr() as usize);
        assert_eq!(view.group, group.as_ptr() as usize);
        assert!(view.control & SE_DACL_PRESENT != 0);
        assert!(view.control & SE_SACL_PRESENT == 0);
        assert_eq!(
            unsafe { rtl_valid_security_descriptor(out as *const u8) },
            1
        );
        let dacl = view.dacl as *const u8;
        assert_eq!(acl_of(dacl).ace_count, 1);
        let header = core::mem::size_of::<SecurityDescriptor>();
        let sacl = (out as usize + header + 8 + 24) as *const u8;
        assert_eq!(acl_of(sacl).ace_count, 1);
        assert!(heap_free(out as usize));
        // An unknown ACE type is rejected.
        let bad = [AceData {
            ace_type: 9,
            sid: owner.as_ptr() as usize,
            ..AceData::default()
        }];
        assert_eq!(
            unsafe {
                rtl_create_and_set_sd(bad.as_ptr(), 1, owner.as_ptr(), group.as_ptr(), &mut out)
            },
            STATUS_INVALID_PARAMETER
        );
    }
}

