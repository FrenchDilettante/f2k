//! The in-memory security-object lifecycle: the create, convert and delete routines work on a
//! descriptor in the process heap, the public contract's shape — a new descriptor is a heap
//! self-relative copy of the creator's (a blank self-relative one when there is none), the
//! conversion marks a copy's ACLs auto-inherited, and the delete gives the heap block back. F2K
//! applies no parent inheritance to these in-memory objects, so the parent, token and mapping
//! arguments are not consulted.

use super::luid::{copy_luid, rtl_equal_luid};
use super::*;
use crate::sec::convert::rtl_make_self_relative_sd;

// The token information class whose answer carries the modified id.
#[cfg(not(test))]
const TOKEN_STATISTICS: u32 = 10;

// --- The in-memory security-object lifecycle
// ------------------------------------------------------
//
// The create/convert/delete routines work on a descriptor in the process heap, the public
// contract's shape: a new descriptor is a heap self-relative copy of the creator's (a blank
// self-relative one when there is none), the conversion marks a copy's ACLs auto-inherited,
// and the delete gives the heap block back. F2K applies no parent inheritance to these
// in-memory objects, so the parent, token and mapping arguments are not consulted.

/// A heap block holding the SD at `sd` (either form) in self-relative form; none on failure.
fn heap_relative_copy(sd: *const u8) -> Option<usize> {
    // SAFETY: the caller's SD, whole.
    let length = unsafe { rtl_length_security_descriptor(sd) } as usize;
    let block = heap_alloc(length)?;
    let mut size = length as u32;
    // SAFETY: the block holds `length` bytes, the caller's SD its descriptor.
    let status = unsafe { rtl_make_self_relative_sd(sd, block as *mut u8, &mut size) };
    if status != STATUS_SUCCESS {
        heap_free(block);
        return None;
    }
    Some(block)
}

/// A heap block holding a blank self-relative SD (the 20-byte header alone); none on failure.
fn heap_blank_relative() -> Option<usize> {
    let block = heap_alloc(core::mem::size_of::<SecurityDescriptorRelative>())?;
    write(
        block as *mut u8,
        SecurityDescriptorRelative {
            revision: SECURITY_DESCRIPTOR_REVISION,
            sbz1: 0,
            control: SE_SELF_RELATIVE,
            ..SecurityDescriptorRelative::default()
        },
    );
    Some(block)
}

/// The heap self-relative copy of `source` (a blank one when null) out at `out`.
fn new_descriptor_out(source: *const u8, out: *mut *mut u8) -> u32 {
    if out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let block = if source.is_null() {
        heap_blank_relative()
    } else {
        heap_relative_copy(source)
    };
    let Some(block) = block else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: the caller's out slot.
    unsafe { out.write_unaligned(block as *mut u8) };
    STATUS_SUCCESS
}

/// RtlNewSecurityObject: a heap self-relative copy of `creator_descriptor` out at
/// `new_descriptor` (a blank self-relative SD when the creator is null).
#[unsafe(export_name = "f2k_export_RtlNewSecurityObject")]
pub unsafe extern "system" fn rtl_new_security_object(
    _parent_descriptor: *const u8,
    creator_descriptor: *const u8,
    new_descriptor: *mut *mut u8,
    _is_directory_object: u32,
    _token: u32,
    _generic_mapping: *const u8,
) -> u32 {
    new_descriptor_out(creator_descriptor, new_descriptor)
}

/// RtlNewSecurityObjectEx: as RtlNewSecurityObject; the object type and the auto-inherit flags
/// name no extra part for an in-memory object.
#[unsafe(export_name = "f2k_export_RtlNewSecurityObjectEx")]
pub unsafe extern "system" fn rtl_new_security_object_ex(
    _parent_descriptor: *const u8,
    creator_descriptor: *const u8,
    new_descriptor: *mut *mut u8,
    _object_type: *const u8,
    _is_directory_object: u32,
    _auto_inherit_flags: u32,
    _token: u32,
    _generic_mapping: *const u8,
) -> u32 {
    new_descriptor_out(creator_descriptor, new_descriptor)
}

/// RtlCreateUserSecurityObject: a heap self-relative SD built from the ACE data list, the owner
/// and the group, out at `new_descriptor`.
#[unsafe(export_name = "f2k_export_RtlCreateUserSecurityObject")]
pub unsafe extern "system" fn rtl_create_user_security_object(
    ace_data: *const AceData,
    ace_count: u32,
    owner_sid: *const u8,
    group_sid: *const u8,
    _is_directory_object: u32,
    _generic_mapping: *const u8,
    new_descriptor: *mut *mut u8,
) -> u32 {
    if new_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut absolute = core::ptr::null_mut();
    // SAFETY: the caller's ACE list, owner and group SIDs, and out slot.
    let status =
        unsafe { rtl_create_and_set_sd(ace_data, ace_count, owner_sid, group_sid, &mut absolute) };
    if status != STATUS_SUCCESS {
        return status;
    }
    let block = heap_relative_copy(absolute);
    heap_free(absolute as usize);
    let Some(block) = block else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: the caller's out slot.
    unsafe { new_descriptor.write_unaligned(block as *mut u8) };
    STATUS_SUCCESS
}

/// The token's current modified id (its TokenStatistics' last LUID), or the status the
/// token query failed with.
#[cfg(not(test))]
fn token_modified_id(token: u32) -> Result<[u8; 8], u32> {
    use rtl::sys::nr;
    // TOKEN_STATISTICS is 56 bytes; its ModifiedId is the last 8.
    let stats = [0u8; 56];
    let mut length = 0u32;
    let status = service(
        nr::NtQueryInformationToken,
        &[
            token,
            TOKEN_STATISTICS,
            address(&stats),
            stats.len() as u32,
            address_mut(&mut length),
        ],
    );
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    Ok(stats[48..56].try_into().unwrap())
}

/// The host tests' stand-in: the modified id the test installed.
#[cfg(test)]
fn token_modified_id(_token: u32) -> Result<[u8; 8], u32> {
    Ok(tests::token::modified_id())
}

/// RtlNewInstanceSecurityObject: the token's current modified id out at
/// `new_client_token_modified_id` (written unconditionally — a null slot faults on the
/// caller); when it equals `old_client_token_modified_id` and neither descriptor changed,
/// the old descriptor still fits and a null descriptor is passed back, otherwise a new
/// self-relative descriptor is built as RtlNewSecurityObject would.
#[unsafe(export_name = "f2k_export_RtlNewInstanceSecurityObject")]
pub unsafe extern "system" fn rtl_new_instance_security_object(
    parent_descriptor_changed: u32,
    creator_descriptor_changed: u32,
    old_client_token_modified_id: *const u8,
    new_client_token_modified_id: *mut u8,
    parent_descriptor: *const u8,
    creator_descriptor: *const u8,
    new_descriptor: *mut *mut u8,
    _is_directory_object: u32,
    token: u32,
    _generic_mapping: *const u8,
) -> u32 {
    let modified = match token_modified_id(token) {
        Ok(modified) => modified,
        Err(status) => return status,
    };
    // SAFETY: the caller's out LUID; a null slot raises the access violation, and the
    // old id is read through its pointer the same way.
    unsafe {
        copy_luid(new_client_token_modified_id, modified.as_ptr());
        if rtl_equal_luid(new_client_token_modified_id, old_client_token_modified_id) == 1
            && parent_descriptor_changed == 0
            && creator_descriptor_changed == 0
        {
            // Nothing changed: the old descriptor is valid for this instance too.
            if new_descriptor.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            new_descriptor.write_unaligned(core::ptr::null_mut());
            return STATUS_SUCCESS;
        }
    }
    let source = if creator_descriptor.is_null() {
        parent_descriptor
    } else {
        creator_descriptor
    };
    new_descriptor_out(source, new_descriptor)
}

/// RtlConvertToAutoInheritSecurityObject: a heap self-relative copy of `current` out at
/// `new_descriptor`; each ACL keeps its present and protected bits and gains the
/// auto-inherited one (a missing DACL is forced protected), and no request bits are set.
#[unsafe(export_name = "f2k_export_RtlConvertToAutoInheritSecurityObject")]
pub unsafe extern "system" fn rtl_convert_to_auto_inherit_security_object(
    _parent_descriptor: *const u8,
    current_security_descriptor: *const u8,
    new_security_descriptor: *mut *mut u8,
    _object_type: *const u8,
    _is_directory_object: u32,
    _generic_mapping: *const u8,
) -> u32 {
    if current_security_descriptor.is_null() || new_security_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // The current descriptor must be valid and carry an owner; the out slot is answered
    // even on failure.
    // SAFETY: the caller's descriptor and out slot.
    let status = unsafe {
        if rtl_valid_security_descriptor(current_security_descriptor) != 1
            || sd_fields(current_security_descriptor)[0] == 0
        {
            new_security_descriptor.write_unaligned(core::ptr::null_mut());
            STATUS_INVALID_SECURITY_DESCR
        } else {
            match heap_relative_copy(current_security_descriptor) {
                None => {
                    new_security_descriptor.write_unaligned(core::ptr::null_mut());
                    STATUS_NO_MEMORY
                }
                Some(block) => {
                    let at = block as *mut u8;
                    let control = sd_control(at);
                    let dacl_missing = sd_fields(at)[3] == 0;
                    let mut converted = SE_SELF_RELATIVE
                        | (control
                            & (SE_SACL_PROTECTED
                                | SE_SACL_PRESENT
                                | SE_DACL_PROTECTED
                                | SE_DACL_PRESENT))
                        | SE_SACL_AUTO_INHERITED
                        | SE_DACL_AUTO_INHERITED;
                    if dacl_missing {
                        converted |= SE_DACL_PROTECTED;
                    }
                    write(at.wrapping_add(2), converted);
                    new_security_descriptor.write_unaligned(block as *mut u8);
                    STATUS_SUCCESS
                }
            }
        }
    };
    status
}

/// RtlDeleteSecurityObject: the heap descriptor at `*object_descriptor` given back, the slot
/// nulled; deleting a null descriptor succeeds.
#[unsafe(export_name = "f2k_export_RtlDeleteSecurityObject")]
pub unsafe extern "system" fn rtl_delete_security_object(object_descriptor: *mut *mut u8) -> u32 {
    if object_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's slot.
    let block = unsafe { object_descriptor.read_unaligned() };
    if !block.is_null() {
        heap_free(block as usize);
        // SAFETY: the caller's slot.
        unsafe { object_descriptor.write_unaligned(core::ptr::null_mut()) };
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{absolute_sd, dacl_with};
    use super::*;
    use crate::sec::test_support::*;

    /// The host stand-in for the token's modified id: the value the test installs.
    pub(crate) mod token {
        use std::sync::Mutex;

        static MODIFIED_ID: Mutex<[u8; 8]> = Mutex::new([0; 8]);

        pub(crate) fn set_modified_id(id: [u8; 8]) {
            *MODIFIED_ID.lock().unwrap() = id;
        }

        pub(crate) fn modified_id() -> [u8; 8] {
            *MODIFIED_ID.lock().unwrap()
        }
    }

    #[test]
    fn a_new_descriptor_is_a_self_relative_copy_and_the_delete_frees_it() {
        let owner = admins();
        let group = world();
        let dacl = dacl_with(0x0012_019F, &world());
        let creator = absolute_sd(&owner, &group, Some(&dacl));
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_new_security_object(
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut out,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert!(!out.is_null());
        // The copy is self-relative, the parts packed after the header: DACL at 20, owner at
        // 84, group at 100, for a 112-byte descriptor.
        // SAFETY: the block is the call's descriptor.
        let header: SecurityDescriptorRelative = read(out as *const u8);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert_eq!(
            (header.sacl, header.dacl, header.owner, header.group),
            (0, 20, 84, 100)
        );
        // SAFETY: the block holds 112 bytes.
        let bytes = unsafe { bytes(out as *const u8, 112) };
        assert_eq!(&bytes[20..84], &dacl[..]);
        assert_eq!(&bytes[84..100], &owner[..]);
        assert_eq!(&bytes[100..112], &group[..]);
        assert_eq!(
            unsafe { rtl_valid_relative_security_descriptor(out as *const u8, 112, 0) },
            1
        );
        // The Ex variant answers the same; a null out slot is refused.
        let mut out_ex = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_new_security_object_ex(
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut out_ex,
                    core::ptr::null(),
                    0,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert!(!out_ex.is_null());
        assert_eq!(
            unsafe {
                rtl_new_security_object_ex(
                    core::ptr::null(),
                    creator.as_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    0,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_INVALID_PARAMETER
        );
        // The delete gives the blocks back and nulls the slots; a null descriptor is fine.
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        assert!(out.is_null());
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out_ex) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_delete_security_object(core::ptr::null_mut()) },
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn a_new_descriptor_without_a_creator_is_blank() {
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_new_security_object(
                    core::ptr::null(),
                    core::ptr::null(),
                    &mut out,
                    1,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        // SAFETY: the block holds the 20-byte header.
        let header: SecurityDescriptorRelative = read(out as *const u8);
        assert_eq!(header.revision, 1);
        assert_eq!(header.control, SE_SELF_RELATIVE);
        assert_eq!(
            (header.owner, header.group, header.sacl, header.dacl),
            (0, 0, 0, 0)
        );
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn a_user_security_object_is_built_from_the_ace_data() {
        let owner = admins();
        let group = world();
        let everyone = world();
        let ace_data = [
            AceData {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0xF01F_FFFF,
                sid: owner.as_ptr() as usize,
            },
            AceData {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0x0000_0001,
                sid: everyone.as_ptr() as usize,
            },
        ];
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_create_user_security_object(
                    ace_data.as_ptr(),
                    2,
                    owner.as_ptr(),
                    group.as_ptr(),
                    0,
                    core::ptr::null(),
                    &mut out,
                )
            },
            STATUS_SUCCESS
        );
        // SAFETY: the block is the call's self-relative descriptor.
        let header: SecurityDescriptorRelative = read(out as *const u8);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert!(header.control & SE_DACL_PRESENT != 0);
        // SAFETY: the block holds the descriptor.
        let all = unsafe { bytes(out as *const u8, 20 + 64 + 16 + 12) };
        assert_eq!(&all[header.owner as usize..][..16], &owner[..]);
        assert_eq!(&all[header.group as usize..][..12], &group[..]);
        let dacl = acl_of(all[header.dacl as usize..].as_ptr());
        assert_eq!(dacl.ace_count, 2);
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        // A bad ACE type is refused before anything is allocated out.
        let bad = [AceData {
            ace_type: 99,
            inherit_flags: 0,
            ace_flags: 0,
            mask: 0,
            sid: owner.as_ptr() as usize,
        }];
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_create_user_security_object(
                    bad.as_ptr(),
                    1,
                    owner.as_ptr(),
                    group.as_ptr(),
                    0,
                    core::ptr::null(),
                    &mut out,
                )
            },
            STATUS_INVALID_PARAMETER
        );
        assert!(out.is_null());
    }

    #[test]
    fn a_new_instance_carries_the_token_modified_id_and_reuses_or_rebuilds() {
        let owner = admins();
        let creator = absolute_sd(&owner, &world(), None);
        let modified = [9u8, 8, 7, 6, 5, 4, 3, 2];
        token::set_modified_id(modified);
        let old_id = modified;
        let mut new_id = [0u8; 8];
        let mut out = core::ptr::null_mut();
        // The ids match but a descriptor changed: the long route builds a new SD.
        assert_eq!(
            unsafe {
                rtl_new_instance_security_object(
                    1,
                    1,
                    old_id.as_ptr(),
                    new_id.as_mut_ptr(),
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut out,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(new_id, modified);
        assert!(!out.is_null());
        // SAFETY: the block is the call's descriptor.
        let header: SecurityDescriptorRelative = read(out as *const u8);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert_ne!(header.owner, 0);
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        // The ids match and nothing changed: the old descriptor fits, a null one is out.
        let mut out = 0x1usize as *mut u8;
        assert_eq!(
            unsafe {
                rtl_new_instance_security_object(
                    0,
                    0,
                    old_id.as_ptr(),
                    new_id.as_mut_ptr(),
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut out,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(new_id, modified);
        assert!(out.is_null());
        // A different old id: the long route even with no changed flags.
        let stale = [1u8, 1, 1, 1, 1, 1, 1, 1];
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_new_instance_security_object(
                    0,
                    0,
                    stale.as_ptr(),
                    new_id.as_mut_ptr(),
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut out,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(new_id, modified);
        assert!(!out.is_null());
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        // Without a creator, the parent's descriptor is the source.
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_new_instance_security_object(
                    1,
                    0,
                    stale.as_ptr(),
                    new_id.as_mut_ptr(),
                    creator.as_ptr(),
                    core::ptr::null(),
                    &mut out,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert!(!out.is_null());
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn the_auto_inherit_conversion_marks_the_copy() {
        let owner = admins();
        let dacl = dacl_with(0x0012_019F, &world());
        let current = absolute_sd(&owner, &world(), Some(&dacl));
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_convert_to_auto_inherit_security_object(
                    core::ptr::null(),
                    current.as_ptr(),
                    &mut out,
                    core::ptr::null(),
                    1,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        // SAFETY: the block is the call's copy.
        let control = sd_control(out as *const u8);
        // Self-relative, the DACL still present, both ACLs auto-inherited, no request
        // bits, no protected bits (the input had none and its DACL is present).
        assert_eq!(
            control,
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_AUTO_INHERITED | SE_DACL_AUTO_INHERITED
        );
        // The parts carried over whole.
        // SAFETY: the block holds the copy.
        let header: SecurityDescriptorRelative = read(out as *const u8);
        let all = unsafe { bytes(out as *const u8, 20 + 64 + 16 + 12) };
        assert_eq!(&all[header.dacl as usize..][..64], &dacl[..]);
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        // A missing DACL is forced protected; the protected bits of the input are kept.
        let mut protected = absolute_sd(&owner, &world(), None);
        write(
            protected.as_mut_ptr().wrapping_add(2),
            SE_DACL_PROTECTED | SE_DACL_PRESENT,
        );
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_convert_to_auto_inherit_security_object(
                    core::ptr::null(),
                    protected.as_ptr(),
                    &mut out,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            sd_control(out as *const u8),
            SE_SELF_RELATIVE
                | SE_DACL_PROTECTED
                | SE_DACL_PRESENT
                | SE_SACL_AUTO_INHERITED
                | SE_DACL_AUTO_INHERITED
        );
        assert_eq!(
            unsafe { rtl_delete_security_object(&mut out) },
            STATUS_SUCCESS
        );
        // A null current descriptor is refused; an invalid one answers a null
        // descriptor and STATUS_INVALID_SECURITY_DESCR.
        assert_eq!(
            unsafe {
                rtl_convert_to_auto_inherit_security_object(
                    core::ptr::null(),
                    core::ptr::null(),
                    &mut out,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_INVALID_PARAMETER
        );
        let mut bad = vec![0u8; 20];
        bad[0] = 7; // a bad revision
        let mut out = 0x1usize as *mut u8;
        assert_eq!(
            unsafe {
                rtl_convert_to_auto_inherit_security_object(
                    core::ptr::null(),
                    bad.as_ptr(),
                    &mut out,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                )
            },
            STATUS_INVALID_SECURITY_DESCR
        );
        assert!(out.is_null());
    }
}
