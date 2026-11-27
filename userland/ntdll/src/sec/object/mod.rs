//! The security-object wrappers: the routines that answer for an object's stored security
//! descriptor, split by shape — the query and set wrappers over the object's descriptor slot
//! (`mod.rs`), the in-memory descriptor lifecycle (`create`), and the impersonation check with
//! the LUID helpers (`luid`).
//!
//! The query and set wrappers work on the object's descriptor in memory: the query builds a
//! self-relative descriptor of the parts the caller's SECURITY_INFORMATION names, the set
//! merges the named parts of the caller's modification descriptor into the object's and
//! answers the new self-relative descriptor through the object's slot. The generic mapping and
//! the token arguments the public contract carries are the caller's own concern — the caller
//! has already done the access checking — so the wrappers leave them alone.
//!
//! In the host tests the wrappers run over plain buffers, so the tests pin the descriptor
//! building, the size protocol and a set-then-query round trip.

use super::*;

// The SECURITY_INFORMATION bits past the owner and group ones mod.rs carries.
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const SACL_SECURITY_INFORMATION: u32 = 0x8;

mod create;
mod luid;

// --- The wrappers over the object's descriptor ----------------------------------------------

/// The SECURITY_INFORMATION bit of each part, in the parts' order (owner, group, SACL, DACL).
const PART_INFO: [u32; 4] = [
    OWNER_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
    DACL_SECURITY_INFORMATION,
];
/// The control bit a present ACL part carries.
const PART_PRESENT: [u16; 4] = [0, 0, SE_SACL_PRESENT, SE_DACL_PRESENT];
/// The control bit a defaulted part carries.
const PART_DEFAULTED: [u16; 4] = [
    SE_OWNER_DEFAULTED,
    SE_GROUP_DEFAULTED,
    SE_SACL_DEFAULTED,
    SE_DACL_DEFAULTED,
];

/// A heap block holding a self-relative SD of the parts at `addrs`/`sizes` (owner, group, SACL,
/// DACL order in the arrays, packed after the header in SACL, DACL, owner, group order), with
/// `control` and `revision`; none on failure.
fn heap_relative_sd(
    addrs: [usize; 4],
    sizes: [usize; 4],
    control: u16,
    revision: u8,
) -> Option<usize> {
    let header = core::mem::size_of::<SecurityDescriptorRelative>();
    let total = header + sizes.iter().sum::<usize>();
    let block = heap_alloc(total)?;
    // SAFETY: the block holds `total` bytes, the parts their own.
    unsafe {
        core::ptr::write_bytes(block as *mut u8, 0, header);
        let mut field = block + header;
        let mut offsets = [0u32; 4];
        for index in [2usize, 3, 0, 1] {
            if sizes[index] > 0 {
                core::ptr::copy_nonoverlapping(addrs[index] as *const u8, field as *mut u8, sizes[index]);
                offsets[index] = (field - block) as u32;
                field += sizes[index];
            }
        }
        write(
            block as *mut u8,
            SecurityDescriptorRelative {
                revision,
                sbz1: 0,
                control,
                owner: offsets[0],
                group: offsets[1],
                sacl: offsets[2],
                dacl: offsets[3],
            },
        );
    }
    Some(block)
}

/// RtlQuerySecurityObject: the parts of the descriptor at `object_descriptor` the
/// `security_information` names, as a self-relative descriptor in `resultant_descriptor` (of
/// `descriptor_length` bytes), the size the answer takes into `return_length`.
#[unsafe(export_name = "f2k_export_RtlQuerySecurityObject")]
pub unsafe extern "system" fn rtl_query_security_object(
    object_descriptor: *const u8,
    security_information: u32,
    resultant_descriptor: *mut u8,
    descriptor_length: u32,
    return_length: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor; a bad pointer faults on the read, as it should.
    let (addrs, sizes) = query_sd(object_descriptor);
    let control = sd_control(object_descriptor);
    // Only the named parts are packed into the answer.
    let mut packed = [0usize; 4];
    let mut size = core::mem::size_of::<SecurityDescriptorRelative>() as u32;
    let mut answer_control = SE_SELF_RELATIVE;
    for index in 0..4 {
        if security_information & PART_INFO[index] != 0 {
            packed[index] = sizes[index];
            size += sizes[index] as u32;
            answer_control |= control & (PART_PRESENT[index] | PART_DEFAULTED[index]);
        }
    }
    // SAFETY: the caller's out word, written before the length check.
    unsafe { return_length.write_unaligned(size) };
    if size > descriptor_length {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let revision = read::<u8>(object_descriptor);
    let Some(block) = heap_relative_sd(addrs, packed, answer_control, revision) else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: the caller's buffer holds `size` bytes, the block the same answer.
    unsafe {
        core::ptr::copy_nonoverlapping(block as *const u8, resultant_descriptor, size as usize);
        heap_free(block);
    }
    STATUS_SUCCESS
}

/// The set wrappers' shared body: merge the parts `security_information` names from
/// `modification_descriptor` into the self-relative descriptor the slot at
/// `objects_security_descriptor` holds, and answer the new descriptor through the slot.
fn set_security_object(
    security_information: u32,
    modification_descriptor: *const u8,
    objects_security_descriptor: *mut *mut u8,
) -> u32 {
    if objects_security_descriptor.is_null() || modification_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's slot and modification descriptor; a bad pointer faults on the
    // read, as it should.
    let (current, modification) = unsafe {
        (
            objects_security_descriptor.read_unaligned(),
            modification_descriptor,
        )
    };
    if current.is_null() || sd_control(current) & SE_SELF_RELATIVE == 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    // SAFETY: both descriptors are the caller's.
    let (mut addrs, mut sizes) = query_sd(current);
    let (mod_addrs, mod_sizes) = query_sd(modification);
    let mut control = sd_control(current);
    let mod_control = sd_control(modification);
    for index in 0..4 {
        if security_information & PART_INFO[index] == 0 {
            continue;
        }
        // The named part comes from the modification (a null one clears it), with its
        // present and defaulted bits.
        control = (control & !(PART_PRESENT[index] | PART_DEFAULTED[index]))
            | (mod_control & (PART_PRESENT[index] | PART_DEFAULTED[index]));
        addrs[index] = mod_addrs[index];
        sizes[index] = mod_sizes[index];
    }
    let revision = read::<u8>(current);
    let Some(block) = heap_relative_sd(addrs, sizes, control | SE_SELF_RELATIVE, revision) else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: the slot holds the old heap descriptor, answered with the new one.
    unsafe {
        heap_free(current as usize);
        objects_security_descriptor.write_unaligned(block as *mut u8);
    }
    STATUS_SUCCESS
}

/// RtlSetSecurityObject: merge the named parts of `modification_descriptor` into the object's
/// descriptor at `objects_security_descriptor`.
#[unsafe(export_name = "f2k_export_RtlSetSecurityObject")]
pub unsafe extern "system" fn rtl_set_security_object(
    security_information: u32,
    modification_descriptor: *const u8,
    objects_security_descriptor: *mut *mut u8,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    set_security_object(
        security_information,
        modification_descriptor,
        objects_security_descriptor,
    )
}

/// RtlSetSecurityObjectEx: as RtlSetSecurityObject; the auto-inherit flags name no extra part
/// for an in-memory object.
#[unsafe(export_name = "f2k_export_RtlSetSecurityObjectEx")]
pub unsafe extern "system" fn rtl_set_security_object_ex(
    security_information: u32,
    modification_descriptor: *const u8,
    objects_security_descriptor: *mut *mut u8,
    _auto_inherit_flags: u32,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    set_security_object(
        security_information,
        modification_descriptor,
        objects_security_descriptor,
    )
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! The descriptor builders the tests of this module and of `create` share.

    use super::*;

    pub(crate) fn absolute_sd(owner: &[u8], group: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
        let mut sd = vec![0u8; 64];
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd.as_mut_ptr(), 1) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(sd.as_mut_ptr(), owner.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_group_security_descriptor(sd.as_mut_ptr(), group.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        if let Some(dacl) = dacl {
            assert_eq!(
                unsafe {
                    rtl_set_dacl_security_descriptor(
                        sd.as_mut_ptr(),
                        1,
                        dacl.as_ptr() as *mut u8,
                        0,
                    )
                },
                STATUS_SUCCESS
            );
        }
        sd
    }

    pub(crate) fn dacl_with(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut acl = vec![0u8; 64];
        assert_eq!(
            unsafe { rtl_create_acl(acl.as_mut_ptr(), 64, 2) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl.as_mut_ptr(), 2, mask, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        acl
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{absolute_sd, dacl_with};
    use super::*;
    use crate::sec::convert::rtl_make_self_relative_sd;
    use crate::sec::test_support::*;

    /// A heap block holding `sd` in self-relative form, as an object's slot holds it.
    fn heap_relative(sd: &[u8]) -> *mut u8 {
        let length = unsafe { rtl_length_security_descriptor(sd.as_ptr()) } as usize;
        let block = heap_alloc(length).unwrap();
        let mut size = length as u32;
        assert_eq!(
            unsafe { rtl_make_self_relative_sd(sd.as_ptr(), block as *mut u8, &mut size) },
            STATUS_SUCCESS
        );
        block as *mut u8
    }

    #[test]
    fn a_query_builds_a_self_relative_answer_of_the_named_parts() {
        let owner = admins();
        let group = world();
        let dacl = dacl_with(0x0012_019F, &world());
        let object = absolute_sd(&owner, &group, Some(&dacl));
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut buffer = [0u8; 256];
        let mut needed = 0u32;
        // Too small a buffer: the size comes out, nothing is written.
        assert_eq!(
            unsafe {
                rtl_query_security_object(object.as_ptr(), info, buffer.as_mut_ptr(), 0, &mut needed)
            },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(needed, 20 + 64 + 16);
        assert_eq!(&buffer[..20], &[0u8; 20]);
        // Enough room: the self-relative answer with the two named parts, packed in
        // SACL, DACL, owner, group order — the DACL at 20, the owner at 84.
        assert_eq!(
            unsafe {
                rtl_query_security_object(object.as_ptr(), info, buffer.as_mut_ptr(), 256, &mut needed)
            },
            STATUS_SUCCESS
        );
        assert_eq!(needed, 100);
        let header: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(header.revision, 1);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert!(header.control & SE_DACL_PRESENT != 0);
        assert_eq!((header.owner, header.group, header.sacl, header.dacl), (84, 0, 0, 20));
        assert_eq!(&buffer[20..84], &dacl[..]);
        assert_eq!(&buffer[84..100], &owner[..]);
        // Naming nothing answers the header alone.
        assert_eq!(
            unsafe {
                rtl_query_security_object(object.as_ptr(), 0, buffer.as_mut_ptr(), 256, &mut needed)
            },
            STATUS_SUCCESS
        );
        assert_eq!(needed, 20);
        let header: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(
            (header.owner, header.group, header.sacl, header.dacl),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn a_set_merges_the_named_parts_and_answers_through_the_slot() {
        let owner = admins();
        let group = world();
        let dacl = dacl_with(0x0012_019F, &world());
        let object = absolute_sd(&owner, &group, Some(&dacl));
        let mut slot = heap_relative(&object);
        // A modification naming the DACL and the owner.
        let new_dacl = dacl_with(0x0010_0000, &world());
        let modification = absolute_sd(&admins(), &world(), Some(&new_dacl));
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    &mut slot,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_SUCCESS
        );
        assert!(!slot.is_null());
        // SAFETY: the block is the call's answer.
        let header: SecurityDescriptorRelative = read(slot as *const u8);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert!(header.control & SE_DACL_PRESENT != 0);
        assert_ne!(header.dacl, 0);
        assert_ne!(header.owner, 0);
        // The DACL in the answer is the modification's; the group was not named, so it
        // is the object's.
        // SAFETY: the block holds the answer.
        let all = unsafe { bytes(slot as *const u8, 20 + 64 + 16 + 12) };
        assert_eq!(&all[header.dacl as usize..][..64], &new_dacl[..]);
        assert_eq!(&all[header.group as usize..][..12], &group[..]);
        // Query the new descriptor back through the wrapper: the merged parts come out.
        let mut buffer = [0u8; 256];
        let mut needed = 0u32;
        assert_eq!(
            unsafe {
                rtl_query_security_object(
                    slot,
                    DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                    buffer.as_mut_ptr(),
                    256,
                    &mut needed,
                )
            },
            STATUS_SUCCESS
        );
        let answer: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(answer.dacl, 20);
        assert_eq!(&buffer[20..84], &new_dacl[..]);
        assert_eq!(answer.group, 84);
        assert_eq!(&buffer[84..96], &group[..]);
        // The Ex variant answers the same way.
        assert_eq!(
            unsafe {
                rtl_set_security_object_ex(
                    GROUP_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    &mut slot,
                    0,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_SUCCESS
        );
        // An absolute descriptor in the slot is refused; so are a null slot and a null
        // modification.
        let mut absolute_slot = object.as_ptr() as *mut u8;
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    DACL_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    &mut absolute_slot,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_BAD_DESCRIPTOR_FORMAT
        );
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    DACL_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    DACL_SECURITY_INFORMATION,
                    core::ptr::null(),
                    &mut slot,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_INVALID_PARAMETER
        );
        assert!(heap_free(slot as usize));
    }
}
