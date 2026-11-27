//! The private-object security calls: CreatePrivateObjectSecurity(Ex),
//! Get/SetPrivateObjectSecurity(Ex), DestroyPrivateObjectSecurity and
//! ConvertToAutoInheritPrivateObjectSecurity, as Windows 2000's advapi32 runs them.
//!
//! A private object is a protected server's own object, so its security descriptor lives in the
//! server's memory: these calls are pure user-mode work over the local [`crate::sd`] helpers and
//! the process heap, over the shared descriptor readers and writer in [`super`].
//!
//! CreatePrivateObjectSecurity(Ex) allocates a self-relative descriptor on the process heap whose
//! components come from the creator descriptor when given, else the parent's, and whose control
//! carries the auto-inherit request flags when a parent is given (the Ex form's SEF auto-inherit
//! bits mark the inherited ACLs when the parent carries them). GetPrivateObjectSecurity copies
//! the parts the SECURITY_INFORMATION mask names (owner 1, group 2, DACL 4, SACL 8) into the
//! caller's buffer, sizing it first: a buffer too small answers ERROR_INSUFFICIENT_BUFFER with
//! the size in the length out. SetPrivateObjectSecurity(Ex) merges the parts the mask names from
//! the modification descriptor into the object's descriptor, reallocating the heap block and
//! leaving the new address in the caller's pointer slot. DestroyPrivateObjectSecurity frees the
//! block and nulls the slot. ConvertToAutoInherit... marks the object's ACLs auto-inherited when
//! the parent carries them, protected otherwise, keeping the owner and group.

use rtl::heap::ProcessHeap as _;
use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

use super::{
    present_bits,
    propagate_bits,
    read_parts,
    read_sd,
    sd_parts,
    storage_size,
    target_size,
    write_self_relative,
    FIELD_INFO,
    SEF_DACL_AUTO_INHERIT,
    SEF_SACL_AUTO_INHERIT,
};
use crate::imports::{self as nt, ProcessHeap};
use crate::sd::{
    control,
    FIELD_DACL,
    FIELD_SACL,
    SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_PRESENT,
    SE_DACL_PROTECTED,
    SE_SACL_AUTO_INHERITED,
    SE_SACL_AUTO_INHERIT_REQ,
    SE_SACL_PRESENT,
    SE_SACL_PROTECTED,
    SE_SELF_RELATIVE,
};
use crate::sid::ERROR_INVALID_SECURITY_DESCR;
use crate::{caller_bytes_mut, Out};

// --- The cores

/// CreatePrivateObjectSecurity(Ex)'s core: a new self-relative descriptor on the process heap,
/// its components from `creator` when given, else `parent`'s, with the auto-inherit request
/// flags when a parent is given (and, for the Ex form, the inherited marks on the ACLs the SEF
/// auto-inherit bits name when the parent carries them); the block's address into `new_out`.
/// TRUE, or FALSE with the last error set.
fn create_core(parent: *const u8, creator: *const u8, new_out: *mut usize, sef_flags: u32) -> u32 {
    // SAFETY: the caller's out place.
    let mut new_out = unsafe { Out::optional(new_out) };
    let Some(new_out) = new_out.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the caller's descriptors.
    let parent_parts = match unsafe { read_parts(parent) } {
        Some(parts) => Some(parts),
        None => {
            nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
            return 0;
        }
    };
    // SAFETY: the caller's descriptor; a null creator means no creator descriptor.
    let creator_parts = if creator.is_null() {
        None
    } else {
        match unsafe { read_parts(creator) } {
            Some(parts) => Some(parts),
            None => {
                nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
                return 0;
            }
        }
    };
    let parent_given = !parent.is_null();
    let parts = creator_parts
        .or(parent_parts)
        .unwrap_or([None, None, None, None]);
    let parent = parent_parts.unwrap_or([None, None, None, None]);
    let mut control_bits = present_bits(&parts);
    if parent_given {
        control_bits |= SE_DACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERIT_REQ;
    }
    if sef_flags & SEF_DACL_AUTO_INHERIT != 0 && parent[FIELD_DACL].is_some() {
        control_bits |= SE_DACL_AUTO_INHERITED;
    }
    if sef_flags & SEF_SACL_AUTO_INHERIT != 0 && parent[FIELD_SACL].is_some() {
        control_bits |= SE_SACL_AUTO_INHERITED;
    }
    let size = storage_size(&parts);
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of `size` bytes, ours to write.
    let out = unsafe { core::slice::from_raw_parts_mut(block, size) };
    write_self_relative(out, control_bits, &parts);
    new_out.set(block as usize);
    1
}

/// GetPrivateObjectSecurity's core: the `object` descriptor's parts the `info` mask names copied
/// into the caller's `resultant` of `length` bytes as a self-relative descriptor, the size needed
/// into `return_length`. TRUE, or FALSE with the last error set (ERROR_INSUFFICIENT_BUFFER when
/// the buffer is too small, the size still reported).
fn get_core(
    object: *const u8,
    info: u32,
    resultant: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and size place.
    let (object, mut return_length) = unsafe { (read_sd(object), Out::optional(return_length)) };
    let Some((base, header)) = object else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the descriptor's components are read as it names them.
    let all = match unsafe { sd_parts(base, header) } {
        Some(parts) => parts,
        None => {
            nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
            return 0;
        }
    };
    let source_control = control(header);
    let mut selected: [Option<&[u8]>; 4] = [None, None, None, None];
    let mut control_bits = 0u16;
    for index in 0..4 {
        if info & FIELD_INFO[index] != 0 {
            selected[index] = all[index];
            control_bits |= propagate_bits(source_control, index);
        }
    }
    let needed = target_size(&selected) as u32;
    if let Some(return_length) = return_length.as_mut() {
        return_length.set(needed);
    }
    if needed > length {
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let size = storage_size(&selected);
    // SAFETY: the caller's buffer; on the target its `length` bytes hold the storage.
    let Some(out) = (unsafe { caller_bytes_mut(resultant, size) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    write_self_relative(out, control_bits, &selected);
    1
}

/// SetPrivateObjectSecurity(Ex)'s core: the parts the `info` mask names taken from `modification`
/// (a null one clears them) merged over the object descriptor the caller's `objects` slot holds,
/// reallocated on the process heap; the new address into the slot, the old block freed. TRUE, or
/// FALSE with the last error set.
fn set_core(info: u32, modification: *const u8, objects: *mut usize, sef_flags: u32) -> u32 {
    // SAFETY: the caller's pointer slot.
    let mut objects = unsafe { Out::optional(objects) };
    let Some(objects) = objects.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let current_ptr = objects.get();
    let mut current_parts: [Option<&[u8]>; 4] = [None, None, None, None];
    let mut control_bits = 0u16;
    if current_ptr != 0 {
        // SAFETY: the object descriptor the slot holds.
        let Some((base, header)) = (unsafe { read_sd(current_ptr as *const u8) }) else {
            nt::set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        // SAFETY: its components are read as it names them.
        let parts = match unsafe { sd_parts(base, header) } {
            Some(parts) => parts,
            None => {
                nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
                return 0;
            }
        };
        if control(header) & SE_SELF_RELATIVE == 0 {
            nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
            return 0;
        }
        current_parts = parts;
        control_bits = control(header);
    }
    // SAFETY: the caller's modification descriptor.
    let modification_parts = if modification.is_null() {
        [None, None, None, None]
    } else {
        match unsafe { read_parts(modification) } {
            Some(parts) => parts,
            None => {
                nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
                return 0;
            }
        }
    };
    let mut merged = current_parts;
    for index in 0..4 {
        if info & FIELD_INFO[index] != 0 {
            merged[index] = modification_parts[index];
        }
    }
    control_bits &= !(SE_DACL_PRESENT | SE_SACL_PRESENT);
    control_bits |= present_bits(&merged);
    if sef_flags & SEF_DACL_AUTO_INHERIT != 0 {
        control_bits |= SE_DACL_AUTO_INHERIT_REQ;
    }
    if sef_flags & SEF_SACL_AUTO_INHERIT != 0 {
        control_bits |= SE_SACL_AUTO_INHERIT_REQ;
    }
    let size = storage_size(&merged);
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of `size` bytes, ours to write.
    let out = unsafe { core::slice::from_raw_parts_mut(block, size) };
    write_self_relative(out, control_bits, &merged);
    if current_ptr != 0 {
        // SAFETY: the block CreatePrivateObjectSecurity handed out, freed once, nothing uses it
        // past the call.
        unsafe { ProcessHeap::free(current_ptr as *mut u8) };
    }
    objects.set(block as usize);
    1
}

/// DestroyPrivateObjectSecurity's core: the heap block the `object` slot holds freed, the slot
/// nulled. TRUE, or FALSE with the last error set (a null slot).
fn destroy_core(object: *mut usize) -> u32 {
    // SAFETY: the caller's pointer slot.
    let mut object = unsafe { Out::optional(object) };
    let Some(object) = object.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let ptr = object.get();
    if ptr != 0 {
        // SAFETY: the block CreatePrivateObjectSecurity handed out, freed once.
        unsafe { ProcessHeap::free(ptr as *mut u8) };
    }
    object.set(0);
    1
}

/// ConvertToAutoInheritPrivateObjectSecurity's core: a new self-relative descriptor on the
/// process heap from `current`'s components (the owner and group kept), its ACLs marked
/// auto-inherited when the `parent` carries them, protected otherwise; the block's address into
/// `new_out`. TRUE, or FALSE with the last error set.
fn convert_core(parent: *const u8, current: *const u8, new_out: *mut usize) -> u32 {
    // SAFETY: the caller's out place.
    let mut new_out = unsafe { Out::optional(new_out) };
    let Some(new_out) = new_out.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the caller's descriptors.
    let (current, parent_sd) = unsafe { (read_sd(current), read_sd(parent)) };
    let Some((base, header)) = current else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the descriptors' components are read as they name them.
    let parts = match unsafe { sd_parts(base, header) } {
        Some(parts) => parts,
        None => {
            nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
            return 0;
        }
    };
    let parent_parts = match parent_sd {
        Some((base, header)) => match unsafe { sd_parts(base, header) } {
            Some(parts) => Some(parts),
            None => {
                nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
                return 0;
            }
        },
        None if parent.is_null() => None,
        None => {
            nt::set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    let mut control_bits = control(header)
        & !(SE_DACL_AUTO_INHERITED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_DACL_PROTECTED
            | SE_SACL_AUTO_INHERITED
            | SE_SACL_AUTO_INHERIT_REQ
            | SE_SACL_PROTECTED);
    control_bits |= present_bits(&parts);
    if parts[FIELD_DACL].is_some() {
        control_bits |= match &parent_parts {
            Some(parent) if parent[FIELD_DACL].is_some() => SE_DACL_AUTO_INHERITED,
            _ => SE_DACL_PROTECTED,
        };
    }
    if parts[FIELD_SACL].is_some() {
        control_bits |= match &parent_parts {
            Some(parent) if parent[FIELD_SACL].is_some() => SE_SACL_AUTO_INHERITED,
            _ => SE_SACL_PROTECTED,
        };
    }
    let size = storage_size(&parts);
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block of `size` bytes, ours to write.
    let out = unsafe { core::slice::from_raw_parts_mut(block, size) };
    write_self_relative(out, control_bits, &parts);
    new_out.set(block as usize);
    1
}

// --- The exports
// Each converts its caller's pointers once, on entry, and hands the rest to its core. The
// arguments are the caller's, as the export's kinds say.

/// CreatePrivateObjectSecurity: the new self-relative descriptor for a protected server object,
/// from the creator descriptor (else the parent's), into `new`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_CreatePrivateObjectSecurity")]
pub unsafe extern "system" fn create_private_object_security(
    parent: *const u8,
    creator: *const u8,
    new: *mut usize,
    _is_directory: u32,
    _token: u32,
    _generic_mapping: *const u8,
) -> u32 {
    create_core(parent, creator, new, 0)
}

/// CreatePrivateObjectSecurityEx: CreatePrivateObjectSecurity with the object type's GUID and the
/// SEF auto-inherit flags.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_CreatePrivateObjectSecurityEx")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn create_private_object_security_ex(
    parent: *const u8,
    creator: *const u8,
    new: *mut usize,
    _object_type: *const u8,
    _is_container: u32,
    auto_inherit_flags: u32,
    _token: u32,
    _generic_mapping: *const u8,
) -> u32 {
    create_core(parent, creator, new, auto_inherit_flags)
}

/// GetPrivateObjectSecurity: the object descriptor's `info` parts into the caller's `resultant`
/// of `length` bytes, the size needed into `return_length`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetPrivateObjectSecurity")]
pub unsafe extern "system" fn get_private_object_security(
    object: *const u8,
    info: u32,
    resultant: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    get_core(object, info, resultant, length, return_length)
}

/// SetPrivateObjectSecurity: the `info` parts from the `modification` descriptor merged into the
/// object descriptor the `objects` slot holds.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetPrivateObjectSecurity")]
pub unsafe extern "system" fn set_private_object_security(
    info: u32,
    modification: *const u8,
    objects: *mut usize,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    set_core(info, modification, objects, 0)
}

/// SetPrivateObjectSecurityEx: SetPrivateObjectSecurity with the SEF auto-inherit flags.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetPrivateObjectSecurityEx")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn set_private_object_security_ex(
    info: u32,
    modification: *const u8,
    objects: *mut usize,
    auto_inherit_flags: u32,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    set_core(info, modification, objects, auto_inherit_flags)
}

/// DestroyPrivateObjectSecurity: the heap block the `object` slot holds freed, the slot nulled.
///
/// # Safety
///
/// `object` is the caller's place for the descriptor pointer.
#[unsafe(export_name = "f2k_export_DestroyPrivateObjectSecurity")]
pub unsafe extern "system" fn destroy_private_object_security(object: *mut usize) -> u32 {
    destroy_core(object)
}

/// ConvertToAutoInheritPrivateObjectSecurity: the `current` descriptor's ACLs marked
/// auto-inherited (when the parent carries them) or protected, into `new`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_ConvertToAutoInheritPrivateObjectSecurity")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn convert_to_auto_inherit_private_object_security(
    parent: *const u8,
    current: *const u8,
    new: *mut usize,
    _object_type: *const u8,
    _is_directory: u32,
    _generic_mapping: *const u8,
) -> u32 {
    convert_core(parent, current, new)
}

#[cfg(test)]
mod tests {
    use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER};

    use super::*;
    use crate::filesec::{
        DACL_SECURITY_INFORMATION,
        GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION,
    };
    use crate::imports::host::LAST_ERROR;
    use crate::private::testkit::{acl, control_of, parts_of, priv_sd, sid};
    use crate::sd::{
        long_align,
        sd_field,
        FIELD_GROUP,
        FIELD_OWNER,
        SD_HEADER,
        SD_REVISION,
        SE_DACL_DEFAULTED,
        SE_OWNER_DEFAULTED,
    };
    use crate::sid::{ptr_field, set_ptr_field};

    const WANT: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// CreatePrivateObjectSecurity(Ex): the new descriptor's components come from the creator
    /// when given, else the parent's; a parent sets the auto-inherit request flags; the Ex
    /// form's SEF flags mark the inherited ACLs when the parent carries them; the block's
    /// address goes into the out place. The error paths: a null out place, an invalid
    /// descriptor.
    #[test]
    fn create_builds_the_descriptor_from_the_creator_or_parent() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&sid(1, &[]));
        let creator = priv_sd(
            SE_DACL_PRESENT,
            Some(&owner),
            Some(&group),
            None,
            Some(&dacl),
        );
        let parent_dacl = acl(&sid(5, &[]));
        let parent = priv_sd(SE_DACL_PRESENT, None, None, None, Some(&parent_dacl));

        // The creator given, no parent: its components, no request flags.
        let mut slot = 0usize;
        arm();
        assert_eq!(
            create_core(core::ptr::null(), creator.as_ptr(), &mut slot, 0),
            1
        );
        assert_eq!(last_error(), 0xF2F2, "untouched on success");
        assert_ne!(slot, 0);
        assert_eq!(
            parts_of(slot),
            [
                Some(owner.clone()),
                Some(group.clone()),
                None,
                Some(dacl.clone())
            ]
        );
        let bits = control_of(slot);
        assert_eq!(bits & SE_SELF_RELATIVE, SE_SELF_RELATIVE);
        assert_eq!(bits & SE_DACL_PRESENT, SE_DACL_PRESENT);
        assert_eq!(
            bits & (SE_DACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERIT_REQ),
            0
        );
        assert_eq!(destroy_core(&mut slot), 1);
        assert_eq!(slot, 0);

        // No creator: the parent's components, with the request flags.
        let mut slot = 0usize;
        assert_eq!(
            create_core(parent.as_ptr(), core::ptr::null(), &mut slot, 0),
            1
        );
        assert_eq!(
            parts_of(slot),
            [None, None, None, Some(parent_dacl.clone())]
        );
        let bits = control_of(slot);
        assert_eq!(
            bits & (SE_DACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERIT_REQ),
            SE_DACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERIT_REQ
        );
        assert_eq!(destroy_core(&mut slot), 1);

        // Both given: the creator's components win, the parent still sets the request flags.
        let mut slot = 0usize;
        assert_eq!(
            create_core(parent.as_ptr(), creator.as_ptr(), &mut slot, 0),
            1
        );
        assert_eq!(parts_of(slot)[3], Some(dacl.clone()), "the creator's DACL");
        assert_eq!(
            control_of(slot) & SE_DACL_AUTO_INHERIT_REQ,
            SE_DACL_AUTO_INHERIT_REQ
        );
        assert_eq!(destroy_core(&mut slot), 1);

        // Neither: the bare header.
        let mut slot = 0usize;
        assert_eq!(
            create_core(core::ptr::null(), core::ptr::null(), &mut slot, 0),
            1
        );
        assert_eq!(parts_of(slot), [None, None, None, None]);
        assert_eq!(control_of(slot), SE_SELF_RELATIVE);
        assert_eq!(destroy_core(&mut slot), 1);

        // The Ex form: SEF_DACL_AUTO_INHERIT marks the DACL inherited when the parent has one.
        let mut slot = 0usize;
        assert_eq!(
            create_core(
                parent.as_ptr(),
                core::ptr::null(),
                &mut slot,
                SEF_DACL_AUTO_INHERIT
            ),
            1
        );
        let bits = control_of(slot);
        assert_eq!(bits & SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERITED);
        assert_eq!(bits & SE_SACL_AUTO_INHERITED, 0, "the parent has no SACL");
        assert_eq!(destroy_core(&mut slot), 1);

        // The error paths.
        arm();
        assert_eq!(
            create_core(
                core::ptr::null(),
                creator.as_ptr(),
                core::ptr::null_mut(),
                0
            ),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        let mut broken = creator.clone();
        broken[0] = 0;
        let mut slot = 0usize;
        arm();
        assert_eq!(
            create_core(core::ptr::null(), broken.as_ptr(), &mut slot, 0),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_SECURITY_DESCR);
        assert_eq!(slot, 0);
    }

    /// GetPrivateObjectSecurity: the size is reported first (a buffer too small answers
    /// ERROR_INSUFFICIENT_BUFFER with the size still set); with room, the requested parts are
    /// copied into a self-relative resultant with their PRESENT/DEFAULTED bits propagated, the
    /// unrequested parts left out. The error paths: a null or invalid object descriptor, a null
    /// length out (allowed, simply not written).
    #[test]
    fn get_copies_the_requested_parts_and_sizes_first() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&sid(1, &[]));
        let object = priv_sd(
            SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_OWNER_DEFAULTED,
            Some(&owner),
            Some(&group),
            None,
            Some(&dacl),
        );
        let selected: [Option<&[u8]>; 4] = [Some(&owner), Some(&group), None, Some(&dacl)];
        let needed = target_size(&selected) as u32;
        assert_eq!(
            needed,
            20 + owner.len() as u32 + group.len() as u32 + dacl.len() as u32
        );
        let group_at = SD_HEADER + owner.len();
        let dacl_at = long_align(group_at + group.len());

        // The size query: a null resultant, no room.
        let mut reported = 0xF2F2u32;
        arm();
        assert_eq!(
            get_core(
                object.as_ptr(),
                WANT,
                core::ptr::null_mut(),
                0,
                &mut reported
            ),
            0
        );
        assert_eq!(
            (last_error(), reported),
            (ERROR_INSUFFICIENT_BUFFER, needed)
        );

        // With the room asked for: the parts copied, the propagated bits.
        let mut buffer = vec![0xCCu8; storage_size(&selected)];
        let mut reported = 0u32;
        arm();
        assert_eq!(
            get_core(
                object.as_ptr(),
                WANT,
                buffer.as_mut_ptr(),
                needed,
                &mut reported
            ),
            1
        );
        assert_eq!((last_error(), reported), (0xF2F2, needed));
        assert_eq!(buffer[0], SD_REVISION);
        assert_eq!(
            u16::from_le_bytes(buffer[2..4].try_into().unwrap()),
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_OWNER_DEFAULTED
        );
        assert_eq!(
            (
                ptr_field(&buffer, sd_field(FIELD_OWNER)).unwrap(),
                ptr_field(&buffer, sd_field(FIELD_GROUP)).unwrap(),
                ptr_field(&buffer, sd_field(FIELD_SACL)).unwrap(),
                ptr_field(&buffer, sd_field(FIELD_DACL)).unwrap()
            ),
            (SD_HEADER, group_at, 0, dacl_at)
        );
        assert_eq!(&buffer[SD_HEADER..SD_HEADER + owner.len()], &owner[..]);
        assert_eq!(&buffer[dacl_at..dacl_at + dacl.len()], &dacl[..]);

        // Only the DACL asked for: the owner and group left out, their bits not propagated.
        let dacl_only: [Option<&[u8]>; 4] = [None, None, None, Some(&dacl)];
        let mut buffer = vec![0xCCu8; storage_size(&dacl_only)];
        let mut reported = 0u32;
        assert_eq!(
            get_core(
                object.as_ptr(),
                DACL_SECURITY_INFORMATION,
                buffer.as_mut_ptr(),
                target_size(&dacl_only) as u32,
                &mut reported
            ),
            1
        );
        assert_eq!(reported, 20 + dacl.len() as u32);
        assert_eq!(
            u16::from_le_bytes(buffer[2..4].try_into().unwrap()),
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_DEFAULTED
        );
        assert_eq!(ptr_field(&buffer, sd_field(FIELD_OWNER)).unwrap(), 0);
        assert_eq!(ptr_field(&buffer, sd_field(FIELD_DACL)).unwrap(), SD_HEADER);

        // The error paths.
        arm();
        assert_eq!(
            get_core(
                core::ptr::null(),
                WANT,
                buffer.as_mut_ptr(),
                64,
                &mut reported
            ),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        let mut broken = object.clone();
        broken[0] = 9;
        arm();
        assert_eq!(
            get_core(
                broken.as_ptr(),
                WANT,
                buffer.as_mut_ptr(),
                64,
                &mut reported
            ),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_SECURITY_DESCR);
        // A null length out is simply not written.
        let untouched = 0xF2F2u32;
        assert_eq!(
            get_core(
                object.as_ptr(),
                WANT,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut()
            ),
            0
        );
        assert_eq!(
            (last_error(), untouched),
            (ERROR_INSUFFICIENT_BUFFER, 0xF2F2)
        );
    }

    /// SetPrivateObjectSecurity(Ex): the parts the mask names are taken from the modification (a
    /// null one clears them) over the object's descriptor, reallocated on the heap with the new
    /// address in the slot; the unnamed parts are kept; the Ex form's SEF flags set the request
    /// bits. The error paths: a null slot, an invalid modification, a current descriptor that is
    /// not self-relative.
    #[test]
    fn set_merges_the_named_parts_and_reallocates() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&sid(1, &[]));
        let creator = priv_sd(
            SE_DACL_PRESENT,
            Some(&owner),
            Some(&group),
            None,
            Some(&dacl),
        );
        let mut slot = 0usize;
        assert_eq!(
            create_core(core::ptr::null(), creator.as_ptr(), &mut slot, 0),
            1
        );
        let first = slot;

        // The DACL replaced, the owner and group kept, the slot repointed.
        let new_dacl = acl(&sid(1, &[1]));
        let modification = priv_sd(SE_DACL_PRESENT, None, None, None, Some(&new_dacl));
        arm();
        assert_eq!(
            set_core(
                DACL_SECURITY_INFORMATION,
                modification.as_ptr(),
                &mut slot,
                0
            ),
            1
        );
        assert_eq!(last_error(), 0xF2F2);
        assert_ne!(slot, first, "reallocated");
        assert_eq!(
            parts_of(slot),
            [
                Some(owner.clone()),
                Some(group.clone()),
                None,
                Some(new_dacl.clone())
            ]
        );
        assert_eq!(
            control_of(slot) & (SE_SELF_RELATIVE | SE_DACL_PRESENT),
            SE_SELF_RELATIVE | SE_DACL_PRESENT
        );

        // The owner replaced, the DACL kept.
        let new_owner = sid(1, &[0]);
        let modification = priv_sd(0, Some(&new_owner), None, None, None);
        assert_eq!(
            set_core(
                OWNER_SECURITY_INFORMATION,
                modification.as_ptr(),
                &mut slot,
                0
            ),
            1
        );
        assert_eq!(
            parts_of(slot),
            [
                Some(new_owner.clone()),
                Some(group.clone()),
                None,
                Some(new_dacl.clone())
            ]
        );

        // A null modification clears the named part.
        assert_eq!(
            set_core(DACL_SECURITY_INFORMATION, core::ptr::null(), &mut slot, 0),
            1
        );
        assert_eq!(
            parts_of(slot),
            [Some(new_owner.clone()), Some(group.clone()), None, None]
        );
        assert_eq!(control_of(slot) & SE_DACL_PRESENT, 0);

        // The Ex form's flag sets the request bit.
        let modification = priv_sd(SE_DACL_PRESENT, None, None, None, Some(&dacl));
        assert_eq!(
            set_core(
                DACL_SECURITY_INFORMATION,
                modification.as_ptr(),
                &mut slot,
                SEF_DACL_AUTO_INHERIT
            ),
            1
        );
        assert_eq!(
            control_of(slot) & SE_DACL_AUTO_INHERIT_REQ,
            SE_DACL_AUTO_INHERIT_REQ
        );
        assert_eq!(destroy_core(&mut slot), 1);

        // The error paths.
        arm();
        assert_eq!(
            set_core(
                DACL_SECURITY_INFORMATION,
                modification.as_ptr(),
                core::ptr::null_mut(),
                0
            ),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        let mut slot = 0usize;
        assert_eq!(
            create_core(core::ptr::null(), creator.as_ptr(), &mut slot, 0),
            1
        );
        let mut broken = modification.clone();
        broken[0] = 0;
        arm();
        assert_eq!(
            set_core(DACL_SECURITY_INFORMATION, broken.as_ptr(), &mut slot, 0),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_SECURITY_DESCR);
        assert_eq!(destroy_core(&mut slot), 1);

        // A current descriptor that is not self-relative: the error.
        let abs_owner = sid(5, &[1]);
        let mut absolute = vec![0u8; SD_HEADER];
        absolute[0] = SD_REVISION;
        set_ptr_field(
            &mut absolute,
            sd_field(FIELD_OWNER),
            abs_owner.as_ptr() as usize,
        );
        let mut slot = absolute.as_ptr() as usize;
        arm();
        assert_eq!(
            set_core(
                OWNER_SECURITY_INFORMATION,
                modification.as_ptr(),
                &mut slot,
                0
            ),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_SECURITY_DESCR);
    }

    /// DestroyPrivateObjectSecurity: the block freed, the slot nulled, TRUE; a null slot is the
    /// error, an already-null slot a no-op success.
    #[test]
    fn destroy_frees_and_nulls() {
        let owner = sid(5, &[32]);
        let creator = priv_sd(0, Some(&owner), None, None, None);
        let mut slot = 0usize;
        assert_eq!(
            create_core(core::ptr::null(), creator.as_ptr(), &mut slot, 0),
            1
        );
        arm();
        assert_eq!(destroy_core(&mut slot), 1);
        assert_eq!((slot, last_error()), (0, 0xF2F2));
        assert_eq!(destroy_core(&mut slot), 1, "an already-null slot");
        arm();
        assert_eq!(destroy_core(core::ptr::null_mut()), 0);
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// ConvertToAutoInheritPrivateObjectSecurity: the new descriptor keeps the current's owner,
    /// group and components, its ACLs marked auto-inherited when the parent carries them,
    /// protected otherwise.
    #[test]
    fn convert_marks_the_acls_from_the_parent() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[0]);
        let dacl = acl(&sid(1, &[]));
        let sacl = acl(&sid(5, &[]));
        let current = priv_sd(
            SE_DACL_PRESENT | SE_SACL_PRESENT,
            Some(&owner),
            Some(&group),
            Some(&sacl),
            Some(&dacl),
        );
        let parent_dacl = acl(&sid(5, &[]));
        let parent = priv_sd(SE_DACL_PRESENT, None, None, None, Some(&parent_dacl));

        // The parent carries the DACL only: the DACL inherited, the SACL protected.
        let mut slot = 0usize;
        arm();
        assert_eq!(
            convert_core(parent.as_ptr(), current.as_ptr(), &mut slot),
            1
        );
        assert_eq!(last_error(), 0xF2F2);
        assert_ne!(slot, 0);
        let bits = control_of(slot);
        assert_eq!(bits & SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERITED);
        assert_eq!(bits & SE_DACL_PROTECTED, 0);
        assert_eq!(bits & SE_SACL_PROTECTED, SE_SACL_PROTECTED);
        assert_eq!(bits & SE_SACL_AUTO_INHERITED, 0);
        assert_eq!(
            parts_of(slot),
            [
                Some(owner.clone()),
                Some(group.clone()),
                Some(sacl.clone()),
                Some(dacl.clone())
            ],
            "the owner and group kept"
        );
        assert_eq!(destroy_core(&mut slot), 1);

        // A parent carrying both ACLs: both inherited. A null parent: both protected.
        let parent_both = priv_sd(
            SE_DACL_PRESENT | SE_SACL_PRESENT,
            None,
            None,
            Some(&sacl),
            Some(&parent_dacl),
        );
        let mut slot = 0usize;
        assert_eq!(
            convert_core(parent_both.as_ptr(), current.as_ptr(), &mut slot),
            1
        );
        let bits = control_of(slot);
        assert_eq!(
            bits & (SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED),
            SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED
        );
        assert_eq!(destroy_core(&mut slot), 1);
        let mut slot = 0usize;
        assert_eq!(
            convert_core(core::ptr::null(), current.as_ptr(), &mut slot),
            1
        );
        let bits = control_of(slot);
        assert_eq!(
            bits & (SE_DACL_PROTECTED | SE_SACL_PROTECTED),
            SE_DACL_PROTECTED | SE_SACL_PROTECTED
        );
        assert_eq!(destroy_core(&mut slot), 1);

        // The error paths: a null current, an invalid current, a null out place.
        let mut slot = 0usize;
        arm();
        assert_eq!(
            convert_core(core::ptr::null(), core::ptr::null(), &mut slot),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
        let mut broken = current.clone();
        broken[0] = 3;
        arm();
        assert_eq!(
            convert_core(core::ptr::null(), broken.as_ptr(), &mut slot),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_SECURITY_DESCR);
        arm();
        assert_eq!(
            convert_core(core::ptr::null(), current.as_ptr(), core::ptr::null_mut()),
            0
        );
        assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    }

    /// The exports convert their arguments once and run their cores.
    #[test]
    fn the_exports_convert_their_arguments_once() {
        let owner = sid(5, &[32, 544]);
        let dacl = acl(&sid(1, &[]));
        let creator = priv_sd(SE_DACL_PRESENT, Some(&owner), None, None, Some(&dacl));
        let mut slot = 0usize;
        // SAFETY: the test's own descriptors and slots.
        unsafe {
            assert_eq!(
                create_private_object_security(
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut slot,
                    0,
                    0,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(parts_of(slot)[3], Some(dacl.clone()));
            assert_eq!(
                create_private_object_security_ex(
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut slot,
                    core::ptr::null(),
                    0,
                    SEF_DACL_AUTO_INHERIT,
                    0,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(destroy_private_object_security(&mut slot), 1);
            assert_eq!(slot, 0);

            // Get: the size query, then the copy with the room asked for.
            let mut needed = 0u32;
            assert_eq!(
                get_private_object_security(
                    creator.as_ptr(),
                    WANT,
                    core::ptr::null_mut(),
                    0,
                    &mut needed
                ),
                0
            );
            assert_eq!((last_error(), needed), (ERROR_INSUFFICIENT_BUFFER, 60));
            let selected: [Option<&[u8]>; 4] = [Some(&owner), None, None, Some(&dacl)];
            let mut buffer = vec![0u8; storage_size(&selected)];
            assert_eq!(
                get_private_object_security(
                    creator.as_ptr(),
                    WANT,
                    buffer.as_mut_ptr(),
                    needed,
                    &mut needed
                ),
                1
            );

            // Set (both forms), convert, then destroy.
            let modification = priv_sd(SE_DACL_PRESENT, None, None, None, Some(&dacl));
            assert_eq!(
                set_private_object_security(
                    DACL_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    &mut slot,
                    core::ptr::null(),
                    0
                ),
                1
            );
            assert_ne!(slot, 0);
            assert_eq!(
                set_private_object_security_ex(
                    DACL_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    &mut slot,
                    SEF_DACL_AUTO_INHERIT,
                    core::ptr::null(),
                    0
                ),
                1
            );
            assert_eq!(
                control_of(slot) & SE_DACL_AUTO_INHERIT_REQ,
                SE_DACL_AUTO_INHERIT_REQ
            );
            assert_eq!(
                convert_to_auto_inherit_private_object_security(
                    core::ptr::null(),
                    creator.as_ptr(),
                    &mut slot,
                    core::ptr::null(),
                    0,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(destroy_private_object_security(&mut slot), 1);
        }
    }
}
