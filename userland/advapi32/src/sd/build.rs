//! The builders over trustee and access-list structures: BuildSecurityDescriptorA/W,
//! ConvertAccessToSecurityDescriptorA/W, and the ConvertSecurityDescriptorToAccess family.
//!
//! Trustee names resolve through the well-known names (no account database in F2K); an unknown
//! name is ERROR_NONE_MAPPED. An access entry becomes an ACE by its mode (grant and set: an
//! allowed ACE, deny: a denied one; the audit modes go to the SACL). F2K objects carry no
//! security descriptor, so the ConvertSecurityDescriptorToAccess family answers
//! ERROR_INVALID_PRIMARY_GROUP and touches nothing.

use rtl::edge::{InStr, InWStr};
use rtl::heap::ProcessHeap as _;
use rtl::pod::Pod;
use rtl::winerror::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY,
};

use crate::acl::{
    set_word, ACE_SIZE_OFF, ACL_COUNT_OFF, ACL_HEADER, ACL_REV_OFF, ACL_REVISION, ACL_SIZE_OFF,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FAILED_ACCESS_ACE_FLAG, KNOWN_ACE_FIXED,
    SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE_TYPE,
};
use crate::imports::{self as nt, ProcessHeap};
use crate::sid::{
    caller_sid, ptr_field, sid_len, sid_parts_bytes, well_known_sid, ERROR_INVALID_PRIMARY_GROUP,
    ERROR_NONE_MAPPED,
};
use crate::trustee::{
    EA_MODE, EA_PERMS, EA_SIZE, EA_TRUSTEE, FORM_NAME, FORM_OBJECTS_AND_SID, FORM_SID, OAS_SID,
    OAS_SIZE, TRUSTEE_FORM, TRUSTEE_NAME, TRUSTEE_SIZE,
};
use crate::{caller_bytes, caller_bytes_mut, Out};

use super::{
    long_align, set_control, set_sd_field_value, FIELD_DACL, FIELD_GROUP, FIELD_OWNER, FIELD_SACL,
    SD_HEADER, SD_REVISION, SD_TARGET_HEADER, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PRESENT,
    SE_SACL_AUTO_INHERIT_REQ, SE_SACL_PRESENT,
};

// --- The well-known names ------------------------------------------------------------------------

/// The well-known account names and their kinds (a WELL_KNOWN_SID_TYPE each).
const NAMES: &[(&str, u32)] = &[
    ("Everyone", 1),
    ("World", 1),
    ("CreatorOwner", 3),
    ("CreatorGroup", 4),
    ("Dialup", 8),
    ("Network", 9),
    ("Batch", 10),
    ("Interactive", 11),
    ("Service", 12),
    ("Anonymous", 13),
    ("EnterpriseDomainControllers", 15),
    ("PrincipalSelf", 16),
    ("Self", 16),
    ("AuthenticatedUsers", 17),
    ("Restricted", 18),
    ("LocalSystem", 22),
    ("System", 22),
    ("LocalService", 23),
    ("NetworkService", 24),
    ("Administrators", 26),
    ("Users", 27),
    ("Guests", 28),
    ("PowerUsers", 29),
    ("AccountOperators", 30),
    ("ServerOperators", 31),
    ("PrintOperators", 32),
    ("BackupOperators", 33),
    ("Replicator", 34),
    ("PreWindows2000CompatibleAccess", 35),
    ("RemoteDesktopUsers", 36),
];

/// The kind a well-known name names, compared case-insensitively.
fn name_kind(name: &[u8]) -> Option<u32> {
    NAMES
        .iter()
        .find(|(known, _)| known.as_bytes().eq_ignore_ascii_case(name))
        .map(|(_, kind)| *kind)
}

/// As [`name_kind`], for a UTF-16 name.
fn wide_name_kind(units: &[u16]) -> Option<u32> {
    NAMES.iter().find(|(known, _)| {
        let wide: Vec<u16> = known.encode_utf16().collect();
        wide.len() == units.len()
            && wide
                .iter()
                .zip(units)
                .all(|(a, b)| (*a as u8).to_ascii_lowercase() == (*b as u8).to_ascii_lowercase())
    }).map(|(_, kind)| *kind)
}

/// The SID bytes of a well-known kind.
fn sid_of_kind(kind: u32) -> Option<Vec<u8>> {
    let parts = well_known_sid(kind, None)?;
    let mut bytes = vec![0u8; sid_len(parts.count)];
    sid_parts_bytes(&parts, &mut bytes);
    Some(bytes)
}

fn dword(bytes: &[u8], at: usize) -> Option<u32> {
    u32::read_from(bytes, at)
}

/// The trustee's SID bytes: the SID form's, the objects-and-SID form's, or the well-known SID
/// a name form names.
///
/// # Safety
///
/// `trustee` is null or a trustee structure the call may read.
unsafe fn trustee_sid(trustee: *const u8, wide: bool) -> Option<Vec<u8>> {
    // SAFETY: the caller's trustee.
    let bytes = unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }?;
    let form = dword(bytes, TRUSTEE_FORM)?;
    let name = ptr_field(bytes, TRUSTEE_NAME)?;
    match form {
        FORM_SID => unsafe { caller_sid(name as *const u8) }.map(<[u8]>::to_vec),
        FORM_NAME => {
            let kind = if wide {
                // SAFETY: the caller's wide name.
                let name = unsafe { InWStr::optional(name as *const u16) }?;
                let units = name.units();
                let units: Vec<u16> = (0..units.len()).map(|at| units.get(at)).collect();
                wide_name_kind(&units)?
            } else {
                // SAFETY: the caller's ANSI name.
                let name = unsafe { InStr::optional(name as *const u8) }?;
                name_kind(name.bytes())?
            };
            sid_of_kind(kind)
        }
        FORM_OBJECTS_AND_SID => {
            // SAFETY: the objects-and-SID structure the trustee points at.
            let objects = unsafe { caller_bytes(name as *const u8, OAS_SIZE) }?;
            let sid = ptr_field(objects, OAS_SID)?;
            unsafe { caller_sid(sid as *const u8) }.map(<[u8]>::to_vec)
        }
        _ => None,
    }
}

/// An access-list entry: its mode and mask, and its trustee's SID.
struct Access {
    mode: u32,
    mask: u32,
    sid: Vec<u8>,
}

/// The access list at `list` (`count` entries): none for an entry whose trustee has no SID.
///
/// # Safety
///
/// `list` is null (for a zero count) or `count` entries the call may read.
unsafe fn entries_of(list: *const u8, count: u32, wide: bool) -> Option<Vec<Access>> {
    if count == 0 {
        return Some(Vec::new());
    }
    // SAFETY: the caller's list.
    let bytes = unsafe { caller_bytes(list, count as usize * EA_SIZE) }?;
    let mut entries = Vec::new();
    for index in 0..count as usize {
        let at = index * EA_SIZE;
        let mode = dword(bytes, at + EA_MODE)?;
        let mask = dword(bytes, at + EA_PERMS)?;
        // SAFETY: the entry's trustee.
        let sid = unsafe { trustee_sid(bytes[at + EA_TRUSTEE..].as_ptr(), wide) }?;
        entries.push(Access { mode, mask, sid });
    }
    Some(entries)
}

/// The ACE mode values (ACCESS_MODE).
const AM_DENY: u32 = 3;
const AM_SET_AUDIT_SUCCESS: u32 = 5;
const AM_SET_AUDIT_FAILURE: u32 = 6;

/// An ACL of plain ACEs, one per access entry: allowed for grant and set, denied for deny, in
/// the DACL; the audit modes go to the SACL as audit ACEs.
fn build_acls(access: &[Access], audit: &[Access]) -> (Vec<u8>, Vec<u8>) {
    let mut dacl = Vec::new();
    let mut sacl = Vec::new();
    let push = |acl: &mut Vec<u8>, kind: u8, flags: u32, mask: u32, sid: &[u8]| {
        let ace_size = KNOWN_ACE_FIXED + sid.len();
        acl.push(kind);
        acl.push(flags as u8);
        acl.extend((ace_size as u16).to_le_bytes());
        acl.extend(mask.to_le_bytes());
        acl.extend_from_slice(sid);
    };
    for entry in access {
        match entry.mode {
            AM_DENY => push(&mut dacl, ACCESS_DENIED_ACE_TYPE, 0, entry.mask, &entry.sid),
            _ => push(&mut dacl, ACCESS_ALLOWED_ACE_TYPE, 0, entry.mask, &entry.sid),
        }
    }
    for entry in audit {
        let flags = match entry.mode {
            AM_SET_AUDIT_SUCCESS => SUCCESSFUL_ACCESS_ACE_FLAG,
            AM_SET_AUDIT_FAILURE => FAILED_ACCESS_ACE_FLAG,
            _ => SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
        };
        push(&mut sacl, SYSTEM_AUDIT_ACE_TYPE, flags, entry.mask, &entry.sid);
    }
    let wrap = |body: Vec<u8>| -> Vec<u8> {
        if body.is_empty() {
            return Vec::new();
        }
        let mut acl = vec![0u8; ACL_HEADER];
        acl[ACL_REV_OFF] = ACL_REVISION as u8;
        set_word(&mut acl, ACL_SIZE_OFF, (ACL_HEADER + body.len()) as u16);
        // The ACE count: walking the body.
        let mut count = 0u16;
        let mut at = 0;
        while at < body.len() {
            at += usize::from(u16::from_le_bytes([
                body[at + ACE_SIZE_OFF],
                body[at + ACE_SIZE_OFF + 1],
            ]));
            count += 1;
        }
        set_word(&mut acl, ACL_COUNT_OFF, count);
        acl.extend(body);
        acl
    };
    (wrap(dacl), wrap(sacl))
}

/// The components of a built descriptor: (owner, group, sacl, dacl) byte strings.
fn components_of(
    owner: &[u8],
    group: &[u8],
    dacl: &[u8],
    sacl: &[u8],
) -> [Option<Vec<u8>>; 4] {
    [
        Some(owner.to_vec()),
        Some(group.to_vec()),
        if sacl.is_empty() { None } else { Some(sacl.to_vec()) },
        if dacl.is_empty() { None } else { Some(dacl.to_vec()) },
    ]
}

/// The size a built absolute descriptor takes on the target, and the storage it takes on the
/// host: the header plus the long-aligned components.
fn built_sizes(components: &[Option<Vec<u8>>; 4]) -> (usize, usize) {
    let sum: usize = components.iter().flatten().map(|c| long_align(c.len())).sum();
    (SD_TARGET_HEADER + sum, SD_HEADER + sum)
}

/// Write an absolute descriptor into `out` (of `used` bytes): the header, then the components
/// at running offsets, the fields their absolute addresses, `extra_control` OR'd in.
fn write_absolute(out: &mut [u8], components: &[Option<Vec<u8>>; 4], extra_control: u16) {
    out.fill(0);
    out[0] = SD_REVISION;
    set_control(out, extra_control);
    let base = out.as_ptr() as usize;
    let mut running = SD_HEADER;
    // The fields' order is owner, group, sacl, dacl; pack in the self-relative order.
    for index in [FIELD_SACL, FIELD_DACL, FIELD_OWNER, FIELD_GROUP] {
        if let Some(component) = &components[index] {
            running = long_align(running);
            out[running..running + component.len()].copy_from_slice(component);
            set_sd_field_value(out, index, base + running);
            running += long_align(component.len());
        }
    }
}

/// BuildSecurityDescriptorA/W's body: the descriptor built from the owner and group trustees and
/// the access and audit lists into `sd` (its room `size` pointing at). Both a short buffer and a
/// built descriptor answer FALSE with ERROR_INSUFFICIENT_BUFFER as the last error and the size
/// (needed, or used) in `*size`; a trustee with no resolvable SID is ERROR_NONE_MAPPED.
///
/// # Safety
///
/// The trustees, lists and descriptor are the caller's.
#[allow(clippy::too_many_arguments)]
unsafe fn build_security_descriptor(
    owner: *const u8,
    group: *const u8,
    access_count: u32,
    access_list: *const u8,
    audit_count: u32,
    audit_list: *const u8,
    sd: *mut u8,
    size: *mut u32,
    new_sd: *mut *mut u8,
    wide: bool,
) -> u32 {
    // SAFETY: the caller's trustees and lists.
    let (owner, group, access, audit) = unsafe {
        (
            trustee_sid(owner, wide),
            trustee_sid(group, wide),
            entries_of(access_list, access_count, wide),
            entries_of(audit_list, audit_count, wide),
        )
    };
    let (Some(owner), Some(group), Some(access), Some(audit)) = (owner, group, access, audit) else {
        nt::set_last_error(ERROR_NONE_MAPPED);
        return 0;
    };
    let (dacl, sacl) = build_acls(&access, &audit);
    let components = components_of(&owner, &group, &dacl, &sacl);
    let (needed, used) = built_sizes(&components);
    // SAFETY: the caller's place.
    let mut room = unsafe { Out::optional(size) };
    let Some(room) = room.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if sd.is_null() || room.get() < needed as u32 {
        room.set(needed as u32);
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's buffer of `used` bytes at least, writable.
    let out = unsafe { caller_bytes_mut(sd, used.max(needed)) };
    let Some(out) = out else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    write_absolute(out, &components, 0);
    room.set(needed as u32);
    // SAFETY: the caller's place for the descriptor's address.
    if let Some(mut new_sd) = unsafe { Out::optional(new_sd) } {
        new_sd.set(sd);
    }
    nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
    0
}

/// BuildSecurityDescriptorA: as [`build_security_descriptor`], ANSI trustee names.
///
/// # Safety
///
/// As [`build_security_descriptor`]'s.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_BuildSecurityDescriptorA")]
pub unsafe extern "system" fn build_security_descriptor_a(
    owner: *const u8,
    group: *const u8,
    access_count: u32,
    access_list: *const u8,
    audit_count: u32,
    audit_list: *const u8,
    sd: *mut u8,
    size: *mut u32,
    new_sd: *mut *mut u8,
) -> u32 {
    unsafe {
        build_security_descriptor(
            owner,
            group,
            access_count,
            access_list,
            audit_count,
            audit_list,
            sd,
            size,
            new_sd,
            false,
        )
    }
}

/// BuildSecurityDescriptorW: as the A form, wide trustee names.
///
/// # Safety
///
/// As the A form's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_BuildSecurityDescriptorW")]
pub unsafe extern "system" fn build_security_descriptor_w(
    owner: *const u8,
    group: *const u8,
    access_count: u32,
    access_list: *const u8,
    audit_count: u32,
    audit_list: *const u8,
    sd: *mut u8,
    size: *mut u32,
    new_sd: *mut *mut u8,
) -> u32 {
    unsafe {
        build_security_descriptor(
            owner,
            group,
            access_count,
            access_list,
            audit_count,
            audit_list,
            sd,
            size,
            new_sd,
            true,
        )
    }
}

/// ConvertAccessToSecurityDescriptorA/W's body: a descriptor built from the access and audit
/// lists and the owner and group names, allocated from the process heap, its address into
/// `new_sd`; the answer is an error code (ERROR_SUCCESS when built). The descriptor carries the
/// DACL (and SACL, for a non-empty audit list) with the auto-inherit-requested bits.
///
/// # Safety
///
/// The lists and names are the caller's; `new_sd` the caller's place.
#[allow(clippy::too_many_arguments)]
unsafe fn convert_access_to_sd(
    access_list: *const u8,
    audit_list: *const u8,
    owner_name: *const u8,
    group_name: *const u8,
    new_sd: *mut *mut u8,
    wide: bool,
) -> u32 {
    // The list structure is a count and a pointer to the entries.
    fn read_list(list: *const u8, wide: bool) -> Option<Vec<Access>> {
        if list.is_null() {
            return Some(Vec::new());
        }
        // SAFETY: the caller's list structure: a count, then a pointer field.
        let head = unsafe { caller_bytes(list, 4 + crate::sid::PTR) }?;
        let count = dword(head, 0)?;
        let entries = ptr_field(head, 4)?;
        // SAFETY: the caller's entries.
        unsafe { entries_of(entries as *const u8, count, wide) }
    }
    // SAFETY: the caller's lists.
    let (Some(access), Some(audit)) = (read_list(access_list, wide), read_list(audit_list, wide)) else {
        return ERROR_INVALID_PARAMETER;
    };
    let owner = name_sid(owner_name, wide);
    let group = name_sid(group_name, wide);
    let (Some(owner), Some(group)) = (owner, group) else {
        return ERROR_NONE_MAPPED;
    };
    let (dacl, sacl) = build_acls(&access, &audit);
    let mut components = components_of(&owner, &group, &dacl, &sacl);
    // An empty access list still carries a (present, empty) DACL.
    if components[FIELD_DACL].is_none() {
        let mut empty = vec![0u8; ACL_HEADER];
        empty[ACL_REV_OFF] = ACL_REVISION as u8;
        set_word(&mut empty, ACL_SIZE_OFF, ACL_HEADER as u16);
        components[FIELD_DACL] = Some(empty);
    }
    let (_, used) = built_sizes(&components);
    let block = ProcessHeap::allocate(used);
    if block.is_null() {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    // SAFETY: the heap's new block of `used` bytes, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block, used) };
    let extra = SE_DACL_PRESENT
        | SE_DACL_AUTO_INHERIT_REQ
        | if components[FIELD_SACL].is_some() {
            SE_SACL_PRESENT | SE_SACL_AUTO_INHERIT_REQ
        } else {
            0
        };
    write_absolute(out, &components, extra);
    // SAFETY: the caller's place.
    if let Some(mut new_sd) = unsafe { Out::optional(new_sd) } {
        new_sd.set(block);
    }
    0
}

/// A name argument's well-known SID bytes (null: none).
///
/// # Safety
///
/// `name` is null or a string the call may read.
unsafe fn name_sid(name: *const u8, wide: bool) -> Option<Vec<u8>> {
    if name.is_null() {
        return None;
    }
    let kind = if wide {
        // SAFETY: the caller's wide name.
        let name = unsafe { InWStr::optional(name as *const u16) }?;
        let units = name.units();
        let units: Vec<u16> = (0..units.len()).map(|at| units.get(at)).collect();
        wide_name_kind(&units)?
    } else {
        // SAFETY: the caller's ANSI name.
        let name = unsafe { InStr::optional(name as *const u8) }?;
        name_kind(name.bytes())?
    };
    sid_of_kind(kind)
}

/// ConvertAccessToSecurityDescriptorA: as [`convert_access_to_sd`], ANSI names.
///
/// # Safety
///
/// As [`convert_access_to_sd`]'s.
#[unsafe(export_name = "f2k_export_ConvertAccessToSecurityDescriptorA")]
pub unsafe extern "system" fn convert_access_to_security_descriptor_a(
    access_list: *const u8,
    audit_list: *const u8,
    owner_name: *const u8,
    group_name: *const u8,
    new_sd: *mut *mut u8,
) -> u32 {
    unsafe {
        convert_access_to_sd(access_list, audit_list, owner_name, group_name, new_sd, false)
    }
}

/// ConvertAccessToSecurityDescriptorW: as the A form, wide names.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_ConvertAccessToSecurityDescriptorW")]
pub unsafe extern "system" fn convert_access_to_security_descriptor_w(
    access_list: *const u8,
    audit_list: *const u8,
    owner_name: *const u16,
    group_name: *const u16,
    new_sd: *mut *mut u8,
) -> u32 {
    unsafe {
        convert_access_to_sd(
            access_list,
            audit_list,
            owner_name.cast(),
            group_name.cast(),
            new_sd,
            true,
        )
    }
}

/// ConvertSecurityDescriptorToAccessA/W's body: F2K objects carry no security descriptor, so the
/// answer is ERROR_INVALID_PRIMARY_GROUP and nothing is touched.
#[allow(clippy::too_many_arguments)]
unsafe fn convert_sd_to_access() -> u32 {
    ERROR_INVALID_PRIMARY_GROUP
}

/// ConvertSecurityDescriptorToAccessA: as [`convert_sd_to_access`].
///
/// # Safety
///
/// The arguments are the caller's, unused.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToAccessA")]
pub unsafe extern "system" fn convert_security_descriptor_to_access_a(
    _handle: u32,
    _object_type: u32,
    _sd: *const u8,
    _access_list: *mut *mut u8,
    _audit_list: *mut *mut u8,
    _owner_name: *mut *mut u8,
    _group_name: *mut *mut u8,
) -> u32 {
    unsafe { convert_sd_to_access() }
}

/// ConvertSecurityDescriptorToAccessW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToAccessW")]
pub unsafe extern "system" fn convert_security_descriptor_to_access_w(
    _handle: u32,
    _object_type: u32,
    _sd: *const u8,
    _access_list: *mut *mut u8,
    _audit_list: *mut *mut u8,
    _owner_name: *mut *mut u8,
    _group_name: *mut *mut u8,
) -> u32 {
    unsafe { convert_sd_to_access() }
}

/// ConvertSecurityDescriptorToAccessNamedA: as the A form, the object named.
///
/// # Safety
///
/// As the A form's, `name` a string the call does not read.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToAccessNamedA")]
pub unsafe extern "system" fn convert_security_descriptor_to_access_named_a(
    _name: *const u8,
    _object_type: u32,
    _sd: *const u8,
    _access_list: *mut *mut u8,
    _audit_list: *mut *mut u8,
    _owner_name: *mut *mut u8,
    _group_name: *mut *mut u8,
) -> u32 {
    unsafe { convert_sd_to_access() }
}

/// ConvertSecurityDescriptorToAccessNamedW: as the named A form, a wide name.
///
/// # Safety
///
/// As the named A form's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToAccessNamedW")]
pub unsafe extern "system" fn convert_security_descriptor_to_access_named_w(
    _name: *const u16,
    _object_type: u32,
    _sd: *const u8,
    _access_list: *mut *mut u8,
    _audit_list: *mut *mut u8,
    _owner_name: *mut *mut u8,
    _group_name: *mut *mut u8,
) -> u32 {
    unsafe { convert_sd_to_access() }
}

