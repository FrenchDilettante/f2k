//! The trustee builders and queries: BuildTrusteeWithName/Sid/ObjectsAndName/ObjectsAndSid
//! A/W, BuildImpersonateTrusteeA/W, BuildImpersonateExplicitAccessWithNameA/W, and
//! GetTrusteeForm/Name/Type A/W, as Windows 2000's advapi32 answers them.
//!
//! A trustee is accctrl.h's TRUSTEE: a pointer to a multiple trustee, the operation, the form
//! (SID, name, objects and SID, objects and name), the type, and the name (a SID's or a name's
//! address, or the objects structure's, by the form). An explicit access entry is an
//! EXPLICIT_ACCESS: permissions, mode, inheritance, then a trustee. The builders fill the
//! caller's structure; the queries read it back. They touch no last error.
//!
//! The structures hold pointers, so on the host the tests run on a pointer field takes a whole
//! pointer's width where the target takes a dword (as [`crate::sid::PTR`]); the layouts below
//! give every pointer its own slot.

use rtl::pod::Pod;

use crate::sid::{ptr_field, set_ptr_field, PTR};
use crate::{caller_bytes, caller_bytes_mut};

// --- The structures' layouts (accctrl.h's) -----------------------------------------------------

/// A TRUSTEE's size: four dwords and two pointers.
pub(crate) const TRUSTEE_SIZE: usize = 12 + 2 * PTR;
/// The offsets in a TRUSTEE.
pub(crate) const TRUSTEE_MULTIPLE: usize = 0;
pub(crate) const TRUSTEE_OP: usize = PTR;
pub(crate) const TRUSTEE_FORM: usize = PTR + 4;
pub(crate) const TRUSTEE_TYPE: usize = PTR + 8;
pub(crate) const TRUSTEE_NAME: usize = PTR + 12;

/// An EXPLICIT_ACCESS's size and its trustee's offset.
pub(crate) const EA_SIZE: usize = 12 + TRUSTEE_SIZE;
pub(crate) const EA_PERMS: usize = 0;
pub(crate) const EA_MODE: usize = 4;
pub(crate) const EA_INHERITANCE: usize = 8;
pub(crate) const EA_TRUSTEE: usize = 12;

/// An OBJECTS_AND_SID's size and its SID pointer's offset.
pub(crate) const OAS_SIZE: usize = 36 + PTR;
pub(crate) const OAS_SID: usize = 36;

/// An OBJECTS_AND_NAME's size and its first name pointer's offset (three follow).
pub(crate) const OAN_SIZE: usize = 36 + 3 * PTR;
pub(crate) const OAN_NAMES: usize = 36;

/// The ObjectsPresent bits (the ACE object flags).
pub(crate) const OBJECT_TYPE_PRESENT: u32 = 0x1;
pub(crate) const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

/// A GUID's size.
pub(crate) const GUID: usize = 16;

/// The trustee forms (TRUSTEE_FORM).
pub(crate) const FORM_SID: u32 = 0;
pub(crate) const FORM_NAME: u32 = 1;
pub(crate) const FORM_OBJECTS_AND_SID: u32 = 3;
pub(crate) const FORM_OBJECTS_AND_NAME: u32 = 4;

/// The multiple trustee operations (MULTIPLE_TRUSTEE_OPERATION).
pub(crate) const OP_NONE: u32 = 0;
pub(crate) const OP_IMPERSONATE: u32 = 1;

/// The trustee types (TRUSTEE_TYPE).
pub(crate) const TYPE_UNKNOWN: u32 = 0;

fn dword(bytes: &[u8], at: usize) -> Option<u32> {
    u32::read_from(bytes, at)
}

fn set_dword(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = bytes.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// The caller's trustee, writable: none for null.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read and write.
unsafe fn trustee_mut<'a>(trustee: *mut u8) -> Option<&'a mut [u8]> {
    // SAFETY: the caller's trustee.
    unsafe { caller_bytes_mut(trustee, TRUSTEE_SIZE) }
}

/// Zero a trustee and set its operation, form, type and name.
fn fill_trustee(bytes: &mut [u8], op: u32, form: u32, name: usize) {
    bytes.fill(0);
    set_dword(bytes, TRUSTEE_OP, op);
    set_dword(bytes, TRUSTEE_FORM, form);
    set_dword(bytes, TRUSTEE_TYPE, TYPE_UNKNOWN);
    set_ptr_field(bytes, TRUSTEE_NAME, name);
}

/// BuildTrusteeWithNameA: a trustee by name: the form NAME, the name's address.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may write; `name` a NUL-terminated ANSI string.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithNameA")]
pub unsafe extern "system" fn build_trustee_with_name_a(trustee: *mut u8, name: *const u8) {
    // SAFETY: the caller's trustee and name.
    let buffer = unsafe { trustee_mut(trustee) };
    if let Some(buffer) = buffer {
        fill_trustee(buffer, OP_NONE, FORM_NAME, name as usize);
    }
}

/// BuildTrusteeWithNameW: as the A form, for a wide name.
///
/// # Safety
///
/// As the A form's, for a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithNameW")]
pub unsafe extern "system" fn build_trustee_with_name_w(trustee: *mut u8, name: *const u16) {
    // SAFETY: the caller's trustee and name.
    let buffer = unsafe { trustee_mut(trustee) };
    if let Some(buffer) = buffer {
        fill_trustee(buffer, OP_NONE, FORM_NAME, name as usize);
    }
}

/// BuildTrusteeWithSidA: a trustee by SID: the form SID, the SID's address as the name.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may write; `sid` a SID the call may read.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithSidA")]
pub unsafe extern "system" fn build_trustee_with_sid_a(trustee: *mut u8, sid: *const u8) {
    // SAFETY: the caller's trustee and SID.
    let buffer = unsafe { trustee_mut(trustee) };
    if let Some(buffer) = buffer {
        fill_trustee(buffer, OP_NONE, FORM_SID, sid as usize);
    }
}

/// BuildTrusteeWithSidW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithSidW")]
pub unsafe extern "system" fn build_trustee_with_sid_w(trustee: *mut u8, sid: *const u8) {
    // SAFETY: the caller's trustee and SID.
    let buffer = unsafe { trustee_mut(trustee) };
    if let Some(buffer) = buffer {
        fill_trustee(buffer, OP_NONE, FORM_SID, sid as usize);
    }
}

/// BuildTrusteeWithObjectsAndSidA/W's body: the objects-and-SID structure filled (the GUIDs
/// copied, the ObjectsPresent bits set to the GUIDs given), the trustee of the form
/// OBJECTS_AND_SID pointing at it.
///
/// # Safety
///
/// `trustee` and `objects` are null-or-writable structures; the GUID pointers null or 16 bytes.
unsafe fn build_objects_and_sid(
    trustee: *mut u8,
    objects: *mut u8,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) {
    // SAFETY: the caller's structures and GUIDs.
    let (trustee, objects) = unsafe { (trustee_mut(trustee), caller_bytes_mut(objects, OAS_SIZE)) };
    let (Some(trustee), Some(objects)) = (trustee, objects) else {
        return;
    };
    objects.fill(0);
    let mut present = 0u32;
    // SAFETY: the caller's GUIDs.
    for (guid, bit, at) in [
        (object_type, OBJECT_TYPE_PRESENT, 4),
        (
            inherited_object_type,
            INHERITED_OBJECT_TYPE_PRESENT,
            4 + GUID,
        ),
    ] {
        // SAFETY: the caller's GUID.
        if let Some(bytes) = unsafe { caller_bytes(guid, GUID) } {
            objects[at..at + GUID].copy_from_slice(bytes);
            present |= bit;
        }
    }
    set_dword(objects, 0, present);
    set_ptr_field(objects, OAS_SID, sid as usize);
    fill_trustee(
        trustee,
        OP_NONE,
        FORM_OBJECTS_AND_SID,
        objects.as_ptr() as usize,
    );
}

/// BuildTrusteeWithObjectsAndSidA: as [`build_objects_and_sid`], ANSI names.
///
/// # Safety
///
/// As [`build_objects_and_sid`]'s.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithObjectsAndSidA")]
pub unsafe extern "system" fn build_trustee_with_objects_and_sid_a(
    trustee: *mut u8,
    objects: *mut u8,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) {
    unsafe { build_objects_and_sid(trustee, objects, object_type, inherited_object_type, sid) }
}

/// BuildTrusteeWithObjectsAndSidW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithObjectsAndSidW")]
pub unsafe extern "system" fn build_trustee_with_objects_and_sid_w(
    trustee: *mut u8,
    objects: *mut u8,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) {
    unsafe { build_objects_and_sid(trustee, objects, object_type, inherited_object_type, sid) }
}

/// BuildTrusteeWithObjectsAndNameA/W's body: the objects-and-name structure filled (the names
/// at its three pointer slots, the ObjectsPresent bits set to the names given), the trustee of
/// the form OBJECTS_AND_NAME pointing at it.
///
/// # Safety
///
/// `trustee` and `objects` are null-or-writable structures; the name pointers null or strings.
unsafe fn build_objects_and_name(
    trustee: *mut u8,
    objects: *mut u8,
    object_type_name: *const u8,
    inherited_object_type_name: *const u8,
    name: *const u8,
) {
    // SAFETY: the caller's structures.
    let (trustee, objects) = unsafe { (trustee_mut(trustee), caller_bytes_mut(objects, OAN_SIZE)) };
    let (Some(trustee), Some(objects)) = (trustee, objects) else {
        return;
    };
    objects.fill(0);
    for (given, at) in [
        (object_type_name, OAN_NAMES),
        (inherited_object_type_name, OAN_NAMES + PTR),
        (name, OAN_NAMES + 2 * PTR),
    ] {
        if !given.is_null() {
            set_ptr_field(objects, at, given as usize);
        }
    }
    // The ObjectsPresent bits name the object type and inherited object type only.
    let bits = (if !object_type_name.is_null() {
        OBJECT_TYPE_PRESENT
    } else {
        0
    }) | (if !inherited_object_type_name.is_null() {
        INHERITED_OBJECT_TYPE_PRESENT
    } else {
        0
    });
    set_dword(objects, 0, bits);
    fill_trustee(
        trustee,
        OP_NONE,
        FORM_OBJECTS_AND_NAME,
        objects.as_ptr() as usize,
    );
}

/// BuildTrusteeWithObjectsAndNameA: as [`build_objects_and_name`], ANSI names.
///
/// # Safety
///
/// As [`build_objects_and_name`]'s.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithObjectsAndNameA")]
pub unsafe extern "system" fn build_trustee_with_objects_and_name_a(
    trustee: *mut u8,
    objects: *mut u8,
    _object_type: u32,
    object_type_name: *const u8,
    inherited_object_type_name: *const u8,
    name: *const u8,
) {
    unsafe {
        build_objects_and_name(
            trustee,
            objects,
            object_type_name,
            inherited_object_type_name,
            name,
        )
    }
}

/// BuildTrusteeWithObjectsAndNameW: as the A form, wide names.
///
/// # Safety
///
/// As the A form's, for NUL-terminated UTF-16 strings.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithObjectsAndNameW")]
pub unsafe extern "system" fn build_trustee_with_objects_and_name_w(
    trustee: *mut u8,
    objects: *mut u8,
    _object_type: u32,
    object_type_name: *const u16,
    inherited_object_type_name: *const u16,
    name: *const u16,
) {
    unsafe {
        build_objects_and_name(
            trustee,
            objects,
            object_type_name.cast(),
            inherited_object_type_name.cast(),
            name.cast(),
        )
    }
}

/// BuildImpersonateTrusteeA/W: the source trustee copied into `trustee`, its multiple trustee
/// operation set to impersonate.
///
/// # Safety
///
/// Both are TRUSTEEs the call may read and write.
unsafe fn build_impersonate_trustee(trustee: *mut u8, multiple: *const u8) {
    // SAFETY: the caller's trustees.
    let (dest, source) = unsafe { (trustee_mut(trustee), caller_bytes(multiple, TRUSTEE_SIZE)) };
    let (Some(dest), Some(source)) = (dest, source) else {
        return;
    };
    dest.copy_from_slice(source);
    set_dword(dest, TRUSTEE_OP, OP_IMPERSONATE);
}

/// BuildImpersonateTrusteeA: as [`build_impersonate_trustee`].
///
/// # Safety
///
/// As [`build_impersonate_trustee`]'s.
#[unsafe(export_name = "f2k_export_BuildImpersonateTrusteeA")]
pub unsafe extern "system" fn build_impersonate_trustee_a(trustee: *mut u8, multiple: *const u8) {
    unsafe { build_impersonate_trustee(trustee, multiple) }
}

/// BuildImpersonateTrusteeW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_BuildImpersonateTrusteeW")]
pub unsafe extern "system" fn build_impersonate_trustee_w(trustee: *mut u8, multiple: *const u8) {
    unsafe { build_impersonate_trustee(trustee, multiple) }
}

/// BuildImpersonateExplicitAccessWithNameA/W's body: the entry filled (permissions, mode,
/// inheritance) with a trustee by name whose multiple trustee is `multiple`, impersonating.
///
/// # Safety
///
/// `ea` is null or an EXPLICIT_ACCESS the call may write; `name` a string, `multiple` a TRUSTEE.
unsafe fn build_impersonate_explicit_access(
    ea: *mut u8,
    name: *const u8,
    multiple: *const u8,
    permissions: u32,
    mode: u32,
    inheritance: u32,
) {
    // SAFETY: the caller's entry, name and trustee.
    let buffer = unsafe { caller_bytes_mut(ea, EA_SIZE) };
    let Some(buffer) = buffer else {
        return;
    };
    buffer.fill(0);
    set_dword(buffer, EA_PERMS, permissions);
    set_dword(buffer, EA_MODE, mode);
    set_dword(buffer, EA_INHERITANCE, inheritance);
    let trustee = &mut buffer[EA_TRUSTEE..EA_TRUSTEE + TRUSTEE_SIZE];
    set_ptr_field(trustee, TRUSTEE_MULTIPLE, multiple as usize);
    set_dword(trustee, TRUSTEE_OP, OP_IMPERSONATE);
    set_dword(trustee, TRUSTEE_FORM, FORM_NAME);
    set_dword(trustee, TRUSTEE_TYPE, TYPE_UNKNOWN);
    set_ptr_field(trustee, TRUSTEE_NAME, name as usize);
}

/// BuildImpersonateExplicitAccessWithNameA: as [`build_impersonate_explicit_access`], ANSI name.
///
/// # Safety
///
/// As [`build_impersonate_explicit_access`]'s.
#[unsafe(export_name = "f2k_export_BuildImpersonateExplicitAccessWithNameA")]
pub unsafe extern "system" fn build_impersonate_explicit_access_with_name_a(
    ea: *mut u8,
    name: *const u8,
    multiple: *const u8,
    permissions: u32,
    mode: u32,
    inheritance: u32,
) {
    unsafe { build_impersonate_explicit_access(ea, name, multiple, permissions, mode, inheritance) }
}

/// BuildImpersonateExplicitAccessWithNameW: as the A form, wide name.
///
/// # Safety
///
/// As the A form's, for a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_BuildImpersonateExplicitAccessWithNameW")]
pub unsafe extern "system" fn build_impersonate_explicit_access_with_name_w(
    ea: *mut u8,
    name: *const u16,
    multiple: *const u8,
    permissions: u32,
    mode: u32,
    inheritance: u32,
) {
    unsafe {
        build_impersonate_explicit_access(ea, name.cast(), multiple, permissions, mode, inheritance)
    }
}

/// The caller's trustee: none for null.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
unsafe fn trustee_bytes<'a>(trustee: *const u8) -> Option<&'a [u8]> {
    // SAFETY: the caller's trustee.
    unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }
}

/// GetTrusteeFormA/W: the trustee's form.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
#[unsafe(export_name = "f2k_export_GetTrusteeFormA")]
pub unsafe extern "system" fn get_trustee_form_a(trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    unsafe { trustee_bytes(trustee) }
        .and_then(|bytes| dword(bytes, TRUSTEE_FORM))
        .unwrap_or(0)
}

/// GetTrusteeFormW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetTrusteeFormW")]
pub unsafe extern "system" fn get_trustee_form_w(trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    unsafe { get_trustee_form_a(trustee) }
}

/// GetTrusteeNameA/W: the trustee's name (its address: a SID's, a name's, or the objects
/// structure's, by the form).
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
#[unsafe(export_name = "f2k_export_GetTrusteeNameA")]
pub unsafe extern "system" fn get_trustee_name_a(trustee: *const u8) -> *mut u8 {
    // SAFETY: the caller's trustee.
    unsafe { trustee_bytes(trustee) }
        .and_then(|bytes| ptr_field(bytes, TRUSTEE_NAME))
        .map_or(core::ptr::null_mut(), |at| at as *mut u8)
}

/// GetTrusteeNameW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetTrusteeNameW")]
pub unsafe extern "system" fn get_trustee_name_w(trustee: *const u8) -> *mut u8 {
    // SAFETY: the caller's trustee.
    unsafe { get_trustee_name_a(trustee) }
}

/// GetTrusteeTypeA/W: the trustee's type.
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
#[unsafe(export_name = "f2k_export_GetTrusteeTypeA")]
pub unsafe extern "system" fn get_trustee_type_a(trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    unsafe { trustee_bytes(trustee) }
        .and_then(|bytes| dword(bytes, TRUSTEE_TYPE))
        .unwrap_or(0)
}

/// GetTrusteeTypeW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetTrusteeTypeW")]
pub unsafe extern "system" fn get_trustee_type_w(trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    unsafe { get_trustee_type_a(trustee) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// The name and SID builders fill the caller's structure (armed bytes come back set): the
    /// form, type 0, the name's address; the queries read them back and touch no error.
    #[test]
    fn name_and_sid_trustees_are_built_and_read() {
        let name = b"Everyone\0";
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        arm();
        unsafe { build_trustee_with_name_a(tr.as_mut_ptr(), name.as_ptr()) };
        assert_eq!(last_error(), 0xF2F2, "no error touched");
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_NAME));
        assert_eq!(dword(&tr, TRUSTEE_TYPE), Some(TYPE_UNKNOWN));
        assert_eq!(dword(&tr, TRUSTEE_OP), Some(OP_NONE));
        assert_eq!(ptr_field(&tr, TRUSTEE_MULTIPLE), Some(0));
        assert_eq!(ptr_field(&tr, TRUSTEE_NAME), Some(name.as_ptr() as usize));
        assert_eq!(unsafe { get_trustee_form_a(tr.as_ptr()) }, FORM_NAME);
        assert_eq!(
            unsafe { get_trustee_name_a(tr.as_ptr()) },
            name.as_ptr() as *mut u8
        );
        assert_eq!(unsafe { get_trustee_type_a(tr.as_ptr()) }, TYPE_UNKNOWN);
        // The W form.
        let wname = wide("Everyone");
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe { build_trustee_with_name_w(tr.as_mut_ptr(), wname.as_ptr()) };
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_NAME));
        assert_eq!(
            unsafe { get_trustee_name_w(tr.as_ptr()) },
            wname.as_ptr() as *mut u8
        );
        // The SID form: the name is the SID's address.
        let admins = sid(5, &[32, 544]);
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        arm();
        unsafe { build_trustee_with_sid_a(tr.as_mut_ptr(), admins.as_ptr()) };
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_SID));
        assert_eq!(
            unsafe { get_trustee_name_a(tr.as_ptr()) },
            admins.as_ptr() as *mut u8
        );
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe { build_trustee_with_sid_w(tr.as_mut_ptr(), admins.as_ptr()) };
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_SID));
        // A null trustee is left alone.
        assert_eq!(unsafe { get_trustee_form_a(core::ptr::null()) }, 0);
        assert!(unsafe { get_trustee_name_a(core::ptr::null()) }.is_null());
    }

    /// The objects-and-SID builder fills the caller's structure: the GUIDs copied, the
    /// ObjectsPresent bits set to the GUIDs given (a preset value is overwritten), the SID's
    /// address; the trustee's form is OBJECTS_AND_SID and its name the structure's address.
    #[test]
    fn objects_and_sid_trustees_are_built() {
        let admins = sid(5, &[32, 544]);
        let guid = [0xF2u8; GUID];
        let mut os = vec![0u8; OAS_SIZE];
        set_dword(
            &mut os,
            0,
            OBJECT_TYPE_PRESENT | INHERITED_OBJECT_TYPE_PRESENT,
        );
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe {
            build_trustee_with_objects_and_sid_a(
                tr.as_mut_ptr(),
                os.as_mut_ptr(),
                guid.as_ptr(),
                core::ptr::null(),
                admins.as_ptr(),
            )
        };
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_OBJECTS_AND_SID));
        assert_eq!(ptr_field(&tr, TRUSTEE_NAME), Some(os.as_ptr() as usize));
        assert_eq!(
            dword(&os, 0),
            Some(OBJECT_TYPE_PRESENT),
            "only the GUID bits"
        );
        assert_eq!(&os[4..4 + GUID], &guid);
        assert_eq!(ptr_field(&os, OAS_SID), Some(admins.as_ptr() as usize));
        // No GUIDs: the bits are 0.
        let mut os = vec![0xCCu8; OAS_SIZE];
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe {
            build_trustee_with_objects_and_sid_w(
                tr.as_mut_ptr(),
                os.as_mut_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                admins.as_ptr(),
            )
        };
        assert_eq!(dword(&os, 0), Some(0));
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_OBJECTS_AND_SID));
    }

    /// The objects-and-name builder: form OBJECTS_AND_NAME, the three names at the structure's
    /// pointer slots, the ObjectsPresent bits naming the type names given; GetTrusteeName
    /// answers the structure's address verbatim.
    #[test]
    fn objects_and_name_trustees_are_built() {
        let objtype = b"F2KObjectType\0";
        let name = b"Everyone\0";
        let wname = wide("Everyone");
        let mut on = vec![0u8; OAN_SIZE];
        set_dword(&mut on, 0, OBJECT_TYPE_PRESENT);
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe {
            build_trustee_with_objects_and_name_a(
                tr.as_mut_ptr(),
                on.as_mut_ptr(),
                1,
                objtype.as_ptr(),
                core::ptr::null(),
                name.as_ptr(),
            )
        };
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_OBJECTS_AND_NAME));
        assert_eq!(ptr_field(&tr, TRUSTEE_NAME), Some(on.as_ptr() as usize));
        assert_eq!(dword(&on, 0), Some(OBJECT_TYPE_PRESENT));
        assert_eq!(ptr_field(&on, OAN_NAMES), Some(objtype.as_ptr() as usize));
        assert_eq!(ptr_field(&on, OAN_NAMES + PTR), Some(0));
        assert_eq!(
            ptr_field(&on, OAN_NAMES + 2 * PTR),
            Some(name.as_ptr() as usize)
        );
        // GetTrusteeName answers the structure's address verbatim (the first byte is the
        // ObjectsPresent low byte).
        let named = unsafe { get_trustee_name_a(tr.as_ptr()) };
        assert_eq!(named, on.as_ptr() as *mut u8);
        assert_eq!(unsafe { *named }, 1);
        // The W form.
        let mut on = vec![0xCCu8; OAN_SIZE];
        let mut tr = vec![0xCCu8; TRUSTEE_SIZE];
        let wobjtype = wide("F2KObjectType");
        unsafe {
            build_trustee_with_objects_and_name_w(
                tr.as_mut_ptr(),
                on.as_mut_ptr(),
                1,
                wobjtype.as_ptr(),
                core::ptr::null(),
                wname.as_ptr(),
            )
        };
        assert_eq!(dword(&tr, TRUSTEE_FORM), Some(FORM_OBJECTS_AND_NAME));
        assert_eq!(
            ptr_field(&on, OAN_NAMES + 2 * PTR),
            Some(wname.as_ptr() as usize)
        );
    }

    /// BuildImpersonateTrustee copies the source and sets the impersonate operation;
    /// BuildImpersonateExplicitAccessWithName fills the entry and builds a name trustee in it
    /// whose multiple trustee is the one given, impersonating.
    #[test]
    fn impersonation_is_built() {
        let name = b"Everyone\0";
        let mut tr = vec![0u8; TRUSTEE_SIZE];
        unsafe { build_trustee_with_name_a(tr.as_mut_ptr(), name.as_ptr()) };
        let mut imp = vec![0xCCu8; TRUSTEE_SIZE];
        arm();
        unsafe { build_impersonate_trustee_a(imp.as_mut_ptr(), tr.as_ptr()) };
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(dword(&imp, TRUSTEE_OP), Some(OP_IMPERSONATE));
        assert_eq!(dword(&imp, TRUSTEE_FORM), Some(FORM_NAME));
        assert_eq!(ptr_field(&imp, TRUSTEE_NAME), Some(name.as_ptr() as usize));
        let mut imp = vec![0xCCu8; TRUSTEE_SIZE];
        unsafe { build_impersonate_trustee_w(imp.as_mut_ptr(), tr.as_ptr()) };
        assert_eq!(dword(&imp, TRUSTEE_OP), Some(OP_IMPERSONATE));
        // The explicit access entry.
        let mut ea = vec![0xCCu8; EA_SIZE];
        let src = vec![0u8; TRUSTEE_SIZE];
        unsafe {
            build_impersonate_explicit_access_with_name_a(
                ea.as_mut_ptr(),
                name.as_ptr(),
                src.as_ptr(),
                0x000F01FF,
                1,
                0,
            )
        };
        assert_eq!(dword(&ea, EA_PERMS), Some(0x000F01FF));
        assert_eq!(dword(&ea, EA_MODE), Some(1));
        assert_eq!(dword(&ea, EA_INHERITANCE), Some(0));
        let trustee = &ea[EA_TRUSTEE..EA_TRUSTEE + TRUSTEE_SIZE];
        assert_eq!(dword(trustee, TRUSTEE_OP), Some(OP_IMPERSONATE));
        assert_eq!(dword(trustee, TRUSTEE_FORM), Some(FORM_NAME));
        assert_eq!(
            ptr_field(trustee, TRUSTEE_MULTIPLE),
            Some(src.as_ptr() as usize)
        );
        assert_eq!(
            ptr_field(trustee, TRUSTEE_NAME),
            Some(name.as_ptr() as usize)
        );
        assert_eq!(
            unsafe { get_trustee_form_a(ea[EA_TRUSTEE..].as_ptr()) },
            FORM_NAME
        );
        // The W form.
        let wname = wide("Everyone");
        let mut ea = vec![0xCCu8; EA_SIZE];
        unsafe {
            build_impersonate_explicit_access_with_name_w(
                ea.as_mut_ptr(),
                wname.as_ptr(),
                src.as_ptr(),
                0x000F01FF,
                1,
                0,
            )
        };
        assert_eq!(dword(&ea, EA_PERMS), Some(0x000F01FF));
        let trustee = &ea[EA_TRUSTEE..EA_TRUSTEE + TRUSTEE_SIZE];
        assert_eq!(
            ptr_field(trustee, TRUSTEE_NAME),
            Some(wname.as_ptr() as usize)
        );
    }
}
