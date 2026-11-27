//! GetEffectiveRightsFromAcl A/W and the multiple-trustee queries, as a program that asks what
//! a trustee may do makes them.
//!
//! GetEffectiveRightsFromAcl walks the caller's ACL for the trustee's SID: the allow ACEs' masks
//! unioned minus the deny ACEs' (a deny wins whatever its order), stripped to the effective
//! bits (see [`super::effective_rights`]). It returns the Win32 error code (ERROR_SUCCESS on a
//! success, also left as the last error on a failure). A trustee by name resolves against the
//! well-known accounts only, and leaves ERROR_ENVVAR_NOT_FOUND as the last error on the success
//! path, as the capture shows; a name no well-known account spells leaves the mask untouched.
//!
//! GetMultipleTrustee and GetMultipleTrusteeOperation read the trustee's multiple-trustee
//! pointer and operation; a null trustee answers null and zero.

use rtl::winerror::{ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_PARAMETER};

use super::{effective_rights, trustee_sid};
use crate::acl::{caller_acl, edit};
use crate::explicit::fail;
use crate::imports::{self as nt};
use crate::sid::ptr_field;
use crate::sid::ERROR_INVALID_ACL;
use crate::trustee::{TRUSTEE_MULTIPLE, TRUSTEE_OP, TRUSTEE_SIZE};
use crate::{caller_bytes, Out};

/// GetEffectiveRightsFromAclA/W's body: the ACL walked for the trustee's SID, the effective mask
/// into the caller's place. `wide` says the trustee's name form is a wide string.
///
/// # Safety
///
/// The pointers are the caller's: the ACL, the trustee and the mask's place.
unsafe fn effective_rights_from_acl(
    acl: *const u8,
    trustee: *const u8,
    access: *mut u32,
    wide: bool,
) -> u32 {
    // SAFETY: the caller's ACL, trustee and place.
    let (buffer, trustee_bytes, mut place) = unsafe {
        (
            caller_acl(acl),
            caller_bytes(trustee, TRUSTEE_SIZE),
            Out::optional(access),
        )
    };
    if buffer.is_none() || trustee_bytes.is_none() || place.is_none() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let buffer = buffer.unwrap();
    if !edit::valid_acl(buffer) {
        return fail(ERROR_INVALID_ACL);
    }
    // SAFETY: the caller's trustee.
    let resolved = match unsafe { trustee_sid(trustee, wide) } {
        Ok(resolved) => resolved,
        Err(error) => return fail(error),
    };
    let Some(resolved) = resolved else {
        // A name no well-known account spells: no account database to resolve it against, and
        // the capture's last error for a name-form trustee.
        nt::set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    };
    let mask = effective_rights(buffer, resolved.as_slice());
    // SAFETY: the caller's place for the mask.
    place.as_mut().unwrap().set(mask);
    if wide_name_form(trustee_bytes.unwrap()) {
        // A name-form trustee leaves the capture's last error even on a success.
        nt::set_last_error(ERROR_ENVVAR_NOT_FOUND);
    }
    0
}

/// Whether the trustee's form is the name one.
fn wide_name_form(trustee: &[u8]) -> bool {
    crate::acl::dword(trustee, crate::trustee::TRUSTEE_FORM) == Some(crate::trustee::FORM_NAME)
}

/// GetEffectiveRightsFromAclA: the effective rights of the trustee in the ACL, into the caller's
/// mask. The return is the Win32 error code: ERROR_SUCCESS when the mask is written.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetEffectiveRightsFromAclA")]
pub unsafe extern "system" fn get_effective_rights_from_acl_a(
    acl: *const u8,
    trustee: *const u8,
    access: *mut u32,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe { effective_rights_from_acl(acl, trustee, access, false) }
}

/// GetEffectiveRightsFromAclW: as the A form, for a wide trustee name.
///
/// # Safety
///
/// As the A form's, for a NUL-terminated UTF-16 name.
#[unsafe(export_name = "f2k_export_GetEffectiveRightsFromAclW")]
pub unsafe extern "system" fn get_effective_rights_from_acl_w(
    acl: *const u8,
    trustee: *const u8,
    access: *mut u32,
) -> u32 {
    // SAFETY: as the A form's.
    unsafe { effective_rights_from_acl(acl, trustee, access, true) }
}

/// GetMultipleTrusteeA/W: the trustee's multiple-trustee pointer (null for none).
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
#[unsafe(export_name = "f2k_export_GetMultipleTrusteeA")]
pub unsafe extern "system" fn get_multiple_trustee_a(trustee: *const u8) -> *mut u8 {
    multiple_trustee(trustee)
}

/// GetMultipleTrusteeW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetMultipleTrusteeW")]
pub unsafe extern "system" fn get_multiple_trustee_w(trustee: *const u8) -> *mut u8 {
    multiple_trustee(trustee)
}

/// The trustee's multiple-trustee pointer, null for a null trustee or none.
fn multiple_trustee(trustee: *const u8) -> *mut u8 {
    // SAFETY: the caller's trustee.
    unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }
        .and_then(|bytes| ptr_field(bytes, TRUSTEE_MULTIPLE))
        .map_or(core::ptr::null_mut(), |at| at as *mut u8)
}

/// GetMultipleTrusteeOperationA/W: the trustee's multiple-trustee operation (zero for a null
/// trustee or none).
///
/// # Safety
///
/// `trustee` is null or a TRUSTEE the call may read.
#[unsafe(export_name = "f2k_export_GetMultipleTrusteeOperationA")]
pub unsafe extern "system" fn get_multiple_trustee_operation_a(trustee: *const u8) -> u32 {
    multiple_trustee_operation(trustee)
}

/// GetMultipleTrusteeOperationW: as the A form.
///
/// # Safety
///
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetMultipleTrusteeOperationW")]
pub unsafe extern "system" fn get_multiple_trustee_operation_w(trustee: *const u8) -> u32 {
    multiple_trustee_operation(trustee)
}

/// The trustee's operation, zero for a null trustee.
fn multiple_trustee_operation(trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    unsafe { caller_bytes(trustee, TRUSTEE_SIZE) }
        .and_then(|bytes| crate::acl::dword(bytes, TRUSTEE_OP))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use rtl::winerror::{ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_INVALID_SID};

    use super::*;
    use crate::explicit::tests_support::{make_acl, sid};
    use crate::imports::host::LAST_ERROR;
    use crate::sid::ERROR_INVALID_ACL;
    use crate::trustee::{
        FORM_NAME,
        FORM_SID,
        TRUSTEE_FORM,
        TRUSTEE_MULTIPLE,
        TRUSTEE_NAME,
        TRUSTEE_OP,
    };

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// A TRUSTEE by SID: the form SID, the SID's address as the name.
    fn trustee_by_sid(sid: &[u8]) -> Vec<u8> {
        let mut trustee = vec![0u8; TRUSTEE_SIZE];
        crate::acl::set_dword(&mut trustee, TRUSTEE_FORM, FORM_SID);
        crate::sid::set_ptr_field(&mut trustee, TRUSTEE_NAME, sid.as_ptr() as usize);
        trustee
    }

    /// A TRUSTEE by name: the form NAME, the name's address as the name.
    fn trustee_by_name(name: &[u8]) -> Vec<u8> {
        let mut trustee = vec![0u8; TRUSTEE_SIZE];
        crate::acl::set_dword(&mut trustee, TRUSTEE_FORM, FORM_NAME);
        crate::sid::set_ptr_field(&mut trustee, TRUSTEE_NAME, name.as_ptr() as usize);
        trustee
    }

    /// A TRUSTEE by wide name.
    fn trustee_by_wide_name(name: &[u16]) -> Vec<u8> {
        let mut trustee = vec![0u8; TRUSTEE_SIZE];
        crate::acl::set_dword(&mut trustee, TRUSTEE_FORM, FORM_NAME);
        crate::sid::set_ptr_field(&mut trustee, TRUSTEE_NAME, name.as_ptr() as usize);
        trustee
    }

    /// GetEffectiveRightsFromAcl walks the ACL for the trustee's SID: an allow ACE's mask comes
    /// out whole, a deny wins over a later allow (the deny's bits are gone for good), and the
    /// generic, system-security and reserved high bits are stripped; the return is ERROR_SUCCESS
    /// and the last error is untouched for a SID-form trustee.
    #[test]
    fn effective_rights_walk_the_acl() {
        let everyone = sid(1, &[0]);
        let allow = make_acl(&[(0, 0, 0x000F_01FF, &everyone)]);
        let deny_first = make_acl(&[
            (1, 0, 0x000F_01FF, &everyone),
            (0, 0, 0xFFFF_FFFF, &everyone),
        ]);
        let trustee = trustee_by_sid(&everyone);
        let mut mask = 0xF2F2;
        arm();
        let code =
            unsafe { get_effective_rights_from_acl_a(allow.as_ptr(), trustee.as_ptr(), &mut mask) };
        assert_eq!((code, mask, last_error()), (0, 0x000F_01FF, 0xF2F2));
        let mut mask = 0;
        arm();
        let code = unsafe {
            get_effective_rights_from_acl_a(deny_first.as_ptr(), trustee.as_ptr(), &mut mask)
        };
        assert_eq!((code, mask, last_error()), (0, 0x02F0_FE00, 0xF2F2));
        // The W form reads the same ACL.
        let mut mask = 0;
        let code = unsafe {
            get_effective_rights_from_acl_w(deny_first.as_ptr(), trustee.as_ptr(), &mut mask)
        };
        assert_eq!((code, mask), (0, 0x02F0_FE00));
        // A trustee no ACE names gets the empty mask.
        let admins = sid(5, &[32, 544]);
        let other = trustee_by_sid(&admins);
        let mut mask = 0xF2F2;
        let code =
            unsafe { get_effective_rights_from_acl_a(allow.as_ptr(), other.as_ptr(), &mut mask) };
        assert_eq!((code, mask), (0, 0));
    }

    /// A name-form trustee resolves against the well-known accounts: "Everyone" walks as S-1-1-0,
    /// the mask is written, ERROR_SUCCESS is returned, and the last error is the capture's
    /// ERROR_ENVVAR_NOT_FOUND; an unknown name leaves the mask untouched with the same answer.
    /// The A and W forms resolve their own width.
    #[test]
    fn name_trustees_resolve_well_known_accounts() {
        let everyone = sid(1, &[0]);
        let allow = make_acl(&[(0, 0, 0x000F_01FF, &everyone)]);
        let name = b"Everyone\0";
        let trustee = trustee_by_name(name);
        let mut mask = 0;
        arm();
        let code =
            unsafe { get_effective_rights_from_acl_a(allow.as_ptr(), trustee.as_ptr(), &mut mask) };
        assert_eq!(
            (code, mask, last_error()),
            (0, 0x000F_01FF, ERROR_ENVVAR_NOT_FOUND)
        );
        let wname: Vec<u16> = "BUILTIN\\Administrators\0".encode_utf16().collect();
        let admins = sid(5, &[32, 544]);
        let allow_admins = make_acl(&[(0, 0, 0x1234, &admins)]);
        let trustee = trustee_by_wide_name(&wname);
        let mut mask = 0;
        arm();
        let code = unsafe {
            get_effective_rights_from_acl_w(allow_admins.as_ptr(), trustee.as_ptr(), &mut mask)
        };
        assert_eq!(
            (code, mask, last_error()),
            (0, 0x1234, ERROR_ENVVAR_NOT_FOUND)
        );
        let unknown = b"NoSuchAccount\0";
        let trustee = trustee_by_name(unknown);
        let mut mask = 0xF2F2;
        arm();
        let code =
            unsafe { get_effective_rights_from_acl_a(allow.as_ptr(), trustee.as_ptr(), &mut mask) };
        assert_eq!(
            (code, mask, last_error()),
            (0, 0xF2F2, ERROR_ENVVAR_NOT_FOUND)
        );
    }

    /// The failures: a null ACL, trustee or mask is ERROR_INVALID_PARAMETER, an invalid ACL
    /// ERROR_INVALID_ACL (both returned and set as the last error); a SID form with no valid SID
    /// is ERROR_INVALID_SID.
    #[test]
    fn effective_rights_fails_with_its_error_code() {
        let everyone = sid(1, &[0]);
        let allow = make_acl(&[(0, 0, 1, &everyone)]);
        let trustee = trustee_by_sid(&everyone);
        let mut mask = 0;
        arm();
        assert_eq!(
            (
                unsafe {
                    get_effective_rights_from_acl_a(core::ptr::null(), trustee.as_ptr(), &mut mask)
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    get_effective_rights_from_acl_a(allow.as_ptr(), core::ptr::null(), &mut mask)
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    get_effective_rights_from_acl_a(
                        allow.as_ptr(),
                        trustee.as_ptr(),
                        core::ptr::null_mut(),
                    )
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
        let junk = [0xFFu8; 16];
        arm();
        assert_eq!(
            (
                unsafe {
                    get_effective_rights_from_acl_a(junk.as_ptr(), trustee.as_ptr(), &mut mask)
                },
                last_error()
            ),
            (ERROR_INVALID_ACL, ERROR_INVALID_ACL)
        );
        let bad_sid = [0xFFu8; 12];
        let trustee = trustee_by_sid(&bad_sid);
        arm();
        assert_eq!(
            (
                unsafe {
                    get_effective_rights_from_acl_a(allow.as_ptr(), trustee.as_ptr(), &mut mask)
                },
                last_error()
            ),
            (ERROR_INVALID_SID, ERROR_INVALID_SID)
        );
    }

    /// GetMultipleTrustee and GetMultipleTrusteeOperation read the trustee's fields; a null
    /// trustee answers null and zero, and neither touches the last error.
    #[test]
    fn multiple_trustee_queries_read_the_fields() {
        let mut trustee = vec![0xCCu8; TRUSTEE_SIZE];
        let multiple = [0u8; TRUSTEE_SIZE];
        crate::acl::set_dword(&mut trustee, TRUSTEE_OP, 1);
        crate::sid::set_ptr_field(&mut trustee, TRUSTEE_MULTIPLE, multiple.as_ptr() as usize);
        arm();
        assert_eq!(
            unsafe { get_multiple_trustee_a(trustee.as_ptr()) },
            multiple.as_ptr() as *mut u8
        );
        assert_eq!(
            unsafe { get_multiple_trustee_w(trustee.as_ptr()) },
            multiple.as_ptr() as *mut u8
        );
        assert_eq!(
            unsafe { get_multiple_trustee_operation_a(trustee.as_ptr()) },
            1
        );
        assert_eq!(
            unsafe { get_multiple_trustee_operation_w(trustee.as_ptr()) },
            1
        );
        assert_eq!(last_error(), 0xF2F2, "no error touched");
        assert!(unsafe { get_multiple_trustee_a(core::ptr::null()) }.is_null());
        assert_eq!(
            unsafe { get_multiple_trustee_operation_a(core::ptr::null()) },
            0
        );
        let plain = [0u8; TRUSTEE_SIZE];
        assert!(unsafe { get_multiple_trustee_a(plain.as_ptr()) }.is_null());
        assert_eq!(
            unsafe { get_multiple_trustee_operation_w(plain.as_ptr()) },
            0
        );
    }
}
