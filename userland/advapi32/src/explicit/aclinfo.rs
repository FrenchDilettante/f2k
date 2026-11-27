//! The ACL-information and object-permission forms: GetAclInformation and SetAclInformation,
//! the thin BOOL wrappers over the Rtl* information calls (FALSE with the error as the last
//! error on a failure, TRUE on success with the last error untouched), and
//! GetAccessPermissionsForObject A and W, the trusted-server form that asks an object's provider
//! for its access list — F2K serves no providers, so it fails ERROR_NOT_SUPPORTED without
//! touching the caller's outs.

use rtl::winerror::{ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};

use super::{fail, services, ERROR_INVALID_ACL};
use crate::imports::{self as nt};

/// GetAclInformation: the ACL's information of the class into the caller's buffer: TRUE, or
/// FALSE with the error as the last error (ERROR_INVALID_ACL for what is not an ACL).
///
/// # Safety
///
/// The pointers are the caller's; the information buffer is handed to the helper, which probes it.
#[unsafe(export_name = "f2k_export_GetAclInformation")]
pub unsafe extern "system" fn get_acl_information(
    p_acl: *const u8,
    p_acl_information: *mut u8,
    n_acl_information_length: u32,
    dw_acl_information_class: u32,
) -> u32 {
    if p_acl.is_null() || !services::valid_acl(p_acl) {
        nt::set_last_error(ERROR_INVALID_ACL);
        return 0;
    }
    // SAFETY: the caller's buffer, handed through.
    match unsafe {
        services::query_information_acl(
            p_acl,
            p_acl_information,
            n_acl_information_length,
            dw_acl_information_class,
        )
    } {
        Ok(()) => 1,
        Err(status) => {
            nt::set_last_error(nt::dos_error(status));
            0
        }
    }
}

/// SetAclInformation: the ACL's information of the class set from the caller's buffer: TRUE, or
/// FALSE with the error as the last error.
///
/// # Safety
///
/// As GetAclInformation's.
#[unsafe(export_name = "f2k_export_SetAclInformation")]
pub unsafe extern "system" fn set_acl_information(
    p_acl: *mut u8,
    p_acl_information: *const u8,
    n_acl_information_length: u32,
    dw_acl_information_class: u32,
) -> u32 {
    if p_acl.is_null() || !services::valid_acl(p_acl) {
        nt::set_last_error(ERROR_INVALID_ACL);
        return 0;
    }
    // SAFETY: as GetAclInformation's.
    match unsafe {
        services::set_information_acl(
            p_acl,
            p_acl_information,
            n_acl_information_length,
            dw_acl_information_class,
        )
    } {
        Ok(()) => 1,
        Err(status) => {
            nt::set_last_error(nt::dos_error(status));
            0
        }
    }
}

/// GetAccessPermissionsForObjectA: the trusted-server form that asks the object's provider for
/// its access list. F2K serves no providers, so the call fails ERROR_NOT_SUPPORTED without
/// touching the caller's outs.
///
/// # Safety
///
/// The pointers are the caller's; the form reads none of the name arguments and writes no out.
#[unsafe(export_name = "f2k_export_GetAccessPermissionsForObjectA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_access_permissions_for_object_a(
    _lp_object: *const u8,
    _object_type: u32,
    _lp_obj_type: *const u8,
    _lp_provider: *const u8,
    pc_entries: *mut u32,
    _pp_access_info_list: *mut *mut u8,
    _pc_rights: *mut u32,
    _pp_rights_list: *mut *mut u8,
    _pf_access_flags: *mut u32,
) -> u32 {
    if pc_entries.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    fail(ERROR_NOT_SUPPORTED)
}

/// GetAccessPermissionsForObjectW: the A form's body, the wide names dropped.
///
/// # Safety
/// As the A form's.
#[unsafe(export_name = "f2k_export_GetAccessPermissionsForObjectW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_access_permissions_for_object_w(
    _lp_object: *const u16,
    _object_type: u32,
    _lp_obj_type: *const u16,
    _lp_provider: *const u16,
    pc_entries: *mut u32,
    _pp_access_info_list: *mut *mut u8,
    _pc_rights: *mut u32,
    _pp_rights_list: *mut *mut u8,
    _pf_access_flags: *mut u32,
) -> u32 {
    // SAFETY: as the A form's.
    unsafe {
        get_access_permissions_for_object_a(
            _lp_object as *const u8,
            _object_type,
            _lp_obj_type as *const u8,
            _lp_provider as *const u8,
            pc_entries,
            _pp_access_info_list,
            _pc_rights,
            _pp_rights_list,
            _pf_access_flags,
        )
    }
}

#[cfg(test)]
mod tests {
    use rtl::winerror::ERROR_INSUFFICIENT_BUFFER;

    use super::*;
    use crate::explicit::tests_support::make_acl;
    use crate::explicit::{ACL_REVISION_INFORMATION, ACL_SIZE_INFORMATION, ERROR_INVALID_ACL};
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// GetAclInformation and SetAclInformation are the thin BOOL forms: the size and revision
    /// information answer TRUE with the last error untouched; a buffer too small for the size
    /// information fails; an unknown class fails; a bad ACL is FALSE with ERROR_INVALID_ACL in
    /// both forms; SetAclInformation raises the revision, never lowers it.
    #[test]
    fn acl_information_wrappers_answer_bool() {
        let admins = crate::explicit::tests_support::sid(5, &[32, 544]);
        let everyone = crate::explicit::tests_support::sid(1, &[0]);
        let mut acl = make_acl(&[(0, 0, 0x1234, &admins), (1, 0x10, 0xFF, &everyone)]);
        let mut info = [0u8; 12];
        arm();
        assert_eq!(
            unsafe {
                get_acl_information(acl.as_ptr(), info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION)
            },
            1
        );
        assert_eq!(last_error(), 0xF2F2);
        assert_eq!(
            u32::from_le_bytes(info[0..4].try_into().unwrap()),
            2,
            "two ACEs"
        );
        let in_use = u32::from_le_bytes(info[4..8].try_into().unwrap()) as usize;
        assert_eq!(in_use, 8 + (8 + admins.len()) + (8 + everyone.len()));
        assert_eq!(
            u32::from_le_bytes(info[8..12].try_into().unwrap()) as usize,
            512 - in_use
        );
        arm();
        assert_eq!(
            unsafe {
                get_acl_information(acl.as_ptr(), info.as_mut_ptr(), 4, ACL_REVISION_INFORMATION)
            },
            1
        );
        assert_eq!(&info[..4], &2u32.to_le_bytes());
        // A buffer too small for the size information fails.
        arm();
        assert_eq!(
            (
                unsafe {
                    get_acl_information(acl.as_ptr(), info.as_mut_ptr(), 4, ACL_SIZE_INFORMATION)
                },
                last_error()
            ),
            (0, ERROR_INSUFFICIENT_BUFFER)
        );
        // An unknown class fails.
        arm();
        assert_eq!(
            unsafe { get_acl_information(acl.as_ptr(), info.as_mut_ptr(), 12, 7) },
            0
        );
        assert_ne!(last_error(), 0xF2F2);
        // A buffer that is no ACL is ERROR_INVALID_ACL, both forms.
        let mut bad = [0u8; 16];
        bad[0] = 1;
        arm();
        assert_eq!(
            (
                unsafe {
                    get_acl_information(bad.as_ptr(), info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION)
                },
                last_error()
            ),
            (0, ERROR_INVALID_ACL)
        );
        arm();
        let revision = 3u32;
        assert_eq!(
            (
                unsafe {
                    set_acl_information(
                        acl.as_mut_ptr(),
                        revision.to_le_bytes().as_ptr(),
                        4,
                        ACL_REVISION_INFORMATION,
                    )
                },
                last_error()
            ),
            (1, 0xF2F2)
        );
        assert_eq!(acl[0], 3, "the revision raised");
        arm();
        let low = 2u32;
        assert_eq!(
            unsafe {
                set_acl_information(
                    acl.as_mut_ptr(),
                    low.to_le_bytes().as_ptr(),
                    4,
                    ACL_REVISION_INFORMATION,
                )
            },
            0,
            "never lowered"
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    set_acl_information(
                        bad.as_mut_ptr(),
                        revision.to_le_bytes().as_ptr(),
                        4,
                        ACL_REVISION_INFORMATION,
                    )
                },
                last_error()
            ),
            (0, ERROR_INVALID_ACL)
        );
    }

    /// GetAccessPermissionsForObject has no provider to ask in F2K: ERROR_NOT_SUPPORTED as the
    /// return and the last error, the outs untouched; a missing count place is
    /// ERROR_INVALID_PARAMETER.
    #[test]
    fn access_permissions_for_object_fails_without_a_provider() {
        let mut entries = 0xCCu32;
        let mut list: *mut u8 = core::ptr::null_mut();
        let name = b"\\\\.\\C:\\TMP\0";
        arm();
        assert_eq!(
            (
                unsafe {
                    get_access_permissions_for_object_a(
                        name.as_ptr(),
                        1,
                        core::ptr::null(),
                        core::ptr::null(),
                        &mut entries,
                        &mut list,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                },
                last_error(),
                entries
            ),
            (ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED, 0xCC)
        );
        let wide: Vec<u16> = "C:\\TMP".encode_utf16().collect();
        arm();
        assert_eq!(
            (
                unsafe {
                    get_access_permissions_for_object_w(
                        wide.as_ptr(),
                        1,
                        core::ptr::null(),
                        core::ptr::null(),
                        &mut entries,
                        &mut list,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                },
                last_error()
            ),
            (ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED)
        );
        arm();
        assert_eq!(
            (
                unsafe {
                    get_access_permissions_for_object_a(
                        name.as_ptr(),
                        1,
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null_mut(),
                        &mut list,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                },
                last_error()
            ),
            (ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER)
        );
    }
}
