//! TrusteeAccessToObject A/W: the trustee's access to a named object, as a program that asks
//! before it acts makes them.
//!
//! The object's security descriptor is read through the named-security call ([`crate::filesec`],
//! a file object), the trustee's SID resolved as in [`super`], and the check run over the served
//! NtAccessCheck ([`crate::accesscheck::services`]) with the process's token, a zeroed generic
//! mapping and MAXIMUM_ALLOWED as the desired access. The return is the Win32 error code:
//! ERROR_SUCCESS when the check grants, the denial's error (ERROR_ACCESS_DENIED) when it runs
//! and is denied, the service's error when it fails, and ERROR_INVALID_PARAMETER for a null
//! name, trustee or GUID array with a count. The last error is set on every failure and
//! untouched on a success.

use rtl::heap::ProcessHeap as _;
use rtl::nt::access::TOKEN_QUERY;
use rtl::winerror::ERROR_INVALID_PARAMETER;

use super::trustee_sid;
use crate::accesscheck::services;
use crate::explicit::fail;
use crate::filesec::get_named_security_info_w;
use crate::imports::{self as nt, HeapBlock, ProcessHeap};
use crate::sd::DACL_SECURITY_INFORMATION;

/// GetCurrentProcess's pseudo-handle.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// MAXIMUM_ALLOWED, the desired access the check asks for.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// A token handle opened for advapi32's own use, closed when dropped.
struct OpenedToken(u32);

impl Drop for OpenedToken {
    fn drop(&mut self) {
        let _ = nt::close(self.0);
    }
}

/// TrusteeAccessToObjectW's body: the named object's descriptor checked against the process's
/// token for the trustee. `name` is the caller's NUL-terminated wide object name.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[allow(clippy::too_many_arguments)]
unsafe fn trustee_access_to_object(
    name: *const u16,
    object_type: u32,
    trustee: *const u8,
    guid_count: u32,
    guids: *const u8,
) -> u32 {
    if name.is_null() || trustee.is_null() || (guid_count > 0 && guids.is_null()) {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // The object's descriptor, through the named-security call (a file object); its error is
    // already the last error.
    let mut sd = 0usize;
    let code = unsafe {
        get_named_security_info_w(
            name,
            object_type,
            DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut sd,
        )
    };
    if code != 0 {
        return code;
    }
    // The descriptor's heap block is ours until the end of the call.
    let sd_ptr = sd as *const u8;
    let result = check_trustee(sd_ptr, trustee);
    // SAFETY: the block the named-security call allocated, freed once.
    unsafe { ProcessHeap::free(sd_ptr.cast_mut()) };
    result
}

/// The descriptor at `sd` checked for the trustee: the process token opened, the served
/// NtAccessCheck run with MAXIMUM_ALLOWED, the token closed. The Win32 error code.
///
/// # Safety
///
/// `sd` is the descriptor's block, readable; `trustee` the caller's TRUSTEE.
unsafe fn check_trustee(sd: *const u8, trustee: *const u8) -> u32 {
    // SAFETY: the caller's trustee.
    let resolved = match unsafe { trustee_sid(trustee, true) } {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return fail(crate::sid::ERROR_NONE_MAPPED),
        Err(error) => return fail(error),
    };
    let _ = resolved;
    let token = match nt::open_own_process_token(CURRENT_PROCESS, TOKEN_QUERY) {
        Ok(token) => OpenedToken(token),
        Err(status) => return fail(nt::dos_error(status)),
    };
    // A private zeroed privilege set of one entry, as the plain check needs one.
    let Some(mut set) = HeapBlock::new(8 + 12) else {
        return fail(rtl::winerror::ERROR_NOT_ENOUGH_MEMORY);
    };
    let mut length = 20u32;
    let mapping = [0u8; 16];
    let mut granted = 0u32;
    // SAFETY: the descriptor block, the caller's trustee memory and the local blocks handed to
    // the service, which probes them.
    let (service, real) = services::access_check(
        sd,
        token.0,
        MAXIMUM_ALLOWED,
        mapping.as_ptr(),
        set.bytes_mut().as_mut_ptr(),
        &mut length,
        &mut granted,
    );
    if !service.is_success() {
        return fail(nt::dos_error(service));
    }
    if !real.is_success() {
        return fail(nt::dos_error(real));
    }
    0
}

/// TrusteeAccessToObjectW: the trustee's access to the named object. The return is the Win32
/// error code (ERROR_SUCCESS when the access is granted).
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say: a NUL-terminated wide object name,
/// the trustee, and the object-class GUID array with its count.
#[unsafe(export_name = "f2k_export_TrusteeAccessToObjectW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn trustee_access_to_object_w(
    p_object_name: *const u16,
    object_type: u32,
    _lp_provider: *const u16,
    p_trustee: *const u8,
    guid_count: u32,
    p_object_class_guids: *const u8,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe {
        trustee_access_to_object(
            p_object_name,
            object_type,
            p_trustee,
            guid_count,
            p_object_class_guids,
        )
    }
}

/// TrusteeAccessToObjectA: TrusteeAccessToObjectW of the name converted.
///
/// # Safety
///
/// As the W form's, for a NUL-terminated ANSI object name.
#[unsafe(export_name = "f2k_export_TrusteeAccessToObjectA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn trustee_access_to_object_a(
    p_object_name: *const u8,
    object_type: u32,
    _lp_provider: *const u8,
    p_trustee: *const u8,
    guid_count: u32,
    p_object_class_guids: *const u8,
) -> u32 {
    if p_object_name.is_null()
        || p_trustee.is_null()
        || (guid_count > 0 && p_object_class_guids.is_null())
    {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the caller's ANSI name, converted; the wide name lives across the call.
    let converted = unsafe { crate::token::optional_ansi(p_object_name) }
        .map(nt::ansi_to_unicode)
        .transpose();
    let name = match converted {
        Ok(Some(name)) => name,
        Ok(None) => return fail(ERROR_INVALID_PARAMETER),
        Err(status) => return fail(nt::dos_error(status)),
    };
    let units = name.terminated_bytes();
    // SAFETY: as the W form's, with the converted name's units as a NUL-terminated wide string.
    unsafe {
        trustee_access_to_object(
            units.as_ptr().cast::<u16>(),
            object_type,
            p_trustee,
            guid_count,
            p_object_class_guids,
        )
    }
}

#[cfg(test)]
mod tests {
    use rtl::status::STATUS_ACCESS_DENIED;

    use super::*;
    use crate::accesscheck::host::{CALLS, GRANTED, REAL, STATUS};
    use crate::explicit::tests_support::{make_acl, sid};
    use crate::filesec::host::SEC_REPLY;
    use crate::filesec::SE_FILE_OBJECT;
    use crate::imports::host::{TOKEN, TOKEN_CALLS};
    use crate::sd::{
        initialize_security_descriptor,
        make_self_relative_sd,
        set_security_descriptor_dacl,
    };
    use crate::testkit::{arm, last_error};
    use crate::trustee::{FORM_SID, TRUSTEE_FORM, TRUSTEE_NAME, TRUSTEE_SIZE};

    fn clear() {
        CALLS.with(|calls| calls.borrow_mut().clear());
        TOKEN_CALLS.with(|calls| calls.borrow_mut().clear());
        STATUS.with(|status| status.set(0));
        REAL.with(|real| real.set(0));
        GRANTED.with(|granted| granted.set(0));
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_000F));
    }

    /// A self-relative descriptor carrying the DACL, as the named-security call would read it.
    fn sd_with_dacl(dacl: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        assert_eq!(
            unsafe { initialize_security_descriptor(buf.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(
            unsafe { set_security_descriptor_dacl(buf.as_mut_ptr(), 1, dacl.as_ptr(), 0) },
            1
        );
        let mut rel = vec![0u8; 1024];
        let mut len = 1024u32;
        assert_eq!(
            unsafe { make_self_relative_sd(buf.as_ptr(), rel.as_mut_ptr(), &mut len) },
            1
        );
        rel.truncate(len as usize);
        rel
    }

    fn trustee_by_sid(sid: &[u8]) -> Vec<u8> {
        let mut trustee = vec![0u8; TRUSTEE_SIZE];
        crate::acl::set_dword(&mut trustee, TRUSTEE_FORM, FORM_SID);
        crate::sid::set_ptr_field(&mut trustee, TRUSTEE_NAME, sid.as_ptr() as usize);
        trustee
    }

    /// TrusteeAccessToObject reads the named object's descriptor, opens the process token and
    /// runs NtAccessCheck for MAXIMUM_ALLOWED: ERROR_SUCCESS when the check grants (the last
    /// error untouched), the denial's error when it is denied, the service's error when it
    /// fails, and the named-security call's error when the object cannot be read.
    #[test]
    fn the_check_runs_over_the_served_service() {
        let everyone = sid(1, &[0]);
        let dacl = make_acl(&[(0, 0, 0x000F_01FF, &everyone)]);
        let dacl = {
            let mut d = dacl;
            let size = usize::from(crate::acl::word(&d, crate::acl::ACL_SIZE_OFF).unwrap());
            d.truncate(size);
            d
        };
        let sd = sd_with_dacl(&dacl);
        let trustee = trustee_by_sid(&everyone);
        let name: Vec<u16> = "C:\\tmp\\thing.txt\0".encode_utf16().collect();
        let guids = [0u8; 16];
        clear();
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        arm();
        let code = unsafe {
            trustee_access_to_object_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                core::ptr::null(),
                trustee.as_ptr(),
                1,
                guids.as_ptr(),
            )
        };
        assert_eq!(
            (code, last_error()),
            (0, 122),
            "the descriptor query's sizing leftover"
        );
        assert_eq!(
            CALLS.with(|calls| calls.borrow().clone()).last(),
            Some(&("NtAccessCheck", TOKEN, MAXIMUM_ALLOWED, 0))
        );
        assert_eq!(
            TOKEN_CALLS.with(|calls| calls.borrow().clone()).last(),
            Some(&("NtOpenProcessToken", CURRENT_PROCESS, TOKEN_QUERY))
        );
        // A denial: the check ran and was denied — ERROR_ACCESS_DENIED.
        clear();
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        REAL.with(|real| real.set(STATUS_ACCESS_DENIED));
        arm();
        let code = unsafe {
            trustee_access_to_object_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                core::ptr::null(),
                trustee.as_ptr(),
                0,
                core::ptr::null(),
            )
        };
        assert_eq!((code, last_error()), (5, 5));
        // A failed service: its error.
        clear();
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        STATUS.with(|status| status.set(0xC000_0008));
        arm();
        let code = unsafe {
            trustee_access_to_object_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                core::ptr::null(),
                trustee.as_ptr(),
                0,
                core::ptr::null(),
            )
        };
        assert_eq!((code, last_error()), (6, 6));
        // The object cannot be read: the named-security call's error, no check run.
        clear();
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0034));
        arm();
        let code = unsafe {
            trustee_access_to_object_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                core::ptr::null(),
                trustee.as_ptr(),
                0,
                core::ptr::null(),
            )
        };
        assert!(code != 0 && CALLS.with(|calls| calls.borrow().is_empty()));
        // A null name, trustee, or GUID array with a count: ERROR_INVALID_PARAMETER, no calls.
        clear();
        arm();
        assert_eq!(
            (
                unsafe {
                    trustee_access_to_object_w(
                        core::ptr::null(),
                        SE_FILE_OBJECT,
                        core::ptr::null(),
                        trustee.as_ptr(),
                        0,
                        core::ptr::null(),
                    )
                },
                last_error()
            ),
            (87, 87)
        );
        assert_eq!(
            (
                unsafe {
                    trustee_access_to_object_w(
                        name.as_ptr(),
                        SE_FILE_OBJECT,
                        core::ptr::null(),
                        core::ptr::null(),
                        1,
                        guids.as_ptr(),
                    )
                },
                last_error()
            ),
            (87, 87)
        );
        clear();
    }

    /// The A form converts the object name and runs the same check.
    #[test]
    fn the_a_form_converts_the_name() {
        let everyone = sid(1, &[0]);
        let dacl = make_acl(&[(0, 0, 1, &everyone)]);
        let dacl = {
            let mut d = dacl;
            let size = usize::from(crate::acl::word(&d, crate::acl::ACL_SIZE_OFF).unwrap());
            d.truncate(size);
            d
        };
        let sd = sd_with_dacl(&dacl);
        let trustee = trustee_by_sid(&everyone);
        clear();
        SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        arm();
        let code = unsafe {
            trustee_access_to_object_a(
                c"C:\\tmp\\thing.txt".as_ptr() as *const u8,
                SE_FILE_OBJECT,
                core::ptr::null(),
                trustee.as_ptr(),
                0,
                core::ptr::null(),
            )
        };
        assert_eq!(
            (code, last_error()),
            (0, 122),
            "the descriptor query's sizing leftover"
        );
        assert!(!CALLS.with(|calls| calls.borrow().is_empty()));
        clear();
    }
}
