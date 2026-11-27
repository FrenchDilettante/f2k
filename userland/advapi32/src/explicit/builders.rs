//! The trustee and explicit-access builders: BuildTrusteeWithName and BuildTrusteeWithSid A and
//! W, BuildExplicitAccessWithName and BuildImpersonateExplicitAccessWithName A and W. Each fills
//! one whole structure in the caller's memory, stores the caller's string or SID pointer as the
//! trustee's name, and leaves the last error untouched.

use super::{
    read_trustee,
    ExplicitAccess,
    Trustee,
    IMPERSONATION,
    NO_MULTIPLE_TRUSTEE,
    TRUSTEE_IS_NAME,
    TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN,
};

/// Fill a whole TRUSTEE: the form and the name pointer given, the rest the plain values.
fn fill_trustee(p_trustee: *mut u8, form: u32, name: usize) {
    if p_trustee.is_null() {
        return;
    }
    let trustee = Trustee {
        p_multiple_trustee: 0,
        multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
        trustee_form: form,
        trustee_type: TRUSTEE_IS_UNKNOWN,
        ptstr_name: name,
    };
    // SAFETY: the caller's trustee, written unaligned.
    unsafe { (p_trustee as *mut Trustee).write_unaligned(trustee) };
}

/// Fill a whole EXPLICIT_ACCESS over the trustee given (the name one when none).
fn fill_explicit_access(
    p_explicit_access: *mut u8,
    name: usize,
    permissions: u32,
    mode: u32,
    inheritance: u32,
    trustee: Option<Trustee>,
) {
    if p_explicit_access.is_null() {
        return;
    }
    let trustee = trustee.unwrap_or(Trustee {
        p_multiple_trustee: 0,
        multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
        trustee_form: TRUSTEE_IS_NAME,
        trustee_type: TRUSTEE_IS_UNKNOWN,
        ptstr_name: name,
    });
    let entry = ExplicitAccess {
        grf_access_permissions: permissions,
        grf_access_mode: mode,
        grf_inheritance: inheritance,
        trustee,
    };
    // SAFETY: the caller's entry, written unaligned.
    unsafe { (p_explicit_access as *mut ExplicitAccess).write_unaligned(entry) };
}

/// BuildTrusteeWithNameA: the trustee names the narrow string.
///
/// # Safety
///
/// The pointers are the caller's; the last error is untouched.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithNameA")]
pub unsafe extern "system" fn build_trustee_with_name_a(p_trustee: *mut u8, p_name: *const u8) {
    fill_trustee(p_trustee, TRUSTEE_IS_NAME, p_name as usize);
}

/// BuildTrusteeWithNameW: the trustee names the wide string.
///
/// # Safety
/// As the A form's, for a wide string.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithNameW")]
pub unsafe extern "system" fn build_trustee_with_name_w(p_trustee: *mut u8, p_name: *const u16) {
    fill_trustee(p_trustee, TRUSTEE_IS_NAME, p_name as usize);
}

/// BuildTrusteeWithSidA: the trustee is the SID.
///
/// # Safety
/// As the name form's, for a SID.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithSidA")]
pub unsafe extern "system" fn build_trustee_with_sid_a(p_trustee: *mut u8, p_sid: *const u8) {
    fill_trustee(p_trustee, TRUSTEE_IS_SID, p_sid as usize);
}

/// BuildTrusteeWithSidW: the W form's body, the SID the same.
///
/// # Safety
/// As the A form's.
#[unsafe(export_name = "f2k_export_BuildTrusteeWithSidW")]
pub unsafe extern "system" fn build_trustee_with_sid_w(p_trustee: *mut u8, p_sid: *const u8) {
    fill_trustee(p_trustee, TRUSTEE_IS_SID, p_sid as usize);
}

/// BuildExplicitAccessWithNameA: the entry grants (or denies, or sets) `access_permissions` to
/// the narrow-named trustee, inheriting as `inheritance` says.
///
/// # Safety
///
/// The pointers are the caller's; the last error is untouched.
#[unsafe(export_name = "f2k_export_BuildExplicitAccessWithNameA")]
pub unsafe extern "system" fn build_explicit_access_with_name_a(
    p_explicit_access: *mut u8,
    p_trustee_name: *const u8,
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
) {
    fill_explicit_access(
        p_explicit_access,
        p_trustee_name as usize,
        access_permissions,
        access_mode,
        inheritance,
        None,
    );
}

/// BuildExplicitAccessWithNameW: the W form, the wide name.
///
/// # Safety
/// As the A form's, for a wide string.
#[unsafe(export_name = "f2k_export_BuildExplicitAccessWithNameW")]
pub unsafe extern "system" fn build_explicit_access_with_name_w(
    p_explicit_access: *mut u8,
    p_trustee_name: *const u16,
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
) {
    fill_explicit_access(
        p_explicit_access,
        p_trustee_name as usize,
        access_permissions,
        access_mode,
        inheritance,
        None,
    );
}

/// BuildImpersonateExplicitAccessWithNameA: the entry as the A form builds it, its trustee
/// impersonating `p_trustee`.
///
/// # Safety
///
/// As the A form's, plus the caller's trustee to impersonate.
#[unsafe(export_name = "f2k_export_BuildImpersonateExplicitAccessWithNameA")]
pub unsafe extern "system" fn build_impersonate_explicit_access_with_name_a(
    p_explicit_access: *mut u8,
    p_trustee_name: *const u8,
    p_trustee: *const u8,
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
) {
    let trustee = if p_trustee.is_null() {
        None
    } else {
        // SAFETY: the caller's trustee to impersonate.
        let mut source = unsafe { read_trustee(p_trustee) };
        source.p_multiple_trustee = p_trustee as usize;
        source.multiple_trustee_operation = IMPERSONATION;
        Some(source)
    };
    fill_explicit_access(
        p_explicit_access,
        p_trustee_name as usize,
        access_permissions,
        access_mode,
        inheritance,
        trustee,
    );
}

/// BuildImpersonateExplicitAccessWithNameW: the W form, the wide name.
///
/// # Safety
/// As the A form's, for a wide string.
#[unsafe(export_name = "f2k_export_BuildImpersonateExplicitAccessWithNameW")]
pub unsafe extern "system" fn build_impersonate_explicit_access_with_name_w(
    p_explicit_access: *mut u8,
    p_trustee_name: *const u16,
    p_trustee: *const u8,
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
) {
    // SAFETY: as the A form's.
    unsafe {
        build_impersonate_explicit_access_with_name_a(
            p_explicit_access,
            p_trustee_name as *const u8,
            p_trustee,
            access_permissions,
            access_mode,
            inheritance,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explicit::{DENY_ACCESS, GRANT_ACCESS, SET_ACCESS};
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn zeroed_trustee() -> Trustee {
        Trustee {
            p_multiple_trustee: 0xCC,
            multiple_trustee_operation: 0xCC,
            trustee_form: 0xCC,
            trustee_type: 0xCC,
            ptstr_name: 0xCC,
        }
    }

    fn zeroed_entry() -> ExplicitAccess {
        ExplicitAccess {
            grf_access_permissions: 0xCC,
            grf_access_mode: 0xCC,
            grf_inheritance: 0xCC,
            trustee: zeroed_trustee(),
        }
    }

    /// The trustee builders fill the whole structure: the name forms with the caller's string
    /// pointer, the SID forms with the SID, the type unknown and no multiple trustee, and the
    /// last error untouched.
    #[test]
    fn trustee_builders_fill_the_forms() {
        let name = b"Everyone\0";
        let wide: Vec<u16> = "Everyone".encode_utf16().chain([0]).collect();
        let admins = crate::explicit::tests_support::sid(5, &[32, 544]);
        let mut trustee = zeroed_trustee();
        let at = &mut trustee as *mut Trustee as *mut u8;
        arm();
        unsafe { build_trustee_with_name_a(at, name.as_ptr()) };
        assert_eq!(
            (
                trustee.trustee_form,
                trustee.trustee_type,
                trustee.multiple_trustee_operation,
                trustee.p_multiple_trustee,
                trustee.ptstr_name
            ),
            (
                TRUSTEE_IS_NAME,
                TRUSTEE_IS_UNKNOWN,
                NO_MULTIPLE_TRUSTEE,
                0,
                name.as_ptr() as usize
            )
        );
        assert_eq!(last_error(), 0xF2F2);
        arm();
        unsafe { build_trustee_with_name_w(at, wide.as_ptr()) };
        assert_eq!(
            (trustee.trustee_form, trustee.ptstr_name),
            (TRUSTEE_IS_NAME, wide.as_ptr() as usize)
        );
        assert_eq!(last_error(), 0xF2F2);
        arm();
        unsafe { build_trustee_with_sid_a(at, admins.as_ptr()) };
        assert_eq!(
            (trustee.trustee_form, trustee.ptstr_name),
            (TRUSTEE_IS_SID, admins.as_ptr() as usize)
        );
        assert_eq!(last_error(), 0xF2F2);
        unsafe { build_trustee_with_sid_w(at, admins.as_ptr()) };
        assert_eq!(trustee.trustee_form, TRUSTEE_IS_SID);
        assert_eq!(last_error(), 0xF2F2);
    }

    /// The explicit-access builders fill the whole entry: permissions, mode, inheritance and
    /// the name trustee; the impersonate form copies the given trustee with the impersonation
    /// operation and its address as the multiple trustee.
    #[test]
    fn explicit_access_builders_fill_the_entry() {
        let name = b"Everyone\0";
        let wide: Vec<u16> = "Everyone".encode_utf16().chain([0]).collect();
        let mut entry = zeroed_entry();
        let at = &mut entry as *mut ExplicitAccess as *mut u8;
        arm();
        unsafe {
            build_explicit_access_with_name_a(at, name.as_ptr(), 0x000F_01FF, GRANT_ACCESS, 0)
        };
        assert_eq!(
            (
                entry.grf_access_permissions,
                entry.grf_access_mode,
                entry.grf_inheritance,
                entry.trustee.trustee_form,
                entry.trustee.ptstr_name
            ),
            (
                0x000F_01FF,
                GRANT_ACCESS,
                0,
                TRUSTEE_IS_NAME,
                name.as_ptr() as usize
            )
        );
        assert_eq!(last_error(), 0xF2F2);
        unsafe { build_explicit_access_with_name_w(at, wide.as_ptr(), 0xFF, DENY_ACCESS, 3) };
        assert_eq!(
            (
                entry.grf_access_permissions,
                entry.grf_access_mode,
                entry.grf_inheritance,
                entry.trustee.ptstr_name
            ),
            (0xFF, DENY_ACCESS, 3, wide.as_ptr() as usize)
        );
        // The impersonate form: the source trustee's form and name, impersonating it.
        let mut source = Trustee {
            p_multiple_trustee: 0,
            multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
            trustee_form: TRUSTEE_IS_NAME,
            trustee_type: TRUSTEE_IS_UNKNOWN,
            ptstr_name: name.as_ptr() as usize,
        };
        let source_at = &mut source as *mut Trustee as *const u8;
        arm();
        unsafe {
            build_impersonate_explicit_access_with_name_a(
                at,
                name.as_ptr(),
                source_at,
                0x000F_01FF,
                GRANT_ACCESS,
                0,
            )
        };
        assert_eq!(
            (
                entry.grf_access_permissions,
                entry.grf_access_mode,
                entry.trustee.multiple_trustee_operation,
                entry.trustee.p_multiple_trustee,
                entry.trustee.trustee_form,
                entry.trustee.ptstr_name
            ),
            (
                0x000F_01FF,
                GRANT_ACCESS,
                IMPERSONATION,
                source_at as usize,
                TRUSTEE_IS_NAME,
                name.as_ptr() as usize
            )
        );
        assert_eq!(last_error(), 0xF2F2);
        unsafe {
            build_impersonate_explicit_access_with_name_w(
                at,
                wide.as_ptr(),
                source_at,
                1,
                SET_ACCESS,
                0,
            )
        };
        assert_eq!(
            (
                entry.grf_access_mode,
                entry.trustee.multiple_trustee_operation
            ),
            (SET_ACCESS, IMPERSONATION)
        );
    }
}
