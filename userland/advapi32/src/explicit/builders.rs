//! The trustee and explicit-access builders: BuildTrusteeWithName and BuildTrusteeWithSid A and
//! W, BuildExplicitAccessWithName and BuildImpersonateExplicitAccessWithName A and W. Each fills
//! one whole structure in the caller's memory, stores the caller's string or SID pointer as the
//! trustee's name, and leaves the last error untouched.

use super::{
    ExplicitAccess,
    Trustee,
    NO_MULTIPLE_TRUSTEE,
    TRUSTEE_IS_NAME,
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
    /// The explicit-access builders fill the whole entry: permissions, mode, inheritance and
    /// the name trustee (the impersonate form lives with the trustee builders).
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
        assert_eq!(last_error(), 0xF2F2);
    }
}
