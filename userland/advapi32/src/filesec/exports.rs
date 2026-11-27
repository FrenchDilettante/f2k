//! The security info calls' exports: each converts its caller's pointers once, on entry, and
//! hands the rest to its core. The arguments are the caller's, as the export's kinds say.

use super::cores::*;
use super::*;

// --- The exports
// Each converts its caller's pointers once, on entry, and hands the rest to its core. The
// arguments are the caller's, as the export's kinds say.

/// GetSecurityInfo: the handle's descriptor of the `info` parts, split into the out parameters.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetSecurityInfo")]
pub unsafe extern "system" fn get_security_info(
    handle: u32,
    _object_type: u32,
    info: u32,
    owner: *mut usize,
    group: *mut usize,
    dacl: *mut usize,
    sacl: *mut usize,
    sd: *mut usize,
) -> u32 {
    // SAFETY: the caller's out parameters.
    let mut outs = unsafe { five_outs(owner, group, dacl, sacl, sd) };
    get_security_info_core(handle, info, &mut outs)
}

/// SetSecurityInfo: the handle's descriptor of the `info` parts set to `descriptor`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetSecurityInfo")]
pub unsafe extern "system" fn set_security_info(
    handle: u32,
    _object_type: u32,
    info: u32,
    descriptor: *const u8,
) -> u32 {
    set_security_info_core(handle, info, descriptor)
}

/// GetNamedSecurityInfoW: the named object's descriptor of the `info` parts, split into the out
/// parameters (the descriptor a process-heap block, freed with LocalFree).
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetNamedSecurityInfoW")]
pub unsafe extern "system" fn get_named_security_info_w(
    name: *const u16,
    object_type: u32,
    info: u32,
    owner: *mut usize,
    group: *mut usize,
    dacl: *mut usize,
    sacl: *mut usize,
    sd: *mut usize,
) -> u32 {
    // SAFETY: the caller's string and out parameters.
    let (name, mut outs) = unsafe { (wide_text(name), five_outs(owner, group, dacl, sacl, sd)) };
    named_get(&Counted::new(name), object_type, info, &mut outs)
}

/// GetNamedSecurityInfoA: GetNamedSecurityInfoW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetNamedSecurityInfoA")]
pub unsafe extern "system" fn get_named_security_info_a(
    name: *const u8,
    object_type: u32,
    info: u32,
    owner: *mut usize,
    group: *mut usize,
    dacl: *mut usize,
    sacl: *mut usize,
    sd: *mut usize,
) -> u32 {
    // SAFETY: the caller's string and out parameters.
    let (name, mut outs) = unsafe { (ansi_text(name), five_outs(owner, group, dacl, sacl, sd)) };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => return code,
    };
    // The A form leaves ERROR_SUCCESS behind when it answers before the inner call sets an
    // error of its own (the capture pins err=0 on a missing path).
    nt::set_last_error(ERROR_SUCCESS);
    named_get(&name.counted(), object_type, info, &mut outs)
}

/// SetNamedSecurityInfoW: the named object's `info` parts set from the components given.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetNamedSecurityInfoW")]
pub unsafe extern "system" fn set_named_security_info_w(
    name: *const u16,
    object_type: u32,
    info: u32,
    owner: *const u8,
    group: *const u8,
    dacl: *const u8,
    sacl: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { wide_text(name) };
    named_set(
        &Counted::new(name),
        object_type,
        info,
        owner,
        group,
        dacl,
        sacl,
    )
}

/// SetNamedSecurityInfoA: SetNamedSecurityInfoW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetNamedSecurityInfoA")]
pub unsafe extern "system" fn set_named_security_info_a(
    name: *const u8,
    object_type: u32,
    info: u32,
    owner: *const u8,
    group: *const u8,
    dacl: *const u8,
    sacl: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { ansi_text(name) };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => return code,
    };
    named_set(&name.counted(), object_type, info, owner, group, dacl, sacl)
}

/// GetNamedSecurityInfoExW: GetNamedSecurityInfoW's answer with the access and audit lists out
/// beside the owner and group (no provider consulted).
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetNamedSecurityInfoExW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_named_security_info_ex_w(
    name: *const u16,
    object_type: u32,
    info: u32,
    _provider: *const u16,
    _property: *const u16,
    access_list: *mut usize,
    audit_list: *mut usize,
    owner: *mut usize,
    group: *mut usize,
) -> u32 {
    // SAFETY: the caller's string and out parameters.
    let (name, mut outs) = unsafe {
        (
            wide_text(name),
            ex_outs(access_list, audit_list, owner, group),
        )
    };
    ex_get(&Counted::new(name), object_type, info, &mut outs, true)
}

/// GetNamedSecurityInfoExA: GetNamedSecurityInfoExW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetNamedSecurityInfoExA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn get_named_security_info_ex_a(
    name: *const u8,
    object_type: u32,
    info: u32,
    _provider: *const u8,
    _property: *const u8,
    access_list: *mut usize,
    audit_list: *mut usize,
    owner: *mut usize,
    group: *mut usize,
) -> u32 {
    // SAFETY: the caller's string and out parameters.
    let (name, mut outs) = unsafe {
        (
            ansi_text(name),
            ex_outs(access_list, audit_list, owner, group),
        )
    };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => return code,
    };
    ex_get(&name.counted(), object_type, info, &mut outs, false)
}

/// SetNamedSecurityInfoExW: SetNamedSecurityInfoW with the access and audit lists in beside the
/// owner and group (no provider consulted).
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetNamedSecurityInfoExW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn set_named_security_info_ex_w(
    name: *const u16,
    object_type: u32,
    info: u32,
    _provider: *const u16,
    _property: *const u16,
    _access_list: *const u8,
    _audit_list: *const u8,
    _owner: *const u8,
    _group: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { wide_text(name) };
    ex_set(&Counted::new(name), object_type, info)
}

/// SetNamedSecurityInfoExA: SetNamedSecurityInfoExW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetNamedSecurityInfoExA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn set_named_security_info_ex_a(
    name: *const u8,
    object_type: u32,
    info: u32,
    _provider: *const u8,
    _property: *const u8,
    _access_list: *const u8,
    _audit_list: *const u8,
    _owner: *const u8,
    _group: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { ansi_text(name) };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => return code,
    };
    ex_set(&name.counted(), object_type, info)
}

/// GetFileSecurityW: the named file's descriptor of the `info` parts into the caller's `descriptor`
/// of `length` bytes, its size into `needed`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetFileSecurityW")]
pub unsafe extern "system" fn get_file_security_w(
    name: *const u16,
    info: u32,
    descriptor: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { wide_text(name) };
    file_get(&Counted::new(name), info, descriptor, length, needed)
}

/// GetFileSecurityA: GetFileSecurityW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetFileSecurityA")]
pub unsafe extern "system" fn get_file_security_a(
    name: *const u8,
    info: u32,
    descriptor: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { ansi_text(name) };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => {
            nt::set_last_error(code);
            return 0;
        }
    };
    file_get(&name.counted(), info, descriptor, length, needed)
}

/// SetFileSecurityW: the named file's `info` parts set to the caller's `descriptor`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetFileSecurityW")]
pub unsafe extern "system" fn set_file_security_w(
    name: *const u16,
    info: u32,
    descriptor: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { wide_text(name) };
    file_set(&Counted::new(name), info, descriptor)
}

/// SetFileSecurityA: SetFileSecurityW of the name converted.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetFileSecurityA")]
pub unsafe extern "system" fn set_file_security_a(
    name: *const u8,
    info: u32,
    descriptor: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { ansi_text(name) };
    let name = match wide(name) {
        Ok(name) => name,
        Err(code) => {
            nt::set_last_error(code);
            return 0;
        }
    };
    file_set(&name.counted(), info, descriptor)
}

/// GetKernelObjectSecurity: the kernel object `handle`'s descriptor of the `info` parts into the
/// caller's `descriptor` of `length` bytes, its size into `needed`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_GetKernelObjectSecurity")]
pub unsafe extern "system" fn get_kernel_object_security(
    handle: u32,
    info: u32,
    descriptor: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    // The current process's own handle answers with its token's descriptor where the kernel
    // keeps the blank one.
    let sd_block = match read_object_sd(handle, info, || {
        (handle == crate::sid::CURRENT_PROCESS)
            .then(|| defaults::process_sd(info))
            .flatten()
    }) {
        Ok(block) => block,
        Err(_) => return 0,
    };
    give_sd(descriptor, length, needed, sd_block.bytes())
}

/// SetKernelObjectSecurity: the kernel object `handle`'s `info` parts set to the caller's
/// `descriptor`.
///
/// # Safety
///
/// The arguments are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_SetKernelObjectSecurity")]
pub unsafe extern "system" fn set_kernel_object_security(
    handle: u32,
    info: u32,
    descriptor: *const u8,
) -> u32 {
    // SAFETY: the caller's descriptor, handed to the service in the self-relative form.
    let status = unsafe { defaults::set_object_sd(handle, info, descriptor) };
    if status.is_success() {
        1
    } else {
        fail(status);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    /// The named calls open the file with the mask's access, shared for read/write/delete, reparse
    /// points opened (a plain open when the flag is refused); a missing path is the open's error
    /// as the code with the last error left alone; another object type is ERROR_INVALID_PARAMETER.
    /// The Ex forms marshal the access and audit lists beside the owner and group. SetNamed-
    /// SecurityInfo opens with the set access and sets the assembled descriptor; the A form
    /// converts the name first.
    #[test]
    fn the_named_and_ex_calls_open_then_query_or_set() {
        reset();
        let name = wide_z("filesec.tmp");
        host::SEC_OPEN_STATUS.with(|status| status.set(0xC000_0034));
        arm();
        let mut sd = 0usize;
        let code = unsafe {
            get_named_security_info_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!((code, last_error(), sd), (2, 0xF2F2, 0));
        assert_eq!(
            host::OPEN_CALLS.with(|calls| calls.borrow().clone()),
            [(READ_CONTROL, FILE_SHARE_ALL, FILE_OPEN_REPARSE_POINT)]
        );
        assert_eq!(
            host::OPEN_NAMES.with(|names| names.borrow().clone()),
            [nt_name("filesec.tmp")]
        );

        // The flag refused: the plain open follows, then the query on the handle.
        reset();
        host::SEC_OPEN_QUEUE.with(|queue| queue.borrow_mut().extend([STATUS_INVALID_PARAMETER, 0]));
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(self_relative(20, 0, 0, 0, 28)));
        let code = unsafe {
            get_named_security_info_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        assert_ne!(sd, 0);
        assert_eq!(
            host::OPEN_CALLS.with(|calls| calls.borrow().clone()),
            [
                (READ_CONTROL, FILE_SHARE_ALL, FILE_OPEN_REPARSE_POINT),
                (READ_CONTROL, FILE_SHARE_ALL, 0),
            ]
        );
        // SAFETY: the block the call handed out.
        unsafe { ProcessHeap::free(sd as *mut u8) };

        // Another object type: ERROR_INVALID_PARAMETER, nothing opened.
        reset();
        let code = unsafe {
            get_named_security_info_w(
                name.as_ptr(),
                SE_REGISTRY_KEY,
                WANT,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, ERROR_INVALID_PARAMETER);
        assert!(host::OPEN_CALLS.with(|calls| calls.borrow().is_empty()));

        // SetNamedSecurityInfo: the set access open, then ERROR_INVALID_FUNCTION — F2K's files
        // keep no security descriptor to set, and no service call goes out.
        reset();
        let dacl = acl(8);
        arm();
        let code = unsafe {
            set_named_security_info_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null(),
            )
        };
        assert_eq!(
            (code, last_error()),
            (ERROR_INVALID_FUNCTION, ERROR_INVALID_FUNCTION)
        );
        assert_eq!(
            host::OPEN_CALLS.with(|calls| calls.borrow().clone()),
            [(WRITE_DAC, FILE_SHARE_ALL, FILE_OPEN_REPARSE_POINT)]
        );
        assert!(host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
        // The A form: the name arrives converted.
        reset();
        let code = unsafe {
            set_named_security_info_a(
                b"filesec.tmp\0".as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null(),
            )
        };
        assert_eq!(code, ERROR_INVALID_FUNCTION, "the A form answers the same");
        assert_eq!(
            host::OPEN_NAMES.with(|names| names.borrow().clone()),
            [nt_name("filesec.tmp")]
        );

        // The Ex get: the access list out (empty: the descriptor's DACL is null here), the
        // audit list untouched, the owner and group names out as their SIDs' text.
        reset();
        let mut sd_bytes = self_relative(20, 36, 0, 0, 52);
        let admins = sid(5, &[32, 544]);
        sd_bytes[20..36].copy_from_slice(&admins);
        sd_bytes[36..52].copy_from_slice(&admins);
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd_bytes));
        let (mut access, mut audit, mut owner, mut group) = (0usize, 0xF2F2usize, 0usize, 0usize);
        arm();
        let code = unsafe {
            get_named_security_info_ex_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null(),
                core::ptr::null(),
                &mut access,
                &mut audit,
                &mut owner,
                &mut group,
            )
        };
        assert_eq!((code, last_error()), (ERROR_SUCCESS, ERROR_NONE_MAPPED));
        assert_ne!(access, 0, "the access list set");
        assert_eq!(audit, 0xF2F2, "the audit list untouched");
        assert_ne!((owner, group), (0, 0), "the owner and group names set");
        // SAFETY: our own blocks.
        unsafe {
            ProcessHeap::free(access as *mut u8);
            ProcessHeap::free(owner as *mut u8);
            ProcessHeap::free(group as *mut u8);
        }
        // The Ex set on the file: 1 with 1008 as the last error.
        reset();
        arm();
        let code = unsafe {
            set_named_security_info_ex_w(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        assert_eq!(
            (code, last_error()),
            (ERROR_INVALID_FUNCTION, ERROR_NO_TOKEN)
        );
        reset();
        host::SEC_OPEN_STATUS.with(|status| status.set(0xC000_0034));
        let code = unsafe {
            get_named_security_info_ex_a(
                b"filesec-none.tmp\0".as_ptr(),
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, ERROR_INVALID_PARAMETER, "every out place null: 87");

        // The Ex get with the out places given: the open, the read, the lists and names out,
        // ERROR_NONE_MAPPED left as the last error.
        reset();
        let mut sd_bytes = self_relative(20, 36, 0, 0, 52);
        let admins = sid(5, &[32, 544]);
        sd_bytes[20..36].copy_from_slice(&admins);
        sd_bytes[36..52].copy_from_slice(&admins);
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd_bytes));
        let (mut access, mut audit, mut owner, mut group) = (0usize, 0xF2F2usize, 0usize, 0usize);
        arm();
        let code = unsafe {
            get_named_security_info_ex_a(
                b"filesec.tmp\0".as_ptr(),
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null(),
                core::ptr::null(),
                &mut access,
                &mut audit,
                &mut owner,
                &mut group,
            )
        };
        assert_eq!((code, last_error()), (ERROR_SUCCESS, ERROR_NONE_MAPPED));
        assert_ne!(access, 0, "the access list set");
        assert_eq!(audit, 0xF2F2, "the audit list untouched");
        assert_ne!(owner, 0, "the owner name set");
        assert_ne!(group, 0, "the group name set");
        // SAFETY: our own blocks.
        unsafe {
            ProcessHeap::free(access as *mut u8);
            ProcessHeap::free(owner as *mut u8);
            ProcessHeap::free(group as *mut u8);
        }

        // The Ex set on the file: 1 with 1008 as the last error, no service call.
        reset();
        arm();
        let code = unsafe {
            set_named_security_info_ex_a(
                b"filesec.tmp\0".as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        assert_eq!(
            (code, last_error()),
            (ERROR_INVALID_FUNCTION, ERROR_NO_TOKEN)
        );
        assert!(host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
    }

    /// Get/SetFileSecurity open by name and pass the caller's buffer, length and size through to
    /// the service; the BOOL answer with the last error set on a failure, untouched on success.
    /// The kernel object calls hand the handle straight to the service, no open whatever.
    #[test]
    fn the_file_and_kernel_object_calls_go_to_the_service() {
        reset();
        let name = wide_z("filesec.tmp");
        let sd_bytes = self_relative(20, 0, 0, 0, 28);
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd_bytes.clone()));
        let mut buffer = [0xCCu8; 64];
        // The size query, a byte short, and the size asked for.
        let mut need = 0xF2F2_F2F2u32;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, core::ptr::null_mut(), 0, &mut need)
        };
        assert_eq!((ok, last_error(), need), (0, 122, 28));
        let mut need2 = 27;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, buffer.as_mut_ptr(), 27, &mut need2)
        };
        assert_eq!(
            (ok, last_error(), need2, buffer[0]),
            (0, 122, 28, sd_bytes[0]),
            "a byte short: what fits is copied"
        );
        assert_eq!(&buffer[..27], &sd_bytes[..27]);
        let mut need3 = 28;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, buffer.as_mut_ptr(), 28, &mut need3)
        };
        assert_eq!((ok, last_error(), need3), (1, 0xF2F2, 28));
        assert_eq!(&buffer[..28], &sd_bytes[..]);
        assert_eq!(
            host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 0),
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 28),
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 0),
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 28),
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 0),
                ("NtQuerySecurityObject", host::SEC_HANDLE, WANT, 28),
            ],
            "each get sizes then reads"
        );
        // A missing path: FALSE, the open's error as the last error, the size untouched.
        reset();
        host::SEC_OPEN_STATUS.with(|status| status.set(0xC000_0034));
        let mut need = 0xF2F2_F2F2u32;
        arm();
        let ok = unsafe {
            get_file_security_a(
                b"filesec-none.tmp\0".as_ptr(),
                WANT,
                buffer.as_mut_ptr(),
                64,
                &mut need,
            )
        };
        assert_eq!((ok, last_error(), need), (0, 2, 0xF2F2_F2F2));
        // Set: F2K's files keep no security descriptor to set — FALSE with ERROR_INVALID_FUNCTION
        // after the open, whatever the service would answer.
        reset();
        arm();
        let ok = unsafe {
            set_file_security_w(name.as_ptr(), DACL_SECURITY_INFORMATION, sd_bytes.as_ptr())
        };
        assert_eq!((ok, last_error()), (0, ERROR_INVALID_FUNCTION));
        arm();
        let ok = unsafe {
            set_file_security_a(
                b"filesec.tmp\0".as_ptr(),
                DACL_SECURITY_INFORMATION,
                sd_bytes.as_ptr(),
            )
        };
        assert_eq!((ok, last_error()), (0, ERROR_INVALID_FUNCTION));
        assert!(host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));

        // The kernel object calls: the handle goes straight through.
        reset();
        let sd_bytes = self_relative(20, 0, 0, 36, 52);
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd_bytes.clone()));
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut need = 0u32;
        arm();
        let ok = unsafe {
            get_kernel_object_security(0xFFFF_FFFF, info, core::ptr::null_mut(), 0, &mut need)
        };
        assert_eq!((ok, last_error(), need), (0, 122, 52));
        let mut need2 = 52;
        arm();
        let ok = unsafe {
            get_kernel_object_security(0xFFFF_FFFF, info, buffer.as_mut_ptr(), 52, &mut need2)
        };
        assert_eq!((ok, last_error(), need2), (1, 0xF2F2, 52));
        assert_eq!(&buffer[..52], &sd_bytes[..]);
        arm();
        let ok = unsafe {
            set_kernel_object_security(0xFFFF_FFFF, DACL_SECURITY_INFORMATION, sd_bytes.as_ptr())
        };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        let handles = host::SEC_CALLS
            .with(|calls| calls.borrow().clone())
            .into_iter()
            .map(|(_, h, _, _)| h)
            .collect::<Vec<_>>();
        assert_eq!(
            handles, [0xFFFF_FFFF; 5],
            "two gets (sizing and read) and a set"
        );
        // A closed handle: the status as the last error too.
        reset();
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0008));
        arm();
        let ok =
            unsafe { get_kernel_object_security(0x1234, info, buffer.as_mut_ptr(), 64, &mut need) };
        assert_eq!((ok, last_error()), (0, 6));
        host::SEC_SET_STATUS.with(|status| status.set(0xC000_0008));
        arm();
        let ok = unsafe {
            set_kernel_object_security(0x1234, DACL_SECURITY_INFORMATION, sd_bytes.as_ptr())
        };
        assert_eq!((ok, last_error()), (0, 6));
        assert!(
            host::OPEN_CALLS.with(|calls| calls.borrow().is_empty()),
            "no open"
        );
    }

    /// GetSecurityInfo's export shape: the out parameters convert once, nulls simply not written.
    #[test]
    fn the_exports_convert_their_arguments_once() {
        reset();
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(self_relative(20, 28, 0, 36, 52)));
        let mut owner = 0xF2F2usize;
        let mut sd = 0usize;
        arm();
        let code = unsafe {
            get_security_info(
                0x58,
                SE_FILE_OBJECT,
                WANT,
                &mut owner,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        assert_ne!(owner, 0xF2F2);
        assert_ne!(sd, 0);
        // SAFETY: the block the call handed out.
        unsafe { ProcessHeap::free(sd as *mut u8) };
        let owner = 0xF2F2usize;
        let code = unsafe {
            get_security_info(
                0x58,
                SE_FILE_OBJECT,
                WANT,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(owner, 0xF2F2);
    }
}
