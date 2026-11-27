//! The access-mask comparisons, and the few routines that reach the token services (adjust a privilege, a new security-granted access, the default NP ACL).

use super::*;

// --- Access masks, privileges, and the routines that reach the token services -------------

/// RtlAreAllAccessesGranted: whether `granted` has every bit of `desired`.
#[unsafe(export_name = "f2k_export_RtlAreAllAccessesGranted")]
pub unsafe extern "system" fn rtl_are_all_accesses_granted(granted: u32, desired: u32) -> u32 {
    u32::from(!granted & desired == 0)
}

/// RtlAreAnyAccessesGranted: whether `granted` has any bit of `desired`.
#[unsafe(export_name = "f2k_export_RtlAreAnyAccessesGranted")]
pub unsafe extern "system" fn rtl_are_any_accesses_granted(granted: u32, desired: u32) -> u32 {
    u32::from(granted & desired != 0)
}

/// The target's RtlAdjustPrivilege, over the token services.
#[cfg(not(test))]
pub(crate) fn adjust_privilege(privilege: u32, enable: u32, client: u32, was_enabled: *mut u32) -> u32 {
    use rtl::nt::access::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
    use rtl::sys::nr;
    let access = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    let mut token = 0u32;
    let status = if client != 0 {
        service(
            nr::NtOpenThreadToken,
            &[CURRENT_THREAD, access, 0, address_mut(&mut token)],
        )
    } else {
        service(
            nr::NtOpenProcessToken,
            &[CURRENT_PROCESS, access, address_mut(&mut token)],
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    // A TOKEN_PRIVILEGES with one entry: count, LUID, attributes.
    let mut new = [0u8; 16];
    set_dword(new.as_mut_ptr(), 1);
    new[4..8].copy_from_slice(&privilege.to_le_bytes());
    set_dword(
        new.as_mut_ptr().wrapping_add(12),
        if enable != 0 { SE_PRIVILEGE_ENABLED } else { 0 },
    );
    let mut old = [0u8; 16];
    let mut length = 0u32;
    let mut status = service(
        nr::NtAdjustPrivilegesToken,
        &[
            token,
            0,
            address(&new),
            16,
            address_mut(&mut old),
            address_mut(&mut length),
        ],
    );
    service(nr::NtClose, &[token]);
    if status == STATUS_NOT_ALL_ASSIGNED {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    if status == STATUS_SUCCESS {
        let was = if dword(old.as_ptr()) == 0 {
            enable != 0
        } else {
            dword(old.as_ptr().wrapping_add(12)) & SE_PRIVILEGE_ENABLED != 0
        };
        // SAFETY: the caller's out parameter.
        unsafe { was_enabled.write_unaligned(u32::from(was)) };
    }
    status
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
pub(crate) fn adjust_privilege(_: u32, _: u32, _: u32, _: *mut u32) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlAdjustPrivilege: enable or disable `privilege` in the thread's or the process's token,
/// whether it was enabled out.
#[unsafe(export_name = "f2k_export_RtlAdjustPrivilege")]
pub unsafe extern "system" fn rtl_adjust_privilege(
    privilege: u32,
    enable: u32,
    client: u32,
    was_enabled: *mut u32,
) -> u32 {
    adjust_privilege(privilege, enable, client, was_enabled)
}

/// The target's RtlNewSecurityGrantedAccess, over the token services.
#[cfg(not(test))]
pub(crate) fn new_security_granted_access(
    desired: u32,
    privileges: *mut u8,
    length: *mut u32,
    token: u32,
    mapping: *const GenericMapping,
    remaining: *mut u32,
) -> u32 {
    use rtl::nt::access::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, TOKEN_QUERY};
    use rtl::sys::nr;
    let (token, passed) = if token != 0 {
        (token, true)
    } else {
        let mut handle = 0u32;
        let status = service(
            nr::NtOpenThreadToken,
            &[CURRENT_THREAD, TOKEN_QUERY, 1, address_mut(&mut handle)],
        );
        if status != STATUS_SUCCESS {
            return status;
        }
        (handle, false)
    };
    let mut desired = desired;
    if !mapping.is_null() {
        let map: GenericMapping = read(mapping as *const u8);
        if desired & GENERIC_READ != 0 {
            desired |= map.generic_read;
        }
        if desired & GENERIC_WRITE != 0 {
            desired |= map.generic_write;
        }
        if desired & GENERIC_EXECUTE != 0 {
            desired |= map.generic_execute;
        }
        if desired & GENERIC_ALL != 0 {
            desired |= map.generic_all;
        }
        desired &= !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    }
    // SAFETY: the caller's out parameter.
    unsafe { remaining.write_unaligned(desired) };
    let mut result = 0u32;
    if desired & ACCESS_SYSTEM_SECURITY != 0 {
        // A PRIVILEGE_SET asking for SeSecurityPrivilege.
        let mut request = [0u8; 20];
        set_dword(request.as_mut_ptr(), 1);
        set_dword(
            request.as_mut_ptr().wrapping_add(4),
            PRIVILEGE_SET_ALL_NECESSARY,
        );
        request[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
        let status = service(
            nr::NtPrivilegeCheck,
            &[token, address(&request), address_mut(&mut result)],
        );
        if !passed {
            service(nr::NtClose, &[token]);
        }
        if status != STATUS_SUCCESS {
            return status;
        }
        if result == 0 {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        desired &= !ACCESS_SYSTEM_SECURITY;
        // SAFETY: the caller's out parameter.
        unsafe { remaining.write_unaligned(desired) };
    } else if !passed {
        service(nr::NtClose, &[token]);
    }
    // SAFETY: the caller's size.
    if 16 > unsafe { *length } {
        // SAFETY: the caller's size.
        unsafe { length.write_unaligned(16) };
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller's PRIVILEGE_SET holds 16 bytes.
    unsafe {
        let set = bytes_mut(privileges, 16);
        set[..4].copy_from_slice(&u32::from(result != 0).to_le_bytes());
        if result != 0 {
            set[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
            set[12..16].copy_from_slice(&SE_PRIVILEGE_USED_FOR_ACCESS.to_le_bytes());
        }
    }
    STATUS_SUCCESS
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
pub(crate) fn new_security_granted_access(
    _: u32,
    _: *mut u8,
    _: *mut u32,
    _: u32,
    _: *const GenericMapping,
    _: *mut u32,
) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlNewSecurityGrantedAccess: the access a create may grant, the privilege set used out.
#[unsafe(export_name = "f2k_export_RtlNewSecurityGrantedAccess")]
pub unsafe extern "system" fn rtl_new_security_granted_access(
    desired: u32,
    privileges: *mut u8,
    length: *mut u32,
    token: u32,
    mapping: *const GenericMapping,
    remaining: *mut u32,
) -> u32 {
    new_security_granted_access(desired, privileges, length, token, mapping, remaining)
}

/// The target's RtlDefaultNpAcl, over the token services: the default named-pipe ACL (SYSTEM,
/// Administrators and the token's owner: all; Everyone: read).
#[cfg(not(test))]
pub(crate) fn default_np_acl(acl_out: *mut *mut u8) -> u32 {
    use rtl::nt::access::{GENERIC_ALL, GENERIC_READ, TOKEN_QUERY};
    use rtl::sys::nr;
    // SAFETY: the caller's out parameter.
    unsafe { acl_out.write_unaligned(core::ptr::null_mut()) };
    let mut token = 0u32;
    let mut status = service(
        nr::NtOpenThreadToken,
        &[CURRENT_THREAD, TOKEN_QUERY, 1, address_mut(&mut token)],
    );
    if status == STATUS_NO_TOKEN {
        status = service(
            nr::NtOpenProcessToken,
            &[CURRENT_PROCESS, TOKEN_QUERY, address_mut(&mut token)],
        );
    }
    if status != STATUS_SUCCESS {
        return status;
    }
    let mut returned = 0u32;
    status = service(
        nr::NtQueryInformationToken,
        &[token, TOKEN_OWNER, 0, 0, address_mut(&mut returned)],
    );
    if status == STATUS_BUFFER_TOO_SMALL {
        let Some(owner_block) = heap_alloc(returned as usize) else {
            service(nr::NtClose, &[token]);
            return STATUS_NO_MEMORY;
        };
        status = service(
            nr::NtQueryInformationToken,
            &[
                token,
                TOKEN_OWNER,
                owner_block as u32,
                returned,
                address_mut(&mut returned),
            ],
        );
        if status == STATUS_SUCCESS {
            // SAFETY: the block holds the TOKEN_OWNER.
            let owner = read::<usize>(owner_block as *const u8);
            // SAFETY: the owner is a SID.
            let owner_len = unsafe { sid_len_of(bytes(owner as *const u8, SID_HEADER)) };
            let acl_size = 8 + 3 * 12 + owner_len + 16;
            if let Some(acl) = heap_alloc(acl_size) {
                let acl = acl as *mut u8;
                // SAFETY: the block is the ACL the descriptor's out parameter carries.
                unsafe {
                    rtl_create_acl(acl, acl_size as u32, ACL_REVISION);
                    let mut sid = [0u8; 16];
                    rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 1);
                    set_dword(sid.as_mut_ptr().wrapping_add(8), SECURITY_LOCAL_SYSTEM_RID);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, sid.as_ptr());
                    rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 2);
                    set_dword(
                        sid.as_mut_ptr().wrapping_add(8),
                        SECURITY_BUILTIN_DOMAIN_RID,
                    );
                    set_dword(sid.as_mut_ptr().wrapping_add(12), DOMAIN_ALIAS_RID_ADMINS);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, sid.as_ptr());
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, owner as *const u8);
                    rtl_initialize_sid(sid.as_mut_ptr(), WORLD_AUTHORITY.as_ptr(), 1);
                    set_dword(sid.as_mut_ptr().wrapping_add(8), SECURITY_WORLD_RID);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_READ, sid.as_ptr());
                    acl_out.write_unaligned(acl);
                }
            } else {
                status = STATUS_NO_MEMORY;
            }
        }
        heap_free(owner_block);
    }
    service(nr::NtClose, &[token]);
    if status != STATUS_SUCCESS {
        // SAFETY: the caller's out parameter.
        let made = unsafe { *acl_out };
        if !made.is_null() {
            heap_free(made as usize);
            // SAFETY: the caller's out parameter.
            unsafe { acl_out.write_unaligned(core::ptr::null_mut()) };
        }
    }
    status
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
pub(crate) fn default_np_acl(_: *mut *mut u8) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlDefaultNpAcl: the default named-pipe ACL in a heap block, its address out.
#[unsafe(export_name = "f2k_export_RtlDefaultNpAcl")]
pub unsafe extern "system" fn rtl_default_np_acl(acl_out: *mut *mut u8) -> u32 {
    default_np_acl(acl_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

    #[test]
    fn access_masks_compare() {
        assert_eq!(unsafe { rtl_are_all_accesses_granted(0xF0, 0x10) }, 1);
        assert_eq!(unsafe { rtl_are_all_accesses_granted(0xF0, 0x100) }, 0);
        assert_eq!(unsafe { rtl_are_any_accesses_granted(0xF0, 0x100) }, 0);
        assert_eq!(unsafe { rtl_are_any_accesses_granted(0xF0, 0x10) }, 1);
    }
}

