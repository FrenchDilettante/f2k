//! The AccessCheck family and the privilege lookups, as a program that checks an object's
//! security descriptor or asks about a privilege makes them: AccessCheck, AccessCheckByType,
//! AccessCheckByTypeResultList, the *AndAuditAlarm* wrappers, the AreAll/AreAny mask sugar,
//! PrivilegeCheck and the LookupPrivilegeName/DisplayName pairs. The bodies are advapi32's own
//! code over ntdll's services (the AccessCheck forms over NtAccessCheck and its by-type forms,
//! the rest over the token services in the [`services`] seam, as on Windows 2000): the caller's
//! pointers are handed through as they are, and the statuses the services answer are mapped to
//! the call's BOOL and last error — a failed service is FALSE with its status as the last error;
//! a check that ran and was denied reports FALSE through AccessStatus with the denial's status
//! (STATUS_ACCESS_DENIED maps to ERROR_ACCESS_DENIED) as the last error while the call still
//! returns TRUE.
//!
//! The *AndAuditAlarm* forms run the same plain check and skip the alarm: audit is a silent no-op
//! in F2K, so the audit-only arguments are dropped, the caller's effective token is used where
//! the form takes no token (F2K's threads never impersonate, so the process's), a private zeroed
//! privilege set is supplied where the plain service needs one, and pfGenerateOnClose is FALSE.
//! The lookups answer from the privileges' public names and LUIDs (winnt.h's SE_*_NAME and
//! SE_*_PRIVILEGE), where Windows 2000's asks the local security authority, which F2K does not
//! have.

use rtl::nt::access::TOKEN_QUERY;
use rtl::nt::Luid;
use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL};
// ERROR_NOACCESS: a LUID or buffer a lookup cannot write. ERROR_NOT_ENOUGH_MEMORY: no room for
// the alarm wrappers' private privilege set. ERROR_OUTOFMEMORY: no room for a query's block.
use rtl::winerror::{ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY};

use crate::imports::{self as nt, Answer, Counted, HeapBlock};
use crate::token::{bool_of, deliver_name, failed, name_for_luid, optional_ansi, optional_wide};
use crate::{caller_bytes_mut, Out};

/// GetCurrentProcess's pseudo-handle.
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// OBJECT_ATTRIBUTES as the token services read it (the layout is public), the same type the
/// imports seam's NtDuplicateToken declares.
pub(crate) type ObjectAttributes =
    rtl::nt::ObjectAttributes<u32, *const rtl::string::UnicodeString, *const u8>;

// --- The Nt security services' seam ------------------------------------------------------
//
// Declared once here: as ntdll imports on the target, as recording stand-ins on the host.

#[cfg(all(target_arch = "x86", not(test)))]
#[allow(non_snake_case)]
mod raw {
    use super::ObjectAttributes;

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn NtAccessCheck(
            sd: *const u8,
            token: u32,
            desired: u32,
            mapping: *const u8,
            priv_set: *mut u8,
            priv_len: *mut u32,
            granted: *mut u32,
            access_status: *mut u32,
        ) -> u32;
        pub fn NtAccessCheckByType(
            sd: *const u8,
            self_sid: *const u8,
            token: u32,
            desired: u32,
            list: *const u8,
            list_len: u32,
            mapping: *const u8,
            priv_set: *mut u8,
            priv_len: *mut u32,
            granted: *mut u32,
            access_status: *mut u32,
        ) -> u32;
        pub fn NtAccessCheckByTypeResultList(
            sd: *const u8,
            self_sid: *const u8,
            token: u32,
            desired: u32,
            list: *const u8,
            list_len: u32,
            mapping: *const u8,
            priv_set: *mut u8,
            priv_len: *mut u32,
            granted_list: *mut u32,
            status_list: *mut u32,
        ) -> u32;
        pub fn NtPrivilegeCheck(token: u32, required: *mut u8, result: *mut u8) -> u32;
        pub fn NtQueryInformationToken(
            token: u32,
            class: u32,
            info: *mut u8,
            length: u32,
            result_length: *mut u32,
        ) -> u32;
        pub fn NtSetInformationToken(token: u32, class: u32, info: *const u8, length: u32) -> u32;
        pub fn NtAdjustGroupsToken(
            token: u32,
            reset: u8,
            new_state: *const u8,
            length: u32,
            previous: *mut u8,
            return_length: *mut u32,
        ) -> u32;
        pub fn NtOpenThreadToken(
            thread: u32,
            access: u32,
            open_as_self: u8,
            token: *mut u32,
        ) -> u32;
        pub fn NtFilterToken(
            token: u32,
            flags: u32,
            disabled: *const u8,
            deleted: *const u8,
            restricted: *const u8,
            new_token: *mut u32,
        ) -> u32;
        pub fn NtDuplicateToken(
            token: u32,
            access: u32,
            attributes: *const ObjectAttributes,
            effective_only: u8,
            kind: u32,
            new_token: *mut u32,
        ) -> u32;
    }
}

/// The host tests' stand-ins: each records its call and answers the status [`STATUS`] holds,
/// writing [`REAL`]/[`RESULT`]/[`HANDLE`]/[`LIST`]/[`GRANTED`] into the outs the wrapper gave
/// (see each fake). [`TOKEN_REPLY`] is what NtQueryInformationToken delivers (bytes with the
/// whole's size, STATUS_BUFFER_TOO_SMALL when not the whole, or a status); [`DUP`] and
/// [`FILTER_COUNTS`] record what the duplicate and filter services were handed.
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub(crate) mod host {
    use std::cell::{Cell, RefCell};

    use rtl::status::{STATUS_BUFFER_TOO_SMALL, STATUS_NOT_IMPLEMENTED};

    use super::ObjectAttributes;

    std::thread_local! {
        pub static STATUS: Cell<u32> = const { Cell::new(0) };
        pub static REAL: Cell<u32> = const { Cell::new(0) };
        pub static RESULT: Cell<u32> = const { Cell::new(0) };
        pub static HANDLE: Cell<u32> = const { Cell::new(0x60) };
        pub static GRANTED: Cell<u32> = const { Cell::new(0) };
        pub static LIST: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
        pub static CALLS: RefCell<std::vec::Vec<(&'static str, u32, u32, u32)>> =
            const { RefCell::new(std::vec::Vec::new()) };
        pub static TOKEN_REPLY: RefCell<Result<std::vec::Vec<u8>, u32>> =
            const { RefCell::new(Err(STATUS_NOT_IMPLEMENTED)) };
        pub static DUP: Cell<(usize, u32, u32)> = const { Cell::new((0, 0, 0)) };
        pub static FILTER_COUNTS: RefCell<std::vec::Vec<u32>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    fn record(name: &'static str, a: u32, b: u32, c: u32) -> u32 {
        CALLS.with(|calls| calls.borrow_mut().push((name, a, b, c)));
        STATUS.with(|status| status.get())
    }

    /// The access-check services' outs: the granted mask and the reported access status.
    unsafe fn check_outs(granted: *mut u32, access_status: *mut u32) {
        // SAFETY: the caller's outs the test gave.
        unsafe {
            granted.write(GRANTED.with(|granted| granted.get()));
            access_status.write(REAL.with(|real| real.get()));
        }
    }

    pub unsafe extern "system" fn NtAccessCheck(
        _: *const u8,
        token: u32,
        desired: u32,
        _: *const u8,
        _: *mut u8,
        _: *mut u32,
        granted: *mut u32,
        access_status: *mut u32,
    ) -> u32 {
        let status = record("NtAccessCheck", token, desired, 0);
        if status == 0 {
            unsafe { check_outs(granted, access_status) }
        }
        status
    }

    pub unsafe extern "system" fn NtAccessCheckByType(
        _: *const u8,
        _: *const u8,
        token: u32,
        desired: u32,
        _: *const u8,
        list_len: u32,
        _: *const u8,
        _: *mut u8,
        _: *mut u32,
        granted: *mut u32,
        access_status: *mut u32,
    ) -> u32 {
        let status = record("NtAccessCheckByType", token, desired, list_len);
        if status == 0 {
            unsafe { check_outs(granted, access_status) }
        }
        status
    }

    pub unsafe extern "system" fn NtAccessCheckByTypeResultList(
        _: *const u8,
        _: *const u8,
        token: u32,
        desired: u32,
        _: *const u8,
        list_len: u32,
        _: *const u8,
        _: *mut u8,
        _: *mut u32,
        granted_list: *mut u32,
        status_list: *mut u32,
    ) -> u32 {
        let status = record("NtAccessCheckByTypeResultList", token, desired, list_len);
        if status == 0 {
            // SAFETY: the caller's lists the test gave.
            unsafe {
                let granted = GRANTED.with(|granted| granted.get());
                for index in 0..list_len {
                    granted_list.add(index as usize).write(granted);
                }
                let list = LIST.with(|list| list.borrow().clone());
                for (index, entry) in list.iter().take(list_len as usize).enumerate() {
                    status_list.add(index).write(*entry);
                }
            }
        }
        status
    }

    pub unsafe extern "system" fn NtPrivilegeCheck(token: u32, _: *mut u8, result: *mut u8) -> u32 {
        let status = record("NtPrivilegeCheck", token, 0, 0);
        // SAFETY: the local the wrapper gave.
        unsafe { result.write(RESULT.with(|result| result.get()) as u8) };
        status
    }

    pub unsafe extern "system" fn NtQueryInformationToken(
        token: u32,
        class: u32,
        info: *mut u8,
        length: u32,
        result_length: *mut u32,
    ) -> u32 {
        record("NtQueryInformationToken", token, class, 0);
        TOKEN_REPLY.with(|reply| match &*reply.borrow() {
            Err(status) => *status,
            Ok(bytes) => {
                let fits = bytes.len().min(length as usize);
                // SAFETY: the caller's buffer of `length` bytes and its result length.
                unsafe {
                    info.copy_from_nonoverlapping(bytes.as_ptr(), fits);
                    result_length.write(bytes.len() as u32)
                };
                if fits < bytes.len() {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    0
                }
            }
        })
    }

    pub unsafe extern "system" fn NtSetInformationToken(
        token: u32,
        class: u32,
        _: *const u8,
        _: u32,
    ) -> u32 {
        record("NtSetInformationToken", token, class, 0)
    }

    pub unsafe extern "system" fn NtAdjustGroupsToken(
        token: u32,
        reset: u8,
        _: *const u8,
        _: u32,
        _: *mut u8,
        _: *mut u32,
    ) -> u32 {
        record("NtAdjustGroupsToken", token, u32::from(reset), 0)
    }

    pub unsafe extern "system" fn NtOpenThreadToken(
        thread: u32,
        access: u32,
        _: u8,
        token: *mut u32,
    ) -> u32 {
        let status = record("NtOpenThreadToken", thread, access, 0);
        if status == 0 {
            // SAFETY: the caller's handle slot the test gave.
            unsafe { token.write(HANDLE.with(|handle| handle.get())) };
        }
        status
    }

    pub unsafe extern "system" fn NtFilterToken(
        token: u32,
        flags: u32,
        disabled: *const u8,
        deleted: *const u8,
        restricted: *const u8,
        new_token: *mut u32,
    ) -> u32 {
        let status = record("NtFilterToken", token, flags, 0);
        FILTER_COUNTS.with(|counts| {
            let mut counts = counts.borrow_mut();
            counts.clear();
            for block in [disabled, deleted, restricted] {
                // SAFETY: the heap block the body built (null counted as none), its count first.
                counts.push(if block.is_null() {
                    0
                } else {
                    unsafe { block.cast::<u32>().read_unaligned() }
                });
            }
        });
        if status == 0 {
            unsafe { new_token.write(HANDLE.with(|handle| handle.get())) }
        }
        status
    }

    pub unsafe extern "system" fn NtDuplicateToken(
        token: u32,
        access: u32,
        attributes: *const ObjectAttributes,
        _: u8,
        kind: u32,
        new_token: *mut u32,
    ) -> u32 {
        let status = record("NtDuplicateToken", token, access, kind);
        // SAFETY: the attributes the body built, alive across the call.
        let (descriptor, flags, level) = unsafe {
            let attributes = &*attributes;
            (
                attributes.security_descriptor as usize,
                attributes.attributes,
                (*attributes.security_quality_of_service.cast::<[u32; 3]>())[1],
            )
        };
        DUP.with(|dup| dup.set((descriptor, flags, level)));
        if status == 0 {
            unsafe { new_token.write(HANDLE.with(|handle| handle.get())) }
        }
        status
    }
}

#[cfg(test)]
use host as raw;

/// The safe wrappers over the seam: a service's failure an `Err` of its status, an access
/// check's answer its service status and reported access status.
pub(crate) mod services {
    use rtl::status::{checked, NtStatus};

    use super::{raw, Answer, ObjectAttributes};

    /// NtAccessCheck: the service's status and the access status it reported (the caller's
    /// memory is handed through, which the service probes).
    pub fn access_check(
        sd: *const u8,
        token: u32,
        desired: u32,
        mapping: *const u8,
        priv_set: *mut u8,
        priv_len: *mut u32,
        granted: *mut u32,
    ) -> (NtStatus, NtStatus) {
        let mut access_status = 0u32;
        // SAFETY: as the doc says.
        let status = unsafe {
            raw::NtAccessCheck(
                sd,
                token,
                desired,
                mapping,
                priv_set,
                priv_len,
                granted,
                &mut access_status,
            )
        };
        (NtStatus(status), NtStatus(access_status))
    }

    /// NtAccessCheckByType: as [`access_check`], with the principal-self SID and type list.
    #[allow(clippy::too_many_arguments)]
    pub fn access_check_by_type(
        sd: *const u8,
        self_sid: *const u8,
        token: u32,
        desired: u32,
        list: *const u8,
        list_len: u32,
        mapping: *const u8,
        priv_set: *mut u8,
        priv_len: *mut u32,
        granted: *mut u32,
    ) -> (NtStatus, NtStatus) {
        let mut access_status = 0u32;
        // SAFETY: as [`access_check`]'s.
        let status = unsafe {
            raw::NtAccessCheckByType(
                sd,
                self_sid,
                token,
                desired,
                list,
                list_len,
                mapping,
                priv_set,
                priv_len,
                granted,
                &mut access_status,
            )
        };
        (NtStatus(status), NtStatus(access_status))
    }

    /// NtAccessCheckByTypeResultList: the service's status; the granted and status lists are
    /// written where they point.
    #[allow(clippy::too_many_arguments)]
    pub fn access_check_by_type_result_list(
        sd: *const u8,
        self_sid: *const u8,
        token: u32,
        desired: u32,
        list: *const u8,
        list_len: u32,
        mapping: *const u8,
        priv_set: *mut u8,
        priv_len: *mut u32,
        granted_list: *mut u32,
        status_list: *mut u32,
    ) -> NtStatus {
        // SAFETY: as [`access_check`]'s.
        NtStatus(unsafe {
            raw::NtAccessCheckByTypeResultList(
                sd,
                self_sid,
                token,
                desired,
                list,
                list_len,
                mapping,
                priv_set,
                priv_len,
                granted_list,
                status_list,
            )
        })
    }

    /// NtPrivilegeCheck: the service's status and the result it reported.
    pub fn privilege_check(token: u32, required: *mut u8) -> (NtStatus, u32) {
        let mut result = 0u8;
        // SAFETY: the caller's privilege set handed through, which the service probes; the one
        // other place it writes is the local.
        let status = unsafe { raw::NtPrivilegeCheck(token, required, &mut result) };
        (NtStatus(status), u32::from(result))
    }

    /// NtQueryInformationToken: the token's information of `class` into `information` (too small
    /// a buffer is STATUS_BUFFER_TOO_SMALL, the size in its length).
    pub fn query_information_token(token: u32, class: u32, information: &mut [u8]) -> Answer {
        let mut length = 0u32;
        // SAFETY: the service writes at most the buffer's length into it, and the length into the
        // local.
        let status = unsafe {
            raw::NtQueryInformationToken(
                token,
                class,
                information.as_mut_ptr(),
                information.len() as u32,
                &mut length,
            )
        };
        Answer {
            status: NtStatus(status),
            length,
        }
    }

    /// NtSetInformationToken.
    pub fn set_information_token(
        token: u32,
        class: u32,
        info: *const u8,
        length: u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the caller's memory handed through, which the service probes.
        checked(unsafe { raw::NtSetInformationToken(token, class, info, length) })
    }

    /// NtAdjustGroupsToken.
    pub fn adjust_groups_token(
        token: u32,
        reset: bool,
        new_state: *const u8,
        length: u32,
        previous: *mut u8,
        return_length: *mut u32,
    ) -> NtStatus {
        // SAFETY: the caller's memory handed through, which the service probes.
        NtStatus(unsafe {
            raw::NtAdjustGroupsToken(
                token,
                u8::from(reset),
                new_state,
                length,
                previous,
                return_length,
            )
        })
    }

    /// NtOpenThreadToken.
    pub fn open_thread_token(
        thread: u32,
        access: u32,
        open_as_self: bool,
        token: *mut u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the one place the service writes is the caller's, which it probes.
        checked(unsafe { raw::NtOpenThreadToken(thread, access, u8::from(open_as_self), token) })
    }

    /// NtFilterToken.
    pub fn filter_token(
        token: u32,
        flags: u32,
        disabled: *const u8,
        deleted: *const u8,
        restricted: *const u8,
        new_token: *mut u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the heap blocks live across the call; the one caller place is the handle slot.
        checked(unsafe {
            raw::NtFilterToken(token, flags, disabled, deleted, restricted, new_token)
        })
    }

    /// NtDuplicateToken with the attributes built.
    pub fn duplicate_token(
        token: u32,
        access: u32,
        attributes: *const ObjectAttributes,
        kind: u32,
        new_token: *mut u32,
    ) -> Result<(), NtStatus> {
        // SAFETY: the attributes live across the call; the one caller place is the handle slot.
        checked(unsafe { raw::NtDuplicateToken(token, access, attributes, 0, kind, new_token) })
    }
}

// --- The AccessCheck family ---------------------------------------------------------------

/// The check's answer as a BOOL: a failed service is FALSE with its status as the last error;
/// otherwise AccessStatus gets the reported access status (FALSE, with the denial's status as
/// the last error, for STATUS_ACCESS_DENIED and its kin) and the call returns TRUE. The alarm
/// wrappers' pfGenerateOnClose is written FALSE (no alarm is ever generated).
fn answer(
    service: NtStatus,
    real: NtStatus,
    status: Option<&mut Out<'_, u32>>,
    pf_generate_on_close: *mut u32,
) -> u32 {
    if !service.is_success() {
        nt::set_last_error(nt::dos_error(service));
        return 0;
    }
    if let Some(status) = status {
        status.set(u32::from(real.is_success()));
    }
    if !real.is_success() {
        nt::set_last_error(nt::dos_error(real));
    }
    // SAFETY: the caller's place, when it gave one.
    if !pf_generate_on_close.is_null() {
        unsafe { pf_generate_on_close.write(0) };
    }
    1
}

/// The result-list check's status list as Win32 errors, converted in place where the service
/// left it: STATUS_SUCCESS to NO_ERROR, anything else to its Win32 mapping.
fn convert_status_list(list: *mut u32, length: u32) {
    if list.is_null() {
        return;
    }
    // SAFETY: the caller's list of `length` dwords the service just wrote.
    let Some(bytes) = (unsafe { caller_bytes_mut(list as *mut u8, 4 * length as usize) }) else {
        return;
    };
    for entry in bytes.chunks_exact_mut(4) {
        let status = u32::from_le_bytes(entry.try_into().unwrap());
        let error = if status == 0 {
            0
        } else {
            nt::dos_error(NtStatus(status))
        };
        entry.copy_from_slice(&error.to_le_bytes());
    }
}

/// AccessCheck: the security descriptor checked against the token for the desired access. The
/// last error is untouched on a plain success, a failed service's status on its failure, the
/// denial's status (STATUS_ACCESS_DENIED: ERROR_ACCESS_DENIED) when the check ran and was
/// denied, with AccessStatus FALSE and the call TRUE all the same.
///
/// # Safety
///
/// The pointers are the caller's, which the service probes and the call writes: the descriptor,
/// mapping, privilege set and its length, the granted mask and the status.
#[unsafe(export_name = "f2k_export_AccessCheck")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check(
    security_descriptor: *const u8,
    client_token: u32,
    desired_access: u32,
    generic_mapping: *const u8,
    privilege_set: *mut u8,
    privilege_set_length: *mut u32,
    granted_access: *mut u32,
    access_status: *mut u32,
) -> u32 {
    // SAFETY: the caller's place for the status.
    let mut status = unsafe { Out::optional(access_status) };
    let (service, real) = services::access_check(
        security_descriptor,
        client_token,
        desired_access,
        generic_mapping,
        privilege_set,
        privilege_set_length,
        granted_access,
    );
    answer(service, real, status.as_mut(), core::ptr::null_mut())
}

/// AccessCheckByType: AccessCheck over an object-type list (and the principal-self SID the
/// PRINCIPAL_SELF_SID ACEs resolve to), same answer mapping.
///
/// # Safety
///
/// As AccessCheck's, plus the caller's SID and type list.
#[unsafe(export_name = "f2k_export_AccessCheckByType")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type(
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    client_token: u32,
    desired_access: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    privilege_set: *mut u8,
    privilege_set_length: *mut u32,
    granted_access: *mut u32,
    access_status: *mut u32,
) -> u32 {
    // SAFETY: the caller's place for the status.
    let mut status = unsafe { Out::optional(access_status) };
    let (service, real) = services::access_check_by_type(
        security_descriptor,
        principal_self_sid,
        client_token,
        desired_access,
        object_type_list,
        object_type_list_length,
        generic_mapping,
        privilege_set,
        privilege_set_length,
        granted_access,
    );
    answer(service, real, status.as_mut(), core::ptr::null_mut())
}

/// AccessCheckByTypeResultList: AccessCheckByType with a granted mask and a status per type-list
/// entry; the status list comes back as Win32 errors. A failed service is FALSE with its status
/// as the last error; otherwise the call returns TRUE whatever the entries say.
///
/// # Safety
///
/// As AccessCheckByType's, plus the caller's granted and status lists.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeResultList")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_result_list(
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    client_token: u32,
    desired_access: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    privilege_set: *mut u8,
    privilege_set_length: *mut u32,
    granted_access_list: *mut u32,
    access_status_list: *mut u32,
) -> u32 {
    let service = services::access_check_by_type_result_list(
        security_descriptor,
        principal_self_sid,
        client_token,
        desired_access,
        object_type_list,
        object_type_list_length,
        generic_mapping,
        privilege_set,
        privilege_set_length,
        granted_access_list,
        access_status_list,
    );
    if !service.is_success() {
        nt::set_last_error(nt::dos_error(service));
        return 0;
    }
    convert_status_list(access_status_list, object_type_list_length);
    1
}

/// AreAllAccessesGranted: whether the granted mask has every bit the desired one has; the last
/// error is untouched.
#[unsafe(export_name = "f2k_export_AreAllAccessesGranted")]
pub unsafe extern "system" fn are_all_accesses_granted(
    granted_access: u32,
    desired_access: u32,
) -> u32 {
    u32::from(granted_access & desired_access == desired_access)
}

/// AreAnyAccessesGranted: whether the granted mask has any bit the desired one has; the last
/// error is untouched.
#[unsafe(export_name = "f2k_export_AreAnyAccessesGranted")]
pub unsafe extern "system" fn are_any_accesses_granted(
    granted_access: u32,
    desired_access: u32,
) -> u32 {
    u32::from(granted_access & desired_access != 0)
}

// --- The *AndAuditAlarm* wrappers ----------------------------------------------------------

/// A token handle opened for advapi32's own use, closed when dropped.
struct OpenedToken(u32);

impl Drop for OpenedToken {
    fn drop(&mut self) {
        let _ = nt::close(self.0);
    }
}

/// The caller's effective token for the alarm forms that take none: F2K's threads never
/// impersonate, so the process's own.
fn effective_token() -> Result<OpenedToken, NtStatus> {
    nt::open_own_process_token(CURRENT_PROCESS, TOKEN_QUERY).map(OpenedToken)
}

/// A zeroed privilege set of one entry on the process heap, with its length: the plain check
/// needs one where the audit-alarm service takes none.
fn private_privilege_set() -> Option<(HeapBlock, u32)> {
    Some((HeapBlock::new(8 + 12)?, 20))
}

/// The alarm forms' shared work with the alarm skipped: the plain check against `token`, with
/// pfGenerateOnClose FALSE.
#[allow(clippy::too_many_arguments)]
fn alarm_check(
    sd: *const u8,
    token: u32,
    desired: u32,
    mapping: *const u8,
    granted: *mut u32,
    status: *mut u32,
    pf: *mut u32,
) -> u32 {
    let Some((mut set, mut length)) = private_privilege_set() else {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let (service, real) = services::access_check(
        sd,
        token,
        desired,
        mapping,
        set.bytes_mut().as_mut_ptr(),
        &mut length,
        granted,
    );
    // SAFETY: the caller's place for the status.
    answer(service, real, unsafe { Out::optional(status) }.as_mut(), pf)
}

/// The by-type alarm forms' shared work: the plain by-type check against `token`.
#[allow(clippy::too_many_arguments)]
fn alarm_check_by_type(
    sd: *const u8,
    self_sid: *const u8,
    token: u32,
    desired: u32,
    list: *const u8,
    list_len: u32,
    mapping: *const u8,
    granted: *mut u32,
    status: *mut u32,
    pf: *mut u32,
) -> u32 {
    let Some((mut set, mut length)) = private_privilege_set() else {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let (service, real) = services::access_check_by_type(
        sd,
        self_sid,
        token,
        desired,
        list,
        list_len,
        mapping,
        set.bytes_mut().as_mut_ptr(),
        &mut length,
        granted,
    );
    // SAFETY: the caller's place for the status.
    answer(service, real, unsafe { Out::optional(status) }.as_mut(), pf)
}

/// The result-list alarm forms' shared work: the plain result-list check against `token`, the
/// status list converted to Win32 errors.
#[allow(clippy::too_many_arguments)]
fn alarm_check_by_type_result_list(
    sd: *const u8,
    self_sid: *const u8,
    token: u32,
    desired: u32,
    list: *const u8,
    list_len: u32,
    mapping: *const u8,
    granted_list: *mut u32,
    status_list: *mut u32,
    pf: *mut u32,
) -> u32 {
    let Some((mut set, mut length)) = private_privilege_set() else {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let service = services::access_check_by_type_result_list(
        sd,
        self_sid,
        token,
        desired,
        list,
        list_len,
        mapping,
        set.bytes_mut().as_mut_ptr(),
        &mut length,
        granted_list,
        status_list,
    );
    // SAFETY: the caller's place, when it gave one.
    if !pf.is_null() {
        unsafe { pf.write(0) };
    }
    if !service.is_success() {
        nt::set_last_error(nt::dos_error(service));
        return 0;
    }
    convert_status_list(status_list, list_len);
    1
}

/// AccessCheckAndAuditAlarmW: the plain AccessCheck against the caller's effective token, the
/// alarm skipped (the audit-only arguments are dropped).
///
/// # Safety
/// The pointers are the caller's, as AccessCheck's.
#[unsafe(export_name = "f2k_export_AccessCheckAndAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_and_audit_alarm_w(
    _subsystem_name: *const u16,
    _handle_id: *const u8,
    _object_type_name: *const u16,
    _object_name: *const u16,
    security_descriptor: *const u8,
    desired_access: u32,
    generic_mapping: *const u8,
    _object_creation: u32,
    granted_access: *mut u32,
    access_status: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    let token = match effective_token() {
        Ok(token) => token,
        Err(status) => return failed(status),
    };
    alarm_check(
        security_descriptor,
        token.0,
        desired_access,
        generic_mapping,
        granted_access,
        access_status,
        pf_generate_on_close,
    )
}

/// AccessCheckAndAuditAlarmA: the W form, the alarm skipped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_AccessCheckAndAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_and_audit_alarm_a(
    _subsystem_name: *const u8,
    _handle_id: *const u8,
    _object_type_name: *const u8,
    _object_name: *const u8,
    security_descriptor: *const u8,
    desired_access: u32,
    generic_mapping: *const u8,
    object_creation: u32,
    granted_access: *mut u32,
    access_status: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    // SAFETY: the same marshaling as the W form, whose names it drops with the alarm.
    unsafe {
        access_check_and_audit_alarm_w(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            security_descriptor,
            desired_access,
            generic_mapping,
            object_creation,
            granted_access,
            access_status,
            pf_generate_on_close,
        )
    }
}

/// AccessCheckByTypeAndAuditAlarmW: the plain AccessCheckByType against the caller's effective
/// token, the alarm skipped.
///
/// # Safety
/// As AccessCheckByType's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeAndAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_and_audit_alarm_w(
    _subsystem_name: *const u16,
    _handle_id: *const u8,
    _object_type_name: *const u16,
    _object_name: *const u16,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    _audit_type: u32,
    _flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    _object_creation: u32,
    granted_access: *mut u32,
    access_status: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    let token = match effective_token() {
        Ok(token) => token,
        Err(status) => return failed(status),
    };
    alarm_check_by_type(
        security_descriptor,
        principal_self_sid,
        token.0,
        desired_access,
        object_type_list,
        object_type_list_length,
        generic_mapping,
        granted_access,
        access_status,
        pf_generate_on_close,
    )
}

/// AccessCheckByTypeAndAuditAlarmA: the W form, the alarm skipped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeAndAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_and_audit_alarm_a(
    _subsystem_name: *const u8,
    _handle_id: *const u8,
    _object_type_name: *const u8,
    _object_name: *const u8,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    audit_type: u32,
    flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    object_creation: u32,
    granted_access: *mut u32,
    access_status: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    // SAFETY: as the W form's.
    unsafe {
        access_check_by_type_and_audit_alarm_w(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            security_descriptor,
            principal_self_sid,
            desired_access,
            audit_type,
            flags,
            object_type_list,
            object_type_list_length,
            generic_mapping,
            object_creation,
            granted_access,
            access_status,
            pf_generate_on_close,
        )
    }
}

/// AccessCheckByTypeResultListAndAuditAlarmW: the plain AccessCheckByTypeResultList against the
/// caller's effective token, the alarm skipped.
///
/// # Safety
/// As AccessCheckByTypeResultList's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeResultListAndAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_result_list_and_audit_alarm_w(
    _subsystem_name: *const u16,
    _handle_id: *const u8,
    _object_type_name: *const u16,
    _object_name: *const u16,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    _audit_type: u32,
    _flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    _object_creation: u32,
    granted_access_list: *mut u32,
    access_status_list: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    let token = match effective_token() {
        Ok(token) => token,
        Err(status) => return failed(status),
    };
    alarm_check_by_type_result_list(
        security_descriptor,
        principal_self_sid,
        token.0,
        desired_access,
        object_type_list,
        object_type_list_length,
        generic_mapping,
        granted_access_list,
        access_status_list,
        pf_generate_on_close,
    )
}

/// AccessCheckByTypeResultListAndAuditAlarmA: the W form, the alarm skipped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeResultListAndAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_result_list_and_audit_alarm_a(
    _subsystem_name: *const u8,
    _handle_id: *const u8,
    _object_type_name: *const u8,
    _object_name: *const u8,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    audit_type: u32,
    flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    object_creation: u32,
    granted_access_list: *mut u32,
    access_status_list: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    // SAFETY: as the W form's.
    unsafe {
        access_check_by_type_result_list_and_audit_alarm_w(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            security_descriptor,
            principal_self_sid,
            desired_access,
            audit_type,
            flags,
            object_type_list,
            object_type_list_length,
            generic_mapping,
            object_creation,
            granted_access_list,
            access_status_list,
            pf_generate_on_close,
        )
    }
}

/// AccessCheckByTypeResultListAndAuditAlarmByHandleW: the plain AccessCheckByTypeResultList
/// against the client token given, the alarm skipped.
///
/// # Safety
/// As AccessCheckByTypeResultList's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeResultListAndAuditAlarmByHandleW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_result_list_and_audit_alarm_by_handle_w(
    _subsystem_name: *const u16,
    _handle_id: *const u8,
    client_token: u32,
    _object_type_name: *const u16,
    _object_name: *const u16,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    _audit_type: u32,
    _flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    _object_creation: u32,
    granted_access_list: *mut u32,
    access_status_list: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    alarm_check_by_type_result_list(
        security_descriptor,
        principal_self_sid,
        client_token,
        desired_access,
        object_type_list,
        object_type_list_length,
        generic_mapping,
        granted_access_list,
        access_status_list,
        pf_generate_on_close,
    )
}

/// AccessCheckByTypeResultListAndAuditAlarmByHandleA: the W form, the alarm skipped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_AccessCheckByTypeResultListAndAuditAlarmByHandleA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn access_check_by_type_result_list_and_audit_alarm_by_handle_a(
    _subsystem_name: *const u8,
    _handle_id: *const u8,
    client_token: u32,
    _object_type_name: *const u8,
    _object_name: *const u8,
    security_descriptor: *const u8,
    principal_self_sid: *const u8,
    desired_access: u32,
    audit_type: u32,
    flags: u32,
    object_type_list: *const u8,
    object_type_list_length: u32,
    generic_mapping: *const u8,
    object_creation: u32,
    granted_access_list: *mut u32,
    access_status_list: *mut u32,
    pf_generate_on_close: *mut u32,
) -> u32 {
    // SAFETY: as the W form's.
    unsafe {
        access_check_by_type_result_list_and_audit_alarm_by_handle_w(
            core::ptr::null(),
            core::ptr::null(),
            client_token,
            core::ptr::null(),
            core::ptr::null(),
            security_descriptor,
            principal_self_sid,
            desired_access,
            audit_type,
            flags,
            object_type_list,
            object_type_list_length,
            generic_mapping,
            object_creation,
            granted_access_list,
            access_status_list,
            pf_generate_on_close,
        )
    }
}

/// PrivilegeCheck: NtPrivilegeCheck, the result written whatever the status, a failure's status
/// as the last error and FALSE, TRUE on success with the last error untouched.
///
/// # Safety
///
/// `required_privileges` is the caller's privilege set (the service reads and marks it).
#[unsafe(export_name = "f2k_export_PrivilegeCheck")]
pub unsafe extern "system" fn privilege_check(
    token: u32,
    required_privileges: *mut u8,
    pf_result: *mut u32,
) -> u32 {
    // SAFETY: the caller's place for the result.
    let mut place = unsafe { Out::optional(pf_result) };
    let (status, result) = services::privilege_check(token, required_privileges);
    if let Some(place) = place.as_mut() {
        place.set(result);
    }
    match status.ok() {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// LookupPrivilegeNameW: the privilege's public name for the LUID, into the caller's buffer of
/// `*cch_name` units (see [`deliver_name`]).
///
/// # Safety
///
/// `system` and `luid` are null or what they name; `name` and `cch_name` the caller's buffer and
/// count.
#[unsafe(export_name = "f2k_export_LookupPrivilegeNameW")]
pub unsafe extern "system" fn lookup_privilege_name_w(
    system: *const u16,
    luid: *const Luid,
    name: *mut u16,
    cch_name: *mut u32,
) -> u32 {
    // SAFETY: the caller's string, LUID and count.
    let (system, luid, mut cch) = unsafe {
        (
            optional_wide(system),
            Out::optional(luid as *mut Luid).map(|luid| luid.get()),
            Out::optional(cch_name),
        )
    };
    let Some(cch) = cch.as_mut() else {
        nt::set_last_error(ERROR_NOACCESS);
        return 0;
    };
    match name_for_luid(system, luid)
        .and_then(|text| deliver_name(text, true, name as *mut u8, cch))
    {
        Ok(()) => 1,
        Err(error) => bool_of(Err(error)),
    }
}

/// LookupPrivilegeNameA: LookupPrivilegeNameW of the system name converted; the name delivered
/// in ANSI (the public names are ASCII, one byte per unit).
///
/// # Safety
///
/// As LookupPrivilegeNameW's, for ANSI strings.
#[unsafe(export_name = "f2k_export_LookupPrivilegeNameA")]
pub unsafe extern "system" fn lookup_privilege_name_a(
    system: *const u8,
    luid: *const Luid,
    name: *mut u8,
    cch_name: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, LUID and count.
    let (system, luid, mut cch) = unsafe {
        (
            optional_ansi(system),
            Out::optional(luid as *mut Luid).map(|luid| luid.get()),
            Out::optional(cch_name),
        )
    };
    let Some(cch) = cch.as_mut() else {
        nt::set_last_error(ERROR_NOACCESS);
        return 0;
    };
    let converted = system.map(nt::ansi_to_unicode).transpose();
    let system = match converted {
        Ok(system) => system,
        Err(status) => return bool_of(Err(nt::dos_error(status))),
    };
    let system = system.as_ref().map(|wide| wide.counted());
    match name_for_luid(system.as_ref().map(Counted::units), luid)
        .and_then(|text| deliver_name(text, false, name, cch))
    {
        Ok(()) => 1,
        Err(error) => bool_of(Err(error)),
    }
}

/// TokenRestrictedSids, the information class the restriction query reads.
const TOKEN_RESTRICTED_SIDS: u32 = 11;

/// IsTokenRestricted's answer: whether the token's restricted-SID list is not empty, or the
/// error. The size query comes first (STATUS_BUFFER_TOO_SMALL with the size; any other status
/// there is the failure), then the list itself into a heap block.
fn restricted(token: u32) -> Result<bool, u32> {
    let first = services::query_information_token(token, TOKEN_RESTRICTED_SIDS, &mut []);
    if first.status.0 != STATUS_BUFFER_TOO_SMALL {
        return Err(nt::dos_error(first.status));
    }
    let mut block = HeapBlock::new(first.length as usize).ok_or(ERROR_OUTOFMEMORY)?;
    let second = services::query_information_token(token, TOKEN_RESTRICTED_SIDS, block.bytes_mut());
    if !second.status.is_success() {
        return Err(nt::dos_error(second.status));
    }
    Ok(block
        .bytes()
        .get(..4)
        .is_some_and(|count| u32::from_le_bytes(count.try_into().unwrap()) != 0))
}

/// IsTokenRestricted: whether the token has restricted SIDs; the return value is the answer
/// itself, the last error untouched on the success path and the failure's error on a failure.
#[unsafe(export_name = "f2k_export_IsTokenRestricted")]
pub unsafe extern "system" fn is_token_restricted(token: u32) -> u32 {
    match restricted(token) {
        Ok(restricted) => u32::from(restricted),
        Err(error) => {
            nt::set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use rtl::nt::Luid;
    use rtl::status::STATUS_ACCESS_DENIED;
    use rtl::testing::wide_z;

    use super::*;
    use crate::accesscheck::host::{
        CALLS,
        DUP,
        FILTER_COUNTS,
        GRANTED,
        HANDLE,
        LIST,
        REAL,
        RESULT,
        STATUS,
        TOKEN_REPLY,
    };
    use crate::imports::host::{LAST_ERROR, TOKEN, TOKEN_CALLS, TOKEN_STATUS};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn calls() -> Vec<(&'static str, u32, u32, u32)> {
        CALLS.with(|calls| calls.borrow().clone())
    }

    fn clear() {
        CALLS.with(|calls| calls.borrow_mut().clear());
        TOKEN_CALLS.with(|calls| calls.borrow_mut().clear());
        STATUS.with(|status| status.set(0));
        REAL.with(|real| real.set(0));
        RESULT.with(|result| result.set(0));
        GRANTED.with(|granted| granted.set(0));
        HANDLE.with(|handle| handle.set(0x60));
        DUP.with(|dup| dup.set((0, 0, 0)));
        LIST.with(|list| list.borrow_mut().clear());
        FILTER_COUNTS.with(|counts| counts.borrow_mut().clear());
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_000F));
        TOKEN_STATUS.with(|status| status.set(0));
    }

    /// AreAll/AreAny are mask math and leave the last error alone.
    #[test]
    fn are_all_and_any_are_mask_math() {
        arm();
        assert_eq!(unsafe { are_all_accesses_granted(0x000F_01FF, 1) }, 1);
        assert_eq!(unsafe { are_all_accesses_granted(1, 0x000F_01FF) }, 0);
        assert_eq!(
            unsafe { are_all_accesses_granted(0x000F_01FF, 0x000F_01FF) },
            1
        );
        assert_eq!(unsafe { are_any_accesses_granted(1, 0x000F_01FF) }, 1);
        assert_eq!(unsafe { are_any_accesses_granted(0, 0x000F_01FF) }, 0);
        assert_eq!(
            unsafe { are_any_accesses_granted(0x0010_0000, 0x000F_01FF) },
            0
        );
        assert_eq!(last_error(), 0xF2F2);
    }

    /// AccessCheck hands the mask and token through and maps the two statuses: a failed service
    /// is FALSE with its status as the last error and AccessStatus untouched; a denial reports
    /// FALSE through AccessStatus with ERROR_ACCESS_DENIED as the last error and TRUE; a grant
    /// reports TRUE and leaves the last error alone, GrantedAccess out.
    #[test]
    fn access_check_maps_the_two_statuses() {
        let mut granted = 0u32;
        let mut status = 0xF2F2;
        let sd = [0u8; 4];
        let mapping = [0u8; 16];
        let call = |granted: *mut u32, status: *mut u32| unsafe {
            access_check(
                sd.as_ptr(),
                0x58,
                0x0002_0000,
                mapping.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                granted,
                status,
            )
        };
        clear();
        STATUS.with(|s| s.set(STATUS_ACCESS_DENIED));
        arm();
        assert_eq!(
            (call(&mut granted, &mut status), last_error(), status),
            (0, 5, 0xF2F2)
        );
        assert_eq!(
            calls().last(),
            Some(&("NtAccessCheck", 0x58, 0x0002_0000, 0))
        );
        clear();
        REAL.with(|real| real.set(STATUS_ACCESS_DENIED));
        GRANTED.with(|g| g.set(0x1234));
        arm();
        assert_eq!(
            (
                call(&mut granted, &mut status),
                last_error(),
                status,
                granted
            ),
            (1, 5, 0, 0x1234)
        );
        clear();
        GRANTED.with(|g| g.set(0x000F_01FF));
        arm();
        assert_eq!(
            (
                call(&mut granted, &mut status),
                last_error(),
                status,
                granted
            ),
            (1, 0xF2F2, 1, 0x000F_01FF)
        );
    }

    /// AccessCheckByType passes the type list's length through with the same answer mapping.
    #[test]
    fn by_type_passes_the_type_list_through() {
        let mut granted = 0u32;
        let mut status = 0xF2F2;
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let types = [0u8; 24];
        clear();
        let ok = unsafe {
            access_check_by_type(
                core::ptr::null(),
                sid.as_ptr(),
                0x58,
                1,
                types.as_ptr(),
                2,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut granted,
                &mut status,
            )
        };
        assert_eq!((ok, status), (1, 1));
        assert_eq!(calls().last(), Some(&("NtAccessCheckByType", 0x58, 1, 2)));
    }

    /// AccessCheckByTypeResultList converts the service's status list to Win32 errors in place
    /// (STATUS_SUCCESS to NO_ERROR, the rest to their mapping) and returns TRUE; a failed
    /// service leaves the list alone and returns FALSE with its status as the last error.
    #[test]
    fn result_list_converts_the_statuses_to_win32() {
        let mut granted = [0u32; 3];
        let mut statuses = [0xFFFF_FFFFu32; 3];
        let types = [0u8; 24];
        let call = |granted: *mut u32, statuses: *mut u32| unsafe {
            access_check_by_type_result_list(
                core::ptr::null(),
                core::ptr::null(),
                0x58,
                1,
                types.as_ptr(),
                3,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                granted,
                statuses,
            )
        };
        clear();
        LIST.with(|list| *list.borrow_mut() = vec![0, STATUS_ACCESS_DENIED, 0xC000_0008]);
        GRANTED.with(|g| g.set(7));
        assert_eq!(call(granted.as_mut_ptr(), statuses.as_mut_ptr()), 1);
        assert_eq!((statuses, granted), ([0, 5, 6], [7, 7, 7]));
        assert_eq!(
            calls().last(),
            Some(&("NtAccessCheckByTypeResultList", 0x58, 1, 3))
        );
        clear();
        STATUS.with(|s| s.set(0xC000_0008));
        arm();
        assert_eq!(
            (
                call(granted.as_mut_ptr(), statuses.as_mut_ptr()),
                last_error(),
                statuses
            ),
            (0, 6, [0, 5, 6])
        );
    }

    /// The alarm wrappers run the plain check against the process's token (F2K's threads never
    /// impersonate), write pfGenerateOnClose FALSE, and map the statuses as AccessCheck does;
    /// the A form drops its narrow names the same way; the ByHandle form uses the client token
    /// it is given and opens nothing; a token that cannot be opened fails the wrapper.
    #[test]
    fn alarm_wrappers_run_the_plain_check_and_skip_the_alarm() {
        let mut granted = 0u32;
        let mut status = 0xF2F2;
        let mut generate = 0xF2F2;
        let subsystem = wide_z("File");
        let alarm_w = |granted: *mut u32, status: *mut u32, generate: *mut u32| unsafe {
            access_check_and_audit_alarm_w(
                subsystem.as_ptr(),
                core::ptr::null(),
                subsystem.as_ptr(),
                subsystem.as_ptr(),
                core::ptr::null(),
                1,
                core::ptr::null(),
                0,
                granted,
                status,
                generate,
            )
        };
        clear();
        REAL.with(|real| real.set(STATUS_ACCESS_DENIED));
        arm();
        assert_eq!(
            (
                alarm_w(&mut granted, &mut status, &mut generate),
                last_error(),
                status,
                generate
            ),
            (1, 5, 0, 0)
        );
        assert_eq!(calls().last(), Some(&("NtAccessCheck", TOKEN, 1, 0)));
        assert_eq!(
            TOKEN_CALLS.with(|calls| calls.borrow().clone()).last(),
            Some(&("NtOpenProcessToken", CURRENT_PROCESS, TOKEN_QUERY))
        );
        clear();
        REAL.with(|real| real.set(STATUS_ACCESS_DENIED));
        let subsystem_a = b"File\0";
        let ok = unsafe {
            access_check_and_audit_alarm_a(
                subsystem_a.as_ptr(),
                core::ptr::null(),
                subsystem_a.as_ptr(),
                subsystem_a.as_ptr(),
                core::ptr::null(),
                1,
                core::ptr::null(),
                0,
                &mut granted,
                &mut status,
                &mut generate,
            )
        };
        assert_eq!((ok, status, generate), (1, 0, 0));
        assert_eq!(calls().last(), Some(&("NtAccessCheck", TOKEN, 1, 0)));
        clear();
        TOKEN_STATUS.with(|s| s.set(0xC000_0008));
        arm();
        assert_eq!(
            (
                alarm_w(&mut granted, &mut status, &mut generate),
                last_error()
            ),
            (0, 6)
        );
        assert!(calls().is_empty());
        clear();
        let types = [0u8; 24];
        let ok = unsafe {
            access_check_by_type_and_audit_alarm_w(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                1,
                0,
                0,
                types.as_ptr(),
                2,
                core::ptr::null(),
                0,
                &mut granted,
                &mut status,
                &mut generate,
            )
        };
        assert_eq!((ok, status, generate), (1, 1, 0));
        assert_eq!(calls().last(), Some(&("NtAccessCheckByType", TOKEN, 1, 2)));
        clear();
        let mut granted_list = [0u32; 2];
        let mut status_list = [0u32; 2];
        LIST.with(|list| *list.borrow_mut() = vec![0, STATUS_ACCESS_DENIED]);
        let ok = unsafe {
            access_check_by_type_result_list_and_audit_alarm_by_handle_w(
                core::ptr::null(),
                core::ptr::null(),
                0x1234,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                1,
                0,
                0,
                types.as_ptr(),
                2,
                core::ptr::null(),
                0,
                granted_list.as_mut_ptr(),
                status_list.as_mut_ptr(),
                &mut generate,
            )
        };
        assert_eq!((ok, status_list, generate), (1, [0, 5], 0));
        assert_eq!(
            calls().last(),
            Some(&("NtAccessCheckByTypeResultList", 0x1234, 1, 2))
        );
        assert!(TOKEN_CALLS.with(|calls| calls.borrow().is_empty()));
    }

    /// PrivilegeCheck writes the result whatever the status and maps the service's: TRUE with
    /// the last error untouched on success, FALSE with the status's error on failure (the
    /// result written all the same).
    #[test]
    fn privilege_check_writes_the_result_and_maps_the_status() {
        let required = [0u8; 20];
        let call = |result: *mut u32| unsafe {
            privilege_check(TOKEN, required.as_ptr() as *mut u8, result)
        };
        clear();
        RESULT.with(|result| result.set(1));
        let mut result = 0xF2F2;
        arm();
        assert_eq!((call(&mut result), last_error(), result), (1, 0xF2F2, 1));
        assert_eq!(calls().last(), Some(&("NtPrivilegeCheck", TOKEN, 0, 0)));
        clear();
        RESULT.with(|result| result.set(0));
        assert_eq!((call(&mut result), result), (1, 0));
        clear();
        STATUS.with(|status| status.set(0xC000_0008));
        RESULT.with(|result| result.set(1));
        arm();
        assert_eq!((call(&mut result), last_error(), result), (0, 6, 1));
        clear();
    }

    /// LookupPrivilegeName answers as the capture shows: the size query (a count too small)
    /// fails ERROR_INSUFFICIENT_BUFFER with the count set to the needed chars including the
    /// terminator; the exact size succeeds with the name, the count the chars without it and
    /// ERROR_IO_PENDING as the last error; one short fails the same way; an unknown LUID (or a
    /// nonzero high part) is ERROR_NO_SUCH_PRIVILEGE with the count untouched; a system other
    /// than the local computer's is RPC_S_SERVER_UNAVAILABLE. The A form converts.
    #[test]
    fn name_lookups_answer_as_the_capture() {
        clear();
        let luid = Luid {
            low_part: 19,
            high_part: 0,
        };
        let mut buffer = [0xCCu16; 32];
        let name_w = |luid: *const Luid, buffer: *mut u16, cch: *mut u32| unsafe {
            lookup_privilege_name_w(core::ptr::null(), luid, buffer, cch)
        };
        let mut cch = 0u32;
        arm();
        assert_eq!(
            (
                name_w(&luid, buffer.as_mut_ptr(), &mut cch),
                last_error(),
                cch
            ),
            (0, 122, 20),
            "the size query"
        );
        let mut cch = 20u32;
        arm();
        assert_eq!(
            (
                name_w(&luid, buffer.as_mut_ptr(), &mut cch),
                last_error(),
                cch
            ),
            (1, 997, 19)
        );
        assert_eq!(&buffer[..20], wide_z("SeShutdownPrivilege").as_slice());
        let mut cch = 19u32;
        arm();
        assert_eq!(
            (
                name_w(&luid, buffer.as_mut_ptr(), &mut cch),
                last_error(),
                cch
            ),
            (0, 122, 20),
            "one short"
        );
        let unknown = Luid {
            low_part: 65536,
            high_part: 0,
        };
        let mut cch = 128u32;
        arm();
        assert_eq!(
            (
                name_w(&unknown, buffer.as_mut_ptr(), &mut cch),
                last_error(),
                cch
            ),
            (0, 1313, 128),
            "an unknown LUID"
        );
        let high = Luid {
            low_part: 19,
            high_part: 1,
        };
        assert_eq!(
            (name_w(&high, buffer.as_mut_ptr(), &mut cch), last_error()),
            (0, 1313),
            "a nonzero high part"
        );
        let remote = wide_z("\\\\ELSEWHERE");
        let ok = unsafe {
            lookup_privilege_name_w(remote.as_ptr(), &luid, buffer.as_mut_ptr(), &mut cch)
        };
        assert_eq!((ok, last_error()), (0, 1722), "a remote system");
        let mut ansi = [0xCCu8; 32];
        let mut cch = 20u32;
        arm();
        let ok = unsafe {
            lookup_privilege_name_a(b"qemu\0".as_ptr(), &luid, ansi.as_mut_ptr(), &mut cch)
        };
        assert_eq!((ok, last_error(), cch), (1, 997, 19));
        assert_eq!(&ansi[..20], b"SeShutdownPrivilege\0");
        let mut cch = 0u32;
        let ok = unsafe {
            lookup_privilege_name_a(core::ptr::null(), &luid, ansi.as_mut_ptr(), &mut cch)
        };
        assert_eq!((ok, last_error(), cch), (0, 122, 20), "the A size query");
    }

    /// IsTokenRestricted queries TokenRestrictedSids for its size then the list: a nonempty
    /// count answers TRUE (1), an empty one FALSE (0), the last error untouched; a first query
    /// that is not STATUS_BUFFER_TOO_SMALL fails with its error.
    #[test]
    fn is_token_restricted_reads_the_restricted_sids() {
        clear();
        let groups = |count: u32| {
            let mut bytes = count.to_le_bytes().to_vec();
            bytes.resize(bytes.len() + 8 * count as usize, 0);
            bytes
        };
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Ok(groups(2)));
        arm();
        assert_eq!(
            (unsafe { is_token_restricted(TOKEN) }, last_error()),
            (1, 0xF2F2)
        );
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Ok(groups(0)));
        arm();
        assert_eq!(
            (unsafe { is_token_restricted(TOKEN) }, last_error()),
            (0, 0xF2F2)
        );
        assert_eq!(
            calls().last(),
            Some(&("NtQueryInformationToken", TOKEN, 11, 0))
        );
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0008));
        arm();
        assert_eq!(
            (unsafe { is_token_restricted(TOKEN) }, last_error()),
            (0, 6)
        );
        clear();
    }
}
