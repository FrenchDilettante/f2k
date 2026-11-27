//! The process token's calls, as a program that shuts the machine down makes them first, and as
//! programs inspect their token: OpenProcessToken, OpenThreadToken, LookupPrivilegeValueW and
//! LookupPrivilegeValueA, LookupPrivilegeNameA/W, LookupPrivilegeDisplayNameA/W,
//! AdjustTokenPrivileges, AdjustTokenGroups, GetTokenInformation, SetTokenInformation,
//! DuplicateToken, DuplicateTokenEx, PrivilegeCheck, IsTokenRestricted and
//! CreateRestrictedToken. The token calls are advapi32's own code over ntdll's token services
//! (NtOpenProcessToken, NtOpenThreadToken, NtAdjustPrivilegesToken, NtAdjustGroupsToken,
//! NtQueryInformationToken, NtSetInformationToken, NtDuplicateToken, NtPrivilegeCheck,
//! NtFilterToken — the [`crate::accesscheck::services`] seam), as on Windows 2000; the lookups
//! answer from the privileges' public names and LUIDs (winnt.h's SE_*_NAME and
//! SE_*_PRIVILEGE), where Windows 2000's asks the local security authority, which F2K does not
//! have.
//!
//! F2K checks no privilege anywhere: the token keeps the privileges' state as bookkeeping, so that
//! these calls answer as Windows 2000's do (see the kernel's `se`).

use rtl::cstr;
use rtl::nt::Luid;
use rtl::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER};
// ERROR_IO_PENDING: the last error a successful lookup leaves (see
// [`lookup_privilege_value`]). ERROR_NOACCESS: a LUID the lookup cannot write.
// ERROR_NO_SUCH_PRIVILEGE: a name no privilege has.
use rtl::winerror::{ERROR_IO_PENDING, ERROR_NOACCESS, ERROR_NO_SUCH_PRIVILEGE};

use crate::accesscheck::{services, ObjectAttributes};
use crate::imports::{self as nt, Counted, HeapBlock, Passed};
use crate::{caller_bytes, caller_bytes_mut, Out};
/// RPC_S_SERVER_UNAVAILABLE: a system name other than the local computer's (there is no remote
/// security authority to ask).
pub(crate) const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
/// The rights DuplicateToken's copy is opened with (TOKEN_IMPERSONATE | TOKEN_QUERY), and its
/// type (TokenImpersonation).
const DUPLICATE_ACCESS: u32 = 0x0004 | 0x0008;
const TOKEN_IMPERSONATION: u32 = 2;

/// The privileges' public names and LUIDs, Windows 2000's (winnt.h's SE_*_NAME and
/// SE_*_PRIVILEGE: the same on every machine). LUID 6 is SeMachineAccountPrivilege, the name the
/// security authority knows it by.
pub const PRIVILEGES: [(&str, u32); 26] = [
    ("SeCreateTokenPrivilege", 2),
    ("SeAssignPrimaryTokenPrivilege", 3),
    ("SeLockMemoryPrivilege", 4),
    ("SeIncreaseQuotaPrivilege", 5),
    ("SeMachineAccountPrivilege", 6),
    ("SeTcbPrivilege", 7),
    ("SeSecurityPrivilege", 8),
    ("SeTakeOwnershipPrivilege", 9),
    ("SeLoadDriverPrivilege", 10),
    ("SeSystemProfilePrivilege", 11),
    ("SeSystemtimePrivilege", 12),
    ("SeProfileSingleProcessPrivilege", 13),
    ("SeIncreaseBasePriorityPrivilege", 14),
    ("SeCreatePagefilePrivilege", 15),
    ("SeCreatePermanentPrivilege", 16),
    ("SeBackupPrivilege", 17),
    ("SeRestorePrivilege", 18),
    ("SeShutdownPrivilege", 19),
    ("SeDebugPrivilege", 20),
    ("SeAuditPrivilege", 21),
    ("SeSystemEnvironmentPrivilege", 22),
    ("SeChangeNotifyPrivilege", 23),
    ("SeRemoteShutdownPrivilege", 24),
    ("SeUndockPrivilege", 25),
    ("SeSyncAgentPrivilege", 26),
    ("SeEnableDelegationPrivilege", 27),
];

/// Whether `units` spell `text` (ASCII), case-insensitively.
fn same_name(units: &[u16], text: &str) -> bool {
    units.len() == text.len()
        && units.iter().zip(text.bytes()).all(|(&unit, byte)| {
            u8::try_from(unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(&byte))
        })
}

/// The LUID of the privilege named `name`, case-insensitively; none for a name no privilege has.
pub fn privilege_luid(name: &[u16]) -> Option<u32> {
    PRIVILEGES
        .iter()
        .find(|(known, _)| same_name(name, known))
        .map(|&(_, luid)| luid)
}

/// Whether `system` names the local computer: no name, or the computer's own, with or without
/// the leading `\\` of a UNC name (case-insensitively).
pub(crate) fn is_local(system: &[u16]) -> bool {
    let system = system
        .strip_prefix(&[u16::from(b'\\'), u16::from(b'\\')][..])
        .unwrap_or(system);
    if system.is_empty() {
        return true;
    }
    let mut local = [0u16; 32];
    nt::computer_name(&mut local).is_some_and(|length| {
        let local = &local[..length];
        system.len() == local.len()
            && system.iter().zip(local).all(|(&a, &b)| {
                let fold = |unit: u16| match u8::try_from(unit) {
                    Ok(byte) => u16::from(byte.to_ascii_uppercase()),
                    Err(_) => unit,
                };
                fold(a) == fold(b)
            })
    })
}

/// LookupPrivilegeValueW's work, its answer the error it fails with. A LUID the call cannot write
/// is ERROR_NOACCESS; a system name other than the local computer's is RPC_S_SERVER_UNAVAILABLE,
/// the LUID untouched; a name no privilege has (or none) is ERROR_NO_SUCH_PRIVILEGE, the LUID
/// zeroed (the capture's). A found privilege's LUID is written, and the last error is
/// ERROR_IO_PENDING: Windows 2000's lookup asks the local security authority over local RPC,
/// which leaves it there, and the capture shows it after every successful lookup.
fn lookup_privilege_value(
    system: Option<&[u16]>,
    name: Option<&[u16]>,
    luid: Option<&mut Out<'_, Luid>>,
) -> Result<(), u32> {
    let luid = luid.ok_or(ERROR_NOACCESS)?;
    if !system.is_none_or(is_local) {
        return Err(RPC_S_SERVER_UNAVAILABLE);
    }
    let found = name.and_then(privilege_luid);
    luid.set(Luid {
        low_part: found.unwrap_or(0),
        high_part: 0,
    });
    found.ok_or(ERROR_NO_SUCH_PRIVILEGE)?;
    nt::set_last_error(ERROR_IO_PENDING);
    Ok(())
}

/// A lookup's answer as a BOOL: TRUE, or FALSE with the error as the last error.
pub(crate) fn bool_of(result: Result<(), u32>) -> u32 {
    match result {
        Ok(()) => 1,
        Err(error) => {
            nt::set_last_error(error);
            0
        }
    }
}

/// The caller's NUL-terminated string at `text`, its terminator left out: none for null.
///
/// # Safety
///
/// `text` is null or a NUL-terminated string the call may read.
pub(crate) unsafe fn optional_wide<'a>(text: *const u16) -> Option<&'a [u16]> {
    // SAFETY: the caller's contract, for the non-null string.
    (!text.is_null()).then(|| unsafe { cstr::units_until_nul(text) })
}

/// The caller's NUL-terminated ANSI string at `text`, its terminator left out: none for null.
///
/// # Safety
///
/// `text` is null or a NUL-terminated string the call may read.
pub(crate) unsafe fn optional_ansi<'a>(text: *const u8) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract, for the non-null string.
    (!text.is_null()).then(|| unsafe { cstr::bytes_until_nul(text) })
}

/// LookupPrivilegeValueW (see [`lookup_privilege_value`]).
///
/// # Safety
///
/// `system` and `name` are null or NUL-terminated strings; `luid` is null or a LUID the call may
/// write.
#[unsafe(export_name = "f2k_export_LookupPrivilegeValueW")]
pub unsafe extern "system" fn lookup_privilege_value_w(
    system: *const u16,
    name: *const u16,
    luid: *mut Luid,
) -> u32 {
    // SAFETY: the caller's strings and out parameter.
    let (system, name, mut luid) = unsafe {
        (
            optional_wide(system),
            optional_wide(name),
            Out::optional(luid),
        )
    };
    bool_of(lookup_privilege_value(system, name, luid.as_mut()))
}

/// LookupPrivilegeValueA: LookupPrivilegeValueW of the names converted.
///
/// # Safety
///
/// As LookupPrivilegeValueW's, for ANSI strings.
#[unsafe(export_name = "f2k_export_LookupPrivilegeValueA")]
pub unsafe extern "system" fn lookup_privilege_value_a(
    system: *const u8,
    name: *const u8,
    luid: *mut Luid,
) -> u32 {
    // SAFETY: the caller's strings and out parameter.
    let (system, name, mut luid) = unsafe {
        (
            optional_ansi(system),
            optional_ansi(name),
            Out::optional(luid),
        )
    };
    let converted = |text: Option<&[u8]>| text.map(nt::ansi_to_unicode).transpose();
    let (system, name) = match (converted(system), converted(name)) {
        (Ok(system), Ok(name)) => (system, name),
        (Err(status), _) | (_, Err(status)) => return bool_of(Err(nt::dos_error(status))),
    };
    let system = system.as_ref().map(|text| text.counted());
    let name = name.as_ref().map(|text| text.counted());
    bool_of(lookup_privilege_value(
        system.as_ref().map(Counted::units),
        name.as_ref().map(Counted::units),
        luid.as_mut(),
    ))
}

/// A failed service's status as the last error (BaseSetLastNTError); FALSE.
pub(crate) fn failed(status: NtStatus) -> u32 {
    nt::set_last_error(nt::dos_error(status));
    0
}

/// OpenProcessToken: a handle to the process's token, granted `access`, into the caller's
/// `token`. The last error is untouched on success.
///
/// # Safety
///
/// `token` is the caller's place for the handle (the service probes it).
#[unsafe(export_name = "f2k_export_OpenProcessToken")]
pub unsafe extern "system" fn open_process_token(
    process: u32,
    access: u32,
    token: *mut u32,
) -> u32 {
    // SAFETY: the caller's place, handed to the service.
    let token = unsafe { Passed::new(token as usize) };
    match nt::open_process_token(process, access, token) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// AdjustTokenPrivileges: NtAdjustPrivilegesToken, its status as the last error whatever it is
/// (ERROR_SUCCESS; ERROR_NOT_ALL_ASSIGNED, a success all the same; or the failure's error), and
/// TRUE for a success. The privileges are bookkeeping only: nothing in F2K checks them.
///
/// # Safety
///
/// `new_state`, `previous_state` and `return_length` are the caller's (the service probes them).
#[unsafe(export_name = "f2k_export_AdjustTokenPrivileges")]
pub unsafe extern "system" fn adjust_token_privileges(
    token: u32,
    disable_all: u32,
    new_state: *const u8,
    length: u32,
    previous_state: *mut u8,
    return_length: *mut u32,
) -> u32 {
    // SAFETY: the caller's memory, handed to the service.
    let (new_state, previous_state, return_length) = unsafe {
        (
            Passed::new(new_state as usize),
            Passed::new(previous_state as usize),
            Passed::new(return_length as usize),
        )
    };
    let status = nt::adjust_privileges_token(
        token,
        disable_all != 0,
        new_state,
        length,
        previous_state,
        return_length,
    );
    nt::set_last_error(nt::dos_error(status));
    u32::from(status.is_success())
}

/// GetTokenInformation: NtQueryInformationToken, whatever the class; a failure's status as the
/// last error (STATUS_BUFFER_TOO_SMALL's ERROR_INSUFFICIENT_BUFFER with the size the answer takes
/// in ReturnLength), which is untouched on success.
///
/// # Safety
///
/// `information` and `return_length` are the caller's (the service probes them).
#[unsafe(export_name = "f2k_export_GetTokenInformation")]
pub unsafe extern "system" fn get_token_information(
    token: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    // SAFETY: the caller's memory, handed to the service.
    let (information, return_length) = unsafe {
        (
            Passed::new(information as usize),
            Passed::new(return_length as usize),
        )
    };
    match nt::query_information_token(token, class, information, length, return_length) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// DuplicateToken: DuplicateTokenEx's impersonation copy of `token` (opened with
/// TOKEN_DUPLICATE) at `level`, its handle granted TOKEN_IMPERSONATE and TOKEN_QUERY:
/// NtDuplicateToken with the level in the attributes' SECURITY_QUALITY_OF_SERVICE (static tracking,
/// not effective only). A failure's status as the last error, which is untouched on success.
///
/// # Safety
///
/// `duplicate` is the caller's place for the handle (the service probes it).
#[unsafe(export_name = "f2k_export_DuplicateToken")]
pub unsafe extern "system" fn duplicate_token(token: u32, level: u32, duplicate: *mut u32) -> u32 {
    // SAFETY: the caller's place, handed to the service.
    let duplicate = unsafe { Passed::new(duplicate as usize) };
    match nt::duplicate_token(
        token,
        DUPLICATE_ACCESS,
        level,
        TOKEN_IMPERSONATION,
        duplicate,
    ) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// SECURITY_DYNAMIC_TRACKING (a quality of service's context tracking).
const SECURITY_DYNAMIC_TRACKING: u8 = 1;
/// SECURITY_QUALITY_OF_SERVICE as the token services read it (the layout is public).
#[repr(C)]
struct QualityOfService {
    length: u32,
    level: u32,
    tracking: u8,
    effective_only: u8,
}

/// DuplicateTokenEx: NtDuplicateToken with the caller's desired access and type, the attributes
/// from `lpTokenAttributes` (its security descriptor, OBJ_INHERIT when it inherits handles) and
/// a quality of service carrying the impersonation level (dynamic tracking, not effective only).
/// A failure's status is the last error; the last error is untouched on success.
///
/// # Safety
///
/// `attributes` is null or the caller's SECURITY_ATTRIBUTES; `new_token` its place for the
/// handle (the service probes it).
#[unsafe(export_name = "f2k_export_DuplicateTokenEx")]
pub unsafe extern "system" fn duplicate_token_ex(
    token: u32,
    access: u32,
    attributes: *const u8,
    level: u32,
    kind: u32,
    new_token: *mut u32,
) -> u32 {
    // LPSECURITY_ATTRIBUTES: its length, its security descriptor and its inherit-handle flag.
    // SAFETY: the caller's attributes, when it gave them.
    let (descriptor, inherit) = if attributes.is_null() {
        (core::ptr::null(), false)
    } else {
        match unsafe { caller_bytes(attributes, 12) } {
            Some(bytes) => (
                u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as *const u8,
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 0,
            ),
            None => {
                nt::set_last_error(ERROR_NOACCESS);
                return 0;
            }
        }
    };
    let quality = QualityOfService {
        length: 12,
        level,
        tracking: SECURITY_DYNAMIC_TRACKING,
        effective_only: 0,
    };
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: core::ptr::null(),
        attributes: if inherit { rtl::nt::OBJ_INHERIT } else { 0 },
        security_descriptor: descriptor,
        security_quality_of_service: (&quality as *const QualityOfService).cast(),
    };
    match services::duplicate_token(token, access, &attributes, kind, new_token) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// A count-headered copy of the caller's `count` 8-byte entries (SID_AND_ATTRIBUTES or
/// LUID_AND_ATTRIBUTES) on the process heap: none for a zero count, STATUS_INVALID_PARAMETER
/// for a count with no array or no room.
fn counted_copy(count: u32, entries: *const u8) -> Result<Option<HeapBlock>, NtStatus> {
    if count == 0 {
        return Ok(None);
    }
    if entries.is_null() {
        return Err(NtStatus(STATUS_INVALID_PARAMETER));
    }
    // SAFETY: the caller's array of `count` entries.
    let bytes = unsafe { caller_bytes(entries, 8 * count as usize) }
        .ok_or(NtStatus(STATUS_INVALID_PARAMETER))?;
    let mut block =
        HeapBlock::new(4 + 8 * count as usize).ok_or(NtStatus(STATUS_INSUFFICIENT_RESOURCES))?;
    let all = block.bytes_mut();
    all[..4].copy_from_slice(&count.to_le_bytes());
    all[4..].copy_from_slice(bytes);
    Ok(Some(block))
}

/// CreateRestrictedToken's work: the caller's SID and privilege arrays copied under their counts
/// (a count with no array is STATUS_INVALID_PARAMETER), then NtFilterToken.
#[allow(clippy::too_many_arguments)]
fn filtered(
    token: u32,
    flags: u32,
    disable_sid_count: u32,
    sids_to_disable: *const u8,
    delete_privilege_count: u32,
    privileges_to_delete: *const u8,
    restricted_sid_count: u32,
    sids_to_restrict: *const u8,
    new_token: *mut u32,
) -> Result<(), NtStatus> {
    let disabled = counted_copy(disable_sid_count, sids_to_disable)?;
    let deleted = counted_copy(delete_privilege_count, privileges_to_delete)?;
    let restricted = counted_copy(restricted_sid_count, sids_to_restrict)?;
    let at = |block: &Option<HeapBlock>| {
        block.as_ref().map_or(core::ptr::null(), |block| block.bytes().as_ptr())
    };
    services::filter_token(token, flags, at(&disabled), at(&deleted), at(&restricted), new_token)
}

/// CreateRestrictedToken: NtFilterToken over the token, with the SIDs to disable, the privileges
/// to delete and the SIDs to restrict (each a count and an array; a count with no array is
/// ERROR_INVALID_PARAMETER). A failure's status is the last error.
///
/// # Safety
///
/// The arrays are the caller's (each `count` 8-byte entries); `new_token` its place for the
/// handle (the service probes it).
#[unsafe(export_name = "f2k_export_CreateRestrictedToken")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn create_restricted_token(
    token: u32,
    flags: u32,
    disable_sid_count: u32,
    sids_to_disable: *const u8,
    delete_privilege_count: u32,
    privileges_to_delete: *const u8,
    restricted_sid_count: u32,
    sids_to_restrict: *const u8,
    new_token: *mut u32,
) -> u32 {
    match filtered(token, flags, disable_sid_count, sids_to_disable, delete_privilege_count, privileges_to_delete, restricted_sid_count, sids_to_restrict, new_token) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// AdjustTokenGroups: NtAdjustGroupsToken, its status as the last error whatever it is
/// (ERROR_SUCCESS, ERROR_NOT_ALL_ASSIGNED a success all the same, or the failure's error), and
/// TRUE for a success — as AdjustTokenPrivileges.
///
/// # Safety
///
/// `new_state`, `previous_state` and `return_length` are the caller's (the service probes them).
#[unsafe(export_name = "f2k_export_AdjustTokenGroups")]
pub unsafe extern "system" fn adjust_token_groups(
    token: u32,
    reset_to_default: u32,
    new_state: *const u8,
    length: u32,
    previous_state: *mut u8,
    return_length: *mut u32,
) -> u32 {
    let status = services::adjust_groups_token(token, reset_to_default != 0, new_state, length, previous_state, return_length);
    nt::set_last_error(nt::dos_error(status));
    u32::from(status.is_success())
}

/// SetTokenInformation: NtSetInformationToken, whatever the class; a failure's status as the
/// last error, which is untouched on success.
///
/// # Safety
///
/// `information` is the caller's (the service probes it).
#[unsafe(export_name = "f2k_export_SetTokenInformation")]
pub unsafe extern "system" fn set_token_information(
    token: u32,
    class: u32,
    information: *const u8,
    length: u32,
) -> u32 {
    match services::set_information_token(token, class, information, length) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// OpenThreadToken: NtOpenThreadToken, a handle to the thread's token granted `access`; a
/// failure's status (STATUS_NO_TOKEN: ERROR_NO_TOKEN when the thread has none) as the last
/// error, which is untouched on success.
///
/// # Safety
///
/// `token` is the caller's place for the handle (the service probes it).
#[unsafe(export_name = "f2k_export_OpenThreadToken")]
pub unsafe extern "system" fn open_thread_token(
    thread: u32,
    access: u32,
    open_as_self: u32,
    token: *mut u32,
) -> u32 {
    match services::open_thread_token(thread, access, open_as_self != 0, token) {
        Ok(()) => 1,
        Err(status) => failed(status),
    }
}

/// The display language F2K answers (LANG_ENGLISH with SUBLANG_DEFAULT): F2K has no local
/// security authority's resource strings, so a privilege's display name is its public name.
const LANG_ENGLISH_US: u32 = 0x0409;

/// The privilege a LUID names: its public name, for a zero high part and a known low one.
pub fn privilege_name(luid: &Luid) -> Option<&'static str> {
    if luid.high_part != 0 {
        return None;
    }
    PRIVILEGES
        .iter()
        .find(|&(_, low)| *low == luid.low_part)
        .map(|&(name, _)| name)
}

/// A found privilege's name delivered into the caller's buffer of `*cch` units (wide) or bytes
/// (ANSI), terminator included: too small a room fails ERROR_INSUFFICIENT_BUFFER with `*cch` the
/// needed count including the terminator; a fitting room gets the name, `*cch` the count without
/// it, and ERROR_IO_PENDING as the last error (a successful lookup's leftover).
pub(crate) fn deliver_name(name: &str, wide: bool, buffer: *mut u8, cch: &mut Out<'_, u32>) -> Result<(), u32> {
    let needed = name.len() + 1;
    if needed > cch.get() as usize {
        cch.set(needed as u32);
        return Err(nt::dos_error(NtStatus(STATUS_BUFFER_TOO_SMALL)));
    }
    let bytes = needed * if wide { 2 } else { 1 };
    // SAFETY: the caller's buffer of `*cch` units (wide) or bytes, which the needed count fits.
    let Some(slice) = (unsafe { caller_bytes_mut(buffer, bytes) }) else {
        return Err(ERROR_NOACCESS);
    };
    if wide {
        for (at, byte) in name.bytes().enumerate() {
            slice[2 * at..2 * at + 2].copy_from_slice(&u16::from(byte).to_le_bytes());
        }
        slice[2 * name.len()..2 * name.len() + 2].copy_from_slice(&0u16.to_le_bytes());
    } else {
        slice[..name.len()].copy_from_slice(name.as_bytes());
        slice[name.len()] = 0;
    }
    cch.set(name.len() as u32);
    nt::set_last_error(ERROR_IO_PENDING);
    Ok(())
}

/// LookupPrivilegeName's answer: the privilege's name for `luid`, or the error (a non-local
/// system RPC_S_SERVER_UNAVAILABLE, no LUID ERROR_NOACCESS, an unknown LUID
/// ERROR_NO_SUCH_PRIVILEGE; the count untouched on every failure).
pub(crate) fn name_for_luid(system: Option<&[u16]>, luid: Option<Luid>) -> Result<&'static str, u32> {
    if !system.is_none_or(is_local) {
        return Err(RPC_S_SERVER_UNAVAILABLE);
    }
    let luid = luid.ok_or(ERROR_NOACCESS)?;
    privilege_name(&luid).ok_or(ERROR_NO_SUCH_PRIVILEGE)
}

/// LookupPrivilegeDisplayName's answer: the privilege's display name for `name`, or the error
/// (as LookupPrivilegeName's); the language id is written whatever the answer.
pub(crate) fn display_name_for(
    system: Option<&[u16]>,
    name: Option<&[u16]>,
    language_id: Option<&mut Out<'_, u32>>,
) -> Result<&'static str, u32> {
    if let Some(language) = language_id {
        language.set(LANG_ENGLISH_US);
    }
    if !system.is_none_or(is_local) {
        return Err(RPC_S_SERVER_UNAVAILABLE);
    }
    let luid = name.and_then(privilege_luid).ok_or(ERROR_NO_SUCH_PRIVILEGE)?;
    privilege_name(&Luid { low_part: luid, high_part: 0 }).ok_or(ERROR_NO_SUCH_PRIVILEGE)
}

/// LookupPrivilegeDisplayNameW: the privilege's display name for the name, into the caller's
/// buffer of `*cch_display_name` units (see [`deliver_name`]), the language into `lp_language_id`.
///
/// # Safety
///
/// As LookupPrivilegeNameW's, plus the caller's display-name buffer and language id.
#[unsafe(export_name = "f2k_export_LookupPrivilegeDisplayNameW")]
pub unsafe extern "system" fn lookup_privilege_display_name_w(
    system: *const u16, name: *const u16, display_name: *mut u16, cch_display_name: *mut u32, lp_language_id: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, count and language id.
    let (system, name, mut cch, mut language) = unsafe {
        (
            optional_wide(system),
            optional_wide(name),
            Out::optional(cch_display_name),
            Out::optional(lp_language_id),
        )
    };
    let Some(cch) = cch.as_mut() else {
        nt::set_last_error(ERROR_NOACCESS);
        return 0;
    };
    match display_name_for(system, name, language.as_mut()).and_then(|text| deliver_name(text, true, display_name as *mut u8, cch)) {
        Ok(()) => 1,
        Err(error) => bool_of(Err(error)),
    }
}

/// LookupPrivilegeDisplayNameA: LookupPrivilegeDisplayNameW of the names converted.
///
/// # Safety
///
/// As LookupPrivilegeDisplayNameW's, for ANSI strings.
#[unsafe(export_name = "f2k_export_LookupPrivilegeDisplayNameA")]
pub unsafe extern "system" fn lookup_privilege_display_name_a(
    system: *const u8, name: *const u8, display_name: *mut u8, cch_display_name: *mut u32, lp_language_id: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, count and language id.
    let (system, name, mut cch, mut language) = unsafe {
        (
            optional_ansi(system),
            optional_ansi(name),
            Out::optional(cch_display_name),
            Out::optional(lp_language_id),
        )
    };
    let Some(cch) = cch.as_mut() else {
        nt::set_last_error(ERROR_NOACCESS);
        return 0;
    };
    let converted = |text: Option<&[u8]>| text.map(nt::ansi_to_unicode).transpose();
    let (system, name) = match (converted(system), converted(name)) {
        (Ok(system), Ok(name)) => (system, name),
        (Err(status), _) | (_, Err(status)) => return bool_of(Err(nt::dos_error(status))),
    };
    let system = system.as_ref().map(|wide| wide.counted());
    let name = name.as_ref().map(|wide| wide.counted());
    match display_name_for(
        system.as_ref().map(Counted::units),
        name.as_ref().map(Counted::units),
        language.as_mut(),
    )
    .and_then(|text| deliver_name(text, false, display_name, cch))
    {
        Ok(()) => 1,
        Err(error) => bool_of(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide_z;

    use super::*;
    use crate::imports::host::{LAST_ERROR, TOKEN, TOKEN_CALLS, TOKEN_STATUS};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// The table holds Windows 2000's privileges, LUIDs 2 to 27, each once.
    #[test]
    fn the_privilege_table_is_windows_2000s() {
        for (index, &(name, luid)) in PRIVILEGES.iter().enumerate() {
            assert_eq!(luid as usize, index + 2, "{name}");
            assert!(name.starts_with("Se") && name.ends_with("Privilege"));
        }
        let luid = |name: &str| privilege_luid(&name.encode_utf16().collect::<Vec<_>>());
        assert_eq!(luid("SeShutdownPrivilege"), Some(19));
        assert_eq!(luid("SeChangeNotifyPrivilege"), Some(23));
        assert_eq!(luid("SeDebugPrivilege"), Some(20));
        assert_eq!(luid("SeTcbPrivilege"), Some(7));
        assert_eq!(luid("seshutdownprivilege"), Some(19));
        assert_eq!(luid("SeNoSuchPrivilege"), None);
        assert_eq!(luid(""), None);
        assert_eq!(luid("SeShutdownPrivilegeX"), None);
    }

    /// A lookup's answers, as the token fixture's lookup block shows them: the LUID and
    /// ERROR_IO_PENDING; an unknown, empty or null name ERROR_NO_SUCH_PRIVILEGE with the LUID
    /// zeroed; a null LUID ERROR_NOACCESS; the local computer's name, bare or as UNC, as no name.
    #[test]
    fn lookups_answer_as_the_capture() {
        let mut luid = Luid {
            low_part: 0xF2F2,
            high_part: 0x2F2F,
        };
        let name = wide_z("SeShutdownPrivilege");
        arm();
        let ok = unsafe { lookup_privilege_value_w(core::ptr::null(), name.as_ptr(), &mut luid) };
        assert_eq!((ok, last_error()), (1, 997));
        assert_eq!((luid.low_part, luid.high_part), (19, 0));
        for system in ["", "QEMU", "qemu", "\\\\QEMU"] {
            luid.low_part = 0;
            let system = wide_z(system);
            let ok = unsafe { lookup_privilege_value_w(system.as_ptr(), name.as_ptr(), &mut luid) };
            assert_eq!((ok, luid.low_part), (1, 19));
        }
        let remote = wide_z("\\\\ELSEWHERE");
        luid.low_part = 0xF2F2;
        let ok = unsafe { lookup_privilege_value_w(remote.as_ptr(), name.as_ptr(), &mut luid) };
        assert_eq!((ok, last_error(), luid.low_part), (0, 1722, 0xF2F2));
        for unknown in ["SeNoSuchPrivilege", ""] {
            luid.low_part = 0xF2F2;
            let unknown = wide_z(unknown);
            let ok =
                unsafe { lookup_privilege_value_w(core::ptr::null(), unknown.as_ptr(), &mut luid) };
            assert_eq!((ok, last_error(), luid.low_part), (0, 1313, 0));
        }
        luid.low_part = 0xF2F2;
        let ok =
            unsafe { lookup_privilege_value_w(core::ptr::null(), core::ptr::null(), &mut luid) };
        assert_eq!((ok, last_error(), luid.low_part), (0, 1313, 0));
        let ok = unsafe {
            lookup_privilege_value_w(core::ptr::null(), name.as_ptr(), core::ptr::null_mut())
        };
        assert_eq!((ok, last_error()), (0, 998));
        luid.low_part = 0;
        let ok = unsafe {
            lookup_privilege_value_a(
                b"qemu\0".as_ptr(),
                b"sechangenotifyprivilege\0".as_ptr(),
                &mut luid,
            )
        };
        assert_eq!((ok, last_error(), luid.low_part), (1, 997, 23));
        let ok = unsafe { lookup_privilege_value_a(core::ptr::null(), b"\0".as_ptr(), &mut luid) };
        assert_eq!((ok, last_error(), luid.low_part), (0, 1313, 0));
    }

    /// AdjustTokenPrivileges sets the last error from the status whatever it is: 0 for success,
    /// ERROR_NOT_ALL_ASSIGNED for the partial assignment (TRUE all the same), the failure's error
    /// with FALSE (STATUS_BUFFER_TOO_SMALL: ERROR_INSUFFICIENT_BUFFER).
    #[test]
    fn adjust_reports_its_status_as_the_last_error() {
        let call = || unsafe {
            adjust_token_privileges(
                TOKEN,
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        for (status, answer, error) in [
            (0, 1, 0),
            (0x0000_0106, 1, 1300),
            (0xC000_0023, 0, 122),
            (0xC000_0008, 0, 6),
        ] {
            TOKEN_STATUS.with(|next| next.set(status));
            arm();
            assert_eq!((call(), last_error()), (answer, error), "{status:#x}");
        }
        TOKEN_STATUS.with(|next| next.set(0));
    }

    /// OpenProcessToken leaves the last error on success and maps a failure's status;
    /// GetTokenInformation asks the service for every class, a failure's status the last error.
    #[test]
    fn open_and_query_go_to_the_services() {
        let mut token = 0;
        arm();
        assert_eq!(
            unsafe { open_process_token(0xFFFF_FFFF, 0x28, &mut token) },
            1
        );
        assert_eq!((token, last_error()), (TOKEN, 0xF2F2));
        TOKEN_STATUS.with(|next| next.set(0xC000_0024));
        assert_eq!(unsafe { open_process_token(0xFFFF_FFFE, 8, &mut token) }, 0);
        assert_eq!(last_error(), 6);
        TOKEN_STATUS.with(|next| next.set(0));
        arm();
        let mut length = 0;
        let ok = unsafe { get_token_information(TOKEN, 3, core::ptr::null_mut(), 0, &mut length) };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        let calls = TOKEN_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(
            calls.last(),
            Some(&("NtQueryInformationToken", TOKEN, 3)),
            "{calls:?}"
        );
        for (class, status, error) in [
            (1, 0xC000_0023, 122),
            (12, 0xC000_0004, 24),
            (99, 0xC000_0003, 87),
        ] {
            TOKEN_STATUS.with(|next| next.set(status));
            arm();
            let ok = unsafe {
                get_token_information(TOKEN, class, core::ptr::null_mut(), 0, &mut length)
            };
            assert_eq!((ok, last_error()), (0, error), "{class}");
        }
        TOKEN_STATUS.with(|next| next.set(0));
    }

    /// DuplicateToken asks NtDuplicateToken for an impersonation copy at the level given, opened
    /// for TOKEN_IMPERSONATE and TOKEN_QUERY.
    #[test]
    fn duplicate_asks_for_an_impersonation_copy() {
        let mut copy = 0;
        arm();
        assert_eq!(unsafe { duplicate_token(TOKEN, 2, &mut copy) }, 1);
        assert_eq!((copy, last_error()), (TOKEN + 4, 0xF2F2));
        let calls = TOKEN_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(
            calls.last(),
            Some(&("NtDuplicateToken", TOKEN, 0xC)),
            "{calls:?}"
        );
        TOKEN_STATUS.with(|next| next.set(0xC000_0022));
        assert_eq!(unsafe { duplicate_token(TOKEN, 1, &mut copy) }, 0);
        assert_eq!(last_error(), 5);
        TOKEN_STATUS.with(|next| next.set(0));
    }

    use crate::accesscheck::host::{
        CALLS, DUP, FILTER_COUNTS, HANDLE, RESULT, STATUS, TOKEN_REPLY,
    };

    fn service_calls() -> Vec<(&'static str, u32, u32, u32)> {
        CALLS.with(|calls| calls.borrow().clone())
    }

    fn clear_services() {
        CALLS.with(|calls| calls.borrow_mut().clear());
        for cell in [&STATUS, &RESULT, &HANDLE] {
            cell.set(0);
        }
        HANDLE.with(|handle| handle.set(0x60));
        DUP.with(|dup| dup.set((0, 0, 0)));
        FILTER_COUNTS.with(|counts| counts.borrow_mut().clear());
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_000F));
    }

    /// DuplicateTokenEx hands NtDuplicateToken the access and type given, the attributes built
    /// from lpTokenAttributes (its security descriptor, OBJ_INHERIT when inheriting) and the
    /// quality of service's level; a failure's status is the last error.
    #[test]
    fn duplicate_token_ex_builds_the_attributes() {
        clear_services();
        let mut copy = 0;
        arm();
        let ok = unsafe { duplicate_token_ex(TOKEN, 0x0C, core::ptr::null(), 2, 2, &mut copy) };
        assert_eq!((ok, copy, last_error()), (1, 0x60, 0xF2F2));
        assert_eq!(service_calls().last(), Some(&("NtDuplicateToken", TOKEN, 0x0C, 2)));
        assert_eq!(DUP.with(|dup| dup.get()), (0, 0, 2), "no attributes: no descriptor, no inherit, the level");
        let attributes = [12u32, 0x1000, 1];
        let ok = unsafe { duplicate_token_ex(TOKEN, 8, attributes.as_ptr() as *const u8, 3, 1, &mut copy) };
        assert_eq!(ok, 1);
        assert_eq!(DUP.with(|dup| dup.get()), (0x1000, rtl::nt::OBJ_INHERIT, 3));
        clear_services();
        STATUS.with(|status| status.set(0xC000_0022));
        arm();
        assert_eq!((unsafe { duplicate_token_ex(TOKEN, 8, core::ptr::null(), 2, 2, &mut copy) }, last_error()), (0, 5));
        clear_services();
    }

    /// CreateRestrictedToken copies each count's array under its count header for NtFilterToken
    /// (a count with no array is ERROR_INVALID_PARAMETER and no call is made); the new handle
    /// comes out, a failure's status is the last error.
    #[test]
    fn create_restricted_token_builds_the_counted_blocks() {
        clear_services();
        let mut token = 0;
        arm();
        let ok = unsafe { create_restricted_token(TOKEN, 0, 0, core::ptr::null(), 0, core::ptr::null(), 0, core::ptr::null(), &mut token) };
        assert_eq!((ok, token, last_error()), (1, 0x60, 0xF2F2));
        assert_eq!(FILTER_COUNTS.with(|counts| counts.borrow().clone()), vec![0, 0, 0]);
        assert_eq!(service_calls().last(), Some(&("NtFilterToken", TOKEN, 0, 0)));
        let sids = [0x1111u32, 0x4, 0x2222, 0x4];
        let privs = [0u64, 0];
        let ok = unsafe {
            create_restricted_token(TOKEN, 1, 1, sids.as_ptr() as *const u8, 1, privs.as_ptr() as *const u8, 0, core::ptr::null(), &mut token)
        };
        assert_eq!(ok, 1);
        assert_eq!(FILTER_COUNTS.with(|counts| counts.borrow().clone()), vec![1, 1, 0]);
        clear_services();
        arm();
        let ok = unsafe { create_restricted_token(TOKEN, 0, 1, core::ptr::null(), 0, core::ptr::null(), 0, core::ptr::null(), &mut token) };
        assert_eq!((ok, last_error()), (0, 87), "a count with no array");
        assert!(service_calls().is_empty());
        STATUS.with(|status| status.set(0xC000_0022));
        let ok = unsafe { create_restricted_token(TOKEN, 0, 0, core::ptr::null(), 0, core::ptr::null(), 0, core::ptr::null(), &mut token) };
        assert_eq!((ok, last_error()), (0, 5));
        clear_services();
    }

    /// AdjustTokenGroups sets the last error from the status whatever it is: 0 for success,
    /// ERROR_NOT_ALL_ASSIGNED for the partial assignment (TRUE all the same), the failure's
    /// error with FALSE.
    #[test]
    fn adjust_token_groups_reports_its_status() {
        clear_services();
        let call = |reset| unsafe {
            adjust_token_groups(TOKEN, reset, core::ptr::null(), 0, core::ptr::null_mut(), core::ptr::null_mut())
        };
        for (status, answer, error, reset) in [
            (0, 1, 0, 0),
            (0x0000_0106, 1, 1300, 1),
            (0xC000_0023, 0, 122, 0),
        ] {
            STATUS.with(|next| next.set(status));
            arm();
            assert_eq!((call(reset), last_error()), (answer, error), "{status:#x}");
            assert_eq!(service_calls().last(), Some(&("NtAdjustGroupsToken", TOKEN, reset, 0)));
        }
        clear_services();
    }

    /// SetTokenInformation asks the service for the class given; a failure's status is the last
    /// error, the last error untouched on success.
    #[test]
    fn set_token_information_maps_the_status() {
        clear_services();
        let info = [0u8; 4];
        arm();
        let ok = unsafe { set_token_information(TOKEN, 0xFFFF, info.as_ptr(), 4) };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        assert_eq!(service_calls().last(), Some(&("NtSetInformationToken", TOKEN, 0xFFFF, 0)));
        STATUS.with(|status| status.set(0xC000_000D));
        arm();
        let ok = unsafe { set_token_information(TOKEN, 1, info.as_ptr(), 4) };
        assert_eq!((ok, last_error()), (0, 87));
        clear_services();
    }

    /// OpenThreadToken asks the service; no thread token (STATUS_NO_TOKEN) is ERROR_NO_TOKEN,
    /// a success hands the handle out and leaves the last error alone.
    #[test]
    fn open_thread_token_maps_the_status() {
        clear_services();
        let mut token = 0;
        arm();
        let ok = unsafe { open_thread_token(0xFFFF_FFFE, 8, 1, &mut token) };
        assert_eq!((ok, token, last_error()), (1, 0x60, 0xF2F2));
        assert_eq!(service_calls().last(), Some(&("NtOpenThreadToken", 0xFFFF_FFFE, 8, 0)));
        STATUS.with(|status| status.set(0xC000_007C));
        arm();
        let ok = unsafe { open_thread_token(0xFFFF_FFFE, 8, 0, &mut token) };
        assert_eq!((ok, last_error()), (0, 1008), "STATUS_NO_TOKEN (0xC000007C)");
        clear_services();
    }
    /// LookupPrivilegeDisplayName answers like the name lookup, with the language id written
    /// whatever the answer (US English here); an unknown name is ERROR_NO_SUCH_PRIVILEGE.
    #[test]
    fn display_name_lookups_answer() {
        clear_services();
        let name = wide_z("SeShutdownPrivilege");
        let mut buffer = [0xCCu16; 32];
        let disp_w = |name: *const u16, buffer: *mut u16, cch: *mut u32, lang: *mut u32| unsafe {
            lookup_privilege_display_name_w(core::ptr::null(), name, buffer, cch, lang)
        };
        let mut cch = 0u32;
        let mut lang = 0xF2F2;
        arm();
        assert_eq!((disp_w(name.as_ptr(), buffer.as_mut_ptr(), &mut cch, &mut lang), last_error(), cch, lang), (0, 122, 20, 0x0409), "the size query sets the language");
        let mut cch = 20u32;
        let mut lang = 0xF2F2;
        arm();
        assert_eq!((disp_w(name.as_ptr(), buffer.as_mut_ptr(), &mut cch, &mut lang), last_error(), cch, lang), (1, 997, 19, 0x0409));
        let unknown = wide_z("SeNoSuchPrivilege");
        let mut cch = 128u32;
        let mut lang = 0xF2F2;
        assert_eq!((disp_w(unknown.as_ptr(), buffer.as_mut_ptr(), &mut cch, &mut lang), last_error(), cch), (0, 1313, 128));
        let mut ansi = [0xCCu8; 32];
        let mut cch = 20u32;
        let mut lang = 0xF2F2;
        arm();
        let ok = unsafe { lookup_privilege_display_name_a(b"\0".as_ptr(), b"SeShutdownPrivilege\0".as_ptr(), ansi.as_mut_ptr(), &mut cch, &mut lang) };
        assert_eq!((ok, last_error(), cch, lang), (1, 997, 19, 0x0409), "the A form");
        assert_eq!(&ansi[..20], b"SeShutdownPrivilege\0");
    }
}
