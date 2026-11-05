//! The process token's calls, as a program that shuts the machine down makes them first:
//! OpenProcessToken, LookupPrivilegeValueW and LookupPrivilegeValueA, AdjustTokenPrivileges and
//! GetTokenInformation(TokenPrivileges). The token calls are advapi32's own code over ntdll's token
//! services (NtOpenProcessToken, NtAdjustPrivilegesToken, NtQueryInformationToken), as on Windows
//! 2000; the lookup answers from the privileges' public names and LUIDs (winnt.h's SE_*_NAME and
//! SE_*_PRIVILEGE), where Windows 2000's asks the local security authority, which F2K does not
//! have.
//!
//! F2K checks no privilege anywhere: the token keeps the privileges' state as bookkeeping, so that
//! these calls answer as Windows 2000's do (see the kernel's `se`).

use rtl::cstr;
use rtl::nt::Luid;
use rtl::status::NtStatus;

use crate::imports::{self as nt, Counted, Passed};
use crate::Out;

/// ERROR_IO_PENDING: the last error a successful lookup leaves (see [`lookup_privilege_value`]).
const ERROR_IO_PENDING: u32 = 997;
/// ERROR_NOACCESS: a LUID the lookup cannot write.
const ERROR_NOACCESS: u32 = 998;
/// ERROR_NO_SUCH_PRIVILEGE: a name no privilege has.
pub const ERROR_NO_SUCH_PRIVILEGE: u32 = 1313;
/// RPC_S_SERVER_UNAVAILABLE: a system name other than the local computer's (there is no remote
/// security authority to ask).
const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
/// TokenPrivileges: the one token information class answered.
const TOKEN_PRIVILEGES: u32 = 3;

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
fn is_local(system: &[u16]) -> bool {
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
fn bool_of(result: Result<(), u32>) -> u32 {
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
unsafe fn optional_wide<'a>(text: *const u16) -> Option<&'a [u16]> {
    // SAFETY: the caller's contract, for the non-null string.
    (!text.is_null()).then(|| unsafe { cstr::units_until_nul(text) })
}

/// The caller's NUL-terminated ANSI string at `text`, its terminator left out: none for null.
///
/// # Safety
///
/// `text` is null or a NUL-terminated string the call may read.
unsafe fn optional_ansi<'a>(text: *const u8) -> Option<&'a [u8]> {
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
fn failed(status: NtStatus) -> u32 {
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

/// GetTokenInformation: NtQueryInformationToken, for TokenPrivileges; a failure's status as the
/// last error, which is untouched on success. The other classes are stubbed: F2K's tokens hold no
/// user, groups or defaults to answer them with.
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
    if class != TOKEN_PRIVILEGES {
        let args = [
            u64::from(token),
            u64::from(class),
            information as u64,
            u64::from(length),
            return_length as u64,
        ];
        // SAFETY: the arguments as the caller passed them, read as the spec's kinds say.
        return unsafe {
            crate::stub::stubbed(
                &crate::spec::GetTokenInformation,
                "only TokenPrivileges is answered",
                &args,
            )
        };
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{LAST_ERROR, TOKEN, TOKEN_CALLS, TOKEN_STATUS};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

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
        let name = wide("SeShutdownPrivilege");
        arm();
        let ok = unsafe { lookup_privilege_value_w(core::ptr::null(), name.as_ptr(), &mut luid) };
        assert_eq!((ok, last_error()), (1, 997));
        assert_eq!((luid.low_part, luid.high_part), (19, 0));
        for system in ["", "QEMU", "qemu", "\\\\QEMU"] {
            luid.low_part = 0;
            let system = wide(system);
            let ok = unsafe { lookup_privilege_value_w(system.as_ptr(), name.as_ptr(), &mut luid) };
            assert_eq!((ok, luid.low_part), (1, 19));
        }
        let remote = wide("\\\\ELSEWHERE");
        luid.low_part = 0xF2F2;
        let ok = unsafe { lookup_privilege_value_w(remote.as_ptr(), name.as_ptr(), &mut luid) };
        assert_eq!((ok, last_error(), luid.low_part), (0, 1722, 0xF2F2));
        for unknown in ["SeNoSuchPrivilege", ""] {
            luid.low_part = 0xF2F2;
            let unknown = wide(unknown);
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
    /// GetTokenInformation asks the service for TokenPrivileges alone.
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
    }
}
