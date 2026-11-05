//! The calls a program makes to shut the machine down, as Windows 2000's own programs make them:
//! the local computer's name (kernel32's GetComputerNameW); the standard preamble that enables a
//! privilege in the process's own token (advapi32's OpenProcessToken, LookupPrivilegeValueW and
//! AdjustTokenPrivileges); and the request itself (user32's ExitWindowsEx). Each is imported by
//! name and wrapped once, safely.

use crate::output::Error;

/// The longest computer name, its terminator left out (MAX_COMPUTERNAME_LENGTH).
pub const MAX_COMPUTERNAME_LENGTH: usize = 15;

/// SE_SHUTDOWN_NAME: the privilege ExitWindowsEx asks of its caller for every action but a
/// logoff.
pub const SE_SHUTDOWN_NAME: &str = "SeShutdownPrivilege";

/// A token's access: its privileges adjusted, and queried (AdjustTokenPrivileges asks both when
/// it reports the previous state; the preamble asks both, as programs do).
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_QUERY: u32 = 0x0008;

/// ExitWindowsEx's flags: a shutdown (which ends on "It is now safe to turn off your computer"
/// on Windows 2000), a restart, and EWX_FORCE, which ends the session's programs without asking
/// them.
pub const EWX_SHUTDOWN: u32 = 0x01;
pub const EWX_REBOOT: u32 = 0x02;
pub const EWX_FORCE: u32 = 0x04;

/// GetCurrentProcess's pseudo-handle.
const CURRENT_PROCESS: usize = usize::MAX;
/// A privilege's attribute that enables it.
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
/// AdjustTokenPrivileges' last error when the token does not hold a privilege it was asked to
/// change: the call returns TRUE all the same.
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
/// The units a privilege's name is copied into, its terminator included (winnt.h's longest is 31
/// characters).
const PRIVILEGE_NAME: usize = 64;
/// ERROR_INVALID_PARAMETER: a privilege name too long for that buffer.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// A LUID: how the system names a privilege on this computer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

/// TOKEN_PRIVILEGES holding one LUID_AND_ATTRIBUTES: what AdjustTokenPrivileges reads.
#[repr(C)]
struct TokenPrivileges {
    count: u32,
    luid: Luid,
    attributes: u32,
}

const _: () = assert!(core::mem::size_of::<TokenPrivileges>() == 16);

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling thread's last error.
    fn GetLastError() -> u32;
    /// The thread's last error set.
    fn SetLastError(error: u32);
    /// The local computer's name into a buffer of `*size` units: its length in `*size`, or the
    /// size it needs there when it does not fit (FALSE).
    fn GetComputerNameW(buffer: *mut u16, size: *mut u32) -> i32;
    /// A handle closed.
    fn CloseHandle(object: usize) -> i32;
}

#[link(
    name = "advapi32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// A handle to a process's token, with the access asked.
    fn OpenProcessToken(process: usize, access: u32, token: *mut usize) -> i32;
    /// The LUID a privilege's NUL-terminated name has on a system (null: the local one).
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    /// A token's privileges enabled or disabled as `new_state` says; the previous state reported
    /// when asked for (null here). TRUE even when not every privilege was held: the last error
    /// says so.
    fn AdjustTokenPrivileges(
        token: usize,
        disable_all: i32,
        new_state: *const TokenPrivileges,
        buffer_length: u32,
        previous_state: usize,
        return_length: *mut u32,
    ) -> i32;
}

#[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// The session ended as the flags ask, then the machine shut down for every action but a
    /// logoff: TRUE once the request is taken, before any of it happens.
    fn ExitWindowsEx(flags: u32, reserved: u32) -> i32;
}

/// The calling thread's last error, as an [`Error`].
fn last_error() -> Error {
    // SAFETY: no arguments; it reads the thread's own TEB.
    Error(unsafe { GetLastError() })
}

/// The local computer's name, in `buffer`.
pub fn computer_name(buffer: &mut [u16; MAX_COMPUTERNAME_LENGTH + 1]) -> Result<&[u16], Error> {
    let mut size = buffer.len() as u32;
    // SAFETY: the buffer holds the `size` units the call is told of; `size` is a live dword.
    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut size) } == 0 {
        return Err(last_error());
    }
    Ok(&buffer[..(size as usize).min(MAX_COMPUTERNAME_LENGTH)])
}

/// The LUID the privilege `name` (ASCII, as winnt.h's SE_*_NAME are) has on the local computer.
pub fn lookup_privilege(name: &str) -> Result<Luid, Error> {
    let mut wide = [0u16; PRIVILEGE_NAME];
    if name.len() >= PRIVILEGE_NAME || !name.is_ascii() {
        return Err(Error(ERROR_INVALID_PARAMETER));
    }
    for (unit, byte) in wide.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    let mut luid = Luid::default();
    // SAFETY: the name ends with a NUL within `wide`; no system name (the local computer); the
    // call writes a LUID into `luid`.
    if unsafe { LookupPrivilegeValueW(core::ptr::null(), wide.as_ptr(), &mut luid) } == 0 {
        return Err(last_error());
    }
    Ok(luid)
}

/// The calling process's own token, closed when dropped.
pub struct Token(usize);

impl Token {
    /// The process's own token, opened with `access` (TOKEN_* rights).
    pub fn open_own(access: u32) -> Result<Token, Error> {
        let mut token = 0usize;
        // SAFETY: the pseudo-handle names the process; the call writes a handle into `token`.
        if unsafe { OpenProcessToken(CURRENT_PROCESS, access, &mut token) } == 0 {
            return Err(last_error());
        }
        Ok(Token(token))
    }

    /// Enable the privilege `luid` names in the token (opened with TOKEN_ADJUST_PRIVILEGES): an
    /// error when the call fails, or when the token does not hold the privilege
    /// (ERROR_NOT_ALL_ASSIGNED, which the call reports through its last error alone).
    pub fn enable(&self, luid: Luid) -> Result<(), Error> {
        let state = TokenPrivileges {
            count: 1,
            luid,
            attributes: SE_PRIVILEGE_ENABLED,
        };
        // The last error is the call's answer even when it succeeds: start from none.
        // SAFETY: no pointers.
        unsafe { SetLastError(0) };
        // SAFETY: the call reads the TOKEN_PRIVILEGES `state`; no previous state is asked for, so
        // it writes nothing.
        let done = unsafe { AdjustTokenPrivileges(self.0, 0, &state, 0, 0, core::ptr::null_mut()) };
        let error = last_error();
        if done == 0 {
            return Err(error);
        }
        if error == Error(ERROR_NOT_ALL_ASSIGNED) {
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle is the token's, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Ask for the session's end, then the machine's, as `flags` (EWX_*) say: returns once the request
/// is taken, before any of it happens.
pub fn exit_windows(flags: u32) -> Result<(), Error> {
    // SAFETY: no pointers.
    if unsafe { ExitWindowsEx(flags, 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}
