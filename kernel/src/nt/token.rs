//! The token services: NtOpenProcessToken, NtAdjustPrivilegesToken and NtQueryInformationToken,
//! over the process's token (`se`). advapi32's OpenProcessToken, AdjustTokenPrivileges and
//! GetTokenInformation are Win32 code over these, as on Windows 2000.
//!
//! F2K checks no privilege anywhere: what these services keep is bookkeeping, so that the calls a
//! program makes before it shuts the machine down answer as Windows 2000's do (see `se`). Where
//! Windows 2000 would grant or refuse a token's access by its security descriptor, F2K grants
//! every right asked for. The handle checks are the object manager's, as for any object: a handle
//! naming nothing is STATUS_INVALID_HANDLE, one naming another kind of object (a pseudo-handle
//! included) STATUS_OBJECT_TYPE_MISMATCH, one not granted the right a service needs
//! STATUS_ACCESS_DENIED: TOKEN_QUERY to query, TOKEN_ADJUST_PRIVILEGES to adjust (and TOKEN_QUERY
//! too when the old state is asked for, as the documentation says).

use crate::status::*;

/// The token rights (winnt.h's TOKEN_*).
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
/// The generic rights' mapping for tokens, and what MAXIMUM_ALLOWED grants (every token right).
pub const TOKEN_READ: u32 = 0x0002_0008;
pub const TOKEN_WRITE: u32 = 0x0002_00E0;
pub const TOKEN_EXECUTE: u32 = 0x0002_0000;
pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// The standard and the token-specific rights: what a request names besides the generic ones.
const SPECIFIC_AND_STANDARD: u32 = 0x00FF_FFFF;

info_class! {
    /// The token information classes (TOKEN_INFORMATION_CLASS), Windows 2000's.
    pub enum TokenClass {
        User = 1,
        Groups = 2,
        Privileges = 3,
        Owner = 4,
        PrimaryGroup = 5,
        DefaultDacl = 6,
        Source = 7,
        Type = 8,
        ImpersonationLevel = 9,
        Statistics = 10,
        RestrictedSids = 11,
        SessionId = 12,
        GroupsAndPrivileges = 13,
        SessionReference = 14,
        SandBoxInert = 15,
    }
}

/// The rights an open asking for `desired` is granted: the rights it names, the generic ones
/// mapped to the token rights, MAXIMUM_ALLOWED as every token right.
pub fn granted(desired: u32) -> u32 {
    let mut access = desired & SPECIFIC_AND_STANDARD;
    for (generic, rights) in [
        (GENERIC_READ, TOKEN_READ),
        (GENERIC_WRITE, TOKEN_WRITE),
        (GENERIC_EXECUTE, TOKEN_EXECUTE),
        (GENERIC_ALL | MAXIMUM_ALLOWED, TOKEN_ALL_ACCESS),
    ] {
        if desired & generic != 0 {
            access |= rights;
        }
    }
    access
}

#[cfg(target_arch = "x86")]
pub use services::*;

/// The services themselves, on the calling process's handles and the processes' tokens.
#[cfg(target_arch = "x86")]
mod services {
    use rtl::nt::LuidAndAttributes;
    use rtl::pod::Pod;

    use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use super::super::object::{
        is_console_handle,
        reference_process,
        CURRENT_PROCESS,
        CURRENT_THREAD,
        PROCESS_QUERY_INFORMATION,
    };
    use super::*;
    use crate::ob::{self, ObRef, ObjectType};
    use crate::se::{privileges_size, Change, Requests, HELD};

    /// NewState's entries copied in at a time, through a buffer on the stack (384 bytes).
    const CHUNK: usize = 32;

    /// The token `handle` names in the calling process, its open granted `needed`, referenced for
    /// the service's scope: STATUS_INVALID_HANDLE for a handle naming nothing (a console handle
    /// included), STATUS_OBJECT_TYPE_MISMATCH for another kind of object (the process and thread
    /// pseudo-handles among them), STATUS_ACCESS_DENIED for an open without the rights.
    fn token_of(handle: u32, needed: u32) -> Result<ObRef, NtStatus> {
        if handle == CURRENT_PROCESS || handle == CURRENT_THREAD {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .lookup_handle(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Token {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if entry.access & needed != needed {
            return Err(STATUS_ACCESS_DENIED);
        }
        ob::reference(id).ok_or(STATUS_INVALID_HANDLE)
    }

    /// NtOpenProcessToken: a handle to the token of the process `process` names (opened with
    /// PROCESS_QUERY_INFORMATION), granted the rights asked for, into TokenHandle. The thread
    /// pseudo-handle names a thread, not a process (STATUS_OBJECT_TYPE_MISMATCH); asking for no
    /// right at all is STATUS_ACCESS_DENIED, as an access check refuses an empty request.
    pub fn open_process_token(
        call: &mut NtCall,
        process: Handle,
        desired: u32,
        slot: UserPtr<u32>,
    ) -> NtResult {
        if slot.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        slot.addr().probe(4)?;
        if process.raw() == CURRENT_THREAD {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        let process_ref = reference_process(process.raw(), PROCESS_QUERY_INFORMATION)?;
        let access = granted(desired);
        if access == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let token =
            ob::reference_process_token(process_ref.id()).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        drop(process_ref);
        let caller = call.process();
        let handle = ob::open(caller, token.id(), access, false)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .get();
        drop(token);
        if slot.write(handle).is_err() {
            caller.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(STATUS_SUCCESS)
    }

    /// NewState's entries, folded (see [`Requests`]): its count, then that many
    /// LUID_AND_ATTRIBUTES, copied in a chunk at a time.
    fn read_requests(new_state: UserAddr) -> Result<Requests, NtStatus> {
        let count = new_state.cast::<u32>().read()? as usize;
        let mut requests = Requests::new();
        let mut buffer = [LuidAndAttributes::default(); CHUNK];
        let mut at = new_state.offset(4);
        let mut left = count;
        while left > 0 {
            let take = left.min(CHUNK);
            let bytes =
                &mut buffer.as_bytes_mut()[..take * core::mem::size_of::<LuidAndAttributes>()];
            at.read(bytes)?;
            at = at.offset(bytes.len() as u32);
            for &entry in &buffer[..take] {
                requests.add(entry);
            }
            left -= take;
        }
        Ok(requests)
    }

    /// NtAdjustPrivilegesToken: the token's privileges enabled or disabled as NewState says, or
    /// every one disabled (DisableAllPrivileges, NewState ignored). With PreviousState, what
    /// changed is reported there with its old attributes (a TOKEN_PRIVILEGES), and its size in
    /// ReturnLength; a PreviousState of BufferLength bytes too short for the report changes
    /// nothing: STATUS_BUFFER_TOO_SMALL, the size it takes in ReturnLength. A privilege the token
    /// does not hold is not assigned (STATUS_NOT_ALL_ASSIGNED, a success: the others change).
    /// No NewState without DisableAllPrivileges is STATUS_INVALID_PARAMETER, before the handle is
    /// looked at. The privileges are bookkeeping only (see `se`): nothing checks them.
    pub fn adjust_privileges_token(
        _: &mut NtCall,
        handle: Handle,
        disable_all: bool,
        new_state: UserAddr,
        length: u32,
        previous: UserAddr,
        return_length: UserPtr<u32>,
    ) -> NtResult {
        if !disable_all && new_state.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let reported = !previous.is_null();
        if reported {
            previous.probe(length)?;
            if return_length.is_null() {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            return_length.addr().probe(4)?;
        }
        let change = if disable_all {
            Change::DisableAll
        } else {
            Change::Set(read_requests(new_state)?)
        };
        let needed = TOKEN_ADJUST_PRIVILEGES | if reported { TOKEN_QUERY } else { 0 };
        let token = token_of(handle.raw(), needed)?;
        let room = reported.then_some(length);
        let adjusted = ob::locked(|directory| {
            directory
                .token(token.id())
                .map(|body| body.adjust(&change, room))
        })
        .ok_or(STATUS_INVALID_HANDLE)?;
        drop(token);
        let adjusted = match adjusted {
            Ok(adjusted) => adjusted,
            Err(size) => {
                return_length.write(size)?;
                return Err(STATUS_BUFFER_TOO_SMALL);
            }
        };
        if reported {
            previous
                .cast::<u32>()
                .write(adjusted.previous.len() as u32)?;
            for (index, entry) in adjusted.previous.iter().enumerate() {
                let offset = privileges_size(index);
                previous.offset(offset).write(entry.as_bytes())?;
            }
            return_length.write(adjusted.length())?;
        }
        if adjusted.not_all_assigned {
            Ok(STATUS_NOT_ALL_ASSIGNED)
        } else {
            Ok(STATUS_SUCCESS)
        }
    }

    /// NtQueryInformationToken: the token's information of the class asked for, into a buffer of
    /// TokenInformationLength bytes, the size the answer takes into ReturnLength (when the buffer
    /// is too short too: STATUS_BUFFER_TOO_SMALL, nothing written). TokenPrivileges alone is
    /// answered: a TOKEN_PRIVILEGES, the privileges the token holds and their state; the other
    /// classes Windows 2000 answers are not served (STATUS_NOT_IMPLEMENTED), and a class it does
    /// not have is STATUS_INVALID_INFO_CLASS.
    pub fn query_information_token(
        _: &mut NtCall,
        handle: Handle,
        class: u32,
        information: UserAddr,
        length: u32,
        return_length: UserPtr<u32>,
    ) -> NtResult {
        if TokenClass::try_from(class)? != TokenClass::Privileges {
            return Err(STATUS_NOT_IMPLEMENTED);
        }
        information.probe(length)?;
        if return_length.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        return_length.addr().probe(4)?;
        let token = token_of(handle.raw(), TOKEN_QUERY)?;
        let privileges =
            ob::locked(|directory| directory.token(token.id()).map(|body| body.privileges()))
                .ok_or(STATUS_INVALID_HANDLE)?;
        drop(token);
        let size = privileges_size(HELD);
        if length < size {
            return_length.write(size)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        information.cast::<u32>().write(HELD as u32)?;
        information.offset(4).write(privileges.as_bytes())?;
        return_length.write(size)?;
        Ok(STATUS_SUCCESS)
    }
}

/// The host builds' token services (see `unserved`).
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        open_process_token(Handle, u32, UserPtr<u32>);
        adjust_privileges_token(Handle, bool, UserAddr, u32, UserAddr, UserPtr<u32>);
        query_information_token(Handle, u32, UserAddr, u32, UserPtr<u32>);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// The rights asked for are granted, the generic ones mapped to the token rights: TOKEN_QUERY
    /// alone is 0x8, with TOKEN_ADJUST_PRIVILEGES 0x28 (the capture's granted access); no right
    /// asked for is none granted.
    #[test]
    fn the_rights_asked_for_are_granted() {
        assert_eq!(granted(TOKEN_QUERY), 0x8);
        assert_eq!(granted(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), 0x28);
        assert_eq!(granted(0), 0);
        assert_eq!(granted(GENERIC_READ), TOKEN_READ);
        assert_eq!(granted(GENERIC_WRITE), TOKEN_WRITE);
        assert_eq!(granted(MAXIMUM_ALLOWED), TOKEN_ALL_ACCESS);
        assert_eq!(granted(GENERIC_ALL | TOKEN_QUERY), TOKEN_ALL_ACCESS);
    }

    /// TokenPrivileges is class 3; a class past Windows 2000's is STATUS_INVALID_INFO_CLASS.
    #[test]
    fn the_token_classes_are_windows_2000s() {
        assert_eq!(TokenClass::try_from(3), Ok(TokenClass::Privileges));
        assert_eq!(TokenClass::try_from(16), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(TokenClass::try_from(0), Err(STATUS_INVALID_INFO_CLASS));
    }
}
