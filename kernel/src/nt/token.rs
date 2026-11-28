//! The token services: NtOpenProcessToken, NtAdjustPrivilegesToken, NtQueryInformationToken and
//! NtDuplicateToken, over the process's token and its copies (`se`). advapi32's OpenProcessToken,
//! AdjustTokenPrivileges, GetTokenInformation and DuplicateToken are Win32 code over these, as on
//! Windows 2000.
//!
//! What these services keep is bookkeeping, so that the calls a program makes before it shuts the
//! machine down answer as Windows 2000's do (see `se`); the one privilege F2K checks is
//! SeLoadDriverPrivilege, which a driver's load and unload require (`nt::driver`). Where
//! Windows 2000 would grant or refuse a token's access by its security descriptor, F2K grants
//! every right asked for. The handle checks are the object manager's, as for any object: a handle
//! naming nothing is STATUS_INVALID_HANDLE, one naming another kind of object (a pseudo-handle
//! included) STATUS_OBJECT_TYPE_MISMATCH, one not granted the right a service needs
//! STATUS_ACCESS_DENIED: TOKEN_QUERY to query (TOKEN_QUERY_SOURCE for TokenSource),
//! TOKEN_ADJUST_PRIVILEGES to adjust (and TOKEN_QUERY too when the old state is asked for, as the
//! documentation says), TOKEN_ADJUST_DEFAULT to set the owner, the primary group, the default DACL
//! or the session id (with TOKEN_ADJUST_SESSIONID for the session id), TOKEN_DUPLICATE to
//! duplicate.

use rtl::nt::access::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED};
// The token rights (winnt.h's TOKEN_*), and the generic rights' mapping for tokens and what
// MAXIMUM_ALLOWED grants (every token right).
#[cfg_attr(not(target_arch = "x86"), allow(unused_imports))]
pub use rtl::nt::access::{
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE,
    TOKEN_EXECUTE,
    TOKEN_QUERY,
    TOKEN_QUERY_SOURCE,
    TOKEN_READ,
    TOKEN_WRITE,
};

/// The default-adjusting rights a set needs (winnt.h's TOKEN_ADJUST_DEFAULT and
/// TOKEN_ADJUST_SESSIONID): specific rights, carried by TOKEN_WRITE and TOKEN_ALL_ACCESS.
#[cfg_attr(not(test), allow(dead_code))] // wired to its service's export when that lands
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
#[cfg_attr(not(test), allow(dead_code))]
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;

use crate::se;
use crate::status::*;
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

/// The information class F2K answers for `class`, and the right its query needs:
/// STATUS_INVALID_INFO_CLASS for a class Windows 2000 does not have, STATUS_NOT_IMPLEMENTED for
/// the ones past TokenSessionId it has (TokenGroupsAndPrivileges, TokenSessionReference,
/// TokenSandBoxInert), which nothing F2K runs asks for.
pub fn query_class(class: u32) -> Result<(se::Class, u32), NtStatus> {
    let class = match TokenClass::try_from(class)? {
        TokenClass::User => se::Class::User,
        TokenClass::Groups => se::Class::Groups,
        TokenClass::Privileges => se::Class::Privileges,
        TokenClass::Owner => se::Class::Owner,
        TokenClass::PrimaryGroup => se::Class::PrimaryGroup,
        TokenClass::DefaultDacl => se::Class::DefaultDacl,
        TokenClass::Source => return Ok((se::Class::Source, TOKEN_QUERY_SOURCE)),
        TokenClass::Type => se::Class::Type,
        TokenClass::ImpersonationLevel => se::Class::ImpersonationLevel,
        TokenClass::Statistics => se::Class::Statistics,
        TokenClass::RestrictedSids => se::Class::RestrictedSids,
        TokenClass::SessionId => se::Class::SessionId,
        TokenClass::GroupsAndPrivileges
        | TokenClass::SessionReference
        | TokenClass::SandBoxInert => return Err(STATUS_NOT_IMPLEMENTED),
    };
    Ok((class, TOKEN_QUERY))
}

/// The information class F2K answers a set for `class`, and the right its set needs:
/// STATUS_INVALID_INFO_CLASS for every class but the owner's, the primary group's, the default
/// DACL's and the session id's — answered before the handle is looked at, as Windows 2000's does.
#[cfg_attr(not(test), allow(dead_code))] // wired to its service's export when that lands
pub fn set_class(class: u32) -> Result<(SetClass, u32), NtStatus> {
    Ok(match TokenClass::try_from(class)? {
        TokenClass::Owner => (SetClass::Owner, TOKEN_ADJUST_DEFAULT),
        TokenClass::PrimaryGroup => (SetClass::PrimaryGroup, TOKEN_ADJUST_DEFAULT),
        TokenClass::DefaultDacl => (SetClass::DefaultDacl, TOKEN_ADJUST_DEFAULT),
        TokenClass::SessionId => (
            SetClass::SessionId,
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        ),
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    })
}

/// The token information classes a set can address (every other class answers
/// STATUS_INVALID_INFO_CLASS to a set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetClass {
    Owner,
    PrimaryGroup,
    DefaultDacl,
    SessionId,
}

/// Whether `acl` holds a well-formed ACL: a known revision, its size word-aligned and agreeing
/// with the buffer, and each of its ACEs within it — a known ACE (an allow, deny, audit or alarm
/// one) long-aligned, with a valid SID at its end.
fn acl_valid(acl: &[u8]) -> bool {
    if acl.len() < 8 || (acl[0] != 2 && acl[0] != 4) {
        return false;
    }
    let size = u16::from_le_bytes([acl[2], acl[3]]) as usize;
    if size != acl.len() || size % 2 != 0 {
        return false;
    }
    let count = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    let mut at = 8;
    for _ in 0..count {
        if at + 4 >= acl.len() {
            return false;
        }
        let ace_size = u16::from_le_bytes([acl[at + 2], acl[at + 3]]) as usize;
        if ace_size == 0 || ace_size % 2 != 0 || at + ace_size > acl.len() {
            return false;
        }
        if acl[at] <= 3 {
            if ace_size % 4 != 0 || ace_size < 8 {
                return false;
            }
            let Some(sid_len) = crate::sec::sid::length(&acl[at + 8..]) else {
                return false;
            };
            if ace_size < 8 + sid_len {
                return false;
            }
        }
        at += ace_size;
    }
    true
}

/// The set paths of a token (NtSetInformationToken's classes), on its body.
impl se::TokenBody {
    /// The token's dynamic part's free room: what its default DACL and primary group leave of it.
    pub(crate) fn dynamic_available(&self) -> usize {
        se::DYNAMIC_CHARGED as usize - self.default_dacl.len() - self.primary_group.len()
    }

    /// Whether `sid` names the token's user or one of its groups, and whether it may be the
    /// token's owner: the user always may, a group only with its owner attribute.
    fn named(&self, sid: &[u8]) -> Option<bool> {
        if crate::sec::equal(self.user.as_slice(), sid) {
            return Some(true);
        }
        se::GROUPS
            .iter()
            .find(|(group, _)| crate::sec::equal(se::sid_bytes(group).as_slice(), sid))
            .map(|(_, attributes)| attributes & se::SE_GROUP_OWNER != 0)
    }

    /// Set the default owner to the SID `sid` (a set of TokenOwner): it must be one the token
    /// names and may be an owner — the user, or a group with its owner attribute — else
    /// STATUS_INVALID_OWNER; a malformed SID is STATUS_INVALID_SID.
    pub fn set_owner(&mut self, sid: &[u8]) -> Result<(), NtStatus> {
        if !crate::sec::sid::is_valid(sid) {
            return Err(se::STATUS_INVALID_SID);
        }
        match self.named(sid) {
            Some(true) => {
                self.owner_sid.clear();
                self.owner_sid
                    .try_extend_from_slice(sid)
                    .expect("a SID fits its buffer");
                Ok(())
            }
            _ => Err(se::STATUS_INVALID_OWNER),
        }
    }

    /// Set the primary group to the SID `sid` (TokenPrimaryGroup): it must be one the token names
    /// (the user or a group), else STATUS_INVALID_PRIMARY_GROUP; it must fit the token's dynamic
    /// part, else STATUS_ALLOTTED_SPACE_EXCEEDED; a malformed SID is STATUS_INVALID_SID.
    pub fn set_primary_group(&mut self, sid: &[u8]) -> Result<(), NtStatus> {
        if !crate::sec::sid::is_valid(sid) {
            return Err(se::STATUS_INVALID_SID);
        }
        if self.named(sid).is_none() {
            return Err(se::STATUS_INVALID_PRIMARY_GROUP);
        }
        if sid.len() > self.primary_group.len() + self.dynamic_available() {
            return Err(se::STATUS_ALLOTTED_SPACE_EXCEEDED);
        }
        self.primary_group.clear();
        self.primary_group
            .try_extend_from_slice(sid)
            .expect("the space check passed");
        Ok(())
    }

    /// Set the default DACL to `acl` (TokenDefaultDacl; None clears it): a malformed ACL is
    /// STATUS_INVALID_ACL, one that does not fit the token's dynamic part
    /// STATUS_ALLOTTED_SPACE_EXCEEDED.
    pub fn set_default_dacl(&mut self, acl: Option<&[u8]>) -> Result<(), NtStatus> {
        let new = match acl {
            None => 0,
            Some(bytes) => {
                if !acl_valid(bytes) {
                    return Err(se::STATUS_INVALID_ACL);
                }
                bytes.len()
            }
        };
        if new > self.default_dacl.len() + self.dynamic_available() {
            return Err(se::STATUS_ALLOTTED_SPACE_EXCEEDED);
        }
        self.default_dacl.clear();
        if let Some(bytes) = acl {
            self.default_dacl
                .try_extend_from_slice(bytes)
                .expect("the space check passed");
        }
        Ok(())
    }

    /// Set the session id (TokenSessionId): only with the TCB privilege held
    /// (STATUS_PRIVILEGE_NOT_HELD otherwise).
    pub fn set_session_id(&mut self, session: u32, tcb_held: bool) -> Result<(), NtStatus> {
        if !tcb_held {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        self.session = session;
        Ok(())
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
    use super::super::capture::read_required_sid;
    use super::super::object::{
        is_console_handle,
        reference_process,
        CURRENT_PROCESS,
        CURRENT_THREAD,
        PROCESS_QUERY_INFORMATION,
    };
    use super::*;
    use crate::ob::{self, ObRef, ObjectType};
    use crate::se::{privileges_size, Change, Requests};

    /// NewState's entries copied in at a time, through a buffer on the stack (384 bytes).
    const CHUNK: usize = 32;

    /// The token `handle` names in the calling process, its open granted `needed`, referenced for
    /// the service's scope, with the handle's granted access: STATUS_INVALID_HANDLE for a handle
    /// naming nothing (a console handle included), STATUS_OBJECT_TYPE_MISMATCH for another kind of
    /// object (the process and thread pseudo-handles among them), STATUS_ACCESS_DENIED for an open
    /// without the rights.
    pub(crate) fn token_of(handle: u32, needed: u32) -> Result<(ObRef, u32), NtStatus> {
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
        let access = entry.access;
        Ok((ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?, access))
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
    /// looked at. Only SeLoadDriverPrivilege is ever checked (see `se`).
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
        let (token, _) = token_of(handle.raw(), needed)?;
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
    /// is too short too: STATUS_BUFFER_TOO_SMALL, nothing written). The classes are Windows 2000's
    /// structures (see `se`'s [`TokenBody::information`]), their pointers into the caller's
    /// buffer. TokenSessionId takes a buffer of its ULONG's size exactly
    /// (STATUS_INFO_LENGTH_MISMATCH otherwise, ReturnLength untouched, answered before the handle
    /// is looked at); TokenImpersonationLevel of a primary token is STATUS_INVALID_PARAMETER. A
    /// class Windows 2000 does not have is STATUS_INVALID_INFO_CLASS, before the handle is looked
    /// at.
    pub fn query_information_token(
        _: &mut NtCall,
        handle: Handle,
        class: u32,
        information: UserAddr,
        length: u32,
        return_length: UserPtr<u32>,
    ) -> NtResult {
        let (class, needed) = query_class(class)?;
        information.probe(length)?;
        if return_length.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        return_length.addr().probe(4)?;
        // TokenSessionId's buffer is exactly its ULONG, asked before the handle is looked at.
        if class == se::Class::SessionId && length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let (token, _) = token_of(handle.raw(), needed)?;
        let body = ob::locked(|directory| directory.token(token.id()).copied())
            .ok_or(STATUS_INVALID_HANDLE)?;
        drop(token);
        let reply = body.information(class, information.raw())?;
        let size = reply.len() as u32;
        if let Err(status) = se::fits(class, size, length) {
            if status == STATUS_BUFFER_TOO_SMALL {
                return_length.write(size)?;
            }
            return Err(status);
        }
        information.write(reply.as_slice())?;
        return_length.write(size)?;
        Ok(STATUS_SUCCESS)
    }

    /// The ACL at the caller's address `ptr` (a set structure's ACL pointer), read whole: None for
    /// a null pointer; a size under the ACL header's is STATUS_INVALID_ACL.
    fn read_acl(ptr: u32) -> Result<Option<crate::sec::Owned>, NtStatus> {
        if ptr == 0 {
            return Ok(None);
        }
        let at = UserAddr(ptr);
        let mut header = [0u8; 8];
        at.read(&mut header)?;
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size < 8 {
            return Err(se::STATUS_INVALID_ACL);
        }
        let mut acl = crate::sec::allocate(size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        at.read(crate::sec::bytes_mut(&mut acl))?;
        Ok(Some(acl))
    }

    /// NtSetInformationToken: set the token's information of the class asked for. Only the owner,
    /// the primary group, the default DACL and the session id are settable — any other class is
    /// STATUS_INVALID_INFO_CLASS before the handle is looked at — and the set needs
    /// TOKEN_ADJUST_DEFAULT (with TOKEN_ADJUST_SESSIONID for the session id). A buffer shorter
    /// than the class's structure is STATUS_INFO_LENGTH_MISMATCH; the session id's buffer is its
    /// ULONG exactly. The owner must be a SID the token names and may be an owner
    /// (STATUS_INVALID_OWNER), the primary group one it names (STATUS_INVALID_PRIMARY_GROUP), the
    /// ACL well formed (STATUS_INVALID_ACL), and what is set must fit the token's dynamic part
    /// (STATUS_ALLOTTED_SPACE_EXCEEDED); the session id needs the TCB privilege held
    /// (STATUS_PRIVILEGE_NOT_HELD).
    #[cfg_attr(not(test), allow(dead_code))] // wired to its service's export when that lands
    pub fn set_information_token(
        _call: &mut NtCall,
        handle: Handle,
        class: u32,
        information: UserAddr,
        length: u32,
    ) -> NtResult {
        information.probe(length)?;
        let (class, needed) = set_class(class)?;
        let (token, _) = token_of(handle.raw(), needed)?;
        let result = match class {
            SetClass::Owner | SetClass::PrimaryGroup => {
                if length < 4 {
                    Err(STATUS_INFO_LENGTH_MISMATCH)
                } else {
                    let sid = read_required_sid(information.cast::<u32>().read()?)?;
                    ob::locked(|directory| {
                        directory.token(token.id()).map(|body| match class {
                            SetClass::Owner => body.set_owner(sid.as_slice()),
                            _ => body.set_primary_group(sid.as_slice()),
                        })
                    })
                    .ok_or(STATUS_INVALID_HANDLE)?
                }
            }
            SetClass::DefaultDacl => {
                if length < 4 {
                    Err(STATUS_INFO_LENGTH_MISMATCH)
                } else {
                    let acl = read_acl(information.cast::<u32>().read()?)?;
                    ob::locked(|directory| {
                        directory.token(token.id()).map(|body| {
                            body.set_default_dacl(acl.as_ref().map(|acl| crate::sec::bytes(acl)))
                        })
                    })
                    .ok_or(STATUS_INVALID_HANDLE)?
                }
            }
            SetClass::SessionId => {
                if length != 4 {
                    Err(STATUS_INFO_LENGTH_MISMATCH)
                } else {
                    let session = information.cast::<u32>().read()?;
                    let caller = crate::process::current().object();
                    let tcb_held = ob::locked(|directory| {
                        directory
                            .process_token(caller)
                            .and_then(|id| directory.token(id))
                            .map(|body| body.enabled(se::SE_TCB_PRIVILEGE))
                            .unwrap_or(false)
                    });
                    ob::locked(|directory| {
                        directory
                            .token(token.id())
                            .map(|body| body.set_session_id(session, tcb_held))
                    })
                    .ok_or(STATUS_INVALID_HANDLE)?
                }
            }
        };
        drop(token);
        result.map(|_| STATUS_SUCCESS)
    }

    /// NtDuplicateToken: a new token, a copy of the one `existing` names (opened with
    /// TOKEN_DUPLICATE), of type `kind` (TokenPrimary or TokenImpersonation: another is
    /// STATUS_INVALID_PARAMETER, before the handle is looked at), its handle granted the rights
    /// asked for into NewTokenHandle (the existing handle's granted access when none is asked
    /// for). An impersonation copy's level is the ObjectAttributes' SECURITY_QUALITY_OF_SERVICE's,
    /// or the source token's own when there is none; a level past SecurityDelegation, above an
    /// impersonation source's own, or a primary copy of a source below impersonation level, is
    /// STATUS_BAD_IMPERSONATION_LEVEL. The attributes' OBJ_INHERIT makes the handle inheritable.
    /// EffectiveOnly is not honoured: F2K's tokens hold no disabled group, and a copy keeps the
    /// disabled privileges.
    pub fn duplicate_token(
        call: &mut NtCall,
        existing: Handle,
        desired: u32,
        attributes: UserAddr,
        _effective_only: bool,
        kind: u32,
        slot: UserPtr<u32>,
    ) -> NtResult {
        if slot.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        slot.addr().probe(4)?;
        if kind != se::TOKEN_PRIMARY && kind != se::TOKEN_IMPERSONATION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (qos_level, inherit) = quality_of_service(attributes)?;
        let (token, access) = token_of(existing.raw(), TOKEN_DUPLICATE)?;
        let body = ob::locked(|directory| directory.token(token.id()).copied())
            .ok_or(STATUS_INVALID_HANDLE)?;
        // Without a quality of service, the copy takes the source token's own level.
        let level = qos_level.unwrap_or(body.level);
        let copy = match body.duplicate(kind, level) {
            Ok(copy) => copy,
            Err(status) => {
                drop(token);
                return Err(status);
            }
        };
        let copy = ob::locked(|directory| directory.create_token(copy))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        drop(token);
        let caller = call.process();
        let access = if desired == 0 {
            access
        } else {
            granted(desired)
        };
        let handle = ob::publish(caller, copy, access, inherit)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
            .get();
        if slot.write(handle).is_err() {
            caller.close_handle(handle);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(STATUS_SUCCESS)
    }

    /// An OBJECT_ATTRIBUTES' impersonation level (its SECURITY_QUALITY_OF_SERVICE's dword at
    /// offset 4; None for no attributes, no quality of service, or one whose length is neither
    /// the plain nor the advanced one — that length is STATUS_INVALID_PARAMETER) and whether it
    /// asks for an inheritable handle.
    pub(crate) fn quality_of_service(
        attributes: UserAddr,
    ) -> Result<(Option<u32>, bool), NtStatus> {
        if attributes.is_null() {
            return Ok((None, false));
        }
        let header = attributes.cast::<rtl::nt::ObjectAttributes<u32>>().read()?;
        let inherit = header.attributes & super::super::attributes::OBJ_INHERIT != 0;
        let quality = UserAddr(header.security_quality_of_service);
        if quality.is_null() {
            return Ok((None, inherit));
        }
        // sizeof(SECURITY_QUALITY_OF_SERVICE) and the advanced one's, on the target's 32 bits.
        const QOS: u32 = 12;
        const ADVANCED_QOS: u32 = 20;
        let length = quality.cast::<u32>().read()?;
        if length != QOS && length != ADVANCED_QOS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok((Some(quality.offset(4).cast::<u32>().read()?), inherit))
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
        set_information_token(Handle, u32, UserAddr, u32);
        duplicate_token(Handle, u32, UserAddr, bool, u32, UserPtr<u32>);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectId;
    use crate::se::{self, Class};

    const BASE: u32 = 0x0040_1000;

    fn token() -> se::TokenBody {
        se::TokenBody::of(ObjectId {
            kind: crate::ob::ObjectType::Process,
            index: 1,
            generation: 0,
        })
    }

    fn answer(token: &se::TokenBody, class: Class) -> se::Reply {
        token.information(class, BASE).unwrap()
    }

    fn word(reply: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(reply[at..at + 4].try_into().unwrap())
    }

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

    /// Every class to TokenSessionId is answered, TokenSource with TOKEN_QUERY_SOURCE, the others
    /// with TOKEN_QUERY; the three past it are not implemented, and a class Windows 2000 does not
    /// have (0, 16, 99) is STATUS_INVALID_INFO_CLASS.
    #[test]
    fn the_classes_answered_and_their_rights() {
        assert_eq!(query_class(1), Ok((se::Class::User, TOKEN_QUERY)));
        assert_eq!(query_class(7), Ok((se::Class::Source, TOKEN_QUERY_SOURCE)));
        assert_eq!(query_class(12), Ok((se::Class::SessionId, TOKEN_QUERY)));
        assert_eq!(query_class(13), Err(STATUS_NOT_IMPLEMENTED));
        for class in [0, 16, 99] {
            assert_eq!(query_class(class), Err(STATUS_INVALID_INFO_CLASS));
        }
    }

    /// TokenPrivileges is class 3; a class past Windows 2000's is STATUS_INVALID_INFO_CLASS.
    #[test]
    fn the_token_classes_are_windows_2000s() {
        assert_eq!(TokenClass::try_from(3), Ok(TokenClass::Privileges));
        assert_eq!(TokenClass::try_from(16), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(TokenClass::try_from(0), Err(STATUS_INVALID_INFO_CLASS));
    }

    /// The settable classes and their rights: the owner, the primary group and the default DACL
    /// need TOKEN_ADJUST_DEFAULT, the session id that with TOKEN_ADJUST_SESSIONID; every other
    /// class — the read-only ones, the ones past TokenSessionId, a number Windows 2000 does not
    /// have — is STATUS_INVALID_INFO_CLASS, answered before the handle is looked at.
    #[test]
    fn the_settable_classes_and_their_rights() {
        assert_eq!(set_class(4), Ok((SetClass::Owner, TOKEN_ADJUST_DEFAULT)));
        assert_eq!(
            set_class(5),
            Ok((SetClass::PrimaryGroup, TOKEN_ADJUST_DEFAULT))
        );
        assert_eq!(
            set_class(6),
            Ok((SetClass::DefaultDacl, TOKEN_ADJUST_DEFAULT))
        );
        assert_eq!(
            set_class(12),
            Ok((
                SetClass::SessionId,
                TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
            ))
        );
        for class in [1, 2, 3, 7, 8, 9, 10, 11, 13, 14, 15, 0, 16, 0xFFFF] {
            assert_eq!(set_class(class), Err(STATUS_INVALID_INFO_CLASS), "{class}");
        }
    }

    /// The default-adjusting rights are specific rights: a request naming them is granted them as
    /// they are, and the write and all-access masks carry them.
    #[test]
    fn the_adjust_default_rights_are_granted() {
        assert_eq!(granted(TOKEN_ADJUST_DEFAULT), 0x80);
        assert_eq!(
            granted(TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID),
            0x180
        );
        assert!(TOKEN_WRITE & TOKEN_ADJUST_DEFAULT != 0);
        assert!(TOKEN_ALL_ACCESS & TOKEN_ADJUST_SESSIONID != 0);
    }
    /// A well-formed ACL of `size` bytes: its header, then one ACE of the rest of an unrecognized
    /// type (which carries no SID to validate).
    fn big_acl(size: usize) -> Vec<u8> {
        let mut acl = vec![0u8; size];
        acl[0] = 2;
        acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
        acl[4..6].copy_from_slice(&1u16.to_le_bytes());
        acl[8] = 0x10;
        acl[10..12].copy_from_slice(&((size - 8) as u16).to_le_bytes());
        acl
    }

    /// The set paths round trip: the owner to the user, the primary group to another group, the
    /// default DACL to a new one and to none, the session id with the TCB privilege held.
    #[test]
    fn the_set_paths_round_trip() {
        let mut token = token();
        token.set_owner(&se::sid_bytes(&se::USER)).unwrap();
        let owner = answer(&token, Class::Owner);
        assert_eq!(
            (owner.len(), word(&owner, 0)),
            (4 + se::USER.size(), BASE + 4)
        );
        assert!(se::USER.matches(&owner[4..]));
        token.set_primary_group(&se::sid_bytes(&se::USERS)).unwrap();
        assert!(se::USERS.matches(&answer(&token, Class::PrimaryGroup)[4..]));
        // An ACL of its header alone, no ACEs, is well formed.
        let empty = [2, 0, 8, 0, 0, 0, 0, 0];
        token.set_default_dacl(Some(&empty)).unwrap();
        let dacl = answer(&token, Class::DefaultDacl);
        assert_eq!((dacl.len(), word(&dacl, 0)), (12, BASE + 4));
        assert_eq!(&dacl[4..], empty);
        token.set_default_dacl(None).unwrap();
        let none = answer(&token, Class::DefaultDacl);
        assert_eq!(
            (none.len(), word(&none, 0)),
            (4, 0),
            "a NULL DACL's pointer"
        );
        assert_eq!(
            token.set_session_id(7, false),
            Err(STATUS_PRIVILEGE_NOT_HELD)
        );
        assert_eq!(
            answer(&token, Class::SessionId).as_slice(),
            0u32.to_le_bytes()
        );
        token.set_session_id(7, true).unwrap();
        assert_eq!(
            answer(&token, Class::SessionId).as_slice(),
            7u32.to_le_bytes()
        );
    }

    /// The set paths' refusals: a malformed SID is STATUS_INVALID_SID; an owner that is neither
    /// the user nor an owner group, or a SID the token does not name, is STATUS_INVALID_OWNER; a
    /// primary group the token does not name is STATUS_INVALID_PRIMARY_GROUP; a malformed ACL is
    /// STATUS_INVALID_ACL; what does not fit the token's dynamic part is
    /// STATUS_ALLOTTED_SPACE_EXCEEDED.
    #[test]
    fn the_set_paths_refuse() {
        let mut token = token();
        let malformed = [0u8, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0];
        assert_eq!(token.set_owner(&malformed), Err(se::STATUS_INVALID_SID));
        assert_eq!(
            token.set_primary_group(&malformed),
            Err(se::STATUS_INVALID_SID)
        );
        assert_eq!(
            token.set_owner(&se::sid_bytes(&se::USERS)),
            Err(se::STATUS_INVALID_OWNER)
        );
        let stranger = se::sid_bytes(&se::Sid {
            authority: 5,
            sub: &[99],
        });
        assert_eq!(token.set_owner(&stranger), Err(se::STATUS_INVALID_OWNER));
        assert_eq!(
            token.set_primary_group(&stranger),
            Err(se::STATUS_INVALID_PRIMARY_GROUP)
        );
        // A size that disagrees with the buffer, an unknown revision, an ACE past the ACL's end,
        // a known ACE whose SID is malformed.
        assert_eq!(
            token.set_default_dacl(Some(&[2, 0, 9, 0, 0, 0, 0, 0])),
            Err(se::STATUS_INVALID_ACL)
        );
        assert_eq!(
            token.set_default_dacl(Some(&[3, 0, 8, 0, 0, 0, 0, 0])),
            Err(se::STATUS_INVALID_ACL)
        );
        let overrun = [2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0];
        assert_eq!(
            token.set_default_dacl(Some(&overrun)),
            Err(se::STATUS_INVALID_ACL)
        );
        let bad_sid_ace = [2, 0, 20, 0, 1, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            token.set_default_dacl(Some(&bad_sid_ace)),
            Err(se::STATUS_INVALID_ACL)
        );
        // A well-formed ACL taking the whole dynamic part fits (the default DACL's 52 bytes and
        // the primary group's 28 leave room for exactly 472); more does not.
        token.set_default_dacl(Some(&big_acl(468))).unwrap();
        assert_eq!(answer(&token, Class::DefaultDacl).len(), 4 + 468);
        token.set_default_dacl(Some(&big_acl(472))).unwrap();
        assert_eq!(
            token.set_default_dacl(Some(&big_acl(474))),
            Err(se::STATUS_ALLOTTED_SPACE_EXCEEDED)
        );
        // With the dynamic part full, a shorter primary group fits; then a longer one or a bigger
        // DACL does not.
        token.set_primary_group(&se::sid_bytes(&se::USERS)).unwrap();
        token.set_default_dacl(Some(&big_acl(484))).unwrap();
        assert_eq!(
            token.set_default_dacl(Some(&big_acl(486))),
            Err(se::STATUS_ALLOTTED_SPACE_EXCEEDED)
        );
        assert_eq!(
            token.set_primary_group(&se::sid_bytes(&se::PRIMARY_GROUP)),
            Err(se::STATUS_ALLOTTED_SPACE_EXCEEDED)
        );
    }
}
