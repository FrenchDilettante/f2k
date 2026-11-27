//! The services themselves, on the calling process's handles and the caller's memory:
//! the captures (the descriptor, the SID, the type list, the mapping), the handle lookup, and
//! the out-param writes.

use rtl::nt::access::TOKEN_QUERY;

use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
use super::super::object::{is_console_handle, CURRENT_PROCESS, CURRENT_THREAD};
use super::*;
use crate::ob::{self, ObRef};
use crate::sec::sd::{self, Memory};
use crate::sec::{self, Owned};

/// The most object types a captured list holds.
const MAX_TYPE_LIST: usize = 128;
/// An OBJECT_TYPE_LIST entry's bytes: its level, a spare word and its GUID's address.
const TYPE_ENTRY: usize = 8;
/// The highest level an entry may name.
const MAX_LEVEL: u16 = 4;

/// The token `handle` names in the calling process: looked up as any handle (the pseudo- and
/// console handles name no token), referenced, its body copied out.
fn token_of(handle: u32, needed: u32) -> Result<(ObRef, se::TokenBody), NtStatus> {
    if handle == CURRENT_PROCESS || handle == CURRENT_THREAD {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if is_console_handle(handle) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let entry = calling_process()
        .lookup_handle(handle)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let id = token_of_entry(Some(entry), needed)?;
    let reference = ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
    let body = ob::locked(|directory| directory.token(id).copied()).ok_or(STATUS_INVALID_HANDLE)?;
    Ok((reference, body))
}

/// The caller's address space as a descriptor-capture seam: the probe checks the alignment
/// the read needs, then that the range is the caller's.
struct UserMemory;

impl Memory for UserMemory {
    fn probe(&self, addr: u32, align: u32, len: u32) -> Result<(), NtStatus> {
        if addr % align != 0 {
            return Err(sd::STATUS_DATATYPE_MISALIGNMENT);
        }
        UserAddr(addr).probe(len)?;
        Ok(())
    }

    fn read(&self, addr: u32, align: u32, buf: &mut [u8]) -> Result<(), NtStatus> {
        if addr % align != 0 {
            return Err(sd::STATUS_DATATYPE_MISALIGNMENT);
        }
        UserAddr(addr).read(buf)?;
        Ok(())
    }
}

/// The security descriptor at `at`, captured self-relative into a fresh buffer (None for a
/// null pointer): every range probed, each part sized from its own header and validated.
fn capture_sd(at: UserAddr) -> Result<Option<Owned>, NtStatus> {
    if at.is_null() {
        return Ok(None);
    }
    let mem = UserMemory;
    let len = sd::length(&mem, at.raw()).ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut out = sec::allocate(len as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut written = 0u32;
    let status = sd::capture(
        &mem,
        at.raw(),
        true,
        false,
        sec::bytes_mut(&mut out),
        &mut written,
    );
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    Ok(Some(out))
}

/// The SID at `ptr` (None for a null pointer), read and validated: a malformed one is
/// STATUS_INVALID_SID.
fn read_sid(ptr: UserAddr) -> Result<Option<se::SidBytes>, NtStatus> {
    if ptr.is_null() {
        return Ok(None);
    }
    let mut header = [0u8; 2];
    ptr.read(&mut header)?;
    if header[0] & 0x0F != sec::REVISION || usize::from(header[1]) > sec::MAX_SUB_AUTHORITIES {
        return Err(sd::STATUS_INVALID_SID);
    }
    let mut sid = se::SidBytes::new();
    sid.try_extend_default(sec::length_required(usize::from(header[1])))
        .map_err(|_| sd::STATUS_INVALID_SID)?;
    ptr.read(sid.as_mut_slice())?;
    if !sec::sid::is_valid(sid.as_slice()) {
        return Err(sd::STATUS_INVALID_SID);
    }
    Ok(Some(sid))
}

/// The caller's object type list at `list`, `count` entries, captured as its GUIDs in order:
/// a null list with a count, or a level past the maximum, is STATUS_INVALID_PARAMETER, a
/// list too long for the capture STATUS_INSUFFICIENT_RESOURCES.
fn capture_type_list(
    list: UserAddr,
    count: u32,
) -> Result<ArrayVec<Guid, MAX_TYPE_LIST>, NtStatus> {
    let mut guids = ArrayVec::new();
    if count == 0 {
        return Ok(guids);
    }
    if list.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if count as usize > MAX_TYPE_LIST {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let bytes = count as usize * TYPE_ENTRY;
    list.probe(bytes as u32)?;
    let mut entries = sec::allocate(bytes).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    list.read(sec::bytes_mut(&mut entries))?;
    let entries = sec::bytes(&entries);
    for i in 0..count as usize {
        let at = i * TYPE_ENTRY;
        if u16::from_le_bytes([entries[at], entries[at + 1]]) > MAX_LEVEL {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let guid_at = UserAddr(u32::from_le_bytes(
            entries[at + 4..at + 8].try_into().unwrap(),
        ));
        let mut raw = [0u8; 16];
        guid_at.read(&mut raw)?;
        guids.push(Guid {
            data1: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            data2: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
            data3: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
            data4: raw[8..16].try_into().unwrap(),
        });
    }
    Ok(guids)
}

/// The GENERIC_MAPPING at `at`, read whole (16 bytes).
fn read_mapping(at: UserAddr) -> Result<GenericMapping, NtStatus> {
    at.probe(16)?;
    let mut raw = [0u8; 16];
    at.read(&mut raw)?;
    Ok(GenericMapping {
        generic_read: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        generic_write: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
        generic_execute: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
        generic_all: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
    })
}

/// Probe one out-param of `bytes` bytes (an array's worth for the result list); a null
/// pointer is a fault.
fn probe_out(out: UserPtr<u32>, bytes: u32) -> Result<(), NtStatus> {
    if out.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    out.addr().probe(bytes)?;
    Ok(())
}

/// Probe the privilege-set out-params and read the buffer's size, before the handle is
/// looked at.
fn probe_privilege_set(
    privilege_set: UserAddr,
    privilege_set_length: UserPtr<u32>,
) -> Result<(UserAddr, UserPtr<u32>, u32), NtStatus> {
    if privilege_set_length.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    privilege_set_length.addr().probe(4)?;
    let room = privilege_set_length.read()?;
    privilege_set.probe(room)?;
    Ok((privilege_set, privilege_set_length, room))
}

/// Write the privilege set to the caller's buffer: its count, a zero control, the entries.
fn write_privilege_set(
    at: UserAddr,
    used: &ArrayVec<LuidAndAttributes, 2>,
) -> Result<(), NtStatus> {
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&(used.len() as u32).to_le_bytes());
    at.write(&header)?;
    if !used.is_empty() {
        at.offset(8).write(rtl::pod::slice_bytes(used.as_slice()))?;
    }
    Ok(())
}

/// Apply the core's answer to a single-result call: write the privilege set, the granted
/// mask and the access status, or refuse with the status (the size the set takes in
/// PrivilegeSetLength when the buffer is too small).
fn apply(
    answer: Answer,
    privilege_set: UserAddr,
    privilege_set_length: UserPtr<u32>,
    granted_access: UserPtr<u32>,
    access_status: UserPtr<u32>,
) -> NtResult {
    match answer {
        Answer::Refused {
            status,
            privilege_length,
        } => {
            if let Some(len) = privilege_length {
                privilege_set_length.write(len)?;
            }
            Err(status)
        }
        Answer::Checked(answer) => {
            write_privilege_set(privilege_set, &answer.used)?;
            granted_access.write(answer.granted)?;
            access_status.write(answer.access_status.0)?;
            Ok(STATUS_SUCCESS)
        }
    }
}

/// NtAccessCheck: the walk over the descriptor's DACL against the token `token` names, the
/// granted mask and access status into the caller's out-params.
pub fn access_check(
    _: &mut NtCall,
    security_descriptor: UserAddr,
    token: Handle,
    desired_access: u32,
    generic_mapping: UserAddr,
    privilege_set: UserAddr,
    privilege_set_length: UserPtr<u32>,
    granted_access: UserPtr<u32>,
    access_status: UserPtr<u32>,
) -> NtResult {
    probe_out(granted_access, 4)?;
    probe_out(access_status, 4)?;
    let (privilege_set, privilege_set_length, room) =
        probe_privilege_set(privilege_set, privilege_set_length)?;
    let mapping = read_mapping(generic_mapping)?;
    let (_reference, body) = token_of(token.raw(), TOKEN_QUERY)?;
    let sd = capture_sd(security_descriptor)?;
    let input = CheckInput {
        sd: sd.as_ref().map(|sd| sec::bytes(sd)),
        token: Some(&body),
        desired: desired_access,
        mapping,
        principal_self: None,
        object_types: &[],
        privilege_room: room,
    };
    apply(
        run(&input),
        privilege_set,
        privilege_set_length,
        granted_access,
        access_status,
    )
}

/// NtAccessCheckByType: as NtAccessCheck, with the object's principal-self SID (an ACE's
/// principal-self SID stands for it) and the caller's object-type list gating the typed
/// object ACEs.
#[allow(clippy::too_many_arguments)]
pub fn access_check_by_type(
    _: &mut NtCall,
    security_descriptor: UserAddr,
    principal_self_sid: UserAddr,
    token: Handle,
    desired_access: u32,
    object_type_list: UserAddr,
    object_type_list_length: u32,
    generic_mapping: UserAddr,
    privilege_set: UserAddr,
    privilege_set_length: UserPtr<u32>,
    granted_access: UserPtr<u32>,
    access_status: UserPtr<u32>,
) -> NtResult {
    probe_out(granted_access, 4)?;
    probe_out(access_status, 4)?;
    let (privilege_set, privilege_set_length, room) =
        probe_privilege_set(privilege_set, privilege_set_length)?;
    let mapping = read_mapping(generic_mapping)?;
    let (_reference, body) = token_of(token.raw(), TOKEN_QUERY)?;
    let object_types = capture_type_list(object_type_list, object_type_list_length)?;
    let principal_self = read_sid(principal_self_sid)?;
    let sd = capture_sd(security_descriptor)?;
    let input = CheckInput {
        sd: sd.as_ref().map(|sd| sec::bytes(sd)),
        token: Some(&body),
        desired: desired_access,
        mapping,
        principal_self: principal_self.as_ref().map(|sid| sid.as_slice()),
        object_types: object_types.as_slice(),
        privilege_room: room,
    };
    apply(
        run(&input),
        privilege_set,
        privilege_set_length,
        granted_access,
        access_status,
    )
}

/// NtAccessCheckByTypeResultList: as NtAccessCheckByType, but GrantedAccess and AccessStatus
/// are arrays of ObjectTypeListLength entries, one walk per list entry.
#[allow(clippy::too_many_arguments)]
pub fn access_check_by_type_result_list(
    _: &mut NtCall,
    security_descriptor: UserAddr,
    principal_self_sid: UserAddr,
    token: Handle,
    desired_access: u32,
    object_type_list: UserAddr,
    object_type_list_length: u32,
    generic_mapping: UserAddr,
    privilege_set: UserAddr,
    privilege_set_length: UserPtr<u32>,
    granted_access_list: UserPtr<u32>,
    access_status_list: UserPtr<u32>,
) -> NtResult {
    // A result list with no entries is refused before anything is probed.
    if object_type_list_length == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let stride = 4u32
        .checked_mul(object_type_list_length)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    probe_out(granted_access_list, stride)?;
    probe_out(access_status_list, stride)?;
    let (privilege_set, privilege_set_length, room) =
        probe_privilege_set(privilege_set, privilege_set_length)?;
    let mapping = read_mapping(generic_mapping)?;
    let (_reference, body) = token_of(token.raw(), TOKEN_QUERY)?;
    let object_types = capture_type_list(object_type_list, object_type_list_length)?;
    let principal_self = read_sid(principal_self_sid)?;
    let sd = capture_sd(security_descriptor)?;
    let sd_bytes = sd.as_ref().map(|sd| sec::bytes(sd));
    let self_bytes = principal_self.as_ref().map(|sid| sid.as_slice());
    // One walk per list entry, each with the types up to and including it.
    let mut used = ArrayVec::new();
    let mut granted_out = [0u32; MAX_TYPE_LIST];
    let mut status_out = [0u32; MAX_TYPE_LIST];
    for i in 0..object_type_list_length as usize {
        let input = CheckInput {
            sd: sd_bytes,
            token: Some(&body),
            desired: desired_access,
            mapping,
            principal_self: self_bytes,
            object_types: &object_types[..=i],
            privilege_room: room,
        };
        match run(&input) {
            Answer::Refused {
                status,
                privilege_length,
            } => {
                if let Some(len) = privilege_length {
                    privilege_set_length.write(len)?;
                }
                return Err(status);
            }
            Answer::Checked(answer) => {
                used = answer.used;
                granted_out[i] = answer.granted;
                status_out[i] = answer.access_status.0;
            }
        }
    }
    write_privilege_set(privilege_set, &used)?;
    for i in 0..object_type_list_length as usize {
        let at = 4 * i as u32;
        granted_access_list
            .addr()
            .offset(at)
            .write(&granted_out[i].to_le_bytes())?;
        access_status_list
            .addr()
            .offset(at)
            .write(&status_out[i].to_le_bytes())?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtPrivilegeCheck: whether the token `token` names holds the caller's privilege set —
/// every entry when its control carries PRIVILEGE_SET_ALL_NECESSARY, any one otherwise —
/// each held-and-enabled entry marked used in the caller's buffer, the answer in Result.
pub fn privilege_check(
    _: &mut NtCall,
    token: Handle,
    required_privileges: UserAddr,
    result: UserPtr<u32>,
) -> NtResult {
    let (_reference, body) = token_of(token.raw(), TOKEN_QUERY)?;
    required_privileges.probe(8)?;
    let mut header = [0u8; 8];
    required_privileges.read(&mut header)?;
    let count = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    if count > (u32::MAX as usize - 8) / 12 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let bytes = 8 + count * 12;
    required_privileges.probe(bytes as u32)?;
    probe_out(result, 4)?;
    let mut set = sec::allocate(bytes).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    required_privileges.read(sec::bytes_mut(&mut set))?;
    let privileges = match body.information(se::Class::Privileges, 0) {
        Ok(reply) => parse_privileges(&reply),
        Err(status) => return Err(status),
    };
    let held = check_privileges(sec::bytes_mut(&mut set), privileges.as_slice());
    // The entries go back with their used-for-access bits; the header is untouched.
    required_privileges
        .offset(8)
        .write(&sec::bytes(&set)[8..])?;
    result.write(u32::from(held))?;
    Ok(STATUS_SUCCESS)
}
