//! The audit-alarm services: the Nt*AuditAlarm family, over the same access-check walk the
//! plain NtAccessCheck* services run ([`crate::nt::seccheck`]). advapi32's
//! AccessCheckAndAuditAlarm* wrappers are Win32 code over the plain services, as on
//! Windows 2000; these are the native forms.
//!
//! F2K keeps no event log, so no audit or alarm is ever generated. The alarm-only calls
//! therefore answer STATUS_SUCCESS and probe nothing (the subsystem, object-type and
//! object names, the handle id, the audit type, the flags and the object-creation flag are
//! audit-only and dropped); NtOpenObjectAuditAlarm still writes its GenerateOnClose
//! out-param, FALSE — nothing is ever queued to fire on close. The AccessCheck ones run
//! the walk over the calling process's token (F2K's threads never impersonate, so it is
//! the caller's effective one; the ByHandle form takes the ClientToken handle instead)
//! and report through GrantedAccess/AccessStatus, returning the walk's status; the
//! result-list forms answer one pair per object-type-list entry. Those four need the
//! calling process's handle table, so the host builds serve them as unserved; the rest
//! touch only the caller's memory and run on the host too.

use super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// GenerateOnClose's answer: no alarm is ever generated, so nothing fires on close.
#[cfg_attr(not(test), allow(dead_code))] // read through the services below
const GENERATE_ON_CLOSE: u8 = 0;

/// NtCloseObjectAuditAlarm: no alarm to raise when the handle is closed.
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn close_object_audit_alarm(
    _: &mut NtCall,
    _subsystem_name: UserAddr,
    _handle_id: UserAddr,
    _generate_on_close: bool,
) -> NtResult {
    Ok(STATUS_SUCCESS)
}

/// NtDeleteObjectAuditAlarm: no alarm to raise when the object is deleted.
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn delete_object_audit_alarm(
    _: &mut NtCall,
    _subsystem_name: UserAddr,
    _handle_id: UserAddr,
    _generate_on_close: bool,
) -> NtResult {
    Ok(STATUS_SUCCESS)
}

/// NtPrivilegeObjectAuditAlarm: no alarm to raise for the privileged operation on the
/// already-open object.
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn privilege_object_audit_alarm(
    _: &mut NtCall,
    _subsystem_name: UserAddr,
    _handle_id: UserAddr,
    _client_token: Handle,
    _desired_access: u32,
    _privileges: UserAddr,
    _access_granted: bool,
) -> NtResult {
    Ok(STATUS_SUCCESS)
}

/// NtPrivilegedServiceAuditAlarm: no alarm to raise for the privileged service.
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn privileged_service_audit_alarm(
    _: &mut NtCall,
    _subsystem_name: UserAddr,
    _service_name: UserAddr,
    _client_token: Handle,
    _privileges: UserAddr,
    _access_granted: bool,
) -> NtResult {
    Ok(STATUS_SUCCESS)
}

/// NtOpenObjectAuditAlarm: no alarm to raise when the object is opened; GenerateOnClose
/// comes back FALSE. A null or unwritable out-param is STATUS_ACCESS_VIOLATION.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn open_object_audit_alarm(
    _: &mut NtCall,
    _subsystem_name: UserAddr,
    _handle_id: UserAddr,
    _object_type_name: UserAddr,
    _object_name: UserAddr,
    _security_descriptor: UserAddr,
    _client_token: Handle,
    _desired_access: u32,
    _granted_access: u32,
    _privileges: UserAddr,
    _object_creation: bool,
    _access_granted: bool,
    generate_on_close: UserPtr<u8>,
) -> NtResult {
    if generate_on_close.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    generate_on_close.write(GENERATE_ON_CLOSE)?;
    Ok(STATUS_SUCCESS)
}

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
pub use services::*;

/// The access-check-and-audit-alarm services, on the calling process's token (or the
/// ByHandle form's ClientToken handle) and the caller's memory.
#[cfg(target_arch = "x86")]
mod services {
    use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use super::super::object::{is_console_handle, CURRENT_PROCESS, CURRENT_THREAD};
    use super::*;
    use crate::nt::seccheck::{self, Answer, CheckInput};
    use crate::ob::{self, ObRef};
    use crate::sec::sd::{self, Memory};
    use crate::sec::{self, GenericMapping, Guid, Owned};
    use crate::se;
    use rtl::array_vec::ArrayVec;
    use rtl::nt::access::TOKEN_QUERY;

    /// The most object types a captured list holds.
    const MAX_TYPE_LIST: usize = 128;
    /// An OBJECT_TYPE_LIST entry's bytes: its level, a spare word and its GUID's address.
    const TYPE_ENTRY: usize = 8;
    /// The highest level an entry may name.
    const MAX_LEVEL: u16 = 4;

    /// The caller's address space as a descriptor-capture seam: the probe checks the
    /// alignment the read needs, then that the range is the caller's.
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

    /// The security descriptor at `at`, captured self-relative into a fresh buffer (None
    /// for a null pointer): every range probed, each part sized from its own header and
    /// validated.
    fn capture_sd(at: UserAddr) -> Result<Option<Owned>, NtStatus> {
        if at.is_null() {
            return Ok(None);
        }
        let mem = UserMemory;
        let len = sd::length(&mem, at.raw()).ok_or(STATUS_ACCESS_VIOLATION)?;
        let mut out = sec::allocate(len as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut written = 0u32;
        let status =
            sd::capture(&mem, at.raw(), true, false, sec::bytes_mut(&mut out), &mut written);
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
        if header[0] & 0x0F != sec::REVISION || usize::from(header[1]) > sec::MAX_SUB_AUTHORITIES
        {
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

    /// The caller's object type list at `list`, `count` entries, captured as its GUIDs in
    /// order: a null list with a count, or a level past the maximum, is
    /// STATUS_INVALID_PARAMETER, a list too long for the capture
    /// STATUS_INSUFFICIENT_RESOURCES.
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
            let guid_at =
                UserAddr(u32::from_le_bytes(entries[at + 4..at + 8].try_into().unwrap()));
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

    /// Probe the GenerateOnClose out-param; a null pointer is a fault.
    fn probe_on_close(generate_on_close: UserPtr<u8>) -> Result<(), NtStatus> {
        if generate_on_close.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        generate_on_close.addr().probe(1)?;
        Ok(())
    }

    /// The calling process's token, copied out of the directory; None when it has none (the
    /// walk then refuses with STATUS_INVALID_HANDLE). F2K's threads never impersonate, so
    /// this is the caller's effective token.
    fn caller_token() -> Option<se::TokenBody> {
        let process = crate::process::current().object();
        ob::locked(|directory| {
            directory
                .process_token(process)
                .and_then(|id| directory.token(id))
                .copied()
        })
    }

    /// The token `handle` names in the calling process (the ByHandle form's ClientToken),
    /// referenced, its body copied out: the handle rules of any token handle (a pseudo- or
    /// console handle names none).
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
        let id = seccheck::token_of_entry(Some(entry), needed)?;
        let reference = ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
        let body = ob::locked(|directory| directory.token(id).copied())
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok((reference, body))
    }

    /// Apply the walk's answer to a single-result call's out-params: the granted mask, the
    /// access status and GenerateOnClose FALSE; a parameter-level refusal is the call's
    /// return.
    fn apply(
        answer: Answer,
        granted_access: UserPtr<u32>,
        access_status: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        match answer {
            Answer::Refused { status, .. } => Err(status),
            Answer::Checked(answer) => {
                granted_access.write(answer.granted)?;
                access_status.write(answer.access_status.0)?;
                generate_on_close.write(GENERATE_ON_CLOSE)?;
                Ok(STATUS_SUCCESS)
            }
        }
    }

    /// One walk over the captured inputs (the alarm half is a no-op): the out-params on a
    /// ran walk, the refusal's status otherwise.
    fn single_check(
        token: Option<&se::TokenBody>,
        security_descriptor: UserAddr,
        principal_self: Option<&[u8]>,
        object_types: &[Guid],
        desired_access: u32,
        mapping: GenericMapping,
        granted_access: UserPtr<u32>,
        access_status: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        let sd = capture_sd(security_descriptor)?;
        let input = CheckInput {
            sd: sd.as_ref().map(|sd| sec::bytes(sd)),
            token,
            desired: desired_access,
            mapping,
            principal_self,
            object_types,
            privilege_room: seccheck::privilege_set_size(2),
        };
        apply(
            seccheck::run(&input),
            granted_access,
            access_status,
            generate_on_close,
        )
    }

    /// The result-list walk shared by the two result-list services: one walk per list
    /// entry, each with the types up to and including that entry, a GrantedAccess/
    /// AccessStatus pair written per entry.
    #[allow(clippy::too_many_arguments)]
    fn result_list(
        token: Option<&se::TokenBody>,
        security_descriptor: UserAddr,
        principal_self_sid: UserAddr,
        desired_access: u32,
        object_type_list: UserAddr,
        object_type_list_length: u32,
        generic_mapping: UserAddr,
        granted_access_list: UserPtr<u32>,
        access_status_list: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
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
        probe_on_close(generate_on_close)?;
        let mapping = read_mapping(generic_mapping)?;
        let object_types = capture_type_list(object_type_list, object_type_list_length)?;
        let principal_self = read_sid(principal_self_sid)?;
        let sd = capture_sd(security_descriptor)?;
        let sd_bytes = sd.as_ref().map(|sd| sec::bytes(sd));
        let self_bytes = principal_self.as_ref().map(|sid| sid.as_slice());
        let mut granted_out = [0u32; MAX_TYPE_LIST];
        let mut status_out = [0u32; MAX_TYPE_LIST];
        for i in 0..object_type_list_length as usize {
            let input = CheckInput {
                sd: sd_bytes,
                token,
                desired: desired_access,
                mapping,
                principal_self: self_bytes,
                object_types: &object_types[..=i],
                privilege_room: seccheck::privilege_set_size(2),
            };
            match seccheck::run(&input) {
                Answer::Refused { status, .. } => return Err(status),
                Answer::Checked(answer) => {
                    granted_out[i] = answer.granted;
                    status_out[i] = answer.access_status.0;
                }
            }
        }
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
        generate_on_close.write(GENERATE_ON_CLOSE)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtAccessCheckAndAuditAlarm: the same walk as NtAccessCheck over the calling
    /// process's token; the alarm half is a no-op.
    #[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
    pub fn access_check_and_audit_alarm(
        _: &mut NtCall,
        _subsystem_name: UserAddr,
        _handle_id: UserAddr,
        _object_type_name: UserAddr,
        _object_name: UserAddr,
        security_descriptor: UserAddr,
        desired_access: u32,
        generic_mapping: UserAddr,
        _object_creation: bool,
        granted_access: UserPtr<u32>,
        access_status: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        probe_out(granted_access, 4)?;
        probe_out(access_status, 4)?;
        probe_on_close(generate_on_close)?;
        let mapping = read_mapping(generic_mapping)?;
        let token = caller_token();
        single_check(
            token.as_ref(),
            security_descriptor,
            None,
            &[],
            desired_access,
            mapping,
            granted_access,
            access_status,
            generate_on_close,
        )
    }

    /// NtAccessCheckByTypeAndAuditAlarm: as NtAccessCheckByType, over the calling
    /// process's token; the alarm half is a no-op.
    #[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
    #[allow(clippy::too_many_arguments)]
    pub fn access_check_by_type_and_audit_alarm(
        _: &mut NtCall,
        _subsystem_name: UserAddr,
        _handle_id: UserAddr,
        _object_type_name: UserAddr,
        _object_name: UserAddr,
        security_descriptor: UserAddr,
        principal_self_sid: UserAddr,
        desired_access: u32,
        _audit_type: u32,
        _flags: u32,
        object_type_list: UserAddr,
        object_type_list_length: u32,
        generic_mapping: UserAddr,
        _object_creation: bool,
        granted_access: UserPtr<u32>,
        access_status: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        probe_out(granted_access, 4)?;
        probe_out(access_status, 4)?;
        probe_on_close(generate_on_close)?;
        let mapping = read_mapping(generic_mapping)?;
        let token = caller_token();
        let object_types = capture_type_list(object_type_list, object_type_list_length)?;
        let principal_self = read_sid(principal_self_sid)?;
        single_check(
            token.as_ref(),
            security_descriptor,
            principal_self.as_ref().map(|sid| sid.as_slice()),
            object_types.as_slice(),
            desired_access,
            mapping,
            granted_access,
            access_status,
            generate_on_close,
        )
    }

    /// NtAccessCheckByTypeResultListAndAuditAlarm: as NtAccessCheckByTypeResultList over
    /// the calling process's token; GrantedAccess and AccessStatus are arrays of
    /// ObjectTypeListLength entries.
    #[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
    #[allow(clippy::too_many_arguments)]
    pub fn access_check_by_type_result_list_and_audit_alarm(
        _: &mut NtCall,
        _subsystem_name: UserAddr,
        _handle_id: UserAddr,
        _object_type_name: UserAddr,
        _object_name: UserAddr,
        security_descriptor: UserAddr,
        principal_self_sid: UserAddr,
        desired_access: u32,
        _audit_type: u32,
        _flags: u32,
        object_type_list: UserAddr,
        object_type_list_length: u32,
        generic_mapping: UserAddr,
        _object_creation: bool,
        granted_access_list: UserPtr<u32>,
        access_status_list: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        let token = caller_token();
        result_list(
            token.as_ref(),
            security_descriptor,
            principal_self_sid,
            desired_access,
            object_type_list,
            object_type_list_length,
            generic_mapping,
            granted_access_list,
            access_status_list,
            generate_on_close,
        )
    }

    /// NtAccessCheckByTypeResultListAndAuditAlarmByHandle: as the result-list form, but
    /// the walk runs over the ClientToken handle's token.
    #[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
    #[allow(clippy::too_many_arguments)]
    pub fn access_check_by_type_result_list_and_audit_alarm_by_handle(
        _: &mut NtCall,
        _subsystem_name: UserAddr,
        _handle_id: UserAddr,
        client_token: Handle,
        _object_type_name: UserAddr,
        _object_name: UserAddr,
        security_descriptor: UserAddr,
        principal_self_sid: UserAddr,
        desired_access: u32,
        _audit_type: u32,
        _flags: u32,
        object_type_list: UserAddr,
        object_type_list_length: u32,
        generic_mapping: UserAddr,
        _object_creation: bool,
        granted_access_list: UserPtr<u32>,
        access_status_list: UserPtr<u32>,
        generate_on_close: UserPtr<u8>,
    ) -> NtResult {
        let (_reference, body) = token_of(client_token.raw(), TOKEN_QUERY)?;
        result_list(
            Some(&body),
            security_descriptor,
            principal_self_sid,
            desired_access,
            object_type_list,
            object_type_list_length,
            generic_mapping,
            granted_access_list,
            access_status_list,
            generate_on_close,
        )
    }
}

/// The host builds' access-check-and-audit-alarm services (see `nt`'s `unserved`): they
/// run on the target's handle table and process.
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        access_check_and_audit_alarm(UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, u32, UserAddr, bool, UserPtr<u32>, UserPtr<u32>, UserPtr<u8>);
        access_check_by_type_and_audit_alarm(UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, u32, u32, u32, UserAddr, u32, UserAddr, bool, UserPtr<u32>, UserPtr<u32>, UserPtr<u8>);
        access_check_by_type_result_list_and_audit_alarm(UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, u32, u32, u32, UserAddr, u32, UserAddr, bool, UserPtr<u32>, UserPtr<u32>, UserPtr<u8>);
        access_check_by_type_result_list_and_audit_alarm_by_handle(UserAddr, UserAddr, Handle, UserAddr, UserAddr, UserAddr, UserAddr, u32, u32, u32, UserAddr, u32, UserAddr, bool, UserPtr<u32>, UserPtr<u32>, UserPtr<u8>);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::TrapFrame;
    use crate::user::syscall::host::{install, UserMemory};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Mapped user memory at [BASE, BASE + len): anything else faults.
    const BASE: u32 = 0x0050_0000;

    struct Page(Vec<u8>);

    impl UserMemory for Page {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            bytes.copy_from_slice(
                self.0
                    .get(at..at + bytes.len())
                    .ok_or(STATUS_ACCESS_VIOLATION)?,
            );
            Ok(())
        }

        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            self.0
                .get_mut(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?
                .copy_from_slice(bytes);
            Ok(())
        }
    }

    /// The alarm-only services answer STATUS_SUCCESS and probe nothing: even null
    /// arguments pass, the names and handle id being audit-only and dropped.
    #[test]
    fn the_alarm_only_services_are_no_op_successes() {
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            close_object_audit_alarm(&mut call, UserAddr(0), UserAddr(0), false),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            delete_object_audit_alarm(&mut call, UserAddr(0), UserAddr(0), true),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            privilege_object_audit_alarm(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                Handle(0x40),
                0x1,
                UserAddr(0),
                false
            ),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            privileged_service_audit_alarm(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                Handle(0x40),
                UserAddr(0),
                true
            ),
            Ok(STATUS_SUCCESS)
        );
    }

    /// NtOpenObjectAuditAlarm writes GenerateOnClose FALSE (no alarm is ever generated,
    /// so nothing fires on close); a null or unwritable out-param is
    /// STATUS_ACCESS_VIOLATION.
    #[test]
    fn the_open_writes_generate_on_close_false() {
        let page = Rc::new(RefCell::new(Page(vec![0xAAu8; 0x40])));
        let _installed = install(page.clone());
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        let open = |call: &mut NtCall, at: u32| {
            open_object_audit_alarm(
                call,
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                Handle(0x40),
                0,
                0,
                UserAddr(0),
                false,
                false,
                UserPtr::at(at),
            )
        };
        assert_eq!(open(&mut call, BASE), Ok(STATUS_SUCCESS));
        assert_eq!(page.borrow().0[0], GENERATE_ON_CLOSE);
        assert_eq!(open(&mut call, 0), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(open(&mut call, BASE + 0x1000), Err(STATUS_ACCESS_VIOLATION));
    }

    /// On the host the four access-check-and-audit-alarm services are unserved: they need
    /// the target's handle table, so they answer STATUS_NOT_IMPLEMENTED here.
    #[cfg(not(target_arch = "x86"))]
    #[test]
    fn the_access_check_alarms_are_unserved_on_the_host() {
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        let unserved = [
            access_check_and_audit_alarm(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                0,
                UserAddr(0),
                false,
                UserPtr::at(0),
                UserPtr::at(0),
                UserPtr::at(0),
            ),
            access_check_by_type_and_audit_alarm(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                0,
                0,
                0,
                UserAddr(0),
                0,
                UserAddr(0),
                false,
                UserPtr::at(0),
                UserPtr::at(0),
                UserPtr::at(0),
            ),
            access_check_by_type_result_list_and_audit_alarm(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                0,
                0,
                0,
                UserAddr(0),
                0,
                UserAddr(0),
                false,
                UserPtr::at(0),
                UserPtr::at(0),
                UserPtr::at(0),
            ),
            access_check_by_type_result_list_and_audit_alarm_by_handle(
                &mut call,
                UserAddr(0),
                UserAddr(0),
                Handle(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                UserAddr(0),
                0,
                0,
                0,
                UserAddr(0),
                0,
                UserAddr(0),
                false,
                UserPtr::at(0),
                UserPtr::at(0),
                UserPtr::at(0),
            ),
        ];
        for result in unserved {
            assert_eq!(result, Err(STATUS_NOT_IMPLEMENTED));
        }
    }
}
