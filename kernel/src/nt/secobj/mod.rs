//! The object-security services: NtQuerySecurityObject and NtSetSecurityObject, over the
//! security descriptor every object record stores (see `ob::security` and
//! `ob::Directory`'s seam).
//!
//! A query names the parts it wants in its SECURITY_INFORMATION (owner, group, DACL, SACL)
//! and answers with a fresh self-relative descriptor holding just those parts, packed after
//! the header in the order owner, group, DACL, SACL ([`query_reply`]). The size-then-buffer
//! protocol: the size the answer takes goes to LengthNeeded on success and when the buffer is
//! too short (STATUS_BUFFER_TOO_SMALL, nothing written), but not when the handle itself
//! failed. A set captures the caller's descriptor (probed and validated from user mode,
//! always captured) and merges it into the stored one ([`set_merge`]): the parts named are
//! replaced wholesale, the others kept as they were, and the result stored back on the
//! record.
//!
//! The access the two need on the handle: a query needs READ_CONTROL for the owner, group or
//! DACL; a set needs WRITE_OWNER for the owner or group and WRITE_DAC for the DACL. Naming
//! the SACL on either needs the security privilege held enabled in the caller's token
//! (STATUS_PRIVILEGE_NOT_HELD otherwise, see [`privilege_gate`]). A handle naming nothing is
//! STATUS_INVALID_HANDLE, one short of the needed rights STATUS_ACCESS_DENIED.

mod query;
mod set;

pub use query::*;
use rtl::nt::access::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
#[cfg_attr(not(any(test, target_arch = "x86")), allow(unused_imports))]
pub use set::*;

use crate::sec::sd::STATUS_INVALID_SECURITY_DESCR;
use crate::sec::{
    SecurityDescriptor,
    ACCESS_SYSTEM_SECURITY,
    DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
    SECURITY_DESCRIPTOR_REVISION,
    SE_RESTORE_PRIVILEGE,
    SE_SECURITY_PRIVILEGE,
};
#[cfg(test)]
use crate::sec::{
    SECURITY_DESCRIPTOR_MIN_LENGTH,
    SE_DACL_PRESENT,
    SE_GROUP_DEFAULTED,
    SE_OWNER_DEFAULTED,
    SE_SACL_PRESENT,
    SE_SELF_RELATIVE,
};
use crate::status::*;

/// Round a length up to a dword boundary: the alignment the parts are packed with.
pub(crate) const fn align4(len: u32) -> u32 {
    (len + 3) & !3
}

/// The header of a self-relative descriptor in a flat buffer, checked: the header parses,
/// the revision is known and the self-relative flag is set (STATUS_INVALID_SECURITY_DESCR
/// otherwise — the stored and captured descriptors are self-relative by construction).
pub(crate) fn header_relative(bytes: &[u8]) -> Result<SecurityDescriptor, NtStatus> {
    let h = SecurityDescriptor::parse(bytes).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    if h.revision != SECURITY_DESCRIPTOR_REVISION || !h.is_self_relative() {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    Ok(h)
}

/// One part of a self-relative descriptor in a flat buffer: where it sits and its raw length
/// (a SID's by its sub-authority count, an ACL's by its AclSize).
pub(crate) struct Part<'a> {
    pub bytes: &'a [u8],
    pub offset: u32,
    pub raw: u32,
}

impl Part<'_> {
    /// The part's bytes.
    pub fn slice(&self) -> &[u8] {
        let at = self.offset as usize;
        &self.bytes[at..at + self.raw as usize]
    }
}

/// The SID part at `field` (an offset) of the self-relative descriptor in `bytes`; none when
/// the field is zero.
pub(crate) fn sid_part(bytes: &[u8], field: u32) -> Option<Part<'_>> {
    if field == 0 {
        return None;
    }
    let raw = crate::sec::sid::length(bytes.get(field as usize..)?)? as u32;
    Some(Part {
        bytes,
        offset: field,
        raw,
    })
}

/// The ACL part at `field` of the self-relative descriptor in `bytes`, when its `present` flag
/// is set in `control` and the field is non-zero (a null ACL is a present flag with a zero
/// field).
pub(crate) fn acl_part(bytes: &[u8], control: u16, present: u16, field: u32) -> Option<Part<'_>> {
    if control & present == 0 || field == 0 {
        return None;
    }
    let at = field as usize;
    let raw = u16::from_le_bytes([*bytes.get(at + 2)?, *bytes.get(at + 3)?]) as u32;
    Some(Part {
        bytes,
        offset: field,
        raw,
    })
}

/// The access a query of the `info` parts needs on the object: READ_CONTROL for the owner,
/// group or DACL, ACCESS_SYSTEM_SECURITY for the SACL.
pub fn query_access(info: u32) -> u32 {
    let mut access = 0;
    if info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
        != 0
    {
        access |= READ_CONTROL;
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    access
}

/// The access a set of the `info` parts needs on the object: WRITE_OWNER for the owner or
/// group, WRITE_DAC for the DACL, ACCESS_SYSTEM_SECURITY for the SACL.
pub fn set_access(info: u32) -> u32 {
    let mut access = 0;
    if info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION) != 0 {
        access |= WRITE_OWNER;
    }
    if info & DACL_SECURITY_INFORMATION != 0 {
        access |= WRITE_DAC;
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    access
}

/// Whether `info` names the SACL: the part whose query or set needs the security privilege.
pub fn names_sacl(info: u32) -> bool {
    info & SACL_SECURITY_INFORMATION != 0
}

/// The privilege gate of a query or set that names the SACL: the token must hold the security
/// privilege enabled (STATUS_PRIVILEGE_NOT_HELD otherwise).
pub fn privilege_gate(info: u32, token: &crate::se::TokenBody) -> Result<(), NtStatus> {
    if names_sacl(info) && !token.enabled(SE_SECURITY_PRIVILEGE) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    Ok(())
}

/// What a token lets its holder assign as an object's new owner: its user SID, one of its
/// owner groups, or anything at all with the restore privilege held enabled.
struct OwnerRules {
    user: crate::se::SidBytes,
    restore: bool,
}

impl OwnerRules {
    fn of(token: &crate::se::TokenBody) -> Self {
        OwnerRules {
            user: token.user.clone(),
            restore: token.enabled(SE_RESTORE_PRIVILEGE),
        }
    }

    /// Whether `sid` is an owner this token's holder may assign.
    fn allows(&self, sid: &[u8]) -> bool {
        if crate::sec::sid::equal(self.user.as_slice(), sid) || self.restore {
            return true;
        }
        crate::se::GROUPS.iter().any(|(group, attributes)| {
            *attributes & crate::se::SE_GROUP_OWNER != 0
                && crate::sec::sid::equal(crate::se::sid_bytes(group).as_slice(), sid)
        })
    }
}

/// The query of the live object `id` on `directory` for the `info` parts: its stored
/// descriptor's answer (see [`query_reply`]); STATUS_INVALID_HANDLE for an id that names
/// nothing.
#[cfg_attr(not(test), allow(dead_code))]
fn query_on(
    directory: &mut crate::ob::Directory,
    id: crate::ob::ObjectId,
    info: u32,
) -> Result<Reply, NtStatus> {
    let stored = directory
        .security_descriptor(id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    query_reply(stored, info)
}

/// Store `merged` as the security descriptor of the live object `id` on `directory`: the
/// seam's own refusals (STATUS_INVALID_HANDLE for a dead id, STATUS_BUFFER_TOO_SMALL past
/// the record's storage).
#[cfg_attr(not(test), allow(dead_code))]
fn set_on(
    directory: &mut crate::ob::Directory,
    id: crate::ob::ObjectId,
    merged: &[u8],
) -> Result<(), NtStatus> {
    directory.set_security_descriptor(id, merged)
}

#[cfg(target_arch = "x86")]
pub use services::*;

/// The services themselves, on the calling process's handles and the object manager's stored
/// descriptors.
#[cfg(target_arch = "x86")]
mod services {
    use super::super::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use super::super::object::{is_console_handle, CURRENT_PROCESS, CURRENT_THREAD};
    use super::*;
    use crate::ob::security::{CallerMemory, MAX_SD};
    use crate::ob::{self, ObRef};
    use crate::sec::CallerMode;

    /// The object `handle` names, referenced for the service's scope: the process and thread
    /// pseudo-handles name their own objects with every right; a console handle or a handle
    /// naming no entry is STATUS_INVALID_HANDLE; one whose granted access is short of
    /// `needed` is STATUS_ACCESS_DENIED.
    fn object_of(handle: u32, needed: u32) -> Result<ObRef, NtStatus> {
        let id = match handle {
            CURRENT_PROCESS => crate::process::current().object(),
            CURRENT_THREAD => ob::current_thread().ok_or(STATUS_INVALID_HANDLE)?,
            _ if is_console_handle(handle) => return Err(STATUS_INVALID_HANDLE),
            _ => {
                let entry = calling_process()
                    .lookup_handle(handle)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
                if entry.access & needed != needed {
                    return Err(STATUS_ACCESS_DENIED);
                }
                id
            }
        };
        ob::reference(id).ok_or(STATUS_INVALID_HANDLE)
    }

    /// The calling process's token, copied out of the directory; none when it has none.
    fn caller_token() -> Option<crate::se::TokenBody> {
        let process = crate::process::current().object();
        ob::locked(|directory| {
            directory
                .process_token(process)
                .and_then(|id| directory.token(id))
                .copied()
        })
    }

    /// NtQuerySecurityObject: the object's stored security descriptor of the `info` parts
    /// into the caller's buffer of `length` bytes, the size the answer takes into
    /// LengthNeeded — written on success and when the buffer is too short
    /// (STATUS_BUFFER_TOO_SMALL, nothing written), not when the handle itself failed. A null
    /// LengthNeeded or an unprobeable output range is STATUS_ACCESS_VIOLATION, answered
    /// before the handle is looked at.
    pub fn query_security_object(
        _: &mut NtCall,
        handle: Handle,
        info: u32,
        descriptor: UserAddr,
        length: u32,
        length_needed: UserPtr<u32>,
    ) -> NtResult {
        if length_needed.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        length_needed.addr().probe(4)?;
        descriptor.probe(length)?;
        let object = object_of(handle.raw(), query_access(info) & !ACCESS_SYSTEM_SECURITY)?;
        if let Some(token) = caller_token() {
            privilege_gate(info, &token)?;
        } else if names_sacl(info) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        let reply = ob::locked(|directory| query_on(directory, object.id(), info))?;
        let size = reply.size;
        if fits(size, length).is_err() {
            length_needed.write(size)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        descriptor.write(&reply.bytes[..size as usize])?;
        length_needed.write(size)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtSetSecurityObject: the caller's descriptor captured (always, even from kernel
    /// mode; every range probed and each part validated from user mode) and merged into the
    /// object's stored one per the `info` parts (see [`set_merge`]), then stored back on the
    /// record. A null descriptor pointer is STATUS_ACCESS_VIOLATION.
    pub fn set_security_object(
        _: &mut NtCall,
        handle: Handle,
        info: u32,
        descriptor: UserAddr,
    ) -> NtResult {
        if descriptor.is_null() {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let object = object_of(handle.raw(), set_access(info) & !ACCESS_SYSTEM_SECURITY)?;
        let token = caller_token();
        if let Some(token) = &token {
            privilege_gate(info, token)?;
        } else if names_sacl(info) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        let user_mode = ob::security::caller_mode() == CallerMode::User;
        let mut captured = [0u8; MAX_SD];
        let mut captured_len = 0u32;
        let captured_status = crate::sec::sd::capture(
            &CallerMemory,
            descriptor.raw(),
            user_mode,
            true,
            &mut captured,
            &mut captured_len,
        );
        if captured_status != STATUS_SUCCESS {
            return Err(captured_status);
        }
        let rules = token.as_ref().map(OwnerRules::of);
        let merged = ob::locked(|directory| {
            let stored = directory
                .security_descriptor(object.id())
                .ok_or(STATUS_INVALID_HANDLE)?;
            set_merge(stored, info, &captured[..captured_len as usize], |sid| {
                rules.as_ref().is_some_and(|rules| rules.allows(sid))
            })
        })?;
        ob::locked(|directory| directory.set_security_descriptor(object.id(), &merged))?;
        Ok(STATUS_SUCCESS)
    }
}

/// The host builds' services (see `nt::unserved`): they run on the target's handle table and
/// directory; the host tests exercise the pure parts above and the directory seam.
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        query_security_object(Handle, u32, UserAddr, u32, UserPtr<u32>);
        set_security_object(Handle, u32, UserAddr);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

/// The test fixtures the query and set tests share: the SD/ACL/SID byte builders, the
/// fixture descriptor, a fresh directory with one event, and a token.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::vec::Vec;

    use super::*;
    use crate::ob::{Directory, ObjectId, ObjectType};
    use crate::se::TokenBody;
    use crate::sec::{ACCESS_ALLOWED_ACE_TYPE, ACL_REVISION2};

    /// A SID's bytes: revision 1, the count, a zeroed 6-byte authority with the authority's
    /// low byte last, then a dword per sub-authority.
    pub fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for &sub in subs {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// An ACE's bytes: type, flags, the dword-padded size, then the body.
    pub fn ace(ace_type: u8, body: &[u8]) -> Vec<u8> {
        let size = align4((4 + body.len()) as u32) as usize;
        let mut v = vec![ace_type, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(body);
        v.resize(size, 0);
        v
    }

    /// An access-allowed ACE of `mask` to the SID's bytes.
    pub fn allowed_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(sid);
        ace(ACCESS_ALLOWED_ACE_TYPE, &body)
    }

    /// An ACL's bytes: the header, then the ACEs; the size the dword-aligned whole takes.
    pub fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let raw = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
        let size = align4(raw as u32) as usize;
        let mut v = vec![ACL_REVISION2, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        for a in aces {
            v.extend_from_slice(a);
        }
        v.resize(size, 0);
        v
    }

    /// A self-relative security descriptor in one flat buffer: the header, then the SACL,
    /// DACL, owner and group (each when given) packed dword-aligned in that order, with
    /// `extra` control flags on top of SE_SELF_RELATIVE.
    pub fn self_relative(
        extra: u16,
        sacl: Option<&[u8]>,
        dacl: Option<&[u8]>,
        owner: Option<&[u8]>,
        group: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut v = vec![0u8; SECURITY_DESCRIPTOR_MIN_LENGTH];
        let mut h = SecurityDescriptor {
            revision: SECURITY_DESCRIPTOR_REVISION,
            sbz1: 0,
            control: SE_SELF_RELATIVE | extra,
            owner: 0,
            group: 0,
            sacl: 0,
            dacl: 0,
        };
        let mut at = SECURITY_DESCRIPTOR_MIN_LENGTH as u32;
        for (field, part) in [
            (&mut h.sacl, sacl),
            (&mut h.dacl, dacl),
            (&mut h.owner, owner),
            (&mut h.group, group),
        ] {
            if let Some(part) = part {
                *field = at;
                v.extend_from_slice(part);
                at += align4(part.len() as u32);
                while v.len() < at as usize {
                    v.push(0);
                }
            }
        }
        assert!(h.write(&mut v[..SECURITY_DESCRIPTOR_MIN_LENGTH]));
        v
    }

    /// The fixture descriptor's parts: an owner SID of 2 sub-authorities (16 bytes), a group
    /// SID of 5 (28), a DACL with one allowed ACE over a 1-sub-authority SID (28), an empty
    /// SACL (8).
    pub fn parts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let owner = sid(5, &[32, 544]);
        let group = sid(5, &[21, 111, 222, 333, 513]);
        let dacl = acl(&[allowed_ace(0x000F_01FF, &sid(1, &[0]))]);
        let sacl = acl(&[]);
        assert_eq!(
            (owner.len(), group.len(), dacl.len(), sacl.len()),
            (16, 28, 28, 8)
        );
        (owner, group, dacl, sacl)
    }

    /// The stored fixture descriptor: all four parts, the DACL and SACL present, the owner
    /// and group defaulted.
    pub fn stored_sd() -> Vec<u8> {
        let (owner, group, dacl, sacl) = parts();
        self_relative(
            SE_DACL_PRESENT | SE_SACL_PRESENT | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED,
            Some(&sacl),
            Some(&dacl),
            Some(&owner),
            Some(&group),
        )
    }

    pub fn header_of(bytes: &[u8]) -> SecurityDescriptor {
        SecurityDescriptor::parse(bytes).unwrap()
    }

    /// A fresh directory with one event object, as the ob tests make one.
    pub fn directory_with_event() -> (&'static mut Directory, ObjectId) {
        crate::sched::testkit::dispatcher();
        let mut directory = Box::<Directory>::new_uninit();
        // SAFETY: the box is valid, aligned and the records' final address once leaked.
        unsafe { Directory::write_empty(directory.as_mut_ptr()) };
        // SAFETY: written whole just above.
        let directory = Box::leak(unsafe { directory.assume_init() });
        let id = directory
            .create_event(crate::sched::event::EventKind::Notification, false)
            .unwrap();
        (directory, id)
    }

    pub fn token() -> TokenBody {
        TokenBody::of(ObjectId {
            kind: ObjectType::Process,
            index: 1,
            generation: 0,
        })
    }

    /// Enable `luid` in the token.
    pub fn enable(token: &mut TokenBody, luid: u32) {
        let mut requests = crate::sec::Requests::new();
        requests.add(crate::sec::privilege(
            luid,
            crate::sec::SE_PRIVILEGE_ENABLED,
        ));
        token
            .adjust(&crate::sec::Change::Set(requests), None)
            .unwrap();
    }

    pub const ALL: u32 = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION;
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::se;

    #[test]
    fn the_access_masks_of_the_info_parts() {
        assert_eq!(query_access(OWNER_SECURITY_INFORMATION), READ_CONTROL);
        assert_eq!(
            query_access(GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION),
            READ_CONTROL
        );
        assert_eq!(
            query_access(SACL_SECURITY_INFORMATION),
            ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(
            query_access(OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION),
            READ_CONTROL | ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(query_access(0), 0);
        assert_eq!(query_access(0x10), 0, "an unknown bit names no access");
        assert_eq!(
            set_access(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION),
            WRITE_OWNER
        );
        assert_eq!(set_access(DACL_SECURITY_INFORMATION), WRITE_DAC);
        assert_eq!(
            set_access(SACL_SECURITY_INFORMATION),
            ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(
            set_access(ALL),
            WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY
        );
        assert_eq!(set_access(0), 0);
        assert!(names_sacl(SACL_SECURITY_INFORMATION));
        assert!(!names_sacl(
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        ));
    }

    // -- the privilege gate --------------------------------------------------------

    /// Naming the SACL needs the security privilege held enabled: held but disabled is
    /// STATUS_PRIVILEGE_NOT_HELD, enabling it passes, and the other parts need nothing.
    #[test]
    fn the_sacl_needs_the_security_privilege_enabled() {
        let mut token = token();
        assert_eq!(
            privilege_gate(SACL_SECURITY_INFORMATION, &token),
            Err(STATUS_PRIVILEGE_NOT_HELD),
            "held but disabled"
        );
        assert_eq!(privilege_gate(ALL, &token), Err(STATUS_PRIVILEGE_NOT_HELD));
        assert_eq!(
            privilege_gate(
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &token
            ),
            Ok(())
        );
        enable(&mut token, SE_SECURITY_PRIVILEGE);
        assert_eq!(privilege_gate(SACL_SECURITY_INFORMATION, &token), Ok(()));
        assert_eq!(privilege_gate(ALL, &token), Ok(()));
    }

    /// The owner rules: the token's user and its owner groups are assignable, a stranger is
    /// not — unless the restore privilege is held enabled.
    #[test]
    fn the_owner_rules_follow_the_token() {
        let mut token = token();
        let rules = OwnerRules::of(&token);
        let user = se::sid_bytes(&se::USER);
        let admins = se::sid_bytes(&se::ADMINISTRATORS);
        let stranger = sid(5, &[21, 111, 222, 333, 1001]);
        assert!(rules.allows(&user));
        assert!(rules.allows(&admins), "an owner group");
        assert!(!rules.allows(&stranger));
        enable(&mut token, SE_RESTORE_PRIVILEGE);
        let rules = OwnerRules::of(&token);
        assert!(
            rules.allows(&stranger),
            "the restore privilege allows any owner"
        );
    }
}
