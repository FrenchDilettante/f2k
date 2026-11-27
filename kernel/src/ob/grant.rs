//! The access check a handle's grant runs: the object's shared security descriptor (see
//! [`super::sdcache`], held on its record in the directory), the kind's generic mapping, the
//! requested access, and the subject built from the calling process's token.
//!
//! The granted mask goes on the handle as it always has, and a denied check is its status
//! (STATUS_ACCESS_DENIED). Kernel-mode callers are granted as asked, and MAXIMUM_ALLOWED takes the
//! check's own fast path.

use rtl::array_vec::ArrayVec;
use rtl::nt::access::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use rtl::nt::LuidAndAttributes;

#[cfg(target_arch = "x86")]
use super::security::caller_mode;
use super::{ObjectId, ObjectType};
use crate::sec::{AccessCheck, CallerMode, GenericMapping, SidAndAttributes, Subject, TokenView};
use crate::status::NtStatus;

/// The kind's GENERIC_MAPPING as the access check takes it: each generic right's mapped rights —
/// the mask [`ObjectType::granted`] gives a lone generic right.
fn mapping_of(kind: ObjectType) -> GenericMapping {
    GenericMapping {
        generic_read: kind.granted(GENERIC_READ),
        generic_write: kind.granted(GENERIC_WRITE),
        generic_execute: kind.granted(GENERIC_EXECUTE),
        generic_all: kind.granted(GENERIC_ALL),
    }
}

/// The access a handle to an object of `kind` asking for `desired` is granted: `sd` is the
/// object's security descriptor, `subject` the caller's. A kernel-mode caller is granted as
/// asked, mapped as the kind maps it, without the descriptor being read; a user-mode caller's
/// request runs the access check — MAXIMUM_ALLOWED included, on the check's fast path — and a
/// denial is its status (STATUS_ACCESS_DENIED). The kinds whose masks pass through unmapped
/// (win32k's) keep their mask as asked: the check cannot express an identity mapping.
pub fn granted_access(
    kind: ObjectType,
    desired: u32,
    sd: &[u8],
    subject: Subject<'_>,
    mode: CallerMode,
) -> Result<u32, NtStatus> {
    if mode == CallerMode::Kernel || !kind.maps_generics() {
        return Ok(kind.granted(desired));
    }
    let outcome = crate::sec::access_check(&AccessCheck {
        sd,
        subject,
        desired,
        mapping: mapping_of(kind),
        previously_granted: 0,
        mode,
        principal_self: None,
        object_types: &[],
    });
    if outcome.is_granted() {
        Ok(outcome.granted)
    } else {
        Err(outcome.status)
    }
}

/// A SID's bytes, onto `out`: revision 1, the sub-authority count, the authority, then a dword
/// per sub-authority.
fn sid_bytes(sid: &crate::se::Sid, out: &mut ArrayVec<u8, 72>) {
    out.try_extend_from_slice(&[1, sid.sub.len() as u8, 0, 0, 0, 0, 0, sid.authority])
        .ok()
        .expect("a SID's bytes fit");
    for &sub in sid.sub {
        out.try_extend_from_slice(&sub.to_le_bytes())
            .ok()
            .expect("a SID's bytes fit");
    }
}

/// The token's privilege set, as its TokenPrivileges information answers it.
fn privileges_of(token: &crate::se::TokenBody) -> [LuidAndAttributes; crate::sec::HELD] {
    use rtl::pod::Pod;
    let mut out = crate::sec::DEFAULT_PRIVILEGES;
    if let Ok(reply) = token.information(crate::se::Class::Privileges, 0) {
        let bytes = &reply[..];
        let count = bytes
            .get(..4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()) as usize)
            .unwrap_or(0);
        for (index, slot) in out.iter_mut().enumerate().take(count.min(crate::sec::HELD)) {
            let at = 4 + core::mem::size_of::<LuidAndAttributes>() * index;
            if let Some(entry) = bytes
                .get(at..at + 12)
                .and_then(LuidAndAttributes::from_bytes)
            {
                *slot = entry;
            }
        }
    }
    out
}

/// The subject of a handle grant's check, in owned form, from the calling process's token: the
/// user, the groups with their attributes, the owner, and the privilege set. F2K has one token
/// per process and no impersonation, so the effective and the primary token are the same one.
pub struct SubjectParts {
    /// The user SID's bytes (index 0 of the token's SIDs, always matching).
    pub user: ArrayVec<u8, 72>,
    /// Each group's SID bytes and its SE_GROUP_* attributes, in the token's order.
    pub groups: ArrayVec<(ArrayVec<u8, 72>, u32), 9>,
    /// The token's owner SID's bytes.
    pub owner: ArrayVec<u8, 72>,
    /// The token's privilege set.
    pub privileges: [LuidAndAttributes; crate::sec::HELD],
}

/// The subject of a handle grant's check, from the process's token `token` (see [`SubjectParts`]).
pub fn subject_parts(token: &crate::se::TokenBody) -> SubjectParts {
    let mut user = ArrayVec::new();
    sid_bytes(&crate::se::USER, &mut user);
    let mut groups = ArrayVec::new();
    for (sid, attributes) in crate::se::GROUPS {
        let mut bytes = ArrayVec::new();
        sid_bytes(&sid, &mut bytes);
        groups.push((bytes, attributes));
    }
    let mut owner = ArrayVec::new();
    sid_bytes(&crate::se::ADMINISTRATORS, &mut owner);
    SubjectParts {
        user,
        groups,
        owner,
        privileges: privileges_of(token),
    }
}

/// Run the handle grant's access check with `parts` as the subject (the effective and the primary
/// token are the same one: no impersonation), as [`granted_access`] does.
pub fn check_with(
    parts: &SubjectParts,
    kind: ObjectType,
    desired: u32,
    sd: &[u8],
    mode: CallerMode,
) -> Result<u32, NtStatus> {
    let mut sids = [SidAndAttributes {
        sid: &[],
        attributes: 0,
    }; 10];
    let mut count = 0;
    sids[count] = SidAndAttributes {
        sid: &parts.user[..],
        attributes: 0,
    };
    count += 1;
    for (sid, attributes) in parts.groups.iter() {
        sids[count] = SidAndAttributes {
            sid: &sid[..],
            attributes: *attributes,
        };
        count += 1;
    }
    let token = TokenView {
        sids: &sids[..count],
        owner: &parts.owner[..],
        privileges: &parts.privileges,
    };
    granted_access(
        kind,
        desired,
        sd,
        Subject {
            effective: token,
            primary: token,
        },
        mode,
    )
}

/// The access a new handle to the object `id` of `process` asking for `desired` is granted: the
/// object's own security descriptor — read out of the directory as a shared handle, which keeps
/// its entry alive for the check — checked against the calling process's token when the caller is
/// in user mode (see [`granted_access`]); kernel mode as asked. `creating` tells a create's grant
/// from an open's: a create asking no access at all gets an empty handle, as it always has.
#[cfg(target_arch = "x86")]
pub fn grant_handle(
    process: &crate::process::Process,
    id: ObjectId,
    desired: u32,
    creating: bool,
) -> Result<u32, NtStatus> {
    use crate::status::{STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE};
    let mode = caller_mode();
    if mode == CallerMode::Kernel {
        return Ok(id.kind.granted(desired));
    }
    if creating && desired == 0 {
        return Ok(0);
    }
    let sd = crate::ob::locked(|directory| directory.sd(id)).ok_or(STATUS_INVALID_HANDLE)?;
    let token = crate::ob::reference_process_token(process.object())
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let body = crate::ob::locked(|directory| directory.token(token.id()).copied())
        .ok_or(STATUS_INVALID_HANDLE)?;
    let parts = subject_parts(&body);
    drop(token);
    // The descriptor's bytes are copied out of the cache entry for the check.
    sd.with_bytes(|bytes| check_with(&parts, id.kind, desired, bytes, mode))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::nt::access::{
        EVENT_MODIFY_STATE,
        EVENT_QUERY_STATE,
        GENERIC_ALL,
        GENERIC_READ,
        MAXIMUM_ALLOWED,
        READ_CONTROL,
        SYNCHRONIZE,
    };

    use super::super::access::EVENT_MAPPING;
    use super::*;
    use crate::sec::{
        SecurityDescriptor,
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE,
        ACL_REVISION2,
        SE_DACL_PRESENT,
        SE_GROUP_ENABLED,
        SE_SELF_RELATIVE,
        WORLD_SID,
    };
    use crate::status::STATUS_ACCESS_DENIED;

    // -- the byte builders -------------------------------------------------------

    /// A SID's bytes: revision 1, the count, a zeroed 6-byte authority with the authority's
    /// low byte last, then a little-endian dword per sub-authority.
    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for &s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    /// An ACE's bytes: the type, the flags, the dword-padded size, then the body.
    fn ace(ace_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let size = (4 + body.len() + 3) & !3;
        let mut v = vec![ace_type, flags];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(body);
        v.resize(size, 0);
        v
    }

    /// An access-allowed ACE of `mask` to `sid`.
    fn allowed(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(sid);
        ace(ACCESS_ALLOWED_ACE_TYPE, 0, &body)
    }

    /// An access-denied ACE of `mask` to `sid`.
    fn denied(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(sid);
        ace(ACCESS_DENIED_ACE_TYPE, 0, &body)
    }

    /// An ACL's bytes: the header, then the ACEs.
    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
        let mut v = vec![ACL_REVISION2, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        for a in aces {
            v.extend_from_slice(a);
        }
        v
    }

    /// A self-relative security descriptor in one buffer: the header, then the DACL (when
    /// present) and the owner, dword-aligned.
    fn descriptor(owner: Option<&[u8]>, dacl_present: bool, dacl: Option<&[u8]>) -> Vec<u8> {
        let mut control = SE_SELF_RELATIVE;
        let mut dacl_field = 0u32;
        let mut v = vec![0u8; 20];
        if dacl_present {
            control |= SE_DACL_PRESENT;
            if let Some(d) = dacl {
                dacl_field = v.len() as u32;
                v.extend_from_slice(d);
                while v.len() % 4 != 0 {
                    v.push(0);
                }
            }
        }
        let mut owner_field = 0u32;
        if let Some(o) = owner {
            owner_field = v.len() as u32;
            v.extend_from_slice(o);
            while v.len() % 4 != 0 {
                v.push(0);
            }
        }
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control,
            owner: owner_field,
            group: 0,
            sacl: 0,
            dacl: dacl_field,
        };
        assert!(h.write(&mut v[..]));
        v
    }

    /// A descriptor with a present DACL of `aces` and the given owner.
    fn sd(owner: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
        descriptor(Some(owner), true, Some(&acl(aces)))
    }

    // -- the subject builders ------------------------------------------------------

    /// The test user's SID, S-1-5-21-111-222-333-1000.
    fn user_sid() -> Vec<u8> {
        sid(5, &[21, 111, 222, 333, 1000])
    }

    /// Another account's SID, S-1-5-21-111-222-333-1001: an owner the subject is not.
    fn other_sid() -> Vec<u8> {
        sid(5, &[21, 111, 222, 333, 1001])
    }

    /// A handle's descriptor bytes, copied out of its cache entry.
    fn sd_bytes(handle: &super::super::sdcache::SdRef) -> Vec<u8> {
        handle.with_bytes(|bytes| bytes.to_vec()).unwrap()
    }

    /// Run [`granted_access`] as a subject of just `user` plus `groups` (SID bytes, attributes).
    fn run(
        kind: ObjectType,
        desired: u32,
        sd: &[u8],
        user: &[u8],
        groups: &[(Vec<u8>, u32)],
        mode: CallerMode,
    ) -> Result<u32, NtStatus> {
        let mut sids = [SidAndAttributes {
            sid: &[],
            attributes: 0,
        }; 10];
        let mut count = 0;
        sids[count] = SidAndAttributes {
            sid: user,
            attributes: 0,
        };
        count += 1;
        for (sid, attributes) in groups {
            sids[count] = SidAndAttributes {
                sid,
                attributes: *attributes,
            };
            count += 1;
        }
        let token = TokenView {
            sids: &sids[..count],
            owner: user,
            privileges: &[],
        };
        granted_access(
            kind,
            desired,
            sd,
            Subject {
                effective: token,
                primary: token,
            },
            mode,
        )
    }

    /// Run as the lone user, in user mode.
    fn run_user(kind: ObjectType, desired: u32, sd: &[u8]) -> Result<u32, NtStatus> {
        let user = user_sid();
        run(kind, desired, sd, &user, &[], CallerMode::User)
    }

    // -- the grant's check ----------------------------------------------------------

    /// The default shared descriptor is a NULL DACL that grants all: every kind everything asked,
    /// exactly as the kind's mapping grants it.
    #[test]
    fn the_default_null_dacl_grants_every_kind_everything() {
        let default = super::super::security::null_dacl().unwrap();
        let bytes = sd_bytes(&default);
        assert_eq!(bytes.len(), 20);

        let event = ObjectType::Event;
        for desired in [
            GENERIC_ALL,
            MAXIMUM_ALLOWED,
            EVENT_MODIFY_STATE | SYNCHRONIZE,
        ] {
            assert_eq!(
                run_user(event, desired, &bytes),
                Ok(event.granted(desired)),
                "{desired:#x}"
            );
        }
        for kind in [
            ObjectType::Semaphore,
            ObjectType::Mutex,
            ObjectType::Timer,
            ObjectType::Section,
            ObjectType::Directory,
            ObjectType::Process,
            ObjectType::Thread,
            ObjectType::File,
            ObjectType::Key,
            ObjectType::Token,
        ] {
            assert_eq!(
                run_user(kind, GENERIC_ALL, &bytes),
                Ok(kind.granted(GENERIC_ALL)),
                "{kind:?}"
            );
            assert_eq!(
                run_user(kind, MAXIMUM_ALLOWED, &bytes),
                Ok(kind.granted(MAXIMUM_ALLOWED)),
                "{kind:?}"
            );
        }
    }

    /// A create with a passed SD grants and denies per the asked mask: the event type's generic
    /// all is denied by the deny ACE, its generic read is granted by the allow.
    #[test]
    fn a_create_with_sd_grants_and_denies_per_mask() {
        let user = user_sid();
        // Owned by another account, so the subject gets no implicit owner rights.
        let d = sd(
            &other_sid(),
            &[
                denied(EVENT_MODIFY_STATE, &user),
                allowed(READ_CONTROL | EVENT_QUERY_STATE | SYNCHRONIZE, &user),
            ],
        );
        let event = ObjectType::Event;
        // GENERIC_ALL maps to EVENT_ALL_ACCESS; the deny leaves EVENT_MODIFY_STATE remaining.
        assert_eq!(run_user(event, GENERIC_ALL, &d), Err(STATUS_ACCESS_DENIED));
        // MAXIMUM_ALLOWED asks the most grantable, not everything: the allow's mask, the deny
        // already out of it.
        assert_eq!(
            run_user(event, MAXIMUM_ALLOWED, &d),
            Ok(READ_CONTROL | EVENT_QUERY_STATE | SYNCHRONIZE),
            "the maximum walk finds the deny too"
        );
        // GENERIC_READ maps to the mapping's read rights, all allowed.
        assert_eq!(
            run_user(event, GENERIC_READ, &d),
            Ok(EVENT_MAPPING.read),
            "granted as the mapping reads"
        );
        assert_eq!(
            run_user(event, EVENT_MODIFY_STATE, &d),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            run_user(event, EVENT_QUERY_STATE | SYNCHRONIZE, &d),
            Ok(EVENT_QUERY_STATE | SYNCHRONIZE)
        );
        assert_eq!(
            run_user(event, 0, &d),
            Err(STATUS_ACCESS_DENIED),
            "an empty ask grants nothing"
        );
    }

    /// An open asking for what the descriptor does not grant is ACCESS_DENIED; one asking within
    /// the grant gets exactly the granted mask.
    #[test]
    fn an_open_short_of_access_is_denied() {
        let user = user_sid();
        let d = sd(&user, &[allowed(READ_CONTROL | EVENT_QUERY_STATE, &user)]);
        let event = ObjectType::Event;
        assert_eq!(
            run_user(event, EVENT_MODIFY_STATE, &d),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            run_user(event, EVENT_MODIFY_STATE | EVENT_QUERY_STATE, &d),
            Err(STATUS_ACCESS_DENIED),
            "the whole ask is denied when any of it is"
        );
        assert_eq!(
            run_user(event, EVENT_QUERY_STATE, &d),
            Ok(EVENT_QUERY_STATE)
        );
    }

    /// MAXIMUM_ALLOWED takes the check's fast path: one pass OR-ing the matching allows minus
    /// the denies, not the kind's all.
    #[test]
    fn maximum_allowed_uses_the_checks_fast_path() {
        let user = user_sid();
        let world = WORLD_SID.to_vec();
        // Owned by another account; deny 0x1 to the user, allow 0x7 to everyone: the maximum is
        // 0x6, not the kind's all.
        let d = sd(&other_sid(), &[denied(0x1, &user), allowed(0x7, &world)]);
        let groups = [(world, SE_GROUP_ENABLED)];
        let event = ObjectType::Event;
        assert_eq!(
            run(event, MAXIMUM_ALLOWED, &d, &user, &groups, CallerMode::User),
            Ok(0x6)
        );
        // A lone MAXIMUM_ALLOWED against an empty DACL denies.
        let empty = sd(&other_sid(), &[]);
        assert_eq!(
            run_user(event, MAXIMUM_ALLOWED, &empty),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    /// Kernel-mode callers bypass the descriptor entirely: granted as asked, mapped as the kind
    /// maps it, even against a deny-everything DACL and with no descriptor at all.
    #[test]
    fn kernel_mode_bypasses_the_descriptor() {
        let user = user_sid();
        let deny_all = sd(&user, &[denied(0xFFFF_FFFF, &user)]);
        let event = ObjectType::Event;
        for desired in [
            GENERIC_ALL,
            MAXIMUM_ALLOWED,
            EVENT_MODIFY_STATE | SYNCHRONIZE,
            0x1,
        ] {
            assert_eq!(
                run(event, desired, &deny_all, &user, &[], CallerMode::Kernel),
                Ok(event.granted(desired)),
                "{desired:#x}"
            );
            assert_eq!(
                run(event, desired, &[], &user, &[], CallerMode::Kernel),
                Ok(event.granted(desired)),
                "no descriptor at all: {desired:#x}"
            );
        }
    }

    /// The subject comes from the process's token: the user SID first, the groups with their
    /// attributes, the owner, the privilege set — and a group's allow ACE matches through it.
    #[test]
    fn the_subject_is_the_processs_token() {
        use crate::se::{TokenBody, ADMINISTRATORS, GROUPS, USER};
        let process = ObjectId {
            kind: ObjectType::Process,
            index: 3,
            generation: 1,
        };
        let token = TokenBody::of(process);
        let parts = subject_parts(&token);

        // The user, the groups, the owner, as the token answers them.
        let mut expected_user = ArrayVec::new();
        sid_bytes(&USER, &mut expected_user);
        assert_eq!(&parts.user[..], &expected_user[..]);
        assert_eq!(parts.groups.len(), GROUPS.len());
        for ((sid, attributes), (expected_sid, expected_attributes)) in
            parts.groups.iter().zip(GROUPS.iter())
        {
            let mut expected = ArrayVec::new();
            sid_bytes(expected_sid, &mut expected);
            assert_eq!(&sid[..], &expected[..]);
            assert_eq!(attributes, expected_attributes);
        }
        let mut expected_owner = ArrayVec::new();
        sid_bytes(&ADMINISTRATORS, &mut expected_owner);
        assert_eq!(&parts.owner[..], &expected_owner[..]);
        assert_eq!(parts.privileges, crate::sec::DEFAULT_PRIVILEGES);

        // The check runs with it: a DACL allowing the administrators group grants through the
        // group, not the user.
        let mut admins = ArrayVec::new();
        sid_bytes(&ADMINISTRATORS, &mut admins);
        let d = sd(&parts.user[..], &[allowed(EVENT_QUERY_STATE, &admins[..])]);
        let event = ObjectType::Event;
        assert_eq!(
            check_with(&parts, event, EVENT_QUERY_STATE, &d, CallerMode::User),
            Ok(EVENT_QUERY_STATE),
            "the owner group's allow matches"
        );
        assert_eq!(
            check_with(&parts, event, EVENT_MODIFY_STATE, &d, CallerMode::User),
            Err(STATUS_ACCESS_DENIED)
        );
        // The default NULL DACL grants the token everything.
        let default = super::super::security::null_dacl().unwrap();
        assert_eq!(
            check_with(
                &parts,
                event,
                GENERIC_ALL,
                &sd_bytes(&default),
                CallerMode::User
            ),
            Ok(event.granted(GENERIC_ALL))
        );
    }

    /// Two objects with different descriptors grant differently through the same subject.
    #[test]
    fn two_objects_with_different_sds_grant_differently() {
        let user = user_sid();
        let open = super::super::security::null_dacl().unwrap();
        let locked_down =
            super::super::sdcache::log(&sd(&user, &[denied(0xFFFF_FFFF, &user)])).unwrap();
        let event = ObjectType::Event;
        let groups: [(Vec<u8>, u32); 0] = [];
        assert_eq!(
            run(
                event,
                GENERIC_ALL,
                &sd_bytes(&open),
                &user,
                &groups,
                CallerMode::User
            ),
            Ok(event.granted(GENERIC_ALL))
        );
        assert_eq!(
            run(
                event,
                GENERIC_ALL,
                &sd_bytes(&locked_down),
                &user,
                &groups,
                CallerMode::User
            ),
            Err(STATUS_ACCESS_DENIED)
        );
    }
}
