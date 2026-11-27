//! The access check: the walk over an object's security descriptor that decides what a
//! subject may do with the object.
//!
//! An access check takes the object's security descriptor (its bytes), the subject — the
//! effective and primary tokens' user, groups and privileges — a desired access mask, the
//! object type's generic mapping, any access already granted by higher-level checks, the
//! caller's mode, and the object's own principal SID when it represents a principal. It
//! answers a granted mask and a status.
//!
//! The shape of the answer: kernel-mode callers are granted unconditionally. Otherwise the
//! generic rights in the desired mask are mapped to the type's own rights, the owner is
//! implicitly granted READ_CONTROL and WRITE_DAC, ACCESS_SYSTEM_SECURITY asks for the
//! security privilege and WRITE_OWNER for ownership or the take-ownership privilege, and a
//! missing or null DACL grants everything. What remains is walked against the DACL's ACEs
//! in order — an allow ACE for a SID in the token clears its mask from what remains, a deny
//! ACE whose mask intersects what remains denies the whole check, so the first matching
//! deny in walk order wins — or, when MAXIMUM_ALLOWED was asked for, a single pass that
//! ORs the matching allows together. A SID is in a token when it is the user (the first
//! entry, always) or an enabled group — a deny-only group counts for deny ACEs alone — and
//! an ACE's principal-self SID stands for the object's own SID. The result is granted =
//! desired minus remaining, with STATUS_ACCESS_DENIED when anything remains.
#![allow(dead_code)]

use rtl::nt::access::{
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER,
};
use rtl::nt::LuidAndAttributes;

use crate::sec::{
    equal, held_enabled, luid, Guid, SecurityDescriptor, ACE_HEADER_SIZE, ACE_INHERITED_OBJECT_TYPE_PRESENT,
    ACE_OBJECT_TYPE_PRESENT, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACCESS_MAX_MS_OBJECT_ACE_TYPE, ACCESS_MAX_MS_V2_ACE_TYPE, ACCESS_MIN_MS_OBJECT_ACE_TYPE,
    ACL_HEADER_SIZE, GUID_SIZE, INHERIT_ONLY_ACE, PRINCIPAL_SELF_SID, SE_DACL_PRESENT,
    SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE, SECURITY_DESCRIPTOR_MIN_LENGTH,
    SECURITY_DESCRIPTOR_REVISION, STATUS_INVALID_SECURITY_DESCR, STATUS_UNKNOWN_REVISION,
};
// A few names exist in both the ACL and the SD (or SID) module, so the glob above cannot
// disambiguate them; take those from their module.
use crate::sec::acl::{is_valid as acl_is_valid, STATUS_INVALID_ACL};
use crate::sec::sd::STATUS_INVALID_SID;
use crate::sec::sid::length as sid_length;
use crate::status::{NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS};

/// ACCESS_SYSTEM_SECURITY (winnt.h): the right to read or write an object's audit ACL. The
/// one standard-area right the access-mask module does not name yet.
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// A group's SE_GROUP_ENABLED (winnt.h): the group counts for an allow ACE only when this
/// is set.
pub const SE_GROUP_ENABLED: u32 = 0x4;
/// A group's SE_GROUP_USE_FOR_DENY_ONLY (winnt.h): the group also counts for a deny ACE
/// when this is set.
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

/// The caller's processor mode. Kernel-mode callers are granted unconditionally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerMode {
    /// Kernel mode: everything asked for is granted.
    Kernel,
    /// User mode: the descriptor's DACL is walked.
    User,
}

/// A kind of object's GENERIC_MAPPING: the rights each generic right stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericMapping {
    /// What GENERIC_READ stands for.
    pub generic_read: u32,
    /// What GENERIC_WRITE stands for.
    pub generic_write: u32,
    /// What GENERIC_EXECUTE stands for.
    pub generic_execute: u32,
    /// What GENERIC_ALL stands for.
    pub generic_all: u32,
}

impl GenericMapping {
    /// `access` with its generic rights mapped to this kind's rights and the generic bits
    /// cleared. MAXIMUM_ALLOWED is left alone: the check itself handles it.
    pub fn map(&self, access: u32) -> u32 {
        let mut mapped = access;
        for (generic, rights) in [
            (GENERIC_READ, self.generic_read),
            (GENERIC_WRITE, self.generic_write),
            (GENERIC_EXECUTE, self.generic_execute),
            (GENERIC_ALL, self.generic_all),
        ] {
            if mapped & generic != 0 {
                mapped |= rights;
            }
        }
        mapped &= !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        mapped
    }
}

/// One SID of a token with its attributes: the first entry is the user, the rest are groups.
#[derive(Clone, Copy, Debug)]
pub struct SidAndAttributes<'a> {
    /// The SID's bytes.
    pub sid: &'a [u8],
    /// Its SE_GROUP_* attributes.
    pub attributes: u32,
}

/// A token as the access check reads it.
#[derive(Clone, Copy, Debug)]
pub struct TokenView<'a> {
    /// The user and groups, in order: index 0 is the user and always matches.
    pub sids: &'a [SidAndAttributes<'a>],
    /// The token's owner SID.
    pub owner: &'a [u8],
    /// The token's privilege set.
    pub privileges: &'a [LuidAndAttributes],
}

/// The subject of an access check: the effective (client) token and the primary (process)
/// token — the same token when the caller is not impersonating.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// The effective token: what allow and deny ACEs are matched against.
    pub effective: TokenView<'a>,
    /// The primary token: what a compound ACE's server SID is matched against.
    pub primary: TokenView<'a>,
}

/// The outcome of an access check: the granted access mask and the status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// What was granted: the previously granted access plus whatever the check added.
    pub granted: u32,
    /// STATUS_SUCCESS when everything desired was granted, an error status otherwise.
    pub status: NtStatus,
}

impl Outcome {
    /// Whether the check granted everything asked for.
    pub fn is_granted(&self) -> bool {
        self.status == STATUS_SUCCESS
    }
}

/// One access check's inputs.
pub struct AccessCheck<'a> {
    /// The object's security descriptor's bytes: self-relative, or absolute with the slice
    /// itself as the address space. An empty slice is no descriptor at all.
    pub sd: &'a [u8],
    /// The subject: the effective and primary tokens.
    pub subject: Subject<'a>,
    /// The desired access mask, generic rights included; MAXIMUM_ALLOWED asks for the most
    /// the subject could be granted.
    pub desired: u32,
    /// The object type's generic mapping.
    pub mapping: GenericMapping,
    /// Access already granted by higher-level checks.
    pub previously_granted: u32,
    /// The caller's mode.
    pub mode: CallerMode,
    /// The object's own principal SID, when the object represents a principal (an ACE's
    /// principal-self SID is replaced by it); None when it does not.
    pub principal_self: Option<&'a [u8]>,
    /// The caller's object-type list, for object ACEs that name a type; empty is none.
    pub object_types: &'a [Guid],
}

/// Run the access check: the granted mask and the status (see the module notes for the
/// rules the walk follows).
pub fn access_check(check: &AccessCheck<'_>) -> Outcome {
    let _ = check;
    unimplemented!("the walk lands next")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::{
        ACL_REVISION2, ACL_REVISION3, ACL_REVISION_DS, COMPOUND_ACE_IMPERSONATION,
        SE_PRIVILEGE_ENABLED, SE_SELF_RELATIVE, SYSTEM_AUDIT_ACE_TYPE, WORLD_SID,
        ALIAS_ADMINS_SID, PRINCIPAL_SELF_SID as SELF_SID, privilege,
    };
    use crate::sec::acl::STATUS_INVALID_ACL;
    use crate::sec::sd::STATUS_INVALID_SID;
    use crate::status::STATUS_BUFFER_TOO_SMALL;
    use rtl::nt::access::{DELETE, STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE};
    use std::vec::Vec;

    // -- the byte builders -----------------------------------------------------

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

    /// A plain ACE: the mask, then the SID.
    fn plain_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(sid);
        ace(ace_type, flags, &body)
    }

    /// An access-allowed ACE of `mask` to `sid`.
    fn allowed(mask: u32, sid: &[u8]) -> Vec<u8> {
        plain_ace(ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid)
    }

    /// An access-denied ACE of `mask` to `sid`.
    fn denied(mask: u32, sid: &[u8]) -> Vec<u8> {
        plain_ace(ACCESS_DENIED_ACE_TYPE, 0, mask, sid)
    }

    /// A GUID, named by its first field.
    fn guid(data1: u32) -> Guid {
        Guid {
            data1,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// A GUID's bytes: the first three fields little-endian, the last eight as they are.
    fn guid_bytes(g: &Guid) -> Vec<u8> {
        let mut v = g.data1.to_le_bytes().to_vec();
        v.extend_from_slice(&g.data2.to_le_bytes());
        v.extend_from_slice(&g.data3.to_le_bytes());
        v.extend_from_slice(&g.data4);
        v
    }

    /// An object ACE of `mask` to `sid`, naming `object_type` when given.
    fn object_ace(ace_type: u8, mask: u32, object_type: Option<Guid>, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        let flags = if object_type.is_some() {
            ACE_OBJECT_TYPE_PRESENT
        } else {
            0
        };
        body.extend_from_slice(&flags.to_le_bytes());
        if let Some(g) = object_type {
            body.extend_from_slice(&guid_bytes(&g));
        }
        body.extend_from_slice(sid);
        ace(ace_type, 0, &body)
    }

    /// A compound access-allowed ACE of `mask`, with the server SID first and the client's
    /// second.
    fn compound(mask: u32, server: &[u8], client: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(&COMPOUND_ACE_IMPERSONATION.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(server);
        body.extend_from_slice(client);
        ace(ACCESS_ALLOWED_COMPOUND_ACE_TYPE, 0, &body)
    }

    /// An ACL's bytes: the header, then the ACEs. The revision rises to fit the ACEs.
    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let mut revision = ACL_REVISION2;
        for a in aces {
            match a[0] {
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE => revision = revision.max(ACL_REVISION3),
                t if (0x5..=0x8).contains(&t) => revision = revision.max(ACL_REVISION_DS),
                _ => {}
            }
        }
        let size = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
        let mut v = vec![revision, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        for a in aces {
            v.extend_from_slice(a);
        }
        v
    }

    /// A self-relative security descriptor in one buffer: the header, then the DACL (when
    /// present) and the owner, each packed dword-aligned. A present DACL of None is a null
    /// DACL; `dacl_present == false` leaves the flag clear.
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

    // -- the subject builders ----------------------------------------------------

    /// The test user's SID, S-1-5-21-111-222-333-1000.
    fn user_sid() -> Vec<u8> {
        sid(5, &[21, 111, 222, 333, 1000])
    }

    /// Another account's SID, S-1-5-21-111-222-333-1001.
    fn other_sid() -> Vec<u8> {
        sid(5, &[21, 111, 222, 333, 1001])
    }

    /// A subject whose effective and primary tokens are the same.
    fn same_tokens<'a>(
        sids: &'a [SidAndAttributes<'a>],
        owner: &'a [u8],
        privileges: &'a [LuidAndAttributes],
    ) -> Subject<'a> {
        let token = TokenView {
            sids,
            owner,
            privileges,
        };
        Subject {
            effective: token,
            primary: token,
        }
    }

    /// The test object type's mapping: read 0x1, write 0x2, execute 0x4, all 0xF, each with
    /// READ_CONTROL.
    const MAPPING: GenericMapping = GenericMapping {
        generic_read: READ_CONTROL | 0x1,
        generic_write: READ_CONTROL | 0x2,
        generic_execute: READ_CONTROL | 0x4,
        generic_all: STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xF,
    };

    /// The plain user-mode check: no previously granted access, no principal-self SID, no
    /// object-type list.
    fn run(sd: &[u8], subject: Subject<'_>, desired: u32) -> Outcome {
        full(sd, subject, desired, 0, CallerMode::User, None, &[])
    }

    /// The check with every knob.
    #[allow(clippy::too_many_arguments)]
    fn full(
        sd: &[u8],
        subject: Subject<'_>,
        desired: u32,
        previously: u32,
        mode: CallerMode,
        principal_self: Option<&[u8]>,
        object_types: &[Guid],
    ) -> Outcome {
        access_check(&AccessCheck {
            sd,
            subject,
            desired,
            mapping: MAPPING,
            previously_granted: previously,
            mode,
            principal_self,
            object_types,
        })
    }

    // -- the matrix --------------------------------------------------------------

    /// The generic mapping maps the generic rights and clears them, leaving MAXIMUM_ALLOWED.
    #[test]
    fn generic_mapping_maps_the_generic_rights() {
        assert_eq!(MAPPING.map(GENERIC_READ), READ_CONTROL | 0x1);
        assert_eq!(MAPPING.map(GENERIC_READ | 0x8), READ_CONTROL | 0x1 | 0x8);
        assert_eq!(
            MAPPING.map(GENERIC_ALL | GENERIC_WRITE),
            MAPPING.generic_all | MAPPING.generic_write
        );
        assert_eq!(MAPPING.map(0), 0);
        assert_eq!(
            MAPPING.map(MAXIMUM_ALLOWED),
            MAXIMUM_ALLOWED,
            "MAXIMUM_ALLOWED is the check's to handle"
        );
        assert_eq!(MAPPING.map(GENERIC_READ).count_ones(), (READ_CONTROL | 0x1).count_ones());
    }

    /// Kernel-mode callers are granted whatever they ask for, without the descriptor being
    /// looked at: MAXIMUM_ALLOWED as the kind's generic-all plus the other asked bits.
    #[test]
    fn kernel_mode_is_granted_unconditionally() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[denied(0xFFFF_FFFF, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            full(&sd, subj, 0x7, 0, CallerMode::Kernel, None, &[]),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            full(&sd, subj, MAXIMUM_ALLOWED | DELETE, 0, CallerMode::Kernel, None, &[]),
            Outcome {
                granted: MAPPING.generic_all | DELETE,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            full(&sd, subj, 0x7, 0x100, CallerMode::Kernel, None, &[]),
            Outcome {
                granted: 0x7 | 0x100,
                status: STATUS_SUCCESS
            }
        );
        // Even with no descriptor at all.
        assert_eq!(
            full(&[], subj, 0x7, 0, CallerMode::Kernel, None, &[]),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
    }

    /// A plain allow ACE for the token's user grants its mask; an ACE for a SID the token
    /// does not hold grants nothing.
    #[test]
    fn allow_ace_for_the_user_grants() {
        let user = user_sid();
        let other = other_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[allowed(0x7, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x7),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
        // The same descriptor, a subject that is not the ACE's SID.
        let sids2 = [SidAndAttributes {
            sid: &other,
            attributes: 0,
        }];
        let subj2 = same_tokens(&sids2, &other, &[]);
        assert_eq!(
            run(&sd, subj2, 0x7),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
    }

    /// The generic rights in the desired mask are mapped before the walk: GENERIC_READ asks
    /// for the mapping's read rights, and the granted mask shows them, not the generic bit.
    #[test]
    fn generic_rights_are_mapped_first() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[allowed(READ_CONTROL | 0x1, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        let out = run(&sd, subj, GENERIC_READ);
        assert_eq!(
            out,
            Outcome {
                granted: READ_CONTROL | 0x1,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(out.granted & GENERIC_READ, 0);
    }

    /// Previously granted access is added to the grant — and zeroed when the check denies.
    #[test]
    fn previously_granted_is_added_and_zeroed_on_denial() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[allowed(0x1, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            full(&sd, subj, 0x1, DELETE, CallerMode::User, None, &[]),
            Outcome {
                granted: 0x1 | DELETE,
                status: STATUS_SUCCESS
            }
        );
        // 0x2 is not granted by any ACE: the whole check is denied, granted mask and all.
        assert_eq!(
            full(&sd, subj, 0x1 | 0x2, DELETE, CallerMode::User, None, &[]),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
    }

    /// A zero desired mask is denied unless something was already granted.
    #[test]
    fn zero_desired_access() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let sd = descriptor(Some(&user), true, None);
        assert_eq!(
            run(&sd, subj, 0),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        assert_eq!(
            full(&sd, subj, 0, DELETE, CallerMode::User, None, &[]),
            Outcome {
                granted: DELETE,
                status: STATUS_SUCCESS
            }
        );
    }

    /// Deny-first ordering: a matching deny whose mask intersects the remaining mask denies
    /// the check at once — a later allow does not override it; an earlier allow that already
    /// cleared the mask wins; a deny whose mask no longer intersects remaining does not fire.
    #[test]
    fn deny_first_wins_over_a_later_allow() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        // Deny 0x1 first, then allow 0x1|0x2: desired 0x1|0x2 is denied.
        let dacl = acl(&[denied(0x1, &user), allowed(0x3, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x3),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        // Allow 0x1 first, then deny 0x1: desired 0x1 is granted (the walk ends at zero).
        let dacl = acl(&[allowed(0x1, &user), denied(0x1, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x1),
            Outcome {
                granted: 0x1,
                status: STATUS_SUCCESS
            }
        );
        // Deny 0x1, allow 0x2, desired 0x2: the deny's mask does not intersect remaining.
        let dacl = acl(&[denied(0x1, &user), allowed(0x2, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x2),
            Outcome {
                granted: 0x2,
                status: STATUS_SUCCESS
            }
        );
        // Deny 0x1, allow 0x2, desired 0x1|0x2: the deny still intersects remaining 0x1.
        assert_eq!(
            run(&sd, subj, 0x3),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
    }

    /// Groups: index 0 (the user) always matches; a group matches an allow ACE only when
    /// enabled, and a deny ACE when enabled or deny-only.
    #[test]
    fn groups_need_enabled_and_deny_only_matches_denies() {
        let user = user_sid();
        let group = other_sid();
        let sd_for = |aces: &[Vec<u8>]| descriptor(Some(&user), true, Some(&acl(aces)));

        // An enabled group: both its allow and its deny match.
        let enabled = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }, SidAndAttributes {
            sid: &group,
            attributes: SE_GROUP_ENABLED,
        }];
        let subj = same_tokens(&enabled, &user, &[]);
        assert_eq!(
            run(&sd_for(&[allowed(0x7, &group)]), subj, 0x7),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
        let sd = sd_for(&[denied(0x7, &group), allowed(0x7, WORLD_SID)]);
        assert_eq!(
            run(&sd, subj, 0x7),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );

        // A group with no attributes: neither its allow nor its deny matches.
        let plain = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }, SidAndAttributes {
            sid: &group,
            attributes: 0,
        }];
        let subj = same_tokens(&plain, &user, &[]);
        assert_eq!(
            run(&sd_for(&[allowed(0x7, &group)]), subj, 0x7).status,
            STATUS_ACCESS_DENIED
        );
        let sd = sd_for(&[denied(0x7, &group), allowed(0x7, WORLD_SID)]);
        assert_eq!(
            run(&sd, subj, 0x7),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            },
            "a not-enabled group's deny ACE does not fire"
        );

        // A deny-only group: its deny matches, its allow does not.
        let deny_only = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }, SidAndAttributes {
            sid: &group,
            attributes: SE_GROUP_USE_FOR_DENY_ONLY,
        }];
        let subj = same_tokens(&deny_only, &user, &[]);
        let sd = sd_for(&[denied(0x7, &group), allowed(0x7, WORLD_SID)]);
        assert_eq!(
            run(&sd, subj, 0x7).status,
            STATUS_ACCESS_DENIED,
            "a deny-only group's deny ACE fires"
        );
        assert_eq!(
            run(&sd_for(&[allowed(0x7, &group)]), subj, 0x7).status,
            STATUS_ACCESS_DENIED,
            "a deny-only group's allow ACE does not"
        );

        // The user at index 0 matches with no attributes at all.
        let subj = same_tokens(&plain, &user, &[]);
        assert_eq!(
            run(&sd_for(&[allowed(0x7, &user)]), subj, 0x7),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
    }

    /// The owner of the descriptor is implicitly granted READ_CONTROL and WRITE_DAC, even
    /// against a DACL that denies everything; with MAXIMUM_ALLOWED asked for, both come
    /// along with whatever the maximum walk finds.
    #[test]
    fn owner_gets_read_control_and_write_dac() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let deny_all = acl(&[denied(0xFFFF_FFFF, &user)]);
        let sd = descriptor(Some(&user), true, Some(&deny_all));
        assert_eq!(
            run(&sd, subj, READ_CONTROL | WRITE_DAC),
            Outcome {
                granted: READ_CONTROL | WRITE_DAC,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            run(&sd, subj, READ_CONTROL),
            Outcome {
                granted: READ_CONTROL,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED),
            Outcome {
                granted: READ_CONTROL | WRITE_DAC,
                status: STATUS_SUCCESS
            }
        );
        // A subject that is not the owner gets nothing implicitly.
        let other = other_sid();
        let sids2 = [SidAndAttributes {
            sid: &other,
            attributes: 0,
        }];
        let subj2 = same_tokens(&sids2, &other, &[]);
        assert_eq!(
            run(&sd, subj2, READ_CONTROL | WRITE_DAC),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        // The owner SID may sit in an enabled group, not just at index 0.
        let admins = ALIAS_ADMINS_SID.to_vec();
        let sids3 = [
            SidAndAttributes {
                sid: &user,
                attributes: 0,
            },
            SidAndAttributes {
                sid: &admins,
                attributes: SE_GROUP_ENABLED,
            },
        ];
        let subj3 = same_tokens(&sids3, &user, &[]);
        let sd = descriptor(Some(&admins), true, Some(&acl(&[])));
        assert_eq!(
            run(&sd, subj3, READ_CONTROL | WRITE_DAC),
            Outcome {
                granted: READ_CONTROL | WRITE_DAC,
                status: STATUS_SUCCESS
            }
        );
    }

    /// MAXIMUM_ALLOWED walks the DACL once, OR-ing the matching allows' masks minus what
    /// earlier denies took (and the denies minus what earlier allows granted).
    #[test]
    fn maximum_allowed_ors_the_allow_masks() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let everyone = WORLD_SID;
        // Deny 0x1 first, then allow 0x1|0x2|0x4 to everyone: the maximum is 0x2|0x4.
        let dacl = acl(&[denied(0x1, &user), allowed(0x7, everyone)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED),
            Outcome {
                granted: 0x6,
                status: STATUS_SUCCESS
            }
        );
        // Allow first, then deny: the deny only takes what was not already granted.
        let dacl = acl(&[allowed(0x3, everyone), denied(0x1, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED),
            Outcome {
                granted: 0x3,
                status: STATUS_SUCCESS
            }
        );
        // Extra bits asked alongside MAXIMUM_ALLOWED must be granted too, or all is denied.
        let dacl = acl(&[allowed(0x7, everyone)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED | DELETE),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED | 0x1),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
    }

    /// A missing DACL (flag clear) or a null DACL (present, field zero) grants everything;
    /// MAXIMUM_ALLOWED against one answers the kind's generic-all plus the other asked bits.
    #[test]
    fn no_dacl_grants_everything() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let sd = descriptor(Some(&user), false, None);
        assert_eq!(
            run(&sd, subj, 0x7 | READ_CONTROL),
            Outcome {
                granted: 0x7 | READ_CONTROL,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            run(&sd, subj, MAXIMUM_ALLOWED | 0x1),
            Outcome {
                granted: MAPPING.generic_all | 0x1,
                status: STATUS_SUCCESS
            }
        );
        let null_dacl = descriptor(Some(&user), true, None);
        assert_eq!(
            run(&null_dacl, subj, 0x7),
            Outcome {
                granted: 0x7,
                status: STATUS_SUCCESS
            }
        );
    }

    /// A present DACL with no ACEs denies everything — except a lone MAXIMUM_ALLOWED when
    /// something was already granted.
    #[test]
    fn empty_dacl_denies() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let sd = descriptor(Some(&user), true, Some(&acl(&[])));
        assert_eq!(
            run(&sd, subj, 0x1),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        assert_eq!(
            full(&sd, subj, MAXIMUM_ALLOWED, 0, CallerMode::User, None, &[]),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        assert_eq!(
            full(&sd, subj, MAXIMUM_ALLOWED, DELETE, CallerMode::User, None, &[]),
            Outcome {
                granted: DELETE,
                status: STATUS_SUCCESS
            }
        );
    }

    /// ACCESS_SYSTEM_SECURITY needs the security privilege enabled: held but disabled is not
    /// enough, and a grant-all DACL does not cover it either.
    #[test]
    fn access_system_security_needs_the_privilege_enabled() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let dacl = acl(&[allowed(0x1, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        let no_dacl = descriptor(Some(&user), false, None);

        let subj = same_tokens(&sids, &user, &[]);
        assert_eq!(
            run(&sd, subj, ACCESS_SYSTEM_SECURITY),
            Outcome {
                granted: 0,
                status: STATUS_PRIVILEGE_NOT_HELD
            }
        );
        assert_eq!(
            run(&no_dacl, subj, ACCESS_SYSTEM_SECURITY),
            Outcome {
                granted: 0,
                status: STATUS_PRIVILEGE_NOT_HELD
            },
            "a null DACL grants everything but ACCESS_SYSTEM_SECURITY"
        );

        let held_disabled = [privilege(SE_SECURITY_PRIVILEGE, 0)];
        let subj = same_tokens(&sids, &user, &held_disabled);
        assert_eq!(
            run(&sd, subj, ACCESS_SYSTEM_SECURITY).status,
            STATUS_PRIVILEGE_NOT_HELD
        );

        let enabled = [privilege(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED)];
        let subj = same_tokens(&sids, &user, &enabled);
        assert_eq!(
            run(&sd, subj, ACCESS_SYSTEM_SECURITY),
            Outcome {
                granted: ACCESS_SYSTEM_SECURITY,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            run(&sd, subj, ACCESS_SYSTEM_SECURITY | 0x1),
            Outcome {
                granted: ACCESS_SYSTEM_SECURITY | 0x1,
                status: STATUS_SUCCESS
            }
        );
    }

    /// WRITE_OWNER is granted to the owner or to a subject holding the take-ownership
    /// privilege enabled; otherwise the DACL walk decides.
    #[test]
    fn write_owner_needs_owner_or_the_privilege() {
        let user = user_sid();
        let other = other_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let empty = descriptor(Some(&user), true, Some(&acl(&[])));

        // The owner, against an empty DACL.
        let subj = same_tokens(&sids, &user, &[]);
        assert_eq!(
            run(&empty, subj, WRITE_OWNER),
            Outcome {
                granted: WRITE_OWNER,
                status: STATUS_SUCCESS
            }
        );

        // Not the owner, but the privilege enabled.
        let sids2 = [SidAndAttributes {
            sid: &other,
            attributes: 0,
        }];
        let privs = [privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED)];
        let subj = same_tokens(&sids2, &other, &privs);
        let sd = descriptor(Some(&user), true, Some(&acl(&[])));
        assert_eq!(
            run(&sd, subj, WRITE_OWNER),
            Outcome {
                granted: WRITE_OWNER,
                status: STATUS_SUCCESS
            }
        );

        // Not the owner, privilege held but disabled, DACL allows WRITE_OWNER: the walk grants it.
        let privs = [privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, 0)];
        let subj = same_tokens(&sids2, &other, &privs);
        let dacl = acl(&[allowed(WRITE_OWNER, &other)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, WRITE_OWNER),
            Outcome {
                granted: WRITE_OWNER,
                status: STATUS_SUCCESS
            }
        );

        // Not the owner, no privilege, nothing in the DACL: denied.
        let subj = same_tokens(&sids2, &other, &[]);
        let sd = descriptor(Some(&user), true, Some(&acl(&[])));
        assert_eq!(
            run(&sd, subj, WRITE_OWNER),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
    }

    /// An object ACE with no object-type GUID applies to the object itself, like a plain ACE.
    #[test]
    fn object_ace_without_a_type_applies_to_the_object() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x5, None, &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x5),
            Outcome {
                granted: 0x5,
                status: STATUS_SUCCESS
            }
        );
    }

    /// A typed object allow ACE grants only when the caller's object-type list holds the
    /// ACE's GUID; with no list, no object-ACE grants.
    #[test]
    fn typed_object_allow_needs_the_type_in_the_callers_list() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let g1 = guid(0x1111);
        let g2 = guid(0x2222);
        let dacl = acl(&[object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x5, Some(g1), &user)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        // No type list: no grant.
        assert_eq!(
            run(&sd, subj, 0x5).status,
            STATUS_ACCESS_DENIED
        );
        // The list holds the ACE's GUID: grant.
        assert_eq!(
            full(&sd, subj, 0x5, 0, CallerMode::User, None, &[g1]),
            Outcome {
                granted: 0x5,
                status: STATUS_SUCCESS
            }
        );
        // A list without it: no grant.
        assert_eq!(
            full(&sd, subj, 0x5, 0, CallerMode::User, None, &[g2]).status,
            STATUS_ACCESS_DENIED
        );
    }

    /// A typed object deny ACE applies to the whole object when the caller has no type list,
    /// and only when the list holds the GUID otherwise.
    #[test]
    fn typed_object_deny_applies_without_a_list() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let everyone = WORLD_SID;
        let g1 = guid(0x1111);
        let g2 = guid(0x2222);
        let dacl = acl(&[
            object_ace(ACCESS_DENIED_OBJECT_ACE_TYPE, 0x1, Some(g1), &user),
            allowed(0x7, everyone),
        ]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        // No list: the typed deny applies to the object, 0x1 is denied (the rest granted? no:
        // the whole check is denied).
        assert_eq!(
            run(&sd, subj, 0x1 | 0x2),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        // A list holding the GUID: same denial.
        assert_eq!(
            full(&sd, subj, 0x1, 0, CallerMode::User, None, &[g1]).status,
            STATUS_ACCESS_DENIED
        );
        // A list without the GUID: the deny does not apply, the allow grants.
        assert_eq!(
            full(&sd, subj, 0x1 | 0x2, 0, CallerMode::User, None, &[g2]),
            Outcome {
                granted: 0x3,
                status: STATUS_SUCCESS
            }
        );
    }

    /// A compound ACE grants only when its client SID is in the effective token and its
    /// server SID in the primary token.
    #[test]
    fn compound_ace_needs_client_in_effective_and_server_in_primary() {
        let user = user_sid();
        let client = other_sid();
        let server = sid(5, &[32, 544]);
        // Effective token: the impersonated client. Primary token: the user plus the server group.
        let eff = [SidAndAttributes {
            sid: &client,
            attributes: 0,
        }];
        let eff_token = TokenView {
            sids: &eff,
            owner: &client,
            privileges: &[],
        };
        let prim = [
            SidAndAttributes {
                sid: &user,
                attributes: 0,
            },
            SidAndAttributes {
                sid: &server,
                attributes: SE_GROUP_ENABLED,
            },
        ];
        let prim_token = TokenView {
            sids: &prim,
            owner: &user,
            privileges: &[],
        };
        let subj = Subject {
            effective: eff_token,
            primary: prim_token,
        };
        let dacl = acl(&[compound(0x9, &server, &client)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x9),
            Outcome {
                granted: 0x9,
                status: STATUS_SUCCESS
            }
        );
        // The server SID not in the primary token: no grant.
        let prim2 = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let prim_token2 = TokenView {
            sids: &prim2,
            owner: &user,
            privileges: &[],
        };
        let subj2 = Subject {
            effective: eff_token,
            primary: prim_token2,
        };
        assert_eq!(run(&sd, subj2, 0x9).status, STATUS_ACCESS_DENIED);
        // The client SID not in the effective token: no grant.
        let eff2 = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let eff_token2 = TokenView {
            sids: &eff2,
            owner: &user,
            privileges: &[],
        };
        let subj3 = Subject {
            effective: eff_token2,
            primary: prim_token,
        };
        assert_eq!(run(&sd, subj3, 0x9).status, STATUS_ACCESS_DENIED);
    }

    /// An ACE's principal-self SID is replaced by the object's own SID when the object
    /// represents a principal; without one, it matches nothing.
    #[test]
    fn principal_self_is_replaced_by_the_objects_sid() {
        let user = user_sid();
        let other = other_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let self_sid = SELF_SID;
        let dacl = acl(&[allowed(0x3, self_sid)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        // The object is the user: the ACE's principal-self SID becomes the user's.
        assert_eq!(
            full(&sd, subj, 0x3, 0, CallerMode::User, Some(&user), &[]),
            Outcome {
                granted: 0x3,
                status: STATUS_SUCCESS
            }
        );
        // The object is someone else: no match.
        assert_eq!(
            full(&sd, subj, 0x3, 0, CallerMode::User, Some(&other), &[]).status,
            STATUS_ACCESS_DENIED
        );
        // The object represents no principal: the constant matches nothing.
        assert_eq!(
            run(&sd, subj, 0x3).status,
            STATUS_ACCESS_DENIED
        );
        // A deny ACE with the principal-self SID denies the object's own SID.
        let dacl = acl(&[denied(0x1, self_sid), allowed(0x3, WORLD_SID)]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            full(&sd, subj, 0x3, 0, CallerMode::User, Some(&user), &[]),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
    }

    /// ACEs that apply to children only are skipped, and the audit/alarm types are ignored.
    #[test]
    fn inherit_only_and_audit_aces_are_skipped() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);
        let dacl = acl(&[
            plain_ace(ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE, 0x7, &user),
            allowed(0x1, &user),
        ]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x7),
            Outcome {
                granted: 0x1,
                status: STATUS_SUCCESS
            },
            "only the 0x1 was granted"
        );
        let dacl = acl(&[
            plain_ace(SYSTEM_AUDIT_ACE_TYPE, 0, 0x2, &user),
            allowed(0x1, &user),
        ]);
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(
            run(&sd, subj, 0x1 | 0x2),
            Outcome {
                granted: 0x1,
                status: STATUS_SUCCESS
            }
        );
        assert_eq!(
            run(&sd, subj, 0x2),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            },
            "an audit ACE grants nothing"
        );
    }

    /// Structural problems report their own statuses: a malformed DACL, an out-of-range part,
    /// a bad owner SID, an unknown revision, a short header — and no descriptor at all is a
    /// plain denial in user mode.
    #[test]
    fn malformed_parts_report_their_status() {
        let user = user_sid();
        let sids = [SidAndAttributes {
            sid: &user,
            attributes: 0,
        }];
        let subj = same_tokens(&sids, &user, &[]);

        // No descriptor at all.
        assert_eq!(
            run(&[], subj, 0x1),
            Outcome {
                granted: 0,
                status: STATUS_ACCESS_DENIED
            }
        );
        // A slice too short for a header.
        let sd = descriptor(Some(&user), true, None);
        assert_eq!(
            run(&sd[..10], subj, 0x1).status,
            STATUS_BUFFER_TOO_SMALL
        );
        // An unknown revision.
        let mut bad = sd.clone();
        bad[0] = 2;
        assert_eq!(run(&bad, subj, 0x1).status, STATUS_UNKNOWN_REVISION);
        // A DACL with a revision out of range.
        let mut dacl = acl(&[allowed(0x1, &user)]);
        dacl[0] = 9;
        let sd = descriptor(Some(&user), true, Some(&dacl));
        assert_eq!(run(&sd, subj, 0x1).status, STATUS_INVALID_ACL);
        // A DACL whose buffer is shorter than its size word.
        let dacl = acl(&[allowed(0x1, &user)]);
        let short = &dacl[..dacl.len() - 4];
        let sd = descriptor(Some(&user), true, Some(short));
        assert_eq!(run(&sd, subj, 0x1).status, STATUS_INVALID_ACL);
        // A DACL offset outside the descriptor's bytes.
        let dacl = acl(&[allowed(0x1, &user)]);
        let mut sd = descriptor(Some(&user), true, Some(&dacl));
        let mut h = SecurityDescriptor::parse(&sd).unwrap();
        h.dacl = 0xF000;
        assert!(h.write(&mut sd[..]));
        assert_eq!(
            run(&sd, subj, 0x1).status,
            STATUS_INVALID_SECURITY_DESCR
        );
        // An owner SID that is truncated.
        let owner = user_sid();
        let sd = descriptor(Some(&owner[..10]), true, None);
        assert_eq!(run(&sd, subj, 0x1).status, STATUS_INVALID_SID);
    }
}
