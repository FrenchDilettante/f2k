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
//!
//! The ACE bytes are read through [`AceViews`] (in `check_aces`).
#![allow(dead_code)]

use rtl::nt::access::{
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER,
};
use rtl::nt::LuidAndAttributes;

use crate::sec::{
    ace_count, equal, held_enabled, luid, AceView, AceViews, Guid, SecurityDescriptor,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, INHERIT_ONLY_ACE, PRINCIPAL_SELF_SID,
    SE_DACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE,
    SECURITY_DESCRIPTOR_MIN_LENGTH, SECURITY_DESCRIPTOR_REVISION, STATUS_INVALID_SECURITY_DESCR,
    STATUS_UNKNOWN_REVISION,
};
// A few names exist in both the ACL and the SD (or SID) module, so the glob above cannot
// disambiguate them; take those from their module.
use crate::sec::acl::{is_valid as acl_is_valid, STATUS_INVALID_ACL};
use crate::sec::sd::STATUS_INVALID_SID;
use crate::sec::sid::length as sid_length;
use crate::status::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_PRIVILEGE_NOT_HELD,
    STATUS_SUCCESS,
};

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

/// The SID a descriptor part field names: its bytes, or None when the field is zero (no
/// part). The field is an offset in self-relative form and an address in the slice's own
/// space in absolute form, so both read the same here. STATUS_INVALID_SID when the bytes
/// are no valid SID, STATUS_INVALID_SECURITY_DESCR when the field points outside the slice.
fn part_sid<'a>(
    sd: &'a [u8],
    header: &SecurityDescriptor,
    field: u32,
) -> Result<Option<&'a [u8]>, NtStatus> {
    if field == 0 {
        return Ok(None);
    }
    let at = header.addr_of(0, field) as usize;
    let bytes = sd.get(at..).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    let len = sid_length(bytes).ok_or(STATUS_INVALID_SID)?;
    Ok(Some(&bytes[..len]))
}

/// The descriptor's DACL, validated: Some(bytes) when the SE_DACL_PRESENT flag is set and
/// the field is non-zero; None when the flag is clear or the field is zero (a null DACL,
/// which grants everything). STATUS_INVALID_ACL when the bytes are no well-formed ACL.
fn part_dacl<'a>(sd: &'a [u8], header: &SecurityDescriptor) -> Result<Option<&'a [u8]>, NtStatus> {
    if !header.has_control(SE_DACL_PRESENT) || header.dacl == 0 {
        return Ok(None);
    }
    let at = header.addr_of(0, header.dacl) as usize;
    let bytes = sd.get(at..).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    if !acl_is_valid(bytes) {
        return Err(STATUS_INVALID_ACL);
    }
    Ok(Some(bytes))
}

/// Whether `sid` is in `token`: the user (index 0) always matches; a group matches when it
/// is enabled — or, for a deny ACE, when it is deny-only. An ACE's principal-self SID is
/// replaced by `principal_self` when the object represents a principal.
fn sid_in_token(
    token: &TokenView<'_>,
    principal_self: Option<&[u8]>,
    sid: &[u8],
    deny_ace: bool,
) -> bool {
    let sid = match principal_self {
        Some(self_sid) if equal(sid, PRINCIPAL_SELF_SID) => self_sid,
        _ => sid,
    };
    for (index, entry) in token.sids.iter().enumerate() {
        if equal(sid, entry.sid) {
            return index == 0
                || entry.attributes & SE_GROUP_ENABLED != 0
                || (deny_ace && entry.attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0);
        }
    }
    false
}

/// Whether an object ACE naming `ace_type` applies to the object itself in this check: an
/// ACE with no type GUID always does; a typed one does when the caller's type list holds
/// the GUID — except a deny with no caller list, which applies to the whole object.
fn object_ace_applies(ace_type: Option<Guid>, object_types: &[Guid], deny: bool) -> bool {
    match ace_type {
        None => true,
        Some(_) if object_types.is_empty() => deny,
        Some(guid) => object_types.contains(&guid),
    }
}

/// The subject's tokens' SIDs an ACE is matched against, with `deny_ace` telling whether
/// the ACE is a deny one.
fn ace_sid_matches(check: &AccessCheck<'_>, ace: &AceView<'_>, deny_ace: bool) -> bool {
    match ace.sid() {
        Some(sid) => sid_in_token(&check.subject.effective, check.principal_self, sid, deny_ace),
        None => false,
    }
}

/// The normal walk over the DACL's ACEs in order, keeping `remaining`: a matching allow
/// clears its mask from what remains, a matching deny whose mask intersects what remains
/// stops the walk (the first matching deny in walk order wins). Returns what stays
/// ungranted.
fn normal_walk(dacl: &[u8], check: &AccessCheck<'_>, mut remaining: u32) -> u32 {
    for ace in AceViews::new(dacl) {
        if ace.flags() & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = ace.mask();
        match ace.ace_type() {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                let typed = ace.ace_type() == ACCESS_ALLOWED_OBJECT_ACE_TYPE;
                if typed && !object_ace_applies(ace.object_type(), check.object_types, false) {
                    continue;
                }
                if let Some(mask) = mask {
                    if ace_sid_matches(check, &ace, false) {
                        remaining &= !mask;
                    }
                }
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                if let (Some(mask), Some(client), Some(server)) =
                    (mask, ace.second_sid(), ace.sid())
                {
                    if sid_in_token(&check.subject.effective, check.principal_self, client, false)
                        && sid_in_token(&check.subject.primary, None, server, false)
                    {
                        remaining &= !mask;
                    }
                }
            }
            ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
                let typed = ace.ace_type() == ACCESS_DENIED_OBJECT_ACE_TYPE;
                if typed && !object_ace_applies(ace.object_type(), check.object_types, true) {
                    continue;
                }
                if let Some(mask) = mask {
                    if ace_sid_matches(check, &ace, true) && remaining & mask != 0 {
                        return remaining;
                    }
                }
            }
            _ => {}
        }
        if remaining == 0 {
            break;
        }
    }
    remaining
}

/// The MAXIMUM_ALLOWED walk: one pass over the DACL, OR-ing each matching allow's mask
/// (minus what earlier denies took) into the granted mask, and each matching deny's mask
/// (minus what earlier allows granted) into the denied mask. Returns the granted mask.
fn maximum_walk(dacl: &[u8], check: &AccessCheck<'_>) -> u32 {
    let mut granted = 0u32;
    let mut denied = 0u32;
    for ace in AceViews::new(dacl) {
        if ace.flags() & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = ace.mask();
        match ace.ace_type() {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                let typed = ace.ace_type() == ACCESS_ALLOWED_OBJECT_ACE_TYPE;
                if typed && !object_ace_applies(ace.object_type(), check.object_types, false) {
                    continue;
                }
                if let Some(mask) = mask {
                    if ace_sid_matches(check, &ace, false) {
                        granted |= mask & !denied;
                    }
                }
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                if let (Some(mask), Some(client), Some(server)) =
                    (mask, ace.second_sid(), ace.sid())
                {
                    if sid_in_token(&check.subject.effective, check.principal_self, client, false)
                        && sid_in_token(&check.subject.primary, None, server, false)
                    {
                        granted |= mask & !denied;
                    }
                }
            }
            ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
                let typed = ace.ace_type() == ACCESS_DENIED_OBJECT_ACE_TYPE;
                if typed && !object_ace_applies(ace.object_type(), check.object_types, true) {
                    continue;
                }
                if let Some(mask) = mask {
                    if ace_sid_matches(check, &ace, true) {
                        denied |= mask & !granted;
                    }
                }
            }
            _ => {}
        }
    }
    granted
}

/// An outcome of `granted` and `status`.
fn outcome(granted: u32, status: NtStatus) -> Outcome {
    Outcome { granted, status }
}

/// Run the access check: the granted mask and the status (see the module notes for the
/// rules the walk follows).
pub fn access_check(check: &AccessCheck<'_>) -> Outcome {
    // Kernel-mode callers are granted unconditionally.
    if check.mode == CallerMode::Kernel {
        let granted = if check.desired & MAXIMUM_ALLOWED != 0 {
            check.mapping.generic_all
                | (check.desired & !MAXIMUM_ALLOWED)
                | check.previously_granted
        } else {
            check.desired | check.previously_granted
        };
        return outcome(granted, STATUS_SUCCESS);
    }

    // No descriptor at all is a denial; a malformed header reports its own status.
    if check.sd.is_empty() {
        return outcome(0, STATUS_ACCESS_DENIED);
    }
    if check.sd.len() < SECURITY_DESCRIPTOR_MIN_LENGTH {
        return outcome(0, STATUS_BUFFER_TOO_SMALL);
    }
    let Some(header) = SecurityDescriptor::parse(check.sd) else {
        return outcome(0, STATUS_BUFFER_TOO_SMALL);
    };
    if header.revision != SECURITY_DESCRIPTOR_REVISION {
        return outcome(0, STATUS_UNKNOWN_REVISION);
    }

    // The generic rights map to the type's own before anything else; MAXIMUM_ALLOWED stays.
    let mut desired = check.mapping.map(check.desired);
    let mut granted = check.previously_granted;

    if desired == 0 {
        return if granted == 0 {
            outcome(0, STATUS_ACCESS_DENIED)
        } else {
            outcome(granted, STATUS_SUCCESS)
        };
    }

    // The owner of the descriptor is implicitly granted READ_CONTROL and WRITE_DAC.
    let owner = match part_sid(check.sd, &header, header.owner) {
        Ok(owner) => owner,
        Err(status) => return outcome(0, status),
    };
    let is_owner =
        owner.is_some_and(|sid| sid_in_token(&check.subject.effective, None, sid, false));
    if is_owner && desired & (READ_CONTROL | WRITE_DAC | MAXIMUM_ALLOWED) != 0 {
        granted |= if desired & MAXIMUM_ALLOWED != 0 {
            READ_CONTROL | WRITE_DAC
        } else {
            desired & (READ_CONTROL | WRITE_DAC)
        };
        desired &= !(READ_CONTROL | WRITE_DAC);
    }
    if desired == 0 {
        return outcome(granted, STATUS_SUCCESS);
    }

    // ACCESS_SYSTEM_SECURITY needs the security privilege enabled.
    if desired & ACCESS_SYSTEM_SECURITY != 0 {
        if !held_enabled(check.subject.effective.privileges, luid(SE_SECURITY_PRIVILEGE)) {
            return outcome(0, STATUS_PRIVILEGE_NOT_HELD);
        }
        desired &= !ACCESS_SYSTEM_SECURITY;
        granted |= ACCESS_SYSTEM_SECURITY;
        if desired == 0 {
            return Outcome {
                granted,
                status: STATUS_SUCCESS,
            };
        }
    }

    // A missing or null DACL grants everything.
    let dacl = match part_dacl(check.sd, &header) {
        Ok(dacl) => dacl,
        Err(status) => return outcome(0, status),
    };
    let Some(dacl) = dacl else {
        granted = if desired & MAXIMUM_ALLOWED != 0 {
            check.mapping.generic_all | ((desired | granted) & !MAXIMUM_ALLOWED)
        } else {
            granted | desired
        };
        return outcome(granted, STATUS_SUCCESS);
    };

    // WRITE_OWNER: the owner, or the take-ownership privilege enabled.
    if desired & WRITE_OWNER != 0
        && (is_owner
            || held_enabled(
                check.subject.effective.privileges,
                luid(SE_TAKE_OWNERSHIP_PRIVILEGE),
            ))
    {
        desired &= !WRITE_OWNER;
        granted |= WRITE_OWNER;
        if desired == 0 {
            return Outcome {
                granted,
                status: STATUS_SUCCESS,
            };
        }
    }

    // A present DACL with no ACEs denies what remains — a lone MAXIMUM_ALLOWED succeeds
    // when something was already granted.
    if ace_count(dacl) == 0 {
        return if desired == MAXIMUM_ALLOWED && granted != 0 {
            outcome(granted, STATUS_SUCCESS)
        } else {
            outcome(0, STATUS_ACCESS_DENIED)
        };
    }

    if desired & MAXIMUM_ALLOWED != 0 {
        // The fast path: one pass OR-ing the matching allows together.
        let maximum = maximum_walk(dacl, check);
        if desired & !(MAXIMUM_ALLOWED | maximum) != 0 {
            return outcome(0, STATUS_ACCESS_DENIED);
        }
        granted |= maximum;
        return outcome(granted, STATUS_SUCCESS);
    }

    // The normal walk: whatever the ACEs leave ungranted is denied.
    let remaining = normal_walk(dacl, check, desired);
    if remaining != 0 {
        return outcome(0, STATUS_ACCESS_DENIED);
    }
    granted |= desired;
    outcome(granted, STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::acl::STATUS_INVALID_ACL;
    use crate::sec::sd::STATUS_INVALID_SID;
    use crate::sec::{
        ACL_REVISION2, ACL_REVISION3, ACL_REVISION_DS, COMPOUND_ACE_IMPERSONATION,
        SE_PRIVILEGE_ENABLED, SE_SELF_RELATIVE, SYSTEM_AUDIT_ACE_TYPE, WORLD_SID,
        ALIAS_ADMINS_SID, PRINCIPAL_SELF_SID as SELF_SID, privilege,
    };
    use crate::status::STATUS_BUFFER_TOO_SMALL;
    use rtl::nt::access::{DELETE, STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE};
    use std::vec::Vec;

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
        Guid { data1, data2: 0, data3: 0, data4: [0; 8] }
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
        let flags = u32::from(object_type.is_some());
        body.extend_from_slice(&flags.to_le_bytes());
        if let Some(g) = object_type {
            body.extend_from_slice(&guid_bytes(&g));
        }
        body.extend_from_slice(sid);
        ace(ace_type, 0, &body)
    }

    /// A compound access-allowed ACE of `mask`, server SID first, then the client's.
    fn compound(mask: u32, server: &[u8], client: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(&COMPOUND_ACE_IMPERSONATION.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(server);
        body.extend_from_slice(client);
        ace(ACCESS_ALLOWED_COMPOUND_ACE_TYPE, 0, &body)
    }

    /// An ACL's bytes: the header, then the ACEs, with the revision raised to fit them.
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

    /// A descriptor with a present DACL of `aces` and the given owner.
    fn sd(owner: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
        descriptor(Some(owner), true, Some(&acl(aces)))
    }

    // -- the subject builders ------------------------------------------------------

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
        let token = TokenView { sids, owner, privileges };
        Subject { effective: token, primary: token }
    }

    /// The test object type's mapping: read 0x1, write 0x2, execute 0x4, all 0xF, each with
    /// READ_CONTROL.
    const MAPPING: GenericMapping = GenericMapping {
        generic_read: READ_CONTROL | 0x1,
        generic_write: READ_CONTROL | 0x2,
        generic_execute: READ_CONTROL | 0x4,
        generic_all: STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xF,
    };

    /// The expected outcome of a fully granted check.
    fn ok(granted: u32) -> Outcome {
        Outcome { granted, status: STATUS_SUCCESS }
    }

    /// The expected outcome of a denied check: nothing granted at all.
    fn denied_outcome() -> Outcome {
        Outcome { granted: 0, status: STATUS_ACCESS_DENIED }
    }

    /// The plain user-mode check of a subject that is just `user`: no previously granted
    /// access, no principal-self SID, no object-type list.
    fn run(sd: &[u8], user: &[u8], desired: u32) -> Outcome {
        full(sd, user, desired, 0, CallerMode::User, None, &[])
    }

    /// The check of a subject that is just `user`, with every knob.
    #[allow(clippy::too_many_arguments)]
    fn full(
        sd: &[u8],
        user: &[u8],
        desired: u32,
        previously: u32,
        mode: CallerMode,
        principal_self: Option<&[u8]>,
        object_types: &[Guid],
    ) -> Outcome {
        let sids = [SidAndAttributes { sid: user, attributes: 0 }];
        full_s(sd, same_tokens(&sids, user, &[]), desired, previously, mode, principal_self, object_types)
    }

    /// The check of an already-built subject, with every knob.
    #[allow(clippy::too_many_arguments)]
    fn full_s(
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

    // -- the matrix ----------------------------------------------------------------

    /// The generic mapping maps the generic rights and clears them, leaving MAXIMUM_ALLOWED.
    #[test]
    fn generic_mapping_maps_the_generic_rights() {
        assert_eq!(MAPPING.map(GENERIC_READ), READ_CONTROL | 0x1);
        assert_eq!(MAPPING.map(GENERIC_READ | 0x8), READ_CONTROL | 0x9);
        assert_eq!(MAPPING.map(GENERIC_ALL | GENERIC_WRITE), MAPPING.generic_all | MAPPING.generic_write);
        assert_eq!(MAPPING.map(0), 0);
        assert_eq!(MAPPING.map(MAXIMUM_ALLOWED), MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED is the check's to handle");
    }

    /// Kernel-mode callers are granted whatever they ask for, without the descriptor being
    /// looked at: MAXIMUM_ALLOWED as the kind's generic-all plus the other asked bits.
    #[test]
    fn kernel_mode_is_granted_unconditionally() {
        let user = user_sid();
        let d = sd(&user, &[denied(0xFFFF_FFFF, &user)]);
        assert_eq!(full(&d, &user, 0x7, 0, CallerMode::Kernel, None, &[]), ok(0x7));
        assert_eq!(full(&d, &user, MAXIMUM_ALLOWED | DELETE, 0, CallerMode::Kernel, None, &[]), ok(MAPPING.generic_all | DELETE));
        assert_eq!(full(&d, &user, 0x7, 0x100, CallerMode::Kernel, None, &[]), ok(0x107));
        assert_eq!(full(&[], &user, 0x7, 0, CallerMode::Kernel, None, &[]), ok(0x7), "even with no descriptor");
    }

    /// A plain allow ACE for the token's user grants its mask; an ACE for a SID the token
    /// does not hold grants nothing.
    #[test]
    fn allow_ace_for_the_user_grants() {
        let user = user_sid();
        let other = other_sid();
        let d = sd(&user, &[allowed(0x7, &user)]);
        assert_eq!(run(&d, &user, 0x7), ok(0x7));
        assert_eq!(run(&d, &other, 0x7), denied_outcome());
    }

    /// The generic rights in the desired mask are mapped before the walk: GENERIC_READ asks
    /// for the mapping's read rights, and the granted mask shows them, not the generic bit.
    #[test]
    fn generic_rights_are_mapped_first() {
        let user = user_sid();
        let d = sd(&user, &[allowed(READ_CONTROL | 0x1, &user)]);
        let out = run(&d, &user, GENERIC_READ);
        assert_eq!(out, ok(READ_CONTROL | 0x1));
        assert_eq!(out.granted & GENERIC_READ, 0);
    }

    /// Previously granted access is added to the grant — and zeroed when the check denies.
    #[test]
    fn previously_granted_is_added_and_zeroed_on_denial() {
        let user = user_sid();
        let d = sd(&user, &[allowed(0x1, &user)]);
        assert_eq!(full(&d, &user, 0x1, DELETE, CallerMode::User, None, &[]), ok(0x1 | DELETE));
        // 0x2 is granted by no ACE: the whole check is denied, granted mask and all.
        assert_eq!(full(&d, &user, 0x1 | 0x2, DELETE, CallerMode::User, None, &[]), denied_outcome());
    }

    /// A zero desired mask is denied unless something was already granted.
    #[test]
    fn zero_desired_access() {
        let user = user_sid();
        let d = descriptor(Some(&user), true, None);
        assert_eq!(run(&d, &user, 0), denied_outcome());
        assert_eq!(full(&d, &user, 0, DELETE, CallerMode::User, None, &[]), ok(DELETE));
    }

    /// Deny-first ordering: a matching deny whose mask intersects the remaining mask denies
    /// the check at once — a later allow does not override it; an earlier allow that already
    /// cleared the mask wins; a deny whose mask no longer intersects remaining does not fire.
    #[test]
    fn deny_first_wins_over_a_later_allow() {
        let user = user_sid();
        // Deny 0x1 first, then allow 0x1|0x2: desired 0x1|0x2 is denied.
        assert_eq!(run(&sd(&user, &[denied(0x1, &user), allowed(0x3, &user)]), &user, 0x3), denied_outcome());
        // Allow 0x1 first, then deny 0x1: desired 0x1 is granted (the walk ends at zero).
        assert_eq!(run(&sd(&user, &[allowed(0x1, &user), denied(0x1, &user)]), &user, 0x1), ok(0x1));
        // Deny 0x1, allow 0x2: desired 0x2 is granted (the deny's mask does not intersect),
        // desired 0x1|0x2 is denied.
        let d = sd(&user, &[denied(0x1, &user), allowed(0x2, &user)]);
        assert_eq!(run(&d, &user, 0x2), ok(0x2));
        assert_eq!(run(&d, &user, 0x3), denied_outcome());
    }

    /// Groups: index 0 (the user) always matches; a group matches an allow ACE only when
    /// enabled, and a deny ACE when enabled or deny-only.
    #[test]
    fn groups_need_enabled_and_deny_only_matches_denies() {
        let user = user_sid();
        let group = other_sid();
        let allow_group = sd(&user, &[allowed(0x7, &group)]);
        let deny_then_allow = sd(&user, &[denied(0x7, &group), allowed(0x7, &user)]);
        let check = |sids: &[SidAndAttributes<'_>], d: &[u8]| {
            full_s(d, same_tokens(sids, &user, &[]), 0x7, 0, CallerMode::User, None, &[])
        };
        // Enabled: both its allow and its deny match.
        let enabled = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: &group, attributes: SE_GROUP_ENABLED },
        ];
        assert_eq!(check(&enabled, &allow_group), ok(0x7));
        assert_eq!(check(&enabled, &deny_then_allow), denied_outcome());
        // No attributes: neither matches.
        let plain = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: &group, attributes: 0 },
        ];
        assert_eq!(check(&plain, &allow_group), denied_outcome());
        assert_eq!(check(&plain, &deny_then_allow), ok(0x7), "a not-enabled group's deny does not fire");
        // Deny-only: its deny matches, its allow does not.
        let deny_only = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: &group, attributes: SE_GROUP_USE_FOR_DENY_ONLY },
        ];
        assert_eq!(check(&deny_only, &deny_then_allow), denied_outcome());
        assert_eq!(check(&deny_only, &allow_group), denied_outcome(), "a deny-only group's allow does not");
        // The user at index 0 matches with no attributes at all.
        assert_eq!(run(&sd(&user, &[allowed(0x7, &user)]), &user, 0x7), ok(0x7));
    }

    /// The owner of the descriptor is implicitly granted READ_CONTROL and WRITE_DAC, even
    /// against a DACL that denies everything; with MAXIMUM_ALLOWED asked for, both come
    /// along with whatever the maximum walk finds.
    #[test]
    fn owner_gets_read_control_and_write_dac() {
        let user = user_sid();
        let deny_all = sd(&user, &[denied(0xFFFF_FFFF, &user)]);
        assert_eq!(run(&deny_all, &user, READ_CONTROL | WRITE_DAC), ok(READ_CONTROL | WRITE_DAC));
        assert_eq!(run(&deny_all, &user, READ_CONTROL), ok(READ_CONTROL));
        assert_eq!(run(&deny_all, &user, MAXIMUM_ALLOWED), ok(READ_CONTROL | WRITE_DAC));
        // A subject that is not the owner gets nothing implicitly.
        assert_eq!(run(&deny_all, &other_sid(), READ_CONTROL | WRITE_DAC), denied_outcome());
        // The owner SID may sit in an enabled group, not just at index 0.
        let admins = ALIAS_ADMINS_SID.to_vec();
        let sids = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: &admins, attributes: SE_GROUP_ENABLED },
        ];
        let s = same_tokens(&sids, &user, &[]);
        assert_eq!(full_s(&sd(&admins, &[]), s, READ_CONTROL | WRITE_DAC, 0, CallerMode::User, None, &[]), ok(READ_CONTROL | WRITE_DAC));
    }

    /// MAXIMUM_ALLOWED walks the DACL once, OR-ing the matching allows' masks minus what
    /// earlier denies took (and the denies minus what earlier allows granted).
    #[test]
    fn maximum_allowed_ors_the_allow_masks() {
        let user = user_sid();
        let other = other_sid();
        let sids = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: WORLD_SID, attributes: SE_GROUP_ENABLED },
        ];
        let s = same_tokens(&sids, &user, &[]);
        // Deny 0x1 first, then allow 0x1|0x2|0x4 to everyone: the maximum is 0x2|0x4.
        assert_eq!(full_s(&sd(&other, &[denied(0x1, &user), allowed(0x7, WORLD_SID)]), s, MAXIMUM_ALLOWED, 0, CallerMode::User, None, &[]), ok(0x6));
        // Allow first, then deny: the deny only takes what was not already granted.
        assert_eq!(full_s(&sd(&other, &[allowed(0x3, WORLD_SID), denied(0x1, &user)]), s, MAXIMUM_ALLOWED, 0, CallerMode::User, None, &[]), ok(0x3));
        // Extra bits asked alongside MAXIMUM_ALLOWED must be granted too, or all is denied.
        let all = sd(&other, &[allowed(0x7, WORLD_SID)]);
        assert_eq!(full_s(&all, s, MAXIMUM_ALLOWED | DELETE, 0, CallerMode::User, None, &[]), denied_outcome());
        assert_eq!(full_s(&all, s, MAXIMUM_ALLOWED | 0x1, 0, CallerMode::User, None, &[]), ok(0x7));
    }

    /// A missing DACL (flag clear) or a null DACL (present, field zero) grants everything;
    /// MAXIMUM_ALLOWED against one answers the kind's generic-all plus the other asked bits.
    #[test]
    fn no_dacl_grants_everything() {
        let user = user_sid();
        let d = descriptor(Some(&user), false, None);
        assert_eq!(run(&d, &user, 0x7 | READ_CONTROL), ok(0x7 | READ_CONTROL));
        assert_eq!(run(&d, &user, MAXIMUM_ALLOWED | 0x1), ok(MAPPING.generic_all | 0x1));
        let null_dacl = descriptor(Some(&user), true, None);
        assert_eq!(run(&null_dacl, &user, 0x7), ok(0x7));
    }

    /// A present DACL with no ACEs denies everything — except a lone MAXIMUM_ALLOWED when
    /// something was already granted.
    #[test]
    fn empty_dacl_denies() {
        let user = user_sid();
        let d = sd(&other_sid(), &[]);
        assert_eq!(run(&d, &user, 0x1), denied_outcome());
        assert_eq!(full(&d, &user, MAXIMUM_ALLOWED, 0, CallerMode::User, None, &[]), denied_outcome());
        assert_eq!(full(&d, &user, MAXIMUM_ALLOWED, DELETE, CallerMode::User, None, &[]), ok(DELETE));
    }

    /// ACCESS_SYSTEM_SECURITY needs the security privilege enabled: held but disabled is not
    /// enough, and a grant-all DACL does not cover it either.
    #[test]
    fn access_system_security_needs_the_privilege_enabled() {
        let user = user_sid();
        let d = sd(&user, &[allowed(0x1, &user)]);
        let no_dacl = descriptor(Some(&user), false, None);
        let not_held = Outcome { granted: 0, status: STATUS_PRIVILEGE_NOT_HELD };
        let sids = [SidAndAttributes { sid: &user, attributes: 0 }];
        assert_eq!(full_s(&d, same_tokens(&sids, &user, &[]), ACCESS_SYSTEM_SECURITY, 0, CallerMode::User, None, &[]), not_held);
        assert_eq!(full_s(&no_dacl, same_tokens(&sids, &user, &[]), ACCESS_SYSTEM_SECURITY, 0, CallerMode::User, None, &[]), not_held, "a null DACL grants everything but ACCESS_SYSTEM_SECURITY");
        let disabled = [privilege(SE_SECURITY_PRIVILEGE, 0)];
        assert_eq!(full_s(&d, same_tokens(&sids, &user, &disabled), ACCESS_SYSTEM_SECURITY, 0, CallerMode::User, None, &[]), not_held);
        let enabled = [privilege(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED)];
        let s = same_tokens(&sids, &user, &enabled);
        assert_eq!(full_s(&d, s, ACCESS_SYSTEM_SECURITY, 0, CallerMode::User, None, &[]), ok(ACCESS_SYSTEM_SECURITY));
        assert_eq!(full_s(&d, s, ACCESS_SYSTEM_SECURITY | 0x1, 0, CallerMode::User, None, &[]), ok(ACCESS_SYSTEM_SECURITY | 0x1));
    }

    /// WRITE_OWNER is granted to the owner or to a subject holding the take-ownership
    /// privilege enabled; otherwise the DACL walk decides.
    #[test]
    fn write_owner_needs_owner_or_the_privilege() {
        let user = user_sid();
        let other = other_sid();
        // The owner, against an empty DACL.
        assert_eq!(run(&sd(&user, &[]), &user, WRITE_OWNER), ok(WRITE_OWNER));
        // Not the owner, but the privilege enabled.
        let sids = [SidAndAttributes { sid: &other, attributes: 0 }];
        let privs = [privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED)];
        assert_eq!(full_s(&sd(&user, &[]), same_tokens(&sids, &other, &privs), WRITE_OWNER, 0, CallerMode::User, None, &[]), ok(WRITE_OWNER));
        // Not the owner, privilege held but disabled: the DACL walk decides.
        let disabled = [privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, 0)];
        assert_eq!(full_s(&sd(&user, &[allowed(WRITE_OWNER, &other)]), same_tokens(&sids, &other, &disabled), WRITE_OWNER, 0, CallerMode::User, None, &[]), ok(WRITE_OWNER));
        assert_eq!(full_s(&sd(&user, &[]), same_tokens(&sids, &other, &[]), WRITE_OWNER, 0, CallerMode::User, None, &[]), denied_outcome());
    }

    /// An object ACE with no object-type GUID applies to the object itself, like a plain ACE.
    #[test]
    fn object_ace_without_a_type_applies_to_the_object() {
        let user = user_sid();
        let d = sd(&user, &[object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x5, None, &user)]);
        assert_eq!(run(&d, &user, 0x5), ok(0x5));
    }

    /// A typed object allow ACE grants only when the caller's object-type list holds the
    /// ACE's GUID; with no list, no object-ACE grants.
    #[test]
    fn typed_object_allow_needs_the_type_in_the_callers_list() {
        let user = user_sid();
        let g1 = guid(0x1111);
        let g2 = guid(0x2222);
        let d = sd(&user, &[object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x5, Some(g1), &user)]);
        assert_eq!(run(&d, &user, 0x5), denied_outcome(), "no type list: no grant");
        assert_eq!(full(&d, &user, 0x5, 0, CallerMode::User, None, &[g1]), ok(0x5));
        assert_eq!(full(&d, &user, 0x5, 0, CallerMode::User, None, &[g2]), denied_outcome());
    }

    /// A typed object deny ACE applies to the whole object when the caller has no type list,
    /// and only when the list holds the GUID otherwise.
    #[test]
    fn typed_object_deny_applies_without_a_list() {
        let user = user_sid();
        let g1 = guid(0x1111);
        let g2 = guid(0x2222);
        let d = sd(&user, &[
            object_ace(ACCESS_DENIED_OBJECT_ACE_TYPE, 0x1, Some(g1), &user),
            allowed(0x7, &user),
        ]);
        assert_eq!(run(&d, &user, 0x1 | 0x2), denied_outcome(), "no list: the typed deny applies to the object");
        assert_eq!(full(&d, &user, 0x1, 0, CallerMode::User, None, &[g1]), denied_outcome());
        assert_eq!(full(&d, &user, 0x1 | 0x2, 0, CallerMode::User, None, &[g2]), ok(0x3), "a list without the GUID: the deny does not apply");
    }

    /// A compound ACE grants only when its client SID is in the effective token and its
    /// server SID in the primary token.
    #[test]
    fn compound_ace_needs_client_in_effective_and_server_in_primary() {
        let user = user_sid();
        let client = other_sid();
        let server = sid(5, &[32, 544]);
        let eff = [SidAndAttributes { sid: &client, attributes: 0 }];
        let eff_token = TokenView { sids: &eff, owner: &client, privileges: &[] };
        let prim = [
            SidAndAttributes { sid: &user, attributes: 0 },
            SidAndAttributes { sid: &server, attributes: SE_GROUP_ENABLED },
        ];
        let prim_token = TokenView { sids: &prim, owner: &user, privileges: &[] };
        let d = sd(&user, &[compound(0x9, &server, &client)]);
        assert_eq!(full_s(&d, Subject { effective: eff_token, primary: prim_token }, 0x9, 0, CallerMode::User, None, &[]), ok(0x9));
        // The server SID not in the primary token: no grant.
        let prim2 = [SidAndAttributes { sid: &user, attributes: 0 }];
        let no_server = TokenView { sids: &prim2, owner: &user, privileges: &[] };
        assert_eq!(full_s(&d, Subject { effective: eff_token, primary: no_server }, 0x9, 0, CallerMode::User, None, &[]), denied_outcome());
        // The client SID not in the effective token: no grant.
        let eff2 = [SidAndAttributes { sid: &user, attributes: 0 }];
        let no_client = TokenView { sids: &eff2, owner: &user, privileges: &[] };
        assert_eq!(full_s(&d, Subject { effective: no_client, primary: prim_token }, 0x9, 0, CallerMode::User, None, &[]), denied_outcome());
    }

    /// An ACE's principal-self SID is replaced by the object's own SID when the object
    /// represents a principal; without one, it matches nothing.
    #[test]
    fn principal_self_is_replaced_by_the_objects_sid() {
        let user = user_sid();
        let other = other_sid();
        let d = sd(&user, &[allowed(0x3, SELF_SID)]);
        assert_eq!(full(&d, &user, 0x3, 0, CallerMode::User, Some(&user), &[]), ok(0x3), "the object is the user");
        assert_eq!(full(&d, &user, 0x3, 0, CallerMode::User, Some(&other), &[]), denied_outcome());
        assert_eq!(run(&d, &user, 0x3), denied_outcome(), "the object represents no principal");
        // A deny ACE with the principal-self SID denies the object's own SID.
        let d2 = sd(&user, &[denied(0x1, SELF_SID), allowed(0x3, &user)]);
        assert_eq!(full(&d2, &user, 0x3, 0, CallerMode::User, Some(&user), &[]), denied_outcome());
    }

    /// ACEs that apply to children only are skipped, and the audit/alarm types are ignored.
    #[test]
    fn inherit_only_and_audit_aces_are_skipped() {
        let user = user_sid();
        let inherit_only = sd(&user, &[
            plain_ace(ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE, 0x7, &user),
            allowed(0x1, &user),
        ]);
        assert_eq!(run(&inherit_only, &user, 0x7), denied_outcome(), "the inherit-only ACE grants nothing, so 0x6 remains");
        assert_eq!(run(&inherit_only, &user, 0x1), ok(0x1));
        let audit = sd(&user, &[plain_ace(SYSTEM_AUDIT_ACE_TYPE, 0, 0x2, &user), allowed(0x1, &user)]);
        assert_eq!(run(&audit, &user, 0x1 | 0x2), denied_outcome(), "the audit ACE grants nothing, so 0x2 remains");
        assert_eq!(run(&audit, &user, 0x1), ok(0x1));
        assert_eq!(run(&audit, &user, 0x2), denied_outcome());
    }

    /// Structural problems report their own statuses: a malformed DACL, an out-of-range part,
    /// a bad owner SID, an unknown revision, a short header — and no descriptor at all is a
    /// plain denial in user mode.
    #[test]
    fn malformed_parts_report_their_status() {
        let user = user_sid();
        assert_eq!(run(&[], &user, 0x1), denied_outcome(), "no descriptor at all");
        let header_only = descriptor(Some(&user), true, None);
        assert_eq!(run(&header_only[..10], &user, 0x1).status, STATUS_BUFFER_TOO_SMALL);
        let mut bad = header_only.clone();
        bad[0] = 2;
        assert_eq!(run(&bad, &user, 0x1).status, STATUS_UNKNOWN_REVISION);
        // A DACL with a revision out of range (the DACL sits right after the header).
        let mut bad_dacl = sd(&user, &[allowed(0x1, &user)]);
        bad_dacl[20] = 9;
        assert_eq!(run(&bad_dacl, &user, 0x1).status, STATUS_INVALID_ACL);
        // A DACL whose size word runs past the end of the descriptor's bytes.
        let dacl = acl(&[allowed(0x1, &user)]);
        let whole = descriptor(None, true, Some(&dacl));
        assert_eq!(run(&whole[..whole.len() - 4], &user, 0x1).status, STATUS_INVALID_ACL);
        // A DACL offset outside the descriptor's bytes.
        let dacl = acl(&[allowed(0x1, &user)]);
        let mut out_of_range = descriptor(Some(&user), true, Some(&dacl));
        let mut h = SecurityDescriptor::parse(&out_of_range).unwrap();
        h.dacl = 0xF000;
        assert!(h.write(&mut out_of_range[..]));
        assert_eq!(run(&out_of_range, &user, 0x1).status, STATUS_INVALID_SECURITY_DESCR);
        // An owner SID that is truncated.
        let owner = user_sid();
        assert_eq!(run(&descriptor(Some(&owner[..10]), true, None), &user, 0x1).status, STATUS_INVALID_SID);
    }
}
