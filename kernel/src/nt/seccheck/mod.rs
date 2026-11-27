//! The access-check and privilege-check services: NtAccessCheck, NtAccessCheckByType,
//! NtAccessCheckByTypeResultList and NtPrivilegeCheck, over the security reference monitor's
//! walk (`sec::check`) and the token a handle names (`se`).
//!
//! The three access-check services share one shape. The caller's security descriptor, generic
//! mapping, principal-self SID, object-type list and privilege-set buffer are captured from its
//! memory first (every range probed; the descriptor's parts sized from their own headers and
//! validated on the way in), and the out-params probed; the token handle is then looked up as
//! the object manager looks any handle up — a handle naming nothing is STATUS_INVALID_HANDLE,
//! one naming another kind of object STATUS_OBJECT_TYPE_MISMATCH, one opened without
//! TOKEN_QUERY STATUS_ACCESS_DENIED — and the walk over the descriptor's DACL decides the
//! answer. The walk's outcome is an out-parameter, not the call's return: GrantedAccess and
//! AccessStatus receive the granted mask and the status (STATUS_SUCCESS when everything desired
//! was granted, STATUS_ACCESS_DENIED or a structural status otherwise) and the service returns
//! STATUS_SUCCESS. Only parameter-level failures are the return: a faulting caller range
//! (STATUS_ACCESS_VIOLATION), the handle's, a bad object-type list (STATUS_INVALID_PARAMETER),
//! a null or ownerless/groupless descriptor (STATUS_INVALID_SECURITY_DESCR), and a
//! privilege-set buffer too small for the privileges the check used (STATUS_BUFFER_TOO_SMALL,
//! with the size it takes in PrivilegeSetLength — the size-then-buffer protocol; on success the
//! buffer gets the set, count and control first, and PrivilegeSetLength is left alone).
//!
//! The privilege set reports the privileges the check used: ACCESS_SYSTEM_SECURITY asks for the
//! security privilege enabled (reported through AccessStatus as STATUS_PRIVILEGE_NOT_HELD when
//! it is not) and WRITE_OWNER may be satisfied by the take-ownership privilege; each used entry
//! carries SE_PRIVILEGE_USED_FOR_ACCESS. MAXIMUM_ALLOWED is the walk's to handle. The
//! result-list variant runs one walk per object-type-list entry, each with the types up to and
//! including that entry, and answers a GrantedAccess/AccessStatus pair per entry.
//!
//! NtPrivilegeCheck captures the caller's privilege set (its count, control and entries),
//! checks each entry against the token — held and enabled — marking the matching ones
//! SE_PRIVILEGE_USED_FOR_ACCESS in the caller's buffer, and writes Result: whether they all
//! (PRIVILEGE_SET_ALL_NECESSARY in the control) or any of them were held. The call returns
//! STATUS_SUCCESS either way.

use rtl::array_vec::ArrayVec;
use rtl::nt::access::WRITE_OWNER;
use rtl::nt::{Luid, LuidAndAttributes};
use rtl::pod::Pod;

use crate::se;
// The walk itself, under a name of its own: the services below are the access_check the
// service table calls.
use crate::sec::check::access_check as walk;
use crate::sec::sd::STATUS_INVALID_SECURITY_DESCR;
use crate::sec::sid;
use crate::sec::{
    held_enabled,
    luid,
    privilege,
    AccessCheck,
    CallerMode,
    GenericMapping,
    Guid,
    SecurityDescriptor,
    SidAndAttributes,
    Subject,
    TokenView,
    ACCESS_SYSTEM_SECURITY,
    HELD,
    SE_PRIVILEGE_USED_FOR_ACCESS,
    SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
use crate::status::*;

/// PRIVILEGE_SET_ALL_NECESSARY (winnt.h): a privilege set's Control asks for every listed
/// privilege, not any one of them.
pub const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;

/// A PRIVILEGE_SET's size for `count` entries: its count and control dwords and the entries —
/// the structure holds one entry itself, so even an empty set takes its 20 bytes.
pub const fn privilege_set_size(count: usize) -> u32 {
    let size = 8 + 12 * count as u32;
    if size < 20 {
        20
    } else {
        size
    }
}

/// The little-endian dword at `at` in `bytes`.
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// The SID a SID_AND_ATTRIBUTES entry at `at` in a TOKEN_USER or TOKEN_GROUPS answer names:
/// the answers are built at base 0, so the entry's pointer is an offset into the answer.
fn reply_sid<'a>(reply: &'a [u8], at: usize) -> &'a [u8] {
    let at = word(reply, at) as usize;
    let bytes = reply.get(at..).unwrap_or(&[]);
    let len = sid::length(bytes).unwrap_or(0);
    &bytes[..len]
}

/// The privileges of a TOKEN_PRIVILEGES answer (its count, then its entries).
fn parse_privileges(reply: &[u8]) -> ArrayVec<LuidAndAttributes, { HELD }> {
    let mut out = ArrayVec::new();
    for i in 0..word(reply, 0) as usize {
        let at = 4 + 12 * i;
        if at + 12 > reply.len() {
            break;
        }
        out.push(LuidAndAttributes {
            luid: Luid {
                low_part: word(reply, at),
                high_part: word(reply, at + 4) as i32,
            },
            attributes: word(reply, at + 8),
        });
    }
    out
}

/// The token object a handle-table entry names, when the entry grants `needed`: a missing entry
/// is STATUS_INVALID_HANDLE, an entry naming another kind of object STATUS_OBJECT_TYPE_MISMATCH,
/// one whose access lacks a right `needed` asks STATUS_ACCESS_DENIED — in that order.
pub fn token_of_entry(
    entry: Option<crate::ob::Entry>,
    needed: u32,
) -> Result<crate::ob::ObjectId, NtStatus> {
    let entry = entry.ok_or(STATUS_INVALID_HANDLE)?;
    let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
    if id.kind != crate::ob::ObjectType::Token {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if entry.access & needed != needed {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(id)
}

/// One access-check call's captured inputs.
pub struct CheckInput<'a> {
    /// The captured security descriptor's bytes (self-relative); None for a null pointer.
    pub sd: Option<&'a [u8]>,
    /// The handle's token; None when the handle names no token.
    pub token: Option<&'a se::TokenBody>,
    /// The desired access mask, generic rights included.
    pub desired: u32,
    /// The object type's generic mapping.
    pub mapping: GenericMapping,
    /// The object's own principal SID, when it represents a principal.
    pub principal_self: Option<&'a [u8]>,
    /// The caller's object-type list.
    pub object_types: &'a [Guid],
    /// The caller's privilege-set buffer's size (*PrivilegeSetLength on entry).
    pub privilege_room: u32,
}

/// One walk's answer: the out-params and the privileges it used.
pub struct WalkAnswer {
    /// *GrantedAccess (the list's entry).
    pub granted: u32,
    /// *AccessStatus (the list's entry).
    pub access_status: NtStatus,
    /// The privileges the check used, in the set's order (at most two).
    pub used: ArrayVec<LuidAndAttributes, 2>,
}

/// A call's answer: the walk ran, or a parameter-level refusal.
pub enum Answer {
    /// The service returns `status`; `privilege_length`, when Some, goes to *PrivilegeSetLength.
    Refused {
        status: NtStatus,
        privilege_length: Option<u32>,
    },
    /// The walk ran: these are the out-params, and the privilege set is written.
    Checked(WalkAnswer),
}

/// A parameter-level refusal carrying no privilege-set length.
fn refused(status: NtStatus) -> Answer {
    Answer::Refused {
        status,
        privilege_length: None,
    }
}

/// Run one access check over the captured inputs: the walk's answer, or the refusal a
/// parameter-level problem gives (see the module notes for the order the checks run in).
pub fn run(input: &CheckInput<'_>) -> Answer {
    let Some(token) = input.token else {
        return refused(STATUS_INVALID_HANDLE);
    };
    // The token's own answers, held while the views borrow them: the user, the groups, the
    // privileges.
    let (Ok(user), Ok(groups), Ok(privileges_reply)) = (
        token.information(se::Class::User, 0),
        token.information(se::Class::Groups, 0),
        token.information(se::Class::Privileges, 0),
    ) else {
        return refused(STATUS_INVALID_PARAMETER);
    };
    // The user first (index 0 always matches), then the groups with their attributes.
    let mut sids = [SidAndAttributes {
        sid: &[],
        attributes: 0,
    }; 16];
    let mut count = 1;
    sids[0] = SidAndAttributes {
        sid: reply_sid(&user, 0),
        attributes: 0,
    };
    for i in 0..word(&groups, 0) as usize {
        let at = 4 + 8 * i;
        if at + 8 > groups.len() || count >= sids.len() {
            break;
        }
        sids[count] = SidAndAttributes {
            sid: reply_sid(&groups, at),
            attributes: word(&groups, at + 4),
        };
        count += 1;
    }
    let privileges = parse_privileges(&privileges_reply);
    let view = TokenView {
        sids: &sids[..count],
        owner: token.owner_sid.as_slice(),
        privileges: privileges.as_slice(),
    };
    let subject = Subject {
        effective: view,
        primary: view,
    };

    let mapped = input.mapping.map(input.desired);

    // ACCESS_SYSTEM_SECURITY needs the security privilege enabled; the failure goes through
    // the out-params, and the privilege-set buffer is not sized for it.
    if mapped & ACCESS_SYSTEM_SECURITY != 0
        && !held_enabled(privileges.as_slice(), luid(SE_SECURITY_PRIVILEGE))
    {
        return Answer::Checked(WalkAnswer {
            granted: 0,
            access_status: STATUS_PRIVILEGE_NOT_HELD,
            used: ArrayVec::new(),
        });
    }
    // The privileges the check uses: WRITE_OWNER may be satisfied by the take-ownership
    // privilege, ACCESS_SYSTEM_SECURITY by the security one.
    let mut used = ArrayVec::<LuidAndAttributes, 2>::new();
    if mapped & WRITE_OWNER != 0
        && held_enabled(privileges.as_slice(), luid(SE_TAKE_OWNERSHIP_PRIVILEGE))
    {
        used.push(privilege(
            SE_TAKE_OWNERSHIP_PRIVILEGE,
            SE_PRIVILEGE_USED_FOR_ACCESS,
        ));
    }
    if mapped & ACCESS_SYSTEM_SECURITY != 0 {
        used.push(privilege(
            SE_SECURITY_PRIVILEGE,
            SE_PRIVILEGE_USED_FOR_ACCESS,
        ));
    }
    // The size-then-buffer protocol: a buffer shorter than the set takes changes nothing and
    // asks for the size.
    let required = privilege_set_size(used.len());
    if input.privilege_room < required {
        return Answer::Refused {
            status: STATUS_BUFFER_TOO_SMALL,
            privilege_length: Some(required),
        };
    }
    // A null descriptor, or one without an owner and a group, is refused.
    let Some(sd) = input.sd else {
        return refused(STATUS_INVALID_SECURITY_DESCR);
    };
    match SecurityDescriptor::parse(sd) {
        Some(header) if header.owner != 0 && header.group != 0 => {}
        _ => return refused(STATUS_INVALID_SECURITY_DESCR),
    }
    let outcome = walk(&AccessCheck {
        sd,
        subject,
        desired: input.desired,
        mapping: input.mapping,
        previously_granted: 0,
        mode: CallerMode::User,
        principal_self: input.principal_self,
        object_types: input.object_types,
    });
    Answer::Checked(WalkAnswer {
        granted: outcome.granted,
        access_status: outcome.status,
        used,
    })
}

/// The privilege check proper, over the captured PRIVILEGE_SET in `set` (its count, control and
/// entries): each entry the token holds and has enabled is marked SE_PRIVILEGE_USED_FOR_ACCESS
/// in place, and the answer is whether they all (PRIVILEGE_SET_ALL_NECESSARY in the control) or
/// any of them were held.
pub fn check_privileges(set: &mut [u8], held: &[LuidAndAttributes]) -> bool {
    let count = word(set, 0) as usize;
    let all = word(set, 4) & PRIVILEGE_SET_ALL_NECESSARY != 0;
    let mut matched = 0usize;
    for i in 0..count {
        let at = 8 + 12 * i;
        let Some(bytes) = set.get_mut(at..at + 12) else {
            break;
        };
        let mut entry = LuidAndAttributes::from_bytes(bytes).expect("12 bytes");
        if held_enabled(held, entry.luid) {
            entry.attributes |= SE_PRIVILEGE_USED_FOR_ACCESS;
            matched += 1;
            bytes.copy_from_slice(entry.as_bytes());
        }
    }
    if all {
        matched == count
    } else {
        matched > 0
    }
}

#[cfg(target_arch = "x86")]
mod services;
#[cfg(target_arch = "x86")]
pub use services::*;

#[cfg(not(target_arch = "x86"))]
mod host;
#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::nt::access::{MAXIMUM_ALLOWED, READ_CONTROL, TOKEN_QUERY, WRITE_DAC};

    use super::*;
    use crate::ob::{Entry, ObjectId, ObjectType};
    use crate::se::{sid_bytes, Change, Requests, PRIMARY_GROUP, USER};
    use crate::sec::{
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACL_REVISION2,
        SE_CHANGE_NOTIFY_PRIVILEGE,
        SE_DACL_PRESENT,
        SE_PRIVILEGE_ENABLED,
        SE_SELF_RELATIVE,
        SE_SHUTDOWN_PRIVILEGE,
    };

    /// The test object type's mapping: read 0x1, write 0x2, execute 0x4, all 0xF.
    const MAPPING: GenericMapping = GenericMapping {
        generic_read: 0x1,
        generic_write: 0x2,
        generic_execute: 0x4,
        generic_all: 0xF,
    };

    /// A SID's bytes: revision 1, the count, a zeroed authority with the authority's low byte
    /// last, then a dword per sub-authority.
    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for &s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    /// An ACE's bytes: the type, the flags, the dword-padded size, then the body.
    fn ace_body(ace_type: u8, body: &[u8]) -> Vec<u8> {
        let size = (4 + body.len() + 3) & !3;
        let mut v = vec![ace_type, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(body);
        v.resize(size, 0);
        v
    }

    /// A plain ACE of `mask` to `sid`.
    fn ace(ace_type: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut body = mask.to_le_bytes().to_vec();
        body.extend_from_slice(sid);
        ace_body(ace_type, &body)
    }

    /// An ACL's bytes over `aces`.
    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        acl_rev(ACL_REVISION2, aces)
    }

    /// An ACL of `revision`'s bytes over `aces`.
    fn acl_rev(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
        let mut v = vec![revision, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        for a in aces {
            v.extend_from_slice(a);
        }
        v
    }

    /// A self-relative descriptor in one buffer: the header, then the DACL, the owner and the
    /// group, each packed dword-aligned, when present.
    fn descriptor(owner: Option<&[u8]>, group: Option<&[u8]>, dacl: Option<&[u8]>) -> Vec<u8> {
        let mut control = SE_SELF_RELATIVE;
        let mut v = vec![0u8; 20];
        let mut pack = |v: &mut Vec<u8>, part: &[u8]| -> u32 {
            let at = v.len() as u32;
            v.extend_from_slice(part);
            while v.len() % 4 != 0 {
                v.push(0);
            }
            at
        };
        let mut dacl_field = 0;
        if let Some(d) = dacl {
            control |= SE_DACL_PRESENT;
            dacl_field = pack(&mut v, d);
        }
        let mut owner_field = 0;
        if let Some(o) = owner {
            owner_field = pack(&mut v, o);
        }
        let mut group_field = 0;
        if let Some(g) = group {
            group_field = pack(&mut v, g);
        }
        let header = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control,
            owner: owner_field,
            group: group_field,
            sacl: 0,
            dacl: dacl_field,
        };
        assert!(header.write(&mut v[..]));
        v
    }

    /// A new process token.
    fn token() -> se::TokenBody {
        se::TokenBody::of(ObjectId {
            kind: ObjectType::Process,
            index: 1,
            generation: 0,
        })
    }

    /// Enable the privileges `lows` on `token`.
    fn enable(token: &mut se::TokenBody, lows: &[u32]) {
        let mut requests = Requests::new();
        for &low in lows {
            requests.add(privilege(low, SE_PRIVILEGE_ENABLED));
        }
        token.adjust(&Change::Set(requests), None).unwrap();
    }

    /// The token's privileges, parsed from its answer.
    fn privileges_of(token: &se::TokenBody) -> ArrayVec<LuidAndAttributes, { HELD }> {
        parse_privileges(&token.information(se::Class::Privileges, 0).unwrap())
    }

    /// A check input over `sd` and `token`, wanting `desired`, with a privilege-set buffer of
    /// `room` bytes.
    fn input<'a>(
        sd: &'a [u8],
        token: &'a se::TokenBody,
        desired: u32,
        room: u32,
    ) -> CheckInput<'a> {
        CheckInput {
            sd: Some(sd),
            token: Some(token),
            desired,
            mapping: MAPPING,
            principal_self: None,
            object_types: &[],
            privilege_room: room,
        }
    }

    /// A descriptor owned by the token's user, with `dacl` as its DACL.
    fn sd_of(user: &[u8], group: &[u8], dacl: &[u8]) -> Vec<u8> {
        descriptor(Some(user), Some(group), Some(dacl))
    }

    /// The handle-table entry rules: no entry is STATUS_INVALID_HANDLE, another kind of object
    /// STATUS_OBJECT_TYPE_MISMATCH, a missing right STATUS_ACCESS_DENIED, then the token's id.
    #[test]
    fn the_handle_entry_names_a_token() {
        let token_id = ObjectId {
            kind: ObjectType::Token,
            index: 3,
            generation: 0,
        };
        let event = ObjectId {
            kind: ObjectType::Event,
            index: 1,
            generation: 0,
        };
        assert_eq!(
            token_of_entry(None, TOKEN_QUERY),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            token_of_entry(Some(Entry::object(event, TOKEN_QUERY, false)), TOKEN_QUERY),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            token_of_entry(Some(Entry::object(token_id, 0, false)), TOKEN_QUERY),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            token_of_entry(
                Some(Entry::object(token_id, TOKEN_QUERY, false)),
                TOKEN_QUERY
            ),
            Ok(token_id)
        );
    }

    /// A null token or descriptor is refused before the walk: no token is STATUS_INVALID_HANDLE,
    /// a null, ownerless or groupless descriptor STATUS_INVALID_SECURITY_DESCR.
    #[test]
    fn null_and_incomplete_inputs_are_refused() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let sd = sd_of(
            &user,
            &group,
            &acl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0x7, &user)]),
        );
        let mut no_token = input(&sd, &token, 0x7, 64);
        no_token.token = None;
        assert!(
            matches!(run(&no_token), Answer::Refused { status, .. } if status == STATUS_INVALID_HANDLE)
        );
        let mut null_sd = input(&sd, &token, 0x7, 64);
        null_sd.sd = None;
        assert!(
            matches!(run(&null_sd), Answer::Refused { status, .. } if status == STATUS_INVALID_SECURITY_DESCR)
        );
        for sd in [
            descriptor(None, Some(&group), Some(&acl(&[]))),
            descriptor(Some(&user), None, Some(&acl(&[]))),
        ] {
            assert!(
                matches!(run(&input(&sd, &token, 0x7, 64)), Answer::Refused { status, .. } if status == STATUS_INVALID_SECURITY_DESCR)
            );
        }
    }

    /// An allow ACE for the token's user grants its mask: the out-params are the granted mask
    /// and STATUS_SUCCESS, and no privilege was used.
    #[test]
    fn an_allowed_check_grants_the_mask() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let sd = sd_of(
            &user,
            &group,
            &acl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0x7, &user)]),
        );
        match run(&input(&sd, &token, 0x7, 64)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, 0x7);
                assert_eq!(answer.access_status, STATUS_SUCCESS);
                assert!(answer.used.is_empty());
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// A DACL granting nothing denies: granted 0 and STATUS_ACCESS_DENIED through the
    /// out-params.
    #[test]
    fn a_denied_check_reports_access_denied() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let stranger = sid(5, &[32, 546]);
        let sd = sd_of(
            &user,
            &group,
            &acl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0x7, &stranger)]),
        );
        match run(&input(&sd, &token, 0x7, 64)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, 0);
                assert_eq!(answer.access_status, STATUS_ACCESS_DENIED);
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// MAXIMUM_ALLOWED is the walk's: the owner's implicit READ_CONTROL and WRITE_DAC come
    /// along with the OR of the matching allows.
    #[test]
    fn maximum_allowed_grants_the_walked_mask() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let dacl = acl(&[
            ace(ACCESS_ALLOWED_ACE_TYPE, 0x1, &user),
            ace(ACCESS_ALLOWED_ACE_TYPE, 0x2, &user),
        ]);
        let sd = sd_of(&user, &group, &dacl);
        match run(&input(&sd, &token, MAXIMUM_ALLOWED, 64)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, READ_CONTROL | WRITE_DAC | 0x3);
                assert_eq!(answer.access_status, STATUS_SUCCESS);
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// The privilege-set size-then-buffer protocol: an empty set still takes 20 bytes, one
    /// privilege 20, two 32; a buffer shorter than that is STATUS_BUFFER_TOO_SMALL with the
    /// size it takes, a big enough one lets the check run and reports the privileges used.
    #[test]
    fn the_privilege_set_length_protocol() {
        assert_eq!(
            (
                privilege_set_size(0),
                privilege_set_size(1),
                privilege_set_size(2)
            ),
            (20, 20, 32)
        );
        let mut token = token();
        enable(
            &mut token,
            &[SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE],
        );
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let sd = sd_of(
            &user,
            &group,
            &acl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0x7, &user)]),
        );
        // No privilege used: the empty set still takes 20 bytes.
        match run(&input(&sd, &token, 0x7, 19)) {
            Answer::Refused {
                status,
                privilege_length,
            } => {
                assert_eq!(status, STATUS_BUFFER_TOO_SMALL);
                assert_eq!(privilege_length, Some(20));
            }
            Answer::Checked(_) => panic!("the check ran"),
        }
        // ACCESS_SYSTEM_SECURITY with the privilege enabled: it is used, the set takes 20.
        match run(&input(&sd, &token, ACCESS_SYSTEM_SECURITY, 19)) {
            Answer::Refused {
                status,
                privilege_length,
            } => assert_eq!(
                (status, privilege_length),
                (STATUS_BUFFER_TOO_SMALL, Some(20))
            ),
            Answer::Checked(_) => panic!("the check ran"),
        }
        match run(&input(&sd, &token, ACCESS_SYSTEM_SECURITY, 20)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, ACCESS_SYSTEM_SECURITY);
                assert_eq!(answer.access_status, STATUS_SUCCESS);
                assert_eq!(
                    answer.used.as_slice(),
                    [privilege(
                        SE_SECURITY_PRIVILEGE,
                        SE_PRIVILEGE_USED_FOR_ACCESS
                    )]
                );
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
        // Both privileges used: 32 bytes, the take-ownership entry first.
        let both = ACCESS_SYSTEM_SECURITY | WRITE_OWNER;
        match run(&input(&sd, &token, both, 31)) {
            Answer::Refused {
                privilege_length, ..
            } => assert_eq!(privilege_length, Some(32)),
            Answer::Checked(_) => panic!("the check ran"),
        }
        match run(&input(&sd, &token, both, 32)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, both);
                assert_eq!(
                    answer.used.as_slice(),
                    [
                        privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_USED_FOR_ACCESS),
                        privilege(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_USED_FOR_ACCESS),
                    ]
                );
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// ACCESS_SYSTEM_SECURITY without the security privilege enabled is reported through the
    /// out-params (granted 0, STATUS_PRIVILEGE_NOT_HELD), and the privilege-set buffer is not
    /// sized for it — even a zero-length buffer gets the answer, not STATUS_BUFFER_TOO_SMALL.
    #[test]
    fn access_system_security_needs_the_privilege_enabled() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let sd = sd_of(
            &user,
            &group,
            &acl(&[ace(ACCESS_ALLOWED_ACE_TYPE, 0x7, &user)]),
        );
        match run(&input(&sd, &token, ACCESS_SYSTEM_SECURITY, 0)) {
            Answer::Checked(answer) => {
                assert_eq!(answer.granted, 0);
                assert_eq!(answer.access_status, STATUS_PRIVILEGE_NOT_HELD);
                assert!(answer.used.is_empty());
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// A typed object allow ACE grants only when the caller's type list holds its GUID.
    #[test]
    fn the_object_type_list_gates_a_typed_ace() {
        let token = token();
        let user = sid_bytes(&USER);
        let group = sid_bytes(&PRIMARY_GROUP);
        let guid = Guid {
            data1: 0x1111,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let mut guid_bytes = guid.data1.to_le_bytes().to_vec();
        guid_bytes.extend_from_slice(&guid.data2.to_le_bytes());
        guid_bytes.extend_from_slice(&guid.data3.to_le_bytes());
        guid_bytes.extend_from_slice(&guid.data4);
        let mut body = 0x5u32.to_le_bytes().to_vec();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&guid_bytes);
        body.extend_from_slice(&user);
        let sd = sd_of(
            &user,
            &group,
            &acl_rev(4, &[ace_body(ACCESS_ALLOWED_OBJECT_ACE_TYPE, &body)]),
        );
        match run(&input(&sd, &token, 0x5, 64)) {
            Answer::Checked(answer) => assert_eq!(answer.access_status, STATUS_ACCESS_DENIED),
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
        let mut with_types = input(&sd, &token, 0x5, 64);
        let types = [guid];
        with_types.object_types = &types;
        match run(&with_types) {
            Answer::Checked(answer) => {
                assert_eq!(
                    (answer.granted, answer.access_status),
                    (0x5, STATUS_SUCCESS)
                );
            }
            Answer::Refused { status, .. } => panic!("refused: {status:?}"),
        }
    }

    /// A PRIVILEGE_SET's bytes: its count, its control, the entries.
    fn privilege_set_bytes(control: u32, entries: &[LuidAndAttributes]) -> Vec<u8> {
        let mut v = (entries.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&control.to_le_bytes());
        for entry in entries {
            v.extend_from_slice(entry.as_bytes());
        }
        v
    }

    /// The entry `i` of a PRIVILEGE_SET's bytes.
    fn entry_at(set: &[u8], i: usize) -> LuidAndAttributes {
        LuidAndAttributes::from_bytes(&set[8 + 12 * i..]).unwrap()
    }

    /// The privilege check: a held and enabled privilege matches and is marked used in the
    /// caller's buffer, a held but disabled one does not; ALL_NECESSARY wants every entry, any
    /// wants one of them.
    #[test]
    fn privilege_check_marks_and_answers() {
        let body = token();
        let held = privileges_of(&body);
        let enabled = privilege(SE_CHANGE_NOTIFY_PRIVILEGE, 0);
        let disabled = privilege(SE_SHUTDOWN_PRIVILEGE, 0);
        // All necessary, one of the two not held enabled: false, only the enabled one marked.
        let mut set = privilege_set_bytes(PRIVILEGE_SET_ALL_NECESSARY, &[enabled, disabled]);
        assert!(!check_privileges(&mut set, held.as_slice()));
        assert_eq!(entry_at(&set, 0).attributes, SE_PRIVILEGE_USED_FOR_ACCESS);
        assert_eq!(entry_at(&set, 1).attributes, 0);
        // Any of them: the enabled one suffices.
        let mut set = privilege_set_bytes(0, &[enabled, disabled]);
        assert!(check_privileges(&mut set, held.as_slice()));
        // The disabled one alone, all necessary: false.
        let mut set = privilege_set_bytes(PRIVILEGE_SET_ALL_NECESSARY, &[disabled]);
        assert!(!check_privileges(&mut set, held.as_slice()));
        // Enabled on the token: true.
        let mut adjusted = token();
        enable(&mut adjusted, &[SE_SHUTDOWN_PRIVILEGE]);
        let held = privileges_of(&adjusted);
        let mut set = privilege_set_bytes(PRIVILEGE_SET_ALL_NECESSARY, &[disabled]);
        assert!(check_privileges(&mut set, held.as_slice()));
        assert_eq!(entry_at(&set, 0).attributes, SE_PRIVILEGE_USED_FOR_ACCESS);
    }
}
