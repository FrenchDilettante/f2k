//! The token services beyond the open, query, set, adjust-privileges and duplicate ones
//! (`nt::token`): NtAdjustGroupsToken, NtCreateToken, NtFilterToken and NtOpenThreadToken.
//!
//! As in `nt::token`, what these keep is bookkeeping, so that the calls a program makes answer
//! as Windows 2000's do: NtAdjustGroupsToken validates the group list it is given and reports
//! the previous state of what it would change (the token's groups are the logon's fixed set,
//! so nothing is rewritten in the token); NtCreateToken makes a token of the calling process's
//! shape — a copy of its token of the type asked for, so a create with no object attributes
//! succeeds; NtFilterToken makes a copy of the existing token (with nothing disabled, a plain
//! copy) whose handle takes the existing handle's granted access; NtOpenThreadToken answers
//! with the thread's process's token, since F2K's threads never impersonate. The handle checks
//! are the object manager's, as for any object (see `nt::token`): NtAdjustGroupsToken needs
//! TOKEN_ADJUST_GROUPS (with TOKEN_QUERY when PreviousState is given), NtFilterToken
//! TOKEN_DUPLICATE, NtOpenThreadToken THREAD_QUERY_INFORMATION on the thread.

use crate::se;
use crate::status::*;

/// The right a groups adjustment needs (a specific right, carried by TOKEN_WRITE and
/// TOKEN_ALL_ACCESS).
#[cfg_attr(not(test), allow(dead_code))] // wired to its service's export when that lands
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;

/// NtFilterToken's flags: disable every group, and delete every privilege but the traverse one.
#[cfg_attr(not(test), allow(dead_code))]
pub const DISABLE_ALL_GROUPS: u32 = 0x0001;
#[cfg_attr(not(test), allow(dead_code))]
pub const DISABLE_MAX_PRIVILEGE: u32 = 0x0002;

/// An attempt to disable a mandatory group (the whole adjustment is refused, nothing changes).
#[cfg_attr(not(test), allow(dead_code))]
pub const STATUS_CANT_DISABLE_MANDATORY: NtStatus = NtStatus(0xC000_005D);
/// An attempt to enable a deny-only group.
#[cfg_attr(not(test), allow(dead_code))]
pub const STATUS_CANT_ENABLE_DENY_ONLY: NtStatus = NtStatus(0xC000_02B3);

/// The token's group list's slots: one plan entry per group.
#[cfg_attr(not(test), allow(dead_code))]
const GROUP_SLOTS: usize = se::GROUPS.len();

/// Round `x` up to a dword.
#[cfg_attr(not(test), allow(dead_code))]
const fn align4(x: u32) -> u32 {
    (x + 3) & !3
}

/// Whether a groups adjustment has the NewState it needs: STATUS_INVALID_PARAMETER when
/// ResetToDefault is false and NewState is absent — answered before the handle is looked at.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn new_state_required(reset_to_default: bool, new_state_present: bool) -> Result<(), NtStatus> {
    if !reset_to_default && !new_state_present {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// A TOKEN_GROUPS list (a NewState) folded against the token's group list: for each group, the
/// enabled bit the first entry naming it asks for (None when no entry names it), how many of
/// the token's groups the entries name, and the list's own count.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct GroupsPlan {
    wanted: [Option<bool>; GROUP_SLOTS],
    named: u32,
    count: u32,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GroupsPlan {
    /// An empty plan, its count set once the list has been read.
    pub fn new() -> Self {
        GroupsPlan {
            wanted: [None; GROUP_SLOTS],
            named: 0,
            count: 0,
        }
    }

    /// The list's count, read from its header.
    pub fn set_count(&mut self, count: u32) {
        self.count = count;
    }

    /// One more of the list's entries (its SID, already validated, and its attributes), folded:
    /// the first entry naming a group decides that group's wanted enabled bit.
    pub fn add(&mut self, groups: &[(se::Sid, u32)], sid: &[u8], attributes: u32) {
        let index = groups
            .iter()
            .position(|(group, _)| crate::sec::equal(se::sid_bytes(group).as_slice(), sid));
        if let Some(index) = index.filter(|&index| index < GROUP_SLOTS) {
            if self.wanted[index].is_none() {
                self.wanted[index] = Some(attributes & se::SE_GROUP_ENABLED != 0);
                self.named += 1;
            }
        }
    }

    /// Whether the list names a group the token does not hold (not all assigned).
    pub fn not_all_assigned(&self) -> bool {
        self.named < self.count
    }
}

/// What a groups adjustment changes: the previous state of each changed group (its SID and its
/// attributes before the change), in the token's group order, whether the list named a group
/// the token does not hold, and the refusal that stops the walk (a mandatory or deny-only
/// group being changed), if any.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct GroupAdjustment {
    previous: [Option<(se::SidBytes, u32)>; GROUP_SLOTS],
    count: usize,
    not_all_assigned: bool,
    error: Option<NtStatus>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GroupAdjustment {
    fn empty(not_all_assigned: bool) -> Self {
        GroupAdjustment {
            previous: [None; GROUP_SLOTS],
            count: 0,
            not_all_assigned,
            error: None,
        }
    }

    fn record(&mut self, sid: se::SidBytes, attributes: u32) {
        if self.count < GROUP_SLOTS {
            self.previous[self.count] = Some((sid, attributes));
            self.count += 1;
        }
    }

    /// How many groups change.
    pub fn changed(&self) -> usize {
        self.count
    }

    /// Whether the list named a group the token does not hold.
    pub fn not_all_assigned(&self) -> bool {
        self.not_all_assigned
    }

    /// The refusal that stopped the walk, if any.
    pub fn status(&self) -> Result<(), NtStatus> {
        self.error.map_or(Ok(()), Err)
    }

    /// PreviousState's size (ReturnLength): its count, its entries, and the SIDs packed
    /// dword-aligned after them.
    pub fn report_size(&self) -> u32 {
        let mut size = 4 + 8 * self.count as u32;
        for entry in &self.previous[..self.count] {
            let (sid, _) = entry.expect("a recorded entry");
            size += align4(sid.len() as u32);
        }
        size
    }

    /// PreviousState's entries as the caller's buffer at `base` receives them: each changed
    /// group's SID pointer (the SIDs packed dword-aligned after the entries), its old
    /// attributes, and its SID's bytes.
    pub fn entries(&self, base: u32) -> impl Iterator<Item = (u32, u32, se::SidBytes)> + '_ {
        let mut slot = align4(base + 4 + 8 * self.count as u32);
        self.previous[..self.count].iter().map(move |entry| {
            let (sid, attributes) = entry.expect("a recorded entry");
            let at = slot;
            slot += align4(sid.len() as u32);
            (at, attributes, sid)
        })
    }
}

/// The adjustment `plan` asks of the token's `groups` (its type and attributes): ResetToDefault
/// moves each group to its default enabled state; otherwise each group a list entry names moves
/// to the enabled bit that entry asks for. A change to a mandatory group is refused
/// (STATUS_CANT_DISABLE_MANDATORY), to a deny-only group STATUS_CANT_ENABLE_DENY_ONLY, the walk
/// stopping at the first refusal.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn plan_groups(
    reset_to_default: bool,
    groups: &[(se::Sid, u32)],
    plan: &GroupsPlan,
) -> GroupAdjustment {
    let mut adjustment = GroupAdjustment::empty(plan.not_all_assigned());
    for (index, (sid, attributes)) in groups.iter().enumerate() {
        if reset_to_default {
            let enable = attributes & se::SE_GROUP_ENABLED_BY_DEFAULT != 0
                && attributes & se::SE_GROUP_ENABLED == 0;
            let disable = attributes & se::SE_GROUP_ENABLED_BY_DEFAULT == 0
                && attributes & se::SE_GROUP_ENABLED != 0;
            if enable || disable {
                adjustment.record(se::sid_bytes(sid), *attributes);
            }
        } else if let Some(want) = plan.wanted.get(index).copied().flatten() {
            let enabled = *attributes & se::SE_GROUP_ENABLED != 0;
            if want != enabled {
                if *attributes & se::SE_GROUP_MANDATORY != 0 {
                    adjustment.error = Some(STATUS_CANT_DISABLE_MANDATORY);
                    break;
                }
                if *attributes & se::SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                    adjustment.error = Some(STATUS_CANT_ENABLE_DENY_ONLY);
                    break;
                }
                adjustment.record(se::sid_bytes(sid), *attributes);
            }
        }
    }
    adjustment
}

/// The token NtCreateToken makes: a copy of the process's token `source`, of type `kind` at
/// `level` (an impersonation token needs a level; one past SecurityDelegation, or another
/// type than the two, is refused before anything is made).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn created_body(
    source: &se::TokenBody,
    kind: u32,
    level: Option<u32>,
) -> Result<se::TokenBody, NtStatus> {
    if kind != se::TOKEN_PRIMARY && kind != se::TOKEN_IMPERSONATION {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let level = match (kind, level) {
        (se::TOKEN_IMPERSONATION, None) => return Err(se::STATUS_BAD_IMPERSONATION_LEVEL),
        (_, level) => level.unwrap_or(se::SECURITY_ANONYMOUS),
    };
    if level > se::SECURITY_DELEGATION {
        return Err(se::STATUS_BAD_IMPERSONATION_LEVEL);
    }
    source.duplicate(kind, level)
}

/// The token NtFilterToken makes: a copy of the source at the source's own type and level, of
/// no process, a new TokenId. F2K's token body carries no per-token group or restricted-SID
/// state to remove and holds a fixed privilege set, so the flags and the lists (validated as
/// they are read) leave the copy as the source's.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn filtered_body(source: &se::TokenBody) -> Result<se::TokenBody, NtStatus> {
    source.duplicate(source.kind, source.level)
}

/// A RestrictedSids entry's attributes must be zero (STATUS_INVALID_PARAMETER otherwise).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn restricted_attributes_ok(attributes: u32) -> Result<(), NtStatus> {
    if attributes == 0 {
        Ok(())
    } else {
        Err(STATUS_INVALID_PARAMETER)
    }
}

/// The host builds' token-operation services (see `unserved`).
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        adjust_groups_token(Handle, bool, UserAddr, u32, UserAddr, UserPtr<u32>);
        create_token(UserPtr<u32>, u32, UserAddr, u32, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr, UserAddr);
        filter_token(Handle, u32, UserAddr, UserAddr, UserAddr, UserPtr<u32>);
        open_thread_token(Handle, u32, bool, UserPtr<u32>);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectId;

    const BASE: u32 = 0x0040_1000;

    fn token() -> se::TokenBody {
        se::TokenBody::of(ObjectId {
            kind: crate::ob::ObjectType::Process,
            index: 1,
            generation: 0,
        })
    }

    /// A plan folded against `groups` from `entries` (a SID and its attributes), with the
    /// list's count `count`.
    fn plan_of(groups: &[(se::Sid, u32)], entries: &[(&se::Sid, u32)], count: u32) -> GroupsPlan {
        let mut plan = GroupsPlan::new();
        for (sid, attributes) in entries {
            plan.add(groups, &se::sid_bytes(sid), *attributes);
        }
        plan.set_count(count);
        plan
    }

    /// The adjust-groups right is a specific right: asked for alone it is granted alone, and
    /// the write and all-access masks carry it.
    #[test]
    fn the_adjust_groups_right_is_granted() {
        assert_eq!(TOKEN_ADJUST_GROUPS, 0x40);
        assert_eq!(super::super::token::granted(TOKEN_ADJUST_GROUPS), 0x40);
        assert!(rtl::nt::access::TOKEN_WRITE & TOKEN_ADJUST_GROUPS != 0);
        assert!(rtl::nt::access::TOKEN_ALL_ACCESS & TOKEN_ADJUST_GROUPS != 0);
    }

    /// A NULL NewState without ResetToDefault is STATUS_INVALID_PARAMETER, whatever else the
    /// call carries; with either of them it is fine.
    #[test]
    fn a_null_new_state_without_reset_is_refused() {
        assert_eq!(
            new_state_required(false, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(STATUS_INVALID_PARAMETER.0, 0xC000_000D);
        assert!(new_state_required(false, true).is_ok());
        assert!(new_state_required(true, false).is_ok());
    }

    /// The captured call: one group (Everyone) asked enabled, which it already is — no
    /// change, all assigned, a report of the count alone (4 bytes), a success.
    #[test]
    fn an_already_enabled_group_changes_nothing() {
        let plan = plan_of(&se::GROUPS, &[(&se::EVERYONE, se::SE_GROUP_ENABLED)], 1);
        let adjustment = plan_groups(false, &se::GROUPS, &plan);
        assert!(adjustment.status().is_ok());
        assert!(!adjustment.not_all_assigned());
        assert_eq!(adjustment.changed(), 0);
        assert_eq!(adjustment.report_size(), 4);
        assert_eq!(adjustment.entries(BASE).count(), 0);
    }

    /// A group the token does not hold is not assigned: no change, the answer is
    /// STATUS_NOT_ALL_ASSIGNED (a success).
    #[test]
    fn a_group_the_token_does_not_name_is_not_all_assigned() {
        let stranger = se::Sid {
            authority: 5,
            sub: &[99],
        };
        let plan = plan_of(&se::GROUPS, &[(&stranger, se::SE_GROUP_ENABLED)], 1);
        let adjustment = plan_groups(false, &se::GROUPS, &plan);
        assert!(adjustment.status().is_ok());
        assert!(adjustment.not_all_assigned());
        assert_eq!(adjustment.changed(), 0);
        assert_eq!(adjustment.report_size(), 4);
    }

    /// Disabling a mandatory group is refused outright: STATUS_CANT_DISABLE_MANDATORY, no
    /// change reported. Every group of the logon's is mandatory.
    #[test]
    fn disabling_a_mandatory_group_is_refused() {
        let plan = plan_of(&se::GROUPS, &[(&se::EVERYONE, 0)], 1);
        let adjustment = plan_groups(false, &se::GROUPS, &plan);
        assert_eq!(adjustment.status(), Err(STATUS_CANT_DISABLE_MANDATORY));
        assert_eq!(STATUS_CANT_DISABLE_MANDATORY.0, 0xC000_005D);
        assert_eq!(adjustment.changed(), 0);
    }

    /// The first entry naming a group decides its wanted bit: a later entry for the same
    /// group is not a match any more (it counts as unassigned when nothing else names it).
    #[test]
    fn the_first_entry_naming_a_group_decides() {
        let groups = [(se::EVERYONE, se::SE_GROUP_ENABLED)];
        let plan = plan_of(&groups, &[(&se::EVERYONE, 0), (&se::EVERYONE, se::SE_GROUP_ENABLED)], 2);
        assert!(plan.not_all_assigned(), "the second entry matches no group");
        // The group is asked disabled, but it is not mandatory here, so it changes.
        let adjustment = plan_groups(false, &groups, &plan);
        assert!(adjustment.status().is_ok());
        assert_eq!(adjustment.changed(), 1);
    }

    /// A change reports its previous state: the group's old attributes and SID, the report's
    /// size the count, the entry and the dword-aligned SID, and the entry's pointer into the
    /// caller's buffer where the SID is packed after the entries.
    #[test]
    fn a_change_reports_its_previous_state() {
        // A group that may be disabled: enabled, not mandatory.
        let groups = [(se::USERS, se::SE_GROUP_ENABLED)];
        let plan = plan_of(&groups, &[(&se::USERS, 0)], 1);
        let adjustment = plan_groups(false, &groups, &plan);
        assert!(adjustment.status().is_ok());
        assert!(!adjustment.not_all_assigned());
        assert_eq!(adjustment.changed(), 1);
        // The count, the one entry, the SID (S-1-5-32-545, 16 bytes, already dword-aligned).
        assert_eq!(adjustment.report_size(), 4 + 8 + 16);
        let entries: Vec<_> = adjustment.entries(BASE).collect();
        assert_eq!(entries.len(), 1);
        let (at, attributes, sid) = entries[0];
        assert_eq!(at, BASE + 4 + 8, "the SID is packed right after the entries");
        assert_eq!(attributes, se::SE_GROUP_ENABLED, "the old attributes");
        assert!(se::USERS.matches(sid.as_slice()));
    }

    /// ResetToDefault moves each group to its default: an enabled-by-default but disabled
    /// group is enabled, a not-enabled-by-default but enabled one is disabled, and an
    /// already-default one is not reported.
    #[test]
    fn reset_to_default_restores_the_defaults() {
        let groups = [
            (se::EVERYONE, se::SE_GROUP_ENABLED_BY_DEFAULT | se::SE_GROUP_ENABLED),
            (se::USERS, se::SE_GROUP_ENABLED),
            (se::LOCAL, se::SE_GROUP_ENABLED_BY_DEFAULT),
        ];
        let adjustment = plan_groups(true, &groups, &GroupsPlan::new());
        assert!(adjustment.status().is_ok());
        assert_eq!(adjustment.changed(), 2, "the first group is already at its default");
        assert_eq!(
            adjustment.report_size(),
            4 + 2 * 8 + align4(se::USERS.size() as u32) + align4(se::LOCAL.size() as u32)
        );
        let entries: Vec<_> = adjustment.entries(BASE).collect();
        assert_eq!(entries[0].1, se::SE_GROUP_ENABLED, "USERS was enabled");
        assert!(se::USERS.matches(entries[0].2.as_slice()));
        assert_eq!(entries[1].1, se::SE_GROUP_ENABLED_BY_DEFAULT, "LOCAL was disabled");
        assert!(se::LOCAL.matches(entries[1].2.as_slice()));
        // The SIDs are packed dword-aligned, in the report's order.
        let usiders = se::USERS.size() as u32;
        assert_eq!(entries[1].0, BASE + 4 + 2 * 8 + align4(usiders));
    }

    /// A deny-only group being enabled is refused: STATUS_CANT_ENABLE_DENY_ONLY.
    #[test]
    fn enabling_a_deny_only_group_is_refused() {
        let groups = [(se::USERS, se::SE_GROUP_USE_FOR_DENY_ONLY)];
        let plan = plan_of(&groups, &[(&se::USERS, se::SE_GROUP_ENABLED)], 1);
        let adjustment = plan_groups(false, &groups, &plan);
        assert_eq!(adjustment.status(), Err(STATUS_CANT_ENABLE_DENY_ONLY));
        assert_eq!(STATUS_CANT_ENABLE_DENY_ONLY.0, 0xC000_02B3);
    }

    /// A created token is the process's shape: a primary copy of the process's token, of no
    /// process, a new TokenId, the same privileges; an impersonation create needs a level, and
    /// none past delegation, and another type than the two is refused.
    #[test]
    fn a_created_token_is_the_processs_shape() {
        let source = token();
        let made = created_body(&source, se::TOKEN_PRIMARY, None).unwrap();
        assert_eq!(made.kind, se::TOKEN_PRIMARY);
        assert_eq!(made.owner, None);
        let answer = |body: &se::TokenBody, class| body.information(class, BASE).unwrap();
        assert_eq!(answer(&made, se::Class::Type).as_slice(), 1u32.to_le_bytes());
        let made_stats = answer(&made, se::Class::Statistics);
        let source_stats = answer(&source, se::Class::Statistics);
        assert_ne!(&made_stats[..4], &source_stats[..4], "a new TokenId");
        assert_eq!(&made_stats[8..12], &source_stats[8..12], "the same logon id");
        assert_eq!(
            created_body(&source, 3, None).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            created_body(&source, se::TOKEN_IMPERSONATION, None).err(),
            Some(se::STATUS_BAD_IMPERSONATION_LEVEL)
        );
        assert_eq!(
            created_body(&source, se::TOKEN_IMPERSONATION, Some(4)).err(),
            Some(se::STATUS_BAD_IMPERSONATION_LEVEL)
        );
        let imp = created_body(&source, se::TOKEN_IMPERSONATION, Some(se::SECURITY_IMPERSONATION)).unwrap();
        assert_eq!(imp.kind, se::TOKEN_IMPERSONATION);
        assert_eq!(
            answer(&imp, se::Class::ImpersonationLevel).as_slice(),
            se::SECURITY_IMPERSONATION.to_le_bytes()
        );
    }

    /// Filtering with nothing disabled is a copy: same type and level, of no process, a new
    /// TokenId; an impersonation source filters to the same level. A restricted SID's
    /// attributes must be zero.
    #[test]
    fn filtering_with_nothing_disabled_is_a_copy() {
        let source = token();
        let filtered = filtered_body(&source).unwrap();
        assert_eq!(filtered.kind, source.kind);
        assert_eq!(filtered.owner, None);
        let answer = |body: &se::TokenBody, class| body.information(class, BASE).unwrap();
        assert_ne!(
            &answer(&filtered, se::Class::Statistics)[..4],
            &answer(&source, se::Class::Statistics)[..4],
            "a new TokenId"
        );
        let imp = source
            .duplicate(se::TOKEN_IMPERSONATION, se::SECURITY_DELEGATION)
            .unwrap();
        let filtered = filtered_body(&imp).unwrap();
        assert_eq!(filtered.kind, se::TOKEN_IMPERSONATION);
        assert_eq!(
            answer(&filtered, se::Class::ImpersonationLevel).as_slice(),
            se::SECURITY_DELEGATION.to_le_bytes()
        );
        assert!(restricted_attributes_ok(0).is_ok());
        assert_eq!(
            restricted_attributes_ok(se::SE_GROUP_ENABLED),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
