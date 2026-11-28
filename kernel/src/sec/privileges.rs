//! The privilege model's primitives: what names a privilege (a LUID), the well-known privileges
//! and their public names, the lookups between a name and its LUID, the check of a privilege
//! against a set that holds it, and the adjustment of a set's privileges. The token side of these
//! (what a token holds and reports) stays in `crate::se`; the privilege side lives here.
//!
//! A privilege is named by a LUID, 64 bits: a low unsigned part and a high signed part
//! ([`Luid`]); a privilege entry is the LUID with its attributes ([`LuidAndAttributes`], one
//! entry of a TOKEN_PRIVILEGES). The attributes are the public SE_PRIVILEGE_* flags: enabled by
//! default, enabled, used for access. Only the enabled bit ever changes, and an adjustment reads
//! only that bit of what it is given.
//!
//! The well-known privileges have public LUIDs — low parts 2 to 27 with a zero high part — and
//! public names (ASCII strings). A lookup by name answers the privilege's LUID whether the name
//! is given in ANSI or in wide form: both map to the same LUID. A lookup by LUID answers the
//! name. Names match without regard to the case of ASCII letters. One LUID, 6, carries two
//! public names; a lookup by LUID answers the first of them.
//!
//! The check of a privilege against a set ([`held_enabled`]) passes when the set holds the
//! privilege — an entry names its LUID — and that entry has it enabled: the single-privilege
//! check a service makes before it acts.
//!
//! The adjustment of a set ([`adjust`]) enables or disables only what the set holds; a NewState
//! entry naming a privilege the set does not hold is not assigned, which the answer reports (the
//! token service answers STATUS_NOT_ALL_ASSIGNED, Win32's ERROR_NOT_ALL_ASSIGNED) while the
//! held privileges change all the same. The entries whose enabled bit actually changed are
//! reported with their attributes before the change; when the caller's PreviousState buffer is
//! too short for that report, nothing changes and the size the report takes is the answer.
//!
//! [`DEFAULT_PRIVILEGES`] is the set a token holds when it is made: an administrator's, in the
//! order its token lists them.

// The name<->LUID lookups and the well-known LUIDs a token never holds stay unwired until their
// consumers land (the Win32 privilege-name calls, the checks of the privileges no administrator
// holds); the token side uses the rest.
#![allow(dead_code)]

use rtl::array_vec::ArrayVec;
use rtl::nt::{Luid, LuidAndAttributes};

/// The privileges' attributes (the public SE_PRIVILEGE_* flags): enabled when the token was
/// made, enabled now, and used for access (a check marks the privilege it passed on). Only the
/// second changes; an adjustment reads only that bit of what it is given.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x2;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

/// The well-known privileges' public LUID low parts (the public SE_*_PRIVILEGE values); each
/// such LUID's high part is zero. LUID 6 carries two public names (SeMachineAccountPrivilege and
/// SeUnsolicitedInputPrivilege), both looking up to it.
pub const SE_CREATE_TOKEN_PRIVILEGE: u32 = 2;
pub const SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE: u32 = 3;
pub const SE_LOCK_MEMORY_PRIVILEGE: u32 = 4;
pub const SE_INCREASE_QUOTA_PRIVILEGE: u32 = 5;
pub const SE_UNSOLICITED_INPUT_PRIVILEGE: u32 = 6;
pub const SE_MACHINE_ACCOUNT_PRIVILEGE: u32 = 6;
pub const SE_TCB_PRIVILEGE: u32 = 7;
pub const SE_SECURITY_PRIVILEGE: u32 = 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u32 = 9;
pub const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;
pub const SE_SYSTEM_PROFILE_PRIVILEGE: u32 = 11;
pub const SE_SYSTEMTIME_PRIVILEGE: u32 = 12;
pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
pub const SE_INC_BASE_PRIORITY_PRIVILEGE: u32 = 14;
pub const SE_CREATE_PAGEFILE_PRIVILEGE: u32 = 15;
pub const SE_CREATE_PERMANENT_PRIVILEGE: u32 = 16;
pub const SE_BACKUP_PRIVILEGE: u32 = 17;
pub const SE_RESTORE_PRIVILEGE: u32 = 18;
pub const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
pub const SE_DEBUG_PRIVILEGE: u32 = 20;
pub const SE_AUDIT_PRIVILEGE: u32 = 21;
pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: u32 = 22;
pub const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;
pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: u32 = 24;
pub const SE_UNDOCK_PRIVILEGE: u32 = 25;
pub const SE_SYNC_AGENT_PRIVILEGE: u32 = 26;
pub const SE_ENABLE_DELEGATION_PRIVILEGE: u32 = 27;

/// The well-known privileges' LUID range: 2 to 27, high part zero.
pub const SE_MIN_WELL_KNOWN_PRIVILEGE: u32 = SE_CREATE_TOKEN_PRIVILEGE;
pub const SE_MAX_WELL_KNOWN_PRIVILEGE: u32 = SE_ENABLE_DELEGATION_PRIVILEGE;

/// A LUID from its public low part: the well-known privileges' high part is zero.
pub const fn luid(low: u32) -> Luid {
    Luid {
        low_part: low,
        high_part: 0,
    }
}

/// Whether two LUIDs are the same: both parts equal.
pub const fn equal_luid(a: Luid, b: Luid) -> bool {
    a.low_part == b.low_part && a.high_part == b.high_part
}

/// The well-known privileges' public names (the SE_*_NAME strings) with their LUIDs' low parts,
/// in LUID order. LUID 6's two public names both look up to it; the first is the one a lookup by
/// LUID answers.
const NAMES: [(&str, u32); 27] = [
    ("SeCreateTokenPrivilege", SE_CREATE_TOKEN_PRIVILEGE),
    (
        "SeAssignPrimaryTokenPrivilege",
        SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE,
    ),
    ("SeLockMemoryPrivilege", SE_LOCK_MEMORY_PRIVILEGE),
    ("SeIncreaseQuotaPrivilege", SE_INCREASE_QUOTA_PRIVILEGE),
    ("SeMachineAccountPrivilege", SE_MACHINE_ACCOUNT_PRIVILEGE),
    (
        "SeUnsolicitedInputPrivilege",
        SE_UNSOLICITED_INPUT_PRIVILEGE,
    ),
    ("SeTcbPrivilege", SE_TCB_PRIVILEGE),
    ("SeSecurityPrivilege", SE_SECURITY_PRIVILEGE),
    ("SeTakeOwnershipPrivilege", SE_TAKE_OWNERSHIP_PRIVILEGE),
    ("SeLoadDriverPrivilege", SE_LOAD_DRIVER_PRIVILEGE),
    ("SeSystemProfilePrivilege", SE_SYSTEM_PROFILE_PRIVILEGE),
    ("SeSystemtimePrivilege", SE_SYSTEMTIME_PRIVILEGE),
    (
        "SeProfileSingleProcessPrivilege",
        SE_PROF_SINGLE_PROCESS_PRIVILEGE,
    ),
    (
        "SeIncreaseBasePriorityPrivilege",
        SE_INC_BASE_PRIORITY_PRIVILEGE,
    ),
    ("SeCreatePagefilePrivilege", SE_CREATE_PAGEFILE_PRIVILEGE),
    ("SeCreatePermanentPrivilege", SE_CREATE_PERMANENT_PRIVILEGE),
    ("SeBackupPrivilege", SE_BACKUP_PRIVILEGE),
    ("SeRestorePrivilege", SE_RESTORE_PRIVILEGE),
    ("SeShutdownPrivilege", SE_SHUTDOWN_PRIVILEGE),
    ("SeDebugPrivilege", SE_DEBUG_PRIVILEGE),
    ("SeAuditPrivilege", SE_AUDIT_PRIVILEGE),
    (
        "SeSystemEnvironmentPrivilege",
        SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    ),
    ("SeChangeNotifyPrivilege", SE_CHANGE_NOTIFY_PRIVILEGE),
    ("SeRemoteShutdownPrivilege", SE_REMOTE_SHUTDOWN_PRIVILEGE),
    ("SeUndockPrivilege", SE_UNDOCK_PRIVILEGE),
    ("SeSyncAgentPrivilege", SE_SYNC_AGENT_PRIVILEGE),
    (
        "SeEnableDelegationPrivilege",
        SE_ENABLE_DELEGATION_PRIVILEGE,
    ),
];

/// Whether `name` is the ANSI form of the public name `known`: same length, ASCII letters equal
/// without regard to case.
fn name_matches_a(name: &[u8], known: &str) -> bool {
    name.eq_ignore_ascii_case(known.as_bytes())
}

/// Whether `name` is the wide form of the public name `known`: same length, each unit under 0x80
/// and equal to its byte without regard to ASCII case.
fn name_matches_w(name: &[u16], known: &str) -> bool {
    name.len() == known.len()
        && name
            .iter()
            .zip(known.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// The LUID of the well-known privilege whose ANSI name is `name` — None when no well-known
/// privilege has it. ASCII letters match without regard to case.
pub fn luid_of_name_a(name: &[u8]) -> Option<Luid> {
    NAMES
        .iter()
        .find(|(known, _)| name_matches_a(name, known))
        .map(|&(_, low)| luid(low))
}

/// The LUID of the well-known privilege whose wide name is `name`: the same LUID its ANSI form
/// answers. A unit at or above 0x80 matches nothing (the public names are ASCII).
pub fn luid_of_name_w(name: &[u16]) -> Option<Luid> {
    NAMES
        .iter()
        .find(|(known, _)| name_matches_w(name, known))
        .map(|&(_, low)| luid(low))
}

/// The public ANSI name of the well-known privilege whose LUID is `privilege` — None when no
/// well-known privilege has it (a LUID whose high part is not zero is none's). Of a LUID with
/// two public names, the first in the table's order.
pub fn name_of_luid_a(privilege: Luid) -> Option<&'static str> {
    if privilege.high_part != 0 {
        return None;
    }
    NAMES
        .iter()
        .find(|&&(_, low)| low == privilege.low_part)
        .map(|&(name, _)| name)
}

/// The public wide name of the well-known privilege whose LUID is `privilege`, written into
/// `out` without a terminator, the units written returned — None when no well-known privilege
/// has it or `out` is too short. The names are ASCII, so each unit is its byte.
pub fn name_of_luid_w(privilege: Luid, out: &mut [u16]) -> Option<usize> {
    let name = name_of_luid_a(privilege)?;
    let units = out.get_mut(..name.len())?;
    for (unit, byte) in units.iter_mut().zip(name.bytes()) {
        *unit = byte as u16;
    }
    Some(name.len())
}

/// Whether `set` holds `privilege`: an entry of the set names its LUID, whatever its attributes.
pub fn held(set: &[LuidAndAttributes], privilege: Luid) -> bool {
    set.iter().any(|entry| equal_luid(entry.luid, privilege))
}

/// Whether `set` holds `privilege` and has it enabled: an entry whose LUID is the privilege's
/// and whose attributes carry SE_PRIVILEGE_ENABLED. This is the single-privilege check a service
/// makes before it acts; only the enabled bit is read.
pub fn held_enabled(set: &[LuidAndAttributes], privilege: Luid) -> bool {
    set.iter().any(|entry| {
        equal_luid(entry.luid, privilege) && entry.attributes & SE_PRIVILEGE_ENABLED != 0
    })
}

/// How many privileges a token holds.
pub const HELD: usize = 19;

/// TOKEN_PRIVILEGES' size for `count` entries: the count, then the entries.
pub const fn privileges_size(count: usize) -> u32 {
    (4 + count * core::mem::size_of::<LuidAndAttributes>()) as u32
}

/// A privilege of the given public LUID and attributes.
pub const fn privilege(low: u32, attributes: u32) -> LuidAndAttributes {
    LuidAndAttributes {
        luid: Luid {
            low_part: low,
            high_part: 0,
        },
        attributes,
    }
}

/// The privileges a token holds and their state when it is made: an administrator's on Windows
/// 2000, in the order its token lists them. The ones every user holds come first, enabled by
/// default (SeChangeNotifyPrivilege, bypassing traverse checking) or not; then the
/// Administrators group's, held disabled: the token fixture's `privs` block enables
/// SeSystemtimePrivilege, SeBackupPrivilege, SeShutdownPrivilege and SeDebugPrivilege and finds
/// each held and disabled, and `notheld` finds SeTcbPrivilege not held (no account holds it but
/// the system's own). SeUndockPrivilege, which every interactive user holds, starts disabled
/// (Inside Windows 2000; winlogon may change its state later, and F2K has no winlogon). The
/// privileges no administrator's token holds
/// (SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeLockMemoryPrivilege,
/// SeMachineAccountPrivilege, SeTcbPrivilege, SeSyncAgentPrivilege, SeEnableDelegationPrivilege)
/// are refused: not all assigned.
pub const DEFAULT_PRIVILEGES: [LuidAndAttributes; HELD] = [
    privilege(
        SE_CHANGE_NOTIFY_PRIVILEGE,
        SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
    ),
    privilege(SE_SECURITY_PRIVILEGE, 0),
    privilege(SE_BACKUP_PRIVILEGE, 0),
    privilege(SE_RESTORE_PRIVILEGE, 0),
    privilege(SE_SYSTEMTIME_PRIVILEGE, 0),
    privilege(SE_SHUTDOWN_PRIVILEGE, 0),
    privilege(SE_REMOTE_SHUTDOWN_PRIVILEGE, 0),
    privilege(SE_TAKE_OWNERSHIP_PRIVILEGE, 0),
    privilege(SE_DEBUG_PRIVILEGE, 0),
    privilege(SE_AUDIT_PRIVILEGE, 0),
    privilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 0),
    privilege(SE_SYSTEM_PROFILE_PRIVILEGE, 0),
    privilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, 0),
    privilege(SE_INC_BASE_PRIORITY_PRIVILEGE, 0),
    privilege(SE_LOAD_DRIVER_PRIVILEGE, 0),
    privilege(SE_CREATE_PAGEFILE_PRIVILEGE, 0),
    privilege(SE_CREATE_PERMANENT_PRIVILEGE, 0),
    privilege(SE_INCREASE_QUOTA_PRIVILEGE, 0),
    privilege(SE_UNDOCK_PRIVILEGE, 0),
];

/// What a NewState asks of a set, folded from its entries in their order: for each privilege the
/// set holds, whether to enable it (the last entry naming it decides), and whether an entry
/// names a privilege the set does not hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Requests {
    wanted: [Option<bool>; HELD],
    unheld: bool,
}

impl Requests {
    /// No entry yet.
    pub const fn new() -> Self {
        Requests {
            wanted: [None; HELD],
            unheld: false,
        }
    }

    /// One more of NewState's entries: its privilege enabled when its attributes carry
    /// SE_PRIVILEGE_ENABLED, disabled otherwise.
    pub fn add(&mut self, entry: LuidAndAttributes) {
        let slot = DEFAULT_PRIVILEGES
            .iter()
            .position(|held| held.luid == entry.luid);
        match slot {
            Some(index) => self.wanted[index] = Some(entry.attributes & SE_PRIVILEGE_ENABLED != 0),
            None => self.unheld = true,
        }
    }
}

/// An adjustment of a set's privileges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// DisableAllPrivileges: every enabled privilege disabled.
    DisableAll,
    /// NewState's entries.
    Set(Requests),
}

/// What an adjustment did: the privileges it changed, with their attributes before it
/// (PreviousState's entries), and whether NewState named a privilege the set does not hold
/// (not all assigned: the others are changed all the same).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adjusted {
    pub previous: ArrayVec<LuidAndAttributes, HELD>,
    pub not_all_assigned: bool,
}

impl Adjusted {
    /// PreviousState's size: its count and its entries (ReturnLength).
    pub fn length(&self) -> u32 {
        privileges_size(self.previous.len())
    }
}

/// Apply `change` to a privilege set held in the default order (the order [`DEFAULT_PRIVILEGES`]
/// lists them, as a token holds them), as an adjust-privileges call does: each entry the change
/// addresses gets its enabled bit set or cleared — only SE_PRIVILEGE_ENABLED of a NewState
/// entry's attributes is read — and each entry whose enabled bit actually changes is reported in
/// the answer, with its attributes before the change, in the set's order. A NewState entry
/// naming a privilege the set does not hold is not assigned: the answer says so, and the held
/// privileges change all the same. With `room` (PreviousState's buffer length, when the caller
/// gives one), a change whose report would not fit makes no change at all: the error is the size
/// the report takes.
pub fn adjust(
    set: &mut [LuidAndAttributes],
    change: &Change,
    room: Option<u32>,
) -> Result<Adjusted, u32> {
    // What each entry's enabled bit becomes: None where the change does not address it.
    let wanted = |index: usize| match change {
        Change::DisableAll => Some(false),
        Change::Set(requests) => requests.wanted.get(index).copied().flatten(),
    };
    // First pass: what changes, each change's old entry recorded in the set's order.
    let mut previous = ArrayVec::new();
    for (index, entry) in set.iter().enumerate() {
        if let Some(enable) = wanted(index) {
            if enable != (entry.attributes & SE_PRIVILEGE_ENABLED != 0) {
                previous.push(*entry);
            }
        }
    }
    let adjusted = Adjusted {
        previous,
        not_all_assigned: matches!(change, Change::Set(requests) if requests.unheld),
    };
    // A PreviousState too short for the report changes nothing, and asks for the report's size.
    if room.is_some_and(|room| room < adjusted.length()) {
        return Err(adjusted.length());
    }
    // Second pass: make the changes.
    for (index, entry) in set.iter_mut().enumerate() {
        match wanted(index) {
            Some(true) => entry.attributes |= SE_PRIVILEGE_ENABLED,
            Some(false) => entry.attributes &= !SE_PRIVILEGE_ENABLED,
            None => {}
        }
    }
    Ok(adjusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(name: &str) -> Vec<u16> {
        name.encode_utf16().collect()
    }

    fn change(entries: &[(u32, u32)]) -> Change {
        let mut requests = Requests::new();
        for &(low, attributes) in entries {
            requests.add(privilege(low, attributes));
        }
        Change::Set(requests)
    }

    fn attributes_of(set: &[LuidAndAttributes], low: u32) -> Option<u32> {
        set.iter()
            .find(|entry| entry.luid.low_part == low)
            .map(|entry| entry.attributes)
    }

    /// The well-known privileges' public LUID low values, as the privchk fixture pins them:
    /// SeSecurityPrivilege 8, SeShutdownPrivilege 19, SeDebugPrivilege 20,
    /// SeChangeNotifyPrivilege 23; the range is 2 to 27, each LUID's high part zero.
    #[test]
    fn the_well_known_luids_are_the_public_values() {
        assert_eq!(SE_SECURITY_PRIVILEGE, 8);
        assert_eq!(SE_SHUTDOWN_PRIVILEGE, 19);
        assert_eq!(SE_DEBUG_PRIVILEGE, 20);
        assert_eq!(SE_CHANGE_NOTIFY_PRIVILEGE, 23);
        assert_eq!(SE_MIN_WELL_KNOWN_PRIVILEGE, 2);
        assert_eq!(SE_MAX_WELL_KNOWN_PRIVILEGE, 27);
        for low in SE_MIN_WELL_KNOWN_PRIVILEGE..=SE_MAX_WELL_KNOWN_PRIVILEGE {
            let privilege = luid(low);
            assert_eq!(privilege.low_part, low);
            assert_eq!(privilege.high_part, 0);
        }
        assert!(equal_luid(
            luid(19),
            Luid {
                low_part: 19,
                high_part: 0
            }
        ));
        assert!(!equal_luid(
            luid(19),
            Luid {
                low_part: 19,
                high_part: 1
            }
        ));
        assert!(!equal_luid(luid(19), luid(20)));
    }

    /// Every well-known name looks up to its LUID in ANSI and in wide form — both to the same
    /// LUID, ASCII case folded — and every LUID looks back to its name; the privchk fixture's
    /// SeShutdownPrivilege, SeDebugPrivilege and SeSecurityPrivilege pin 19, 20 and 8.
    #[test]
    fn names_look_up_to_their_luids_and_back() {
        assert_eq!(luid_of_name_a(b"SeShutdownPrivilege"), Some(luid(19)));
        assert_eq!(luid_of_name_a(b"SeDebugPrivilege"), Some(luid(20)));
        assert_eq!(luid_of_name_a(b"SeSecurityPrivilege"), Some(luid(8)));
        assert_eq!(luid_of_name_a(b"SeChangeNotifyPrivilege"), Some(luid(23)));
        assert_eq!(luid_of_name_a(b"seshutdownPRIVILEGE"), Some(luid(19)));
        assert_eq!(luid_of_name_w(&wide("SeShutdownPrivilege")), Some(luid(19)));
        assert_eq!(luid_of_name_w(&wide("seshutdownprivilege")), Some(luid(19)));
        for &(name, low) in &NAMES {
            assert_eq!(luid_of_name_a(name.as_bytes()), Some(luid(low)), "{name}");
            assert_eq!(luid_of_name_w(&wide(name)), Some(luid(low)), "{name}");
        }
        // The first name of LUID 6 is the one a lookup by LUID answers.
        assert_eq!(
            luid_of_name_a(b"SeUnsolicitedInputPrivilege"),
            Some(luid(6))
        );
        assert_eq!(name_of_luid_a(luid(6)), Some("SeMachineAccountPrivilege"));
        // Every LUID answers the first of its names in the table's order.
        for &(_, low) in &NAMES {
            let first = NAMES
                .iter()
                .find(|&&(_, named)| named == low)
                .map(|&(name, _)| name)
                .unwrap();
            assert_eq!(name_of_luid_a(luid(low)), Some(first), "{low}");
        }
        assert_eq!(name_of_luid_a(luid(19)), Some("SeShutdownPrivilege"));
        assert_eq!(name_of_luid_a(luid(20)), Some("SeDebugPrivilege"));
        assert_eq!(name_of_luid_a(luid(23)), Some("SeChangeNotifyPrivilege"));
    }

    /// An unknown name or LUID looks up to nothing, in either form: a name no privilege has, an
    /// empty one, a LUID past the well-known range, and one whose high part is not zero.
    #[test]
    fn an_unknown_name_or_luid_looks_up_to_nothing() {
        assert_eq!(luid_of_name_a(b"SeNoSuchPrivilege"), None);
        assert_eq!(luid_of_name_w(&wide("SeNoSuchPrivilege")), None);
        assert_eq!(luid_of_name_a(b""), None);
        assert_eq!(luid_of_name_w(&[]), None);
        assert_eq!(luid_of_name_w(&[0x100]), None);
        assert_eq!(name_of_luid_a(luid(65536)), None);
        assert_eq!(
            name_of_luid_a(Luid {
                low_part: 19,
                high_part: 1
            }),
            None
        );
        assert_eq!(name_of_luid_a(luid(1)), None);
        assert_eq!(name_of_luid_a(luid(28)), None);
    }

    /// The wide name of a LUID is written unit by unit (the names are ASCII), no terminator;
    /// a buffer too short for it answers None.
    #[test]
    fn the_wide_name_is_written_unit_by_unit() {
        let mut out = [0u16; 64];
        let written = name_of_luid_w(luid(SE_SHUTDOWN_PRIVILEGE), &mut out).unwrap();
        assert_eq!(written, "SeShutdownPrivilege".len());
        assert_eq!(&out[..written], wide("SeShutdownPrivilege").as_slice());
        assert_eq!(out[written], 0, "no terminator is written");
        assert_eq!(
            name_of_luid_w(luid(SE_SHUTDOWN_PRIVILEGE), &mut out[..5]),
            None
        );
        assert_eq!(name_of_luid_w(luid(65536), &mut out), None);
    }

    /// The check reads the enabled bit of a held privilege: over the default set,
    /// SeChangeNotifyPrivilege passes (enabled by default), SeShutdownPrivilege and
    /// SeUndockPrivilege are held but do not pass until enabled, and SeTcbPrivilege is not held at
    /// all.
    #[test]
    fn the_check_reads_the_enabled_bit_of_a_held_privilege() {
        let privileges = DEFAULT_PRIVILEGES;
        assert!(held(&privileges, luid(SE_CHANGE_NOTIFY_PRIVILEGE)));
        assert!(held_enabled(&privileges, luid(SE_CHANGE_NOTIFY_PRIVILEGE)));
        assert!(held(&privileges, luid(SE_UNDOCK_PRIVILEGE)));
        assert!(!held_enabled(&privileges, luid(SE_UNDOCK_PRIVILEGE)));
        assert!(held(&privileges, luid(SE_SHUTDOWN_PRIVILEGE)));
        assert!(!held_enabled(&privileges, luid(SE_SHUTDOWN_PRIVILEGE)));
        assert!(!held(&privileges, luid(SE_TCB_PRIVILEGE)));
        assert!(!held_enabled(&privileges, luid(SE_TCB_PRIVILEGE)));
        assert!(!held_enabled(&privileges, luid(65536)));
        let mut privileges = privileges;
        let adjusted = adjust(
            &mut privileges,
            &change(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]),
            None,
        )
        .unwrap();
        assert!(!adjusted.not_all_assigned);
        assert!(held_enabled(&privileges, luid(SE_SHUTDOWN_PRIVILEGE)));
    }

    /// Enabling a held privilege reports its old state and sets the enabled bit; enabling again
    /// changes nothing and reports an empty PreviousState; disabling reports the enabled state.
    /// TOKEN_PRIVILEGES for the default set takes 232 bytes, and the two added
    /// privileges (SeAuditPrivilege, SeCreatePermanentPrivilege) are held disabled like the
    /// rest of the Administrators' ones, SeTcbPrivilege still not held.
    #[test]
    fn adjust_enables_and_disables_and_reports_the_old_state() {
        assert_eq!(privileges_size(HELD), 232);
        let privileges = DEFAULT_PRIVILEGES;
        assert!(held(&privileges, luid(SE_AUDIT_PRIVILEGE)));
        assert!(held(&privileges, luid(SE_CREATE_PERMANENT_PRIVILEGE)));
        assert!(!held(&privileges, luid(SE_TCB_PRIVILEGE)));
        let mut set = DEFAULT_PRIVILEGES;
        let enable = change(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]);
        let first = adjust(&mut set, &enable, Some(256)).unwrap();
        assert_eq!(
            first.previous.as_slice(),
            [privilege(SE_SHUTDOWN_PRIVILEGE, 0)]
        );
        assert_eq!(first.length(), 16);
        assert!(!first.not_all_assigned);
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(2));
        let again = adjust(&mut set, &enable, Some(256)).unwrap();
        assert!(again.previous.is_empty());
        assert_eq!(again.length(), 4);
        let disable = adjust(&mut set, &change(&[(SE_SHUTDOWN_PRIVILEGE, 0)]), None).unwrap();
        assert_eq!(
            disable.previous.as_slice(),
            [privilege(SE_SHUTDOWN_PRIVILEGE, 2)]
        );
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(0));
    }

    /// A privilege the set does not hold is not assigned: the answer says so, the set is
    /// unchanged for it, and the held privileges in the same NewState change all the same.
    #[test]
    fn an_unheld_privilege_is_not_all_assigned() {
        let mut set = DEFAULT_PRIVILEGES;
        let tcb = adjust(
            &mut set,
            &change(&[(SE_TCB_PRIVILEGE, SE_PRIVILEGE_ENABLED)]),
            Some(256),
        )
        .unwrap();
        assert!(tcb.not_all_assigned);
        assert!(tcb.previous.is_empty());
        assert_eq!(attributes_of(&set, SE_TCB_PRIVILEGE), None);
        let mixed = adjust(
            &mut set,
            &change(&[
                (SE_TCB_PRIVILEGE, SE_PRIVILEGE_ENABLED),
                (SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED),
            ]),
            Some(256),
        )
        .unwrap();
        assert!(mixed.not_all_assigned);
        assert_eq!(
            mixed.previous.as_slice(),
            [privilege(SE_SHUTDOWN_PRIVILEGE, 0)]
        );
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(2));
        assert_eq!(attributes_of(&set, SE_TCB_PRIVILEGE), None);
    }

    /// Only SE_PRIVILEGE_ENABLED of a NewState entry's attributes is read: enabled by default
    /// stays as the set was made. A PreviousState too short for the report changes nothing and
    /// asks for the report's size, however short (the count alone, or nothing).
    #[test]
    fn only_the_enabled_bit_is_read_and_a_short_room_changes_nothing() {
        let mut set = DEFAULT_PRIVILEGES;
        adjust(
            &mut set,
            &change(&[(SE_SHUTDOWN_PRIVILEGE, 0x8000_0001)]),
            None,
        )
        .unwrap();
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(0));
        adjust(&mut set, &change(&[(SE_CHANGE_NOTIFY_PRIVILEGE, 0)]), None).unwrap();
        assert_eq!(attributes_of(&set, SE_CHANGE_NOTIFY_PRIVILEGE), Some(1));
        let enable = change(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]);
        assert_eq!(adjust(&mut set, &enable, Some(4)), Err(16));
        assert_eq!(adjust(&mut set, &enable, Some(0)), Err(16));
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(0));
        let disable = change(&[(SE_SHUTDOWN_PRIVILEGE, 0)]);
        assert_eq!(adjust(&mut set, &disable, Some(0)), Err(4));
        assert_eq!(adjust(&mut set, &disable, Some(4)).unwrap().length(), 4);
    }

    /// DisableAll disables what is enabled, reporting it (SeChangeNotifyPrivilege as 0x3, left
    /// 0x1; SeUndockPrivilege, already disabled, not reported).
    #[test]
    fn disable_all_disables_what_is_enabled() {
        let mut set = DEFAULT_PRIVILEGES;
        let all = adjust(&mut set, &Change::DisableAll, Some(4096)).unwrap();
        assert!(!all.not_all_assigned);
        assert_eq!(
            all.previous.as_slice(),
            [privilege(SE_CHANGE_NOTIFY_PRIVILEGE, 3)]
        );
        assert_eq!(attributes_of(&set, SE_CHANGE_NOTIFY_PRIVILEGE), Some(1));
        assert_eq!(attributes_of(&set, SE_UNDOCK_PRIVILEGE), Some(0));
        assert_eq!(attributes_of(&set, SE_SHUTDOWN_PRIVILEGE), Some(0));
        assert!(!held_enabled(&set, luid(SE_CHANGE_NOTIFY_PRIVILEGE)));
    }
}
