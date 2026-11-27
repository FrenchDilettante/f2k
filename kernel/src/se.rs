//! The security reference monitor's one piece F2K keeps: the token, the object OpenProcessToken
//! opens, with what it says about its holder (its user and groups, its privileges, its defaults)
//! and the privileges' state.
//!
//! F2K has no security model: no access control lists are checked, and no logon makes a token. A
//! token's contents are those of the one logon there is, an administrator's interactive one, as
//! Windows 2000 makes it (the account the corpus is captured on), so that the calls programs make
//! to look at their token (GetTokenInformation class by class, the "am I an administrator"
//! checks) answer as Windows 2000's do: the user an account of the machine's domain, the groups
//! the well-known ones an interactive administrator's logon holds and the logon's own SID, the
//! default owner BUILTIN\Administrators, the default DACL granting it and SYSTEM everything
//! ([`TokenBody::information`]). The machine's domain numbers are F2K's own (no SID prints them).
//!
//! The privileges are kept so that the calls a program makes before it shuts the machine down
//! (OpenProcessToken, AdjustTokenPrivileges enabling SeShutdownPrivilege, GetTokenInformation)
//! answer as Windows 2000's do: the change succeeds, and what it changed is reported back. One
//! privilege is checked: SeLoadDriverPrivilege, which NtLoadDriver and NtUnloadDriver require
//! enabled (STATUS_PRIVILEGE_NOT_HELD otherwise, as the `drvload` capture shows), so that a
//! driver's load answers as Windows 2000's does. Where else Windows 2000 checks a privilege
//! (ExitWindowsEx, NtShutdownSystem), F2K does not.
//!
//! Every token holds the same privileges, in the state Windows 2000 gives an administrator's token
//! ([`DEFAULT_PRIVILEGES`]: seventeen, SeChangeNotifyPrivilege and SeUndockPrivilege enabled by
//! default); a privilege it does not hold is refused (STATUS_NOT_ALL_ASSIGNED).
//!
//! A process has one token, made at its first open (Windows 2000 makes a process's primary token
//! with the process; F2K makes it on demand, since nothing reads it before it is opened). The
//! token names its process (see [`TokenBody::owner`]), as EPROCESS.Token names the token; the
//! process's reference on it goes at the process's end (see `crate::ob`). NtDuplicateToken makes
//! tokens of no process: a copy, primary or impersonation, of another ([`TokenBody::duplicate`]).

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::array_vec::ArrayVec;
use rtl::nt::LuidAndAttributes;

use crate::ob::ObjectId;
use crate::status::{NtStatus, STATUS_INVALID_PARAMETER};

// The privilege side — the attributes, the well-known LUIDs and their public names, the
// name<->LUID lookups, the single-privilege check, the adjustment and the default set — lives in
// `sec`; re-exported here where the token reads it.
pub use crate::sec::*;

/// A token's type (TOKEN_TYPE): a process's primary token, or a copy a thread impersonates with.
pub const TOKEN_PRIMARY: u32 = 1;
pub const TOKEN_IMPERSONATION: u32 = 2;

/// The impersonation levels (SECURITY_IMPERSONATION_LEVEL), SecurityAnonymous to
/// SecurityDelegation.
pub const SECURITY_ANONYMOUS: u32 = 0;
pub const SECURITY_DELEGATION: u32 = 3;

/// The locally unique ids F2K hands out (ExAllocateLocallyUniqueId's): from past the ones Windows
/// reserves (the system logon's 999 among them).
static NEXT_LUID: AtomicU32 = AtomicU32::new(0x0002_0000);

/// A new locally unique id's low part (the high part is zero).
fn new_luid() -> u32 {
    NEXT_LUID.fetch_add(1, Ordering::Relaxed)
}

/// The one logon's id (its AuthenticationId: an interactive logon's, not the system's 999), which
/// its logon SID carries too.
pub const LOGON_ID: u32 = 0x0000_C1A5;

/// The token source's id (TOKEN_SOURCE's SourceIdentifier) and its name, as the interactive
/// logon's tokens carry them: "User32  ".
const SOURCE_ID: u32 = 0x0000_C1A4;
const SOURCE_NAME: [u8; 8] = *b"User32  ";

/// A SID (winnt.h's): revision 1, its identifier authority (the low byte of the six: no authority
/// F2K names is larger), its sub-authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sid {
    pub authority: u8,
    pub sub: &'static [u32],
}

impl Sid {
    /// Its bytes' count: the header, then a dword per sub-authority.
    pub const fn size(&self) -> usize {
        8 + 4 * self.sub.len()
    }

    /// Its bytes, onto `out`.
    fn put(&self, out: &mut Reply) {
        out.bytes(&[1, self.sub.len() as u8, 0, 0, 0, 0, 0, self.authority]);
        for &sub in self.sub {
            out.word(sub);
        }
    }

    /// Whether `bytes` begin with this SID's bytes.
    #[cfg(test)]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        let mut mine = Reply::new();
        self.put(&mut mine);
        bytes.get(..self.size()) == Some(mine.as_slice())
    }
}

/// The machine's account domain (S-1-5-21-a-b-c), F2K's own numbers.
const DOMAIN: [u32; 4] = [21, 0x3B8F_43D1, 0x6A21_9C0E, 0x2E57_B6A9];

/// The well-known SIDs a token names.
pub const EVERYONE: Sid = Sid {
    authority: 1,
    sub: &[0],
};
pub const LOCAL: Sid = Sid {
    authority: 2,
    sub: &[0],
};
pub const INTERACTIVE: Sid = Sid {
    authority: 5,
    sub: &[4],
};
pub const AUTHENTICATED_USERS: Sid = Sid {
    authority: 5,
    sub: &[11],
};
pub const LOCAL_SYSTEM: Sid = Sid {
    authority: 5,
    sub: &[18],
};
pub const ADMINISTRATORS: Sid = Sid {
    authority: 5,
    sub: &[32, 544],
};
pub const USERS: Sid = Sid {
    authority: 5,
    sub: &[32, 545],
};
/// The logon's own SID, S-1-5-5-0-<its id>.
pub const LOGON: Sid = Sid {
    authority: 5,
    sub: &[5, 0, LOGON_ID],
};
/// The user: the account domain's first user (RID 1000), an administrator.
pub const USER: Sid = Sid {
    authority: 5,
    sub: &[DOMAIN[0], DOMAIN[1], DOMAIN[2], DOMAIN[3], 1000],
};
/// Its primary group: the account domain's "None" (RID 513), every local account's.
pub const PRIMARY_GROUP: Sid = Sid {
    authority: 5,
    sub: &[DOMAIN[0], DOMAIN[1], DOMAIN[2], DOMAIN[3], 513],
};

/// The groups' attributes (winnt.h's SE_GROUP_*).
pub const SE_GROUP_MANDATORY: u32 = 0x1;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x2;
pub const SE_GROUP_ENABLED: u32 = 0x4;
pub const SE_GROUP_OWNER: u32 = 0x8;
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
/// A group as a logon holds it: mandatory, enabled, as it was made.
const GROUP: u32 = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;

/// The groups an interactive administrator's logon holds, with their attributes, in the order
/// Windows 2000 lists them: BUILTIN\Administrators may own what the token makes.
pub const GROUPS: [(Sid, u32); 8] = [
    (PRIMARY_GROUP, GROUP),
    (EVERYONE, GROUP),
    (ADMINISTRATORS, GROUP | SE_GROUP_OWNER),
    (USERS, GROUP),
    (INTERACTIVE, GROUP),
    (AUTHENTICATED_USERS, GROUP),
    (LOGON, GROUP | SE_GROUP_LOGON_ID),
    (LOCAL, GROUP),
];

// The default DACL's ACE mask.
use rtl::nt::access::GENERIC_ALL;
/// The default DACL's ACEs: ACCESS_ALLOWED_ACE_TYPE, no flags, GENERIC_ALL, to
/// BUILTIN\Administrators and SYSTEM.
const DEFAULT_DACL: [Sid; 2] = [ADMINISTRATORS, LOCAL_SYSTEM];

/// The bytes the default DACL takes: the ACL's header, then each ACE's header, mask and SID.
const fn dacl_size() -> usize {
    8 + (8 + ADMINISTRATORS.size()) + (8 + LOCAL_SYSTEM.size())
}

/// What a token's statistics say it is charged for its dynamic part, and how much of it the
/// primary group and the default DACL leave.
const DYNAMIC_CHARGED: u32 = 500;

/// The token information classes F2K answers (TOKEN_INFORMATION_CLASS's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    User,
    Groups,
    Privileges,
    Owner,
    PrimaryGroup,
    DefaultDacl,
    Source,
    Type,
    ImpersonationLevel,
    Statistics,
    RestrictedSids,
    SessionId,
}

/// A token information class's answer as the caller's buffer receives it: the structure, its
/// pointers absolute (the buffer's address added), then what they point at.
pub type Reply = ArrayVec<u8, 512>;

/// Writing an answer's parts.
trait Put {
    fn bytes(&mut self, bytes: &[u8]);
    fn word(&mut self, word: u32);
}

impl Put for Reply {
    fn bytes(&mut self, bytes: &[u8]) {
        self.try_extend_from_slice(bytes)
            .expect("a token's answer fits its reply");
    }

    fn word(&mut self, word: u32) {
        self.bytes(&word.to_le_bytes());
    }
}

/// A token object's body.
#[derive(Clone, Copy, Debug)]
pub struct TokenBody {
    /// The process whose token it is, while that process holds it: cleared when the process lets
    /// go of it (its end), the token living on while handles to it are open. None in a pool's
    /// fresh record, and for a duplicate.
    pub owner: Option<ObjectId>,
    /// The privileges it holds and their state: bookkeeping only (see the module notes).
    privileges: [LuidAndAttributes; HELD],
    /// Its type, TOKEN_PRIMARY or TOKEN_IMPERSONATION, and an impersonation token's level.
    pub kind: u32,
    pub level: u32,
    /// Its TokenId, and its ModifiedId: a new one at each change of its privileges.
    id: u32,
    modified: u32,
}

impl TokenBody {
    /// A record holding no token yet (a pool's fresh record).
    pub const fn none() -> Self {
        TokenBody {
            owner: None,
            privileges: DEFAULT_PRIVILEGES,
            kind: TOKEN_PRIMARY,
            level: SECURITY_ANONYMOUS,
            id: 0,
            modified: 0,
        }
    }

    /// A new primary token for the process `owner`, its privileges in their default state.
    pub fn of(owner: ObjectId) -> Self {
        let id = new_luid();
        TokenBody {
            owner: Some(owner),
            id,
            modified: id,
            ..TokenBody::none()
        }
    }

    /// A copy of this token (NtDuplicateToken's), of type `kind` (an impersonation token at
    /// `level`): a new TokenId, of no process, the rest as this one's.
    pub fn duplicate(&self, kind: u32, level: u32) -> Self {
        TokenBody {
            owner: None,
            kind,
            level: if kind == TOKEN_IMPERSONATION {
                level
            } else {
                SECURITY_ANONYMOUS
            },
            id: new_luid(),
            ..*self
        }
    }

    /// The privileges and their state, in the token's order.
    #[cfg(test)]
    pub fn privileges(&self) -> [LuidAndAttributes; HELD] {
        self.privileges
    }

    /// Whether the token holds the privilege of public LUID `luid` and has it enabled: what a
    /// privilege check (SeSinglePrivilegeCheck) asks.
    pub fn enabled(&self, luid: u32) -> bool {
        crate::sec::held_enabled(&self.privileges, crate::sec::luid(luid))
    }

    /// Apply `change` to the privileges, as NtAdjustPrivilegesToken does: each privilege whose
    /// enabled bit changes is reported in the answer, with its attributes before the change, in
    /// the token's order. With `room` (PreviousState's buffer length, when the caller gives one),
    /// a change whose report would not fit makes no change at all: the error is the size the
    /// report takes. A change that changes something gives the token a new ModifiedId.
    pub fn adjust(&mut self, change: &Change, room: Option<u32>) -> Result<Adjusted, u32> {
        let adjusted = crate::sec::adjust(&mut self.privileges, change, room)?;
        if !adjusted.previous.is_empty() {
            self.modified = new_luid();
        }
        Ok(adjusted)
    }

    /// The token's information of `class`, as it reads at the caller's buffer's address `base`
    /// (NtQueryInformationToken's answer; see [`Class`]). TokenImpersonationLevel of a primary
    /// token is STATUS_INVALID_PARAMETER: it has none.
    pub fn information(&self, class: Class, base: u32) -> Result<Reply, NtStatus> {
        let mut out = Reply::new();
        match class {
            // TOKEN_USER: a SID_AND_ATTRIBUTES (the SID's address, no attributes), the SID.
            Class::User => {
                out.word(base + 8);
                out.word(0);
                USER.put(&mut out);
            }
            // TOKEN_GROUPS: the count, a SID_AND_ATTRIBUTES each, the SIDs in their order.
            Class::Groups => {
                out.word(GROUPS.len() as u32);
                let mut at = base + 4 + 8 * GROUPS.len() as u32;
                for (sid, attributes) in GROUPS {
                    out.word(at);
                    out.word(attributes);
                    at += sid.size() as u32;
                }
                for (sid, _) in GROUPS {
                    sid.put(&mut out);
                }
            }
            // TOKEN_PRIVILEGES: the count, then the entries.
            Class::Privileges => {
                out.word(HELD as u32);
                for privilege in self.privileges {
                    out.word(privilege.luid.low_part);
                    out.word(privilege.luid.high_part as u32);
                    out.word(privilege.attributes);
                }
            }
            // TOKEN_OWNER and TOKEN_PRIMARY_GROUP: the SID's address, the SID.
            Class::Owner | Class::PrimaryGroup => {
                out.word(base + 4);
                let sid = if class == Class::Owner {
                    ADMINISTRATORS
                } else {
                    PRIMARY_GROUP
                };
                sid.put(&mut out);
            }
            // TOKEN_DEFAULT_DACL: the ACL's address, the ACL (revision 2) and its ACEs.
            Class::DefaultDacl => {
                out.word(base + 4);
                out.bytes(&[2, 0]);
                out.bytes(&(dacl_size() as u16).to_le_bytes());
                out.bytes(&(DEFAULT_DACL.len() as u16).to_le_bytes());
                out.bytes(&[0, 0]);
                for sid in DEFAULT_DACL {
                    out.bytes(&[0, 0]);
                    out.bytes(&((8 + sid.size()) as u16).to_le_bytes());
                    out.word(GENERIC_ALL);
                    sid.put(&mut out);
                }
            }
            // TOKEN_SOURCE: the source's name and id.
            Class::Source => {
                out.bytes(&SOURCE_NAME);
                out.word(SOURCE_ID);
                out.word(0);
            }
            Class::Type => out.word(self.kind),
            Class::ImpersonationLevel => {
                if self.kind != TOKEN_IMPERSONATION {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                out.word(self.level);
            }
            // TOKEN_STATISTICS.
            Class::Statistics => {
                for luid in [self.id, LOGON_ID] {
                    out.word(luid);
                    out.word(0);
                }
                out.word(u32::MAX);
                out.word(i32::MAX as u32);
                out.word(self.kind);
                out.word(self.level);
                out.word(DYNAMIC_CHARGED);
                out.word(DYNAMIC_CHARGED - (dacl_size() + PRIMARY_GROUP.size()) as u32);
                out.word(GROUPS.len() as u32);
                out.word(HELD as u32);
                out.word(self.modified);
                out.word(0);
            }
            // TOKEN_GROUPS of no group: the token is not restricted.
            Class::RestrictedSids => out.word(0),
            // The session: the console's, 0.
            Class::SessionId => out.word(0),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCB: u32 = 7;

    fn token() -> TokenBody {
        TokenBody::of(ObjectId {
            kind: crate::ob::ObjectType::Process,
            index: 1,
            generation: 0,
        })
    }

    fn set(entries: &[(u32, u32)]) -> Change {
        let mut requests = Requests::new();
        for &(luid, attributes) in entries {
            requests.add(privilege(luid, attributes));
        }
        Change::Set(requests)
    }

    fn attributes_of(token: &TokenBody, luid: u32) -> Option<u32> {
        token
            .privileges()
            .iter()
            .find(|privilege| privilege.luid.low_part == luid)
            .map(|privilege| privilege.attributes)
    }

    /// A new token holds an administrator's privileges: the four the `privs` capture enables
    /// (SeSystemtimePrivilege, SeBackupPrivilege, SeShutdownPrivilege, SeDebugPrivilege) and
    /// SeLoadDriverPrivilege disabled, SeChangeNotifyPrivilege and SeUndockPrivilege enabled by
    /// default, SeTcbPrivilege not at all; each once. TOKEN_PRIVILEGES for them takes 208 bytes.
    #[test]
    fn a_new_token_holds_an_administrators_privileges() {
        let token = token();
        for luid in [
            SE_SYSTEMTIME_PRIVILEGE,
            SE_BACKUP_PRIVILEGE,
            SE_SHUTDOWN_PRIVILEGE,
            SE_DEBUG_PRIVILEGE,
            SE_LOAD_DRIVER_PRIVILEGE,
        ] {
            assert_eq!(attributes_of(&token, luid), Some(0), "{luid}");
        }
        assert_eq!(attributes_of(&token, SE_CHANGE_NOTIFY_PRIVILEGE), Some(3));
        assert_eq!(attributes_of(&token, SE_UNDOCK_PRIVILEGE), Some(3));
        for luid in [2, 3, 4, 6, TCB, 16, 21, 26, 27] {
            assert_eq!(attributes_of(&token, luid), None, "{luid}");
        }
        let mut luids: Vec<u32> = DEFAULT_PRIVILEGES.iter().map(|p| p.luid.low_part).collect();
        luids.sort();
        luids.dedup();
        assert_eq!(luids.len(), HELD);
        assert_eq!(privileges_size(HELD), 208);
    }

    /// The `privs` capture's last call: all four enabled at once report each one's old state,
    /// 52 bytes; that report given back as NewState puts them back.
    #[test]
    fn four_enabled_at_once_and_put_back() {
        let mut token = token();
        let four = [
            SE_SYSTEMTIME_PRIVILEGE,
            SE_BACKUP_PRIVILEGE,
            SE_SHUTDOWN_PRIVILEGE,
            SE_DEBUG_PRIVILEGE,
        ];
        let all = token
            .adjust(
                &set(&four.map(|luid| (luid, SE_PRIVILEGE_ENABLED))),
                Some(52),
            )
            .unwrap();
        assert!(!all.not_all_assigned);
        assert_eq!((all.previous.len(), all.length()), (4, 52));
        let mut requests = Requests::new();
        for &entry in all.previous.as_slice() {
            requests.add(entry);
        }
        token.adjust(&Change::Set(requests), None).unwrap();
        for luid in four {
            assert_eq!(attributes_of(&token, luid), Some(0));
        }
    }

    /// The privilege check reads the enabled bit of a privilege the token holds.
    #[test]
    fn the_check_reads_the_enabled_bit() {
        let mut token = token();
        assert!(token.enabled(SE_CHANGE_NOTIFY_PRIVILEGE));
        assert!(!token.enabled(SE_LOAD_DRIVER_PRIVILEGE));
        assert!(!token.enabled(TCB));
        token
            .adjust(
                &set(&[(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED)]),
                None,
            )
            .unwrap();
        assert!(token.enabled(SE_LOAD_DRIVER_PRIVILEGE));
    }

    /// Enabling reports the old state, 16 bytes; enabling again changes nothing and reports an
    /// empty PreviousState of 4 bytes; disabling reports the enabled state.
    #[test]
    fn previous_state_reports_only_what_changed() {
        let mut token = token();
        let enable = set(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]);
        let first = token.adjust(&enable, Some(256)).unwrap();
        assert_eq!(
            first.previous.as_slice(),
            [privilege(SE_SHUTDOWN_PRIVILEGE, 0)]
        );
        assert_eq!(first.length(), 16);
        assert!(!first.not_all_assigned);
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(2));
        let again = token.adjust(&enable, Some(256)).unwrap();
        assert!(again.previous.is_empty());
        assert_eq!(again.length(), 4);
        let disable = token
            .adjust(&set(&[(SE_SHUTDOWN_PRIVILEGE, 0)]), None)
            .unwrap();
        assert_eq!(
            disable.previous.as_slice(),
            [privilege(SE_SHUTDOWN_PRIVILEGE, 2)]
        );
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(0));
    }

    /// A PreviousState too short for the report changes nothing, and asks for the report's size,
    /// however short (the count alone, or nothing).
    #[test]
    fn a_short_previous_state_changes_nothing() {
        let mut token = token();
        let enable = set(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]);
        assert_eq!(token.adjust(&enable, Some(4)), Err(16));
        assert_eq!(token.adjust(&enable, Some(0)), Err(16));
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(0));
        // A change that reports nothing still reports its count.
        let disable = set(&[(SE_SHUTDOWN_PRIVILEGE, 0)]);
        assert_eq!(token.adjust(&disable, Some(0)), Err(4));
        assert_eq!(token.adjust(&disable, Some(4)).unwrap().length(), 4);
    }

    /// DisableAllPrivileges disables what is enabled, reporting it (SeChangeNotifyPrivilege and
    /// SeUndockPrivilege as 0x3, left 0x1); its report given back as NewState restores them.
    #[test]
    fn disable_all_and_its_restore() {
        let mut token = token();
        let all = token.adjust(&Change::DisableAll, Some(4096)).unwrap();
        assert_eq!(
            all.previous.as_slice(),
            [
                privilege(SE_CHANGE_NOTIFY_PRIVILEGE, 3),
                privilege(SE_UNDOCK_PRIVILEGE, 3)
            ]
        );
        assert_eq!(attributes_of(&token, SE_CHANGE_NOTIFY_PRIVILEGE), Some(1));
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(0));
        let mut requests = Requests::new();
        for &entry in all.previous.as_slice() {
            requests.add(entry);
        }
        let restore = token.adjust(&Change::Set(requests), None).unwrap();
        assert!(!restore.not_all_assigned);
        assert_eq!(attributes_of(&token, SE_CHANGE_NOTIFY_PRIVILEGE), Some(3));
    }

    /// A privilege the token does not hold (SeTcbPrivilege, or a LUID no privilege has) is not
    /// assigned: the others in the same NewState change all the same.
    #[test]
    fn an_unheld_privilege_is_a_partial_assignment() {
        let mut token = token();
        let tcb = token
            .adjust(&set(&[(TCB, SE_PRIVILEGE_ENABLED)]), Some(256))
            .unwrap();
        assert!(tcb.not_all_assigned);
        assert!(tcb.previous.is_empty());
        let none = token
            .adjust(&set(&[(0x10000, SE_PRIVILEGE_ENABLED)]), Some(256))
            .unwrap();
        assert!(none.not_all_assigned);
        let mixed = token
            .adjust(
                &set(&[
                    (TCB, SE_PRIVILEGE_ENABLED),
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
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(2));
        assert_eq!(attributes_of(&token, TCB), None);
    }

    fn word(reply: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(reply[at..at + 4].try_into().unwrap())
    }

    const BASE: u32 = 0x0040_1000;

    fn answer(token: &TokenBody, class: Class) -> Reply {
        token.information(class, BASE).unwrap()
    }

    /// TokenUser, TokenOwner and TokenPrimaryGroup: the header, its pointer to the SID right after
    /// it, the SID: the user an account (S-1-5-21-a-b-c-1000), the owner BUILTIN\Administrators,
    /// the primary group the account domain's 513.
    #[test]
    fn the_sids_follow_their_headers() {
        let token = token();
        let user = answer(&token, Class::User);
        assert_eq!(
            (user.len(), word(&user, 0), word(&user, 4)),
            (36, BASE + 8, 0)
        );
        assert!(USER.matches(&user[8..]));
        assert_eq!(&user[8..16], [1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(word(&user, 32), 1000);
        let owner = answer(&token, Class::Owner);
        assert_eq!((owner.len(), word(&owner, 0)), (20, BASE + 4));
        assert_eq!(
            &owner[4..],
            [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]
        );
        let group = answer(&token, Class::PrimaryGroup);
        assert_eq!(group.len(), 32);
        assert!(PRIMARY_GROUP.matches(&group[4..]));
        assert_eq!(&group[12..28], &user[16..32], "the user's domain");
    }

    /// TokenGroups: the count, the entries pointing at the SIDs packed after them, the attributes
    /// an administrator's logon gives (BUILTIN\Administrators its owner, the logon SID marked).
    #[test]
    fn the_groups_are_an_administrators() {
        let groups = answer(&token(), Class::Groups);
        assert_eq!(word(&groups, 0), 8);
        let mut size = 4 + 8 * 8;
        for (index, (sid, attributes)) in GROUPS.iter().enumerate() {
            let at = word(&groups, 4 + 8 * index) - BASE;
            assert_eq!(at as usize, size);
            assert!(sid.matches(&groups[size..]));
            assert_eq!(word(&groups, 8 + 8 * index), *attributes);
            size += sid.size();
        }
        assert_eq!(groups.len(), size);
        assert_eq!(size, 196);
        let admins = GROUPS
            .iter()
            .find(|(sid, _)| *sid == ADMINISTRATORS)
            .unwrap();
        assert_eq!(admins.1, 0xF);
        let logon = GROUPS.iter().find(|(sid, _)| *sid == LOGON).unwrap();
        assert_eq!(logon.1, 0xC000_0007);
    }

    /// TokenDefaultDacl: the pointer, then an ACL of revision 2 and 52 bytes holding two
    /// GENERIC_ALL ACEs, BUILTIN\Administrators' and SYSTEM's.
    #[test]
    fn the_default_dacl_grants_administrators_and_system() {
        let dacl = answer(&token(), Class::DefaultDacl);
        assert_eq!((dacl.len(), word(&dacl, 0)), (56, BASE + 4));
        assert_eq!(&dacl[4..12], [2, 0, 52, 0, 2, 0, 0, 0]);
        assert_eq!(&dacl[12..16], [0, 0, 24, 0]);
        assert_eq!(word(&dacl, 16), GENERIC_ALL);
        assert!(ADMINISTRATORS.matches(&dacl[20..]));
        assert_eq!(&dacl[36..40], [0, 0, 20, 0]);
        assert!(LOCAL_SYSTEM.matches(&dacl[44..]));
    }

    /// The fixed-size classes: TokenSource's 16 bytes, TokenType's 4, TokenStatistics' 56 (its
    /// counts the groups' and the privileges', the dynamic part 500), TokenRestrictedSids' empty
    /// count; TokenImpersonationLevel of a primary token is refused.
    #[test]
    fn the_fixed_classes() {
        let token = token();
        let source = answer(&token, Class::Source);
        assert_eq!((&source[..8], source.len()), (&b"User32  "[..], 16));
        assert_ne!(word(&source, 8), 0);
        assert_eq!(answer(&token, Class::Type).as_slice(), 1u32.to_le_bytes());
        assert_eq!(
            token.information(Class::ImpersonationLevel, BASE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(answer(&token, Class::RestrictedSids).as_slice(), [0; 4]);
        let statistics = answer(&token, Class::Statistics);
        assert_eq!(statistics.len(), 56);
        assert_ne!(word(&statistics, 0), 0);
        assert_eq!(word(&statistics, 8), LOGON_ID);
        assert_ne!(word(&statistics, 0), LOGON_ID);
        assert_eq!(
            (word(&statistics, 16), word(&statistics, 20)),
            (u32::MAX, 0x7FFF_FFFF)
        );
        assert_eq!((word(&statistics, 24), word(&statistics, 28)), (1, 0));
        assert_eq!(word(&statistics, 32), 500);
        assert!(word(&statistics, 36) <= 500);
        assert_eq!(
            (word(&statistics, 40), word(&statistics, 44)),
            (8, HELD as u32)
        );
    }

    /// A change of the privileges gives the token a new ModifiedId, its TokenId kept; a duplicate
    /// is an impersonation token at its level, of a new TokenId, of the same logon.
    #[test]
    fn modified_ids_and_duplicates() {
        let mut token = token();
        let before = answer(&token, Class::Statistics);
        token
            .adjust(&set(&[(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]), None)
            .unwrap();
        let after = answer(&token, Class::Statistics);
        assert_eq!(word(&before, 0), word(&after, 0));
        assert_ne!(word(&before, 48), word(&after, 48));
        let copy = token.duplicate(TOKEN_IMPERSONATION, 2);
        assert_eq!(answer(&copy, Class::Type).as_slice(), 2u32.to_le_bytes());
        assert_eq!(
            answer(&copy, Class::ImpersonationLevel).as_slice(),
            2u32.to_le_bytes()
        );
        let statistics = answer(&copy, Class::Statistics);
        assert_ne!(word(&statistics, 0), word(&after, 0));
        assert_eq!(word(&statistics, 8), LOGON_ID);
        assert_eq!((word(&statistics, 24), word(&statistics, 28)), (2, 2));
        assert_eq!(copy.owner, None);
        assert_eq!(copy.privileges(), token.privileges());
    }

    /// Only SE_PRIVILEGE_ENABLED of NewState's attributes counts; enabled by default stays as the
    /// token was made.
    #[test]
    fn only_the_enabled_bit_is_read() {
        let mut token = token();
        token
            .adjust(&set(&[(SE_SHUTDOWN_PRIVILEGE, 0x8000_0001)]), None)
            .unwrap();
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(0));
        token
            .adjust(&set(&[(SE_CHANGE_NOTIFY_PRIVILEGE, 0)]), None)
            .unwrap();
        assert_eq!(attributes_of(&token, SE_CHANGE_NOTIFY_PRIVILEGE), Some(1));
    }
}
