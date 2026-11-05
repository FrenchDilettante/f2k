//! The security reference monitor's one piece F2K keeps: the token, the object OpenProcessToken
//! opens, and the privileges it lists.
//!
//! F2K has no security model: no SIDs, no groups, no access control lists, and no privilege check
//! anywhere. A token's privileges are bookkeeping only. They are kept so that the calls a program
//! makes before it shuts the machine down (OpenProcessToken, AdjustTokenPrivileges enabling
//! SeShutdownPrivilege, GetTokenInformation) answer as Windows 2000's do: the change succeeds, and
//! what it changed is reported back. Nothing in F2K ever reads them to allow or refuse anything:
//! where Windows 2000 checks a privilege (ExitWindowsEx, NtShutdownSystem), F2K does not.
//!
//! Every token holds the same two privileges, in the state Windows 2000 gives an interactive
//! user's token: SeChangeNotifyPrivilege, enabled by default, and SeShutdownPrivilege, held and
//! disabled. That is the least that answers the calls' documented behaviour: the adjustments
//! report the old state of what they changed, so the token remembers each privilege's state; and
//! a privilege it does not hold is refused (STATUS_NOT_ALL_ASSIGNED), so some are held and the
//! rest are not.
//!
//! A process has one token, made at its first open (Windows 2000 makes a process's primary token
//! with the process; F2K makes it on demand, since nothing reads it before it is opened). The
//! token names its process (see [`TokenBody::owner`]), as EPROCESS.Token names the token; the
//! process's reference on it goes at the process's end (see `crate::ob`).

use rtl::array_vec::ArrayVec;
use rtl::nt::{Luid, LuidAndAttributes};

use crate::ob::ObjectId;

/// The privileges' attributes (winnt.h's SE_PRIVILEGE_*): enabled when the token was made, and
/// enabled now. Only the second changes; an adjustment reads only that bit of what it is given.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x2;

/// The privileges' public LUIDs (winnt.h's SE_*_PRIVILEGE values) that a token holds.
pub const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
pub const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;

/// How many privileges a token holds.
pub const HELD: usize = 2;

/// TOKEN_PRIVILEGES' size for `count` entries: the count, then the entries.
pub const fn privileges_size(count: usize) -> u32 {
    (4 + count * core::mem::size_of::<LuidAndAttributes>()) as u32
}

/// A privilege of the given public LUID and attributes.
const fn privilege(luid: u32, attributes: u32) -> LuidAndAttributes {
    LuidAndAttributes {
        luid: Luid {
            low_part: luid,
            high_part: 0,
        },
        attributes,
    }
}

/// The privileges a token holds and their state when it is made, in the order Windows 2000 lists
/// them (SeChangeNotifyPrivilege first).
const DEFAULT_PRIVILEGES: [LuidAndAttributes; HELD] = [
    privilege(
        SE_CHANGE_NOTIFY_PRIVILEGE,
        SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
    ),
    privilege(SE_SHUTDOWN_PRIVILEGE, 0),
];

/// A token object's body.
#[derive(Clone, Copy, Debug)]
pub struct TokenBody {
    /// The process whose token it is, while that process holds it: cleared when the process lets
    /// go of it (its end), the token living on while handles to it are open. None in a pool's
    /// fresh record.
    pub owner: Option<ObjectId>,
    /// The privileges it holds and their state: bookkeeping only (see the module notes).
    privileges: [LuidAndAttributes; HELD],
}

impl TokenBody {
    /// A record holding no token yet (a pool's fresh record).
    pub const fn none() -> Self {
        TokenBody {
            owner: None,
            privileges: DEFAULT_PRIVILEGES,
        }
    }

    /// A new token for the process `owner`, its privileges in their default state.
    pub const fn of(owner: ObjectId) -> Self {
        TokenBody {
            owner: Some(owner),
            privileges: DEFAULT_PRIVILEGES,
        }
    }

    /// The privileges and their state, in the token's order: TokenPrivileges' answer.
    pub fn privileges(&self) -> [LuidAndAttributes; HELD] {
        self.privileges
    }

    /// Apply `change` to the privileges, as NtAdjustPrivilegesToken does: each privilege whose
    /// enabled bit changes is reported in the answer, with its attributes before the change, in
    /// the token's order. With `room` (PreviousState's buffer length, when the caller gives one),
    /// a change whose report would not fit makes no change at all: the error is the size the
    /// report takes.
    pub fn adjust(&mut self, change: &Change, room: Option<u32>) -> Result<Adjusted, u32> {
        let mut next = self.privileges;
        for (index, privilege) in next.iter_mut().enumerate() {
            let enable = match change {
                Change::DisableAll => Some(false),
                Change::Set(requests) => requests.wanted[index],
            };
            match enable {
                Some(true) => privilege.attributes |= SE_PRIVILEGE_ENABLED,
                Some(false) => privilege.attributes &= !SE_PRIVILEGE_ENABLED,
                None => {}
            }
        }
        let mut previous = ArrayVec::new();
        for (old, new) in self.privileges.iter().zip(&next) {
            if old.attributes != new.attributes {
                previous.push(*old);
            }
        }
        let adjusted = Adjusted {
            previous,
            not_all_assigned: matches!(change, Change::Set(requests) if requests.unheld),
        };
        if room.is_some_and(|room| room < adjusted.length()) {
            return Err(adjusted.length());
        }
        self.privileges = next;
        Ok(adjusted)
    }
}

/// What a NewState asks of a token, folded from its entries in their order: for each privilege
/// the token holds, whether to enable it (the last entry naming it decides), and whether an entry
/// names a privilege the token does not hold.
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
        let held = DEFAULT_PRIVILEGES
            .iter()
            .position(|privilege| privilege.luid == entry.luid);
        match held {
            Some(index) => self.wanted[index] = Some(entry.attributes & SE_PRIVILEGE_ENABLED != 0),
            None => self.unheld = true,
        }
    }
}

/// An adjustment of a token's privileges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// DisableAllPrivileges: every enabled privilege disabled.
    DisableAll,
    /// NewState's entries.
    Set(Requests),
}

/// What an adjustment did: the privileges it changed, with their attributes before it
/// (PreviousState's entries), and whether NewState named a privilege the token does not hold
/// (STATUS_NOT_ALL_ASSIGNED: the others are changed all the same).
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

    /// A new token holds SeShutdownPrivilege disabled and SeChangeNotifyPrivilege enabled by
    /// default; TOKEN_PRIVILEGES for them takes 28 bytes.
    #[test]
    fn a_new_token_holds_the_defaults() {
        let token = token();
        assert_eq!(attributes_of(&token, SE_SHUTDOWN_PRIVILEGE), Some(0));
        assert_eq!(attributes_of(&token, SE_CHANGE_NOTIFY_PRIVILEGE), Some(3));
        assert_eq!(attributes_of(&token, TCB), None);
        assert_eq!(privileges_size(HELD), 28);
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

    /// DisableAllPrivileges disables what is enabled, reporting it (SeChangeNotifyPrivilege as 0x3,
    /// left 0x1); its report given back as NewState restores it.
    #[test]
    fn disable_all_and_its_restore() {
        let mut token = token();
        let all = token.adjust(&Change::DisableAll, Some(4096)).unwrap();
        assert_eq!(
            all.previous.as_slice(),
            [privilege(SE_CHANGE_NOTIFY_PRIVILEGE, 3)]
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
