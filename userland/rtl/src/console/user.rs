//! The user server's API F2K serves beside the console's, over the same message
//! ([`CsrApiMsg`](super::CsrApiMsg)): UserpExitWindowsEx, user32's ExitWindowsEx asking for the
//! session's end, as Windows 2000's user32 asks csrss's user server (winsrv) for it. The server
//! takes the request and answers at once; the session ends after the call has returned, its
//! processes asked to end in turn (CTRL_LOGOFF_EVENT or CTRL_SHUTDOWN_EVENT to a console
//! program), then the machine shut down for every action but EWX_LOGOFF.
//!
//! The number is made as Windows 2000's are, the user server's index (3) in the high word; the
//! API's index in the low one (0) and the message's layout are F2K's own, as the console's are.
//!
//! The flags' rules are here, shared by user32, which checks them before it asks, and the server,
//! which checks them again (Windows 2000's exitwin capture):
//! - the action is the low bits: EWX_LOGOFF (0), EWX_SHUTDOWN, EWX_REBOOT, EWX_POWEROFF, with
//!   EWX_FORCE and EWX_FORCEIFHUNG beside them;
//! - a bit no Windows 2000 flag names (EWX_QUICKRESOLVE's 0x20 and EWX_RESTARTAPPS' 0x40, which
//!   later systems define, among them) is refused with STATUS_ACCESS_DENIED, ahead of everything
//!   else;
//! - several action bits at once reach the privilege check on Windows 2000, so they are accepted,
//!   one action taken ([`action`]).
//!
//! Windows 2000 then requires SeShutdownPrivilege enabled in the caller's token for every action
//! but EWX_LOGOFF (ERROR_PRIVILEGE_NOT_HELD otherwise). F2K checks no privilege: a known
//! deviation, flagged where the check would be.

use super::api::Word;
use crate::nt::ShutdownAction;
use crate::pod::Pod;
use crate::status::STATUS_ACCESS_DENIED;

/// The user server's index in an API number's high word (Windows 2000's USERSRV_SERVERDLL_INDEX).
pub const USER_SERVER: u32 = 3;

/// UserpExitWindowsEx's API number: the user server's first API.
pub const EXIT_WINDOWS_EX: u32 = USER_SERVER << 16;

/// ExitWindowsEx's flags: the actions (EWX_LOGOFF is none of the action bits), and the two that
/// say how the session's processes are ended.
pub const EWX_LOGOFF: u32 = 0x00;
pub const EWX_SHUTDOWN: u32 = 0x01;
pub const EWX_REBOOT: u32 = 0x02;
pub const EWX_FORCE: u32 = 0x04;
pub const EWX_POWEROFF: u32 = 0x08;
pub const EWX_FORCEIFHUNG: u32 = 0x10;

/// Every flag Windows 2000's ExitWindowsEx knows.
const KNOWN_FLAGS: u32 = EWX_SHUTDOWN | EWX_REBOOT | EWX_FORCE | EWX_POWEROFF | EWX_FORCEIFHUNG;

/// ExitWindowsEx's flags checked as Windows 2000 checks them before its privilege check: a bit it
/// does not know is STATUS_ACCESS_DENIED (ERROR_ACCESS_DENIED to the caller), whatever else the
/// flags hold. Every other combination is accepted.
pub fn check_flags(flags: u32) -> Result<(), u32> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// The machine's end the flags ask for once the session has ended, NtShutdownSystem's action: none
/// for EWX_LOGOFF. With
/// several action bits, EWX_REBOOT wins over EWX_POWEROFF, and EWX_POWEROFF over EWX_SHUTDOWN:
/// EWX_POWEROFF is documented as a shutdown that turns the power off, and a restart is the one
/// action that brings the machine back.
pub fn action(flags: u32) -> Option<ShutdownAction> {
    if flags & EWX_REBOOT != 0 {
        Some(ShutdownAction::Reboot)
    } else if flags & EWX_POWEROFF != 0 {
        Some(ShutdownAction::PowerOff)
    } else if flags & EWX_SHUTDOWN != 0 {
        Some(ShutdownAction::NoReboot)
    } else {
        None
    }
}

/// Whether the session's processes are ended without being asked first (EWX_FORCE).
pub fn forced(flags: u32) -> bool {
    flags & EWX_FORCE != 0
}

/// UserpExitWindowsEx: ExitWindowsEx's flags, and its reserved argument (which Windows 2000
/// ignores: a nonzero one reaches its privilege check).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitWindowsEx<W> {
    pub flags: W,
    pub reserved: W,
}

// SAFETY: a `#[repr(C)]` structure of words, laid out back to back with no padding; every word is
// plain data.
unsafe impl<W: Word> Pod for ExitWindowsEx<W> {}

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<ExitWindowsEx<u32>>() == 8);
    assert!(size_of::<ExitWindowsEx<u32>>() <= 4 * super::DATA_WORDS);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's flags: every action alone and with EWX_FORCE and EWX_FORCEIFHUNG, and
    /// several action bits at once, reach the privilege check on Windows 2000 (accepted here); an
    /// action with 0x20 or 0x40 is ERROR_ACCESS_DENIED, and so is any bit no flag names.
    #[test]
    fn the_flags_are_checked_as_the_capture_shows() {
        for action in [EWX_LOGOFF, EWX_SHUTDOWN, EWX_REBOOT, EWX_POWEROFF] {
            for how in [0, EWX_FORCE, EWX_FORCEIFHUNG, EWX_FORCE | EWX_FORCEIFHUNG] {
                assert_eq!(check_flags(action | how), Ok(()), "{:#x}", action | how);
            }
        }
        for several in [
            EWX_SHUTDOWN | EWX_REBOOT,
            EWX_SHUTDOWN | EWX_POWEROFF,
            EWX_REBOOT | EWX_POWEROFF,
            EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF,
        ] {
            assert_eq!(check_flags(several), Ok(()));
        }
        for refused in [
            EWX_SHUTDOWN | 0x20,
            EWX_SHUTDOWN | 0x40,
            EWX_REBOOT | 0x20,
            EWX_LOGOFF | 0x40,
            0x80,
            0x8000_0000,
        ] {
            assert_eq!(
                check_flags(refused),
                Err(STATUS_ACCESS_DENIED),
                "{refused:#x}"
            );
        }
    }

    /// Each action's SHUTDOWN_ACTION, EWX_LOGOFF none: EWX_SHUTDOWN halts (Windows 2000 stops at
    /// "safe to turn off" even where it could power off), EWX_POWEROFF powers off, EWX_REBOOT
    /// restarts; with several bits a restart wins, then a power-off. EWX_FORCE and EWX_FORCEIFHUNG
    /// change how the processes end, not the action.
    #[test]
    fn each_action_maps_to_its_shutdown_action() {
        assert_eq!(action(EWX_LOGOFF), None);
        assert_eq!(action(EWX_LOGOFF | EWX_FORCE), None);
        assert_eq!(action(EWX_SHUTDOWN), Some(ShutdownAction::NoReboot));
        assert_eq!(action(EWX_REBOOT), Some(ShutdownAction::Reboot));
        assert_eq!(action(EWX_POWEROFF), Some(ShutdownAction::PowerOff));
        assert_eq!(
            action(EWX_SHUTDOWN | EWX_FORCE | EWX_FORCEIFHUNG),
            Some(ShutdownAction::NoReboot)
        );
        assert_eq!(
            action(EWX_SHUTDOWN | EWX_POWEROFF),
            Some(ShutdownAction::PowerOff)
        );
        assert_eq!(
            action(EWX_SHUTDOWN | EWX_REBOOT),
            Some(ShutdownAction::Reboot)
        );
        assert_eq!(
            action(EWX_REBOOT | EWX_POWEROFF),
            Some(ShutdownAction::Reboot)
        );
        assert_eq!(ShutdownAction::PowerOff as u32, 2);
        assert!(forced(EWX_SHUTDOWN | EWX_FORCE));
        assert!(!forced(EWX_SHUTDOWN | EWX_FORCEIFHUNG));
    }
}
