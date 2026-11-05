//! Ending the session: ExitWindowsEx.
//!
//! Windows 2000's user32 sends the request to csrss's user server through CsrClientCallServer and
//! returns once it is taken: the session ends after the call, its processes asked to end in turn,
//! then the machine shut down for every action but EWX_LOGOFF. F2K's user32 sends it the same way,
//! to the kernel's stand-in for csrss, which does that work on its own thread (the kernel's
//! `session` module); the flags' rules are `rtl::console::user`'s, shared with the server.

use rtl::console::user::{check_flags, ExitWindowsEx, EXIT_WINDOWS_EX};
use rtl::pod::Pod;
use rtl::status::{nt_success, NtStatus};

use crate::imports;

/// ExitWindowsEx: the session's end asked for, with the action and how its processes end that
/// `flags` give (`dwReserved` is ignored, as Windows 2000 ignores it); TRUE once the server has
/// taken the request, before the session ends. A flag Windows 2000 does not know (0x20, 0x40...)
/// is ERROR_ACCESS_DENIED, refused before anything else, as its exitwin capture shows.
///
/// Windows 2000 then refuses every action but EWX_LOGOFF with ERROR_PRIVILEGE_NOT_HELD unless the
/// caller's token holds SeShutdownPrivilege enabled; F2K checks no privilege (a known deviation,
/// while it has no security), so a request the capture shows refused is taken here.
#[unsafe(export_name = "f2k_export_ExitWindowsEx")]
pub extern "system" fn exit_windows_ex(flags: u32, reserved: u32) -> u32 {
    if let Err(status) = check_flags(flags) {
        imports::set_last_error(imports::dos_error(NtStatus(status)));
        return 0;
    }
    let mut request = ExitWindowsEx::<u32> { flags, reserved };
    let status = imports::call_server(EXIT_WINDOWS_EX, request.as_bytes_mut());
    if !nt_success(status) {
        imports::set_last_error(imports::dos_error(NtStatus(status)));
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use rtl::console::user::{
        EWX_FORCE,
        EWX_FORCEIFHUNG,
        EWX_LOGOFF,
        EWX_POWEROFF,
        EWX_REBOOT,
        EWX_SHUTDOWN,
    };

    use super::*;
    use crate::imports::host::{LAST_ERROR, SERVER_ANSWER, SERVER_CALLS};

    const UNTOUCHED: u32 = 0x0F2F_2F2F;

    /// One ExitWindowsEx call: its answer, the last error, and the requests the server got.
    fn call(flags: u32, reserved: u32) -> (u32, u32, std::vec::Vec<(u32, std::vec::Vec<u32>)>) {
        LAST_ERROR.with(|error| error.set(UNTOUCHED));
        SERVER_CALLS.with(|calls| calls.borrow_mut().clear());
        let answer = exit_windows_ex(flags, reserved);
        (
            answer,
            LAST_ERROR.with(|error| error.get()),
            SERVER_CALLS.with(|calls| calls.borrow().clone()),
        )
    }

    /// The exitwin capture's flags: every action, with EWX_FORCE and EWX_FORCEIFHUNG, several
    /// action bits, a nonzero dwReserved reach Windows 2000's privilege check, so F2K, which checks
    /// none, sends them on and answers TRUE; 0x20 and 0x40 are ERROR_ACCESS_DENIED, nothing sent.
    #[test]
    fn the_capture_s_flags() {
        for action in [EWX_LOGOFF, EWX_SHUTDOWN, EWX_REBOOT, EWX_POWEROFF] {
            for how in [0, EWX_FORCE, EWX_FORCEIFHUNG, EWX_FORCE | EWX_FORCEIFHUNG] {
                let flags = action | how;
                assert_eq!(
                    call(flags, 0),
                    (
                        1,
                        UNTOUCHED,
                        std::vec![(EXIT_WINDOWS_EX, std::vec![flags, 0])]
                    ),
                    "{flags:#x}"
                );
            }
        }
        for several in [
            EWX_SHUTDOWN | EWX_REBOOT,
            EWX_SHUTDOWN | EWX_POWEROFF,
            EWX_REBOOT | EWX_POWEROFF,
            EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF,
        ] {
            assert_eq!(call(several, 0).0, 1);
        }
        assert_eq!(
            call(EWX_SHUTDOWN, 1),
            (
                1,
                UNTOUCHED,
                std::vec![(EXIT_WINDOWS_EX, std::vec![EWX_SHUTDOWN, 1])]
            )
        );
        for refused in [EWX_SHUTDOWN | 0x20, EWX_SHUTDOWN | 0x40, EWX_REBOOT | 0x20] {
            assert_eq!(call(refused, 0), (0, 5, std::vec![]), "{refused:#x}");
        }
    }

    /// The server's refusal is the caller's: FALSE with its status's error.
    #[test]
    fn a_refused_request_fails() {
        SERVER_ANSWER.with(|answer| answer.set(rtl::status::STATUS_ACCESS_DENIED));
        let (answer, error, _) = call(EWX_SHUTDOWN, 0);
        SERVER_ANSWER.with(|answer| answer.set(0));
        assert_eq!((answer, error), (0, 5));
    }
}
