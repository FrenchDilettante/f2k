//! The impersonation calls: ImpersonateSelf, RevertToSelf, SetThreadToken,
//! ImpersonateAnonymousToken, ImpersonateLoggedOnUser and ImpersonateNamedPipeClient, as a
//! program that asks to run as another principal makes them.
//!
//! F2K's threads never impersonate: the thread's token is the process's, and no thread token is
//! ever attached. So the calls answer the public contract where F2K can satisfy it —
//! ImpersonateSelf succeeds as a no-op (the thread's token is already the process token),
//! RevertToSelf answers TRUE, SetThreadToken's revert (a null token) answers TRUE, and
//! ImpersonateLoggedOnUser answers TRUE after the token's type is read (the thread already runs
//! as the logged-on user). The forms that would attach a token to a thread or a pipe's client —
//! SetThreadToken with a token, ImpersonateAnonymousToken, ImpersonateNamedPipeClient — answer
//! FALSE with ERROR_NOT_SUPPORTED. A BOOL call's failure sets the last error and returns FALSE;
//! a success leaves the last error untouched.

use rtl::winerror::{ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};

use crate::accesscheck::services;
use crate::imports::{self as nt};
use crate::token::failed;

/// TokenType, the information class the logged-on-user call reads.
const TOKEN_TYPE_CLASS: u32 = 8;

/// The impersonation levels the public enum carries (SecurityAnonymous through
/// SecurityDelegation).
const MAX_IMPERSONATION_LEVEL: u32 = 3;

/// A BOOL call's failure: the last error set, FALSE.
fn false_with(error: u32) -> u32 {
    nt::set_last_error(error);
    0
}

/// ImpersonateSelf: the caller's thread given an impersonation token of its own process at the
/// level. F2K's threads never impersonate — the thread's token is the process's — so a valid
/// level succeeds as a no-op and the last error is untouched; a level outside the public enum
/// fails ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// The argument is the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_ImpersonateSelf")]
pub unsafe extern "system" fn impersonate_self(impersonation_level: u32) -> u32 {
    if impersonation_level > MAX_IMPERSONATION_LEVEL {
        return false_with(ERROR_INVALID_PARAMETER);
    }
    1
}

/// RevertToSelf: the thread's impersonation stopped. F2K's threads never impersonate, so there
/// is nothing to stop: TRUE, the last error untouched.
///
/// # Safety
///
/// No arguments.
#[unsafe(export_name = "f2k_export_RevertToSelf")]
pub unsafe extern "system" fn revert_to_self() -> u32 {
    1
}

/// SetThreadToken: the token assigned to the thread (the caller's when `thread` is null); a null
/// token stops the impersonation. F2K's threads never impersonate, so the revert succeeds as a
/// no-op; attaching a token is not something F2K can do, and answers FALSE with
/// ERROR_NOT_SUPPORTED. The last error is untouched on the revert.
///
/// # Safety
///
/// `thread` is null or the caller's place for a thread handle.
#[unsafe(export_name = "f2k_export_SetThreadToken")]
pub unsafe extern "system" fn set_thread_token(thread: *const u32, token: u32) -> u32 {
    let _ = thread;
    if token == 0 {
        return 1;
    }
    false_with(ERROR_NOT_SUPPORTED)
}

/// ImpersonateAnonymousToken: the thread given the system's anonymous token. F2K has no
/// anonymous token to give and never attaches one to a thread: FALSE with ERROR_NOT_SUPPORTED.
///
/// # Safety
///
/// The argument is the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_ImpersonateAnonymousToken")]
pub unsafe extern "system" fn impersonate_anonymous_token(_thread_handle: u32) -> u32 {
    false_with(ERROR_NOT_SUPPORTED)
}

/// ImpersonateLoggedOnUser: the thread given the token's user. The token's type is read first (a
/// handle the service cannot read fails with its error); F2K's threads never impersonate and the
/// process token is the logged-on user's, so the call succeeds as a no-op and the last error is
/// untouched.
///
/// # Safety
///
/// The argument is the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_ImpersonateLoggedOnUser")]
pub unsafe extern "system" fn impersonate_logged_on_user(token: u32) -> u32 {
    let mut kind = [0u8; 4];
    let answer = services::query_information_token(token, TOKEN_TYPE_CLASS, &mut kind);
    if !answer.status.is_success() {
        return failed(answer.status);
    }
    1
}

/// ImpersonateNamedPipeClient: the server thread of a named pipe given the client's token. F2K's
/// pipes carry no client to impersonate and no thread token is ever attached: FALSE with
/// ERROR_NOT_SUPPORTED.
///
/// # Safety
///
/// The argument is the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_ImpersonateNamedPipeClient")]
pub unsafe extern "system" fn impersonate_named_pipe_client(_named_pipe: u32) -> u32 {
    false_with(ERROR_NOT_SUPPORTED)
}

#[cfg(test)]
mod tests {
    use rtl::status::STATUS_INVALID_HANDLE;

    use super::*;
    use crate::accesscheck::host::TOKEN_REPLY;
    use crate::imports::host::{LAST_ERROR, TOKEN};

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// ImpersonateSelf answers TRUE for each public level with the last error untouched, and
    /// FALSE with ERROR_INVALID_PARAMETER for a level outside the enum.
    #[test]
    fn impersonate_self_answers_per_level() {
        for level in 0..=3 {
            arm();
            assert_eq!((unsafe { impersonate_self(level) }, last_error()), (1, 0xF2F2), "{level}");
        }
        arm();
        assert_eq!(
            (unsafe { impersonate_self(4) }, last_error()),
            (0, ERROR_INVALID_PARAMETER)
        );
    }

    /// RevertToSelf answers TRUE with the last error untouched.
    #[test]
    fn revert_to_self_answers_true() {
        arm();
        assert_eq!((unsafe { revert_to_self() }, last_error()), (1, 0xF2F2));
    }

    /// SetThreadToken: a null token (the revert) answers TRUE with the last error untouched,
    /// whatever the thread argument; a token answers FALSE with ERROR_NOT_SUPPORTED.
    #[test]
    fn set_thread_token_answers_per_token() {
        let mut thread = 0xFFFF_FFFEu32;
        arm();
        assert_eq!(
            (unsafe { set_thread_token(core::ptr::null(), 0) }, last_error()),
            (1, 0xF2F2)
        );
        arm();
        assert_eq!(
            (unsafe { set_thread_token(&mut thread, 0) }, last_error()),
            (1, 0xF2F2)
        );
        arm();
        assert_eq!(
            (unsafe { set_thread_token(core::ptr::null(), TOKEN) }, last_error()),
            (0, ERROR_NOT_SUPPORTED)
        );
    }

    /// ImpersonateAnonymousToken and ImpersonateNamedPipeClient answer FALSE with
    /// ERROR_NOT_SUPPORTED (F2K attaches no token to a thread or a pipe's client).
    #[test]
    fn the_attaching_forms_answer_not_supported() {
        arm();
        assert_eq!(
            (unsafe { impersonate_anonymous_token(0xFFFF_FFFE) }, last_error()),
            (0, ERROR_NOT_SUPPORTED)
        );
        arm();
        assert_eq!(
            (unsafe { impersonate_named_pipe_client(0x60) }, last_error()),
            (0, ERROR_NOT_SUPPORTED)
        );
    }

    /// ImpersonateLoggedOnUser reads the token's type through the served query: a token the
    /// service can read answers TRUE with the last error untouched, one it cannot FALSE with
    /// the status's error.
    #[test]
    fn impersonate_logged_on_user_reads_the_token_type() {
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Ok(vec![2, 0, 0, 0]));
        arm();
        assert_eq!((unsafe { impersonate_logged_on_user(TOKEN) }, last_error()), (1, 0xF2F2));
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Err(STATUS_INVALID_HANDLE));
        arm();
        assert_eq!(
            (unsafe { impersonate_logged_on_user(0x1234) }, last_error()),
            (0, 6)
        );
        TOKEN_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_000F));
    }
}
