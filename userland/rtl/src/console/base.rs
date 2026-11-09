//! The base server's APIs F2K serves beside the console server's, over the same message
//! ([`CsrApiMsg`](super::CsrApiMsg)), as Windows 2000's kernel32 sends them to the base server
//! (basesrv, inside csrss):
//! - BasepCreateProcess, kernel32's CreateProcess announcing the new process before it resumes the
//!   process's first thread. Windows 2000's server records the process there, its process group
//!   among the rest: the creator's group, or one the process leads (CREATE_NEW_PROCESS_GROUP).
//!   F2K's kernel tracks its processes itself; the announcement carries what only the creator
//!   knows, its creation flags.
//! - BasepSetProcessShutdownParam and BasepGetProcessShutdownParam, kernel32's
//!   SetProcessShutdownParameters and GetProcessShutdownParameters: the calling process's shutdown
//!   level and flags, which the server keeps for it, and by which the session's end orders its
//!   processes (the highest level first). Every process starts at [`DEFAULT_SHUTDOWN_LEVEL`] with
//!   no flag: a child inherits nothing.
//!
//! The numbers are made as Windows 2000's are, the base server's index (1) in the high word, the
//! API's index in Windows 2000's base server table in the low one (BasepCreateProcess 0,
//! BasepSetProcessShutdownParam 12, BasepGetProcessShutdownParam 13, as the public listings of
//! csrss's API tables give them); the messages' layouts are F2K's own, as the console's are.

use super::api::Word;
use crate::pod::Pod;

/// The base server's index in an API number's high word (Windows 2000's
/// BASESRV_SERVERDLL_INDEX).
pub const BASE_SERVER: u32 = 1;

/// BasepCreateProcess's API number.
pub const CREATE_PROCESS: u32 = BASE_SERVER << 16;

/// BasepSetProcessShutdownParam's API number.
pub const SET_PROCESS_SHUTDOWN_PARAM: u32 = BASE_SERVER << 16 | 12;

/// BasepGetProcessShutdownParam's API number.
pub const GET_PROCESS_SHUTDOWN_PARAM: u32 = BASE_SERVER << 16 | 13;

/// The shutdown level every process starts at: the middle of the applications' "in between"
/// range (0x200-0x2FF).
pub const DEFAULT_SHUTDOWN_LEVEL: u32 = 0x280;

/// SetProcessShutdownParameters' one flag: no retry dialog for the process when it outlasts the
/// session's wait; it is ended then.
pub const SHUTDOWN_NORETRY: u32 = 0x1;

/// CreateProcess's flag that makes the new process the leader of a process group of its own.
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// BasepCreateProcess: the new process (a handle to it in the creator, and its client id), its
/// first thread's, and the creation flags CreateProcess was called with.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateProcess<W> {
    pub process: W,
    pub thread: W,
    pub process_id: W,
    pub thread_id: W,
    pub creation_flags: W,
}

// SAFETY: a `#[repr(C)]` structure of words, laid out back to back with no padding; every word is
// plain data.
unsafe impl<W: Word> Pod for CreateProcess<W> {}

/// BasepSetProcessShutdownParam's request and BasepGetProcessShutdownParam's answer: the level and
/// the flags.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShutdownParameters<W> {
    pub level: W,
    pub flags: W,
}

// SAFETY: a `#[repr(C)]` structure of words, laid out back to back with no padding; every word is
// plain data.
unsafe impl<W: Word> Pod for ShutdownParameters<W> {}

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<CreateProcess<u32>>() == 20);
    assert!(size_of::<CreateProcess<u32>>() <= 4 * super::DATA_WORDS);
    assert!(size_of::<ShutdownParameters<u32>>() == 8);
};

/// Whether the server keeps SetProcessShutdownParameters' arguments: only when the flags hold
/// nothing but SHUTDOWN_NORETRY. Any level is kept, the documentation's ranges notwithstanding
/// (0x000-0x0FF the system's, 0x100-0x3FF the applications', none above): Windows 2000 keeps
/// 0x000, 0x0FF, 0x400 and 0xFFFFFFFF alike and orders the session's end by them. A flag bit
/// other than SHUTDOWN_NORETRY leaves the parameters as they were, the call answered as a success
/// all the same (TRUE, the last error untouched): the shutparm fixture's capture shows both.
pub fn shutdown_parameters_kept(flags: u32) -> bool {
    flags & !SHUTDOWN_NORETRY == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No flag or SHUTDOWN_NORETRY is kept; any other flag bit, alone or beside it, is not. The
    /// numbers are Windows 2000's.
    #[test]
    fn shutdown_parameters_keep_only_noretry() {
        assert!(shutdown_parameters_kept(0));
        assert!(shutdown_parameters_kept(SHUTDOWN_NORETRY));
        for flags in [0x2, 0x3, 0x4, 0x8000_0000, 0xFFFF_FFFF] {
            assert!(!shutdown_parameters_kept(flags), "{flags:#x}");
        }
        assert_eq!(SET_PROCESS_SHUTDOWN_PARAM, 0x1_000C);
        assert_eq!(GET_PROCESS_SHUTDOWN_PARAM, 0x1_000D);
    }
}
