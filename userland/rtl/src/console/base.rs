//! The base server's API F2K serves beside the console server's, over the same message
//! ([`CsrApiMsg`](super::CsrApiMsg)): BasepCreateProcess, kernel32's CreateProcess announcing the
//! new process, as Windows 2000's kernel32 announces it to the base server (basesrv, inside csrss)
//! before it resumes the process's first thread. Windows 2000's server records the process there,
//! its process group among the rest: the creator's group, or one the process leads
//! (CREATE_NEW_PROCESS_GROUP). F2K's kernel tracks its processes itself; the announcement carries
//! what only the creator knows, its creation flags.
//!
//! The number is made as Windows 2000's is, the base server's index (1) in the high word,
//! BasepCreateProcess's (0) in the low one; the message's layout is F2K's own, as the console's
//! are.

use super::api::Word;
use crate::pod::Pod;

/// The base server's index in an API number's high word (Windows 2000's
/// BASESRV_SERVERDLL_INDEX).
pub const BASE_SERVER: u32 = 1;

/// BasepCreateProcess's API number.
pub const CREATE_PROCESS: u32 = BASE_SERVER << 16;

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

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<CreateProcess<u32>>() == 20);
    assert!(size_of::<CreateProcess<u32>>() <= 4 * super::DATA_WORDS);
};
