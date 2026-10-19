//! The process's end: TerminateProcess over NtTerminateProcess (the host's stand-in records the
//! calls; only the current process is reachable); the TLS indexes over the stand-in PEB's bitmaps.

use crate::base::last_error;
use crate::nt::threads::process;
use crate::nt::{TERMINATED, ZEROED_TLS};
use crate::process::terminate_process;
use crate::thread::{tls_alloc, tls_free};

const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const BOGUS: u32 = 0x1234;
/// The sentinel the fixtures arm the last error with ("-" when it survives).
const UNTOUCHED: u32 = 0xF2F2_F2F2;

fn arm() {
    crate::base::set_last_error(UNTOUCHED);
}

/// TerminateProcess reaches the calling process alone (the current process ends with the code);
/// any other handle is ERROR_INVALID_HANDLE, the null one refused before the kernel is
/// asked.
#[test]
fn terminations_reach_what_their_handles_name() {
    TERMINATED.with(|terminated| terminated.borrow_mut().clear());
    assert_eq!((terminate_process(BOGUS, 3), last_error()), (0, 6));
    assert_eq!((terminate_process(0, 3), last_error()), (0, 6));
    assert_eq!(terminate_process(CURRENT_PROCESS, 3), 1);
    let calls = TERMINATED.with(|terminated| terminated.borrow().clone());
    assert_eq!(calls, [(BOGUS, 3), (CURRENT_PROCESS, 3)]);
}

/// The TLS indexes: the lowest free first, the caller's slot cleared; all 1088, then
/// TLS_OUT_OF_INDEXES with ERROR_NOT_ENOUGH_MEMORY; a free clears the index's slot in every thread
/// (ThreadZeroTlsCell) and gives it back; an index not allocated is ERROR_INVALID_PARAMETER. Each
/// call holds the PEB lock, and releases it.
#[test]
fn tls_indexes_allocate_and_free() {
    let teb = process().teb;
    crate::base::write(teb + 0xE10, 0x1111);
    arm();
    assert_eq!(tls_alloc(), 0);
    assert_eq!(
        (crate::base::read(teb + 0xE10), last_error()),
        (0, UNTOUCHED),
        "the caller's slot cleared"
    );
    for expected in 1..1088 {
        assert_eq!(tls_alloc(), expected);
    }
    assert_eq!((tls_alloc(), last_error()), (0xFFFF_FFFF, 8));
    crate::base::write(teb + 0xE10 + 4 * 5, 0x5555);
    arm();
    assert_eq!(tls_free(5), 1);
    assert_eq!(last_error(), UNTOUCHED);
    assert_eq!(ZEROED_TLS.with(|zeroed| zeroed.borrow().clone()), [5]);
    assert_eq!((tls_free(5), last_error()), (0, 87), "a double free");
    assert_eq!(tls_free(70), 1);
    for unallocated in [1088, 5000, u32::MAX] {
        assert_eq!((tls_free(unallocated), last_error()), (0, 87), "{unallocated}");
    }
    assert_eq!((tls_alloc(), tls_alloc(), tls_alloc()), (5, 70, 0xFFFF_FFFF));
    let depth = crate::nt::PEB_LOCK_DEPTH.with(|depth| depth.get());
    assert_eq!(depth, 0, "the PEB lock released");
}
