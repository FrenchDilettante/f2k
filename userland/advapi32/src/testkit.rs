//! The host tests' shared helpers: the thread's last error, armed with a marker before a call so a
//! test sees whether the call touched it, and read back after. The security byte builders (SIDs,
//! ACEs, ACLs, descriptors) are rtl's `testing::sec`, shared with the kernel's tests.

use crate::imports::host::LAST_ERROR;

/// The thread's last error.
pub fn last_error() -> u32 {
    LAST_ERROR.with(|error| error.get())
}

/// Arm the last error with 0xF2F2, a value no call sets, so a test can tell an untouched one.
pub fn arm() {
    LAST_ERROR.with(|error| error.set(0xF2F2));
}
