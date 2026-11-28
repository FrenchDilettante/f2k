//! The processors the boot started: how many (KeNumberProcessors) and which (KeActiveProcessors,
//! the KAFFINITY KeQueryActiveProcessors answers). The one source every processor-count answer
//! reads: SYSTEM_BASIC_INFORMATION's NumberOfProcessors and ActiveProcessorsAffinityMask, the
//! process's and thread's affinity, the HAL's interrupt routing affinity, and a new process's
//! PEB NumberOfProcessors.
//!
//! As on Windows 2000, each processor counts itself as it starts ([`start`], KiInitializeKernel's
//! part): its bit joins the active set and the count covers its number. The boot processor,
//! processor 0, is running before anything can ask, so both values begin with it; the processors
//! the boot starts after it (none yet: F2K boots one) each call [`start`] in turn.
//!
//! KeNumberProcessors is a variable ntoskrnl.exe exports, a CCHAR drivers read in place
//! (`kernel/exports.toml`); KeQueryActiveProcessors is the routine that answers the set.

use core::sync::atomic::{AtomicI8, AtomicU32, Ordering};

/// The boot processor's set: processor 0 alone.
const BOOT_PROCESSOR: u32 = 1;

/// KeNumberProcessors, the variable drivers import: how many processors the boot started.
#[cfg_attr(target_arch = "x86", no_mangle)]
#[allow(non_upper_case_globals)]
pub static f2k_export_KeNumberProcessors: AtomicI8 = AtomicI8::new(1);

/// KeActiveProcessors: the started processors' set, one bit per processor number.
static ACTIVE: AtomicU32 = AtomicU32::new(BOOT_PROCESSOR);

/// Count processor `number` as started: its bit in the active set, and the count raised to cover
/// it. Each processor calls it once, on itself, as it starts; for the boot processor it records
/// what the initial values already say.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub fn start(number: u8) {
    debug_assert!(number < 32, "a KAFFINITY holds 32 processors");
    ACTIVE.fetch_or(1 << number, Ordering::Release);
    f2k_export_KeNumberProcessors.fetch_max(number as i8 + 1, Ordering::Release);
}

/// How many processors the boot started (KeNumberProcessors).
pub fn count() -> u32 {
    f2k_export_KeNumberProcessors.load(Ordering::Acquire) as u32
}

/// The started processors' set (KeActiveProcessors): what a thread's or process's affinity may
/// name, and every routed interrupt line's affinity.
pub fn active() -> u32 {
    ACTIVE.load(Ordering::Acquire)
}

/// KeQueryActiveProcessors: the started processors' set, a KAFFINITY.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub extern "stdcall" fn f2k_export_KeQueryActiveProcessors() -> u32 {
    active()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boot processor is counted from the start, and starting it again changes nothing: the
    /// count is the active set's population.
    #[test]
    fn the_boot_processor_is_the_started_set() {
        start(0);
        assert_eq!((count(), active()), (1, BOOT_PROCESSOR));
        assert_eq!(active().count_ones(), count());
    }
}
