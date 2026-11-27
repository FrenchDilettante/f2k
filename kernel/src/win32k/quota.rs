//! The per-process quotas on the window manager's objects: how many USER objects (windows, menus,
//! accelerator tables, cursors and icons) one process may hold at once, as Windows 2000's
//! USERProcessHandleQuota sets, and the GDI objects' counterpart, GDIProcessHandleQuota.
//!
//! Windows 2000's win32k reads both at its start from
//! `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows` (REG_DWORD values), 10,000 each by
//! default; a create past the USER quota fails with ERROR_NO_MORE_USER_HANDLES (1158), as one past
//! the handle table's own ceiling does (`manywin`'s `quota`: 10,000 menus, then NULL with 1158).
//! The GDI quota is slot-pool slice 13's.
//!
//! F2K reads the USER value from the same key of its registry the first time a process's object is
//! counted ([`user_process_handle_quota`]), and keeps it: as on Windows 2000, a change takes effect
//! at the next start. F2K's registry holds no `Software` key yet, so the default applies until a
//! program writes the value. A value out of range is taken to the nearest bound
//! ([`USER_QUOTA_MIN`], [`USER_QUOTA_MAX`]), as win32k bounds it.
//!
//! The counts themselves are the per-process records' ([`super::process`]); the handle table
//! ([`super::handle::UserHandles`]) checks and moves them at each insert and close.

use core::sync::atomic::{AtomicU32, Ordering};

/// USERProcessHandleQuota's default: Windows 2000's 10,000 USER objects per process.
pub const USER_PROCESS_HANDLE_QUOTA: u32 = 10_000;

/// The least USERProcessHandleQuota win32k takes: a smaller value is raised to it (from memory,
/// the documented range's floor; to confirm in *Inside Windows 2000*).
pub const USER_QUOTA_MIN: u32 = 200;

/// The most USERProcessHandleQuota win32k takes: a larger value is lowered to it (from memory, the
/// documented range's ceiling; to confirm in *Inside Windows 2000*).
pub const USER_QUOTA_MAX: u32 = 18_000;

/// The key Windows 2000's win32k reads its quotas from, below `\Registry`.
pub const QUOTA_KEY: &str = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

/// The USER quota's value name under [`QUOTA_KEY`].
pub const USER_QUOTA_VALUE: &str = "USERProcessHandleQuota";

/// The quota in force once read; 0 until the first read.
static USER_QUOTA: AtomicU32 = AtomicU32::new(0);

/// The quota a registry value gives: the default without one, else the value within its bounds.
pub fn user_quota_from(value: Option<u32>) -> u32 {
    value.map_or(USER_PROCESS_HANDLE_QUOTA, |value| {
        value.clamp(USER_QUOTA_MIN, USER_QUOTA_MAX)
    })
}

/// How many USER objects one process may hold: the registry's USERProcessHandleQuota, read once,
/// or the default.
pub fn user_process_handle_quota() -> u32 {
    match USER_QUOTA.load(Ordering::Relaxed) {
        0 => {
            let quota = user_quota_from(read_user_quota());
            // Two first readers read the same value: either store is the other's.
            USER_QUOTA.store(quota, Ordering::Relaxed);
            quota
        }
        quota => quota,
    }
}

/// The REG_DWORD USERProcessHandleQuota under [`QUOTA_KEY`], if the registry has it.
#[cfg(target_arch = "x86")]
fn read_user_quota() -> Option<u32> {
    crate::cm::with_registry(|registry| registry.dword(QUOTA_KEY, USER_QUOTA_VALUE))
}

/// The host tests' registry has no value: the default applies.
#[cfg(not(target_arch = "x86"))]
fn read_user_quota() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No value is the default, 10,000; a value is taken within its bounds.
    #[test]
    fn the_registry_value_sets_the_quota_within_its_bounds() {
        assert_eq!(user_quota_from(None), 10_000);
        assert_eq!(user_quota_from(Some(5_000)), 5_000);
        assert_eq!(user_quota_from(Some(0)), USER_QUOTA_MIN);
        assert_eq!(user_quota_from(Some(100_000)), USER_QUOTA_MAX);
        assert_eq!(user_process_handle_quota(), USER_PROCESS_HANDLE_QUOTA);
    }
}
