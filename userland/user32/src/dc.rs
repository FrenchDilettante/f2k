//! The GetDC family: GetDC, GetDCEx, GetWindowDC, ReleaseDC and WindowFromDC, over win32k's DC
//! services ([`imports`]).
//!
//! A DC is a kernel object the calling process holds a handle to; ReleaseDC closes the handle
//! (ntdll's NtClose), and the DC goes with it. user32 keeps the DCs the family handed out with
//! their windows ([`Handed`]): WindowFromDC answers from there (no service answers a DC's window:
//! the kernel's DCs are the screen's, the window a seam), and ReleaseDC releases those alone, as
//! its documentation says (a CreateDC DC goes to DeleteDC).

use core::sync::atomic::{AtomicU64, Ordering};

use rtl::status::NtStatus;

use crate::imports;
use crate::window::is_window_alive;
use crate::{answered, failed, ERROR_INVALID_WINDOW_HANDLE, ERROR_NOT_ENOUGH_MEMORY};

/// How many DCs of the family a process holds at once.
const HANDED: usize = 64;

/// The DCs the family handed out and not released yet: each slot the DC's handle in its low
/// dword and its window's in the high one, zero for a free slot. Shared by the process's
/// threads: a slot is taken and freed by one compare-and-swap.
struct Handed([AtomicU64; HANDED]);

static HANDED_DCS: Handed = Handed([const { AtomicU64::new(0) }; HANDED]);

impl Handed {
    /// Keep `dc` of `window`; false when every slot is taken.
    fn keep(&self, dc: u32, window: u32) -> bool {
        let entry = u64::from(window) << 32 | u64::from(dc);
        self.0.iter().any(|slot| {
            slot.compare_exchange(0, entry, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        })
    }

    /// The window `dc` was handed out for, when it was.
    fn window_of(&self, dc: u32) -> Option<u32> {
        self.0
            .iter()
            .map(|slot| slot.load(Ordering::Acquire))
            .find(|&entry| entry != 0 && entry as u32 == dc)
            .map(|entry| (entry >> 32) as u32)
    }

    /// Forget `dc`; false when it was not handed out.
    fn forget(&self, dc: u32) -> bool {
        self.0.iter().any(|slot| {
            let entry = slot.load(Ordering::Acquire);
            entry != 0
                && entry as u32 == dc
                && slot
                    .compare_exchange(entry, 0, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
        })
    }
}

/// The family's core: a DC of `window` (zero: the screen) from `service`, kept with its window;
/// NULL with 1400 for a handle naming no window, ERROR_NOT_ENOUGH_MEMORY when the process holds
/// as many as it may (the DC closed again).
fn handed(
    window: usize,
    service: impl FnOnce() -> Result<u32, NtStatus>,
    call: (&rtl::stub::Entry, &[u64]),
) -> usize {
    if window != 0 && !is_window_alive(window) {
        return failed(ERROR_INVALID_WINDOW_HANDLE).unwrap_or(0);
    }
    let Some(dc) = answered(service()) else {
        return 0;
    };
    if !HANDED_DCS.keep(dc, window as u32) {
        // A program that leaks its DCs meets this on every call after: one line.
        static FULL_LOGGED: rtl::stub::Logged<1> = rtl::stub::Logged::new();
        let (entry, args) = call;
        // SAFETY: the family's arguments: handles and flags, none read.
        unsafe {
            crate::stub::unhandled_once(
                &FULL_LOGGED,
                0,
                entry,
                format_args!(
                    "more than {HANDED} DCs of the GetDC family held at once by a process are \
                     not yet implemented"
                ),
                args,
            )
        };
        let _ = imports::close(dc as usize);
        return failed(ERROR_NOT_ENOUGH_MEMORY).unwrap_or(0);
    }
    dc as usize
}

/// GetDC: a DC of the window's client area (NULL: the screen's).
#[unsafe(export_name = "f2k_export_GetDC")]
pub extern "system" fn get_dc(window: usize) -> usize {
    handed(
        window,
        || imports::get_dc(window),
        (&crate::spec::GetDC, &[window as u64]),
    )
}

/// GetDCEx: a DC of the window with GetDCEx's clipping region and DCX_ flags.
#[unsafe(export_name = "f2k_export_GetDCEx")]
pub extern "system" fn get_dc_ex(window: usize, region: usize, flags: u32) -> usize {
    let args = [window as u64, region as u64, u64::from(flags)];
    for &(flag, what) in &UNCLIPPED {
        if flags & flag != 0 {
            // SAFETY: GetDCEx's arguments: handles and flags, none read.
            unsafe {
                crate::stub::unhandled_once(
                    &CLIPPING_LOGGED,
                    flag,
                    &crate::spec::GetDCEx,
                    format_args!("{what} is not yet implemented: the DC is not clipped by it"),
                    &args,
                )
            };
        }
    }
    handed(
        window,
        || imports::get_dc_ex(window, region, flags),
        (&crate::spec::GetDCEx, &args),
    )
}

/// The DCX_ flags whose clipping the DCs do not have yet (they are clipped to the window's
/// rectangle alone), and what each does.
const UNCLIPPED: [(u32, &str); 4] = [
    (
        0x0000_0040,
        "DCX_EXCLUDERGN (the region taken out of the DC)",
    ),
    (
        0x0000_0080,
        "DCX_INTERSECTRGN (the DC clipped to the region)",
    ),
    (
        0x0000_0100,
        "DCX_EXCLUDEUPDATE (the update region taken out of the DC)",
    ),
    (
        0x0000_0200,
        "DCX_INTERSECTUPDATE (the DC clipped to the update region)",
    ),
];

/// GetDCEx's flags logged in this process.
static CLIPPING_LOGGED: rtl::stub::Logged<8> = rtl::stub::Logged::new();

/// GetWindowDC: a DC of the window's whole rectangle.
#[unsafe(export_name = "f2k_export_GetWindowDC")]
pub extern "system" fn get_window_dc(window: usize) -> usize {
    handed(
        window,
        || imports::get_window_dc(window),
        (&crate::spec::GetWindowDC, &[window as u64]),
    )
}

/// ReleaseDC: a DC the family handed out released (its handle closed); 1, or 0 for a DC it did not
/// hand out (NULL among them), the last error untouched.
#[unsafe(export_name = "f2k_export_ReleaseDC")]
pub extern "system" fn release_dc(_window: usize, dc: usize) -> u32 {
    if dc == 0 || !HANDED_DCS.forget(dc as u32) {
        return 0;
    }
    imports::close(dc).is_ok() as u32
}

/// WindowFromDC: the window a DC of the family was handed out for (NULL for the screen's, or for
/// a DC it did not hand out).
#[unsafe(export_name = "f2k_export_WindowFromDC")]
pub extern "system" fn window_from_dc(dc: usize) -> usize {
    HANDED_DCS.window_of(dc as u32).unwrap_or(0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{wm, DESKTOP_WINDOW, LAST_ERROR};

    const UNSET: u32 = 0xF2F2_F2F2;

    /// The family's DCs name their windows, release once, and close their handles; ReleaseDC of
    /// NULL answers 0 with the last error untouched.
    ///
    /// Pins: user32.GetDC, user32.GetDCEx, user32.GetWindowDC, user32.ReleaseDC,
    /// user32.WindowFromDC
    #[test]
    fn dcs_name_their_windows() {
        let window = DESKTOP_WINDOW as usize;
        LAST_ERROR.with(|error| error.set(UNSET));
        let dc = get_dc(window);
        assert_ne!(dc, 0);
        assert_eq!(window_from_dc(dc), window);
        let screen = get_dc(0);
        assert_eq!(window_from_dc(screen), 0);
        let whole = get_window_dc(window);
        let ex = get_dc_ex(window, 0, 1);
        assert_eq!(window_from_dc(ex), window);
        for handed in [dc, screen, whole, ex] {
            assert_eq!(release_dc(window, handed), 1);
            assert_eq!(window_from_dc(handed), 0);
        }
        assert_eq!(release_dc(window, dc), 0, "released once");
        assert_eq!(release_dc(window, 0), 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), UNSET);
        assert!(wm(|wm| wm.dcs.is_empty()), "every handle closed");
    }

    /// A handle naming no window is 1400, and no DC is made.
    ///
    /// Pins: user32.GetDC
    #[test]
    fn a_dead_window_has_no_dc() {
        assert_eq!(get_dc(0x7FFF_FFFC), 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 1400);
        assert!(wm(|wm| wm.dcs.is_empty()));
    }
}
