//! The GetDC family: GetDC, GetDCEx, GetWindowDC, ReleaseDC and WindowFromDC, over win32k's DC
//! services ([`imports`]).
//!
//! A DC is a GDI object of the calling process; ReleaseDC deletes it (gdi32's DeleteDC). user32
//! keeps the DCs the family handed out with their windows ([`HANDED_DCS`]): WindowFromDC answers
//! from there (no service answers a DC's window: the kernel's DCs are the screen's, the window a
//! seam), and ReleaseDC releases those alone, as its documentation says (a CreateDC DC goes to
//! DeleteDC).
//!
//! A process may hold as many as it likes at once: Windows 2000 hands them out of a DC cache it
//! grows on demand (the GDI handle quota its only bound), and F2K's list grows on the process heap
//! the same way ([`crate::records`]), a record a DC, gone with its ReleaseDC.

use rtl::status::NtStatus;

use crate::imports;
use crate::records::Table;
use crate::window::is_window_alive;
use crate::{answered, failed, ERROR_INVALID_WINDOW_HANDLE, ERROR_NOT_ENOUGH_MEMORY};

/// The DCs the family handed out and not released yet: each record the DC's handle, then its
/// window's (0: the screen's). Shared by the process's threads under user32's lock.
static HANDED_DCS: Table<2> = Table::new();

/// The family's core: a DC of `window` (zero: the screen) from `service`, kept with its window;
/// NULL with 1400 for a handle naming no window, ERROR_NOT_ENOUGH_MEMORY when the heap has no room
/// to keep it (the DC closed again).
fn handed(window: usize, service: impl FnOnce() -> Result<u32, NtStatus>) -> usize {
    if window != 0 && !is_window_alive(window) {
        return failed(ERROR_INVALID_WINDOW_HANDLE).unwrap_or(0);
    }
    let Some(dc) = answered(service()) else {
        return 0;
    };
    let dc = dc as usize;
    if !HANDED_DCS.with(|handed| handed.set([dc, window])) {
        let _ = imports::delete_dc(dc);
        return failed(ERROR_NOT_ENOUGH_MEMORY).unwrap_or(0);
    }
    dc
}

/// GetDC: a DC of the window's client area (NULL: the screen's).
#[unsafe(export_name = "f2k_export_GetDC")]
pub extern "system" fn get_dc(window: usize) -> usize {
    handed(window, || imports::get_dc(window))
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
    handed(window, || imports::get_dc_ex(window, region, flags))
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
    handed(window, || imports::get_window_dc(window))
}

/// ReleaseDC: a DC the family handed out released (its handle closed); 1, or 0 for a DC it did not
/// hand out (NULL among them), the last error untouched.
#[unsafe(export_name = "f2k_export_ReleaseDC")]
pub extern "system" fn release_dc(_window: usize, dc: usize) -> u32 {
    if HANDED_DCS.with(|handed| handed.take(dc)).is_none() {
        return 0;
    }
    imports::delete_dc(dc) as u32
}

/// WindowFromDC: the window a DC of the family was handed out for (NULL for the screen's, or for
/// a DC it did not hand out).
#[unsafe(export_name = "f2k_export_WindowFromDC")]
pub extern "system" fn window_from_dc(dc: usize) -> usize {
    HANDED_DCS
        .with(|handed| handed.get(dc))
        .map_or(0, |[_, window]| window)
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

    /// A process holds as many DCs at once as it asks for, far past the 64 a fixed list kept, each
    /// naming its window until released; the last release leaves no record and no handle behind.
    #[test]
    fn dcs_are_held_past_any_fixed_number() {
        let window = DESKTOP_WINDOW as usize;
        let held: std::vec::Vec<(usize, usize)> = (0..300)
            .map(|index| {
                let of = if index % 3 == 0 { 0 } else { window };
                (get_dc(of), of)
            })
            .collect();
        assert!(held.iter().all(|&(dc, _)| dc != 0));
        assert!(held.iter().all(|&(dc, of)| window_from_dc(dc) == of));
        for &(dc, of) in held.iter().rev() {
            assert_eq!(release_dc(of, dc), 1);
        }
        assert!(HANDED_DCS.with(|handed| handed.is_empty()));
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
