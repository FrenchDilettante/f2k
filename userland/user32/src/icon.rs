//! Icons: LoadIconW and LoadIconA, CopyIcon and DestroyIcon, over win32k's cursor and icon records
//! ([`imports`]).
//!
//! The stock icons (IDI_*) are the system's records in win32k, as the stock cursors are
//! ([`crate::class`]): Windows 2000 loads them from user32's own resources at its boot, which F2K's
//! user32 has none of; LoadIcon with no module finds the one of its id.
//!
//! A module's icon is its RT_GROUP_ICON resource: a directory of RT_ICON images, of which LoadIcon
//! takes the one LookupIconIdFromDirectoryEx picks for SM_CXICON by SM_CYICON on the display
//! (rtl::icon's [`best_entry`]). LoadIcon's icons are shared (LR_SHARED): the kernel answers the
//! icon already loaded from the resource at that size, and only failing one is a record made
//! and filled in (its size, its depth, its resource). The records hold no bits yet: nothing draws
//! an icon.
//!
//! CopyIcon makes a new record of the process's own from what the source holds (NtUserGetIconInfo),
//! not shared, as Windows 2000's makes a new icon of the source's image; DestroyIcon destroys a
//! record of the process's own (NtUserDestroyCursor), and leaves a shared one, which lives as long
//! as its module, answering TRUE. A handle naming no cursor or icon is ERROR_INVALID_CURSOR_HANDLE
//! for both (the menus capture's DestroyIcon on a window, a menu and an accelerator table).

use rtl::display::{DevModeW, ENUM_CURRENT_SETTINGS};
use rtl::icon::{best_entry, CursorData, ICON_SIZE, RT_GROUP_ICON, RT_ICON};
use rtl::pod::Pod;
use rtl::status::NtStatus;
use rtl::user::NO_PARAM_CREATE_EMPTY_CURSOR;

use crate::imports::{self, ResourceName};
use crate::{failed, failed_with, spec};

/// ERROR_RESOURCE_DATA_NOT_FOUND: a group icon that lists no image.
const ERROR_RESOURCE_DATA_NOT_FOUND: u32 = 1812;

/// ERROR_INVALID_CURSOR_HANDLE: a handle naming no cursor or icon.
pub const ERROR_INVALID_CURSOR_HANDLE: u32 = 1402;

/// The Win32 error of a failed cursor or icon service: a handle naming no cursor or icon is
/// ERROR_INVALID_CURSOR_HANDLE (the kernel's icon module), anything else what ntdll maps it to.
fn cursor_error(status: NtStatus) -> u32 {
    match status.0 {
        rtl::status::STATUS_INVALID_HANDLE => ERROR_INVALID_CURSOR_HANDLE,
        _ => imports::dos_error(status),
    }
}

/// LoadIconW: a stock icon (no module, an IDI_ id), or the module's group icon `name` at the
/// standard icon size; see [`load_icon`].
///
/// # Safety
///
/// `name` is a resource id or the address of a NUL-terminated UTF-16 string, as for the
/// platform's.
#[unsafe(export_name = "f2k_export_LoadIconW")]
pub unsafe extern "system" fn load_icon_w(instance: usize, name: *const u16) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        load_icon(
            &spec::LoadIconW,
            instance,
            ResourceName::Wide(name as usize),
        )
    }
}

/// LoadIconA: LoadIconW's, the name an ANSI string or a number.
///
/// # Safety
///
/// As LoadIconW's, the string ANSI.
#[unsafe(export_name = "f2k_export_LoadIconA")]
pub unsafe extern "system" fn load_icon_a(instance: usize, name: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        load_icon(
            &spec::LoadIconA,
            instance,
            ResourceName::Narrow(name as usize),
        )
    }
}

/// LoadIcon's core: with no module, the stock icon the id names (the same handle from either
/// form), NULL with ERROR_RESOURCE_TYPE_NOT_FOUND for an id that names none (as LoadCursor answers
/// one); a stock icon by name goes to the stub routine. A module's icon: its group found, the
/// image picked, the shared icon answered or made.
///
/// # Safety
///
/// A string `name` is the caller's NUL-terminated string.
unsafe fn load_icon(entry: &rtl::stub::Entry, instance: usize, name: ResourceName) -> usize {
    if instance == 0 {
        return match name.id() {
            Some(id) => crate::class::stock(id, RT_ICON),
            None => {
                let raw = match name {
                    ResourceName::Wide(raw) | ResourceName::Narrow(raw) => raw,
                };
                // SAFETY: the arguments as the export's kinds read them: a handle and an address,
                // neither read as memory.
                unsafe {
                    crate::stub::stubbed(
                        entry,
                        "stock icons by name: user32 has no icon resources",
                        &[instance as u64, raw as u64],
                    ) as usize
                }
            }
        };
    }
    // SAFETY: the caller's contract.
    let Some(group) = (unsafe { imports::find_named_resource(instance, RT_GROUP_ICON, name) })
    else {
        return 0;
    };
    let Some(directory) = imports::resource_data(instance, group) else {
        return 0;
    };
    module_icon(instance, directory).unwrap_or(0)
}

/// The bits per pixel of the display's current mode (8 when it cannot be asked).
fn display_bits() -> u32 {
    let mut mode = DevModeW::zeroed();
    mode.size = core::mem::size_of::<DevModeW>() as u16;
    match imports::enum_display_settings(0, ENUM_CURRENT_SETTINGS, &mut mode as *mut _ as usize, 0)
    {
        Ok(()) if mode.bits_per_pel != 0 => mode.bits_per_pel,
        _ => 8,
    }
}

/// The shared icon of the module's group icon whose directory is `directory`: the one loaded
/// before at the standard size, else a record made and filled in from the picked image.
fn module_icon(module: usize, directory: &'static [u8]) -> Option<usize> {
    let Some(image) = best_entry(directory, ICON_SIZE, ICON_SIZE, display_bits()) else {
        return failed(ERROR_RESOURCE_DATA_NOT_FOUND);
    };
    let resource = directory.as_ptr() as usize;
    let existing = failed_with(
        imports::find_existing_cursor_icon(module, resource, ICON_SIZE, ICON_SIZE, RT_ICON),
        imports::dos_error,
    )?;
    if existing != 0 {
        return Some(existing);
    }
    // The image must be there; the icon is the standard size whatever the image's (LoadIcon's
    // LR_DEFAULTSIZE: a smaller image is stretched to it), which FindExistingCursorIcon finds it
    // by.
    let found = imports::find_resource(module, RT_ICON, image.id, 0)?;
    imports::resource_data(module, found)?;
    let data = CursorData {
        is_icon: 1,
        width: ICON_SIZE,
        height: ICON_SIZE,
        hotspot_x: ICON_SIZE / 2,
        hotspot_y: ICON_SIZE / 2,
        bits_per_pixel: image.bits(),
        module: module as u32,
        resource: resource as u32,
        shared: 1,
    };
    let icon = failed_with(
        imports::call_no_param(NO_PARAM_CREATE_EMPTY_CURSOR),
        imports::dos_error,
    )? as usize;
    failed_with(
        imports::set_cursor_icon_data(icon, &data),
        imports::dos_error,
    )?;
    Some(icon)
}

/// CopyIcon: a new icon of the process's own, of the source's size and kind, not shared (see the
/// module notes); NULL with ERROR_INVALID_CURSOR_HANDLE for a handle naming no cursor or icon.
#[unsafe(export_name = "f2k_export_CopyIcon")]
pub extern "system" fn copy_icon(icon: usize) -> usize {
    copy(icon).unwrap_or(0)
}

fn copy(icon: usize) -> Option<usize> {
    let source = failed_with(imports::get_icon_info(icon), cursor_error)?;
    let data = CursorData {
        shared: 0,
        ..source
    };
    let copy = failed_with(
        imports::call_no_param(NO_PARAM_CREATE_EMPTY_CURSOR),
        imports::dos_error,
    )? as usize;
    failed_with(
        imports::set_cursor_icon_data(copy, &data),
        imports::dos_error,
    )?;
    Some(copy)
}

/// DestroyIcon: the icon destroyed, a shared one left (see the module notes); FALSE with
/// ERROR_INVALID_CURSOR_HANDLE for a handle naming no cursor or icon.
#[unsafe(export_name = "f2k_export_DestroyIcon")]
pub extern "system" fn destroy_icon(icon: usize) -> i32 {
    failed_with(imports::destroy_cursor(icon), cursor_error).is_some() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::ERROR_RESOURCE_TYPE_NOT_FOUND;
    use crate::imports::host::{add_resource, CURSORS, LAST_ERROR, PROGRAM};

    /// A group icon of two images, 16 by 16 and 32 by 32, and the second's image.
    fn add_icon() {
        let mut directory = std::vec![0, 0, 1, 0, 2, 0];
        for (side, id) in [(16u8, 1u16), (32, 2)] {
            directory.extend_from_slice(&[side, side, 16, 0, 1, 0, 4, 0]);
            directory.extend_from_slice(&744u32.to_le_bytes());
            directory.extend_from_slice(&id.to_le_bytes());
        }
        add_resource(PROGRAM, RT_GROUP_ICON, 100, &directory);
        let mut image = std::vec![0u8; 40];
        image[0] = 40;
        image[4] = 32;
        image[8] = 64;
        add_resource(PROGRAM, RT_ICON, 2, &image);
    }

    /// Stock icons are the system's, distinct from the stock cursors; a module's icon is made once
    /// and shared after; a copy is the process's own, not shared, and DestroyIcon refuses what is
    /// no icon.
    ///
    /// Pins: user32.LoadIconW, user32.LoadIconA
    #[test]
    fn icons_are_stock_or_shared() {
        // SAFETY: resource numbers.
        let (app, hand, cursor) = unsafe {
            (
                load_icon_w(0, 32512 as *const u16),
                load_icon_a(0, 32513 as *const u8),
                crate::class::load_cursor_w(0, 32512 as *const u16),
            )
        };
        assert!(app != 0 && hand != 0 && hand != app && app != cursor);
        // SAFETY: as above.
        assert_eq!(unsafe { load_icon_w(0, 12345 as *const u16) }, 0);
        assert_eq!(LAST_ERROR.with(|e| e.get()), ERROR_RESOURCE_TYPE_NOT_FOUND);
        add_icon();
        // SAFETY: as above.
        let (first, again) = unsafe {
            (
                load_icon_w(PROGRAM, 100 as *const u16),
                load_icon_a(PROGRAM, 100 as *const u8),
            )
        };
        assert_ne!(first, 0);
        assert_eq!(again, first);
        let made = CURSORS.with(|cursors| *cursors.borrow().last().unwrap());
        assert_eq!(
            (made.is_icon, made.width, made.bits_per_pixel, made.shared),
            (1, 32, 4, 1)
        );
        let copy = copy_icon(first);
        assert!(copy != 0 && copy != first);
        let copied = CURSORS.with(|cursors| *cursors.borrow().last().unwrap());
        assert_eq!((copied.is_icon, copied.width, copied.shared), (1, 32, 0));
        assert_eq!(destroy_icon(copy), 1);
        assert_eq!(destroy_icon(0x1234), 0);
        assert_eq!(LAST_ERROR.with(|e| e.get()), ERROR_INVALID_CURSOR_HANDLE);
        assert_eq!(copy_icon(0x1234), 0);
        assert_eq!(LAST_ERROR.with(|e| e.get()), ERROR_INVALID_CURSOR_HANDLE);
    }
}
