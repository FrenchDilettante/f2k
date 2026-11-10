//! Icons: LoadIconW and LoadIconA, the stock icons as constant handles and a module's icons as
//! win32k's icon records ([`imports`]).
//!
//! The stock icons (IDI_*) are user32's own constant handles, as its stock cursors are
//! ([`crate::class`]): Windows 2000 loads them from user32's own resources, which F2K's user32 has
//! none of. No record holds them, and a class names them to the kernel as none.
//!
//! A module's icon is its RT_GROUP_ICON resource: a directory of RT_ICON images, of which LoadIcon
//! takes the one LookupIconIdFromDirectoryEx picks for SM_CXICON by SM_CYICON on the display
//! (rtl::icon's [`best_entry`]). LoadIcon's icons are shared (LR_SHARED): the kernel answers the
//! icon already loaded from the resource at that size, and only failing one is a record made
//! and filled in (its size, its depth, its resource). The records hold no bits yet: nothing draws
//! an icon.

use rtl::display::{DevModeW, ENUM_CURRENT_SETTINGS};
use rtl::icon::{best_entry, CursorData, ICON_SIZE, RT_GROUP_ICON, RT_ICON};
use rtl::pod::Pod;
use rtl::user::NO_PARAM_CREATE_EMPTY_CURSOR;

use crate::class::ERROR_RESOURCE_TYPE_NOT_FOUND;
use crate::imports::{self, ResourceName};
use crate::{failed, failed_with, spec};

/// ERROR_RESOURCE_DATA_NOT_FOUND: a group icon that lists no image.
const ERROR_RESOURCE_DATA_NOT_FOUND: u32 = 1812;

/// The stock icons' resource ids (winuser.h's IDI_*: IDI_APPLICATION, IDI_HAND, IDI_QUESTION,
/// IDI_EXCLAMATION, IDI_ASTERISK, IDI_WINLOGO; IDI_ERROR, IDI_WARNING and IDI_INFORMATION are
/// IDI_HAND's, IDI_EXCLAMATION's and IDI_ASTERISK's).
const STOCK_ICONS: [u16; 6] = [32512, 32513, 32514, 32515, 32516, 32517];

/// The stock icons' handles: F2K's own constants, the high word 2 and the resource id in the low
/// word (the stock cursors' high word is 1: IDI_APPLICATION and IDC_ARROW share an id).
const STOCK_ICON_BASE: u32 = 0x0002_0000;

/// The handle of the stock icon whose resource id is `id`; none for an id that names none.
pub fn stock_icon(id: u16) -> Option<usize> {
    STOCK_ICONS
        .contains(&id)
        .then_some((STOCK_ICON_BASE | u32::from(id)) as usize)
}

/// Whether `handle` is a stock icon's.
pub fn is_stock_icon(handle: usize) -> bool {
    handle >> 16 == (STOCK_ICON_BASE >> 16) as usize && stock_icon(handle as u16) == Some(handle)
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
            Some(id) => stock_icon(id)
                .or_else(|| failed(ERROR_RESOURCE_TYPE_NOT_FOUND))
                .unwrap_or(0),
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
        imports::find_existing_cursor_icon(module, resource, ICON_SIZE, ICON_SIZE),
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

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Stock icons are constants, distinct from the stock cursors; a module's icon is made once
    /// and shared after.
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
        assert_eq!(app, 0x0002_7F00);
        assert!(hand != 0 && hand != app && app != cursor);
        assert!(is_stock_icon(app) && !is_stock_icon(cursor));
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
        let made = CURSORS.with(|cursors| cursors.borrow()[0]);
        assert_eq!(
            (made.is_icon, made.width, made.bits_per_pixel, made.shared),
            (1, 32, 4, 1)
        );
    }
}
