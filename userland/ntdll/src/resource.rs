//! Resources and messages (`rtl::resource`, `rtl::message`): a module's resource directory walked
//! (LdrFindResource_U, LdrFindResourceDirectory_U) and its data reached (LdrAccessResource); a
//! message found in a module's message table (RtlFindMessage) and laid out (RtlFormatMessage) —
//! kernel32's FormatMessage's work, as on Windows 2000.
//!
//! A module handle is its base: the image as mapped, read in place (a bad handle faults the caller,
//! as on the platform). The language searches fall back on F2K's one locale, US English, for the
//! thread's, the user's and the system's default languages.

use rtl::message::{self, Arguments};
use rtl::resource::{self, Defaults};
use rtl::status::STATUS_SUCCESS;

use crate::loader::Mapped;

/// The path's elements: `length` ULONG_PTRs at `path` (none for an empty path).
///
/// # Safety
///
/// `path` holds `length` elements.
unsafe fn path<'a>(path: *const u32, length: u32) -> &'a [u32] {
    if length == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(path, length as usize) }
}

/// LdrFindResource_U: the IMAGE_RESOURCE_DATA_ENTRY the path (the type, the name, the language)
/// leads to in the module's resource directory, written to `entry`; the level's status for an
/// element not found (`rtl::resource::walk`).
///
/// # Safety
///
/// `module` is a mapped image's base; `path_elements` holds `length` elements (a name's address a
/// NUL-terminated UTF-16 string); `entry` is writable.
#[unsafe(export_name = "f2k_export_LdrFindResource_U")]
pub unsafe extern "system" fn ldr_find_resource_u(
    module: u32,
    path_elements: *const u32,
    length: u32,
    entry: *mut u32,
) -> u32 {
    // SAFETY: the caller's contract.
    let path = unsafe { path(path_elements, length) };
    // SAFETY: the caller's mapped image, its resource directory read in place, and the names its
    // path points at (the caller's contract).
    let image = unsafe { Mapped::new() };
    match resource::find_data(&image, module, path, Defaults::F2K) {
        Ok(found) => {
            // SAFETY: the caller's contract.
            unsafe { entry.write_unaligned(found) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// LdrFindResourceDirectory_U: the IMAGE_RESOURCE_DIRECTORY the path leads to (the root for an
/// empty one), written to `directory`.
///
/// # Safety
///
/// As [`ldr_find_resource_u`]'s.
#[unsafe(export_name = "f2k_export_LdrFindResourceDirectory_U")]
pub unsafe extern "system" fn ldr_find_resource_directory_u(
    module: u32,
    path_elements: *const u32,
    length: u32,
    directory: *mut u32,
) -> u32 {
    // SAFETY: the caller's contract.
    let path = unsafe { path(path_elements, length) };
    // SAFETY: as `ldr_find_resource_u`'s.
    let image = unsafe { Mapped::new() };
    match resource::find_table(&image, module, path, Defaults::F2K) {
        Ok(found) => {
            // SAFETY: the caller's contract.
            unsafe { directory.write_unaligned(found) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// LdrAccessResource: the data of a resource's IMAGE_RESOURCE_DATA_ENTRY, its address and its size
/// written where asked (either may be NULL); STATUS_RESOURCE_DATA_NOT_FOUND for data outside the
/// image.
///
/// # Safety
///
/// `module` is a mapped image's base, `entry` one of its data entries; `address` and `size` are
/// writable when not NULL.
#[unsafe(export_name = "f2k_export_LdrAccessResource")]
pub unsafe extern "system" fn ldr_access_resource(
    module: u32,
    entry: u32,
    address: *mut u32,
    size: *mut u32,
) -> u32 {
    // SAFETY: the caller's mapped image and one of its data entries, read in place (the caller's
    // contract).
    let image = unsafe { Mapped::new() };
    match resource::access(&image, module, entry) {
        Ok((at, bytes)) => {
            // SAFETY: the caller's contract.
            unsafe {
                if !address.is_null() {
                    address.write_unaligned(at);
                }
                if !size.is_null() {
                    size.write_unaligned(bytes);
                }
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// RtlFindMessage: the MESSAGE_RESOURCE_ENTRY of message `id` in the module's message table (the
/// resource of type `table`, name 1, in `language`), written to `entry`;
/// STATUS_MESSAGE_NOT_FOUND for a table without it, the resource walk's statuses for no table. As
/// on Windows 2000, the table is found through LdrFindResource_U and reached through
/// LdrAccessResource (`rtl::resource::find_message` is the same composition).
///
/// # Safety
///
/// `module` is a mapped image's base; `entry` is writable.
#[unsafe(export_name = "f2k_export_RtlFindMessage")]
pub unsafe extern "system" fn rtl_find_message(
    module: u32,
    table: u32,
    language: u32,
    id: u32,
    entry: *mut u32,
) -> u32 {
    let path = [table, resource::MESSAGE_TABLE_NAME, language & 0xFFFF];
    let (mut data, mut at, mut size) = (0, 0, 0);
    // SAFETY: the path and the out-parameters are ours; the module is the caller's.
    let status = unsafe {
        let status = ldr_find_resource_u(module, path.as_ptr(), 3, &mut data);
        if status != STATUS_SUCCESS {
            return status;
        }
        ldr_access_resource(module, data, &mut at, &mut size)
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    // SAFETY: the message table LdrAccessResource found inside the caller's mapped image, `size`
    // bytes, read in place.
    let image = unsafe { Mapped::new() };
    match resource::message_entry(&image, at, size, id) {
        Ok(found) => {
            // SAFETY: the caller's contract.
            unsafe { entry.write_unaligned(found) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// RtlFormatMessage: the message text laid out (`rtl::message::format`: the width, the escapes, the
/// inserts unless ignored) into the buffer of `length` bytes, terminated; the bytes written, the
/// terminator's included, to `return_length` when it is not NULL. The arguments are an array of
/// pointer-sized values (`array`), or a va_list's address; ANSI strings for `ansi`.
/// STATUS_BUFFER_OVERFLOW when the buffer cannot hold the message; STATUS_INVALID_PARAMETER for an
/// insert without arguments or with a format not served.
///
/// # Safety
///
/// `format` is a NUL-terminated UTF-16 string; `buffer` holds `length` bytes; `arguments` (when not
/// NULL) holds every value the inserts name; `return_length` is writable when not NULL.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RtlFormatMessage")]
pub unsafe extern "system" fn rtl_format_message(
    format: *const u16,
    width: u32,
    ignore_inserts: u32,
    ansi: u32,
    array: u32,
    arguments: *const usize,
    buffer: *mut u16,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    let mut units = 0;
    // SAFETY: the caller's string, read to its NUL.
    while unsafe { format.add(units).read_unaligned() } != 0 {
        units += 1;
    }
    // SAFETY: as above.
    let text = unsafe { core::slice::from_raw_parts(format, units) };
    let arguments = (!arguments.is_null()).then(|| Arguments {
        slots: if array as u8 != 0 {
            arguments
        } else {
            // SAFETY: a va_list's address: the list is a pointer to the first argument.
            unsafe { (arguments as *const *const usize).read_unaligned() }
        },
        ansi: ansi as u8 != 0,
    });
    let out: &mut [u16] = if length < 2 {
        &mut []
    } else {
        // SAFETY: the caller's buffer, `length` bytes.
        unsafe { core::slice::from_raw_parts_mut(buffer, length as usize / 2) }
    };
    match message::format(text, width, ignore_inserts as u8 != 0, arguments, out) {
        Ok(written) => {
            if !return_length.is_null() {
                // SAFETY: the caller's contract.
                unsafe { return_length.write_unaligned(2 * (written as u32 + 1)) };
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}
