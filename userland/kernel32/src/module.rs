//! The modules, as far as the PEB and the process parameters name them: GetModuleHandleA of the
//! image (the PEB's ImageBaseAddress) and GetModuleFileNameA (the parameters' ImagePathName, the
//! loader entry's FullDllName on Windows 2000). The module lists, and with them the other modules'
//! handles and names, come with the loader's move to user mode (B10).

use rtl::cp1252;

use crate::base::{peb, process_parameters, read, set_last_error, units};
use crate::startup::IMAGE_PATH_NAME;

/// The PEB's ImageBaseAddress.
const IMAGE_BASE_ADDRESS: usize = 0x08;

const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// The image's base, the PEB's ImageBaseAddress: its module handle.
fn image_base() -> u32 {
    read(peb() + IMAGE_BASE_ADDRESS)
}

/// GetModuleHandleA: the image's handle for a null name (the PEB's ImageBaseAddress). A name is
/// looked up in the module lists (LdrGetDllHandle), which come with B10: until then
/// ERROR_CALL_NOT_IMPLEMENTED.
#[unsafe(export_name = "f2k_export_GetModuleHandleA")]
pub extern "system" fn get_module_handle_a(name: *const u8) -> u32 {
    if name.is_null() {
        return image_base();
    }
    set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    0
}

/// GetModuleFileNameA: the module's full path (the image's for a null handle or its base), narrowed
/// into the caller's buffer, terminated when it fits; its length. Windows 2000's truncation: a
/// buffer too small takes exactly its size, unterminated, and that size comes back, the last error
/// untouched. ERROR_MOD_NOT_FOUND for a handle naming no module F2K's process lists yet (the
/// system DLLs' names come with the module lists, B10), the buffer untouched.
///
/// # Safety
///
/// `buffer` holds `size` bytes (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleFileNameA")]
pub unsafe extern "system" fn get_module_file_name_a(
    module: u32,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    if module != 0 && module != image_base() {
        set_last_error(ERROR_MOD_NOT_FOUND);
        return 0;
    }
    // SAFETY: the process parameters' own string.
    let path = unsafe { units(process_parameters() + IMAGE_PATH_NAME) };
    let copy = path.len().min(size as usize);
    for (at, &unit) in path[..copy].iter().enumerate() {
        // SAFETY: the caller's buffer holds `size` bytes.
        unsafe { buffer.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    if copy < size as usize {
        // SAFETY: as above.
        unsafe { buffer.add(copy).write(0) };
    }
    copy as u32
}
