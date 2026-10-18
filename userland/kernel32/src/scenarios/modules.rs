//! GetModuleFileNameA: the image's path, from the process parameters (the host's stand-in pages).

use crate::base::{last_error, set_last_error};
use crate::module::{get_module_file_name_a, get_module_handle_a};
use crate::nt::threads::{IMAGE_BASE, IMAGE_PATH};

const ERROR_MOD_NOT_FOUND: u32 = 126;

/// GetModuleFileNameA refuses before touching anything: a handle naming no module it knows is
/// ERROR_MOD_NOT_FOUND, and an empty buffer takes nothing; both return 0 and leave the buffer as it
/// was.
#[test]
fn get_module_file_name_refuses_module_handles_and_empty_buffers() {
    let mut buffer = [0xCCu8; 16];
    set_last_error(0);
    // SAFETY: a 16-byte buffer.
    assert_eq!(
        unsafe { get_module_file_name_a(0x1234_0000, buffer.as_mut_ptr(), 16) },
        0
    );
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
    set_last_error(0);
    // SAFETY: as above.
    assert_eq!(
        unsafe { get_module_file_name_a(0, buffer.as_mut_ptr(), 0) },
        0
    );
    assert_eq!(last_error(), 0, "an empty buffer is no error");
    assert_eq!(buffer, [0xCC; 16]);
}

/// GetModuleFileNameA: the image's full path (for a null handle or the image's base), terminated;
/// a buffer too small takes exactly its size, unterminated, and that size comes back, the last
/// error untouched — the runtime fixture's args block ("ret=4 terminated at 3: no err=-").
#[test]
fn get_module_file_name_copies_the_full_path() {
    for module in [0, IMAGE_BASE] {
        let mut buffer = [0xCCu8; 64];
        // SAFETY: a 64-byte buffer.
        let length = unsafe { get_module_file_name_a(module, buffer.as_mut_ptr(), 64) };
        assert_eq!(length as usize, IMAGE_PATH.len());
        assert_eq!(
            &buffer[..IMAGE_PATH.len() + 1],
            format!("{IMAGE_PATH}\0").as_bytes()
        );
    }
    let mut small = [b'x'; 8];
    set_last_error(0);
    // SAFETY: a 4-byte room in an 8-byte buffer.
    assert_eq!(
        unsafe { get_module_file_name_a(0, small.as_mut_ptr(), 4) },
        4
    );
    assert_eq!(&small, b"C:\\Cxxxx");
    assert_eq!(last_error(), 0);
}

/// GetModuleHandleA(NULL) is the image's handle: the PEB's ImageBaseAddress (the runtime fixture's
/// teb block compares the two).
#[test]
fn get_module_handle_of_null_is_the_image() {
    assert_eq!(get_module_handle_a(core::ptr::null()), IMAGE_BASE);
}

/// GetModuleHandleA of a name finds the module in the PEB's lists.
#[test]
#[ignore = "B10: the module lists (LdrGetDllHandle): a name fails with ERROR_CALL_NOT_IMPLEMENTED until then"]
fn get_module_handle_finds_kernel32_by_name() {
    assert_ne!(get_module_handle_a(b"kernel32.dll\0".as_ptr()), 0);
}
