//! The modules: GetModuleHandleA, LoadLibraryA, FreeLibrary and GetProcAddress over ntdll's loader,
//! GetModuleFileNameA over the PEB's module lists (the stand-in lists: the image, ntdll and
//! kernel32, as the kernel lays them out).

use super::{last_error, UNREAD};
use crate::base::set_last_error;
use crate::module::{free_library, get_module_file_name_a, get_module_handle_a, get_proc_address, load_library_a};
use crate::nt::{ASKED, GET_TICK_COUNT, IMAGE_BASE as IMAGE, IMAGE_PATH, KERNEL32, NTDLL};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_INVALID_ORDINAL: u32 = 182;
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// A NUL-terminated copy of `text`.
fn c(text: &[u8]) -> std::vec::Vec<u8> {
    let mut bytes = text.to_vec();
    bytes.push(0);
    bytes
}

/// A path of exactly `length` characters naming kernel32.dll, terminated.
fn kernel32_path(length: usize) -> std::vec::Vec<u8> {
    let mut path = std::vec![b'd'; length - b"\\kernel32.dll".len()];
    path.extend_from_slice(b"\\kernel32.dll");
    c(&path)
}

/// A module name converts as Windows 2000's converts it, into a MAX_PATH-character Unicode string:
/// 260 characters are looked up (the loader gets them all), a longer name is
/// ERROR_FILENAME_EXCED_RANGE before the loader sees it — never cut down to 260 (which made a name
/// with a tail past MAX_PATH find kernel32).
#[test]
fn module_names_past_max_path_are_refused() {
    ASKED.with(|asked| asked.borrow_mut().clear());
    let fits = kernel32_path(260);
    set_last_error(0);
    unsafe { get_module_handle_a(fits.as_ptr()) };
    assert_ne!(last_error(), ERROR_FILENAME_EXCED_RANGE);
    assert_eq!(ASKED.with(|asked| asked.borrow().last().map(|name| name.len())), Some(260));
    let mut long = kernel32_path(260);
    long.insert(260, b'x');
    assert_eq!(unsafe { get_module_handle_a(long.as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_FILENAME_EXCED_RANGE);
    assert_eq!(unsafe { load_library_a(long.as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_FILENAME_EXCED_RANGE);
    assert_eq!(ASKED.with(|asked| asked.borrow().len()), 1, "the long names never reach the loader");
}

/// An export name has no length cap of its own: one longer than any export is ERROR_PROC_NOT_FOUND
/// (the loader finds no such name), never a shorter name's export.
#[test]
fn long_export_names_are_not_found() {
    let mut name = b"GetTickCount".to_vec();
    name.resize(300, b'x');
    let name = c(&name);
    assert_eq!(unsafe { get_proc_address(KERNEL32, c(b"GetTickCount").as_ptr()) }, GET_TICK_COUNT);
    assert_eq!(unsafe { get_proc_address(KERNEL32, name.as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_PROC_NOT_FOUND);
}

/// GetModuleFileNameA refuses before touching anything: a handle naming no module (the image,
/// ntdll and kernel32 are the modules) is ERROR_MOD_NOT_FOUND, and an empty buffer takes nothing;
/// both return 0 and leave the buffer as it was.
#[test]
fn get_module_file_name_refuses_module_handles_and_empty_buffers() {
    let mut buffer = [0xCCu8; 16];
    set_last_error(0);
    assert_eq!(unsafe { get_module_file_name_a(0x1234_0000, buffer.as_mut_ptr(), 16) }, 0);
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
    set_last_error(0);
    assert_eq!(unsafe { get_module_file_name_a(0, buffer.as_mut_ptr(), 0) }, 0);
    assert_eq!(last_error(), 0, "an empty buffer is no error");
    assert_eq!(buffer, [0xCC; 16]);
}

/// GetModuleFileNameA: a module's full path from the lists (the image's for a null handle),
/// terminated; a buffer too small takes exactly its size, unterminated, and that size comes back,
/// the last error untouched.
#[test]
fn get_module_file_name_copies_the_full_path() {
    let mut buffer = [0xCCu8; 64];
    let length = unsafe { get_module_file_name_a(KERNEL32, buffer.as_mut_ptr(), 64) };
    assert_eq!(&buffer[..length as usize + 1], b"C:\\WINNT\\system32\\KERNEL32.DLL\0");
    let length = unsafe { get_module_file_name_a(0, buffer.as_mut_ptr(), 64) };
    assert_eq!(&buffer[..length as usize + 1], format!("{IMAGE_PATH}\0").as_bytes());
    assert_eq!(unsafe { get_module_file_name_a(IMAGE, buffer.as_mut_ptr(), 64) }, length);
    let mut short = [0xCCu8; 8];
    set_last_error(0);
    assert_eq!(unsafe { get_module_file_name_a(NTDLL, short.as_mut_ptr(), 4) }, 4);
    assert_eq!(&short, b"C:\\W\xCC\xCC\xCC\xCC", "exactly its size, unterminated");
    assert_eq!(last_error(), 0);
}

/// GetModuleHandleA: the image for a null name (the PEB's ImageBaseAddress), never asking the
/// loader; a name the loader does not find is ERROR_MOD_NOT_FOUND. LoadLibraryA finds what it
/// finds; a null name is ERROR_INVALID_PARAMETER.
#[test]
fn module_handles_come_from_the_loader() {
    ASKED.with(|asked| asked.borrow_mut().clear());
    assert_eq!(unsafe { get_module_handle_a(core::ptr::null()) }, IMAGE);
    assert_eq!(ASKED.with(|asked| asked.borrow().len()), 0);
    assert_eq!(unsafe { get_module_handle_a(c(b"KERNEL32").as_ptr()) }, KERNEL32);
    assert_eq!(ASKED.with(|asked| asked.borrow().clone()), ["KERNEL32"], "the name as given, in Unicode");
    assert_eq!(unsafe { get_module_handle_a(c(b"nosuch.dll").as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
    assert_eq!(unsafe { load_library_a(c(b"kernel32.dll").as_ptr()) }, KERNEL32);
    assert_eq!(unsafe { load_library_a(c(b"nosuch.dll").as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
    assert_eq!(unsafe { load_library_a(core::ptr::null()) }, 0);
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
}

/// FreeLibrary: a module's handle succeeds; one naming no module is ERROR_MOD_NOT_FOUND
/// (LdrUnloadDll's STATUS_DLL_NOT_FOUND, as Windows 2000 maps it).
#[test]
fn free_library_answers_for_modules() {
    assert_eq!(free_library(KERNEL32), 1);
    assert_eq!(free_library(0x1234_0000), 0);
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
}

/// GetProcAddress: a null handle is the image's; an ordinal (a value below 0x10000) finds nothing
/// yet (ERROR_INVALID_ORDINAL, never reading it as a name); a handle naming no module is
/// ERROR_MOD_NOT_FOUND; names are exact.
#[test]
fn procedures_come_from_the_loader() {
    assert_eq!(unsafe { get_proc_address(KERNEL32, c(b"gettickcount").as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_PROC_NOT_FOUND);
    assert_eq!(unsafe { get_proc_address(0, c(b"GetTickCount").as_ptr()) }, 0, "the image exports nothing");
    assert_eq!(last_error(), ERROR_PROC_NOT_FOUND);
    assert_eq!(unsafe { get_proc_address(KERNEL32, UNREAD as *const u8) }, 0);
    assert_eq!(last_error(), ERROR_INVALID_ORDINAL);
    assert_eq!(unsafe { get_proc_address(0x1234_0000, c(b"GetTickCount").as_ptr()) }, 0);
    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
}
