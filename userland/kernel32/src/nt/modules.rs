//! The host tests' loader: the PEB's module lists as ntdll lays them out (the image, ntdll,
//! kernel32, in load order), and ntdll's loader exports over a table of the same modules (the
//! lookups themselves are `rtl::modules`', tested there and against the real DLLs in the kernel).

use std::cell::RefCell;

/// The system DLLs' bases and the modules' paths in load order, rtl's stand-in process's.
pub use rtl::host::{KERNEL32, MODULE_PATHS, NTDLL};
use rtl::image::ImageNtHeaders32;
use rtl::pod::Pod;

use super::host::failure;
use super::threads::IMAGE_BASE;
use super::{AnsiString, UnicodeString};
/// GetTickCount's stand-in address in kernel32.
pub const GET_TICK_COUNT: u32 = KERNEL32 + 0x1000;
/// GetTickCount's ordinal in the stand-in kernel32.
pub const GET_TICK_COUNT_ORDINAL: u32 = 7;

use rtl::status::{
    STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND,
    STATUS_INVALID_PARAMETER,
    STATUS_ORDINAL_NOT_FOUND,
};

std::thread_local! {
    /// The names the loader was asked for, as kernel32 converted them.
    pub static ASKED: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// The module a name names: its file part, without regard to case, `.dll` when it has no
/// extension.
fn named(name: *const UnicodeString) -> Option<u32> {
    // SAFETY: the caller's string, its buffer holding its length.
    let text = std::string::String::from_utf16_lossy(unsafe { (*name).units() });
    ASKED.with(|asked| asked.borrow_mut().push(text.clone()));
    let file = text.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
    let file = if file.contains('.') {
        file
    } else {
        file + ".dll"
    };
    MODULE_PATHS
        .iter()
        .find(|(_, path)| {
            path.rsplit('\\')
                .next()
                .unwrap()
                .eq_ignore_ascii_case(&file)
        })
        .map(|&(base, _)| base)
}

pub unsafe extern "system" fn LdrGetDllHandle(
    _path: *const u16,
    _characteristics: *const u32,
    name: *const UnicodeString,
    handle: *mut u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    let found = named(name);
    // SAFETY: the caller's handle.
    unsafe { handle.write(found.unwrap_or(0)) };
    found.map_or(STATUS_DLL_NOT_FOUND, |_| 0)
}

pub unsafe extern "system" fn LdrLoadDll(
    path: *const u16,
    characteristics: *const u32,
    name: *const UnicodeString,
    handle: *mut u32,
) -> u32 {
    // SAFETY: as LdrGetDllHandle.
    unsafe { LdrGetDllHandle(path, characteristics, name, handle) }
}

pub unsafe extern "system" fn LdrUnloadDll(module: u32) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    if MODULE_PATHS.iter().any(|&(base, _)| base == module) {
        0
    } else {
        STATUS_DLL_NOT_FOUND
    }
}

std::thread_local! {
    /// The modules whose thread notifications were turned off.
    pub static NO_THREAD_CALLS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// A module of the lists has its thread notifications turned off (recorded); any other handle
/// changes nothing and succeeds, as ntdll's does.
pub unsafe extern "system" fn LdrDisableThreadCalloutsForDll(module: u32) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    if MODULE_PATHS.iter().any(|&(base, _)| base == module) {
        NO_THREAD_CALLS.with(|modules| modules.borrow_mut().push(module));
    }
    0
}

std::thread_local! {
    /// The process image's subsystem version (major, minor), as its NT headers carry it: the
    /// MSVC 6 linker's 4.0 to start.
    pub static IMAGE_SUBSYSTEM_VERSION: std::cell::Cell<(u16, u16)> = const { std::cell::Cell::new((4, 0)) };
    /// The process image's stack sizes (SizeOfStackReserve, SizeOfStackCommit), as its NT
    /// headers carry them: the MSVC 6 linker's 1 MiB and one page to start.
    pub static IMAGE_STACK: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0x10_0000, 0x1000)) };
    /// The headers the stand-in RtlImageNtHeader hands out, one per test thread (leaked).
    static IMAGE_HEADERS: *mut ImageNtHeaders32 =
        std::boxed::Box::into_raw(std::boxed::Box::new(Pod::zeroed()));
}

/// RtlImageNtHeader: the process image's headers (at [`IMAGE_BASE`]: a PE32 image's, its
/// subsystem version [`IMAGE_SUBSYSTEM_VERSION`]'s, its stack sizes [`IMAGE_STACK`]'s); null
/// for any other base.
pub unsafe extern "system" fn RtlImageNtHeader(base: usize) -> *const ImageNtHeaders32 {
    if base != IMAGE_BASE as usize {
        return core::ptr::null();
    }
    let (major, minor) = IMAGE_SUBSYSTEM_VERSION.with(std::cell::Cell::get);
    let (stack_reserve, stack_commit) = IMAGE_STACK.with(std::cell::Cell::get);
    let headers = IMAGE_HEADERS.with(|headers| *headers);
    // SAFETY: the thread's own leaked headers, written here alone, between calls.
    unsafe {
        (*headers).signature = rtl::image::NT_SIGNATURE;
        (*headers).optional_header.magic = rtl::image::PE32_MAGIC;
        (*headers).optional_header.major_subsystem_version = major;
        (*headers).optional_header.minor_subsystem_version = minor;
        (*headers).optional_header.size_of_stack_reserve = stack_reserve;
        (*headers).optional_header.size_of_stack_commit = stack_commit;
    }
    headers
}

/// kernel32's GetTickCount alone is an export (by its exact name, or by its ordinal); no name
/// and ordinal 0 is refused first, as ntdll's loader refuses it.
pub unsafe extern "system" fn LdrGetProcedureAddress(
    module: u32,
    name: *const AnsiString,
    ordinal: u32,
    address: *mut u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    if name.is_null() && ordinal == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if !MODULE_PATHS.iter().any(|&(base, _)| base == module) {
        return STATUS_DLL_NOT_FOUND;
    }
    // SAFETY: the caller's string, when given.
    let Some(name) = (unsafe { name.as_ref() }) else {
        if module == KERNEL32 && ordinal == GET_TICK_COUNT_ORDINAL {
            // SAFETY: the caller's address.
            unsafe { address.write(GET_TICK_COUNT) };
            return 0;
        }
        return STATUS_ORDINAL_NOT_FOUND;
    };
    // SAFETY: as above.
    let name = unsafe { core::slice::from_raw_parts(name.buffer, usize::from(name.length)) };
    if module == KERNEL32 && name == b"GetTickCount" {
        // SAFETY: the caller's address.
        unsafe { address.write(GET_TICK_COUNT) };
        return 0;
    }
    STATUS_ENTRYPOINT_NOT_FOUND
}
