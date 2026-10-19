//! The current directory, where Windows 2000 keeps it: the process parameters' CurrentDirectory (a
//! CURDIR: its DOS path, with its trailing separator, and an open handle to the directory), changed
//! under the PEB lock. RtlSetCurrentDirectory_U opens the new directory (NtOpenFile) before it lets
//! the old one go (NtClose), so a directory that cannot be opened leaves the current one as it was.
//!
//! The DOS paths every Win32 file call takes are made absolute against it here
//! (RtlGetFullPathName_U) and turned into the NT paths the system services take
//! (RtlDosPathNameToNtPathName_U): a relative path under the current directory comes back as a name
//! relative to its handle, which the caller opens through the handle (OBJECT_ATTRIBUTES'
//! RootDirectory), as on Windows 2000.

use rtl::path::{dos_path_to_nt, full_path_name, nt_path, PathError, MAX_PATH};
use rtl::status::{STATUS_NAME_TOO_LONG, STATUS_OBJECT_NAME_INVALID, STATUS_SUCCESS};
use rtl::sys::{self, nr, system_service};

/// A UNICODE_STRING.
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    /// Its units.
    ///
    /// # Safety
    ///
    /// The buffer holds `length` bytes.
    pub(crate) unsafe fn units(&self) -> &[u16] {
        if self.length == 0 {
            return &[];
        }
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts(self.buffer, self.length as usize / 2) }
    }
}

/// The process parameters' CURDIR: CurrentDirectory.DosPath at 0x24, its Handle at 0x2C.
const CURRENT_DIRECTORY: usize = 0x24;
const CURRENT_DIRECTORY_HANDLE: usize = 0x2C;

/// The current directory's DOS path.
fn dos_path() -> &'static mut UnicodeString {
    // SAFETY: the process parameters are mapped for the process's whole life; the DOS path's string
    // is theirs, changed only under the PEB lock.
    unsafe { &mut *((sys::process_parameters() + CURRENT_DIRECTORY) as *mut UnicodeString) }
}

/// NtOpenFile's arguments for a current directory: traverse and synchronize, the share modes
/// Windows 2000 opens it with (read and write: the directory cannot be deleted while it is
/// current), a directory, synchronous I/O; OBJ_CASE_INSENSITIVE | OBJ_INHERIT.
const FILE_TRAVERSE: u32 = 0x20;
const SYNCHRONIZE: u32 = 0x10_0000;
const FILE_SHARE_READ_WRITE: u32 = 0x3;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const OBJ_INHERIT: u32 = 0x2;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// Open the directory at the NT path `name` as a current directory: its handle, or the status.
fn open_directory(name: &[u16]) -> Result<u32, u32> {
    let string = UnicodeString {
        length: (2 * name.len()) as u16,
        maximum_length: (2 * name.len()) as u16,
        buffer: name.as_ptr() as *mut u16,
    };
    let attributes: [u32; 6] = [24, 0, &string as *const UnicodeString as u32, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, 0, 0];
    let mut io_status = [0u32; 2];
    let mut handle = 0u32;
    let args = [
        &mut handle as *mut u32 as u32,
        FILE_TRAVERSE | SYNCHRONIZE,
        attributes.as_ptr() as u32,
        io_status.as_mut_ptr() as u32,
        FILE_SHARE_READ_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    ];
    match system_service(nr::NtOpenFile, &args) {
        STATUS_SUCCESS => Ok(handle),
        status => Err(status),
    }
}

/// RtlSetCurrentDirectory_U: `path` made absolute against the current directory, its trailing
/// separator added, opened (NtOpenFile: a missing directory is the open's status, a file
/// STATUS_NOT_A_DIRECTORY), then the current directory: its DOS path and handle (the old handle
/// closed). STATUS_OBJECT_NAME_INVALID for an empty path, STATUS_NAME_TOO_LONG for one past the DOS
/// path's room.
///
/// # Safety
///
/// `path` is a UNICODE_STRING whose buffer holds its length.
#[unsafe(export_name = "f2k_export_RtlSetCurrentDirectory_U")]
pub unsafe extern "system" fn rtl_set_current_directory_u(path: *const UnicodeString) -> u32 {
    let lock = sys::peb_lock();
    lock.enter(&sys::Native);
    // SAFETY: the caller's string.
    let status = set_current_directory(unsafe { (*path).units() });
    lock.leave(&sys::Native);
    status
}

fn set_current_directory(path: &[u16]) -> u32 {
    let current = dos_path();
    let mut full = [0u16; MAX_PATH + 1];
    // SAFETY: the DOS path's buffer holds its length.
    let made = full_path_name(path, unsafe { current.units() }, &mut full[..MAX_PATH]);
    let mut length = match made {
        Ok((length, _)) => length,
        Err(PathError::Empty) => return STATUS_OBJECT_NAME_INVALID,
        Err(PathError::TooLong) => return STATUS_NAME_TOO_LONG,
    };
    if full[length - 1] != u16::from(b'\\') {
        full[length] = u16::from(b'\\');
        length += 1;
    }
    // The DOS path's room holds the path and its terminator.
    if 2 * (length + 1) > current.maximum_length as usize {
        return STATUS_NAME_TOO_LONG;
    }
    let mut name = [0u16; MAX_PATH + 8];
    let Ok(name_length) = nt_path(&full[..length], &mut name) else {
        return STATUS_NAME_TOO_LONG;
    };
    let handle = match open_directory(&name[..name_length]) {
        Ok(handle) => handle,
        Err(status) => return status,
    };
    let handle_slot = sys::process_parameters() + CURRENT_DIRECTORY_HANDLE;
    let old = sys::read(handle_slot);
    if old != 0 {
        system_service(nr::NtClose, &[old as u32]);
    }
    // SAFETY: the DOS path's own room, checked above to hold the path and its terminator.
    unsafe {
        current.buffer.copy_from_nonoverlapping(full.as_ptr(), length);
        current.buffer.add(length).write(0);
    }
    current.length = (2 * length) as u16;
    sys::write(handle_slot, handle as usize);
    STATUS_SUCCESS
}

/// RtlGetCurrentDirectory_U: the current directory's DOS path into the caller's buffer of
/// `buffer_length` bytes, without its trailing separator (a drive's root keeps it): its length in
/// bytes, or, when it does not fit with its terminator, the bytes it needs (terminator included),
/// nothing written.
///
/// # Safety
///
/// `buffer` holds `buffer_length` bytes.
#[unsafe(export_name = "f2k_export_RtlGetCurrentDirectory_U")]
pub unsafe extern "system" fn rtl_get_current_directory_u(buffer_length: u32, buffer: *mut u16) -> u32 {
    let lock = sys::peb_lock();
    lock.enter(&sys::Native);
    let current = dos_path();
    // SAFETY: the DOS path's buffer holds its length.
    let units = unsafe { current.units() };
    let mut length = units.len();
    if length > 3 && units[length - 1] == u16::from(b'\\') {
        length -= 1;
    }
    let answer = if (buffer_length as usize) < 2 * (length + 1) {
        (2 * (length + 1)) as u32
    } else {
        // SAFETY: the caller's buffer, which holds the path and its terminator.
        unsafe {
            buffer.copy_from_nonoverlapping(units.as_ptr(), length);
            buffer.add(length).write(0);
        }
        (2 * length) as u32
    };
    lock.leave(&sys::Native);
    answer
}

/// The process's first thread's share of the loader's work: open the starting current directory's
/// handle (the kernel names it in the process parameters; a directory that cannot be opened leaves
/// it without one).
pub fn open_starting_directory() {
    let current = dos_path();
    let mut copy = [0u16; MAX_PATH + 1];
    // SAFETY: the DOS path's buffer holds its length.
    let units = unsafe { current.units() };
    let length = units.len().min(MAX_PATH);
    copy[..length].copy_from_slice(&units[..length]);
    if length != 0 {
        let _ = set_current_directory(&copy[..length]);
    }
}

/// RTL_RELATIVE_NAME, Windows 2000's: the name relative to the directory, and the directory's
/// handle.
#[repr(C)]
pub struct RelativeName {
    pub name: UnicodeString,
    pub containing_directory: u32,
}

/// A NUL-terminated string's units (up to UNICODE_STRING's limit).
///
/// # Safety
///
/// `string` points at a NUL-terminated string.
unsafe fn terminated<'a>(string: *const u16) -> &'a [u16] {
    let mut length = 0;
    // SAFETY: the caller's string, read to its terminator.
    while length < 0x7FFF && unsafe { string.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: as above.
    unsafe { core::slice::from_raw_parts(string, length) }
}

/// The current directory's DOS path and handle, copied under the PEB lock into `out`: its length.
pub(crate) fn current_directory(out: &mut [u16; MAX_PATH + 1]) -> (usize, u32) {
    let lock = sys::peb_lock();
    lock.enter(&sys::Native);
    // SAFETY: the DOS path's buffer holds its length.
    let units = unsafe { dos_path().units() };
    let length = units.len().min(MAX_PATH);
    out[..length].copy_from_slice(&units[..length]);
    let handle = sys::read(sys::process_parameters() + CURRENT_DIRECTORY_HANDLE) as u32;
    lock.leave(&sys::Native);
    (length, handle)
}

/// The NT path's buffer, in units: a full DOS path's room and the longest prefix (`\??\UNC`).
const NT_ROOM: usize = MAX_PATH + 8;

/// RtlDosPathNameToNtPathName_U: the NT path of a DOS path (see [`rtl::path::dos_path_to_nt`]), in
/// a buffer on the process heap the caller frees (RtlFreeHeap), with its file part, and, when asked
/// and the path is relative and under the current directory, the name relative to the current
/// directory's handle (RTL_RELATIVE_NAME; zeros otherwise). FALSE for an empty path, one whose full
/// form does not fit MAX_PATH, or no room on the heap.
///
/// # Safety
///
/// `dos` is a NUL-terminated string; `nt` points at a UNICODE_STRING; `file_part` and `relative`
/// are null or point at their structures.
#[unsafe(export_name = "f2k_export_RtlDosPathNameToNtPathName_U")]
pub unsafe extern "system" fn rtl_dos_path_name_to_nt_path_name_u(
    dos: *const u16,
    nt: *mut UnicodeString,
    file_part: *mut *mut u16,
    relative: *mut RelativeName,
) -> u32 {
    // SAFETY: the caller's string.
    let path = unsafe { terminated(dos) };
    let mut current = [0u16; MAX_PATH + 1];
    let (current_length, handle) = current_directory(&mut current);
    let heap = sys::process_heap();
    let Some(buffer) = heap.alloc(&sys::Native, 0, 2 * NT_ROOM) else {
        return 0;
    };
    // SAFETY: a fresh block of NT_ROOM units.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u16, NT_ROOM) };
    let name = match dos_path_to_nt(path, &current[..current_length], handle != 0, out) {
        Ok(name) => name,
        Err(_) => {
            heap.free(&sys::Native, 0, buffer);
            return 0;
        }
    };
    let base = buffer as *mut u16;
    // SAFETY: the caller's structures; the pointers stay inside the block.
    unsafe {
        *nt = UnicodeString { length: (2 * name.length) as u16, maximum_length: (2 * NT_ROOM) as u16, buffer: base };
        if !file_part.is_null() {
            *file_part = name.file_part.map_or(core::ptr::null_mut(), |at| base.add(at));
        }
        if !relative.is_null() {
            *relative = match name.relative {
                Some(at) => RelativeName {
                    name: UnicodeString {
                        length: (2 * (name.length - at)) as u16,
                        maximum_length: (2 * (name.length - at)) as u16,
                        buffer: base.add(at),
                    },
                    containing_directory: handle,
                },
                None => RelativeName {
                    name: UnicodeString { length: 0, maximum_length: 0, buffer: core::ptr::null_mut() },
                    containing_directory: 0,
                },
            };
        }
    }
    1
}

/// RtlGetFullPathName_U: a DOS path made absolute against the current directory and folded (see
/// [`rtl::path::full_path_name`]) into the caller's buffer of `buffer_length` bytes: its length in
/// bytes, the file part pointed at (null when the path ends in a separator); when it does not fit
/// with its terminator, the bytes it needs (terminator included), nothing written; zero for an
/// empty path.
///
/// # Safety
///
/// `path` is a NUL-terminated string; `buffer` holds `buffer_length` bytes; `file_part` is null or
/// points at a pointer.
#[unsafe(export_name = "f2k_export_RtlGetFullPathName_U")]
pub unsafe extern "system" fn rtl_get_full_path_name_u(
    path: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    // SAFETY: the caller's string.
    let path = unsafe { terminated(path) };
    let mut current = [0u16; MAX_PATH + 1];
    let (current_length, _) = current_directory(&mut current);
    let mut full = [0u16; 4 * MAX_PATH];
    let Ok((length, part)) = full_path_name(path, &current[..current_length], &mut full) else {
        return 0;
    };
    if (buffer_length as usize) < 2 * (length + 1) {
        return (2 * (length + 1)) as u32;
    }
    // SAFETY: the caller's buffer holds the path and its terminator.
    unsafe {
        buffer.copy_from_nonoverlapping(full.as_ptr(), length + 1);
        if !file_part.is_null() {
            *file_part = part.map_or(core::ptr::null_mut(), |at| buffer.add(at));
        }
    }
    (2 * length) as u32
}
