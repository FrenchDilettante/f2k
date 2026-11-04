//! The programs' file system calls beyond reading a file: names resolved, files found by a
//! pattern, files and directories created, deleted, copied and moved, a file written, and the
//! local time set. Each kernel32 call is imported by name and wrapped once, safely; a path is
//! handed over NUL-terminated in a buffer of MAX_PATH units, as src/sys.rs hands one.

use crate::output::Error;
use crate::sys::MAX_PATH;
use crate::SystemTime;

/// ERROR_FILENAME_EXCED_RANGE: a path longer than a buffer of MAX_PATH units holds.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// GetFileAttributesW's failure.
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
/// CreateFileW's and FindFirstFileW's failure.
const INVALID_HANDLE_VALUE: usize = usize::MAX;
/// CreateFileW's access, sharing, dispositions and attributes for a file written.
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_ALWAYS: u32 = 4;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// SetFilePointer's origin: the file's end; and its failure.
const FILE_END: u32 = 2;
const INVALID_SET_FILE_POINTER: u32 = u32::MAX;
/// MoveFileExW's flag: an existing file of the new name is replaced.
const MOVEFILE_REPLACE_EXISTING: u32 = 1;

/// WIN32_FIND_DATAW: what FindFirstFileW and FindNextFileW say of a file found.
#[repr(C)]
struct FindData {
    attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    size_high: u32,
    size_low: u32,
    reserved: [u32; 2],
    name: [u16; MAX_PATH],
    alternate_name: [u16; 14],
}

const _: () = assert!(size_of::<FindData>() == 592);

impl FindData {
    const fn empty() -> Self {
        FindData {
            attributes: 0,
            creation_time: [0; 2],
            last_access_time: [0; 2],
            last_write_time: [0; 2],
            size_high: 0,
            size_low: 0,
            reserved: [0; 2],
            name: [0; MAX_PATH],
            alternate_name: [0; 14],
        }
    }
}

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling thread's last error.
    fn GetLastError() -> u32;
    /// A handle closed.
    fn CloseHandle(object: usize) -> i32;
    /// A NUL-terminated path made full (drive, directories, `.` and `..` resolved) into a buffer
    /// of `size` units: its length, the size it needs when it does not fit, zero on failure.
    fn GetFullPathNameW(
        path: *const u16,
        size: u32,
        buffer: *mut u16,
        file_part: *mut usize,
    ) -> u32;
    /// A NUL-terminated path's attributes: INVALID_FILE_ATTRIBUTES when nothing goes by it.
    fn GetFileAttributesW(path: *const u16) -> u32;
    /// A NUL-terminated path's attributes set.
    fn SetFileAttributesW(path: *const u16, attributes: u32) -> i32;
    /// The file a NUL-terminated path names deleted.
    fn DeleteFileW(path: *const u16) -> i32;
    /// A directory created by a NUL-terminated path; no security attributes.
    fn CreateDirectoryW(path: *const u16, security: usize) -> i32;
    /// The empty directory a NUL-terminated path names removed.
    fn RemoveDirectoryW(path: *const u16) -> i32;
    /// A file copied, its attributes and last write time with it; FALSE when `fail_if_exists` and
    /// the new name exists.
    fn CopyFileW(from: *const u16, to: *const u16, fail_if_exists: i32) -> i32;
    /// A file or directory renamed, or moved within its volume.
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    /// The first file a pattern (`*` and `?` in its last component) matches, into `data`: a search
    /// handle, INVALID_HANDLE_VALUE when none matches.
    fn FindFirstFileW(pattern: *const u16, data: *mut FindData) -> usize;
    /// The search's next file, into `data`: FALSE past the last.
    fn FindNextFileW(search: usize, data: *mut FindData) -> i32;
    /// A search handle closed.
    fn FindClose(search: usize) -> i32;
    /// A file opened or created by a NUL-terminated path: its handle, INVALID_HANDLE_VALUE on
    /// failure.
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: usize,
        disposition: u32,
        attributes: u32,
        template: usize,
    ) -> usize;
    /// Bytes to a file.
    fn WriteFile(
        file: usize,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> i32;
    /// A file's position moved: the new position's low dword, INVALID_SET_FILE_POINTER on failure.
    fn SetFilePointer(file: usize, distance: i32, distance_high: *mut i32, method: u32) -> u32;
    /// The local date and time set (the day of the week ignored).
    fn SetLocalTime(time: *const SystemTime) -> i32;
}

/// The calling thread's last error, as an [`Error`].
fn last_error() -> Error {
    // SAFETY: no arguments; it reads the thread's own TEB.
    Error(unsafe { GetLastError() })
}

/// `path` then a NUL, in a buffer of MAX_PATH units: ERROR_FILENAME_EXCED_RANGE when it does not
/// fit.
fn terminated(path: &[u16]) -> Result<[u16; MAX_PATH], Error> {
    if path.len() >= MAX_PATH {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut buffer = [0u16; MAX_PATH];
    buffer[..path.len()].copy_from_slice(path);
    Ok(buffer)
}

/// `path` made full, in `buffer`: the drive and the current directory added to a relative path,
/// `.` and `..` resolved.
#[inline(never)]
pub fn full_path<'a>(path: &[u16], buffer: &'a mut [u16; MAX_PATH]) -> Result<&'a [u16], Error> {
    let path = terminated(path)?;
    let mut file_part = 0;
    // SAFETY: the path ends with a NUL within `path`; the call writes at most MAX_PATH units into
    // `buffer` and a pointer into `file_part`.
    let length = unsafe {
        GetFullPathNameW(
            path.as_ptr(),
            MAX_PATH as u32,
            buffer.as_mut_ptr(),
            &mut file_part,
        )
    } as usize;
    match length {
        0 => Err(last_error()),
        MAX_PATH.. => Err(Error(ERROR_FILENAME_EXCED_RANGE)),
        _ => Ok(&buffer[..length]),
    }
}

/// The attributes of what `path` names (FILE_ATTRIBUTE_*): its error when nothing goes by it.
#[inline(never)]
pub fn attributes(path: &[u16]) -> Result<u32, Error> {
    let path = terminated(path)?;
    // SAFETY: the path ends with a NUL within `path`.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(last_error());
    }
    Ok(attributes)
}

/// The attributes of what `path` names set to `attributes`.
#[inline(never)]
pub fn set_attributes(path: &[u16], attributes: u32) -> Result<(), Error> {
    let path = terminated(path)?;
    // SAFETY: the path ends with a NUL within `path`.
    if unsafe { SetFileAttributesW(path.as_ptr(), attributes) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The file `path` names deleted.
#[inline(never)]
pub fn delete_file(path: &[u16]) -> Result<(), Error> {
    let path = terminated(path)?;
    // SAFETY: the path ends with a NUL within `path`.
    if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// A directory created at `path` (its parent must exist).
#[inline(never)]
pub fn create_directory(path: &[u16]) -> Result<(), Error> {
    let path = terminated(path)?;
    // SAFETY: the path ends with a NUL within `path`; no security attributes.
    if unsafe { CreateDirectoryW(path.as_ptr(), 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The empty directory `path` names removed.
#[inline(never)]
pub fn remove_directory(path: &[u16]) -> Result<(), Error> {
    let path = terminated(path)?;
    // SAFETY: the path ends with a NUL within `path`.
    if unsafe { RemoveDirectoryW(path.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The file `from` copied to `to`, its attributes and last write time with it; an existing `to`
/// is replaced unless `fail_if_exists`.
#[inline(never)]
pub fn copy_file(from: &[u16], to: &[u16], fail_if_exists: bool) -> Result<(), Error> {
    let (from, to) = (terminated(from)?, terminated(to)?);
    // SAFETY: both paths end with a NUL within their buffers.
    if unsafe { CopyFileW(from.as_ptr(), to.as_ptr(), i32::from(fail_if_exists)) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The file or directory `from` renamed to `to`, or moved within its volume; an existing file
/// `to` is replaced when `replace`.
#[inline(never)]
pub fn move_file(from: &[u16], to: &[u16], replace: bool) -> Result<(), Error> {
    let (from, to) = (terminated(from)?, terminated(to)?);
    let flags = if replace {
        MOVEFILE_REPLACE_EXISTING
    } else {
        0
    };
    // SAFETY: both paths end with a NUL within their buffers.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// A file [`find`] found: its name (no directory), attributes and size.
pub struct Found {
    pub attributes: u32,
    /// Its size in bytes.
    pub size: u64,
    name: [u16; MAX_PATH],
    length: usize,
}

impl Found {
    /// The file's name, without its directory.
    pub fn name(&self) -> &[u16] {
        &self.name[..self.length]
    }
}

/// The files a pattern matches ([`find`]), in the directory's order, the search closed when it is
/// dropped.
pub struct Find {
    search: usize,
    /// The entry FindFirstFileW or the last FindNextFileW filled, None once it is handed out.
    next: Option<Found>,
}

impl Find {
    /// The entry `data` holds, owned.
    fn found(data: &FindData) -> Found {
        let length = data
            .name
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(MAX_PATH);
        Found {
            attributes: data.attributes,
            size: u64::from(data.size_high) << 32 | u64::from(data.size_low),
            name: data.name,
            length,
        }
    }
}

impl Iterator for Find {
    type Item = Found;

    fn next(&mut self) -> Option<Found> {
        let found = self.next.take()?;
        let mut data = FindData::empty();
        // SAFETY: the handle is this search's, open while `self` lives; the call writes a
        // WIN32_FIND_DATAW into `data`.
        if unsafe { FindNextFileW(self.search, &mut data) } != 0 {
            self.next = Some(Find::found(&data));
        }
        Some(found)
    }
}

impl Drop for Find {
    fn drop(&mut self) {
        // SAFETY: no pointers; the handle is this value's own, closed once.
        unsafe { FindClose(self.search) };
    }
}

/// The files and directories `pattern` matches, `*` and `?` in its last component as
/// FindFirstFileW reads them (`.` and `..` among them for a pattern matching them): the error
/// when nothing matches (ERROR_FILE_NOT_FOUND) or the directory does not exist
/// (ERROR_PATH_NOT_FOUND).
#[inline(never)]
pub fn find(pattern: &[u16]) -> Result<Find, Error> {
    let pattern = terminated(pattern)?;
    let mut data = FindData::empty();
    // SAFETY: the pattern ends with a NUL within `pattern`; the call writes a WIN32_FIND_DATAW
    // into `data`.
    let search = unsafe { FindFirstFileW(pattern.as_ptr(), &mut data) };
    if search == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(Find {
        search,
        next: Some(Find::found(&data)),
    })
}

/// A file [`create_file`] opened for writing, closed when the value is dropped.
pub struct OutputFile(usize);

impl OutputFile {
    /// All of `bytes` written at the file's position.
    pub fn write(&self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let mut written = 0u32;
            // SAFETY: the call reads `bytes.len()` bytes of `bytes` and writes a dword; no
            // OVERLAPPED.
            let done =
                unsafe { WriteFile(self.0, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) };
            if done == 0 {
                return Err(last_error());
            }
            if written == 0 {
                // ERROR_WRITE_FAULT: nothing taken.
                return Err(Error(29));
            }
            bytes = &bytes[(written as usize).min(bytes.len())..];
        }
        Ok(())
    }
}

impl Drop for OutputFile {
    fn drop(&mut self) {
        // SAFETY: no pointers; the handle is this value's own, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The file `path` names opened for writing, others allowed to read it meanwhile: emptied, or
/// created, unless `append`, which keeps its bytes (creating it when it does not exist) and writes
/// after them.
#[inline(never)]
pub fn create_file(path: &[u16], append: bool) -> Result<OutputFile, Error> {
    let path = terminated(path)?;
    let disposition = if append { OPEN_ALWAYS } else { CREATE_ALWAYS };
    // SAFETY: the path ends with a NUL within `path`; no security attributes or template.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            0,
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let file = OutputFile(handle);
    // Without a high dword, the answer all ones is a failure: a FAT file is shorter than 4 GiB.
    // SAFETY: the handle is the file's; no high dword.
    if append
        && unsafe { SetFilePointer(file.0, 0, core::ptr::null_mut(), FILE_END) }
            == INVALID_SET_FILE_POINTER
    {
        return Err(last_error());
    }
    Ok(file)
}

/// The local date and time set to `time` (its day of the week ignored).
pub fn set_local_time(time: &SystemTime) -> Result<(), Error> {
    // SAFETY: the call reads a SYSTEMTIME.
    if unsafe { SetLocalTime(time) } == 0 {
        return Err(last_error());
    }
    Ok(())
}
