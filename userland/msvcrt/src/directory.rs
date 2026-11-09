//! The current directory and full paths (direct.h's and stdlib.h's): _getdcwd, a drive's current
//! directory, and _wfullpath, a name made a full path.
//!
//! As MSDN documents them: _wfullpath is GetFullPathNameW's answer; with a NULL buffer it
//! allocates one of `_MAX_PATH` characters and ignores the size; a NULL or empty name answers the
//! current directory. _getdcwd answers the current directory of drive `drive` (1 for A:, 0 for the
//! current drive); with a NULL buffer it allocates one of at least `maxlen` bytes, more if the
//! path needs it. A path longer than the buffer is NULL with errno ERANGE; a drive that does not
//! exist is NULL with errno EACCES (_doserrno ERROR_INVALID_DRIVE).
//!
//! Windows keeps each drive's current directory for the process (its `=X:` variables), and
//! GetFullPathNameA of `X:.` reads it: _getdcwd asks it so for a drive other than the current one.

use core::ffi::CStr;

use crate::edge;
use crate::kernel32::{self, PathError, Win32Error};
use crate::thread::{set_dos_error, set_doserrno, set_errno, EACCES, ENOMEM, ERANGE};

/// `_MAX_PATH`: the characters a path holds, its NUL included.
const MAX_PATH: usize = 260;

/// ERROR_INVALID_DRIVE.
const ERROR_INVALID_DRIVE: u32 = 15;

/// GetDriveType's answer for a root that does not exist.
const DRIVE_NO_ROOT_DIR: u32 = 1;

/// A path call's failure as errno says it: ERANGE for a path longer than the buffer, the call's
/// error otherwise.
fn report(error: PathError) {
    match error {
        PathError::Needs(_) => set_errno(ERANGE),
        PathError::Failed(Win32Error(error)) => set_dos_error(error),
    }
}

/// _wfullpath: the full path of `name` into `buffer` of `size` characters, or into a block of
/// `_MAX_PATH` from malloc when `buffer` is NULL; answers the buffer, or NULL (errno).
///
/// # Safety
///
/// `buffer` is null or holds `size` characters; `name` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export__wfullpath")]
pub unsafe extern "C" fn wfullpath(buffer: *mut u16, name: *const u16, size: usize) -> *mut u16 {
    let length = if name.is_null() {
        0
    } else {
        // SAFETY: the caller's string.
        unsafe { edge::wide(name) }.len()
    };
    let (out, size) = if buffer.is_null() {
        let block = crate::heap::allocate(MAX_PATH * 2, false).cast::<u16>();
        if block.is_null() {
            set_errno(ENOMEM);
            return block;
        }
        (block, MAX_PATH)
    } else {
        (buffer, size)
    };
    // SAFETY: the caller's buffer of `size` characters, or the block just allocated.
    let units = unsafe { edge::wide_parts_mut(out, size) };
    let answer = if length == 0 {
        kernel32::current_directory_w(units)
    } else {
        // SAFETY: the caller's string, its NUL included.
        kernel32::full_path_w(unsafe { edge::wide_parts(name, length + 1) }, units)
    };
    match answer {
        Ok(_) => out,
        Err(error) => {
            if buffer.is_null() {
                // SAFETY: the block allocated above, not handed out.
                unsafe { crate::heap::release(out.cast()) };
            }
            report(error);
            core::ptr::null_mut()
        }
    }
}

/// The current directory of `drive` (0 the current drive, 1 A:) into `out`: its length.
fn drive_directory(drive: i32, out: &mut [u8]) -> Result<usize, PathError> {
    let current = kernel32::current_directory_a(out)?;
    if drive == 0 {
        return Ok(current);
    }
    let letter = b'A' + (drive - 1) as u8;
    if out[0].to_ascii_uppercase() == letter && out[1] == b':' {
        return Ok(current);
    }
    let spec = [letter, b':', b'.', 0];
    kernel32::full_path_a(CStr::from_bytes_with_nul(&spec).unwrap_or_default(), out)
}

/// Whether drive `drive` (1 A: to 26 Z:) exists: its root has a type.
fn drive_exists(drive: i32) -> bool {
    if !(1..=26).contains(&drive) {
        return false;
    }
    let root = [b'A' + (drive - 1) as u8, b':', b'\\', 0];
    let root = CStr::from_bytes_with_nul(&root).unwrap_or_default();
    kernel32::drive_type(root) != DRIVE_NO_ROOT_DIR
}

/// _getdcwd: the current directory of drive `drive` (0 the current one) into `buffer` of `size`
/// bytes, or into a block from malloc of at least `size` bytes when `buffer` is NULL; answers the
/// buffer, or NULL (errno).
///
/// # Safety
///
/// `buffer` is null or holds `size` bytes.
#[unsafe(export_name = "f2k_export__getdcwd")]
pub unsafe extern "C" fn getdcwd(drive: i32, buffer: *mut u8, size: i32) -> *mut u8 {
    if drive != 0 && !drive_exists(drive) {
        set_errno(EACCES);
        set_doserrno(ERROR_INVALID_DRIVE);
        return core::ptr::null_mut();
    }
    let mut path = [0u8; MAX_PATH];
    let length = match drive_directory(drive, &mut path) {
        Ok(length) => length,
        Err(error) => {
            report(error);
            return core::ptr::null_mut();
        }
    };
    let size = size.max(0) as usize;
    let out = if buffer.is_null() {
        let block = crate::heap::allocate(size.max(length + 1), false);
        if block.is_null() {
            set_errno(ENOMEM);
            return block;
        }
        block
    } else if length < size {
        buffer
    } else {
        set_errno(ERANGE);
        return core::ptr::null_mut();
    };
    // SAFETY: the caller's buffer, or the block just allocated: room for the path and its NUL.
    let room = unsafe { core::slice::from_raw_parts_mut(out, length + 1) };
    room[..length].copy_from_slice(&path[..length]);
    room[length] = 0;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::CURRENT_DIRECTORY;
    use crate::thread::errno;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn text_of(units: *const u16) -> String {
        // SAFETY: a terminated string the call wrote.
        String::from_utf16_lossy(&edge::units(unsafe { edge::wide(units) }).collect::<Vec<_>>())
    }

    /// _wfullpath into the caller's buffer, into one it allocates, and its failures: a path longer
    /// than the buffer (ERANGE, an allocated block given back); an empty name answers the current
    /// directory.
    #[test]
    fn wfullpath_fills_a_buffer_or_allocates_one() {
        crate::heap::initialize();
        let name = wide("fullpath.tmp");
        let mut buffer = [0u16; 64];
        // SAFETY: a buffer of 64 characters; a terminated name.
        unsafe {
            let got = wfullpath(buffer.as_mut_ptr(), name.as_ptr(), 64);
            assert_eq!(got, buffer.as_mut_ptr());
            assert_eq!(text_of(got), "C:\\CORPUS\\fullpath.tmp");
            let got = wfullpath(core::ptr::null_mut(), name.as_ptr(), 3);
            assert_eq!(text_of(got), "C:\\CORPUS\\fullpath.tmp");
            assert!(crate::heap::size_of(got.cast()) >= MAX_PATH * 2);
            crate::heap::release(got.cast());
            set_errno(0);
            assert!(wfullpath(buffer.as_mut_ptr(), name.as_ptr(), 3).is_null());
            assert_eq!(errno(), ERANGE);
            let got = wfullpath(buffer.as_mut_ptr(), wide("").as_ptr(), 64);
            assert_eq!(text_of(got), "C:\\CORPUS");
            let got = wfullpath(buffer.as_mut_ptr(), core::ptr::null(), 64);
            assert_eq!(text_of(got), "C:\\CORPUS");
        }
    }

    /// _getdcwd of the current drive (0, or its number), of another drive (its `X:.`), of one that
    /// does not exist (EACCES); a NULL buffer allocates at least the size asked; a buffer too small
    /// is ERANGE.
    #[test]
    fn getdcwd_answers_a_drives_directory() {
        crate::heap::initialize();
        CURRENT_DIRECTORY.with(|directory| *directory.borrow_mut() = String::from("C:\\CORPUS"));
        let text = |at: *const u8| {
            // SAFETY: a terminated string the call wrote.
            String::from_utf8_lossy(unsafe { rtl::cstr::bytes_until_nul(at) }).into_owned()
        };
        let mut buffer = [0u8; 64];
        // SAFETY: a buffer of 64 bytes.
        unsafe {
            for drive in [0, 3] {
                let got = getdcwd(drive, buffer.as_mut_ptr(), 64);
                assert_eq!((got, text(got)), (buffer.as_mut_ptr(), "C:\\CORPUS".into()));
            }
            assert_eq!(text(getdcwd(4, buffer.as_mut_ptr(), 64)), "D:.");
            for drive in [5, 27, -1] {
                set_errno(0);
                assert!(getdcwd(drive, buffer.as_mut_ptr(), 64).is_null());
                assert_eq!(errno(), EACCES, "drive {drive}");
            }
            let got = getdcwd(0, core::ptr::null_mut(), 1000);
            assert_eq!(text(got), "C:\\CORPUS");
            assert!(crate::heap::size_of(got) >= 1000);
            crate::heap::release(got);
            let got = getdcwd(0, core::ptr::null_mut(), 2);
            assert_eq!(text(got), "C:\\CORPUS");
            crate::heap::release(got);
            set_errno(0);
            assert!(getdcwd(0, buffer.as_mut_ptr(), 9).is_null());
            assert_eq!(errno(), ERANGE);
            assert!(!getdcwd(0, buffer.as_mut_ptr(), 10).is_null());
        }
    }
}
