//! kernel32's locale and file stand-ins the list box reaches: CompareStringW as an ordinal
//! comparison ignoring ASCII case, and a file system with nothing in it (FindFirstFileW finds no
//! file, the current directory is C:\ and cannot change).

use super::LAST_ERROR;
use crate::imports::FindData;

/// ERROR_FILE_NOT_FOUND: what the empty file system answers for any name.
const ERROR_FILE_NOT_FOUND: u32 = 2;

pub unsafe extern "system" fn GetThreadLocale() -> u32 {
    0x0409
}

pub unsafe extern "system" fn CompareStringW(
    _locale: u32,
    flags: u32,
    a: *const u16,
    a_count: i32,
    b: *const u16,
    b_count: i32,
) -> i32 {
    // SAFETY: the callers' counted strings.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(a, a_count.max(0) as usize),
            core::slice::from_raw_parts(b, b_count.max(0) as usize),
        )
    };
    let fold = |unit: u16| {
        if flags & 1 != 0 && (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - 0x20
        } else {
            unit
        }
    };
    match a
        .iter()
        .map(|&unit| fold(unit))
        .cmp(b.iter().map(|&unit| fold(unit)))
    {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Equal => 2,
        core::cmp::Ordering::Greater => 3,
    }
}

pub unsafe extern "system" fn FindFirstFileW(_pattern: *const u16, _data: *mut FindData) -> usize {
    LAST_ERROR.with(|error| error.set(ERROR_FILE_NOT_FOUND));
    usize::MAX
}

pub unsafe extern "system" fn FindNextFileW(_find: usize, _data: *mut FindData) -> u32 {
    0
}

pub unsafe extern "system" fn FindClose(_find: usize) -> u32 {
    1
}

pub unsafe extern "system" fn GetCurrentDirectoryW(length: u32, buffer: *mut u16) -> u32 {
    let path = [u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0];
    if (length as usize) < path.len() {
        return path.len() as u32;
    }
    // SAFETY: the caller's buffer of `length` units.
    unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), buffer, path.len()) };
    (path.len() - 1) as u32
}

pub unsafe extern "system" fn SetCurrentDirectoryW(_path: *const u16) -> u32 {
    LAST_ERROR.with(|error| error.set(ERROR_FILE_NOT_FOUND));
    0
}

pub unsafe extern "system" fn GetFileAttributesW(_path: *const u16) -> u32 {
    LAST_ERROR.with(|error| error.set(ERROR_FILE_NOT_FOUND));
    u32::MAX
}

pub unsafe extern "system" fn GetLogicalDrives() -> u32 {
    1 << 2
}
