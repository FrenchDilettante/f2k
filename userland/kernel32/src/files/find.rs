//! The directory searches: FindFirstFile, FindNextFile (A and W) and FindClose over
//! NtQueryDirectoryFile, as Windows 2000's kernel32 makes them. A find handle is kernel32's own
//! structure on the process heap (FINDFILE_HANDLE: the directory's handle, a listing buffer and the
//! lock over them), not a kernel handle.
//!
//! FindFirstFile opens the pattern's directory for listing and asks for its first match, the
//! pattern given as the expression after FindFirstFileExW's transformations: `*.*` alone is `*`; a
//! `?` is DOS_QM, a `*` before a dot DOS_STAR, a dot before a wildcard DOS_DOT, and a `*` ending a
//! pattern that ended in a dot (before ntdll trimmed it) DOS_STAR. FindNextFile continues the
//! search a buffer's worth at a time.

use rtl::status::nt_success;

use super::*;
use crate::base::set_last_nt_error;

/// The DOS wildcards.
const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;

/// FindNextFile's listing buffer.
const FIND_BUFFER_SIZE: usize = 4096;

/// A FILE_BOTH_DIR_INFORMATION record's fields.
const NEXT_ENTRY: usize = 0;
const NAME_LENGTH: usize = 60;
const SHORT_NAME_LENGTH: usize = 68;
const SHORT_NAME: usize = 70;
const NAME: usize = 94;

/// A WIN32_FIND_DATAW.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FindDataW {
    /// The attributes, the three times, the size (high dword first) and two reserved dwords.
    pub head: [u8; 44],
    pub name: [u16; MAX_PATH],
    pub alternate: [u16; 14],
}

impl FindDataW {
    pub fn zeroed() -> FindDataW {
        FindDataW {
            head: [0; 44],
            name: [0; MAX_PATH],
            alternate: [0; 14],
        }
    }

    fn until_nul(units: &[u16]) -> &[u16] {
        &units[..units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len())]
    }

    /// The name.
    pub fn name(&self) -> &[u16] {
        Self::until_nul(&self.name)
    }

    /// The 8.3 name beside a long one (empty without).
    pub fn alternate(&self) -> &[u16] {
        Self::until_nul(&self.alternate)
    }

    /// Fill it from a FILE_BOTH_DIR_INFORMATION record.
    fn fill(&mut self, record: &[u8]) {
        let field = |at: usize| word(record, at);
        self.head = [0; 44];
        self.head[..4].copy_from_slice(&record[56..60]);
        self.head[4..28].copy_from_slice(&record[8..32]);
        self.head[28..32].copy_from_slice(&record[44..48]);
        self.head[32..36].copy_from_slice(&record[40..44]);
        let units = |at: usize, bytes: usize, out: &mut [u16]| {
            let count = (bytes / 2).min(out.len() - 1);
            for (index, unit) in out.iter_mut().enumerate().take(count) {
                *unit = u16::from_le_bytes([record[at + 2 * index], record[at + 2 * index + 1]]);
            }
            out[count] = 0;
        };
        units(NAME, field(NAME_LENGTH) as usize, &mut self.name);
        units(
            SHORT_NAME,
            record[SHORT_NAME_LENGTH] as usize,
            &mut self.alternate,
        );
    }

    /// Its WIN32_FIND_DATAA form into `out`: the names through the ANSI code page, each an
    /// ANSI_STRING over its array (ntdll's RtlUnicodeStringToAnsiString: what fits, terminated).
    ///
    /// # Safety
    ///
    /// `out` points at a WIN32_FIND_DATAA.
    unsafe fn narrow_into(&self, out: *mut u8) {
        // SAFETY: the caller's structure: its head, then cFileName[260] and cAlternateFileName[14].
        unsafe {
            out.copy_from_nonoverlapping(self.head.as_ptr(), 44);
            let put = |at: usize, units: &[u16], room: usize| {
                let source = UnicodeString::from_units(units).expect("a name of MAX_PATH");
                let mut name = nt::AnsiString {
                    length: 0,
                    maximum_length: room as u16,
                    buffer: out.add(at),
                };
                nt::RtlUnicodeStringToAnsiString(&mut name, &source, 0);
            };
            put(44, self.name(), MAX_PATH);
            put(304, self.alternate(), 14);
        }
    }
}

/// FINDFILE_HANDLE, Windows 2000's: the directory's handle, the listing buffer (made at the first
/// FindNextFile) and where its next record starts, and the lock over them.
#[repr(C)]
struct FindHandle {
    directory: u32,
    buffer: *mut u8,
    next: *mut u8,
    lock: [u8; 24],
}

/// FindFirstFileExW's transformation of a pattern, in place: see the module's.
fn transform(pattern: &mut [u16], ends_in_dot: bool) -> usize {
    let (star, question, dot) = (u16::from(b'*'), u16::from(b'?'), u16::from(b'.'));
    if pattern == [star, dot, star] {
        return 1;
    }
    for index in 0..pattern.len() {
        if index > 0 && pattern[index] == dot && pattern[index - 1] == star {
            pattern[index - 1] = DOS_STAR;
        }
        if pattern[index] == question || pattern[index] == star {
            if pattern[index] == question {
                pattern[index] = DOS_QM;
            }
            if index > 0 && pattern[index - 1] == dot {
                pattern[index - 1] = DOS_DOT;
            }
        }
    }
    if ends_in_dot && pattern.last() == Some(&star) {
        *pattern.last_mut().expect("not empty") = DOS_STAR;
    }
    pattern.len()
}

/// FindFirstFileExW's work for a standard search: the pattern's directory opened for listing (a
/// missing one STATUS_OBJECT_PATH_NOT_FOUND, never the name's not-found), its first match into
/// `data`; the find handle, or INVALID_HANDLE_VALUE with the error (a pattern matching nothing
/// STATUS_NO_SUCH_FILE, a path ending in a separator ERROR_FILE_NOT_FOUND). Not inlined: its
/// buffers stay off its callers' frames (kernel32's frames stay within a page, no stack probe).
#[inline(never)]
pub fn find_first_w(pattern: &Wide, data: &mut FindDataW) -> u32 {
    let ends_in_dot = pattern.text().last() == Some(&u16::from(b'.'));
    let Some(path) = NtPath::of(pattern.terminated()) else {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    let full = path.units();
    let base = full.as_ptr() as usize;
    let file_start = if path.file_part.is_null() {
        full.len()
    } else {
        (path.file_part as usize - base) / 2
    };
    // The directory's name: the relative name up to the file part, when ntdll made one that starts
    // before it, else the whole path up to it.
    let relative_start = (path.root != 0)
        .then(|| (path.name.buffer as usize - base) / 2)
        .filter(|&start| start < file_start);
    let (root, start) = match relative_start {
        Some(start) => (path.root, start),
        None => (0, 0),
    };
    let mut directory = &full[start..file_start];
    let backslash = u16::from(b'\\');
    let stripped = directory.len() >= 2
        && directory[directory.len() - 2] != u16::from(b':')
        && directory.last() == Some(&backslash);
    if stripped {
        directory = &directory[..directory.len() - 1];
    }
    let open_directory = |units: &[u16]| {
        // Part of the NT path, itself a counted string.
        let name = UnicodeString::from_units(units).expect("part of a counted string");
        let attributes = ObjectAttributes {
            length: 24,
            root_directory: root,
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        };
        let mut handle = 0;
        let mut io_status = IoStatus::default();
        // SAFETY: ntdll's export, over the attributes above.
        let status = unsafe {
            nt::NtOpenFile(
                &mut handle,
                FILE_LIST_DIRECTORY | SYNCHRONIZE,
                &attributes,
                &mut io_status,
                FILE_SHARE_ALL,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
            )
        };
        (status, handle)
    };
    let (mut status, mut handle) = open_directory(directory);
    if (status == STATUS_INVALID_PARAMETER || status == STATUS_NOT_A_DIRECTORY) && stripped {
        (status, handle) = open_directory(&full[start..file_start]);
    }
    if !nt_success(status) {
        if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_TYPE_MISMATCH {
            status = STATUS_OBJECT_PATH_NOT_FOUND;
        }
        set_last_nt_error(status);
        return INVALID_HANDLE_VALUE;
    }
    if file_start == full.len() {
        close(handle);
        set_last_error(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    let mut expression = [0u16; MAX_PATH + 8];
    let count = full.len() - file_start;
    expression[..count].copy_from_slice(&full[file_start..]);
    let count = transform(&mut expression[..count], ends_in_dot);
    drop(path);
    let name = UnicodeString::from_units(&expression[..count]).expect("a name of MAX_PATH");
    let mut record = [0u8; NAME + 2 * MAX_PATH + 8];
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the buffer above.
    let status = unsafe {
        nt::NtQueryDirectoryFile(
            handle,
            0,
            0,
            0,
            &mut io_status,
            record.as_mut_ptr(),
            record.len() as u32,
            FILE_BOTH_DIRECTORY_INFORMATION,
            1,
            &name,
            0,
        )
    };
    if !nt_success(status) {
        close(handle);
        set_last_nt_error(status);
        return INVALID_HANDLE_VALUE;
    }
    data.fill(&record);
    let Some(find) = ntcall::allocate_heap(core::mem::size_of::<FindHandle>()) else {
        close(handle);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    };
    let find = find.as_ptr().cast::<FindHandle>();
    // SAFETY: the fresh block; its lock initialized in place.
    unsafe {
        find.write(FindHandle {
            directory: handle,
            buffer: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            lock: [0; 24],
        });
        nt::RtlInitializeCriticalSection((*find).lock.as_mut_ptr());
    }
    find as u32
}

/// FindNextFileW's work: the next record of the listing buffer, the buffer refilled from the
/// directory (NtQueryDirectoryFile) once it runs out — STATUS_NO_MORE_FILES when the search has —
/// under the handle's lock. INVALID_HANDLE_VALUE is ERROR_INVALID_HANDLE.
pub fn find_next_w(find: u32, data: &mut FindDataW) -> u32 {
    if find == INVALID_HANDLE_VALUE {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // SAFETY: a find handle FindFirstFile made (another pointer faults the caller, as on Windows).
    let find = unsafe { &mut *(find as *mut FindHandle) };
    // SAFETY: ntdll's export, over the handle's lock.
    unsafe { nt::RtlEnterCriticalSection(find.lock.as_mut_ptr()) };
    let answer = (|| {
        if find.buffer.is_null() {
            find.buffer = ntcall::allocate_heap(FIND_BUFFER_SIZE)
                .map_or(core::ptr::null_mut(), |block| block.as_ptr());
            if find.buffer.is_null() {
                set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                return 0;
            }
            find.next = core::ptr::null_mut();
        }
        if find.next.is_null() {
            let mut io_status = IoStatus::default();
            // SAFETY: ntdll's export, into the handle's buffer.
            let status = unsafe {
                nt::NtQueryDirectoryFile(
                    find.directory,
                    0,
                    0,
                    0,
                    &mut io_status,
                    find.buffer,
                    FIND_BUFFER_SIZE as u32,
                    FILE_BOTH_DIRECTORY_INFORMATION,
                    0,
                    core::ptr::null(),
                    0,
                )
            };
            if !nt_success(status) {
                set_last_nt_error(status);
                return 0;
            }
            find.next = find.buffer;
        }
        // SAFETY: a record inside the buffer the listing filled.
        let record = unsafe {
            core::slice::from_raw_parts(
                find.next,
                FIND_BUFFER_SIZE - (find.next as usize - find.buffer as usize),
            )
        };
        data.fill(record);
        let next = word(record, NEXT_ENTRY) as usize;
        // SAFETY: the next record, inside the buffer.
        find.next = if next == 0 {
            core::ptr::null_mut()
        } else {
            unsafe { find.next.add(next) }
        };
        1
    })();
    // SAFETY: as above.
    unsafe { nt::RtlLeaveCriticalSection(find.lock.as_mut_ptr()) };
    answer
}

/// FindClose's work: the directory's handle closed, the buffer and the handle freed.
/// INVALID_HANDLE_VALUE and null are ERROR_INVALID_HANDLE.
pub fn find_close(find: u32) -> u32 {
    if find == INVALID_HANDLE_VALUE || find == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    let handle = find as *mut FindHandle;
    // SAFETY: a find handle FindFirstFile made; ntdll's exports over its parts.
    unsafe {
        close((*handle).directory);
        if !(*handle).buffer.is_null() {
            ntcall::free_heap((*handle).buffer);
        }
        nt::RtlDeleteCriticalSection((*handle).lock.as_mut_ptr());
        ntcall::free_heap(handle.cast());
    }
    1
}

/// FindFirstFileA: the pattern converted, the search opened ([`find_first_w`]), its first match in
/// the caller's WIN32_FIND_DATAA.
///
/// # Safety
///
/// `pattern` is a NUL-terminated string; `data` points at a WIN32_FIND_DATAA.
#[unsafe(export_name = "f2k_export_FindFirstFileA")]
pub unsafe extern "system" fn find_first_file_a(pattern: *const u8, data: *mut u8) -> u32 {
    // SAFETY: the caller's string.
    let Some(pattern) = (unsafe { widen(pattern) }) else {
        return INVALID_HANDLE_VALUE;
    };
    let mut found = FindDataW::zeroed();
    let find = find_first_w(&pattern, &mut found);
    if find != INVALID_HANDLE_VALUE {
        // SAFETY: the caller's structure.
        unsafe { found.narrow_into(data) };
    }
    find
}

/// FindFirstFileW: the pattern copied ([`wide`]), the search opened ([`find_first_w`]), its first
/// match in the caller's WIN32_FIND_DATAW.
///
/// # Safety
///
/// `pattern` is a NUL-terminated UTF-16 string; `data` points at a WIN32_FIND_DATAW.
#[unsafe(export_name = "f2k_export_FindFirstFileW")]
pub unsafe extern "system" fn find_first_file_w(pattern: *const u16, data: *mut FindDataW) -> u32 {
    // SAFETY: the caller's string.
    let Some(pattern) = (unsafe { wide(pattern) }) else {
        return INVALID_HANDLE_VALUE;
    };
    let mut found = FindDataW::zeroed();
    let find = find_first_w(&pattern, &mut found);
    if find != INVALID_HANDLE_VALUE {
        // SAFETY: the caller's structure.
        unsafe { data.write_unaligned(found) };
    }
    find
}

/// FindNextFileA: the search's next match ([`find_next_w`]); ERROR_NO_MORE_FILES when it has none.
///
/// # Safety
///
/// `find` is a find handle; `data` points at a WIN32_FIND_DATAA.
#[unsafe(export_name = "f2k_export_FindNextFileA")]
pub unsafe extern "system" fn find_next_file_a(find: u32, data: *mut u8) -> u32 {
    let mut found = FindDataW::zeroed();
    if find_next_w(find, &mut found) == 0 {
        return 0;
    }
    // SAFETY: the caller's structure.
    unsafe { found.narrow_into(data) };
    1
}

/// FindNextFileW: the search's next match ([`find_next_w`]) in the caller's WIN32_FIND_DATAW.
///
/// # Safety
///
/// `find` is a find handle; `data` points at a WIN32_FIND_DATAW.
#[unsafe(export_name = "f2k_export_FindNextFileW")]
pub unsafe extern "system" fn find_next_file_w(find: u32, data: *mut FindDataW) -> u32 {
    let mut found = FindDataW::zeroed();
    if find_next_w(find, &mut found) == 0 {
        return 0;
    }
    // SAFETY: the caller's structure.
    unsafe { data.write_unaligned(found) };
    1
}

/// FindClose: end a search ([`find_close`]).
///
/// # Safety
///
/// `find` is a find handle.
#[unsafe(export_name = "f2k_export_FindClose")]
pub unsafe extern "system" fn find_close_export(find: u32) -> u32 {
    find_close(find)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transformed(pattern: &str, ends_in_dot: bool) -> String {
        let mut units: Vec<u16> = pattern.encode_utf16().collect();
        let count = transform(&mut units, ends_in_dot);
        String::from_utf16(&units[..count]).unwrap()
    }

    /// FindFirstFileExW's transformations.
    #[test]
    fn patterns_become_expressions() {
        assert_eq!(transformed("*.*", false), "*");
        assert_eq!(transformed("*", false), "*");
        assert_eq!(transformed("*.TXT", false), "<.TXT");
        assert_eq!(transformed("?????.TXT", false), ">>>>>.TXT");
        assert_eq!(transformed("A.*", false), "A\"*");
        assert_eq!(transformed("S*", false), "S*");
        assert_eq!(transformed("*", true), "<", "`*.` after ntdll's trim");
        assert_eq!(transformed("SMALL.TXT", false), "SMALL.TXT");
    }
}
