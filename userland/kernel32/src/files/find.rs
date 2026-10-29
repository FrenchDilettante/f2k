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

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use rtl::critsec::CriticalSection;

use super::*;
use crate::edge::OutBuf;
use crate::error::{answer, bool_answer};
use crate::heap::{HeapArray, Owned};

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

/// A WIN32_FIND_DATAA's size, and where its names start: cFileName[260], cAlternateFileName[14].
const FIND_DATA_A: usize = 318;
const NAME_A: usize = 44;
const ALTERNATE_A: usize = NAME_A + MAX_PATH;

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

    /// Its WIN32_FIND_DATAA form into the caller's: the head as it is, the names through the ANSI
    /// code page, each an ANSI_STRING over its array (ntdll's RtlUnicodeStringToAnsiString: what
    /// fits, terminated).
    fn narrow_into(&self, mut out: OutBuf<'_, u8>) {
        out.put(&self.head);
        let mut name = out.reborrow().tail(NAME_A).head(MAX_PATH);
        ntcall::unicode_string_to_ansi(&mut name, self.name());
        let mut alternate = out.tail(ALTERNATE_A).head(14);
        ntcall::unicode_string_to_ansi(&mut alternate, self.alternate());
    }
}

/// A search's listing: the buffer (made at the first FindNextFile) and where its next record
/// starts (none: the buffer is to be filled).
struct Listing {
    buffer: Option<HeapArray<u8>>,
    next: Option<usize>,
}

/// FINDFILE_HANDLE, as Windows 2000's: the directory's handle, the listing, and the lock over it.
struct FindHandle {
    directory: Owned,
    lock: CriticalSection,
    listing: UnsafeCell<Listing>,
}

impl FindHandle {
    /// `body` over the listing, under the handle's lock.
    fn with<R>(&self, body: impl FnOnce(&mut Listing) -> R) -> R {
        let _entered = ntcall::Entered::enter(&self.lock);
        // SAFETY: the handle's lock is held, so no other thread reaches the listing until it is
        // left; and the bodies (FindNextFile's refill and step) never reach the handle again, so
        // this thread holds no other borrow of it.
        body(unsafe { &mut *self.listing.get() })
    }
}

/// A search FindFirstFile opened: its FINDFILE_HANDLE on the process heap, closed when dropped
/// (the directory's handle, the buffer, the lock and the block given back) unless handed out.
pub struct Search(NonNull<FindHandle>);

impl Search {
    /// A search over the open directory; ERROR_NOT_ENOUGH_MEMORY (the directory closed) when the
    /// heap has no room for its handle.
    fn open(directory: Owned) -> Result<Search, Failure> {
        let block = ntcall::allocate_heap(core::mem::size_of::<FindHandle>())
            .ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?
            .cast::<FindHandle>();
        // SAFETY: the fresh block, of a handle's size, 8-byte aligned (the heap's blocks are),
        // the search's own.
        unsafe {
            block.write(FindHandle {
                directory,
                lock: CriticalSection::new(),
                listing: UnsafeCell::new(Listing {
                    buffer: None,
                    next: None,
                }),
            })
        };
        let search = Search(block);
        // Initialized in place, where it stays; with no event preallocated it cannot fail.
        let _ = ntcall::initialize_critical_section(&search.handle().lock);
        Ok(search)
    }

    /// The search handed out as the caller's find handle (FindClose gives it back).
    pub fn into_handle(self) -> u32 {
        let handle = self.0.as_ptr() as usize as u32;
        core::mem::forget(self);
        handle
    }

    fn handle(&self) -> &FindHandle {
        // SAFETY: the block `open` wrote, the search's own until it is dropped.
        unsafe { self.0.as_ref() }
    }
}

impl Drop for Search {
    fn drop(&mut self) {
        ntcall::delete_critical_section(&self.handle().lock);
        // SAFETY: the block `open` wrote and the search owns: its handle dropped in place (the
        // directory closed, the buffer freed), then the block given back; nothing uses either
        // after.
        unsafe {
            core::ptr::drop_in_place(self.0.as_ptr());
            ntcall::free_heap(self.0.as_ptr().cast());
        }
    }
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
/// `data`; the search (a pattern matching nothing STATUS_NO_SUCH_FILE, a path ending in a separator
/// ERROR_FILE_NOT_FOUND). Not inlined: its buffers stay off its callers' frames (kernel32's frames
/// stay within a page, no stack probe).
#[inline(never)]
pub fn find_first_w(pattern: &Wide, data: &mut FindDataW) -> Result<Search, Failure> {
    let ends_in_dot = pattern.text().last() == Some(&u16::from(b'.'));
    let path = NtPath::of(pattern.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let full = path.units();
    let base = full.as_ptr() as usize;
    let file_start = path.file_part.unwrap_or(full.len());
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
        ntcall::open_file(
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &attributes,
            FILE_SHARE_ALL,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
        )
    };
    let mut opened = open_directory(directory);
    if matches!(
        opened,
        Err(STATUS_INVALID_PARAMETER | STATUS_NOT_A_DIRECTORY)
    ) && stripped
    {
        opened = open_directory(&full[start..file_start]);
    }
    let handle = Owned(opened.map_err(|status| {
        Failure::Status(
            if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_TYPE_MISMATCH {
                STATUS_OBJECT_PATH_NOT_FOUND
            } else {
                status
            },
        )
    })?);
    if file_start == full.len() {
        return Err(Failure::Error(ERROR_FILE_NOT_FOUND));
    }
    let mut expression = [0u16; MAX_PATH + 8];
    let count = full.len() - file_start;
    expression[..count].copy_from_slice(&full[file_start..]);
    let count = transform(&mut expression[..count], ends_in_dot);
    drop(path);
    let name = UnicodeString::from_units(&expression[..count]).expect("a name of MAX_PATH");
    let mut record = [0u8; NAME + 2 * MAX_PATH + 8];
    ntcall::query_directory_file(
        handle.0,
        &mut record,
        FILE_BOTH_DIRECTORY_INFORMATION,
        true,
        Some(&name),
    )
    .map_err(Failure::Status)?;
    data.fill(&record);
    Search::open(handle)
}

/// FindNextFileW's work: the next record of the listing buffer, the buffer refilled from the
/// directory (NtQueryDirectoryFile) once it runs out — STATUS_NO_MORE_FILES when the search has —
/// under the handle's lock.
fn find_next_w(find: &FindHandle, data: &mut FindDataW) -> Result<(), Failure> {
    find.with(|listing| {
        if listing.buffer.is_none() {
            listing.buffer = Some(HeapArray::new(FIND_BUFFER_SIZE)?);
            listing.next = None;
        }
        let buffer = listing.buffer.as_mut().expect("made above");
        let next = match listing.next {
            Some(next) => next,
            None => {
                ntcall::query_directory_file(
                    find.directory.0,
                    buffer,
                    FILE_BOTH_DIRECTORY_INFORMATION,
                    false,
                    None,
                )
                .map_err(Failure::Status)?;
                0
            }
        };
        let record = &buffer[next..];
        data.fill(record);
        listing.next = match word(record, NEXT_ENTRY) as usize {
            0 => None,
            step => Some(next + step),
        };
        Ok(())
    })
}

/// FindFirstFileA: the pattern converted, the search opened ([`find_first_w`]), its first match in
/// the caller's WIN32_FIND_DATAA.
///
/// # Safety
///
/// `pattern` is a NUL-terminated string; `data` points at a WIN32_FIND_DATAA.
#[unsafe(export_name = "f2k_export_FindFirstFileA")]
pub unsafe extern "system" fn find_first_file_a(pattern: *const u8, data: *mut u8) -> u32 {
    // SAFETY: the caller's string (null: the empty one) and structure (the contract).
    let (pattern, data) = unsafe { (InStr::optional(pattern), OutBuf::new(data, FIND_DATA_A)) };
    let mut found = FindDataW::zeroed();
    let search = widen(pattern.as_ref()).and_then(|pattern| find_first_w(&pattern, &mut found));
    answer(
        search.map(|search| {
            found.narrow_into(data);
            search.into_handle()
        }),
        INVALID_HANDLE_VALUE,
    )
}

/// FindFirstFileW: the pattern copied ([`wide`]), the search opened ([`find_first_w`]), its first
/// match in the caller's WIN32_FIND_DATAW.
///
/// # Safety
///
/// `pattern` is a NUL-terminated UTF-16 string; `data` points at a WIN32_FIND_DATAW.
#[unsafe(export_name = "f2k_export_FindFirstFileW")]
pub unsafe extern "system" fn find_first_file_w(pattern: *const u16, data: *mut FindDataW) -> u32 {
    // SAFETY: the caller's string and structure (the contract).
    let (pattern, mut data) = unsafe { (InWStr::new(pattern), Out::new(data)) };
    let mut found = FindDataW::zeroed();
    let search = wide(&pattern).and_then(|pattern| find_first_w(&pattern, &mut found));
    answer(
        search.map(|search| {
            data.set(found);
            search.into_handle()
        }),
        INVALID_HANDLE_VALUE,
    )
}

/// FindNextFileA: the search's next match ([`find_next_w`]); ERROR_NO_MORE_FILES when it has none.
///
/// # Safety
///
/// `find` is a find handle; `data` points at a WIN32_FIND_DATAA.
#[unsafe(export_name = "f2k_export_FindNextFileA")]
pub unsafe extern "system" fn find_next_file_a(find: u32, data: *mut u8) -> u32 {
    // SAFETY: the caller's structure, and its handle when it is not INVALID_HANDLE_VALUE: a find
    // handle FindFirstFile made and nothing closed, its block live for the call (the contract).
    let (find, data) = unsafe {
        (
            (find != INVALID_HANDLE_VALUE).then(|| &*(find as usize as *const FindHandle)),
            OutBuf::new(data, FIND_DATA_A),
        )
    };
    let mut found = FindDataW::zeroed();
    let next = find
        .ok_or(Failure::Error(ERROR_INVALID_HANDLE))
        .and_then(|find| find_next_w(find, &mut found));
    bool_answer(next.map(|()| found.narrow_into(data)))
}

/// FindNextFileW: the search's next match ([`find_next_w`]) in the caller's WIN32_FIND_DATAW.
///
/// # Safety
///
/// `find` is a find handle; `data` points at a WIN32_FIND_DATAW.
#[unsafe(export_name = "f2k_export_FindNextFileW")]
pub unsafe extern "system" fn find_next_file_w(find: u32, data: *mut FindDataW) -> u32 {
    // SAFETY: as FindNextFileA's, the structure a WIN32_FIND_DATAW.
    let (find, mut data) = unsafe {
        (
            (find != INVALID_HANDLE_VALUE).then(|| &*(find as usize as *const FindHandle)),
            Out::new(data),
        )
    };
    let mut found = FindDataW::zeroed();
    let next = find
        .ok_or(Failure::Error(ERROR_INVALID_HANDLE))
        .and_then(|find| find_next_w(find, &mut found));
    bool_answer(next.map(|()| data.set(found)))
}

/// FindClose: end a search — its directory's handle closed, its buffer and the handle itself
/// freed. INVALID_HANDLE_VALUE and null are ERROR_INVALID_HANDLE.
///
/// # Safety
///
/// `find` is a find handle.
#[unsafe(export_name = "f2k_export_FindClose")]
pub unsafe extern "system" fn find_close_export(find: u32) -> u32 {
    if find == INVALID_HANDLE_VALUE || find == 0 {
        return bool_answer(Err::<(), _>(Failure::Error(ERROR_INVALID_HANDLE)));
    }
    // SAFETY: the caller's handle (the contract): a find handle FindFirstFile made and nothing
    // closed, which the caller gives back; nothing uses it after.
    let search = Search(unsafe { NonNull::new_unchecked(find as usize as *mut FindHandle) });
    drop(search);
    1
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
