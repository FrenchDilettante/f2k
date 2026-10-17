//! The file API around open, read and seek: the current directory and path names, metadata and
//! file times, the volume's own facts, directory searches, and read-only file mappings — what the
//! files fixture reads of the boot volume.
//!
//! Paths resolve as CreateFileA's do (see [`super::path`]) against the process's current
//! directory, which starts at the image's own directory (a program launched from its folder, as the
//! fixtures are; the root for a process staged without an image path) until SetCurrentDirectoryA
//! moves it. A lookup failure reports the file missing
//! when its directory exists and the path missing when it does not.
//!
//! The volume keeps local time in its timestamps; with no time zone configured, local time is UTC,
//! so a FILETIME is the stored time itself. Attributes are the stored bits, FILE_ATTRIBUTE_NORMAL
//! standing in for none.
//!
//! A search (FindFirstFileA) lists one directory: the pattern is the path's last component, matched
//! with the platform's wildcard rules — `*`, `?`, and the DOS forms the platform derives from them
//! (a `*` or `?` before a dot stops at the name's last dot; `*.*` is every name) — against each
//! entry's long name and then its 8.3 name, without regard to case. The search remembers where it
//! stopped, by record index, and resumes after it.
//!
//! A file mapping is a section: of a file opened for reading — its views are copies of the file's
//! bytes at map time — or of the paging file — committed pages of its own (its store, a hidden
//! reservation) that every view maps, so a write through one view shows in all of them. A view is
//! a reservation of its own in the process's address space (MEM_MAPPED), on the 64 KiB allocation
//! granularity. A section lives while a handle or a view names it; a named one (the paging-file
//! kind) is found by its name while a handle names it.

use crate::compat::error::*;
use crate::compat::path::{resolve, VolumePath, MAX_PATH};
use crate::fs::fat32::lookup::File;
use crate::user::syscall::{read_user, write_user};
use crate::user::teb::set_last_error;

/// How many searches a process can hold open at once.
pub const FINDS: usize = 16;
/// How many file mappings a process can hold at once.
pub const SECTIONS: usize = 16;
/// How many mapped views a process can hold at once.
pub const VIEWS: usize = 32;

/// The allocation granularity: views start on it, and view offsets must be multiples of it.
pub const ALLOCATION_GRANULARITY: u32 = 0x1_0000;

const PAGE_SIZE: u32 = 4096;

/// FILE_ATTRIBUTE_NORMAL: a file with no other attribute.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// The stored attribute bits Win32 reports as they are.
const REPORTED_ATTRIBUTES: u8 = 0x37;

/// One open directory search.
#[derive(Clone, Copy)]
pub struct Find {
    used: bool,
    /// The directory's first cluster.
    directory: u32,
    /// The record index the next match may start at.
    next: u32,
    /// The pattern, as UTF-16 units after the DOS-wildcard translation.
    pattern: [u16; MAX_PATH],
    len: usize,
}

/// One file mapping.
#[derive(Clone, Copy)]
pub struct Section {
    used: bool,
    /// The mapped file, as its open found it (a file-backed section).
    file: File,
    /// A paging-file section's store: the base of the reservation holding its pages; zero for a
    /// file-backed section.
    store: u32,
    /// The section's size in bytes.
    size: u32,
    /// Whether views may be writable (a read-write mapping).
    writable: bool,
    /// Whether a handle still names it, and how many views map it.
    open: bool,
    views: u32,
}

/// One mapped view.
#[derive(Clone, Copy)]
pub struct View {
    used: bool,
    base: u32,
    /// The section it maps.
    section: u32,
}

/// A process's file-API state. All zeros is the fresh state: the current directory the root, no
/// searches, mappings or views.
pub struct FileState {
    current_set: bool,
    current: VolumePath,
    finds: [Find; FINDS],
    sections: [Section; SECTIONS],
    views: [View; VIEWS],
}

impl FileState {
    /// The fresh state, by value (the tests build processes this way; the kernel writes zeros).
    #[cfg(test)]
    pub const fn empty() -> Self {
        const FIND: Find = Find {
            used: false,
            directory: 0,
            next: 0,
            pattern: [0; MAX_PATH],
            len: 0,
        };
        const SECTION: Section = Section {
            used: false,
            file: File::plain(0, 0, false),
            store: 0,
            size: 0,
            writable: false,
            open: false,
            views: 0,
        };
        const VIEW: View = View {
            used: false,
            base: 0,
            section: 0,
        };
        FileState {
            current_set: false,
            current: VolumePath::root(),
            finds: [FIND; FINDS],
            sections: [SECTION; SECTIONS],
            views: [VIEW; VIEWS],
        }
    }

    /// Start the process in the directory at volume path `directory` (the image's own, staged with
    /// the process parameters).
    pub fn start_in(&mut self, directory: &[u8]) {
        self.current = VolumePath::root();
        self.current_set = self.current.push_path(directory).is_ok();
    }

    /// Release a search record (its handle closed).
    pub fn release_find(&mut self, index: usize) {
        self.finds[index].used = false;
    }

    /// A mapping's last handle closed: its views stay mapped, and the record lives on while they
    /// do. The store to free when the section is gone with it.
    pub fn release_section(&mut self, index: usize) -> Option<u32> {
        let section = &mut self.sections[index];
        section.open = false;
        self.retire(index)
    }

    /// Free a section nothing names any more: the record, and its store to give back.
    fn retire(&mut self, index: usize) -> Option<u32> {
        let section = &mut self.sections[index];
        if !section.used || section.open || section.views != 0 {
            return None;
        }
        section.used = false;
        (section.store != 0).then_some(section.store)
    }
}

// --- Wildcards ------------------------------------------------------------------------------------

/// The DOS wildcard forms the platform translates a search pattern into.
const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;

/// Translate a search pattern (codepage 1252) into the matcher's units, as kernel32 does before the
/// file system sees it: `*.*` at the end is `*`; a `?` is DOS_QM; a `*` before a dot is DOS_STAR;
/// a dot before a wildcard, or ending the pattern, is DOS_DOT. Units are case-folded.
pub fn translate_pattern(pattern: &[u8], out: &mut [u16; MAX_PATH]) -> usize {
    use crate::fs::fat32::dir::{decode_byte, fold_unit};
    let pattern = match pattern.strip_suffix(b"*.*") {
        Some(head) if !head.ends_with(b".") => &pattern[..head.len() + 1],
        _ => pattern,
    };
    let mut len = 0;
    for (i, &byte) in pattern.iter().enumerate() {
        let next = pattern.get(i + 1).copied();
        out[len] = match byte {
            b'?' => DOS_QM,
            b'*' if next == Some(b'.') => DOS_STAR,
            b'.' if matches!(next, Some(b'?') | Some(b'*') | None) => DOS_DOT,
            _ => fold_unit(decode_byte(byte)),
        };
        len += 1;
    }
    len
}

/// Whether `name` (case-folded units) matches the translated `pattern`: the platform's expression
/// rules — `*` any run; DOS_STAR any run not past the name's last dot; `?`-turned-DOS_QM one unit,
/// or none at a dot or the end; DOS_DOT a dot, or nothing at the end.
pub fn matches_pattern(pattern: &[u16], name: &[u16]) -> bool {
    let Some((&first, rest)) = pattern.split_first() else {
        return name.is_empty();
    };
    let dot = b'.' as u16;
    match first {
        0x2A /* * */ => (0..=name.len()).any(|skip| matches_pattern(rest, &name[skip..])),
        DOS_STAR => {
            let last_dot = name.iter().rposition(|&u| u == dot);
            (0..=name.len())
                .filter(|&skip| last_dot.is_none_or(|d| skip <= d))
                .any(|skip| matches_pattern(rest, &name[skip..]))
        }
        DOS_QM => match name.first() {
            None => matches_pattern(rest, name),
            Some(&u) if u == dot => matches_pattern(rest, name),
            Some(_) => matches_pattern(rest, &name[1..]),
        },
        DOS_DOT => match name.first() {
            None => matches_pattern(rest, name),
            Some(&u) if u == dot => matches_pattern(rest, &name[1..]),
            Some(_) => false,
        },
        unit => name.first() == Some(&unit) && matches_pattern(rest, &name[1..]),
    }
}

// --- Conversions ----------------------------------------------------------------------------------

/// The Win32 attributes of stored attribute bits.
pub fn win32_attributes(stored: u8) -> u32 {
    match stored & REPORTED_ATTRIBUTES {
        0 => FILE_ATTRIBUTE_NORMAL,
        bits => bits as u32,
    }
}

/// A file's three FILETIMEs: creation, last access, last write.
pub fn file_times(file: &File) -> [u64; 3] {
    use crate::compat::time::fat_filetime;
    let t = &file.times;
    [
        fat_filetime(t.create_date, t.create_time, t.create_hundredths),
        fat_filetime(t.access_date, 0, 0),
        fat_filetime(t.write_date, t.write_time, 0),
    ]
}

/// The attribute-data block GetFileAttributesExA and the search record share: the attributes, the
/// three times, and the size (high dword first).
fn attribute_data(file: &File, out: &mut [u8]) {
    out[..4].copy_from_slice(&win32_attributes(file.attributes).to_le_bytes());
    for (i, time) in file_times(file).iter().enumerate() {
        out[4 + i * 8..12 + i * 8].copy_from_slice(&time.to_le_bytes());
    }
    out[28..32].copy_from_slice(&0u32.to_le_bytes());
    out[32..36].copy_from_slice(&file.size.to_le_bytes());
}

// --- Paths ----------------------------------------------------------------------------------------

/// A narrow path argument copied out of user memory: its length. ERROR_NOACCESS for an unreadable
/// one, ERROR_FILENAME_EXCED_RANGE for one at or past MAX_PATH.
fn path_arg(pointer: u32, out: &mut [u8; MAX_PATH]) -> Result<usize, u32> {
    if pointer == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut len = 0;
    loop {
        let mut byte = [0u8];
        read_user(pointer + len as u32, &mut byte).map_err(|_| ERROR_NOACCESS)?;
        if byte[0] == 0 {
            return Ok(len);
        }
        if len == MAX_PATH - 1 {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        out[len] = byte[0];
        len += 1;
    }
}

/// The current directory's volume path: the image's directory or the one SetCurrentDirectoryA set,
/// else the root.
#[cfg(target_arch = "x86")]
pub fn current_directory() -> VolumePath {
    let state = crate::process::current_mut().file_state();
    if state.current_set {
        state.current
    } else {
        VolumePath::root()
    }
}

/// Host builds have no process: the root.
#[cfg(not(target_arch = "x86"))]
pub fn current_directory() -> VolumePath {
    VolumePath::root()
}

/// Resolve a path argument against the current directory.
pub(crate) fn resolve_arg(pointer: u32) -> Result<VolumePath, u32> {
    let mut bytes = [0u8; MAX_PATH];
    let len = path_arg(pointer, &mut bytes)?;
    resolve(&bytes[..len], current_directory().as_bytes())
}

/// The file or directory a resolved path names on the boot volume (the root included), or the Win32
/// error its absence reports: the file missing when its directory exists, the path otherwise.
#[cfg(target_arch = "x86")]
pub fn locate(path: &VolumePath) -> Result<File, u32> {
    use crate::fs::fat32::lookup::{lookup, root, LookupError};
    use crate::fs::fat32::volume::with_boot_volume;
    let found = with_boot_volume(|volume| {
        if path.is_root() {
            Ok(root(volume))
        } else {
            lookup(volume, path.as_bytes())
        }
    });
    match found {
        None => Err(ERROR_PATH_NOT_FOUND),
        Some(Ok(file)) => Ok(file),
        Some(Err(LookupError::Corrupt)) => Err(ERROR_FILE_CORRUPT),
        Some(Err(LookupError::Device(_))) => Err(ERROR_IO_DEVICE),
        Some(Err(_)) => {
            let parent = path.parent();
            let parent_is_directory = parent.is_empty()
                || matches!(
                    with_boot_volume(|volume| lookup(volume, parent)),
                    Some(Ok(entry)) if entry.directory
                );
            Err(if parent_is_directory {
                ERROR_FILE_NOT_FOUND
            } else {
                ERROR_PATH_NOT_FOUND
            })
        }
    }
}

/// Copy `text` and its terminator to a caller's buffer of `size` bytes, the Win32 string-return
/// convention: the length without the terminator when it fits, else the size it needs (terminator
/// included) and nothing written.
fn string_out(text: &[u8], buffer: u32, size: u32) -> Result<u32, u32> {
    if (size as usize) <= text.len() {
        return Ok(text.len() as u32 + 1);
    }
    write_user(buffer, text).map_err(|_| ERROR_NOACCESS)?;
    write_user(buffer + text.len() as u32, &[0]).map_err(|_| ERROR_NOACCESS)?;
    Ok(text.len() as u32)
}

/// The Win32 form of a volume path: `C:\` and the path.
fn win32_path(path: &VolumePath, out: &mut [u8; MAX_PATH + 4]) -> usize {
    crate::compat::path::win32_form(path.as_bytes(), out)
}

/// Run a service body, reporting its error through the last error and `failure` in EAX.
pub(crate) fn serve(frame: &mut crate::user::TrapFrame, failure: u32, body: impl FnOnce() -> Result<u32, u32>) {
    frame.eax = match body() {
        Ok(value) => value,
        Err(error) => {
            set_last_error(error);
            failure
        }
    };
}

/// GetCurrentDirectoryA: the current directory's Win32 form (no trailing separator but the root's).
pub fn svc_get_current_directory_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (size, buffer) = (args[0], args[1]);
    serve(frame, 0, || {
        let mut text = [0u8; MAX_PATH + 4];
        let len = win32_path(&current_directory(), &mut text);
        string_out(&text[..len], buffer, size)
    });
}

/// SetCurrentDirectoryA: make an existing directory current. ERROR_DIRECTORY for a file; a missing
/// one reports as any lookup does.
pub fn svc_set_current_directory_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, 0, || {
        let path = resolve_arg(args[0])?;
        #[cfg(target_arch = "x86")]
        {
            if !locate(&path)?.directory {
                return Err(ERROR_DIRECTORY);
            }
            let state = crate::process::current_mut().file_state();
            state.current = VolumePath::root();
            state.current.push_path(path.as_bytes())?;
            state.current_set = true;
        }
        #[cfg(not(target_arch = "x86"))]
        let _ = path;
        Ok(1)
    });
}

/// GetFullPathNameA: the path made absolute and folded (no lookup), its trailing separator kept;
/// the file part points at its last component (null when it ends in a separator).
pub fn svc_get_full_path_name_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (name, size, buffer, file_part) = (args[0], args[1], args[2], args[3]);
    serve(frame, 0, || {
        let path = resolve_arg(name)?;
        let mut text = [0u8; MAX_PATH + 4];
        let mut len = win32_path(&path, &mut text);
        if path.trailing_separator() {
            text[len] = b'\\';
            len += 1;
        }
        let written = string_out(&text[..len], buffer, size)?;
        if written as usize == len && file_part != 0 {
            let part = if path.trailing_separator() || path.is_root() {
                0
            } else {
                buffer + (len - path.file_name().len()) as u32
            };
            write_user(file_part, &part.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
        }
        Ok(written)
    });
}

/// GetShortPathNameA: the existing path with every component's 8.3 name.
pub fn svc_get_short_path_name_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (name, buffer, size) = (args[0], args[1], args[2]);
    serve(frame, 0, || {
        let path = resolve_arg(name)?;
        let mut text = [0u8; MAX_PATH + 4];
        let len = short_path(&path, &mut text)?;
        string_out(&text[..len], buffer, size)
    });
}

/// The 8.3 form of an existing path, in its Win32 form.
#[cfg(target_arch = "x86")]
fn short_path(path: &VolumePath, out: &mut [u8; MAX_PATH + 4]) -> Result<usize, u32> {
    use crate::fs::fat32::lookup::lookup_with;
    use crate::fs::fat32::volume::with_boot_volume;
    locate(path)?;
    out[..3].copy_from_slice(b"C:\\");
    let mut len = 3;
    if !path.is_root() {
        with_boot_volume(|volume| {
            lookup_with(volume, path.as_bytes(), |listed| {
                if len > 3 {
                    out[len] = b'\\';
                    len += 1;
                }
                let mut short = [0u8; 12];
                let n = listed.short_name(&mut short);
                out[len..len + n].copy_from_slice(&short[..n]);
                len += n;
            })
        });
    }
    Ok(len)
}

#[cfg(not(target_arch = "x86"))]
fn short_path(_path: &VolumePath, _out: &mut [u8; MAX_PATH + 4]) -> Result<usize, u32> {
    Err(ERROR_PATH_NOT_FOUND)
}

/// The file a path argument names, or its Win32 error (see [`locate`]).
#[cfg(target_arch = "x86")]
fn locate_arg(pointer: u32) -> Result<File, u32> {
    locate(&resolve_arg(pointer)?)
}

#[cfg(not(target_arch = "x86"))]
fn locate_arg(pointer: u32) -> Result<File, u32> {
    resolve_arg(pointer)?;
    Err(ERROR_PATH_NOT_FOUND)
}

/// GetFileAttributesA: the attributes of the file or directory a path names (INVALID_FILE_ATTRIBUTES
/// on failure).
pub fn svc_get_file_attributes_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, u32::MAX, || {
        Ok(win32_attributes(locate_arg(args[0])?.attributes))
    });
}

/// GetFileAttributesExA: the standard information level only (attributes, times, size);
/// ERROR_INVALID_PARAMETER for another level.
pub fn svc_get_file_attributes_ex_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (name, level, info) = (args[0], args[1], args[2]);
    serve(frame, 0, || {
        if level != 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let file = locate_arg(name)?;
        let mut data = [0u8; 36];
        attribute_data(&file, &mut data);
        write_user(info, &data).map_err(|_| ERROR_NOACCESS)?;
        Ok(1)
    });
}

// --- Handles --------------------------------------------------------------------------------------

/// The open file (or directory) a handle names, copied, or ERROR_INVALID_HANDLE.
#[cfg(target_arch = "x86")]
fn handle_file(handle: u32) -> Result<crate::fs::file::OpenFile, u32> {
    crate::compat::kernel32::open_file_record(handle).ok_or(ERROR_INVALID_HANDLE)
}

#[cfg(not(target_arch = "x86"))]
fn handle_file(_handle: u32) -> Result<crate::fs::file::OpenFile, u32> {
    Err(ERROR_INVALID_HANDLE)
}

/// GetFileSize: the low dword of the size, the high one stored when asked (INVALID_FILE_SIZE and
/// ERROR_INVALID_HANDLE for a handle naming no file).
pub fn svc_get_file_size(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, high) = (args[0], args[1]);
    serve(frame, u32::MAX, || {
        let open = handle_file(handle)?;
        if high != 0 {
            write_user(high, &0u32.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
        }
        if open.file.size == u32::MAX {
            set_last_error(0);
        }
        Ok(open.file.size)
    });
}

/// GetFileTime: each FILETIME asked for (creation, last access, last write).
pub fn svc_get_file_time(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, 0, || {
        let open = handle_file(args[0])?;
        for (pointer, time) in args[1..4].iter().zip(file_times(&open.file)) {
            if *pointer != 0 {
                write_user(*pointer, &time.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
            }
        }
        Ok(1)
    });
}

/// GetFileInformationByHandle: attributes, times, the volume serial number, the size, one link, and
/// an index naming the entry (its directory's cluster and its record).
pub fn svc_get_file_information_by_handle(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, info) = (args[0], args[1]);
    serve(frame, 0, || {
        let open = handle_file(handle)?;
        let file = &open.file;
        let mut data = [0u8; 52];
        data[..4].copy_from_slice(&win32_attributes(file.attributes).to_le_bytes());
        for (i, time) in file_times(file).iter().enumerate() {
            data[4 + i * 8..12 + i * 8].copy_from_slice(&time.to_le_bytes());
        }
        data[28..32].copy_from_slice(&volume_facts().map_or(0, |facts| facts.serial).to_le_bytes());
        data[36..40].copy_from_slice(&file.size.to_le_bytes());
        data[40..44].copy_from_slice(&1u32.to_le_bytes());
        data[44..48].copy_from_slice(&file.parent_cluster.to_le_bytes());
        data[48..52].copy_from_slice(&file.index.to_le_bytes());
        write_user(info, &data).map_err(|_| ERROR_NOACCESS)?;
        Ok(1)
    });
}

/// SetEndOfFile: the file ends at the handle's position, shrunk or grown with zeros (see
/// `filewrite`); a handle without write access is ERROR_ACCESS_DENIED.
pub fn svc_set_end_of_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, 0, || {
        #[cfg(target_arch = "x86")]
        {
            crate::compat::filewrite::set_end_of_file(args[0])
        }
        #[cfg(not(target_arch = "x86"))]
        {
            handle_file(args[0]).map(|_| 1)
        }
    });
}

// --- File times -----------------------------------------------------------------------------------

/// FileTimeToSystemTime: ERROR_INVALID_PARAMETER for a FILETIME past the signed range.
pub fn svc_file_time_to_system_time(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (file_time, system_time) = (args[0], args[1]);
    serve(frame, 0, || {
        let mut bytes = [0u8; 8];
        read_user(file_time, &mut bytes).map_err(|_| ERROR_NOACCESS)?;
        let time = u64::from_le_bytes(bytes);
        if time >= 1 << 63 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let civil = crate::compat::time::system_time_from_filetime(time);
        write_user(system_time, &civil.to_bytes()).map_err(|_| ERROR_NOACCESS)?;
        Ok(1)
    });
}

/// FileTimeToLocalFileTime: local time is UTC (no time zone configured): the same FILETIME.
pub fn svc_file_time_to_local_file_time(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (file_time, local) = (args[0], args[1]);
    serve(frame, 0, || {
        let mut bytes = [0u8; 8];
        read_user(file_time, &mut bytes).map_err(|_| ERROR_NOACCESS)?;
        write_user(local, &bytes).map_err(|_| ERROR_NOACCESS)?;
        Ok(1)
    });
}

// --- The volume -----------------------------------------------------------------------------------

/// DRIVE_NO_ROOT_DIR, DRIVE_FIXED.
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_FIXED: u32 = 3;
/// FS_CASE_IS_PRESERVED | FS_UNICODE_STORED_ON_DISK: what FAT32 reports.
const FAT32_FLAGS: u32 = 0x2 | 0x4;
/// The longest component FAT32 stores.
const MAX_COMPONENT: u32 = 255;

/// Whether a root-path argument names the boot volume's root: null (the current drive), `\`, or
/// `C:\` (`C:` too when `bare_drive`, as GetDriveTypeA takes it).
fn names_root(pointer: u32, bare_drive: bool) -> Result<bool, u32> {
    if pointer == 0 {
        return Ok(true);
    }
    let mut bytes = [0u8; MAX_PATH];
    let len = path_arg(pointer, &mut bytes)?;
    let text = &bytes[..len];
    let separator = |b: u8| b == b'\\' || b == b'/';
    Ok(match text {
        [s] if separator(*s) => true,
        [d, b':', s] if separator(*s) => d.to_ascii_uppercase() == crate::compat::path::DRIVE,
        [d, b':'] if bare_drive => d.to_ascii_uppercase() == crate::compat::path::DRIVE,
        _ => false,
    })
}

/// The volume's facts the volume services report.
#[derive(Clone, Copy)]
struct VolumeFacts {
    serial: u32,
    label: [u8; 11],
    sectors_per_cluster: u32,
    clusters: u32,
    free_clusters: u32,
}

/// Read the boot volume's facts: its boot sector's serial number and label, its geometry, and its
/// free clusters (the FSInfo sector's count when it carries a plausible one, else a FAT scan).
#[cfg(target_arch = "x86")]
fn volume_facts() -> Option<VolumeFacts> {
    use crate::fs::fat32::fat::FatEntry;
    crate::fs::fat32::volume::with_boot_volume(|volume| {
        let layout = *volume.layout();
        let mut sector = [0u8; 512];
        if !crate::status::nt_success(volume.device().read(0, &mut sector)) {
            return None;
        }
        let serial = u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]]);
        let mut label = [0u8; 11];
        label.copy_from_slice(&sector[71..82]);
        let info_sector = u16::from_le_bytes([sector[48], sector[49]]) as u64;
        let mut free = None;
        if info_sector != 0 && info_sector != 0xFFFF && crate::status::nt_success(volume.device().read(info_sector, &mut sector)) {
            let word = |at: usize| u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]]);
            if word(0) == 0x4161_5252 && word(484) == 0x6141_7272 && word(488) <= layout.cluster_count {
                free = Some(word(488));
            }
        }
        let free = free.unwrap_or_else(|| {
            (2..layout.cluster_count + 2)
                .filter(|&cluster| matches!(volume.fat_entry(cluster), Ok(FatEntry::Free)))
                .count() as u32
        });
        Some(VolumeFacts {
            serial,
            label,
            sectors_per_cluster: layout.sectors_per_cluster,
            clusters: layout.cluster_count,
            free_clusters: free,
        })
    })
    .flatten()
}

#[cfg(not(target_arch = "x86"))]
fn volume_facts() -> Option<VolumeFacts> {
    None
}

/// GetDriveTypeA: the boot volume's root is a fixed drive; anything else has no root directory.
pub fn svc_get_drive_type_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = match names_root(args[0], true) {
        Ok(true) if volume_facts().is_some() => DRIVE_FIXED,
        _ => DRIVE_NO_ROOT_DIR,
    };
}

/// GetDiskFreeSpaceA: sectors per cluster, 512-byte sectors, free and total clusters.
pub fn svc_get_disk_free_space_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, 0, || {
        if !names_root(args[0], false)? {
            return Err(ERROR_PATH_NOT_FOUND);
        }
        let facts = volume_facts().ok_or(ERROR_PATH_NOT_FOUND)?;
        let values = [facts.sectors_per_cluster, 512, facts.free_clusters, facts.clusters];
        for (pointer, value) in args[1..5].iter().zip(values) {
            if *pointer != 0 {
                write_user(*pointer, &value.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
            }
        }
        Ok(1)
    });
}

/// GetVolumeInformationA: the label, the serial number, the longest component, the file system's
/// flags, and its name, each where asked. ERROR_BAD_LENGTH for a name buffer too small.
pub fn svc_get_volume_information_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (root, name, name_size, serial, max_component, flags, fs_name, fs_size) =
        (args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
    serve(frame, 0, || {
        if !names_root(root, false)? {
            return Err(ERROR_PATH_NOT_FOUND);
        }
        let facts = volume_facts().ok_or(ERROR_PATH_NOT_FOUND)?;
        let put_string = |pointer: u32, size: u32, text: &[u8]| -> Result<(), u32> {
            if pointer == 0 {
                return Ok(());
            }
            if (size as usize) <= text.len() {
                return Err(ERROR_BAD_LENGTH);
            }
            write_user(pointer, text).map_err(|_| ERROR_NOACCESS)?;
            write_user(pointer + text.len() as u32, &[0]).map_err(|_| ERROR_NOACCESS)
        };
        let label_len = facts.label.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        let label: &[u8] = if &facts.label == b"NO NAME    " { b"" } else { &facts.label[..label_len] };
        put_string(name, name_size, label)?;
        put_string(fs_name, fs_size, b"FAT32")?;
        for (pointer, value) in [(serial, facts.serial), (max_component, MAX_COMPONENT), (flags, FAT32_FLAGS)] {
            if pointer != 0 {
                write_user(pointer, &value.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
            }
        }
        Ok(1)
    });
}

// --- Searches -------------------------------------------------------------------------------------

/// WIN32_FIND_DATAA's size, the two name fields included.
const FIND_DATA_SIZE: usize = 318;

/// Fill a WIN32_FIND_DATAA from a listed entry.
#[cfg(target_arch = "x86")]
fn find_data(listed: &crate::fs::fat32::dir::Listed, out: &mut [u8; FIND_DATA_SIZE]) {
    let file = File::plain(listed.entry.first_cluster, listed.entry.size, listed.entry.is_directory());
    let file = File { attributes: listed.entry.attributes, times: listed.entry.times, size: if file.directory { 0 } else { file.size }, ..file };
    out.fill(0);
    attribute_data(&file, &mut out[..36]);
    let mut name = [0u8; crate::fs::fat32::path::MAX_NAME];
    let n = listed.name(&mut name);
    out[44..44 + n].copy_from_slice(&name[..n]);
    if listed.long_name().is_some() {
        let mut short = [0u8; 12];
        let s = listed.short_name(&mut short);
        out[304..304 + s].copy_from_slice(&short[..s]);
    }
}

/// Whether a listed entry matches a search's translated pattern: by its long name, else its 8.3
/// name.
#[cfg(target_arch = "x86")]
fn entry_matches(listed: &crate::fs::fat32::dir::Listed, pattern: &[u16]) -> bool {
    use crate::fs::fat32::dir::{decode_byte, fold_unit};
    let mut units = [0u16; crate::fs::fat32::path::MAX_NAME];
    let mut bytes = [0u8; crate::fs::fat32::path::MAX_NAME];
    let n = listed.name(&mut bytes);
    for (unit, &byte) in units.iter_mut().zip(&bytes[..n]) {
        *unit = fold_unit(decode_byte(byte));
    }
    if let Some(long) = listed.long_name() {
        for (unit, &u) in units.iter_mut().zip(long) {
            *unit = fold_unit(u);
        }
    }
    if matches_pattern(pattern, &units[..n]) {
        return true;
    }
    if listed.long_name().is_none() {
        return false;
    }
    let mut short = [0u8; 12];
    let s = listed.short_name(&mut short);
    for (unit, &byte) in units.iter_mut().zip(&short[..s]) {
        *unit = fold_unit(decode_byte(byte));
    }
    matches_pattern(pattern, &units[..s])
}

/// The next entry of a search's directory at or after record `from` that matches its pattern, as
/// its find data and the record index after it; none when the directory is exhausted.
#[cfg(target_arch = "x86")]
fn next_match(find: &Find, from: u32) -> Result<Option<([u8; FIND_DATA_SIZE], u32)>, u32> {
    use crate::fs::fat32::dir::walk;
    let pattern = &find.pattern[..find.len];
    let mut found = None;
    let walked = crate::fs::fat32::volume::with_boot_volume(|volume| {
        walk(volume, find.directory, |listed| {
            if listed.index >= from && entry_matches(listed, pattern) {
                let mut data = [0u8; FIND_DATA_SIZE];
                find_data(listed, &mut data);
                found = Some((data, listed.index + 1));
                return false;
            }
            true
        })
    });
    match walked {
        Some(Ok(())) => Ok(found),
        Some(Err(_)) | None => Err(ERROR_FILE_CORRUPT),
    }
}

/// FindFirstFileA: open a search of the pattern's directory and return its first match. The
/// directory must exist (ERROR_PATH_NOT_FOUND); a pattern matching nothing is ERROR_FILE_NOT_FOUND.
pub fn svc_find_first_file_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (pattern, data) = (args[0], args[1]);
    serve(frame, u32::MAX, || {
        let mut bytes = [0u8; MAX_PATH];
        let len = path_arg(pattern, &mut bytes)?;
        let raw = &bytes[..len];
        let split = raw.iter().rposition(|&b| b == b'\\' || b == b'/' || b == b':').map_or(0, |i| i + 1);
        let (directory, name) = raw.split_at(split);
        if name.is_empty() {
            return Err(ERROR_FILE_NOT_FOUND);
        }
        if name.iter().any(|&b| b < b' ' || b"\"<>|".contains(&b)) {
            return Err(ERROR_INVALID_NAME);
        }
        let current = current_directory();
        let directory = if directory.is_empty() {
            current
        } else {
            resolve(directory, current.as_bytes())?
        };
        open_search(&directory, name, data)
    });
}

#[cfg(target_arch = "x86")]
fn open_search(directory: &VolumePath, name: &[u8], data: u32) -> Result<u32, u32> {
    let dir = match locate(directory) {
        Ok(file) if file.directory => file,
        Ok(_) | Err(ERROR_FILE_NOT_FOUND) => return Err(ERROR_PATH_NOT_FOUND),
        Err(error) => return Err(error),
    };
    let mut find = Find {
        used: true,
        directory: dir.first_cluster,
        next: 0,
        pattern: [0; MAX_PATH],
        len: 0,
    };
    find.len = translate_pattern(name, &mut find.pattern);
    let (found, next) = next_match(&find, 0)?.ok_or(ERROR_FILE_NOT_FOUND)?;
    write_user(data, &found).map_err(|_| ERROR_NOACCESS)?;
    find.next = next;
    let process = crate::process::current_mut();
    if process.handles_mut().is_full() {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    let state = process.file_state();
    let index = state.finds.iter().position(|f| !f.used).ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    state.finds[index] = find;
    Ok(process.handles_mut().insert(crate::sched::object::Slot::Find(index)))
}

#[cfg(not(target_arch = "x86"))]
fn open_search(_directory: &VolumePath, _name: &[u8], _data: u32) -> Result<u32, u32> {
    Err(ERROR_PATH_NOT_FOUND)
}

/// The search record a handle names, or ERROR_INVALID_HANDLE.
#[cfg(target_arch = "x86")]
fn find_of(handle: u32) -> Result<usize, u32> {
    match crate::process::current_mut().handles_mut().lookup(handle) {
        Some(crate::sched::object::Slot::Find(index)) => Ok(index),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

/// FindNextFileA: the search's next match; ERROR_NO_MORE_FILES when it has none.
pub fn svc_find_next_file_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, data) = (args[0], args[1]);
    serve(frame, 0, || {
        #[cfg(target_arch = "x86")]
        {
            let index = find_of(handle)?;
            let find = crate::process::current_mut().file_state().finds[index];
            let (found, next) = next_match(&find, find.next)?.ok_or(ERROR_NO_MORE_FILES)?;
            write_user(data, &found).map_err(|_| ERROR_NOACCESS)?;
            crate::process::current_mut().file_state().finds[index].next = next;
            Ok(1)
        }
        #[cfg(not(target_arch = "x86"))]
        {
            let _ = (handle, data);
            Err(ERROR_INVALID_HANDLE)
        }
    });
}

/// FindClose: end a search.
pub fn svc_find_close(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    serve(frame, 0, || {
        #[cfg(target_arch = "x86")]
        {
            find_of(args[0])?;
            crate::process::current_mut().close_handle(args[0]);
            Ok(1)
        }
        #[cfg(not(target_arch = "x86"))]
        Err(ERROR_INVALID_HANDLE)
    });
}

// --- File mappings --------------------------------------------------------------------------------

/// The page protections a mapping takes.
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
/// The view access rights.
const FILE_MAP_WRITE: u32 = 0x0002;

/// Give a paging-file section's store back (the section is gone).
#[cfg(target_arch = "x86")]
pub fn free_store(space: &mut crate::mem::vm::AddressSpace, store: u32) {
    let _ = space.release(&mut crate::mem::vm::CurrentPages, store);
}

#[cfg(not(target_arch = "x86"))]
pub fn free_store(_space: &mut crate::mem::vm::AddressSpace, _store: u32) {}

/// CreateFileMappingA. Of a file opened for reading (a read-write mapping needs write access): a
/// size of zero is the file's size; an empty file cannot be mapped (ERROR_FILE_INVALID), and a
/// read-only mapping cannot reach past the file's end (ERROR_NOT_ENOUGH_MEMORY). Of the paging file
/// (INVALID_HANDLE_VALUE): a size is required (ERROR_INVALID_PARAMETER), the pages are committed
/// zeroed. A name that binds a live mapping opens it instead (a new handle, ERROR_ALREADY_EXISTS);
/// one binding another kind of object is ERROR_INVALID_HANDLE. The last error is cleared on
/// success.
pub fn svc_create_file_mapping_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, _attributes, protect, size_high, size_low, name) =
        (args[0], args[1], args[2], args[3], args[4], args[5]);
    serve(frame, 0, || {
        let mut bytes = [0u8; MAX_PATH];
        let name = crate::compat::kernel32::object_name(name, &mut bytes)?.map(|length| &bytes[..length]);
        if let Some(existing) = name.and_then(lookup_name) {
            let handle = existing?;
            set_last_error(ERROR_ALREADY_EXISTS);
            return Ok(handle);
        }
        let writable = match protect & 0xFF {
            PAGE_READONLY | PAGE_WRITECOPY => false,
            PAGE_READWRITE => true,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
        let section = if handle == u32::MAX {
            if size_high != 0 || size_low == 0 {
                return Err(ERROR_INVALID_PARAMETER);
            }
            Section {
                used: true,
                file: File::plain(0, 0, false),
                store: 0,
                size: size_low,
                writable,
                open: true,
                views: 0,
            }
        } else {
            let open = handle_file(handle)?;
            if open.file.directory {
                return Err(ERROR_INVALID_HANDLE);
            }
            let wants = crate::fs::file::ACCESS_READ | if writable { crate::fs::file::ACCESS_WRITE } else { 0 };
            if open.access & wants != wants {
                return Err(ERROR_ACCESS_DENIED);
            }
            let size = if size_high == 0 && size_low == 0 {
                if open.file.size == 0 {
                    return Err(ERROR_FILE_INVALID);
                }
                open.file.size
            } else if size_high != 0 || size_low > open.file.size {
                return Err(if writable { ERROR_WRITE_PROTECT } else { ERROR_NOT_ENOUGH_MEMORY });
            } else {
                size_low
            };
            Section {
                used: true,
                file: open.file,
                store: 0,
                size,
                writable,
                open: true,
                views: 0,
            }
        };
        let handle = insert_section(section, handle == u32::MAX, name)?;
        set_last_error(0);
        Ok(handle)
    });
}

/// The live mapping `name` binds, as a new handle to it; ERROR_INVALID_HANDLE when it binds
/// another kind of object; none when it binds nothing.
#[cfg(target_arch = "x86")]
fn lookup_name(name: &[u8]) -> Option<Result<u32, u32>> {
    let (handles, objects, _, _) = crate::process::current_mut().mapping_parts();
    let slot = objects.lookup(handles, name)?;
    Some(match slot {
        crate::sched::object::Slot::Section(_) if handles.is_full() => Err(ERROR_NOT_ENOUGH_MEMORY),
        crate::sched::object::Slot::Section(_) => Ok(handles.insert(slot)),
        _ => Err(ERROR_INVALID_HANDLE),
    })
}

#[cfg(not(target_arch = "x86"))]
fn lookup_name(_name: &[u8]) -> Option<Result<u32, u32>> {
    None
}

/// Record a section, its store committed (a paging-file section), a handle to it inserted and its
/// name bound.
#[cfg(target_arch = "x86")]
fn insert_section(mut section: Section, paging_file: bool, name: Option<&[u8]>) -> Result<u32, u32> {
    use crate::mem::vm::{CurrentPages, Kind};
    use crate::sched::object::Slot;
    let (handles, objects, state, space) = crate::process::current_mut().mapping_parts();
    if handles.is_full() {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    let index = state.sections.iter().position(|s| !s.used).ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    if paging_file {
        let store = space
            .reserve(None, section.size, PAGE_READWRITE, Kind::Mapped { shared: false })
            .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
        let size = space.region_at(store).expect("just reserved").size;
        if space.commit(&mut CurrentPages, store, size, PAGE_READWRITE).is_err() {
            let _ = space.release(&mut CurrentPages, store);
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
        section.store = store;
    }
    // A reused record's old name does not come back with it.
    objects.forget_slot(Slot::Section(index));
    state.sections[index] = section;
    let handle = handles.insert(Slot::Section(index));
    if let Some(name) = name {
        if objects.bind(handles, name, Slot::Section(index)).is_err() {
            crate::process::current_mut().close_handle(handle);
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
    }
    Ok(handle)
}

#[cfg(not(target_arch = "x86"))]
fn insert_section(_section: Section, _paging_file: bool, _name: Option<&[u8]>) -> Result<u32, u32> {
    Err(ERROR_NOT_ENOUGH_MEMORY)
}

/// OpenFileMappingA: a new handle to the live mapping the name binds. ERROR_FILE_NOT_FOUND when it
/// binds none, ERROR_INVALID_HANDLE when it binds another kind of object; the access and
/// inheritance arguments are not modeled.
pub fn svc_open_file_mapping_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let name = args[2];
    serve(frame, 0, || {
        let mut bytes = [0u8; MAX_PATH];
        let name = crate::compat::kernel32::object_name(name, &mut bytes)?
            .map(|length| &bytes[..length])
            .ok_or(ERROR_INVALID_PARAMETER)?;
        lookup_name(name).unwrap_or(Err(ERROR_FILE_NOT_FOUND))
    });
}

/// MapViewOfFile: map `bytes` of the section from `offset` (zero bytes: to its end). The offset is a
/// multiple of the allocation granularity (ERROR_MAPPED_ALIGNMENT); a writable view of a read-only
/// mapping is ERROR_ACCESS_DENIED, and so is a view past the section's end. Returns the view's base.
pub fn svc_map_view_of_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, access, offset_high, offset_low, bytes) = (args[0], args[1], args[2], args[3], args[4]);
    serve(frame, 0, || {
        #[cfg(target_arch = "x86")]
        {
            let index = match crate::process::current_mut().handles_mut().lookup(handle) {
                Some(crate::sched::object::Slot::Section(index)) => index,
                _ => return Err(ERROR_INVALID_HANDLE),
            };
            let section = crate::process::current_mut().file_state().sections[index];
            if access & FILE_MAP_WRITE != 0 && !section.writable {
                return Err(ERROR_ACCESS_DENIED);
            }
            if offset_low % ALLOCATION_GRANULARITY != 0 {
                return Err(ERROR_MAPPED_ALIGNMENT);
            }
            if offset_high != 0 || offset_low >= section.size {
                return Err(ERROR_ACCESS_DENIED);
            }
            let bytes = if bytes == 0 { section.size - offset_low } else { bytes };
            if bytes > section.size - offset_low {
                return Err(ERROR_ACCESS_DENIED);
            }
            map_view(index, &section, offset_low, bytes, access & FILE_MAP_WRITE != 0)
        }
        #[cfg(not(target_arch = "x86"))]
        {
            let _ = (handle, access, offset_high, offset_low, bytes);
            Err(ERROR_INVALID_HANDLE)
        }
    });
}

/// Map `bytes` of section `index` from `offset` as a reservation of its own: a paging-file
/// section's store pages themselves, or copies of a file's bytes (zeros past its end) in fresh
/// pages; read-only unless `writable`.
#[cfg(target_arch = "x86")]
fn map_view(index: usize, section: &Section, offset: u32, bytes: u32, writable: bool) -> Result<u32, u32> {
    use crate::mem::vm::{self, CurrentPages, Kind, Pages};
    let (_, _, state, space) = crate::process::current_mut().mapping_parts();
    let slot = state.views.iter().position(|v| !v.used).ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    let pages = bytes.div_ceil(PAGE_SIZE);
    let protect = if writable { PAGE_READWRITE } else { PAGE_READONLY };
    let section_protect = if section.writable { PAGE_READWRITE } else { PAGE_READONLY };
    let shared = section.store != 0;
    let base = space
        .reserve(None, pages * PAGE_SIZE, section_protect, Kind::Mapped { shared })
        .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    let mut table = CurrentPages;
    if shared {
        for page in 0..pages {
            let (frame, _) = vm::decode(table.entry(section.store + offset + page * PAGE_SIZE))
                .expect("a store is committed whole");
            table.set_entry(base + page * PAGE_SIZE, vm::encode(frame, protect));
        }
    } else {
        if space.commit(&mut table, base, pages * PAGE_SIZE, protect).is_err() {
            let _ = space.release(&mut table, base);
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
        let mut buffer = [0u8; PAGE_SIZE as usize];
        for page in 0..pages {
            let at = offset + page * PAGE_SIZE;
            let take = section.file.size.saturating_sub(at).min(PAGE_SIZE) as usize;
            if take == 0 {
                continue;
            }
            if crate::compat::kernel32::read_volume_at(&section.file, at, &mut buffer[..take]).is_none() {
                let _ = space.release(&mut table, base);
                return Err(ERROR_IO_DEVICE);
            }
            let (frame, _) = vm::decode(table.entry(base + page * PAGE_SIZE)).expect("just committed");
            crate::mem::paging::write_frame(frame, 0, &buffer[..take]);
        }
    }
    state.views[slot] = View {
        used: true,
        base,
        section: index as u32,
    };
    state.sections[index].views += 1;
    Ok(base)
}

/// UnmapViewOfFile: unmap the view starting at the address (a section nothing names any more goes
/// with its last view); ERROR_INVALID_ADDRESS for any other address.
pub fn svc_unmap_view_of_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let address = args[0];
    serve(frame, 0, || {
        #[cfg(target_arch = "x86")]
        {
            let (_, _, state, space) = crate::process::current_mut().mapping_parts();
            let view = state
                .views
                .iter_mut()
                .find(|v| v.used && v.base == address)
                .ok_or(ERROR_INVALID_ADDRESS)?;
            view.used = false;
            let index = view.section as usize;
            let _ = space.release(&mut crate::mem::vm::CurrentPages, address);
            state.sections[index].views -= 1;
            if let Some(store) = state.retire(index) {
                free_store(space, store);
            }
            Ok(1)
        }
        #[cfg(not(target_arch = "x86"))]
        {
            let _ = address;
            Err(ERROR_INVALID_ADDRESS)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.bytes()
            .map(|b| crate::fs::fat32::dir::fold_unit(b as u16))
            .collect()
    }

    fn matches(pattern: &str, name: &str) -> bool {
        let mut out = [0u16; MAX_PATH];
        let len = translate_pattern(pattern.as_bytes(), &mut out);
        matches_pattern(&out[..len], &units(name))
    }

    /// The files capture's patterns over its directory.
    #[test]
    fn the_captured_patterns() {
        let names = [".", "..", "BIG.BIN", "EMPTY.DAT", "HIDDEN.TXT", "Long File Name.txt", "SMALL.TXT", "SUB"];
        let listed = |pattern: &str| -> Vec<&str> {
            names.iter().copied().filter(|name| matches(pattern, name)).collect()
        };
        assert_eq!(listed("*"), names);
        assert_eq!(listed("*.*"), names);
        assert_eq!(listed("*.TXT"), ["HIDDEN.TXT", "Long File Name.txt", "SMALL.TXT"]);
        assert_eq!(listed("S*"), ["SMALL.TXT", "SUB"]);
        assert_eq!(listed("?????.TXT"), ["SMALL.TXT"]);
        assert_eq!(listed("Long*"), ["Long File Name.txt"]);
        assert!(listed("*.XYZ").is_empty());
        assert_eq!(listed("sub"), ["SUB"]);
    }

    /// The DOS forms: `?` before a dot matches short names too, `*.` matches names without an
    /// extension, and a DOS star stops at the last dot.
    #[test]
    fn the_dos_wildcards() {
        assert!(matches("????.TXT", "AB.TXT"));
        assert!(!matches("????.TXT", "ABCDE.TXT"));
        assert!(matches("*.", "README"));
        assert!(!matches("*.", "README.TXT"));
        assert!(matches("*.gz", "a.tar.gz"));
        assert!(!matches("*.tar", "a.tar.gz"));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
    }

    /// Attributes: the stored bits, or FILE_ATTRIBUTE_NORMAL for none.
    #[test]
    fn attributes_convert() {
        assert_eq!(win32_attributes(0x20), 0x20);
        assert_eq!(win32_attributes(0x21), 0x21);
        assert_eq!(win32_attributes(0x10), 0x10);
        assert_eq!(win32_attributes(0), 0x80);
    }
}
